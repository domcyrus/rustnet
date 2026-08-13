use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use log::debug;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{aead, hkdf};

use super::packet::{initial_salt_for_version, is_quic_v2, parse_variable_length_int};

/// Decrypt a QUIC Client Initial packet (prioritized for SNI extraction)
pub(super) fn decrypt_client_initial_packet(
    packet: &[u8],
    dcid: &[u8],
    version: u32,
) -> Option<Vec<u8>> {
    // Derive initial secret using HKDF
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, initial_salt_for_version(version));
    let initial_secret = salt.extract(dcid);

    // Derive client initial secret
    let mut client_secret = [0u8; 32];
    if !derive_secret(&initial_secret, b"client in", &mut client_secret) {
        debug!("QUIC: Failed to derive client initial secret");
        return None;
    }

    debug!(
        "QUIC: Attempting client Initial decryption with DCID len={}",
        dcid.len()
    );

    // Try to decrypt as a client Initial packet
    let result = try_decrypt_initial_with_secret(packet, &client_secret, version);
    if result.is_none() {
        debug!("QUIC: Client Initial decryption failed");
    }
    result
}

/// Try to decrypt an Initial packet with a specific secret
fn try_decrypt_initial_with_secret(packet: &[u8], secret: &[u8], version: u32) -> Option<Vec<u8>> {
    // Derive key and IV for packet protection
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp_key = [0u8; 16];

    if !derive_protection_material(secret, &mut key, version, ProtectionMaterial::Key)
        || !derive_protection_material(secret, &mut iv, version, ProtectionMaterial::Iv)
        || !derive_protection_material(
            secret,
            &mut hp_key,
            version,
            ProtectionMaterial::HeaderProtection,
        )
    {
        debug!("QUIC: Failed to derive keys from secret");
        return None;
    }

    // Parse packet structure to find packet number offset
    let mut offset = 5; // Skip first byte and version

    // Skip DCID
    if offset >= packet.len() {
        debug!("QUIC: Packet too short for DCID length field");
        return None;
    }
    let dcid_len = packet[offset] as usize;
    offset += 1 + dcid_len;

    if offset >= packet.len() {
        debug!("QUIC: Packet too short after DCID");
        return None;
    }

    // Skip SCID
    let scid_len = packet[offset] as usize;
    offset += 1 + scid_len;

    if offset >= packet.len() {
        debug!("QUIC: Packet too short after SCID");
        return None;
    }

    debug!(
        "QUIC: Parsed connection IDs - DCID len={}, SCID len={}, offset now={}",
        dcid_len, scid_len, offset
    );

    // Parse token length (for Initial packets)
    let (token_len, bytes_read) = parse_variable_length_int(&packet[offset..])?;
    // QUIC variable-length ints go up to 2^62 — guard against overflow on
    // 32-bit targets and against crafted token lengths that exceed the packet.
    let token_len_usize = usize::try_from(token_len).ok()?;
    offset = offset
        .checked_add(bytes_read)?
        .checked_add(token_len_usize)?;
    if offset > packet.len() {
        debug!("QUIC: token_len pushed offset past end of packet");
        return None;
    }

    // Parse packet length
    let (packet_payload_length, bytes_read) = parse_variable_length_int(&packet[offset..])?;
    offset += bytes_read;

    // Now offset points to the packet number field
    let pn_offset = offset;

    // Sample is taken 4 bytes after the packet number offset
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > packet.len() {
        debug!("QUIC: Not enough data for header protection sample");
        return None;
    }

    // Remove header protection to get packet number
    let sample = &packet[sample_offset..sample_offset + 16];
    let mask = aes_ecb_encrypt(&hp_key, sample)?;

    // Unmask the first byte to get packet number length
    let mut first_byte = packet[0];
    first_byte ^= mask[0] & 0x0f; // Only lower 4 bits for long header
    let pn_length = ((first_byte & 0x03) + 1) as usize;

    // Unmask and extract packet number
    let mut packet_number = 0u64;
    for i in 0..pn_length {
        let unmasked = packet[pn_offset + i] ^ mask[1 + i];
        packet_number = (packet_number << 8) | (unmasked as u64);
    }

    // Prepare for AEAD decryption
    let aead_key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?);

    // Calculate nonce
    let mut nonce_bytes = iv;
    for i in 0..8 {
        nonce_bytes[11 - i] ^= ((packet_number >> (i * 8)) & 0xff) as u8;
    }
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);

    // Create AAD (authenticated header up to and including packet number)
    let mut aad = Vec::new();
    aad.push(first_byte); // Unmasked first byte
    aad.extend_from_slice(&packet[1..pn_offset]); // Rest of header
    for i in 0..pn_length {
        aad.push(packet[pn_offset + i] ^ mask[1 + i]); // Unmasked packet number
    }

    // Decrypt the payload
    let ciphertext_offset = pn_offset + pn_length;
    // `packet_payload_length` is an attacker-controlled varint; if it is
    // smaller than the packet-number length the subtraction would underflow
    // (panic in debug, wrap to a huge value in release that then slips past
    // the bounds check below and panics on the slice). Reject instead.
    let ciphertext_len = (packet_payload_length as usize).checked_sub(pn_length)?;

    if ciphertext_offset + ciphertext_len > packet.len() {
        debug!("QUIC: Ciphertext extends beyond packet");
        return None;
    }

    // The ciphertext includes the authentication tag (last 16 bytes)
    if ciphertext_len < 16 {
        debug!("QUIC: Ciphertext too short for auth tag");
        return None;
    }

    let mut plaintext = packet[ciphertext_offset..ciphertext_offset + ciphertext_len].to_vec();

    match aead_key.open_in_place(nonce, Aad::from(&aad), &mut plaintext) {
        Ok(decrypted) => {
            let decrypted_len = decrypted.len();
            plaintext.truncate(decrypted_len);
            Some(plaintext)
        }
        Err(e) => {
            debug!("QUIC: AEAD decryption failed: {:?}", e);
            None
        }
    }
}

/// Derive a secret using HKDF
pub(super) fn derive_secret(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> bool {
    let info = build_hkdf_label(label, &[], out.len());

    prk.expand(&[&info], ArbitraryOutputLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .is_ok()
}

/// Packet protection material derivable from an initial secret
pub(super) enum ProtectionMaterial {
    Key,
    Iv,
    HeaderProtection,
}

/// Derive packet protection material (key, IV, or header protection key)
/// using the version-specific HKDF label
pub(super) fn derive_protection_material(
    secret: &[u8],
    out: &mut [u8],
    version: u32,
    material: ProtectionMaterial,
) -> bool {
    let label: &[u8] = match (material, is_quic_v2(version)) {
        (ProtectionMaterial::Key, false) => b"quic key",
        (ProtectionMaterial::Key, true) => b"quicv2 key",
        (ProtectionMaterial::Iv, false) => b"quic iv",
        (ProtectionMaterial::Iv, true) => b"quicv2 iv",
        (ProtectionMaterial::HeaderProtection, false) => b"quic hp",
        (ProtectionMaterial::HeaderProtection, true) => b"quicv2 hp",
    };
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    derive_secret(&prk, label, out)
}

/// Build HKDF label
fn build_hkdf_label(label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::new();

    // Length (2 bytes)
    info.push((length >> 8) as u8);
    info.push((length & 0xff) as u8);

    // Label with "tls13 " prefix
    let full_label = [b"tls13 ", label].concat();
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);

    // Context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    info
}

/// AES-ECB encryption for header protection
pub(super) fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    let cipher = Aes128::new(key.try_into().ok()?);
    let mut output: aes::cipher::Array<u8, aes::cipher::consts::U16> = block.try_into().ok()?;
    cipher.encrypt_block(&mut output);
    Some(output.into())
}

/// Wrapper for HKDF expand with arbitrary output length
struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_packet_oversized_token_len_does_not_panic() {
        // Crafted Initial packet whose declared token length pushes the parse
        // offset past the end of the packet. Pre-fix this panicked when
        // slicing &packet[offset..] in try_decrypt_initial_with_secret.
        let mut packet = Vec::new();
        packet.push(0xC0); // long header, type=Initial
        packet.extend_from_slice(&1u32.to_be_bytes()); // version 1
        packet.push(0); // DCID len = 0
        packet.push(0); // SCID len = 0
        // Token length: 2-byte QUIC varint encoding 1000 (top 2 bits = 01).
        let token_varint: u16 = 1000 | 0x4000;
        packet.extend_from_slice(&token_varint.to_be_bytes());
        // Intentionally no token bytes follow — declared length far exceeds packet.

        let secret = [0u8; 32];
        let result = try_decrypt_initial_with_secret(&packet, &secret, 1);
        assert!(result.is_none());
    }

    #[test]
    fn test_initial_packet_short_length_does_not_underflow() {
        // Regression: a crafted Initial packet whose declared payload `Length`
        // varint is smaller than the packet-number length made
        // `packet_payload_length - pn_length` underflow. In debug that panicked
        // outright; in release it wrapped to a huge value that slipped past the
        // bounds check and panicked on the ciphertext slice (start > end).
        // It must now bail out via checked_sub and return None.
        let mut packet = Vec::new();
        packet.push(0xC0); // long header, type = Initial
        packet.extend_from_slice(&1u32.to_be_bytes()); // version 1
        packet.push(0); // DCID len = 0
        packet.push(0); // SCID len = 0
        packet.push(0); // token length varint = 0
        packet.push(0); // packet length varint = 0  (< any pn_length of 1..=4)
        // Enough trailing bytes for the header-protection sample
        // (sample_offset + 16 must be within the packet).
        packet.extend(std::iter::repeat_n(0u8, 24));

        let secret = [0u8; 32];
        // Must not panic in either debug or release.
        let result = try_decrypt_initial_with_secret(&packet, &secret, 1);
        assert!(result.is_none());
    }
}
