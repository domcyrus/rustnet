use crate::network::types::{
    CryptoFrameReassembler, QuicConnectionState, QuicInfo, QuicPacketType, TlsInfo, TlsVersion,
};
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use log::{debug, warn};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::{aead, hkdf};

// QUIC v1 Initial salt (from RFC 9001)
const INITIAL_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// QUIC v2 Initial salt
const INITIAL_SALT_V2: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

// ============================================================================
// SNI Validation and Parsing Helpers
// ============================================================================

/// Minimum length for partial SNI extraction
const PARTIAL_SNI_MIN_LENGTH: usize = 3;

/// Marker suffix for partial SNI values
const PARTIAL_SNI_MARKER: &str = "[PARTIAL]";

/// Validate if a string looks like a valid complete hostname
///
/// This is the unified hostname validation function used across all SNI extraction methods.
/// Rules:
/// - Length between 4 and 253 characters
/// - Contains at least one '.'
/// - Only ASCII alphanumeric, '.', and '-' characters
/// - Doesn't start or end with '.' or '-'
/// - No consecutive dots '..'
/// - Has at least one alphabetic character
/// - Each label is non-empty and at most 63 characters
fn is_valid_hostname(hostname: &str) -> bool {
    // Length check
    if hostname.len() < 4 || hostname.len() > 253 {
        return false;
    }

    // Must contain at least one dot
    if !hostname.contains('.') {
        return false;
    }

    // Check for valid hostname characters only
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    // Must not start or end with a dot or hyphen
    if hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.starts_with('-')
        || hostname.ends_with('-')
    {
        return false;
    }

    // Must not contain consecutive dots
    if hostname.contains("..") {
        return false;
    }

    // Must have at least one alphabetic character (not just numbers and dots)
    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Each label must be non-empty and at most 63 characters
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() < 2 {
        return false;
    }
    if !parts
        .iter()
        .all(|part| !part.is_empty() && part.len() <= 63)
    {
        return false;
    }

    true
}

/// Validate if a string looks like a valid partial hostname
///
/// Partial hostnames have relaxed rules since they may be truncated:
/// - Minimum length (PARTIAL_SNI_MIN_LENGTH)
/// - Only ASCII alphanumeric, '.', and '-' characters
/// - Has at least one alphabetic character
/// - Doesn't start with '.' or '-'
fn is_valid_partial_hostname(hostname: &str) -> bool {
    if hostname.len() < PARTIAL_SNI_MIN_LENGTH {
        return false;
    }

    // Check for valid hostname characters only
    if !hostname
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }

    // Must have at least one alphabetic character
    if !hostname.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    // Must not start with '.' or '-'
    if hostname.starts_with('.') || hostname.starts_with('-') {
        return false;
    }

    true
}

/// Mark an SNI value as partial by appending the marker
fn mark_partial_sni(hostname: &str) -> String {
    format!("{}{}", hostname, PARTIAL_SNI_MARKER)
}

/// Check if an SNI value is marked as partial
pub fn is_partial_sni(sni: &str) -> bool {
    sni.ends_with(PARTIAL_SNI_MARKER)
}

/// Parsed SNI extension header
struct SniHeader {
    /// Server name list length
    list_len: u16,
    /// Name type (should be 0x00 for hostname) - validated but not stored
    #[allow(dead_code)]
    _name_type: u8,
    /// Hostname length
    name_len: u16,
}

/// Parse the SNI extension header from raw data
///
/// Expects data starting at the SNI extension content (after extension type and length):
/// - 2 bytes: server name list length
/// - 1 byte: name type (0x00 = hostname)
/// - 2 bytes: hostname length
///
/// Returns None if data is too short or name type is not hostname
fn parse_sni_header(data: &[u8]) -> Option<SniHeader> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]);
    let name_type = data[2];
    let name_len = u16::from_be_bytes([data[3], data[4]]);

    // Name type must be 0x00 (hostname)
    if name_type != 0x00 {
        return None;
    }

    // Validate hostname length is reasonable
    if name_len == 0 || name_len > 253 {
        return None;
    }

    Some(SniHeader {
        list_len,
        _name_type: name_type,
        name_len,
    })
}

// ============================================================================

/// Main entry point for QUIC packet parsing
/// Handles coalesced packets - multiple QUIC packets in a single UDP datagram
pub fn parse_quic_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.is_empty() {
        debug!("QUIC: Empty payload");
        return None;
    }

    let mut combined_info: Option<QuicInfo> = None;
    let mut offset = 0;
    let mut packet_count = 0;

    // Process all coalesced packets in the UDP datagram
    while offset < payload.len() {
        let remaining = &payload[offset..];
        if remaining.is_empty() {
            break;
        }

        let first_byte = remaining[0];
        let is_long_header = (first_byte & 0x80) != 0;

        debug!(
            "QUIC: Parsing packet {} at offset {} - first_byte=0x{:02x}, is_long_header={}, remaining_len={}",
            packet_count + 1,
            offset,
            first_byte,
            is_long_header,
            remaining.len()
        );

        let (packet_info, packet_len) = if is_long_header {
            parse_long_header_packet_with_length(remaining)
        } else {
            // Short header packet - consumes rest of datagram (no length field)
            let info = parse_short_header_packet(remaining);
            (info, remaining.len())
        };

        if let Some(info) = packet_info {
            combined_info = Some(merge_quic_packet_info(combined_info, info));
        }

        // Move to next packet
        if packet_len == 0 {
            // Couldn't determine length, stop processing
            break;
        }
        offset += packet_len;
        packet_count += 1;

        // Safety limit - don't process more than 10 coalesced packets
        if packet_count >= 10 {
            debug!("QUIC: Reached coalesced packet limit (10), stopping");
            break;
        }
    }

    if packet_count > 1 {
        debug!(
            "QUIC: Processed {} coalesced packets in UDP datagram",
            packet_count
        );
    }

    combined_info
}

/// Merge QUIC info from multiple coalesced packets
/// Prefers more complete information (SNI without [PARTIAL], higher connection state, etc.)
fn merge_quic_packet_info(existing: Option<QuicInfo>, new: QuicInfo) -> QuicInfo {
    match existing {
        None => new,
        Some(mut existing) => {
            // Prefer higher connection state
            let existing_priority = match existing.connection_state {
                QuicConnectionState::Unknown => 0,
                QuicConnectionState::Initial => 1,
                QuicConnectionState::Handshaking => 2,
                QuicConnectionState::Connected => 3,
                QuicConnectionState::Draining => 4,
                QuicConnectionState::Closed => 5,
            };
            let new_priority = match new.connection_state {
                QuicConnectionState::Unknown => 0,
                QuicConnectionState::Initial => 1,
                QuicConnectionState::Handshaking => 2,
                QuicConnectionState::Connected => 3,
                QuicConnectionState::Draining => 4,
                QuicConnectionState::Closed => 5,
            };
            if new_priority > existing_priority {
                existing.connection_state = new.connection_state;
            }

            // Merge TLS info - prefer complete SNI over partial
            match (&existing.tls_info, &new.tls_info) {
                (None, Some(new_tls)) => {
                    existing.tls_info = Some(new_tls.clone());
                }
                (Some(old_tls), Some(new_tls)) => {
                    let old_is_partial = old_tls
                        .sni
                        .as_ref()
                        .map(|s| is_partial_sni(s))
                        .unwrap_or(true);
                    let new_is_partial = new_tls
                        .sni
                        .as_ref()
                        .map(|s| is_partial_sni(s))
                        .unwrap_or(true);

                    // Prefer complete SNI over partial, or any SNI over none
                    if (old_is_partial && !new_is_partial)
                        || (old_tls.sni.is_none() && new_tls.sni.is_some())
                    {
                        existing.tls_info = Some(new_tls.clone());
                    }
                }
                _ => {}
            }

            // Update connection ID if we have a better one
            if existing.connection_id.is_empty() && !new.connection_id.is_empty() {
                existing.connection_id = new.connection_id;
                existing.connection_id_hex = new.connection_id_hex;
            }

            // Update version if we didn't have it
            if existing.version_string.is_none() && new.version_string.is_some() {
                existing.version_string = new.version_string;
            }

            // Merge crypto reassembler if present
            if existing.crypto_reassembler.is_none() && new.crypto_reassembler.is_some() {
                existing.crypto_reassembler = new.crypto_reassembler;
            }

            existing
        }
    }
}

/// Parse a QUIC long header packet and return both the info and the packet length
/// This is needed for coalesced packet handling
fn parse_long_header_packet_with_length(payload: &[u8]) -> (Option<QuicInfo>, usize) {
    if payload.len() < 6 {
        return (None, 0);
    }

    let first_byte = payload[0];
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

    // Create QuicInfo with version
    let mut quic_info = QuicInfo::new(version);

    // Determine packet type
    let packet_type = if version == 0 {
        QuicPacketType::VersionNegotiation
    } else {
        get_long_packet_type(first_byte, version)
    };
    quic_info.packet_type = packet_type;

    // Parse connection IDs
    let mut offset = 5;

    // Destination Connection ID
    if offset >= payload.len() {
        debug!(
            "QUIC: Payload too short to read DCID length at offset {}",
            offset
        );
        return (None, 0);
    }
    let dcid_len = payload[offset] as usize;
    offset += 1;

    debug!(
        "QUIC: Parsing long header packet - version=0x{:08x}, DCID length={}",
        version, dcid_len
    );

    if offset + dcid_len > payload.len() {
        debug!(
            "QUIC: Payload too short for DCID, need {} bytes, have {}",
            offset + dcid_len,
            payload.len()
        );
        return (None, 0);
    }
    let dcid = payload[offset..offset + dcid_len].to_vec();
    quic_info.connection_id = dcid.clone();
    quic_info.connection_id_hex = None;
    offset += dcid_len;

    // Source Connection ID
    if offset >= payload.len() {
        debug!(
            "QUIC: Payload too short for SCID length at offset {}",
            offset
        );
        return (None, 0);
    }
    let scid_len = payload[offset] as usize;
    offset += 1;

    if offset + scid_len > payload.len() {
        debug!(
            "QUIC: Payload too short for SCID, need {} bytes, have {}",
            offset + scid_len,
            payload.len()
        );
        return (None, 0);
    }
    offset += scid_len;

    // For Initial packets, parse token length
    if packet_type == QuicPacketType::Initial {
        if let Some((token_len, bytes_read)) = parse_variable_length_int(&payload[offset..]) {
            offset += bytes_read;
            offset += token_len as usize; // Skip token
        } else {
            return (Some(quic_info), payload.len()); // Can't parse, assume rest of datagram
        }
    }

    // Parse packet length (variable-length integer)
    let packet_length =
        if let Some((pkt_len, bytes_read)) = parse_variable_length_int(&payload[offset..]) {
            offset += bytes_read;
            pkt_len as usize
        } else {
            // Can't parse packet length, assume rest of datagram
            return (Some(quic_info), payload.len());
        };

    // Total packet size = header (offset) + packet_length (includes pkt num + payload)
    let total_packet_size = offset + packet_length;

    debug!(
        "QUIC: Long header packet - header_len={}, packet_length={}, total={}",
        offset, packet_length, total_packet_size
    );

    // Now do the actual TLS extraction on this packet
    let packet_data = if total_packet_size <= payload.len() {
        &payload[..total_packet_size]
    } else {
        payload // Use what we have if packet extends beyond datagram
    };

    // Extract TLS info from this packet
    extract_tls_from_long_header_packet(packet_data, &mut quic_info, &dcid, version, packet_type);

    (Some(quic_info), total_packet_size.min(payload.len()))
}

/// Extract TLS information from a long header packet
fn extract_tls_from_long_header_packet(
    payload: &[u8],
    quic_info: &mut QuicInfo,
    dcid: &[u8],
    version: u32,
    packet_type: QuicPacketType,
) {
    let dcid_len = dcid.len();

    // Set connection state based on packet type
    quic_info.connection_state = match packet_type {
        QuicPacketType::Initial => QuicConnectionState::Initial,
        QuicPacketType::Handshake => QuicConnectionState::Handshaking,
        QuicPacketType::Retry => QuicConnectionState::Initial,
        QuicPacketType::VersionNegotiation => QuicConnectionState::Initial,
        QuicPacketType::ZeroRtt => QuicConnectionState::Handshaking,
        _ => QuicConnectionState::Unknown,
    };

    // NOTE: QUIC Initial and Handshake packets are ENCRYPTED using keys derived from the DCID.
    // We must decrypt them first before extracting TLS information.
    // Do NOT try to pattern-match on encrypted payload - it will give garbage results.

    // For Initial and Handshake packets, try to decrypt and extract TLS information
    // Focus on Client packets as they contain the SNI information
    match packet_type {
        QuicPacketType::Initial if dcid_len > 0 => {
            debug!("QUIC: Processing Initial packet with DCID len={}", dcid_len);
            // Try to decrypt as client packet first (most likely to have SNI)
            if let Some(decrypted_payload) = decrypt_client_initial_packet(payload, dcid, version) {
                debug!("QUIC: Successfully decrypted Client Initial packet");
                // Extract TLS info from decrypted payload using reassembly
                if let Some(tls_info) =
                    process_crypto_frames_in_packet(&decrypted_payload, quic_info)
                {
                    quic_info.tls_info = Some(tls_info);
                    // This is a Client Initial packet with crypto frames - mark it for connection tracking
                    if !dcid.is_empty() {
                        quic_info.connection_id_hex = Some(connection_id_to_hex(dcid));
                        debug!(
                            "QUIC: Marking Client Initial packet with DCID {} for connection tracking",
                            connection_id_to_hex(dcid)
                        );
                    }
                }
            } else if let Some(decrypted_payload) =
                decrypt_server_initial_packet(payload, dcid, version)
            {
                debug!("QUIC: Successfully decrypted Server Initial packet");
                // Server Initial rarely has SNI but may have ALPN or other TLS info
                if let Some(tls_info) =
                    process_crypto_frames_in_packet(&decrypted_payload, quic_info)
                {
                    quic_info.tls_info = Some(tls_info);
                }
            } else {
                debug!(
                    "QUIC: Failed to decrypt Initial packet (tried both client and server keys)"
                );
                debug!(
                    "QUIC: Packet details - DCID={:02x?}, version=0x{:08x}, payload_len={}",
                    dcid,
                    version,
                    payload.len()
                );
                // Cannot extract TLS info from encrypted payload - don't try pattern matching
            }
        }
        QuicPacketType::Handshake if dcid_len > 0 => {
            // Handshake packets are encrypted with handshake keys derived from the TLS handshake
            // We cannot decrypt these without the handshake secrets, so we skip TLS extraction
            debug!("QUIC: Processing Handshake packet - encrypted, cannot extract TLS info");
        }
        QuicPacketType::Initial => {
            debug!("QUIC: Initial packet has zero-length DCID - cannot derive decryption keys");
            debug!(
                "QUIC: Packet details - version=0x{:08x}, payload_len={}, packet_type={:?}",
                version,
                payload.len(),
                packet_type
            );
            // Cannot decrypt without DCID - don't try pattern matching on encrypted data
        }
        _ => {
            debug!(
                "QUIC: Packet type {:?} not processed for TLS extraction",
                packet_type
            );
        }
    }
}

/// Parse a QUIC short header packet
fn parse_short_header_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.is_empty() {
        return None;
    }

    // For short header, we don't have version info
    let mut quic_info = QuicInfo::new(0);
    quic_info.packet_type = QuicPacketType::OneRtt;
    quic_info.connection_state = QuicConnectionState::Connected;

    // For short header, connection ID length is not in the packet
    // We'll use common sizes (8 bytes) as a heuristic
    let dcid = if payload.len() >= 9 {
        payload[1..9].to_vec()
    } else {
        payload[1..].to_vec()
    };

    quic_info.connection_id = dcid.clone();
    // Short header packets are data packets - don't use for connection tracking
    quic_info.connection_id_hex = None;

    Some(quic_info)
}

/// Decrypt a QUIC Client Initial packet (prioritized for SNI extraction)
fn decrypt_client_initial_packet(packet: &[u8], dcid: &[u8], version: u32) -> Option<Vec<u8>> {
    let salt = if is_quic_v2(version) {
        INITIAL_SALT_V2
    } else {
        INITIAL_SALT_V1
    };

    // Derive initial secret using HKDF
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
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

/// Decrypt a QUIC Server Initial packet
fn decrypt_server_initial_packet(packet: &[u8], dcid: &[u8], version: u32) -> Option<Vec<u8>> {
    let salt = if is_quic_v2(version) {
        INITIAL_SALT_V2
    } else {
        INITIAL_SALT_V1
    };

    // Derive initial secret using HKDF
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let initial_secret = salt.extract(dcid);

    // Derive server initial secret
    let mut server_secret = [0u8; 32];
    if !derive_secret(&initial_secret, b"server in", &mut server_secret) {
        debug!("QUIC: Failed to derive server initial secret");
        return None;
    }

    debug!(
        "QUIC: Attempting server Initial decryption with DCID len={}",
        dcid.len()
    );

    // Try to decrypt as a server Initial packet
    let result = try_decrypt_initial_with_secret(packet, &server_secret, version);
    if result.is_none() {
        debug!("QUIC: Server Initial decryption failed");
    }
    result
}

/// Try to decrypt an Initial packet with a specific secret
fn try_decrypt_initial_with_secret(packet: &[u8], secret: &[u8], version: u32) -> Option<Vec<u8>> {
    // Derive key and IV for packet protection
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp_key = [0u8; 16];

    if !derive_packet_protection_key(secret, &mut key, version)
        || !derive_packet_protection_iv(secret, &mut iv, version)
        || !derive_header_protection_key(secret, &mut hp_key, version)
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
    offset += bytes_read + token_len as usize;

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
    let ciphertext_len = packet_payload_length as usize - pn_length;

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

/// Process all frames in a decrypted QUIC packet payload and extract CRYPTO frames
pub fn process_crypto_frames_in_packet(
    payload: &[u8],
    quic_info: &mut QuicInfo,
) -> Option<TlsInfo> {
    // Ensure we have a reassembler
    quic_info.ensure_reassembler();

    let mut offset = 0;
    let mut found_crypto_frames = false;

    while offset < payload.len() {
        let frame_type_byte = payload[offset];
        offset += 1;

        match frame_type_byte {
            0x00 => {
                // PADDING frame
                while offset < payload.len() && payload[offset] == 0x00 {
                    offset += 1;
                }
            }

            0x01 => {
                // PING frame
                debug!("QUIC: Found PING frame");
            }

            0x02 | 0x03 => {
                // ACK or ACK_ECN frame
                debug!("QUIC: Found ACK frame");

                // Parse and skip ACK frame fields
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let (ack_range_count, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                for _ in 0..ack_range_count {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }

                if frame_type_byte == 0x03 {
                    // ECN counts
                    for _ in 0..3 {
                        let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                        offset += bytes_read;
                    }
                }
            }

            0x04 => {
                // RESET_STREAM frame
                for _ in 0..3 {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }
            }

            0x05 => {
                // STOP_SENDING frame
                for _ in 0..2 {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }
            }

            0x06 => {
                // CRYPTO frame - this is what we're looking for!
                debug!("QUIC: Found CRYPTO frame");
                found_crypto_frames = true;
                quic_info.has_crypto_frame = true;

                let (crypto_offset, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let (crypto_length, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                debug!(
                    "QUIC: CRYPTO frame - offset={}, length={}",
                    crypto_offset, crypto_length
                );

                let crypto_len = crypto_length as usize;
                let available = (payload.len() - offset).min(crypto_len);

                if available > 0 {
                    let crypto_data = payload[offset..offset + available].to_vec();

                    if let Some(reassembler) = &mut quic_info.crypto_reassembler
                        && let Err(e) = reassembler.add_fragment(crypto_offset, crypto_data)
                    {
                        warn!("QUIC: Failed to add CRYPTO fragment: {}", e);
                    }
                }

                offset += available;
            }

            0x07 => {
                // NEW_TOKEN frame
                let (token_length, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read + token_length as usize;
            }

            0x08..=0x0f => {
                // STREAM frames
                let has_offset = (frame_type_byte & 0x04) != 0;
                let has_length = (frame_type_byte & 0x02) != 0;

                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                if has_offset {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }

                let stream_data_len = if has_length {
                    let (length, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                    length as usize
                } else {
                    payload.len() - offset
                };

                offset += stream_data_len;
            }

            0x10..=0x17 => {
                // Various MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED frames
                let num_vars = match frame_type_byte {
                    0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 => 1,
                    0x11 | 0x15 => 2,
                    _ => 0,
                };

                for _ in 0..num_vars {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }
            }

            0x18 => {
                // NEW_CONNECTION_ID frame
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                if offset >= payload.len() {
                    break;
                }
                let cid_length = payload[offset] as usize;
                offset += 1 + cid_length + 16; // CID + stateless reset token
            }

            0x19 => {
                // RETIRE_CONNECTION_ID frame
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;
            }

            0x1a | 0x1b => {
                // PATH_CHALLENGE or PATH_RESPONSE frame
                offset += 8;
            }

            0x1c | 0x1d => {
                // CONNECTION_CLOSE frame - extract detailed information
                let (error_code, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // 0x1c has an additional frame type field, 0x1d does not
                if frame_type_byte == 0x1c {
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }

                // Extract reason phrase if present
                let (reason_length, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                let reason =
                    if reason_length > 0 && offset + reason_length as usize <= payload.len() {
                        let reason_bytes = &payload[offset..offset + reason_length as usize];
                        String::from_utf8(reason_bytes.to_vec()).ok()
                    } else {
                        None
                    };
                offset += reason_length as usize;

                // Store CONNECTION_CLOSE information in quic_info
                quic_info.connection_close = Some(crate::network::types::QuicCloseInfo {
                    frame_type: frame_type_byte,
                    error_code,
                });

                // Update connection state based on close frame
                quic_info.connection_state = if error_code == 0 {
                    // NO_ERROR - graceful close, enter draining
                    crate::network::types::QuicConnectionState::Draining
                } else {
                    // Error close - connection is closed
                    crate::network::types::QuicConnectionState::Closed
                };

                debug!(
                    "QUIC: Detected CONNECTION_CLOSE frame type 0x{:02x}, error_code: {}, reason: {:?}",
                    frame_type_byte, error_code, reason
                );
            }

            0x1e => {
                // HANDSHAKE_DONE frame
                debug!("QUIC: Found HANDSHAKE_DONE frame");
            }

            _ => {
                warn!(
                    "QUIC: Unknown frame type 0x{:02x}, stopping",
                    frame_type_byte
                );
                break;
            }
        }

        if offset > payload.len() {
            warn!("QUIC: Frame parsing exceeded payload length");
            break;
        }
    }

    if found_crypto_frames
        && let Some(reassembler) = &mut quic_info.crypto_reassembler
        && let Some(tls_info) = try_extract_tls_from_reassembler(reassembler, false)
    {
        debug!(
            "QUIC: Successfully extracted TLS info: SNI={:?}",
            tls_info.sni
        );
        quic_info.tls_info = Some(tls_info.clone());
        return Some(tls_info);
    }

    None
}

/// Check if SNI is complete (not partial)
fn is_complete_sni(sni: &Option<String>) -> bool {
    match sni {
        Some(s) => !is_partial_sni(s),
        None => false,
    }
}

/// Strategy 1: Try to extract TLS info from contiguous reassembled data
fn try_extract_from_contiguous(
    reassembler: &CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    let reassembled = reassembler.get_contiguous_data()?;

    debug!(
        "QUIC: Attempting to parse {} bytes of contiguous crypto data (allow_partial={})",
        reassembled.len(),
        allow_partial
    );

    // Only attempt to parse if we have enough data for a reasonable ClientHello
    // Use lower threshold (50 bytes) when allowing partial extraction
    let threshold = if allow_partial { 50 } else { 100 };
    if reassembled.len() < threshold {
        debug!(
            "QUIC: Only {} contiguous bytes available, waiting for more data before parsing",
            reassembled.len()
        );
        return None;
    }

    let tls_info = parse_partial_tls_handshake(&reassembled, allow_partial)?;

    // Check if we have the essential info (SNI and ALPN)
    if tls_info.sni.is_none() && tls_info.alpn.is_empty() {
        return None;
    }

    let sni_is_complete = is_complete_sni(&tls_info.sni);
    debug!(
        "QUIC: Found TLS info from contiguous data (complete={})",
        sni_is_complete
    );
    Some(tls_info)
}

/// Strategy 2: Try to parse individual fragments with proper TLS headers
fn try_extract_from_fragments(
    reassembler: &CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    debug!("QUIC: Trying to parse individual crypto fragments with proper TLS headers");

    for (&offset, fragment_data) in reassembler.get_fragments() {
        debug!(
            "QUIC: Trying fragment at offset {} with {} bytes",
            offset,
            fragment_data.len()
        );

        // Only try to parse fragments that look like they contain complete TLS structures
        // Check if fragment starts with TLS handshake header (0x01 for ClientHello)
        if fragment_data.len() >= 4
            && fragment_data[0] == 0x01
            && let Some(tls_info) = parse_partial_tls_handshake(fragment_data, allow_partial)
            && (tls_info.sni.is_some() || !tls_info.alpn.is_empty())
        {
            let sni_is_complete = is_complete_sni(&tls_info.sni);
            debug!(
                "QUIC: Found TLS info from individual fragment at offset {} (complete={})",
                offset, sni_is_complete
            );
            return Some(tls_info);
        }

        // Also try direct TLS pattern matching, but only for fragments that look like TLS records
        if fragment_data.len() >= 6
            && fragment_data[0] == 0x16
            && let Some(tls_info) = try_parse_unencrypted_crypto_frames(fragment_data)
            && (tls_info.sni.is_some() || !tls_info.alpn.is_empty())
        {
            let sni_is_complete = is_complete_sni(&tls_info.sni);
            debug!(
                "QUIC: Found TLS info from pattern matching in fragment at offset {} (complete={})",
                offset, sni_is_complete
            );
            return Some(tls_info);
        }

        debug!(
            "QUIC: Skipping fragment at offset {} - doesn't start with TLS header",
            offset
        );
    }

    None
}

/// Strategy 3: Try greedy SNI extraction from all fragments and contiguous data
fn try_extract_greedy_from_reassembler(reassembler: &CryptoFrameReassembler) -> Option<TlsInfo> {
    debug!("QUIC: Attempting greedy SNI extraction as final fallback");

    // Try greedy extraction on fragments
    for fragment_data in reassembler.get_fragments().values() {
        if let Some(sni) = try_extract_sni_greedy(fragment_data, true) {
            let mut tls_info = TlsInfo::new();
            tls_info.sni = Some(sni);
            debug!("QUIC: Greedy extraction succeeded from fragment");
            return Some(tls_info);
        }
    }

    // Also try on contiguous data if available
    if let Some(contiguous) = reassembler.get_contiguous_data()
        && let Some(sni) = try_extract_sni_greedy(&contiguous, true)
    {
        let mut tls_info = TlsInfo::new();
        tls_info.sni = Some(sni);
        debug!("QUIC: Greedy extraction succeeded from contiguous data");
        return Some(tls_info);
    }

    None
}

/// Try to extract TLS information from reassembled fragments
///
/// The `allow_partial` parameter controls whether partial SNI extraction is allowed:
/// - `false`: Only return complete SNI (used during initial packet parsing)
/// - `true`: Return partial SNI as fallback (used during merge/re-extraction)
///
/// This function orchestrates multiple extraction strategies in order of preference:
/// 1. Check cache for complete SNI
/// 2. Parse contiguous data
/// 3. Parse individual fragments with TLS headers
/// 4. Reconstruct SNI from fragmented data
/// 5. Greedy fallback extraction
pub fn try_extract_tls_from_reassembler(
    reassembler: &mut CryptoFrameReassembler,
    allow_partial: bool,
) -> Option<TlsInfo> {
    // Strategy 0: Check cache for complete SNI
    if let Some(tls_info) = reassembler.get_cached_tls_info() {
        if is_complete_sni(&tls_info.sni) {
            return Some(tls_info.clone());
        }
        debug!("QUIC: Cached SNI is partial, attempting to find complete SNI");
    }

    // Strategy 1: Try to parse contiguous data
    if let Some(tls_info) = try_extract_from_contiguous(reassembler, allow_partial) {
        if is_complete_sni(&tls_info.sni) {
            reassembler.set_complete_tls_info(tls_info.clone());
        }
        return Some(tls_info);
    }

    // Strategy 2: Try parsing individual fragments with TLS headers
    if let Some(tls_info) = try_extract_from_fragments(reassembler, allow_partial) {
        if is_complete_sni(&tls_info.sni) {
            reassembler.set_complete_tls_info(tls_info.clone());
        }
        return Some(tls_info);
    }

    // Strategy 3: Try fragment reconstruction (requires reasonable data amount)
    let total_fragment_size: usize = reassembler.get_fragments().values().map(|v| v.len()).sum();
    if total_fragment_size >= 100 {
        debug!(
            "QUIC: Have {} total bytes in fragments, attempting reconstruction",
            total_fragment_size
        );
        if let Some(sni) = try_reconstruct_sni_from_fragments(reassembler) {
            let mut tls_info = TlsInfo::new();
            let sni_is_complete = !is_partial_sni(&sni);
            tls_info.sni = Some(sni);
            debug!(
                "QUIC: Reconstructed SNI from fragmented data (complete={})",
                sni_is_complete
            );
            if sni_is_complete {
                reassembler.set_complete_tls_info(tls_info.clone());
            }
            return Some(tls_info);
        }
    } else {
        debug!(
            "QUIC: Only {} total bytes in fragments, not enough for reliable SNI extraction",
            total_fragment_size
        );
    }

    // Strategy 4: Greedy fallback extraction
    if let Some(tls_info) = try_extract_greedy_from_reassembler(reassembler) {
        reassembler.set_complete_tls_info(tls_info.clone());
        return Some(tls_info);
    }

    debug!("QUIC: No TLS info could be extracted from reassembler");
    None
}

/// Parse a TLS handshake from reassembled data
fn parse_partial_tls_handshake(data: &[u8], allow_partial: bool) -> Option<TlsInfo> {
    if data.len() < 4 {
        debug!("QUIC: TLS handshake data too short: {} bytes", data.len());
        return None;
    }

    let handshake_type = data[0];
    let handshake_length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    debug!(
        "QUIC: TLS handshake type=0x{:02x}, declared_length={}, available_data={}, allow_partial={}",
        handshake_type,
        handshake_length,
        data.len() - 4,
        allow_partial
    );

    let mut info = TlsInfo::new();

    let available_data = &data[4..];
    let parse_length = handshake_length.min(available_data.len());

    // Sanity check the handshake length
    if handshake_length > 65536 {
        debug!(
            "QUIC: Handshake length {} seems too large, skipping",
            handshake_length
        );
        return None;
    }

    match handshake_type {
        0x01 => {
            // Client Hello
            debug!("QUIC: Parsing ClientHello with {} bytes", parse_length);
            parse_partial_client_hello(&available_data[..parse_length], &mut info, allow_partial);
        }
        0x02 => {
            // Server Hello
            debug!("QUIC: Parsing ServerHello with {} bytes", parse_length);
            parse_partial_server_hello(&available_data[..parse_length], &mut info);
        }
        _ => {
            debug!(
                "QUIC: Unknown/unsupported handshake type: 0x{:02x}",
                handshake_type
            );
            return None;
        }
    }

    debug!(
        "QUIC: Parsed TLS info - SNI={:?}, ALPN={:?}, version={:?}",
        info.sni, info.alpn, info.version
    );

    if info.sni.is_some() || !info.alpn.is_empty() || info.version.is_some() {
        Some(info)
    } else {
        debug!("QUIC: No useful TLS info extracted");
        None
    }
}

/// Parse a partial Client Hello
fn parse_partial_client_hello(data: &[u8], info: &mut TlsInfo, allow_partial: bool) {
    debug!(
        "QUIC: Parsing ClientHello with {} bytes (allow_partial={})",
        data.len(),
        allow_partial
    );

    if data.len() < 34 {
        debug!(
            "QUIC: ClientHello too short: {} bytes (need at least 34)",
            data.len()
        );
        return;
    }

    // Skip version (2) + random (32)
    let mut offset = 34;
    debug!(
        "QUIC: ClientHello - skipping version and random, offset now={}",
        offset
    );

    // Session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > data.len() {
        return;
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if offset >= data.len() {
        return;
    }

    // Compression methods
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    if offset + 2 > data.len() {
        return;
    }

    // Extensions
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    debug!(
        "QUIC: ClientHello extensions - declared_len={}, available_data={}",
        extensions_len,
        data.len() - offset
    );

    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        debug!("QUIC: Parsing {} bytes of extensions", available_ext_len);
        parse_tls_extensions(
            &data[offset..offset + available_ext_len],
            info,
            true,
            allow_partial,
        );
    } else {
        debug!("QUIC: No extensions data available");
    }
}

/// Parse a partial Server Hello
fn parse_partial_server_hello(data: &[u8], info: &mut TlsInfo) {
    if data.len() < 34 {
        return;
    }

    // Skip version (2) + random (32)
    let mut offset = 34;

    // Session ID
    if offset >= data.len() {
        return;
    }
    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > data.len() {
        return;
    }

    // Cipher suite
    let cipher = u16::from_be_bytes([data[offset], data[offset + 1]]);
    info.cipher_suite = Some(cipher);
    offset += 2;

    // Compression method
    if offset >= data.len() {
        return;
    }
    offset += 1;

    // Extensions
    if offset + 2 > data.len() {
        return;
    }

    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        parse_tls_extensions(
            &data[offset..offset + available_ext_len],
            info,
            false,
            false,
        );
    }
}

/// Parse TLS extensions
fn parse_tls_extensions(data: &[u8], info: &mut TlsInfo, is_client: bool, allow_partial: bool) {
    let mut offset = 0;
    debug!(
        "QUIC: Parsing {} bytes of TLS extensions (is_client={}, allow_partial={})",
        data.len(),
        is_client,
        allow_partial
    );

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        debug!(
            "QUIC: Extension type=0x{:04x}, length={}",
            ext_type, ext_len
        );

        if offset + 4 + ext_len > data.len() {
            // Extension data is incomplete
            if allow_partial && ext_type == 0x0000 && is_client {
                // Try to extract partial SNI as fallback
                let available_ext_len = data.len() - offset - 4;
                if available_ext_len > 5 {
                    debug!(
                        "QUIC: SNI extension is incomplete (need {} bytes, have {}), attempting partial extraction",
                        ext_len, available_ext_len
                    );
                    let ext_data = &data[offset + 4..];
                    if let Some(sni) = parse_sni_extension(ext_data, true) {
                        debug!("QUIC: Extracted partial SNI as fallback: {}", sni);
                        info.sni = Some(sni);
                    }
                }
            } else {
                debug!(
                    "QUIC: Extension 0x{:04x} is incomplete (need {} bytes, have {}), waiting for more data",
                    ext_type,
                    ext_len,
                    data.len() - offset - 4
                );
            }
            break;
        }

        let ext_data = &data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            0x0000 if is_client => {
                // SNI
                debug!("QUIC: Found SNI extension with {} bytes", ext_len);
                if let Some(sni) = parse_sni_extension(ext_data, allow_partial) {
                    debug!("QUIC: Successfully parsed SNI: {}", sni);
                    info.sni = Some(sni);
                } else {
                    debug!("QUIC: Failed to parse SNI extension");
                }
            }
            0x0010 => {
                // ALPN
                debug!("QUIC: Found ALPN extension with {} bytes", ext_len);
                if let Some(alpn) = parse_alpn_extension(ext_data) {
                    debug!("QUIC: Successfully parsed ALPN: {:?}", alpn);
                    info.alpn = alpn;
                } else {
                    debug!("QUIC: Failed to parse ALPN extension");
                }
            }
            0x002b => {
                // Supported Versions
                debug!(
                    "QUIC: Found Supported Versions extension with {} bytes",
                    ext_len
                );
                if let Some(version) = parse_supported_versions(ext_data, is_client) {
                    debug!("QUIC: Successfully parsed version: {:?}", version);
                    info.version = Some(version);
                }
            }
            _ => {
                debug!("QUIC: Skipping unknown extension type 0x{:04x}", ext_type);
            }
        }

        offset += 4 + ext_len;
    }

    debug!(
        "QUIC: Finished parsing extensions - found SNI={:?}, ALPN={:?}",
        info.sni, info.alpn
    );
}

/// Parse SNI extension
fn parse_sni_extension(data: &[u8], allow_partial: bool) -> Option<String> {
    debug!(
        "QUIC: Parsing SNI extension with {} bytes (allow_partial={}): {:02x?}",
        data.len(),
        allow_partial,
        &data[..data.len().min(20)]
    );

    // Parse the SNI header using the unified helper
    let header = match parse_sni_header(data) {
        Some(h) => h,
        None => {
            debug!(
                "QUIC: Failed to parse SNI header (data len: {})",
                data.len()
            );
            return None;
        }
    };

    debug!(
        "QUIC: SNI header - list_len: {}, name_len: {}",
        header.list_len, header.name_len
    );

    let name_len = header.name_len as usize;
    let hostname_start = 5; // After header (2 + 1 + 2 bytes)

    if hostname_start + name_len <= data.len() {
        // Full hostname available
        let sni_data = &data[hostname_start..hostname_start + name_len];
        debug!("QUIC: SNI data: {:02x?}", sni_data);

        match std::str::from_utf8(sni_data) {
            Ok(sni) => {
                if is_valid_hostname(sni) {
                    debug!("QUIC: Successfully parsed complete SNI: {}", sni);
                    Some(sni.to_string())
                } else {
                    debug!("QUIC: SNI doesn't look like a valid hostname: {}", sni);
                    None
                }
            }
            Err(e) => {
                debug!("QUIC: SNI data is not valid UTF-8: {}", e);
                None
            }
        }
    } else if allow_partial && data.len() > hostname_start {
        // Extract partial SNI as fallback when allowed
        let available = &data[hostname_start..];
        debug!(
            "QUIC: SNI name extends beyond available data (need {}, have {}), extracting partial",
            hostname_start + name_len,
            data.len()
        );

        if let Ok(partial) = std::str::from_utf8(available)
            && is_valid_partial_hostname(partial)
        {
            debug!("QUIC: Extracted partial SNI: {}", mark_partial_sni(partial));
            return Some(mark_partial_sni(partial));
        }
        None
    } else {
        // SNI data is incomplete - don't extract partial, wait for more data
        debug!(
            "QUIC: SNI name extends beyond available data (need {}, have {}), waiting for more data",
            hostname_start + name_len,
            data.len()
        );
        None
    }
}

/// Parse ALPN extension
fn parse_alpn_extension(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut protocols = Vec::new();
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    let mut offset = 2;
    let list_end = 2 + alpn_len.min(data.len() - 2);

    while offset < list_end && offset < data.len() {
        let proto_len = data[offset] as usize;
        offset += 1;

        if offset + proto_len <= data.len()
            && let Ok(proto) = std::str::from_utf8(&data[offset..offset + proto_len])
        {
            protocols.push(proto.to_string());
        }

        offset += proto_len;
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
    }
}

/// Greedy SNI extraction - scans raw data for SNI extension pattern
/// This works even when full ClientHello parsing fails due to incomplete data
///
/// The `allow_partial` parameter controls whether partial SNI extraction is allowed:
/// - `false`: Only return complete SNI
/// - `true`: Return partial SNI as fallback when full hostname is truncated
fn try_extract_sni_greedy(data: &[u8], allow_partial: bool) -> Option<String> {
    // SNI extension structure:
    // 0x00 0x00 - extension type (SNI)
    // 2 bytes - extension length
    // 2 bytes - server name list length
    // 0x00 - name type (hostname)
    // 2 bytes - hostname length
    // N bytes - hostname

    if data.len() < 9 {
        return None;
    }

    // Scan for SNI extension type pattern (0x00 0x00)
    for i in 0..data.len().saturating_sub(9) {
        // Look for SNI extension type marker
        if data[i] == 0x00 && data[i + 1] == 0x00 {
            // Read extension length
            if i + 4 > data.len() {
                continue;
            }
            let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;

            // Sanity check extension length (5-300 bytes is reasonable for SNI)
            if !(5..=300).contains(&ext_len) {
                continue;
            }

            // Parse SNI header using unified helper
            let sni_data = &data[i + 4..];
            let header = match parse_sni_header(sni_data) {
                Some(h) => h,
                None => continue,
            };

            // List length should be <= ext_len - 2
            if header.list_len as usize > ext_len {
                continue;
            }

            let name_len = header.name_len as usize;
            let hostname_start = i + 9; // After: ext_type(2) + ext_len(2) + list_len(2) + name_type(1) + name_len(2)
            let hostname_end = hostname_start + name_len;

            if hostname_end <= data.len() {
                // Full hostname available
                if let Ok(hostname) = std::str::from_utf8(&data[hostname_start..hostname_end])
                    && is_valid_hostname(hostname)
                {
                    debug!("QUIC: Greedy SNI extraction found: {}", hostname);
                    return Some(hostname.to_string());
                }
            } else if allow_partial && hostname_start < data.len() {
                // Partial hostname available - extract what we have (only if allowed)
                if let Ok(partial) = std::str::from_utf8(&data[hostname_start..])
                    && is_valid_partial_hostname(partial)
                {
                    debug!(
                        "QUIC: Greedy SNI extraction found partial: {}",
                        mark_partial_sni(partial)
                    );
                    return Some(mark_partial_sni(partial));
                }
            }
        }
    }

    None
}

/// Parse supported versions extension
fn parse_supported_versions(data: &[u8], is_client: bool) -> Option<TlsVersion> {
    if is_client {
        if data.is_empty() {
            return None;
        }

        let list_len = data[0] as usize;
        let mut offset = 1;

        while offset + 1 < data.len() && offset < 1 + list_len {
            if data[offset] == 0x03 && data[offset + 1] == 0x04 {
                return Some(TlsVersion::Tls13);
            }
            offset += 2;
        }
    } else if data.len() >= 2 && data[0] == 0x03 && data[1] == 0x04 {
        return Some(TlsVersion::Tls13);
    }

    // QUIC always uses TLS 1.3
    Some(TlsVersion::Tls13)
}

/// Parse a variable-length integer (QUIC encoding)
fn parse_variable_length_int(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let first_byte = data[0];
    let len = match first_byte >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => return None,
    };

    if data.len() < len {
        return None;
    }

    let value = match len {
        1 => (first_byte & 0x3f) as u64,
        2 => {
            let val = u16::from_be_bytes([data[0] & 0x3f, data[1]]);
            val as u64
        }
        4 => {
            let val = u32::from_be_bytes([data[0] & 0x3f, data[1], data[2], data[3]]);
            val as u64
        }
        8 => u64::from_be_bytes([
            data[0] & 0x3f,
            data[1],
            data[2],
            data[3],
            data[4],
            data[5],
            data[6],
            data[7],
        ]),
        _ => return None,
    };

    Some((value, len))
}

/// Get QUIC packet type from long header
fn get_long_packet_type(first_byte: u8, version: u32) -> QuicPacketType {
    let type_bits = (first_byte & 0x30) >> 4;

    if is_quic_v2(version) {
        // QUIC v2 has different type mappings
        match type_bits {
            0 => QuicPacketType::Retry,
            1 => QuicPacketType::Initial,
            2 => QuicPacketType::ZeroRtt,
            3 => QuicPacketType::Handshake,
            _ => QuicPacketType::Unknown,
        }
    } else {
        // QUIC v1 and drafts
        match type_bits {
            0 => QuicPacketType::Initial,
            1 => QuicPacketType::ZeroRtt,
            2 => QuicPacketType::Handshake,
            3 => QuicPacketType::Retry,
            _ => QuicPacketType::Unknown,
        }
    }
}

/// Check if version is QUIC v2
fn is_quic_v2(version: u32) -> bool {
    version == 0x6b3343cf
}

/// Derive a secret using HKDF
fn derive_secret(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> bool {
    let info = build_hkdf_label(label, &[], out.len());

    prk.expand(&[&info], ArbitraryOutputLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .is_ok()
}

/// Derive packet protection key
fn derive_packet_protection_key(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 key"
    } else {
        b"quic key"
    };
    derive_secret(&prk, label, out)
}

/// Derive packet protection IV
fn derive_packet_protection_iv(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 iv"
    } else {
        b"quic iv"
    };
    derive_secret(&prk, label, out)
}

/// Derive header protection key
fn derive_header_protection_key(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 hp"
    } else {
        b"quic hp"
    };
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
fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    use aes::cipher::generic_array::GenericArray;

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut output = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut output);

    let mut result = [0u8; 16];
    result.copy_from_slice(&output);
    Some(result)
}

/// Convert connection ID to hex string
fn connection_id_to_hex(id: &[u8]) -> String {
    id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}

/// Check if a packet is likely a QUIC packet
pub fn is_quic_packet(payload: &[u8]) -> bool {
    if payload.len() < 5 {
        return false;
    }

    let first_byte = payload[0];

    // Check for QUIC long header (bit 7 set)
    if (first_byte & 0x80) != 0 {
        // Check version
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

        // Check for known QUIC versions
        let known_versions = [
            0x00000001, // QUIC v1 (RFC 9000)
            0x6b3343cf, // QUIC v2
            0xff00001d, // draft-29
            0xff00001c, // draft-28
            0xff00001b, // draft-27
            0x51303530, // Google QUIC Q050
            0x51303433, // Google QUIC Q043
            0x54303530, // Google T050
            0xfaceb001, // Facebook mvfst draft-22
            0xfaceb002, // Facebook mvfst draft-27
            0,          // Version negotiation
        ];

        if known_versions.contains(&version) {
            return true;
        }

        // Check for IETF draft versions (0xff0000XX)
        if (version >> 8) == 0xff0000 {
            return true;
        }

        // Check for forcing version negotiation pattern
        if (version & 0x0F0F0F0F) == 0x0a0a0a0a {
            return true;
        }
    }

    // Short header packet detection
    // Bit 7 is 0, bit 6 is 1 for short header (fixed bit)
    if (first_byte & 0xc0) == 0x40 {
        // Additional heuristics for short header
        return payload.len() >= 20 && payload.len() <= 1500;
    }

    false
}

/// Try to extract TLS information from unencrypted parts of QUIC packets
/// Some QUIC implementations may have plaintext or partially encrypted data
fn try_parse_unencrypted_crypto_frames(payload: &[u8]) -> Option<TlsInfo> {
    // This is a best-effort attempt to find TLS ClientHello in the packet
    // Look for TLS handshake patterns in the payload

    debug!(
        "QUIC: Searching for unencrypted TLS data in {} byte payload",
        payload.len()
    );

    let mut offset = 0;
    while offset + 10 < payload.len() {
        // Need at least 10 bytes for meaningful TLS data
        // Look for TLS handshake record header (0x16 0x03 0x01-0x04)
        if payload[offset] == 0x16 && offset + 5 < payload.len() {
            let tls_version_major = payload[offset + 1];
            let tls_version_minor = payload[offset + 2];

            // Check for reasonable TLS version (3.1 = TLS 1.0, 3.2 = TLS 1.1, 3.3 = TLS 1.2, 3.4 = TLS 1.3)
            if tls_version_major == 0x03 && (0x01..=0x04).contains(&tls_version_minor) {
                let record_length =
                    u16::from_be_bytes([payload[offset + 3], payload[offset + 4]]) as usize;

                debug!(
                    "QUIC: Found TLS record at offset {} with length {}",
                    offset, record_length
                );

                if offset + 5 + record_length <= payload.len() {
                    let handshake_data = &payload[offset + 5..offset + 5 + record_length];

                    // Check if this is a ClientHello (handshake type 0x01)
                    if !handshake_data.is_empty() && handshake_data[0] == 0x01 {
                        debug!("QUIC: Found potential TLS ClientHello at offset {}", offset);

                        if let Some(tls_info) = parse_partial_tls_handshake(handshake_data, false) {
                            debug!(
                                "QUIC: Successfully parsed TLS from unencrypted data - SNI={:?}",
                                tls_info.sni
                            );
                            return Some(tls_info);
                        }
                    }
                }
            }
        }

        // Also try looking for direct handshake data (without TLS record wrapper)
        if payload[offset] == 0x01 && offset + 4 < payload.len() {
            // Direct handshake message starting with ClientHello (0x01)
            let handshake_length = u32::from_be_bytes([
                0,
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]) as usize;

            // Sanity check the length
            if handshake_length > 0
                && handshake_length < 65536
                && offset + 4 + handshake_length <= payload.len()
            {
                debug!(
                    "QUIC: Found potential direct handshake at offset {} with length {}",
                    offset, handshake_length
                );

                if let Some(tls_info) = parse_partial_tls_handshake(
                    &payload[offset..offset + 4 + handshake_length],
                    false,
                ) {
                    debug!(
                        "QUIC: Successfully parsed TLS from direct handshake - SNI={:?}",
                        tls_info.sni
                    );
                    return Some(tls_info);
                }
            }
        }

        // Look for SNI extension pattern directly (0x00 0x00 for SNI type)
        // Add strict validation to reduce false positives from encrypted data
        if offset + 20 < payload.len() && payload[offset] == 0x00 && payload[offset + 1] == 0x00 {
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;

            // Strict validation: reasonable extension length
            if (5..=300).contains(&ext_len) && offset + 4 + ext_len <= payload.len() {
                let ext_data = &payload[offset + 4..offset + 4 + ext_len];

                // Pre-validate SNI structure before parsing
                if ext_data.len() >= 5 {
                    let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                    let sni_type = ext_data[2];
                    let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;

                    // Only parse if structure looks valid
                    if sni_type == 0x00
                        && name_len > 0
                        && name_len <= 253
                        && (3..=256).contains(&list_len)
                        && list_len == name_len + 3
                        && let Some(sni) = parse_sni_extension(ext_data, false)
                    {
                        debug!("QUIC: Found SNI directly in packet: {}", sni);
                        let mut tls_info = TlsInfo::new();
                        tls_info.sni = Some(sni);
                        return Some(tls_info);
                    }
                }
            }
        }

        // Look for ALPN extension pattern (0x00 0x10 for ALPN type)
        if offset + 10 < payload.len() && payload[offset] == 0x00 && payload[offset + 1] == 0x10 {
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;
            if ext_len > 2 && offset + 4 + ext_len <= payload.len() {
                let ext_data = &payload[offset + 4..offset + 4 + ext_len];
                if let Some(alpn) = parse_alpn_extension(ext_data) {
                    debug!("QUIC: Found ALPN directly in packet: {:?}", alpn);
                    let mut tls_info = TlsInfo::new();
                    tls_info.alpn = alpn;
                    return Some(tls_info);
                }
            }
        }

        offset += 1;
    }

    debug!("QUIC: No unencrypted TLS data found in packet");
    None
}

/// Wrapper for HKDF expand with arbitrary output length
struct ArbitraryOutputLen(usize);

impl hkdf::KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Try to reconstruct SNI from fragmented crypto data
/// This looks for hostname patterns across fragment boundaries
fn try_reconstruct_sni_from_fragments(reassembler: &CryptoFrameReassembler) -> Option<String> {
    debug!("QUIC: Attempting SNI reconstruction from fragments");

    let fragments = reassembler.get_fragments();
    let mut sorted_offsets: Vec<_> = fragments.keys().collect();
    sorted_offsets.sort();

    // First try: look for SNI extension patterns in individual fragments and reconstruct
    // IMPORTANT: Only look in fragments that include the beginning of the ClientHello
    // Otherwise we might find partial SNI data that's cut off at fragment boundaries
    for &offset in &sorted_offsets {
        // Skip fragments that don't start near the beginning of the ClientHello
        // The SNI extension typically appears after ~70-150 bytes in the ClientHello
        if *offset > 200 {
            debug!(
                "QUIC: Skipping fragment at offset {} - too far from ClientHello start",
                offset
            );
            continue;
        }

        if let Some(data) = fragments.get(offset) {
            debug!(
                "QUIC: Scanning fragment at offset {} ({} bytes) for SNI patterns",
                offset,
                data.len()
            );

            // Look for SNI extension header patterns in this fragment
            // Be more restrictive to avoid false positives from encrypted data
            let mut i = 0;
            while i + 10 < data.len() {
                // Look for SNI extension: 0x00 0x00 (extension type) followed by length
                if data[i] == 0x00 && data[i + 1] == 0x00 {
                    let ext_len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;

                    // SNI extension length should be reasonable (5-300 bytes typically)
                    if (5..=300).contains(&ext_len) {
                        // Check if we have full extension data or partial
                        let available_ext_data = if i + 4 + ext_len <= data.len() {
                            &data[i + 4..i + 4 + ext_len]
                        } else {
                            &data[i + 4..]
                        };

                        // Parse SNI header using unified helper
                        if let Some(header) = parse_sni_header(available_ext_data) {
                            // Additional validation: list_len should be reasonable
                            if (3..=256).contains(&(header.list_len as usize)) {
                                // Try to parse with partial extraction allowed
                                if let Some(sni) = parse_sni_extension(available_ext_data, true) {
                                    if is_partial_sni(&sni) {
                                        debug!("QUIC: Found partial SNI in fragment: {}", sni);
                                    } else {
                                        debug!("QUIC: Found complete SNI in fragment: {}", sni);
                                    }
                                    return Some(sni);
                                }
                            }
                        }
                    }
                }
                i += 1;
            }
        }
    }

    // Second try: smart fragment combination - try to fill gaps and maintain order
    debug!("QUIC: Smart combining fragments for hostname pattern search");

    // Check if we have fragments that include the ClientHello beginning
    // We need at least one fragment starting at or very close to offset 0
    let has_beginning = sorted_offsets.iter().any(|&offset| *offset <= 10);

    if !has_beginning {
        debug!(
            "QUIC: No fragment near offset 0 (first at {:?}) - missing ClientHello beginning, skipping SNI extraction",
            sorted_offsets.first()
        );
        return None;
    }

    let mut all_data = Vec::new();
    let mut expected_offset = 0u64;
    let mut has_significant_gaps = false;

    for &offset in &sorted_offsets {
        if let Some(data) = fragments.get(offset) {
            debug!(
                "QUIC: Processing fragment at offset {} ({} bytes), expected offset was {}",
                offset,
                data.len(),
                expected_offset
            );

            // If there's a gap, be more careful about continuing
            if *offset > expected_offset {
                let gap_size = *offset - expected_offset;
                debug!("QUIC: Gap detected of {} bytes between fragments", gap_size);

                // Gaps in the first 100 bytes are critical as they likely contain SNI
                // The SNI extension typically appears between bytes 70-200 of the ClientHello
                // Relaxed threshold from 20 to 50 bytes to be less aggressive
                if expected_offset < 100 && gap_size > 50 {
                    has_significant_gaps = true;
                    debug!("QUIC: Gap in critical ClientHello region - SNI might be incomplete");
                }

                // Large gaps anywhere might indicate missing data
                // Relaxed threshold from 200 to 300 bytes
                if gap_size > 300 {
                    has_significant_gaps = true;
                    debug!(
                        "QUIC: Large gap detected ({} bytes) - data might be incomplete",
                        gap_size
                    );
                }

                // For smaller gaps, add minimal padding to maintain data alignment
                if gap_size <= 100 && !all_data.is_empty() {
                    // Add minimal padding to maintain structure
                    all_data.resize(all_data.len() + gap_size as usize, 0);
                    debug!("QUIC: Added {} bytes of padding for small gap", gap_size);
                }
            }

            all_data.extend_from_slice(data);
            expected_offset = *offset + data.len() as u64;
        }
    }

    if all_data.len() < 10 {
        debug!(
            "QUIC: Not enough data for SNI reconstruction ({} bytes)",
            all_data.len()
        );
        return None;
    }

    debug!(
        "QUIC: Searching for hostname patterns in {} bytes of combined data",
        all_data.len()
    );
    let candidates = find_hostname_candidates(&all_data);

    // Process candidates to detect truncation and mark incomplete ones
    let mut processed_candidates = Vec::new();

    // If we have significant gaps (missing fragments), don't trust ANY hostname candidates
    // as they are likely incomplete or corrupted
    if has_significant_gaps {
        debug!("QUIC: Not returning any hostname candidates due to significant gaps in fragments");
        // We could still look for very long, complete-looking hostnames, but it's safer to wait
        for candidate in &candidates {
            // Only accept very long, complete-looking hostnames when gaps exist
            if candidate.len() >= 15 && candidate.matches('.').count() >= 2 {
                debug!(
                    "QUIC: Accepting long candidate '{}' despite gaps",
                    candidate
                );
                if is_valid_hostname(candidate) {
                    processed_candidates.push(candidate.clone());
                }
            } else {
                debug!(
                    "QUIC: Rejecting candidate '{}' due to fragment gaps",
                    candidate
                );
            }
        }
    } else {
        // No significant gaps - process normally
        // Only accept complete valid hostnames
        for candidate in candidates {
            if is_valid_hostname(&candidate) {
                processed_candidates.push(candidate);
            }
            // Don't try to mark truncated hostnames - wait for complete data
        }
    }

    // Sort by length (longer first) to prefer complete hostnames, but prioritize unmarked ones
    processed_candidates.sort_by(|a, b| {
        let a_is_partial = is_partial_sni(a) || a.contains("...");
        let b_is_partial = is_partial_sni(b) || b.contains("...");

        // Prefer complete hostnames over truncated/partial ones
        match (a_is_partial, b_is_partial) {
            (false, true) => std::cmp::Ordering::Less, // a is complete, prefer it
            (true, false) => std::cmp::Ordering::Greater, // b is complete, prefer it
            _ => b.len().cmp(&a.len()),                // both same type, prefer longer
        }
    });

    if let Some(candidate) = processed_candidates.first() {
        debug!("QUIC: Found hostname candidate: {}", candidate);
        return Some(candidate.clone());
    }

    None
}

/// Find potential hostname strings in binary data
fn find_hostname_candidates(data: &[u8]) -> Vec<String> {
    let mut candidates = Vec::new();

    let mut i = 0;
    while i < data.len() {
        // Look for sequences that might be hostnames
        if data[i].is_ascii_alphanumeric() {
            let mut end = i;
            let mut has_dot = false;
            let mut dot_count = 0;

            // Extend while we have valid hostname characters
            while end < data.len()
                && (data[end].is_ascii_alphanumeric() || data[end] == b'.' || data[end] == b'-')
            {
                if data[end] == b'.' {
                    has_dot = true;
                    dot_count += 1;
                }
                end += 1;
            }

            // Extract potential hostname if it looks reasonable
            if end > i + 3 && has_dot && dot_count <= 10 {
                // At least 4 chars with a dot, max 10 dots
                if let Ok(candidate) = String::from_utf8(data[i..end].to_vec()) {
                    // Clean up the candidate
                    let cleaned = candidate
                        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != '-');

                    // Additional validation: check for reasonable hostname structure
                    if !cleaned.is_empty()
                        && !cleaned.starts_with('.')
                        && !cleaned.ends_with('.')
                        && !cleaned.contains("..")
                    {
                        debug!("QUIC: Found hostname candidate: {}", cleaned);
                        candidates.push(cleaned.to_string());

                        // Also look for sub-patterns within longer strings
                        // This helps catch cases where we have "prefix.hostname.suffix"
                        let parts: Vec<&str> = cleaned.split('.').collect();
                        if parts.len() > 2 {
                            // Try combinations of consecutive parts
                            for start_idx in 0..parts.len() {
                                for end_idx in (start_idx + 2)..=parts.len() {
                                    let sub_candidate = parts[start_idx..end_idx].join(".");
                                    if sub_candidate != cleaned && sub_candidate.len() >= 4 {
                                        debug!(
                                            "QUIC: Found sub-hostname candidate: {}",
                                            sub_candidate
                                        );
                                        candidates.push(sub_candidate);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            i = end;
        } else {
            i += 1;
        }
    }

    // Remove duplicates while preserving order
    let mut unique_candidates = Vec::new();
    for candidate in candidates {
        if !unique_candidates.contains(&candidate) {
            unique_candidates.push(candidate);
        }
    }

    unique_candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SNI extension structure
    fn build_sni_extension(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3; // name_type (1) + name_len (2)
        let ext_len = list_len + 2; // list_len (2)

        let mut data = Vec::new();
        // Extension type: SNI (0x0000)
        data.push(0x00);
        data.push(0x00);
        // Extension length
        data.extend_from_slice(&ext_len.to_be_bytes());
        // Server name list length
        data.extend_from_slice(&list_len.to_be_bytes());
        // Name type: hostname (0x00)
        data.push(0x00);
        // Name length
        data.extend_from_slice(&name_len.to_be_bytes());
        // Hostname
        data.extend_from_slice(name_bytes);

        data
    }

    #[test]
    fn test_greedy_sni_extraction_complete() {
        let sni_ext = build_sni_extension("www.example.com");
        // allow_partial doesn't matter when full hostname is available
        let result = try_extract_sni_greedy(&sni_ext, false);
        assert_eq!(result, Some("www.example.com".to_string()));
    }

    #[test]
    fn test_greedy_sni_extraction_with_prefix() {
        // Add some random bytes before the SNI extension
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        data.extend(build_sni_extension("api.google.com"));
        let result = try_extract_sni_greedy(&data, false);
        assert_eq!(result, Some("api.google.com".to_string()));
    }

    #[test]
    fn test_greedy_sni_extraction_partial() {
        // Build partial SNI extension (hostname truncated)
        // With fragmented QUIC packets, we need to extract partial SNI
        let mut data = Vec::new();
        data.push(0x00); // ext type
        data.push(0x00);
        data.extend_from_slice(&20u16.to_be_bytes()); // ext_len (full would be 20)
        data.extend_from_slice(&18u16.to_be_bytes()); // list_len
        data.push(0x00); // name type
        data.extend_from_slice(&15u16.to_be_bytes()); // name_len (15 chars)
        data.extend_from_slice(b"www.examp"); // only 9 chars provided

        // With allow_partial=false, returns None
        let result = try_extract_sni_greedy(&data, false);
        assert_eq!(result, None);

        // With allow_partial=true, returns partial SNI
        let result = try_extract_sni_greedy(&data, true);
        assert_eq!(result, Some("www.examp[PARTIAL]".to_string()));
    }

    #[test]
    fn test_parse_sni_extension_complete() {
        // Build SNI extension data (without the extension type/length header)
        let hostname = "test.example.org";
        let name_bytes = hostname.as_bytes();
        let name_len = name_bytes.len() as u16;
        let list_len = name_len + 3;

        let mut data = Vec::new();
        data.extend_from_slice(&list_len.to_be_bytes());
        data.push(0x00); // name type
        data.extend_from_slice(&name_len.to_be_bytes());
        data.extend_from_slice(name_bytes);

        let result = parse_sni_extension(&data, false);
        assert_eq!(result, Some("test.example.org".to_string()));
    }

    #[test]
    fn test_parse_sni_extension_partial() {
        // Build partial SNI extension data
        let mut data = Vec::new();
        data.extend_from_slice(&20u16.to_be_bytes()); // list_len
        data.push(0x00); // name type
        data.extend_from_slice(&15u16.to_be_bytes()); // declared name_len
        data.extend_from_slice(b"example.co"); // only 10 chars

        // With allow_partial=false, returns None
        let result = parse_sni_extension(&data, false);
        assert_eq!(result, None);

        // With allow_partial=true, returns partial SNI
        let result = parse_sni_extension(&data, true);
        assert_eq!(result, Some("example.co[PARTIAL]".to_string()));
    }

    #[test]
    fn test_parse_alpn_extension() {
        // Build ALPN extension data (without the extension type/length header)
        let mut data = Vec::new();
        let protocols = vec!["h3", "h2"];

        let mut proto_list = Vec::new();
        for proto in &protocols {
            proto_list.push(proto.len() as u8);
            proto_list.extend_from_slice(proto.as_bytes());
        }

        data.extend_from_slice(&(proto_list.len() as u16).to_be_bytes());
        data.extend_from_slice(&proto_list);

        let result = parse_alpn_extension(&data);
        assert_eq!(result, Some(vec!["h3".to_string(), "h2".to_string()]));
    }

    #[test]
    fn test_is_valid_hostname() {
        assert!(is_valid_hostname("example.com"));
        assert!(is_valid_hostname("www.example.com"));
        assert!(is_valid_hostname("sub.domain.example.org"));
        assert!(is_valid_hostname("my-site.io"));

        // Invalid hostnames
        assert!(!is_valid_hostname("com")); // No dot
        assert!(!is_valid_hostname(".example.com")); // Starts with dot
        assert!(!is_valid_hostname("example.com.")); // Ends with dot
        assert!(!is_valid_hostname("-example.com")); // Starts with hyphen
        assert!(!is_valid_hostname("example..com")); // Consecutive dots
        assert!(!is_valid_hostname("ab")); // Too short
    }

    #[test]
    fn test_greedy_extraction_ignores_invalid_patterns() {
        // Data with 0x00 0x00 but invalid SNI structure
        let data = vec![0x00, 0x00, 0x00, 0x01, 0x00]; // ext_len = 1 (too short)
        let result = try_extract_sni_greedy(&data, true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_greedy_extraction_multiple_zeros() {
        // Data with multiple 0x00 0x00 sequences, only one valid
        let mut data = vec![0x00, 0x00, 0x00, 0x02, 0xFF]; // Invalid SNI
        data.extend(build_sni_extension("valid.example.com"));
        let result = try_extract_sni_greedy(&data, false);
        assert_eq!(result, Some("valid.example.com".to_string()));
    }
}
