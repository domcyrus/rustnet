use crate::network::types::{QuicConnectionState, QuicInfo, QuicPacketType, TlsInfo, TlsVersion};
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

pub fn parse_quic_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.is_empty() {
        return None;
    }

    let first_byte = payload[0];
    let is_long_header = (first_byte & 0x80) != 0;

    if is_long_header {
        parse_long_header_packet(payload)
    } else {
        parse_short_header_packet(payload)
    }
}

fn parse_long_header_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.len() < 6 {
        return None;
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
        return None;
    }
    let dcid_len = payload[offset] as usize;
    offset += 1;

    if offset + dcid_len > payload.len() {
        debug!(
            "QUIC: Payload too short for DCID, need {} bytes, have {}",
            offset + dcid_len,
            payload.len()
        );
        return None;
    }
    let dcid = payload[offset..offset + dcid_len].to_vec();
    quic_info.connection_id = dcid.clone();
    quic_info.connection_id_hex = if dcid.is_empty() {
        None
    } else {
        Some(quick_connection_id_to_hex(&dcid))
    };
    offset += dcid_len;

    // Source Connection ID
    if offset >= payload.len() {
        debug!(
            "QUIC: Payload too short for SCID length at offset {}",
            offset
        );
        return None;
    }
    let scid_len = payload[offset] as usize;
    offset += 1;

    if offset + scid_len > payload.len() {
        debug!(
            "QUIC: Payload too short for SCID, need {} bytes, have {}",
            offset + scid_len,
            payload.len()
        );
        return None;
    }
    offset += scid_len;

    // Set connection state based on packet type
    quic_info.connection_state = match packet_type {
        QuicPacketType::Initial => QuicConnectionState::Initial,
        QuicPacketType::Handshake => QuicConnectionState::Handshaking,
        QuicPacketType::Retry => QuicConnectionState::Initial,
        QuicPacketType::VersionNegotiation => QuicConnectionState::Initial,
        QuicPacketType::ZeroRtt => QuicConnectionState::Handshaking,
        _ => QuicConnectionState::Unknown,
    };

    // For Initial packets, try to decrypt and extract TLS information
    if packet_type == QuicPacketType::Initial && dcid_len > 0 {
        // Try to decrypt the Initial packet
        if let Some(decrypted_payload) = decrypt_initial_packet(payload, &dcid, version) {
            // Extract TLS info from decrypted payload
            if let Some(tls_info) = extract_tls_from_decrypted_initial(&decrypted_payload) {
                quic_info.tls_info = Some(tls_info);
                quic_info.has_crypto_frame = true;
            } else {
                warn!("QUIC: Failed to extract TLS info from decrypted payload");
            }
        } else {
            warn!("QUIC: Failed to decrypt Initial packet");
        }
    } else if packet_type == QuicPacketType::Initial {
        warn!("QUIC: Skipping decryption for Initial packet with zero-length DCID");
    }

    Some(quic_info)
}

fn decrypt_initial_packet(packet: &[u8], dcid: &[u8], version: u32) -> Option<Vec<u8>> {
    // Select the appropriate salt based on version
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

    // Try to decrypt as a client Initial packet
    if let Some(decrypted) = try_decrypt_initial_with_secret(packet, &client_secret, version) {
        return Some(decrypted);
    }

    // If that fails, try server initial secret
    let mut server_secret = [0u8; 32];
    if !derive_secret(&initial_secret, b"server in", &mut server_secret) {
        debug!("QUIC: Failed to derive server initial secret");
        return None;
    }

    if let Some(decrypted) = try_decrypt_initial_with_secret(packet, &server_secret, version) {
        return Some(decrypted);
    }

    debug!("QUIC: Failed to decrypt with both client and server keys");
    None
}

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
    let dcid_len = packet[offset] as usize;
    offset += 1 + dcid_len;

    // Skip SCID
    let scid_len = packet[offset] as usize;
    offset += 1 + scid_len;

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
    let mut nonce_bytes = iv.clone();
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

fn extract_tls_from_decrypted_initial(payload: &[u8]) -> Option<TlsInfo> {
    // Log first few bytes
    if !payload.is_empty() {
        let preview_len = payload.len().min(20);
        let preview: Vec<String> = payload[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        debug!("QUIC: Decrypted payload preview: {}", preview.join(" "));
    }

    // Collect all CRYPTO frame data - they may be fragmented
    let mut crypto_fragments: Vec<(u64, Vec<u8>)> = Vec::new();

    let mut offset = 0;
    while offset < payload.len() {
        let frame_type = payload[offset];
        offset += 1;

        match frame_type {
            0x00 => {
                // PADDING frame - skip
                while offset < payload.len() && payload[offset] == 0x00 {
                    offset += 1;
                }
            }
            0x01 => {
                // PING frame - no data
                debug!("QUIC: Found PING frame");
            }
            0x06 => {
                // CRYPTO frame
                debug!("QUIC: Found CRYPTO frame at offset {}", offset - 1);

                // Parse offset (variable-length integer)
                let (crypto_offset, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // Parse length (variable-length integer)
                let (crypto_length, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                debug!(
                    "QUIC: CRYPTO frame - offset={}, length={}",
                    crypto_offset, crypto_length
                );

                // Extract crypto data
                let crypto_len = crypto_length as usize;
                if offset + crypto_len > payload.len() {
                    debug!("QUIC: CRYPTO frame data truncated");
                    // Still collect what we have
                    let available = payload.len() - offset;
                    let crypto_data = payload[offset..offset + available].to_vec();
                    crypto_fragments.push((crypto_offset, crypto_data));
                    offset += available;
                    continue;
                }

                let crypto_data = payload[offset..offset + crypto_len].to_vec();
                crypto_fragments.push((crypto_offset, crypto_data));

                offset += crypto_len;
            }
            0x02 | 0x03 => {
                // ACK or ACK_ECN frame - need to parse properly to skip
                debug!("QUIC: Found ACK frame, attempting to parse");

                // Parse largest acknowledged
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // Parse ACK delay
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // Parse ACK range count
                let (ack_range_count, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // Parse first ACK range
                let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                offset += bytes_read;

                // Parse additional ACK ranges
                for _ in 0..ack_range_count {
                    // Gap
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                    // ACK range
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }

                // If ACK_ECN, parse ECN counts
                if frame_type == 0x03 {
                    // ECT(0) count
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                    // ECT(1) count
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                    // ECN-CE count
                    let (_, bytes_read) = parse_variable_length_int(&payload[offset..])?;
                    offset += bytes_read;
                }
            }
            _ => {
                warn!(
                    "QUIC: Unknown/unhandled frame type 0x{:02x}, stopping frame parsing",
                    frame_type
                );
                break; // Stop parsing frames, we don't know how to skip this one
            }
        }
    }

    if crypto_fragments.is_empty() {
        warn!("QUIC: No CRYPTO frames found in decrypted payload");
        return None;
    }

    // Sort fragments by offset
    crypto_fragments.sort_by_key(|f| f.0);

    // Try multiple strategies to extract TLS info
    let mut tls_info = TlsInfo::new();
    let mut found_info = false;

    // Strategy 1: Try to parse contiguous data from offset 0
    if crypto_fragments.iter().any(|f| f.0 == 0) {
        let reassembled = reassemble_contiguous_from_zero(&crypto_fragments);
        if !reassembled.is_empty() {
            debug!(
                "QUIC: Reassembled {} bytes from offset 0",
                reassembled.len()
            );
            if let Some(info) = parse_partial_tls_handshake(&reassembled) {
                tls_info = info;
                found_info = true;
            }
        }
    }

    // Strategy 2: If we don't have data from offset 0, try to extract what we can from fragments
    if !found_info {
        debug!("QUIC: No data from offset 0, attempting partial extraction from fragments");

        // Look for patterns in any fragment that might contain TLS extensions
        for (offset, data) in &crypto_fragments {
            debug!(
                "QUIC: Scanning fragment at offset {} ({} bytes)",
                offset,
                data.len()
            );

            // Try to find and parse TLS extensions even without full handshake
            if let Some(partial_info) = extract_tls_info_from_fragment(data) {
                // Merge any found information
                if partial_info.sni.is_some() && tls_info.sni.is_none() {
                    tls_info.sni = partial_info.sni;
                    found_info = true;
                }
                if !partial_info.alpn.is_empty() && tls_info.alpn.is_empty() {
                    tls_info.alpn = partial_info.alpn;
                    found_info = true;
                }
                if partial_info.version.is_some() && tls_info.version.is_none() {
                    tls_info.version = partial_info.version;
                    found_info = true;
                }
                if partial_info.cipher_suite.is_some() && tls_info.cipher_suite.is_none() {
                    tls_info.cipher_suite = partial_info.cipher_suite;
                    found_info = true;
                }
            }
        }
    }

    // Strategy 3: Store fragment information for potential future use
    if !found_info {
        // At least record that we found CRYPTO frames with specific offsets
        debug!(
            "QUIC: Found CRYPTO fragments at offsets: {:?}",
            crypto_fragments
                .iter()
                .map(|(o, d)| format!("{}:{}", o, d.len()))
                .collect::<Vec<_>>()
        );
    }

    if found_info {
        Some(tls_info)
    } else {
        // Return basic info indicating we found CRYPTO frames but couldn't parse them
        debug!(
            "QUIC: Found {} CRYPTO fragments but couldn't extract TLS info",
            crypto_fragments.len()
        );
        None
    }
}

fn reassemble_contiguous_from_zero(fragments: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut reassembled = Vec::new();
    let mut expected_offset = 0u64;

    for (offset, data) in fragments {
        if *offset == expected_offset {
            reassembled.extend_from_slice(data);
            expected_offset = offset + data.len() as u64;
        } else if *offset < expected_offset {
            // Overlapping data, skip the overlap
            let overlap = (expected_offset - offset) as usize;
            if overlap < data.len() {
                reassembled.extend_from_slice(&data[overlap..]);
                expected_offset = offset + data.len() as u64;
            }
        } else {
            // Gap in data - for now we stop, but we could continue and mark the gap
            debug!(
                "QUIC: Gap in CRYPTO data at offset {}, expected {}",
                offset, expected_offset
            );
            break;
        }
    }

    reassembled
}

fn parse_partial_tls_handshake(data: &[u8]) -> Option<TlsInfo> {
    if data.len() < 4 {
        debug!("QUIC: TLS handshake data too short: {} bytes", data.len());
        return None;
    }

    let handshake_type = data[0];
    let handshake_length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    debug!(
        "QUIC: TLS handshake type=0x{:02x}, length={}, available={}",
        handshake_type,
        handshake_length,
        data.len() - 4
    );

    let mut info = TlsInfo::new();

    // We might not have the full handshake, parse what we can
    let available_data = &data[4..];
    let parse_length = handshake_length.min(available_data.len());

    match handshake_type {
        0x01 => {
            // Client Hello
            debug!(
                "QUIC: Parsing partial Client Hello ({} bytes available)",
                parse_length
            );
            parse_partial_client_hello(&available_data[..parse_length], &mut info);
        }
        0x02 => {
            // Server Hello
            debug!(
                "QUIC: Parsing partial Server Hello ({} bytes available)",
                parse_length
            );
            parse_partial_server_hello(&available_data[..parse_length], &mut info);
        }
        _ => {
            warn!("QUIC: Unknown handshake type: 0x{:02x}", handshake_type);
            return None;
        }
    }

    if info.sni.is_some() || !info.alpn.is_empty() || info.version.is_some() {
        Some(info)
    } else {
        None
    }
}

fn parse_partial_client_hello(data: &[u8], info: &mut TlsInfo) {
    if data.len() < 34 {
        debug!("QUIC: Client Hello too short for basic parsing");
        // Even with truncated data, try to find patterns
        if let Some(partial_sni) = find_partial_sni_in_fragment(data) {
            info.sni = Some(partial_sni);
        }
        return;
    }

    // Skip version (2) + random (32)
    let mut offset = 34;

    // Session ID
    if offset >= data.len() {
        debug!("QUIC: Client Hello truncated at session ID");
        // Try to extract what we can from the available data
        if let Some(partial_sni) = find_partial_sni_in_fragment(&data[..offset]) {
            info.sni = Some(partial_sni);
        }
        return;
    }

    let session_id_len = data[offset] as usize;
    offset += 1 + session_id_len;

    if offset + 2 > data.len() {
        debug!("QUIC: Client Hello truncated before cipher suites");
        // Try to extract what we can from the available data
        if let Some(partial_sni) = find_partial_sni_in_fragment(data) {
            info.sni = Some(partial_sni);
        }
        return;
    }

    // Cipher suites
    let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    if offset >= data.len() {
        debug!("QUIC: Client Hello truncated before compression methods");
        if let Some(partial_sni) = find_partial_sni_in_fragment(data) {
            info.sni = Some(partial_sni);
        }
        return;
    }

    // Compression methods
    let compression_len = data[offset] as usize;
    offset += 1 + compression_len;

    if offset + 2 > data.len() {
        debug!("QUIC: Client Hello truncated before extensions");
        if let Some(partial_sni) = find_partial_sni_in_fragment(data) {
            info.sni = Some(partial_sni);
        }
        return;
    }

    // Extensions
    let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;

    // Parse as much of the extensions as we have
    let available_ext_len = (data.len() - offset).min(extensions_len);
    if available_ext_len > 0 {
        debug!(
            "QUIC: Parsing {} bytes of extensions (out of {})",
            available_ext_len, extensions_len
        );
        parse_tls_extensions_partial(&data[offset..offset + available_ext_len], info, true);
    }
}

fn parse_partial_server_hello(data: &[u8], info: &mut TlsInfo) {
    if data.len() < 34 {
        debug!("QUIC: Server Hello too short for basic parsing");
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
        parse_tls_extensions_partial(&data[offset..offset + available_ext_len], info, false);
    }
}

fn parse_tls_extensions_partial(data: &[u8], info: &mut TlsInfo, is_client: bool) {
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if offset + 4 + ext_len > data.len() {
            // Extension data is truncated, try to parse what we have
            let available = data.len() - offset - 4;
            debug!(
                "QUIC: Extension 0x{:04x} truncated, only {} of {} bytes available",
                ext_type, available, ext_len
            );

            if available > 0 {
                let ext_data = &data[offset + 4..];
                // Try to parse partial extension data
                match ext_type {
                    0x0000 if is_client => {
                        // SNI - might be able to get partial hostname
                        if let Some(sni) = parse_sni_extension_partial(ext_data) {
                            debug!("QUIC: Found partial SNI: {}", sni);
                            info.sni = Some(sni);
                        }
                    }
                    0x0010 => {
                        // ALPN - might get some protocols
                        if let Some(alpn) = parse_alpn_extension_partial(ext_data) {
                            debug!("QUIC: Found partial ALPN: {:?}", alpn);
                            info.alpn = alpn;
                        }
                    }
                    _ => {}
                }
            }
            break;
        }

        let ext_data = &data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            0x0000 if is_client => {
                // SNI
                if let Some(sni) = parse_sni_extension(ext_data) {
                    debug!("QUIC: Found SNI: {}", sni);
                    info.sni = Some(sni);
                }
            }
            0x0010 => {
                // ALPN
                if let Some(alpn) = parse_alpn_extension(ext_data) {
                    debug!("QUIC: Found ALPN: {:?}", alpn);
                    info.alpn = alpn;
                }
            }
            0x002b => {
                // Supported Versions
                if let Some(version) = parse_supported_versions(ext_data, is_client) {
                    info.version = Some(version);
                }
            }
            _ => {}
        }

        offset += 4 + ext_len;
    }
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // Skip list length (2 bytes) and type (1 byte)
    if data[2] != 0x00 {
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    if 5 + name_len <= data.len() {
        std::str::from_utf8(&data[5..5 + name_len])
            .ok()
            .map(|s| s.to_string())
    } else {
        None
    }
}

fn parse_sni_extension_partial(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        // Not enough data to even read the SNI structure
        return None;
    }

    // Check if we have the full SNI header
    // Skip list length (2 bytes) and type (1 byte)
    if data[2] != 0x00 {
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let name_start = 5;

    if name_start + name_len <= data.len() {
        // We have the complete hostname
        std::str::from_utf8(&data[name_start..name_start + name_len])
            .ok()
            .map(|s| s.to_string())
    } else if data.len() > name_start {
        // We have a partial hostname (truncated at the end)
        std::str::from_utf8(&data[name_start..])
            .ok()
            .map(|s| format!("{}...", s))
    } else {
        None
    }
}

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

        if offset + proto_len <= data.len() {
            if let Ok(proto) = std::str::from_utf8(&data[offset..offset + proto_len]) {
                protocols.push(proto.to_string());
            }
        }

        offset += proto_len;
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
    }
}

fn parse_alpn_extension_partial(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }

    let mut protocols = Vec::new();
    let alpn_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    let mut offset = 2;
    let list_end = data.len().min(2 + alpn_len);

    while offset < list_end {
        if offset >= data.len() {
            break;
        }

        let proto_len = data[offset] as usize;
        offset += 1;

        let available = (data.len() - offset).min(proto_len);
        if available > 0 {
            if let Ok(proto) = std::str::from_utf8(&data[offset..offset + available]) {
                if available < proto_len {
                    protocols.push(format!("{}...", proto));
                } else {
                    protocols.push(proto.to_string());
                }
            }
        }

        offset += proto_len;
    }

    if protocols.is_empty() {
        None
    } else {
        Some(protocols)
    }
}

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
    } else {
        if data.len() >= 2 && data[0] == 0x03 && data[1] == 0x04 {
            return Some(TlsVersion::Tls13);
        }
    }

    // QUIC always uses TLS 1.3
    Some(TlsVersion::Tls13)
}

fn extract_tls_info_from_fragment(data: &[u8]) -> Option<TlsInfo> {
    let mut info = TlsInfo::new();
    let mut found_something = false;

    // Look for SNI pattern (extension type 0x0000)
    if let Some(pos) = find_pattern(data, &[0x00, 0x00]) {
        if pos >= 2 && pos + 2 < data.len() {
            // Check if this looks like an extension header
            let possible_len = u16::from_be_bytes([data[pos - 2], data[pos - 1]]) as usize;
            if possible_len < 1000 && pos + 2 + possible_len <= data.len() {
                // Try to parse as SNI
                if let Some(sni) = parse_sni_extension(
                    &data[pos + 2..pos + 2 + possible_len.min(data.len() - pos - 2)],
                ) {
                    info.sni = Some(sni);
                    found_something = true;
                    debug!("QUIC: Found SNI in fragment: {:?}", info.sni);
                }
            }
        }
    }

    // Look for ALPN pattern (extension type 0x0010)
    if let Some(pos) = find_pattern(data, &[0x00, 0x10]) {
        if pos >= 2 && pos + 2 < data.len() {
            let possible_len = u16::from_be_bytes([data[pos - 2], data[pos - 1]]) as usize;
            if possible_len < 1000 && pos + 2 + possible_len <= data.len() {
                if let Some(alpn) = parse_alpn_extension(
                    &data[pos + 2..pos + 2 + possible_len.min(data.len() - pos - 2)],
                ) {
                    info.alpn = alpn;
                    found_something = true;
                    debug!("QUIC: Found ALPN in fragment: {:?}", info.alpn);
                }
            }
        }
    }

    // Enhanced: Look for partial SNI data in fragments
    if info.sni.is_none() {
        if let Some(partial_sni) = find_partial_sni_in_fragment(data) {
            info.sni = Some(partial_sni);
            found_something = true;
            debug!("QUIC: Found partial SNI in fragment: {:?}", info.sni);
        }
    }

    // Look for common ALPN values as a fallback
    for alpn in &["h3", "h3-29", "h3-28", "h3-27", "http/1.1", "h2"] {
        if let Some(_) = find_pattern(data, alpn.as_bytes()) {
            if info.alpn.is_empty() {
                info.alpn = vec![alpn.to_string()];
                found_something = true;
                debug!("QUIC: Found ALPN string '{}' in fragment", alpn);
            }
        }
    }

    if found_something { Some(info) } else { None }
}

// New function to find partial SNI data in a fragment
fn find_partial_sni_in_fragment(data: &[u8]) -> Option<String> {
    // Strategy 1: Look for domain patterns with TLDs
    let common_tlds = [
        ".com", ".org", ".net", ".io", ".co", ".dev", ".app", ".ai", ".cloud",
    ];

    for tld in &common_tlds {
        if let Some(pos) = find_pattern(data, tld.as_bytes()) {
            if let Some(domain) = extract_partial_domain_around_position(data, pos, tld.len()) {
                return Some(domain);
            }
        }
    }

    // Strategy 2: Look for ASCII domain-like sequences that might be partial
    // This helps when we have the beginning of a domain but not the TLD
    if let Some(partial) = find_domain_like_sequence(data) {
        return Some(partial);
    }

    None
}

// Enhanced domain extraction that handles partial domains
fn extract_partial_domain_around_position(
    data: &[u8],
    tld_pos: usize,
    tld_len: usize,
) -> Option<String> {
    let mut start = tld_pos;
    let mut end = tld_pos + tld_len;

    // Check if we might be at the beginning of the data (partial domain start)
    let at_data_start = tld_pos < 20; // Heuristic: if TLD is near the beginning

    // Go backwards to find the start of the domain
    let mut found_start = false;
    while start > 0 {
        let ch = data[start - 1];
        if ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'.' {
            start -= 1;
        } else {
            found_start = true;
            break;
        }
    }

    // If we reached the beginning of data without finding a delimiter,
    // this might be a truncated domain
    let prefix_truncated = start == 0 && !found_start && at_data_start;

    // Go forward to find the end of the domain
    let mut found_end = false;
    while end < data.len() {
        let ch = data[end];
        if ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'.' {
            end += 1;
        } else {
            found_end = true;
            break;
        }
    }

    // Check if we might have a truncated end
    let suffix_truncated = end == data.len() && !found_end;

    // Validate and return the domain
    if end > start && end - start < 256 {
        if let Ok(domain_part) = std::str::from_utf8(&data[start..end]) {
            // Only return if it looks like a valid domain part
            if domain_part.len() > 2 {
                let result = match (prefix_truncated, suffix_truncated) {
                    (true, true) => format!("...{}...", domain_part),
                    (true, false) => format!("...{}", domain_part),
                    (false, true) => format!("{}...", domain_part),
                    (false, false) => domain_part.to_string(),
                };

                // Additional validation: ensure we have something meaningful
                if result.replace("...", "").len() >= 3 {
                    return Some(result);
                }
            }
        }
    }

    None
}

// Find domain-like sequences that might be partial (no TLD visible)
fn find_domain_like_sequence(data: &[u8]) -> Option<String> {
    let mut best_sequence: Option<(usize, usize, bool, bool)> = None;
    let mut i = 0;

    while i < data.len() {
        // Skip non-domain characters
        while i < data.len() && !is_domain_char(data[i]) {
            i += 1;
        }

        if i >= data.len() {
            break;
        }

        // Found start of a potential domain sequence
        let start = i;
        let at_data_start = start == 0;

        // Collect domain characters
        while i < data.len() && is_domain_char(data[i]) {
            i += 1;
        }

        let end = i;
        let at_data_end = end == data.len();

        // Check if this sequence looks like a domain part
        if end - start >= 4 {
            // Minimum meaningful length
            let sequence = &data[start..end];

            // Check for domain-like characteristics
            if looks_like_domain(sequence) {
                // Prefer sequences with dots (more likely to be domains)
                let has_dot = sequence.contains(&b'.');

                match best_sequence {
                    None => best_sequence = Some((start, end, at_data_start, at_data_end)),
                    Some((_, _, _, _)) if has_dot => {
                        best_sequence = Some((start, end, at_data_start, at_data_end));
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some((start, end, at_start, at_end)) = best_sequence {
        if let Ok(domain_part) = std::str::from_utf8(&data[start..end]) {
            // Determine if this looks truncated
            let looks_truncated_start = at_start && !domain_part.starts_with("www.");
            let looks_truncated_end = at_end && !has_complete_tld(domain_part);

            let result = match (looks_truncated_start, looks_truncated_end) {
                (true, true) => format!("...{}...", domain_part),
                (true, false) => format!("...{}", domain_part),
                (false, true) => format!("{}...", domain_part),
                (false, false) => domain_part.to_string(),
            };

            return Some(result);
        }
    }

    None
}

// Helper functions for domain parsing
fn is_domain_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'-' || ch == b'.'
}

fn looks_like_domain(data: &[u8]) -> bool {
    // Must have at least some alphanumeric characters
    let has_alnum = data.iter().any(|&b| b.is_ascii_alphanumeric());

    // Should not start or end with special characters
    let valid_start = data.first().map_or(false, |&b| b.is_ascii_alphanumeric());
    let valid_end = data.last().map_or(false, |&b| b.is_ascii_alphanumeric());

    // Should not have consecutive dots
    let no_consecutive_dots = !data.windows(2).any(|w| w == b"..");

    has_alnum && valid_start && valid_end && no_consecutive_dots
}

fn has_complete_tld(domain: &str) -> bool {
    let known_tlds = [
        ".com", ".org", ".net", ".edu", ".gov", ".mil", ".io", ".co", ".dev", ".app", ".ai",
        ".cloud", ".uk", ".de", ".fr", ".jp", ".cn", ".au", ".ca", ".info", ".biz", ".tv", ".cc",
        ".me", ".in",
    ];

    known_tlds.iter().any(|tld| domain.ends_with(tld))
}

fn find_pattern(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_short_header_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.len() < 1 {
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
    quic_info.connection_id_hex = if dcid.is_empty() {
        None
    } else {
        Some(quick_connection_id_to_hex(&dcid))
    };

    Some(quic_info)
}

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
        8 => {
            let val = u64::from_be_bytes([
                data[0] & 0x3f,
                data[1],
                data[2],
                data[3],
                data[4],
                data[5],
                data[6],
                data[7],
            ]);
            val
        }
        _ => return None,
    };

    Some((value, len))
}

fn get_long_packet_type(first_byte: u8, version: u32) -> QuicPacketType {
    let type_bits = (first_byte & 0x30) >> 4;

    // Check if this is QUIC v2
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

fn is_quic_v2(version: u32) -> bool {
    version == 0x6b3343cf
}

fn derive_secret(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> bool {
    let info = build_hkdf_label(label, &[], out.len());

    prk.expand(&[&info], ArbitraryOutputLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .is_ok()
}

fn derive_packet_protection_key(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 key"
    } else {
        b"quic key"
    };
    derive_secret(&prk, label, out)
}

fn derive_packet_protection_iv(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 iv"
    } else {
        b"quic iv"
    };
    derive_secret(&prk, label, out)
}

fn derive_header_protection_key(secret: &[u8], out: &mut [u8], version: u32) -> bool {
    let prk = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, secret);
    let label: &[u8] = if is_quic_v2(version) {
        b"quicv2 hp"
    } else {
        b"quic hp"
    };
    derive_secret(&prk, label, out)
}

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

// AES-ECB encryption for header protection
fn aes_ecb_encrypt(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    use aes::cipher::generic_array::GenericArray;

    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut output = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut output);

    let mut result = [0u8; 16];
    result.copy_from_slice(&output);
    Some(result)
}

// Helper function that should be available from your types module
fn quick_connection_id_to_hex(id: &[u8]) -> String {
    id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
}

fn quic_version_to_string(version: u32) -> Option<String> {
    match version {
        0x00000001 => Some("v1".to_string()),
        0x6b3343cf => Some("v2".to_string()),
        0xff00001d => Some("draft-29".to_string()),
        0xff00001c => Some("draft-28".to_string()),
        0xff00001b => Some("draft-27".to_string()),
        0 => Some("negotiation".to_string()),
        _ => Some(format!("0x{:08x}", version)),
    }
}

// Enhanced is_quic_packet function with better version detection
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

// Wrapper for HKDF expand with arbitrary output length
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
    fn test_variable_length_int_parsing() {
        // 1-byte encoding
        let data = vec![0x25];
        assert_eq!(parse_variable_length_int(&data), Some((0x25, 1)));

        // 2-byte encoding
        let data = vec![0x40, 0x25];
        assert_eq!(parse_variable_length_int(&data), Some((0x25, 2)));

        // 4-byte encoding
        let data = vec![0x80, 0x00, 0x00, 0x25];
        assert_eq!(parse_variable_length_int(&data), Some((0x25, 4)));

        // 8-byte encoding
        let data = vec![0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25];
        assert_eq!(parse_variable_length_int(&data), Some((0x25, 8)));
    }

    #[test]
    fn test_find_pattern() {
        let data = b"hello world";
        assert_eq!(find_pattern(data, b"world"), Some(6));
        assert_eq!(find_pattern(data, b"hello"), Some(0));
        assert_eq!(find_pattern(data, b"foo"), None);
    }

    #[test]
    fn test_extract_partial_domain_around_position() {
        // Complete domain
        let data = b"some text example.com more text";
        let pos = find_pattern(data, b".com").unwrap();
        let domain = extract_partial_domain_around_position(data, pos, 4);
        assert_eq!(domain, Some("example.com".to_string()));

        // Domain at the beginning (might be truncated)
        let data = b"gle.com and other text";
        let pos = find_pattern(data, b".com").unwrap();
        let domain = extract_partial_domain_around_position(data, pos, 4);
        assert_eq!(domain, Some("...gle.com".to_string()));

        // Domain at the end (might be truncated)
        let data = b"visit googl";
        if let Some(partial) = find_domain_like_sequence(data) {
            assert_eq!(partial, "googl...");
        }
    }

    #[test]
    fn test_has_complete_tld() {
        assert!(has_complete_tld("example.com"));
        assert!(has_complete_tld("sub.domain.org"));
        assert!(!has_complete_tld("example.co"));
        assert!(!has_complete_tld("partial"));
    }

    #[test]
    fn test_looks_like_domain() {
        assert!(looks_like_domain(b"example.com"));
        assert!(looks_like_domain(b"sub-domain"));
        assert!(!looks_like_domain(b"..example"));
        assert!(!looks_like_domain(b"example.."));
        assert!(!looks_like_domain(b"-example"));
    }

    #[test]
    fn test_find_partial_sni_in_fragment() {
        // Test with complete domain
        let data = b"\x00\x00\x00\x00example.com\x00\x00";
        let result = find_partial_sni_in_fragment(data);
        assert_eq!(result, Some("example.com".to_string()));

        // Test with partial domain at start
        let data = b"gle.com\x00\x00";
        let result = find_partial_sni_in_fragment(data);
        assert_eq!(result, Some("...gle.com".to_string()));

        // Test with partial domain at end
        let data = b"\x00\x00exam";
        let result = find_partial_sni_in_fragment(data);
        // This should find "exam" and mark it as truncated
        assert!(result.is_some());
        if let Some(domain) = result {
            assert!(domain.ends_with("..."));
        }
    }
}
