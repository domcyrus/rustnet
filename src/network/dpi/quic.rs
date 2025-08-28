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

/// Main entry point for QUIC packet parsing
pub fn parse_quic_packet(payload: &[u8]) -> Option<QuicInfo> {
    if payload.is_empty() {
        debug!("QUIC: Empty payload");
        return None;
    }

    let first_byte = payload[0];
    let is_long_header = (first_byte & 0x80) != 0;

    debug!(
        "QUIC: Parsing packet - first_byte=0x{:02x}, is_long_header={}, payload_len={}",
        first_byte,
        is_long_header,
        payload.len()
    );

    if is_long_header {
        parse_long_header_packet(payload)
    } else {
        parse_short_header_packet(payload)
    }
}

/// Parse a QUIC long header packet
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
    quic_info.packet_type = packet_type.clone();

    // Parse connection IDs
    let mut offset = 5;

    // Destination Connection ID
    if offset >= payload.len() {
        debug!(
            "QUIC: Payload too short to read DCID length at offset {}",
            offset
        );
        return None;
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
        return None;
    }
    let dcid = payload[offset..offset + dcid_len].to_vec();
    quic_info.connection_id = dcid.clone();
    // Don't set connection_id_hex yet - only set it for Client Initial packets with crypto frames
    quic_info.connection_id_hex = None;
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

    // Always try to extract any available information, even if we can't decrypt
    // This includes looking for unencrypted TLS extensions or other plaintext data
    if let Some(tls_info) = try_parse_unencrypted_crypto_frames(payload) {
        debug!(
            "QUIC: Found TLS info in unencrypted packet data: SNI={:?}, ALPN={:?}",
            tls_info.sni, tls_info.alpn
        );
        quic_info.tls_info = Some(tls_info);
    }

    // For Initial and Handshake packets, try to decrypt and extract TLS information
    // Focus on Client packets as they contain the SNI information
    match packet_type {
        QuicPacketType::Initial if dcid_len > 0 => {
            debug!("QUIC: Processing Initial packet with DCID len={}", dcid_len);
            // Try to decrypt as client packet first (most likely to have SNI)
            if let Some(decrypted_payload) = decrypt_client_initial_packet(payload, &dcid, version)
            {
                debug!("QUIC: Successfully decrypted Client Initial packet");
                // Extract TLS info from decrypted payload using reassembly
                if let Some(tls_info) =
                    process_crypto_frames_in_packet(&decrypted_payload, &mut quic_info)
                {
                    quic_info.tls_info = Some(tls_info);
                    // This is a Client Initial packet with crypto frames - mark it for connection tracking
                    if !dcid.is_empty() {
                        quic_info.connection_id_hex = Some(connection_id_to_hex(&dcid));
                        debug!(
                            "QUIC: Marking Client Initial packet with DCID {} for connection tracking",
                            connection_id_to_hex(&dcid)
                        );
                    }
                }
            } else if let Some(decrypted_payload) =
                decrypt_server_initial_packet(payload, &dcid, version)
            {
                debug!("QUIC: Successfully decrypted Server Initial packet");
                // Server Initial rarely has SNI but may have ALPN or other TLS info
                if let Some(tls_info) =
                    process_crypto_frames_in_packet(&decrypted_payload, &mut quic_info)
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

                // Try to extract any unencrypted TLS information
                if let Some(tls_info) = try_parse_unencrypted_crypto_frames(payload) {
                    debug!(
                        "QUIC: Found TLS info in unencrypted parts: SNI={:?}",
                        tls_info.sni
                    );
                    quic_info.tls_info = Some(tls_info);
                }
            }
        }
        QuicPacketType::Handshake if dcid_len > 0 => {
            debug!("QUIC: Processing Handshake packet - these often contain ClientHello");
            // Handshake packets may also contain TLS ClientHello
            // Modern QUIC often puts the actual TLS handshake in Handshake packets, not Initial
            if let Some(tls_info) = try_parse_unencrypted_crypto_frames(payload) {
                debug!(
                    "QUIC: Found TLS info in Handshake packet: SNI={:?}",
                    tls_info.sni
                );
                quic_info.tls_info = Some(tls_info);
            }
        }
        QuicPacketType::Initial => {
            debug!(
                "QUIC: Initial packet has zero-length DCID - this is normal for some QUIC implementations"
            );
            debug!(
                "QUIC: Packet details - version=0x{:08x}, payload_len={}, packet_type={:?}",
                version,
                payload.len(),
                packet_type
            );

            // Zero-length DCID is actually valid for some QUIC implementations
            // We should still try to extract what we can from unencrypted parts
            if let Some(tls_info) = try_parse_unencrypted_crypto_frames(payload) {
                debug!(
                    "QUIC: Extracted TLS info from unencrypted frames: SNI={:?}",
                    tls_info.sni
                );
                quic_info.tls_info = Some(tls_info);
            }
        }
        _ => {
            debug!(
                "QUIC: Packet type {:?} not processed for TLS extraction",
                packet_type
            );
        }
    }

    Some(quic_info)
}

/// Parse a QUIC short header packet
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

                    if let Some(reassembler) = &mut quic_info.crypto_reassembler {
                        if let Err(e) = reassembler.add_fragment(crypto_offset, crypto_data) {
                            warn!("QUIC: Failed to add CRYPTO fragment: {}", e);
                        }
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
                
                let reason = if reason_length > 0 && offset + reason_length as usize <= payload.len() {
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
                    reason: reason.clone(),
                    detected_at: std::time::Instant::now(),
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

    if found_crypto_frames {
        // Try to extract TLS info from reassembler
        if let Some(reassembler) = &mut quic_info.crypto_reassembler {
            if let Some(tls_info) = try_extract_tls_from_reassembler(reassembler) {
                debug!(
                    "QUIC: Successfully extracted TLS info: SNI={:?}",
                    tls_info.sni
                );
                quic_info.tls_info = Some(tls_info.clone());
                return Some(tls_info);
            }
        }
    }

    None
}

/// Try to extract TLS information from reassembled fragments
pub fn try_extract_tls_from_reassembler(
    reassembler: &mut CryptoFrameReassembler,
) -> Option<TlsInfo> {
    // If we already have complete info, return it
    if let Some(tls_info) = reassembler.get_cached_tls_info() {
        return Some(tls_info.clone());
    }

    // Try to reassemble and parse contiguous data first
    if let Some(reassembled) = reassembler.get_contiguous_data() {
        debug!(
            "QUIC: Attempting to parse {} bytes of contiguous crypto data",
            reassembled.len()
        );

        // Only attempt to parse if we have enough data for a reasonable ClientHello
        // A minimal ClientHello is typically at least 100 bytes, but SNI usually appears
        // after 70-200 bytes. Wait for at least 200 bytes to be safe.
        if reassembled.len() >= 200 {
            if let Some(tls_info) = parse_partial_tls_handshake(&reassembled) {
                // Check if we have the essential info (SNI and ALPN)
                if tls_info.sni.is_some() || !tls_info.alpn.is_empty() {
                    debug!("QUIC: Found complete TLS info from contiguous data");
                    reassembler.set_complete_tls_info(tls_info.clone());
                    return Some(tls_info);
                }
            }
        } else {
            debug!(
                "QUIC: Only {} contiguous bytes available, waiting for more data before parsing",
                reassembled.len()
            );
        }
    }

    // If contiguous parsing failed, try parsing individual fragments
    // This can help when we have complete TLS records in separate fragments
    // Only parse fragments that start with proper TLS structures to avoid partial data
    debug!("QUIC: Trying to parse individual crypto fragments with proper TLS headers");
    for (&offset, fragment_data) in reassembler.get_fragments() {
        debug!(
            "QUIC: Trying fragment at offset {} with {} bytes",
            offset,
            fragment_data.len()
        );

        // Only try to parse fragments that look like they contain complete TLS structures
        // Check if fragment starts with TLS handshake header (0x01 for ClientHello)
        if fragment_data.len() >= 4 && fragment_data[0] == 0x01 {
            if let Some(tls_info) = parse_partial_tls_handshake(fragment_data) {
                if tls_info.sni.is_some() || !tls_info.alpn.is_empty() {
                    debug!(
                        "QUIC: Found TLS info from individual fragment at offset {}",
                        offset
                    );
                    reassembler.set_complete_tls_info(tls_info.clone());
                    return Some(tls_info);
                }
            }
        }

        // Also try direct TLS pattern matching, but only for fragments that look like TLS records
        if fragment_data.len() >= 6 && fragment_data[0] == 0x16 {
            // TLS record header
            if let Some(tls_info) = try_parse_unencrypted_crypto_frames(fragment_data) {
                if tls_info.sni.is_some() || !tls_info.alpn.is_empty() {
                    debug!(
                        "QUIC: Found TLS info from pattern matching in fragment at offset {}",
                        offset
                    );
                    reassembler.set_complete_tls_info(tls_info.clone());
                    return Some(tls_info);
                }
            }
        } else {
            debug!(
                "QUIC: Skipping fragment at offset {} - doesn't start with TLS header",
                offset
            );
        }
    }

    // Only try fragment reconstruction if we have a reasonable amount of data
    // but not enough contiguous data (likely due to out-of-order packets)
    let total_fragment_size: usize = reassembler.get_fragments().values().map(|v| v.len()).sum();

    if total_fragment_size >= 200 {
        debug!(
            "QUIC: Have {} total bytes in fragments, attempting reconstruction",
            total_fragment_size
        );

        // Try to reconstruct SNI from fragmented data by looking for hostname patterns
        if let Some(sni) = try_reconstruct_sni_from_fragments(reassembler) {
            let mut tls_info = TlsInfo::new();
            tls_info.sni = Some(sni);
            debug!("QUIC: Reconstructed SNI from fragmented data");
            reassembler.set_complete_tls_info(tls_info.clone());
            return Some(tls_info);
        }
    } else {
        debug!(
            "QUIC: Only {} total bytes in fragments, not enough for reliable SNI extraction",
            total_fragment_size
        );
    }

    debug!("QUIC: No TLS info could be extracted from reassembler");
    None
}

/// Parse a TLS handshake from reassembled data
fn parse_partial_tls_handshake(data: &[u8]) -> Option<TlsInfo> {
    if data.len() < 4 {
        debug!("QUIC: TLS handshake data too short: {} bytes", data.len());
        return None;
    }

    let handshake_type = data[0];
    let handshake_length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;

    debug!(
        "QUIC: TLS handshake type=0x{:02x}, declared_length={}, available_data={}",
        handshake_type,
        handshake_length,
        data.len() - 4
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
            parse_partial_client_hello(&available_data[..parse_length], &mut info);
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
fn parse_partial_client_hello(data: &[u8], info: &mut TlsInfo) {
    debug!("QUIC: Parsing ClientHello with {} bytes", data.len());

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
        parse_tls_extensions(&data[offset..offset + available_ext_len], info, true);
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
        parse_tls_extensions(&data[offset..offset + available_ext_len], info, false);
    }
}

/// Parse TLS extensions
fn parse_tls_extensions(data: &[u8], info: &mut TlsInfo, is_client: bool) {
    let mut offset = 0;
    debug!(
        "QUIC: Parsing {} bytes of TLS extensions (is_client={})",
        data.len(),
        is_client
    );

    while offset + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

        debug!(
            "QUIC: Extension type=0x{:04x}, length={}",
            ext_type, ext_len
        );

        if offset + 4 + ext_len > data.len() {
            debug!(
                "QUIC: Extension data extends beyond available data (need {} bytes, have {})",
                offset + 4 + ext_len,
                data.len()
            );

            // Try to parse with partial data if we have some extension data
            let available_ext_len = (data.len() - offset - 4).min(ext_len);
            if available_ext_len > 0 {
                debug!(
                    "QUIC: Attempting to parse {} bytes of partial extension data",
                    available_ext_len
                );
                let ext_data = &data[offset + 4..offset + 4 + available_ext_len];

                // Try to parse the partial extension
                match ext_type {
                    0x0000 if is_client => {
                        // SNI - try partial parsing
                        debug!(
                            "QUIC: Found partial SNI extension with {} bytes (declared {})",
                            available_ext_len, ext_len
                        );
                        if let Some(sni) = parse_sni_extension(ext_data) {
                            debug!("QUIC: Successfully parsed SNI from partial data: {}", sni);
                            info.sni = Some(sni);
                        } else {
                            debug!("QUIC: Failed to parse partial SNI extension");
                        }
                    }
                    0x0010 => {
                        // ALPN - try partial parsing
                        debug!(
                            "QUIC: Found partial ALPN extension with {} bytes (declared {})",
                            available_ext_len, ext_len
                        );
                        if let Some(alpn) = parse_alpn_extension(ext_data) {
                            debug!(
                                "QUIC: Successfully parsed ALPN from partial data: {:?}",
                                alpn
                            );
                            info.alpn = alpn;
                        } else {
                            debug!("QUIC: Failed to parse partial ALPN extension");
                        }
                    }
                    _ => {
                        debug!("QUIC: Skipping partial extension type 0x{:04x}", ext_type);
                    }
                }
            }
            break;
        }

        let ext_data = &data[offset + 4..offset + 4 + ext_len];

        match ext_type {
            0x0000 if is_client => {
                // SNI
                debug!("QUIC: Found SNI extension with {} bytes", ext_len);
                if let Some(sni) = parse_sni_extension(ext_data) {
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
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    debug!(
        "QUIC: Parsing SNI extension with {} bytes: {:02x?}",
        data.len(),
        &data[..data.len().min(20)]
    );

    if data.len() < 5 {
        debug!(
            "QUIC: SNI extension too short: {} bytes (need at least 5)",
            data.len()
        );
        return None;
    }

    // Parse list length
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    debug!("QUIC: SNI list length: {}", list_len);

    // Skip list length (2 bytes) and check type (1 byte)
    if data[2] != 0x00 {
        debug!("QUIC: SNI type is not hostname (got 0x{:02x})", data[2]);
        return None;
    }

    if data.len() < 5 {
        debug!("QUIC: Not enough data for SNI name length");
        return None;
    }

    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    debug!("QUIC: SNI name length: {}", name_len);

    // Validate name length is reasonable
    if name_len == 0 || name_len > 253 {
        debug!("QUIC: Invalid SNI name length {}", name_len);
        return None;
    }

    if 5 + name_len <= data.len() {
        let sni_data = &data[5..5 + name_len];
        debug!("QUIC: SNI data: {:02x?}", sni_data);

        match std::str::from_utf8(sni_data) {
            Ok(sni) => {
                // Validate the SNI looks like a hostname
                if sni.contains('.')
                    && sni.len() >= 4
                    && sni
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
                {
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
    } else {
        debug!(
            "QUIC: SNI name extends beyond available data (need {}, have {}) - skipping partial extraction",
            5 + name_len,
            data.len()
        );
        // Don't extract partial SNI as it leads to fragmented hostnames like "play.go"
        // Let the fragment reconstruction handle this case
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
    } else {
        if data.len() >= 2 && data[0] == 0x03 && data[1] == 0x04 {
            return Some(TlsVersion::Tls13);
        }
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
            if tls_version_major == 0x03 && tls_version_minor >= 0x01 && tls_version_minor <= 0x04 {
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

                        if let Some(tls_info) = parse_partial_tls_handshake(handshake_data) {
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

                if let Some(tls_info) =
                    parse_partial_tls_handshake(&payload[offset..offset + 4 + handshake_length])
                {
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
            if ext_len >= 5 && ext_len <= 300 && offset + 4 + ext_len <= payload.len() {
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
                        && list_len >= 3
                        && list_len <= 256
                        && list_len == name_len + 3
                    {
                        if let Some(sni) = parse_sni_extension(ext_data) {
                            debug!("QUIC: Found SNI directly in packet: {}", sni);
                            let mut tls_info = TlsInfo::new();
                            tls_info.sni = Some(sni);
                            return Some(tls_info);
                        }
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

                    // Add more strict validation to reduce false positives
                    // SNI extension length should be reasonable (5-300 bytes typically)
                    if ext_len >= 5 && ext_len <= 300 && i + 4 + ext_len <= data.len() {
                        let sni_data = &data[i + 4..i + 4 + ext_len];

                        // Additional validation: check if this looks like a real SNI extension
                        // Real SNI extensions start with list length (2 bytes) + type 0x00 (1 byte) + name length (2 bytes)
                        if sni_data.len() >= 5 {
                            let list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]) as usize;
                            let sni_type = sni_data[2];
                            let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;

                            // Validate SNI structure: type should be 0x00, lengths should be reasonable
                            if sni_type == 0x00
                                && name_len > 0
                                && name_len <= 253
                                && list_len >= 3
                                && list_len <= 256
                                && list_len == name_len + 3
                            {
                                // list_len should equal name_len + 3 (type + name_len)
                                if let Some(sni) = parse_sni_extension(sni_data) {
                                    debug!("QUIC: Found complete SNI in fragment: {}", sni);
                                    return Some(sni);
                                }
                            }
                        }
                    }
                    // Skip the overly aggressive partial data parsing that causes false positives
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
                if expected_offset < 100 && gap_size > 20 {
                    has_significant_gaps = true;
                    debug!("QUIC: Gap in critical ClientHello region - SNI might be incomplete");
                }

                // Large gaps anywhere might indicate missing data
                if gap_size > 200 {
                    has_significant_gaps = true;
                    debug!(
                        "QUIC: Large gap detected ({} bytes) - data might be incomplete",
                        gap_size
                    );
                }

                // For smaller gaps, add minimal padding to maintain data alignment
                if gap_size <= 50 && !all_data.is_empty() {
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
                if is_valid_hostname(&candidate) {
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
        for candidate in candidates {
            if is_valid_hostname(&candidate) {
                processed_candidates.push(candidate);
            } else {
                // Check if this might be a truncated hostname
                if let Some(marked_hostname) =
                    detect_and_mark_truncated_hostname(&candidate, &all_data)
                {
                    processed_candidates.push(marked_hostname);
                }
            }
        }
    }

    // Sort by length (longer first) to prefer complete hostnames, but prioritize unmarked ones
    processed_candidates.sort_by(|a, b| {
        let a_has_dots = a.contains("...");
        let b_has_dots = b.contains("...");

        // Prefer complete hostnames over truncated ones
        match (a_has_dots, b_has_dots) {
            (false, true) => std::cmp::Ordering::Less, // a is complete, prefer it
            (true, false) => std::cmp::Ordering::Greater, // b is complete, prefer it
            _ => b.len().cmp(&a.len()),                // both same type, prefer longer
        }
    });

    for candidate in &processed_candidates {
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
        if is_ascii_letter_or_digit(data[i]) {
            let mut end = i;
            let mut has_dot = false;
            let mut dot_count = 0;

            // Extend while we have valid hostname characters
            while end < data.len()
                && (is_ascii_letter_or_digit(data[end]) || data[end] == b'.' || data[end] == b'-')
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

/// Check if a character is an ASCII letter or digit
fn is_ascii_letter_or_digit(b: u8) -> bool {
    (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z') || (b >= b'0' && b <= b'9')
}

/// Detect if a hostname candidate appears to be truncated and mark it with ...
fn detect_and_mark_truncated_hostname(candidate: &str, full_data: &[u8]) -> Option<String> {
    // Must have basic hostname structure
    if candidate.len() < 3 || !candidate.contains('.') {
        return None;
    }

    // Must have some alphabetic content to be a hostname
    if !candidate.chars().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    // Check if it looks like a truncated hostname based on context
    let candidate_bytes = candidate.as_bytes();

    // Find where this candidate appears in the full data
    if let Some(pos) = find_substring(full_data, candidate_bytes) {
        let mut result = candidate.to_string();
        let mut marked = false;

        // Check if there's likely missing data before this substring
        if pos > 0 {
            // Look for hostname-like characters before this position
            let mut check_pos = pos;
            let mut hostname_chars_before = 0;

            while check_pos > 0 && hostname_chars_before < 20 {
                check_pos -= 1;
                let byte = full_data[check_pos];

                if is_ascii_letter_or_digit(byte) || byte == b'.' || byte == b'-' {
                    hostname_chars_before += 1;
                    // There are hostname characters before, likely truncated
                    if hostname_chars_before >= 3 {
                        // Need at least 3 chars to be confident
                        result = format!("...{}", result);
                        marked = true;
                        break;
                    }
                } else if byte == 0 || byte.is_ascii_whitespace() || byte > 127 {
                    // Hit a clear boundary, not truncated
                    break;
                } else {
                    // Other byte, continue searching but don't count it
                }
            }
        }

        // Check if there's likely missing data after this substring
        let end_pos = pos + candidate_bytes.len();
        if end_pos < full_data.len() {
            // Look for hostname-like characters after this position
            let mut check_pos = end_pos;
            let mut hostname_chars_after = 0;

            while check_pos < full_data.len() && hostname_chars_after < 20 {
                let byte = full_data[check_pos];

                if is_ascii_letter_or_digit(byte) || byte == b'.' || byte == b'-' {
                    hostname_chars_after += 1;
                    // There are hostname characters after, likely truncated
                    if hostname_chars_after >= 3 {
                        // Need at least 3 chars to be confident
                        result = format!("{}...", result);
                        marked = true;
                        break;
                    }
                } else if byte == 0 || byte.is_ascii_whitespace() || byte > 127 {
                    // Hit a clear boundary, not truncated
                    break;
                } else {
                    // Other byte, continue searching but don't count it
                }
                check_pos += 1;
            }
        }

        // Only return if we marked it as truncated and it still looks hostname-like
        if marked && result.split('.').count() >= 2 {
            debug!(
                "QUIC: Detected truncated hostname: {} -> {}",
                candidate, result
            );
            return Some(result);
        }
    }

    None
}

/// Find a substring in a byte array
fn find_substring(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    for i in 0..=(haystack.len() - needle.len()) {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }

    None
}

/// Validate if a string looks like a valid hostname
fn is_valid_hostname(hostname: &str) -> bool {
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

    // Check for reasonable TLD patterns
    let common_tlds = [
        "com", "net", "org", "edu", "gov", "io", "co", "uk", "de", "fr", "jp", "cn", "au", "ca",
        "us", "ru", "br", "in", "it", "es", "pl", "nl",
    ];
    let has_valid_tld = common_tlds
        .iter()
        .any(|&tld| hostname.ends_with(&format!(".{}", tld)) || hostname == tld);

    // Additional check: must have at least one alphabetic character (not just numbers and dots)
    let has_alpha = hostname.chars().any(|c| c.is_ascii_alphabetic());

    // Check if hostname has reasonable structure (at least domain.tld format)
    let parts: Vec<&str> = hostname.split('.').collect();
    let has_reasonable_structure = parts.len() >= 2
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.len() <= 63);

    if has_valid_tld && has_alpha && has_reasonable_structure {
        debug!(
            "QUIC: Hostname {} looks valid (TLD: {}, Structure: {}, HasAlpha: {})",
            hostname, has_valid_tld, has_reasonable_structure, has_alpha
        );
        return true;
    }

    debug!(
        "QUIC: Hostname {} rejected (TLD: {}, Structure: {}, HasAlpha: {})",
        hostname, has_valid_tld, has_reasonable_structure, has_alpha
    );
    false
}
