use crate::network::merge::merge_tls_info;
use crate::network::types::{QuicConnectionState, QuicInfo, QuicPacketType, TlsInfo};
use crate::network::util::hex_encode;
use log::{debug, warn};
use std::ops::Range;

use super::crypto::decrypt_client_initial_packet;
use super::tls::try_extract_tls_from_reassembler;
use crate::network::dpi::tls_common::is_partial_sni;

// QUIC v1 Initial salt (from RFC 9001)
pub(super) const INITIAL_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

// QUIC v2 Initial salt
const INITIAL_SALT_V2: &[u8] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

// Initial salt for IETF drafts 29-32 (and drafts 33-34 reused the v1 salt)
const INITIAL_SALT_DRAFT_29: &[u8] = &[
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

// Initial salt for IETF drafts 23-28 (also used by Facebook mvfst 0xfaceb002 = draft-27)
const INITIAL_SALT_DRAFT_23: &[u8] = &[
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02,
];

/// Select the Initial salt for a QUIC version (RFC 9001 §5.2, RFC 9369 §3.3.1,
/// and the corresponding draft revisions).
pub(super) fn initial_salt_for_version(version: u32) -> &'static [u8] {
    if is_quic_v2(version) {
        return INITIAL_SALT_V2;
    }
    match version {
        0xff00_001d..=0xff00_0020 => INITIAL_SALT_DRAFT_29, // drafts 29-32
        0xff00_0017..=0xff00_001c | 0xface_b002 => INITIAL_SALT_DRAFT_23, // drafts 23-28, mvfst
        _ => INITIAL_SALT_V1, // v1, drafts 33-34, and unknown versions
    }
}

/// Main entry point for QUIC packet parsing
/// Handles coalesced packets - multiple QUIC packets in a single UDP datagram
pub(in crate::network::dpi) fn parse_quic_packet(payload: &[u8]) -> Option<QuicInfo> {
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
/// Prefers more complete information (SNI without `[PARTIAL]`, higher connection state, etc.)
fn merge_quic_packet_info(existing: Option<QuicInfo>, new: QuicInfo) -> QuicInfo {
    match existing {
        None => new,
        Some(mut existing) => {
            // Prefer higher connection state
            if new.connection_state.priority() > existing.connection_state.priority() {
                existing.connection_state = new.connection_state;
            }

            // Merge TLS info - prefer complete SNI over partial
            merge_tls_info(&mut existing.tls_info, &new.tls_info);

            // Update connection ID if we have a better one
            if existing.connection_id.is_empty() && !new.connection_id.is_empty() {
                existing.connection_id = new.connection_id;
                existing.connection_id_hex = new.connection_id_hex;
            }

            // Update version if we didn't have it
            if existing.version_string.is_none() && new.version_string.is_some() {
                existing.version_string = new.version_string;
            }

            // Merge crypto reassemblers. Both packets can carry CRYPTO frames:
            // a large ClientHello (e.g. with post-quantum key shares) is split
            // across two Initial packets that are often coalesced into one
            // datagram. Dropping the second packet's fragments would lose the
            // tail of the ClientHello and with it the SNI.
            match (&mut existing.crypto_reassembler, new.crypto_reassembler) {
                (None, Some(new_reassembler)) => {
                    existing.crypto_reassembler = Some(new_reassembler);
                }
                (Some(existing_reassembler), Some(new_reassembler)) => {
                    for (&frag_offset, data) in new_reassembler.get_fragments() {
                        if let Err(e) = existing_reassembler.add_fragment(frag_offset, data.clone())
                        {
                            warn!("QUIC: Failed to merge coalesced CRYPTO fragment: {}", e);
                        }
                    }

                    // Re-extract if the merged fragments can improve on what we have
                    let sni_missing_or_partial = existing
                        .tls_info
                        .as_ref()
                        .and_then(|tls| tls.sni.as_ref())
                        .is_none_or(|s| is_partial_sni(s));
                    if sni_missing_or_partial
                        && let Some(tls_info) =
                            try_extract_tls_from_reassembler(existing_reassembler, false)
                    {
                        existing.tls_info = Some(tls_info);
                    }
                }
                _ => {}
            }

            existing
        }
    }
}

/// Location of the protected part of a long header packet that carries a
/// `Length` field (Initial, 0-RTT and Handshake, RFC 9000 Section 17.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PacketLayout {
    /// Offset of the (header-protected) packet number field
    pub pn_offset: usize,
    /// Declared `Length`: packet number plus protected payload and AEAD tag
    pub packet_length: usize,
}

/// Fields of a QUIC long header, parsed once and shared by the packet walker
/// and the Initial-packet decryptor.
pub(super) struct LongHeader {
    pub version: u32,
    pub packet_type: QuicPacketType,
    /// Byte range of the Destination Connection ID within the packet.
    /// Remembering the range lets callers reborrow the packet instead of
    /// allocating an owned copy of the DCID.
    pub dcid: Range<usize>,
    /// `None` for Retry and Version Negotiation packets, which have no
    /// `Length` field, and when the token or `Length` varint could not be
    /// parsed. In both cases the packet extends to the end of the datagram.
    pub layout: Option<PacketLayout>,
}

/// Parse the long header fields up to the packet number.
///
/// Returns `None` when the fixed fields or connection IDs are truncated,
/// which means the packet cannot be interpreted at all.
pub(super) fn parse_long_header(payload: &[u8]) -> Option<LongHeader> {
    if payload.len() < 6 {
        return None;
    }

    let first_byte = payload[0];
    let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

    // Determine packet type
    let packet_type = if version == 0 {
        QuicPacketType::VersionNegotiation
    } else {
        get_long_packet_type(first_byte, version)
    };

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
    let dcid = offset..offset + dcid_len;
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

    let mut header = LongHeader {
        version,
        packet_type,
        dcid,
        layout: None,
    };

    // Retry and Version Negotiation packets have no Length field: the retry
    // token / supported-version list simply extends to the end of the
    // datagram (RFC 9000 §17.2.5, RFC 8999 §6). Parsing a Length varint here
    // would read garbage and misinterpret the trailing bytes as coalesced
    // packets, so consume the rest of the datagram instead.
    if matches!(
        packet_type,
        QuicPacketType::Retry | QuicPacketType::VersionNegotiation
    ) {
        return Some(header);
    }

    // For Initial packets, parse token length
    if packet_type == QuicPacketType::Initial {
        let Some(token_len) = read_varint(payload, &mut offset) else {
            return Some(header); // Can't parse, assume rest of datagram
        };
        // Guard: a malformed/adversarial varint may decode to a value far
        // larger than the remaining payload (QUIC varints go up to 2^62, so
        // also guard the usize conversion on 32-bit targets). Treat that as
        // unparseable rather than panicking on the next slice access.
        match usize::try_from(token_len)
            .ok()
            .and_then(|len| len.checked_add(offset))
        {
            Some(new_offset) if new_offset <= payload.len() => offset = new_offset,
            _ => {
                debug!("QUIC: token_len pushed offset past end of packet");
                return Some(header);
            }
        }
    }

    // Parse packet length (variable-length integer)
    let Some(packet_length) = read_varint(payload, &mut offset) else {
        // Can't parse packet length, assume rest of datagram
        return Some(header);
    };

    // Now offset points to the packet number field
    header.layout = Some(PacketLayout {
        pn_offset: offset,
        packet_length: packet_length as usize,
    });
    Some(header)
}

/// Parse a QUIC long header packet and return both the info and the packet length
/// This is needed for coalesced packet handling
pub(super) fn parse_long_header_packet_with_length(payload: &[u8]) -> (Option<QuicInfo>, usize) {
    let Some(header) = parse_long_header(payload) else {
        return (None, 0);
    };

    // Create QuicInfo with version
    let mut quic_info = QuicInfo::new(header.version);
    quic_info.packet_type = header.packet_type;
    quic_info.connection_id = payload[header.dcid.clone()].to_vec();
    quic_info.connection_id_hex = None;

    let Some(layout) = header.layout else {
        // The packet consumes the rest of the datagram. Retry and Version
        // Negotiation carry no Length field and still classify the
        // connection; an Initial / 0-RTT / Handshake packet whose token or
        // Length could not be read is malformed, so its state is left alone.
        if matches!(
            header.packet_type,
            QuicPacketType::Retry | QuicPacketType::VersionNegotiation
        ) {
            extract_tls_from_long_header_packet(payload, &mut quic_info, &header);
        }
        return (Some(quic_info), payload.len());
    };

    // Total packet size = header (pn_offset) + packet_length (includes pkt num + payload).
    // Use checked_add so an adversarial varint length can't overflow usize.
    let total_packet_size = layout
        .pn_offset
        .checked_add(layout.packet_length)
        .unwrap_or(payload.len());

    debug!(
        "QUIC: Long header packet - header_len={}, packet_length={}, total={}",
        layout.pn_offset, layout.packet_length, total_packet_size
    );

    // Now do the actual TLS extraction on this packet
    let packet_data = if total_packet_size <= payload.len() {
        &payload[..total_packet_size]
    } else {
        payload // Use what we have if packet extends beyond datagram
    };

    extract_tls_from_long_header_packet(packet_data, &mut quic_info, &header);

    (Some(quic_info), total_packet_size.min(payload.len()))
}

/// Extract TLS information from a long header packet
///
/// The DCID lives inside `payload`, so it is reborrowed from the header's
/// range instead of cloning the owned `connection_id` Vec.
fn extract_tls_from_long_header_packet(
    payload: &[u8],
    quic_info: &mut QuicInfo,
    header: &LongHeader,
) {
    let LongHeader {
        version,
        packet_type,
        layout,
        ..
    } = *header;
    let dcid = &payload[header.dcid.clone()];
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
            // Only client Initial packets are decryptable here: Initial keys
            // are derived from the client's original DCID (RFC 9001 §5.2),
            // and only client first-flight packets carry that value in their
            // own DCID field. A server Initial's DCID is the client's SCID,
            // so deriving keys from it can never succeed without
            // connection-level state that remembers the original DCID.
            if let Some(decrypted_payload) = layout
                .and_then(|layout| decrypt_client_initial_packet(payload, dcid, version, layout))
            {
                debug!("QUIC: Successfully decrypted Client Initial packet");
                // Extract TLS info from decrypted payload using reassembly
                if let Some(tls_info) =
                    process_crypto_frames_in_packet(&decrypted_payload, quic_info)
                {
                    quic_info.tls_info = Some(tls_info);
                    // This is a Client Initial packet with crypto frames - mark it for connection tracking
                    quic_info.connection_id_hex = Some(hex_encode(dcid, ":"));
                    debug!(
                        "QUIC: Marking Client Initial packet with DCID {} for connection tracking",
                        hex_encode(dcid, ":")
                    );
                }
            } else {
                debug!(
                    "QUIC: Failed to decrypt Initial packet as client first flight - DCID={:02x?}, version=0x{:08x}, payload_len={}",
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

    // A 1-RTT packet must have the fixed bit set (first byte 01xxxxxx,
    // RFC 9000 §17.3.1). This also stops trailing garbage after a misparsed
    // coalesced packet from being claimed as a Connected 1-RTT packet.
    if (payload[0] & 0xc0) != 0x40 {
        return None;
    }

    // For short header, we don't have version info
    let mut quic_info = QuicInfo::new(0);
    quic_info.packet_type = QuicPacketType::OneRtt;
    quic_info.connection_state = QuicConnectionState::Connected;

    // For short header, connection ID length is not in the packet — use a
    // common 8-byte size as a heuristic. Move the slice straight into
    // `connection_id`; the long-header path keeps a local `dcid` because it
    // re-borrows for TLS decryption, but here nothing else reads it.
    quic_info.connection_id = if payload.len() >= 9 {
        payload[1..9].to_vec()
    } else {
        payload[1..].to_vec()
    };
    // Short header packets are data packets - don't use for connection tracking
    quic_info.connection_id_hex = None;

    Some(quic_info)
}

/// Process all frames in a decrypted QUIC packet payload and extract CRYPTO frames
fn process_crypto_frames_in_packet(payload: &[u8], quic_info: &mut QuicInfo) -> Option<TlsInfo> {
    // Ensure we have a reassembler
    quic_info.ensure_reassembler();

    let mut found_crypto_frames = false;

    // Even if the frame walk stops early on a malformed or truncated frame,
    // CRYPTO fragments collected before that point are kept in the
    // reassembler, so still attempt TLS extraction below.
    if scan_packet_frames(payload, quic_info, &mut found_crypto_frames).is_none() {
        debug!("QUIC: Frame walk stopped early on malformed or truncated frame");
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

/// Walk all frames in a decrypted packet payload, feeding CRYPTO frames into
/// the reassembler. Returns `None` if a malformed or truncated frame forced
/// the walk to stop before the end of the payload.
fn scan_packet_frames(
    payload: &[u8],
    quic_info: &mut QuicInfo,
    found_crypto_frames: &mut bool,
) -> Option<()> {
    let mut offset = 0;

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

                // Parse and skip ACK frame fields: Largest Acknowledged,
                // ACK Delay, ACK Range Count, First ACK Range
                skip_varints(payload, &mut offset, 2)?;
                let ack_range_count = read_varint(payload, &mut offset)?;
                read_varint(payload, &mut offset)?;

                // Each ACK Range is a Gap plus an ACK Range Length
                skip_varints(payload, &mut offset, ack_range_count.saturating_mul(2))?;

                if frame_type_byte == 0x03 {
                    // ECN counts
                    skip_varints(payload, &mut offset, 3)?;
                }
            }

            0x04 => {
                // RESET_STREAM frame
                skip_varints(payload, &mut offset, 3)?;
            }

            0x05 => {
                // STOP_SENDING frame
                skip_varints(payload, &mut offset, 2)?;
            }

            0x06 => {
                // CRYPTO frame - this is what we're looking for!
                debug!("QUIC: Found CRYPTO frame");
                *found_crypto_frames = true;
                quic_info.has_crypto_frame = true;

                let crypto_offset = read_varint(payload, &mut offset)?;
                let crypto_length = read_varint(payload, &mut offset)?;

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
                let token_length = read_varint(payload, &mut offset)?;
                offset = offset.checked_add(token_length as usize)?;
                if offset > payload.len() {
                    break;
                }
            }

            0x08..=0x0f => {
                // STREAM frames
                let has_offset = (frame_type_byte & 0x04) != 0;
                let has_length = (frame_type_byte & 0x02) != 0;

                read_varint(payload, &mut offset)?; // Stream ID

                if has_offset {
                    read_varint(payload, &mut offset)?;
                }

                let stream_data_len = if has_length {
                    read_varint(payload, &mut offset)? as usize
                } else {
                    payload.len() - offset
                };

                offset = offset.checked_add(stream_data_len)?;
                if offset > payload.len() {
                    break;
                }
            }

            0x10..=0x17 => {
                // Various MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED frames
                let num_vars = match frame_type_byte {
                    0x10 | 0x12 | 0x13 | 0x14 | 0x16 | 0x17 => 1,
                    0x11 | 0x15 => 2,
                    _ => 0,
                };
                skip_varints(payload, &mut offset, num_vars)?;
            }

            0x18 => {
                // NEW_CONNECTION_ID frame: Sequence Number, Retire Prior To
                skip_varints(payload, &mut offset, 2)?;

                if offset >= payload.len() {
                    break;
                }
                let cid_length = payload[offset] as usize;
                offset = offset.checked_add(1 + cid_length + 16)?; // CID + stateless reset token
                if offset > payload.len() {
                    break;
                }
            }

            0x19 => {
                // RETIRE_CONNECTION_ID frame
                read_varint(payload, &mut offset)?;
            }

            0x1a | 0x1b => {
                // PATH_CHALLENGE or PATH_RESPONSE frame
                offset += 8;
            }

            0x1c | 0x1d => {
                // CONNECTION_CLOSE frame - extract detailed information
                let error_code = read_varint(payload, &mut offset)?;

                // 0x1c has an additional frame type field, 0x1d does not
                if frame_type_byte == 0x1c {
                    read_varint(payload, &mut offset)?;
                }

                // Extract reason phrase if present
                let reason_length = read_varint(payload, &mut offset)?;

                let reason_len = reason_length as usize;
                let reason_end = offset.checked_add(reason_len)?;
                let reason = if reason_length > 0 && reason_end <= payload.len() {
                    let reason_bytes = &payload[offset..reason_end];
                    String::from_utf8(reason_bytes.to_vec()).ok()
                } else {
                    None
                };

                // Store CONNECTION_CLOSE information in quic_info. This must
                // happen before the truncation check below: the error code
                // and frame type were parsed validly even when the reason
                // phrase is cut off, and dropping them would lose the
                // Draining/Closed state transition.
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

                offset = reason_end;
                if offset > payload.len() {
                    break;
                }
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

    Some(())
}

/// Read a variable-length integer at `*offset` and advance past it.
/// Returns `None` (leaving `offset` untouched) if the varint is truncated or
/// `offset` is already past the end of `payload`.
fn read_varint(payload: &[u8], offset: &mut usize) -> Option<u64> {
    let (value, bytes_read) = parse_variable_length_int(payload.get(*offset..)?)?;
    *offset += bytes_read;
    Some(value)
}

/// Skip `count` consecutive variable-length integers starting at `*offset`.
fn skip_varints(payload: &[u8], offset: &mut usize, count: u64) -> Option<()> {
    for _ in 0..count {
        read_varint(payload, offset)?;
    }
    Some(())
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
pub(super) fn is_quic_v2(version: u32) -> bool {
    version == 0x6b3343cf
}

/// Check if a packet is likely a QUIC packet
pub(in crate::network::dpi) fn is_quic_packet(payload: &[u8]) -> bool {
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
        // Minimum plausible 1-RTT packet: first byte + connection ID +
        // packet number + AEAD tag. No upper bound: GSO/GRO capture can
        // deliver datagrams well beyond the usual 1500-byte MTU.
        return payload.len() >= 20;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for a panic in parse_long_header_packet_with_length:
    /// a malformed Initial packet whose token_length varint decodes to a
    /// value far larger than the payload used to push `offset` past
    /// `payload.len()`, causing the next slice access at line 408 to panic
    /// with "range start index ... out of range for slice of length ...".
    #[test]
    fn test_long_header_huge_token_length_does_not_panic() {
        // Build a QUIC v1 Initial long-header packet.
        //   first byte: 0xC0 (long, Initial, pkt num len irrelevant here)
        //   version:    0x00000001
        //   DCID len:   0
        //   SCID len:   0
        //   token len varint: 8-byte form with a huge value (0xC8 8C ...)
        // That varint decodes (with the top 2 bits masked) to
        // 0x08c8c8c8c8c8ca67 — the exact value from the observed panic.
        let mut pkt = Vec::new();
        pkt.push(0xC0);
        pkt.extend_from_slice(&0x0000_0001u32.to_be_bytes());
        pkt.push(0); // DCID len
        pkt.push(0); // SCID len
        pkt.extend_from_slice(&[0xC8, 0x8C, 0x8C, 0x8C, 0x8C, 0x8C, 0xCA, 0x67]);
        // Some trailing bytes to make the payload look plausible.
        pkt.extend(std::iter::repeat_n(0u8, 64));

        // Must not panic.
        let (info, consumed) = parse_long_header_packet_with_length(&pkt);
        assert!(info.is_some(), "should still surface a QuicInfo");
        assert_eq!(
            consumed,
            pkt.len(),
            "unparseable token length should cause us to treat the rest of the datagram as consumed"
        );
    }

    /// Regression: a declared token length that exceeds the packet used to
    /// panic when the decryptor re-parsed the header and sliced
    /// `&packet[offset..]`. The single header parser now reports the packet
    /// number offset as unknown, so decryption is never attempted.
    #[test]
    fn test_initial_packet_oversized_token_len_does_not_panic() {
        let mut packet = Vec::new();
        packet.push(0xC0); // long header, type=Initial
        packet.extend_from_slice(&1u32.to_be_bytes()); // version 1
        packet.push(0); // DCID len = 0
        packet.push(0); // SCID len = 0
        // Token length: 2-byte QUIC varint encoding 1000 (top 2 bits = 01).
        let token_varint: u16 = 1000 | 0x4000;
        packet.extend_from_slice(&token_varint.to_be_bytes());
        // Intentionally no token bytes follow: declared length far exceeds packet.

        let header = parse_long_header(&packet).expect("fixed fields should parse");
        assert_eq!(header.packet_type, QuicPacketType::Initial);
        assert!(header.layout.is_none());

        let (info, consumed) = parse_long_header_packet_with_length(&packet);
        assert!(
            info.expect("should still surface a QuicInfo")
                .tls_info
                .is_none()
        );
        assert_eq!(consumed, packet.len());
    }

    #[test]
    fn test_version_negotiation_consumes_rest_of_datagram() {
        let mut pkt = vec![0x80u8]; // long header form, no fixed bit required
        pkt.extend_from_slice(&0u32.to_be_bytes()); // version 0 = negotiation
        pkt.push(8);
        pkt.extend_from_slice(&[0xaa; 8]); // DCID
        pkt.push(0); // SCID len
        // Supported versions list - must not be misread as a Length field
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&0x6b3343cfu32.to_be_bytes());

        let (info, consumed) = parse_long_header_packet_with_length(&pkt);
        let info = info.expect("Version Negotiation packet should parse");
        assert_eq!(info.packet_type, QuicPacketType::VersionNegotiation);
        assert_eq!(consumed, pkt.len());
    }

    #[test]
    fn test_short_header_requires_fixed_bit() {
        assert!(parse_short_header_packet(&[0x00; 30]).is_none());
        assert!(parse_short_header_packet(&[0x41; 30]).is_some());
    }

    #[test]
    fn test_initial_salt_for_version_mapping() {
        assert_eq!(initial_salt_for_version(0x00000001), INITIAL_SALT_V1);
        assert_eq!(initial_salt_for_version(0x6b3343cf), INITIAL_SALT_V2);
        assert_eq!(initial_salt_for_version(0xff00001d), INITIAL_SALT_DRAFT_29); // draft-29
        assert_eq!(initial_salt_for_version(0xff000020), INITIAL_SALT_DRAFT_29); // draft-32
        assert_eq!(initial_salt_for_version(0xff00001b), INITIAL_SALT_DRAFT_23); // draft-27
        assert_eq!(initial_salt_for_version(0xfaceb002), INITIAL_SALT_DRAFT_23); // mvfst
        assert_eq!(initial_salt_for_version(0xff000022), INITIAL_SALT_V1); // draft-34
    }
}
