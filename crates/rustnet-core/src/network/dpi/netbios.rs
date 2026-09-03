//! NetBIOS Deep Packet Inspection
//!
//! Parses NetBIOS Name Service (UDP 137) and Datagram Service (UDP 138) packets.

use crate::network::types::{NetBiosInfo, NetBiosOpcode, NetBiosResponseStatus, NetBiosService};

/// Minimum NetBIOS Name Service packet size
const MIN_NBNS_SIZE: usize = 12;

/// Datagram Service header sizes per RFC 1002 §4.4: DIRECT_UNIQUE /
/// DIRECT_GROUP / BROADCAST messages have a 14-byte header (through
/// PACKET_OFFSET), QUERY REQUEST/RESPONSE messages a 10-byte header
/// (through SOURCE_PORT), and a DATAGRAM ERROR is 11 bytes (10-byte
/// header plus the error code).
const NBDGM_DIRECT_HEADER: usize = 14;
const NBDGM_QUERY_HEADER: usize = 10;
const NBDGM_ERROR_SIZE: usize = 11;

/// Analyze a NetBIOS Name Service packet (UDP port 137).
///
/// Returns `None` if the packet is too small or invalid.
pub(super) fn analyze_netbios_ns(payload: &[u8]) -> Option<NetBiosInfo> {
    if payload.len() < MIN_NBNS_SIZE {
        return None;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);

    // Extract opcode from flags (bits 11-14)
    let opcode_value = ((flags >> 11) & 0x0F) as u8;
    let has_response_flag = (flags & 0x8000) != 0;

    let opcode = match (has_response_flag, opcode_value) {
        // A WACK is an interim response asking the client to keep waiting.
        (true, 7) => NetBiosOpcode::Wack,
        (true, _) => NetBiosOpcode::Response,
        (false, _) => parse_opcode(opcode_value),
    };
    let is_response = has_response_flag && opcode != NetBiosOpcode::Wack;

    let name = if payload.len() > 12 {
        decode_netbios_name(&payload[12..])
    } else {
        None
    };

    Some(NetBiosInfo {
        service: NetBiosService::NameService,
        opcode,
        name,
        transaction_id: u16::from_be_bytes([payload[0], payload[1]]),
        is_response,
        response_status: is_response
            .then_some(NetBiosResponseStatus::NameService((flags & 0x000F) as u8)),
    })
}

/// Analyze a NetBIOS Datagram Service packet (UDP port 138).
///
/// Returns `None` if the packet is too small or invalid.
pub(super) fn analyze_netbios_dgm(payload: &[u8]) -> Option<NetBiosInfo> {
    // Message type at byte 0
    let msg_type = *payload.first()?;

    // RFC 1002 §4.4: header size (and therefore where the encoded name
    // starts) depends on the message type.
    let (opcode, min_size, name_offset, response_status) = match msg_type {
        // §4.4.1 DIRECT_UNIQUE / DIRECT_GROUP / BROADCAST: message
        // delivery, SOURCE_NAME follows the 14-byte header
        0x10..=0x12 => (
            NetBiosOpcode::Datagram,
            NBDGM_DIRECT_HEADER,
            Some(NBDGM_DIRECT_HEADER),
            None,
        ),
        // §4.4.2 DATAGRAM ERROR: header + error code, no name
        0x13 => (NetBiosOpcode::Error, NBDGM_ERROR_SIZE, None, None),
        // §4.4.3 DATAGRAM QUERY REQUEST: DESTINATION_NAME follows the
        // 10-byte header
        0x14 => (
            NetBiosOpcode::Query,
            NBDGM_QUERY_HEADER,
            Some(NBDGM_QUERY_HEADER),
            None,
        ),
        // §4.4.3 POSITIVE / NEGATIVE QUERY RESPONSE
        0x15 => (
            NetBiosOpcode::Response,
            NBDGM_QUERY_HEADER,
            Some(NBDGM_QUERY_HEADER),
            Some(NetBiosResponseStatus::DatagramPositive),
        ),
        0x16 => (
            NetBiosOpcode::Response,
            NBDGM_QUERY_HEADER,
            Some(NBDGM_QUERY_HEADER),
            Some(NetBiosResponseStatus::DatagramNegative),
        ),
        other => (
            NetBiosOpcode::Unknown(other),
            NBDGM_QUERY_HEADER,
            None,
            None,
        ),
    };

    if payload.len() < min_size {
        return None;
    }

    let name = name_offset
        .and_then(|off| payload.get(off..))
        .and_then(decode_netbios_name);

    Some(NetBiosInfo {
        service: NetBiosService::DatagramService,
        opcode,
        name,
        transaction_id: u16::from_be_bytes([payload[2], payload[3]]),
        is_response: response_status.is_some(),
        response_status,
    })
}

/// Parse NetBIOS opcode from the flags field
fn parse_opcode(value: u8) -> NetBiosOpcode {
    match value {
        0 => NetBiosOpcode::Query,
        5 => NetBiosOpcode::Registration,
        6 => NetBiosOpcode::Release,
        7 => NetBiosOpcode::Wack,
        8 => NetBiosOpcode::Refresh,
        other => NetBiosOpcode::Unknown(other),
    }
}

/// Decode a NetBIOS "first-level" encoded name.
///
/// NetBIOS names are encoded as 32 bytes representing 16 characters:
/// - Each character is split into two nibbles
/// - Each nibble is encoded as 'A' + nibble_value
fn decode_netbios_name(data: &[u8]) -> Option<String> {
    // Need at least length byte + 32 encoded bytes
    if data.is_empty() {
        return None;
    }

    let name_len = data[0] as usize;

    // Standard NetBIOS encoded name is 32 bytes
    if name_len != 32 || data.len() < 33 {
        return None;
    }

    let mut name = String::with_capacity(16);

    for i in 0..16 {
        let idx = 1 + i * 2;
        if idx + 1 >= data.len() {
            break;
        }

        let hi = data[idx];
        let lo = data[idx + 1];

        // Validate encoding (should be 'A'-'P' range)
        if !(b'A'..=b'P').contains(&hi) || !(b'A'..=b'P').contains(&lo) {
            return None;
        }

        let hi_nibble = (hi - b'A') << 4;
        let lo_nibble = lo - b'A';
        let c = hi_nibble | lo_nibble;

        // Keep only printable ASCII: this naturally drops the trailing
        // service-type suffix (0x00/0x1B/etc.) and padding spaces (0x20),
        // since `is_ascii_graphic` covers 0x21..=0x7E exclusively.
        if c.is_ascii_graphic() {
            name.push(c as char);
        }
    }

    if name.is_empty() { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_netbios_name(name: &str) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(33);
        encoded.push(32); // Length byte

        // Pad name to 15 chars + suffix byte
        let padded: Vec<u8> = name
            .bytes()
            .chain(std::iter::repeat(0x20))
            .take(16)
            .collect();

        for &b in &padded {
            encoded.push(b'A' + ((b >> 4) & 0x0F));
            encoded.push(b'A' + (b & 0x0F));
        }

        encoded
    }

    fn build_nbns_query(name: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&[0x00, 0x01]);
        // Flags: Query (opcode 0)
        packet.extend_from_slice(&[0x01, 0x10]);
        // Question count: 1
        packet.extend_from_slice(&[0x00, 0x01]);
        // Answer, Authority, Additional counts: 0
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Encoded name
        packet.extend_from_slice(&encode_netbios_name(name));

        // Null terminator and QTYPE/QCLASS
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x20, 0x00, 0x01]);

        packet
    }

    fn build_nbns_response(name: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // Transaction ID
        packet.extend_from_slice(&[0x00, 0x01]);
        // Flags: Response
        packet.extend_from_slice(&[0x85, 0x00]);
        // Counts
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);

        // Encoded name
        packet.extend_from_slice(&encode_netbios_name(name));

        packet
    }

    #[test]
    fn test_nbns_query() {
        let packet = build_nbns_query("WORKSTATION");
        let info = analyze_netbios_ns(&packet).expect("should parse");
        assert_eq!(info.service, NetBiosService::NameService);
        assert_eq!(info.opcode, NetBiosOpcode::Query);
        assert_eq!(info.name, Some("WORKSTATION".to_string()));
        assert_eq!(info.transaction_id, 1);
        assert!(!info.is_response);
        assert_eq!(info.response_status, None);
    }

    #[test]
    fn test_nbns_response() {
        let packet = build_nbns_response("FILESERVER");
        let info = analyze_netbios_ns(&packet).expect("should parse");
        assert_eq!(info.service, NetBiosService::NameService);
        assert_eq!(info.opcode, NetBiosOpcode::Response);
        assert_eq!(info.name, Some("FILESERVER".to_string()));
        assert_eq!(info.transaction_id, 1);
        assert!(info.is_response);
        assert_eq!(
            info.response_status,
            Some(NetBiosResponseStatus::NameService(0))
        );
    }

    #[test]
    fn test_nbns_negative_response_status() {
        let mut packet = build_nbns_response("MISSING");
        packet[3] = 0x03; // NAM_ERR
        let info = analyze_netbios_ns(&packet).expect("should parse");
        assert_eq!(
            info.response_status,
            Some(NetBiosResponseStatus::NameService(3))
        );
        assert_eq!(info.response_status.unwrap().to_string(), "NAM_ERR");
        assert!(!info.response_status.unwrap().is_success());
    }

    #[test]
    fn test_nbns_wack_is_not_final_response() {
        let mut packet = [0u8; MIN_NBNS_SIZE];
        packet[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        packet[2..4].copy_from_slice(&0xB800u16.to_be_bytes());
        let info = analyze_netbios_ns(&packet).expect("should parse");
        assert_eq!(info.opcode, NetBiosOpcode::Wack);
        assert!(!info.is_response);
        assert_eq!(info.response_status, None);
    }

    #[test]
    fn test_nbns_too_short() {
        let packet = [0u8; 5];
        assert!(analyze_netbios_ns(&packet).is_none());
    }

    #[test]
    fn test_nbdgm_direct() {
        let mut packet = vec![0u8; 14];
        packet[0] = 0x10; // Direct unique datagram
        packet.extend_from_slice(&encode_netbios_name("SENDERPC")); // SOURCE_NAME
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.service, NetBiosService::DatagramService);
        assert_eq!(info.opcode, NetBiosOpcode::Datagram);
        assert_eq!(info.name, Some("SENDERPC".to_string()));
    }

    #[test]
    fn test_nbdgm_broadcast_is_datagram_not_registration() {
        // 0x12 is a broadcast datagram (RFC 1002 §4.4.1); it has nothing
        // to do with NBNS name registration.
        let mut packet = vec![0u8; 14];
        packet[0] = 0x12;
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.opcode, NetBiosOpcode::Datagram);
    }

    #[test]
    fn test_nbdgm_query_request_name_at_offset_10() {
        // §4.4.3 messages have a 10-byte header; DESTINATION_NAME starts at
        // offset 10, not 14.
        let mut packet = vec![0u8; 10];
        packet[0] = 0x14; // DATAGRAM QUERY REQUEST
        packet.extend_from_slice(&encode_netbios_name("FILESERVER"));
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.opcode, NetBiosOpcode::Query);
        assert_eq!(info.name, Some("FILESERVER".to_string()));
        assert_eq!(info.transaction_id, 0);
        assert!(!info.is_response);
    }

    #[test]
    fn test_nbdgm_negative_query_response() {
        let mut packet = vec![0u8; 10];
        packet[0] = 0x16;
        packet[2..4].copy_from_slice(&0x4567u16.to_be_bytes());
        packet.extend_from_slice(&encode_netbios_name("FILESERVER"));
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.opcode, NetBiosOpcode::Response);
        assert_eq!(info.transaction_id, 0x4567);
        assert!(info.is_response);
        assert_eq!(
            info.response_status,
            Some(NetBiosResponseStatus::DatagramNegative)
        );
        assert!(!info.response_status.unwrap().is_success());
    }

    #[test]
    fn test_nbdgm_error_datagram() {
        // A spec-conformant DATAGRAM ERROR is exactly 11 bytes
        // (§4.4.2: 10-byte header + 1-byte error code).
        let mut packet = vec![0u8; 11];
        packet[0] = 0x13;
        packet[10] = 0x82; // ERR_SOURCE_NAME_BAD_FORMAT
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.opcode, NetBiosOpcode::Error);
        assert_eq!(info.name, None);
    }

    #[test]
    fn test_nbdgm_too_short() {
        let packet = [0u8; 5];
        assert!(analyze_netbios_dgm(&packet).is_none());
    }

    #[test]
    fn test_decode_netbios_name() {
        // Encode "TEST"
        let encoded = encode_netbios_name("TEST");
        let name = decode_netbios_name(&encoded).expect("should decode");
        assert_eq!(name, "TEST");
    }

    #[test]
    fn test_decode_netbios_name_with_padding() {
        // Encode "PC" - should trim padding
        let encoded = encode_netbios_name("PC");
        let name = decode_netbios_name(&encoded).expect("should decode");
        assert_eq!(name, "PC");
    }

    #[test]
    fn test_decode_netbios_name_strips_service_type_suffix() {
        // Real NetBIOS names embed a service-type byte at the 16th position
        // (workstation=0x00, file_server=0x20, master_browser=0x1D, etc.).
        // The non-printable suffix must NOT appear in the decoded name;
        // decoding only keeps `is_ascii_graphic` characters (0x21..=0x7E).
        let mut encoded = Vec::with_capacity(33);
        encoded.push(32);
        let padded = b"WORKSTATION    "; // 15 chars
        for &b in padded {
            encoded.push(b'A' + ((b >> 4) & 0x0F));
            encoded.push(b'A' + (b & 0x0F));
        }
        // 16th byte = service-type 0x00 (workstation)
        encoded.push(b'A');
        encoded.push(b'A');

        let decoded = decode_netbios_name(&encoded).expect("should decode");
        assert_eq!(decoded, "WORKSTATION");
    }
}
