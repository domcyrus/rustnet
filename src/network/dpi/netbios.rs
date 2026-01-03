//! NetBIOS Deep Packet Inspection
//!
//! Parses NetBIOS Name Service (UDP 137) and Datagram Service (UDP 138) packets.

use crate::network::types::{NetBiosInfo, NetBiosOpcode, NetBiosService};

/// Minimum NetBIOS Name Service packet size
const MIN_NBNS_SIZE: usize = 12;

/// Minimum NetBIOS Datagram Service packet size
const MIN_NBDGM_SIZE: usize = 14;

/// Analyze a NetBIOS Name Service packet (UDP port 137).
///
/// Returns `None` if the packet is too small or invalid.
pub fn analyze_netbios_ns(payload: &[u8]) -> Option<NetBiosInfo> {
    if payload.len() < MIN_NBNS_SIZE {
        return None;
    }

    // Parse header flags at bytes 2-3
    let flags = u16::from_be_bytes([payload[2], payload[3]]);

    // Extract opcode from flags (bits 11-14)
    let opcode_value = ((flags >> 11) & 0x0F) as u8;
    let is_response = (flags & 0x8000) != 0;

    let opcode = if is_response {
        NetBiosOpcode::Response
    } else {
        parse_opcode(opcode_value)
    };

    // Try to decode NetBIOS name if present
    let name = if payload.len() > 12 {
        decode_netbios_name(&payload[12..])
    } else {
        None
    };

    Some(NetBiosInfo {
        service: NetBiosService::NameService,
        opcode,
        name,
    })
}

/// Analyze a NetBIOS Datagram Service packet (UDP port 138).
///
/// Returns `None` if the packet is too small or invalid.
pub fn analyze_netbios_dgm(payload: &[u8]) -> Option<NetBiosInfo> {
    if payload.len() < MIN_NBDGM_SIZE {
        return None;
    }

    // Message type at byte 0
    let msg_type = payload[0];

    // Map message type to opcode
    let opcode = match msg_type {
        0x10 => NetBiosOpcode::Query,        // Direct unique datagram
        0x11 => NetBiosOpcode::Query,        // Direct group datagram
        0x12 => NetBiosOpcode::Registration, // Broadcast datagram
        0x13 => NetBiosOpcode::Query,        // Datagram error
        0x14 => NetBiosOpcode::Query,        // Datagram query request
        0x15 => NetBiosOpcode::Response,     // Datagram positive query response
        0x16 => NetBiosOpcode::Response,     // Datagram negative query response
        _ => NetBiosOpcode::Unknown(msg_type),
    };

    // Try to extract source name from offset 14 if available
    let name = if payload.len() > 14 {
        decode_netbios_name(&payload[14..])
    } else {
        None
    };

    Some(NetBiosInfo {
        service: NetBiosService::DatagramService,
        opcode,
        name,
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

        // Skip padding spaces (0x20)
        if c != 0x20 && (c.is_ascii_graphic() || c.is_ascii_alphanumeric()) {
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
    }

    #[test]
    fn test_nbns_response() {
        let packet = build_nbns_response("FILESERVER");
        let info = analyze_netbios_ns(&packet).expect("should parse");
        assert_eq!(info.service, NetBiosService::NameService);
        assert_eq!(info.opcode, NetBiosOpcode::Response);
        assert_eq!(info.name, Some("FILESERVER".to_string()));
    }

    #[test]
    fn test_nbns_too_short() {
        let packet = [0u8; 5];
        assert!(analyze_netbios_ns(&packet).is_none());
    }

    #[test]
    fn test_nbdgm_direct() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x10; // Direct unique datagram
        let info = analyze_netbios_dgm(&packet).expect("should parse");
        assert_eq!(info.service, NetBiosService::DatagramService);
        assert_eq!(info.opcode, NetBiosOpcode::Query);
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
}
