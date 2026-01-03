//! SNMP (Simple Network Management Protocol) Deep Packet Inspection
//!
//! Parses SNMP packets (v1, v2c, v3) using simplified BER decoding.
//! SNMP uses UDP ports 161 (agent) and 162 (trap).

use crate::network::types::{SnmpInfo, SnmpPduType, SnmpVersion};

/// Minimum SNMP packet size
const MIN_SNMP_SIZE: usize = 10;

/// BER tag types
const BER_SEQUENCE: u8 = 0x30;
const BER_INTEGER: u8 = 0x02;
const BER_OCTET_STRING: u8 = 0x04;

/// SNMP PDU types (context-specific tags)
const PDU_GET_REQUEST: u8 = 0xA0;
const PDU_GET_NEXT_REQUEST: u8 = 0xA1;
const PDU_GET_RESPONSE: u8 = 0xA2;
const PDU_SET_REQUEST: u8 = 0xA3;
const PDU_TRAP_V1: u8 = 0xA4;
const PDU_GET_BULK_REQUEST: u8 = 0xA5;
const PDU_INFORM_REQUEST: u8 = 0xA6;
const PDU_TRAP_V2: u8 = 0xA7;
const PDU_REPORT: u8 = 0xA8;

/// Analyze an SNMP packet and extract key information.
///
/// Returns `None` if the packet is not valid SNMP.
pub fn analyze_snmp(payload: &[u8]) -> Option<SnmpInfo> {
    if payload.len() < MIN_SNMP_SIZE {
        return None;
    }

    // SNMP message is wrapped in a SEQUENCE
    if payload[0] != BER_SEQUENCE {
        return None;
    }

    // Parse SEQUENCE length
    let (seq_len, mut offset) = parse_ber_length(&payload[1..])?;
    offset += 1; // Account for SEQUENCE tag

    // Check we have enough data
    if offset + seq_len > payload.len() {
        return None;
    }

    // Parse version (INTEGER)
    if offset >= payload.len() || payload[offset] != BER_INTEGER {
        return None;
    }
    offset += 1;

    let (version_len, len_bytes) = parse_ber_length(&payload[offset..])?;
    offset += len_bytes;

    if offset + version_len > payload.len() {
        return None;
    }

    let version = parse_version(&payload[offset..offset + version_len])?;
    offset += version_len;

    // Parse community string for v1/v2c (OCTET STRING)
    let community = if matches!(version, SnmpVersion::V1 | SnmpVersion::V2c) {
        if offset >= payload.len() || payload[offset] != BER_OCTET_STRING {
            None
        } else {
            offset += 1;
            let (comm_len, len_bytes) = parse_ber_length(&payload[offset..])?;
            offset += len_bytes;

            if offset + comm_len > payload.len() {
                None
            } else {
                let community_bytes = &payload[offset..offset + comm_len];
                offset += comm_len;
                std::str::from_utf8(community_bytes)
                    .ok()
                    .map(|s| s.to_string())
            }
        }
    } else {
        // v3 has different structure - skip community
        None
    };

    // Find PDU type (context-specific tag 0xA0-0xA8)
    let pdu_type = find_pdu_type(&payload[offset..])?;

    Some(SnmpInfo {
        version,
        community,
        pdu_type,
    })
}

/// Parse BER length encoding.
/// Returns (length, bytes consumed).
fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];

    if first < 0x80 {
        // Short form: length is in first byte
        Some((first as usize, 1))
    } else if first == 0x80 {
        // Indefinite form - not supported
        None
    } else {
        // Long form: first byte tells how many bytes encode the length
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }

        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (data[1 + i] as usize);
        }

        Some((length, 1 + num_bytes))
    }
}

/// Parse SNMP version from INTEGER value
fn parse_version(data: &[u8]) -> Option<SnmpVersion> {
    if data.is_empty() {
        return None;
    }

    // Version is encoded as 0=v1, 1=v2c, 3=v3
    match data[data.len() - 1] {
        0 => Some(SnmpVersion::V1),
        1 => Some(SnmpVersion::V2c),
        3 => Some(SnmpVersion::V3),
        _ => None,
    }
}

/// Find the PDU type in the remaining data
fn find_pdu_type(data: &[u8]) -> Option<SnmpPduType> {
    // Look for context-specific tags (0xA0-0xA8)
    for &byte in data.iter().take(50) {
        // Limit search
        if (PDU_GET_REQUEST..=PDU_REPORT).contains(&byte) {
            return Some(match byte {
                PDU_GET_REQUEST => SnmpPduType::GetRequest,
                PDU_GET_NEXT_REQUEST => SnmpPduType::GetNextRequest,
                PDU_GET_RESPONSE => SnmpPduType::GetResponse,
                PDU_SET_REQUEST => SnmpPduType::SetRequest,
                PDU_TRAP_V1 => SnmpPduType::Trap,
                PDU_GET_BULK_REQUEST => SnmpPduType::GetBulkRequest,
                PDU_INFORM_REQUEST => SnmpPduType::InformRequest,
                PDU_TRAP_V2 => SnmpPduType::TrapV2,
                PDU_REPORT => SnmpPduType::Report,
                other => SnmpPduType::Unknown(other),
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_snmp_v1_get(community: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // SEQUENCE
        packet.push(BER_SEQUENCE);
        // We'll update length later
        let len_pos = packet.len();
        packet.push(0x00); // Placeholder

        // Version: INTEGER 0 (v1)
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x00);

        // Community: OCTET STRING
        packet.push(BER_OCTET_STRING);
        packet.push(community.len() as u8);
        packet.extend_from_slice(community.as_bytes());

        // GetRequest PDU
        packet.push(PDU_GET_REQUEST);
        packet.push(0x10); // PDU length
        // Request ID
        packet.push(BER_INTEGER);
        packet.push(0x04);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // Error status
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x00);
        // Error index
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x00);
        // Variable bindings (empty)
        packet.push(BER_SEQUENCE);
        packet.push(0x00);

        // Update length
        packet[len_pos] = (packet.len() - len_pos - 1) as u8;

        packet
    }

    fn build_snmp_v2c_response(community: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.push(BER_SEQUENCE);
        let len_pos = packet.len();
        packet.push(0x00);

        // Version: 1 (v2c)
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x01);

        // Community
        packet.push(BER_OCTET_STRING);
        packet.push(community.len() as u8);
        packet.extend_from_slice(community.as_bytes());

        // GetResponse PDU
        packet.push(PDU_GET_RESPONSE);
        packet.push(0x10);
        packet.push(BER_INTEGER);
        packet.push(0x04);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x00);
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x00);
        packet.push(BER_SEQUENCE);
        packet.push(0x00);

        packet[len_pos] = (packet.len() - len_pos - 1) as u8;

        packet
    }

    #[test]
    fn test_snmp_v1_get() {
        let packet = build_snmp_v1_get("public");
        let info = analyze_snmp(&packet).expect("should parse");
        assert_eq!(info.version, SnmpVersion::V1);
        assert_eq!(info.community, Some("public".to_string()));
        assert_eq!(info.pdu_type, SnmpPduType::GetRequest);
    }

    #[test]
    fn test_snmp_v2c_response() {
        let packet = build_snmp_v2c_response("private");
        let info = analyze_snmp(&packet).expect("should parse");
        assert_eq!(info.version, SnmpVersion::V2c);
        assert_eq!(info.community, Some("private".to_string()));
        assert_eq!(info.pdu_type, SnmpPduType::GetResponse);
    }

    #[test]
    fn test_snmp_too_short() {
        let packet = [0x30, 0x05, 0x02, 0x01, 0x00];
        assert!(analyze_snmp(&packet).is_none());
    }

    #[test]
    fn test_snmp_not_sequence() {
        let packet = [
            0x31, 0x10, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        ];
        assert!(analyze_snmp(&packet).is_none());
    }

    #[test]
    fn test_ber_length_short() {
        let data = [0x10];
        let (len, bytes) = parse_ber_length(&data).unwrap();
        assert_eq!(len, 16);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn test_ber_length_long() {
        let data = [0x82, 0x01, 0x00]; // 256
        let (len, bytes) = parse_ber_length(&data).unwrap();
        assert_eq!(len, 256);
        assert_eq!(bytes, 3);
    }
}
