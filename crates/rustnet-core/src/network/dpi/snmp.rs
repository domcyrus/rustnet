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

    // Parse community string for v1/v2c (OCTET STRING). It is mandatory in
    // both versions (RFC 1157 §4, RFC 3416), so its absence means the
    // payload is not SNMP.
    let (community, pdu_type) = match version {
        SnmpVersion::V1 | SnmpVersion::V2c => {
            if offset >= payload.len() || payload[offset] != BER_OCTET_STRING {
                return None;
            }
            offset += 1;
            let (comm_len, len_bytes) = parse_ber_length(&payload[offset..])?;
            offset += len_bytes;

            if offset + comm_len > payload.len() {
                return None;
            }
            let community_bytes = &payload[offset..offset + comm_len];
            offset += comm_len;
            let community = std::str::from_utf8(community_bytes)
                .ok()
                .map(|s| s.to_string());

            // The PDU tag directly follows the community string.
            (community, pdu_type_at(payload, offset)?)
        }
        SnmpVersion::V3 => (None, v3_pdu_type(payload, offset)?),
    };

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

/// Read the PDU tag expected at exactly `offset`. Structural — never scans:
/// a byte in the 0xA0-0xA8 range inside a length or INTEGER value (e.g. a
/// request-id) must not be mistaken for a PDU tag.
fn pdu_type_at(payload: &[u8], offset: usize) -> Option<SnmpPduType> {
    let pdu_type = match *payload.get(offset)? {
        PDU_GET_REQUEST => SnmpPduType::GetRequest,
        PDU_GET_NEXT_REQUEST => SnmpPduType::GetNextRequest,
        PDU_GET_RESPONSE => SnmpPduType::GetResponse,
        PDU_SET_REQUEST => SnmpPduType::SetRequest,
        PDU_TRAP_V1 => SnmpPduType::Trap,
        PDU_GET_BULK_REQUEST => SnmpPduType::GetBulkRequest,
        PDU_INFORM_REQUEST => SnmpPduType::InformRequest,
        PDU_TRAP_V2 => SnmpPduType::TrapV2,
        PDU_REPORT => SnmpPduType::Report,
        _ => return None,
    };
    Some(pdu_type)
}

/// Walk the SNMPv3 message structure (RFC 3412 §6) to the PDU tag:
/// msgGlobalData (SEQUENCE) and msgSecurityParameters (OCTET STRING) are
/// skipped whole, then msgData is either a plaintext ScopedPDU — a SEQUENCE
/// holding contextEngineID, contextName, and the PDU — or an encrypted
/// OCTET STRING, in which case the PDU type is not visible.
fn v3_pdu_type(payload: &[u8], offset: usize) -> Option<SnmpPduType> {
    let offset = skip_tlv(payload, offset, BER_SEQUENCE)?; // msgGlobalData
    let offset = skip_tlv(payload, offset, BER_OCTET_STRING)?; // msgSecurityParameters

    match *payload.get(offset)? {
        BER_SEQUENCE => {
            // Plaintext ScopedPDU: enter the SEQUENCE, then skip
            // contextEngineID and contextName.
            let mut offset = offset + 1;
            let (_, len_bytes) = parse_ber_length(&payload[offset..])?;
            offset += len_bytes;
            let offset = skip_tlv(payload, offset, BER_OCTET_STRING)?; // contextEngineID
            let offset = skip_tlv(payload, offset, BER_OCTET_STRING)?; // contextName
            pdu_type_at(payload, offset)
        }
        BER_OCTET_STRING => Some(SnmpPduType::Encrypted),
        _ => None,
    }
}

/// Skip one TLV with the expected tag, returning the offset just past it.
fn skip_tlv(payload: &[u8], offset: usize, expected_tag: u8) -> Option<usize> {
    if *payload.get(offset)? != expected_tag {
        return None;
    }
    let offset = offset + 1;
    let (len, len_bytes) = parse_ber_length(&payload[offset..])?;
    let end = offset.checked_add(len_bytes)?.checked_add(len)?;
    (end <= payload.len()).then_some(end)
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

    /// Build an SNMPv3 message. `scoped_pdu_plaintext` selects between a
    /// plaintext ScopedPDU (carrying a GetRequest) and an encrypted one.
    fn build_snmp_v3(scoped_pdu_plaintext: bool) -> Vec<u8> {
        let mut packet = Vec::new();

        packet.push(BER_SEQUENCE);
        let len_pos = packet.len();
        packet.push(0x00);

        // Version: INTEGER 3 (v3)
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x03);

        // msgGlobalData SEQUENCE: msgID, msgMaxSize, msgFlags, msgSecurityModel.
        // The msgID value 0x12A34456 deliberately contains a 0xA3 byte — the
        // old scanning detector misread it as a SetRequest PDU tag.
        packet.push(BER_SEQUENCE);
        packet.push(0x10);
        packet.push(BER_INTEGER);
        packet.push(0x04);
        packet.extend_from_slice(&[0x12, 0xA3, 0x44, 0x56]); // msgID
        packet.push(BER_INTEGER);
        packet.push(0x02);
        packet.extend_from_slice(&[0x05, 0xDC]); // msgMaxSize 1500
        packet.push(BER_OCTET_STRING);
        packet.push(0x01);
        packet.push(0x04); // msgFlags: reportable
        packet.push(BER_INTEGER);
        packet.push(0x01);
        packet.push(0x03); // msgSecurityModel: USM

        // msgSecurityParameters: opaque OCTET STRING
        packet.push(BER_OCTET_STRING);
        packet.push(0x02);
        packet.extend_from_slice(&[0x30, 0x00]);

        if scoped_pdu_plaintext {
            // ScopedPDU SEQUENCE: contextEngineID, contextName, PDU
            packet.push(BER_SEQUENCE);
            packet.push(0x0D);
            packet.push(BER_OCTET_STRING);
            packet.push(0x02);
            packet.extend_from_slice(&[0x80, 0x01]); // contextEngineID
            packet.push(BER_OCTET_STRING);
            packet.push(0x00); // contextName (empty)
            packet.push(PDU_GET_REQUEST);
            packet.push(0x05);
            packet.push(BER_INTEGER);
            packet.push(0x01);
            packet.push(0x01); // request-id
            packet.push(BER_SEQUENCE);
            packet.push(0x00); // varbinds (empty)
        } else {
            // Encrypted ScopedPDU: opaque OCTET STRING
            packet.push(BER_OCTET_STRING);
            packet.push(0x04);
            packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }

        packet[len_pos] = (packet.len() - len_pos - 1) as u8;
        packet
    }

    #[test]
    fn test_snmp_v3_plaintext_scoped_pdu() {
        let packet = build_snmp_v3(true);
        let info = analyze_snmp(&packet).expect("should parse");
        assert_eq!(info.version, SnmpVersion::V3);
        assert_eq!(info.community, None);
        assert_eq!(info.pdu_type, SnmpPduType::GetRequest);
    }

    #[test]
    fn test_snmp_v3_encrypted_scoped_pdu() {
        let packet = build_snmp_v3(false);
        let info = analyze_snmp(&packet).expect("should parse");
        assert_eq!(info.version, SnmpVersion::V3);
        assert_eq!(info.pdu_type, SnmpPduType::Encrypted);
    }

    #[test]
    fn test_pdu_tag_not_scanned_from_value_bytes() {
        // A v1 message whose community is followed by a non-PDU byte must be
        // rejected — the detector must not scan ahead for a 0xA0-0xA8 byte.
        let mut packet = build_snmp_v1_get("public");
        // Overwrite the PDU tag with an INTEGER tag: still not SNMP.
        let pdu_pos = packet.iter().position(|&b| b == PDU_GET_REQUEST).unwrap();
        packet[pdu_pos] = BER_INTEGER;
        assert!(analyze_snmp(&packet).is_none());
    }
}
