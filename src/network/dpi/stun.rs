//! STUN (Session Traversal Utilities for NAT) Deep Packet Inspection
//!
//! Parses STUN packets according to RFC 5389 / RFC 8489.
//! STUN uses UDP port 3478 (and 5349 for STUN over TLS).

use crate::network::types::{StunInfo, StunMessageClass, StunMethod};

/// STUN header is exactly 20 bytes
const STUN_HEADER_SIZE: usize = 20;

/// Magic cookie value (RFC 5389 section 6)
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN attribute type: SOFTWARE (0x8022)
const ATTR_SOFTWARE: u16 = 0x8022;

/// Maximum SOFTWARE attribute length to prevent allocating huge strings
const MAX_SOFTWARE_LEN: usize = 128;

/// Analyze a STUN packet and extract key information.
///
/// Returns `None` if the packet is too small, lacks the magic cookie,
/// or has invalid structural properties.
pub fn analyze_stun(payload: &[u8]) -> Option<StunInfo> {
    if payload.len() < STUN_HEADER_SIZE {
        return None;
    }

    // First two bits must be 0b00 (distinguishes STUN from DTLS/RTP/RTCP)
    if payload[0] & 0xC0 != 0x00 {
        return None;
    }

    // Verify magic cookie at bytes 4-7
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return None;
    }

    // Message length (bytes 2-3) must be multiple of 4
    let message_length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if !message_length.is_multiple_of(4) {
        return None;
    }

    // Verify we have enough payload for the declared length
    if payload.len() < STUN_HEADER_SIZE + message_length {
        return None;
    }

    // Decode message type (bytes 0-1, 14 bits after masking top 2 bits)
    let msg_type = u16::from_be_bytes([payload[0] & 0x3F, payload[1]]);

    // Extract class bits: C1 is bit 8, C0 is bit 4 (RFC 5389 section 6)
    let c0 = (msg_type >> 4) & 0x1;
    let c1 = (msg_type >> 8) & 0x1;
    let class_bits = (c1 << 1) | c0;

    let message_class = match class_bits {
        0b00 => StunMessageClass::Request,
        0b01 => StunMessageClass::Indication,
        0b10 => StunMessageClass::SuccessResponse,
        0b11 => StunMessageClass::ErrorResponse,
        _ => unreachable!(),
    };

    // Extract method: remove the class bits from msg_type
    let m0_3 = msg_type & 0x000F;
    let m4_6 = (msg_type >> 1) & 0x0070;
    let m7_11 = (msg_type >> 2) & 0x0F80;
    let method_value = m7_11 | m4_6 | m0_3;

    let method = match method_value {
        0x0001 => StunMethod::Binding,
        other => StunMethod::Unknown(other),
    };

    // Extract 96-bit transaction ID (bytes 8-19)
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&payload[8..20]);

    // Best-effort attribute parsing for SOFTWARE
    let software = parse_software_attribute(payload, message_length);

    Some(StunInfo {
        message_class,
        method,
        transaction_id,
        software,
    })
}

/// Check if a packet looks like STUN without full parsing.
/// Used for non-standard port detection where we want a quick probe.
pub fn is_likely_stun(payload: &[u8]) -> bool {
    if payload.len() < STUN_HEADER_SIZE {
        return false;
    }
    if payload[0] & 0xC0 != 0x00 {
        return false;
    }
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    cookie == STUN_MAGIC_COOKIE
}

/// Walk STUN attributes looking for the SOFTWARE attribute (0x8022).
fn parse_software_attribute(payload: &[u8], message_length: usize) -> Option<String> {
    let attrs_end = STUN_HEADER_SIZE + message_length;
    let mut offset = STUN_HEADER_SIZE;

    while offset + 4 <= attrs_end {
        let attr_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let attr_length = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;

        offset += 4;

        if offset + attr_length > attrs_end {
            return None;
        }

        if attr_type == ATTR_SOFTWARE {
            let effective_len = attr_length.min(MAX_SOFTWARE_LEN);
            return std::str::from_utf8(&payload[offset..offset + effective_len])
                .ok()
                .map(|s| s.trim_end_matches('\0').to_string());
        }

        // Advance to next attribute, padding to 4-byte boundary
        let padded_length = (attr_length + 3) & !3;
        offset += padded_length;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a STUN packet with the given class, method, and body (attributes).
    fn build_stun_packet(class: u8, method: u16, msg_body: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();

        // Encode message type from class + method (RFC 5389 section 6)
        let c0 = class & 0x1;
        let c1 = (class >> 1) & 0x1;
        let m0_3 = method & 0x000F;
        let m4_6 = (method & 0x0070) << 1;
        let m7_11 = (method & 0x0F80) << 2;
        let msg_type = m7_11 | ((c1 as u16) << 8) | m4_6 | ((c0 as u16) << 4) | m0_3;

        packet.push((msg_type >> 8) as u8);
        packet.push((msg_type & 0xFF) as u8);

        // Message length
        let body_len = msg_body.len() as u16;
        packet.push((body_len >> 8) as u8);
        packet.push((body_len & 0xFF) as u8);

        // Magic cookie
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        packet.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ]);

        packet.extend_from_slice(msg_body);
        packet
    }

    /// Build a SOFTWARE attribute (0x8022) with proper TLV + padding.
    fn build_software_attr(software: &str) -> Vec<u8> {
        let mut attr = Vec::new();
        attr.push(0x80);
        attr.push(0x22);
        let len = software.len() as u16;
        attr.push((len >> 8) as u8);
        attr.push((len & 0xFF) as u8);
        attr.extend_from_slice(software.as_bytes());
        while attr.len() % 4 != 0 {
            attr.push(0x00);
        }
        attr
    }

    #[test]
    fn test_empty_payload_safe() {
        assert!(analyze_stun(&[]).is_none());
    }

    #[test]
    fn test_short_payload_safe() {
        assert!(analyze_stun(&[0x00, 0x01]).is_none());
    }

    #[test]
    fn test_binding_request() {
        let packet = build_stun_packet(0, 0x0001, &[]);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.message_class, StunMessageClass::Request);
        assert_eq!(info.method, StunMethod::Binding);
        assert_eq!(info.transaction_id, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        assert!(info.software.is_none());
    }

    #[test]
    fn test_binding_success_response() {
        let packet = build_stun_packet(2, 0x0001, &[]);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.message_class, StunMessageClass::SuccessResponse);
        assert_eq!(info.method, StunMethod::Binding);
    }

    #[test]
    fn test_binding_error_response() {
        let packet = build_stun_packet(3, 0x0001, &[]);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.message_class, StunMessageClass::ErrorResponse);
        assert_eq!(info.method, StunMethod::Binding);
    }

    #[test]
    fn test_binding_indication() {
        let packet = build_stun_packet(1, 0x0001, &[]);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.message_class, StunMessageClass::Indication);
    }

    #[test]
    fn test_with_software_attribute() {
        let software_attr = build_software_attr("TestAgent/1.0");
        let packet = build_stun_packet(2, 0x0001, &software_attr);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.software, Some("TestAgent/1.0".to_string()));
    }

    #[test]
    fn test_too_short() {
        let packet = [0x00; 10];
        assert!(analyze_stun(&packet).is_none());
    }

    #[test]
    fn test_wrong_magic_cookie() {
        let mut packet = build_stun_packet(0, 0x0001, &[]);
        packet[4] = 0xFF;
        assert!(analyze_stun(&packet).is_none());
    }

    #[test]
    fn test_first_two_bits_nonzero() {
        let mut packet = build_stun_packet(0, 0x0001, &[]);
        packet[0] |= 0x80;
        assert!(analyze_stun(&packet).is_none());
    }

    #[test]
    fn test_message_length_not_multiple_of_4() {
        let mut packet = build_stun_packet(0, 0x0001, &[]);
        packet[2] = 0x00;
        packet[3] = 0x03;
        assert!(analyze_stun(&packet).is_none());
    }

    #[test]
    fn test_message_length_exceeds_payload() {
        let mut packet = build_stun_packet(0, 0x0001, &[]);
        packet[2] = 0x00;
        packet[3] = 0x64;
        assert!(analyze_stun(&packet).is_none());
    }

    #[test]
    fn test_unknown_method() {
        let packet = build_stun_packet(0, 0x0003, &[]);
        let info = analyze_stun(&packet).expect("should parse");
        assert_eq!(info.method, StunMethod::Unknown(0x0003));
    }

    #[test]
    fn test_is_likely_stun() {
        let packet = build_stun_packet(0, 0x0001, &[]);
        assert!(is_likely_stun(&packet));

        let not_stun = [0x80u8; 20];
        assert!(!is_likely_stun(&not_stun));

        let too_short = [0x00u8; 10];
        assert!(!is_likely_stun(&too_short));
    }
}
