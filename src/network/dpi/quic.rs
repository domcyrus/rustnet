use crate::network::types::{QuicConnectionState, QuicInfo, QuicPacketType};

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

    // Source Connection ID (we parse but don't store it in the simplified structure)
    if offset >= payload.len() {
        return None;
    }
    let scid_len = payload[offset] as usize;
    offset += 1;

    if offset + scid_len > payload.len() {
        return None;
    }
    // Skip SCID bytes
    // offset += scid_len;

    // Set connection state based on packet type
    quic_info.connection_state = match packet_type {
        QuicPacketType::Initial => QuicConnectionState::Initial,
        QuicPacketType::Handshake => QuicConnectionState::Handshaking,
        QuicPacketType::Retry => QuicConnectionState::Initial,
        QuicPacketType::VersionNegotiation => QuicConnectionState::Initial,
        QuicPacketType::ZeroRtt => QuicConnectionState::Handshaking,
        _ => QuicConnectionState::Unknown,
    };

    Some(quic_info)
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

fn get_long_packet_type(first_byte: u8, version: u32) -> QuicPacketType {
    let type_bits = (first_byte & 0x30) >> 4;

    // Check if this is QUIC v2
    if version == 0x6b3343cf {
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

// Helper function that should be available from your types module
fn quick_connection_id_to_hex(id: &[u8]) -> String {
    id.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_v1_initial_packet() {
        let packet = vec![
            0xc0, // Long header, Initial packet
            0x00, 0x00, 0x00, 0x01, // Version 1
            0x08, // DCID length
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
            0x00, // SCID length
        ];

        assert!(is_quic_packet(&packet));

        let info = parse_quic_packet(&packet).unwrap();
        assert_eq!(info.packet_type, QuicPacketType::Initial);
        assert_eq!(info.version_string, Some("v1".to_string()));
        assert_eq!(
            info.connection_id,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            info.connection_id_hex,
            Some("01:02:03:04:05:06:07:08".to_string())
        );
        assert_eq!(info.connection_state, QuicConnectionState::Initial);
    }

    #[test]
    fn test_quic_v2_handshake_packet() {
        let packet = vec![
            0xd0, // Long header, type 3 (Handshake in v2)
            0x6b, 0x33, 0x43, 0xcf, // Version 2
            0x04, // DCID length
            0x01, 0x02, 0x03, 0x04, // DCID
            0x04, // SCID length
            0x05, 0x06, 0x07, 0x08, // SCID
        ];

        assert!(is_quic_packet(&packet));

        let info = parse_quic_packet(&packet).unwrap();
        assert_eq!(info.packet_type, QuicPacketType::Handshake);
        assert_eq!(info.version_string, Some("v2".to_string()));
        assert_eq!(info.connection_state, QuicConnectionState::Handshaking);
    }

    #[test]
    fn test_short_header_packet() {
        let packet = vec![
            0x40, // Short header (fixed bit set)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Assumed DCID
            0x00, 0x00, 0x00, 0x00, // Some payload
        ];

        assert!(is_quic_packet(&packet));

        let info = parse_quic_packet(&packet).unwrap();
        assert_eq!(info.packet_type, QuicPacketType::OneRtt);
        assert_eq!(info.connection_state, QuicConnectionState::Connected);
        assert_eq!(info.version_string, None); // No version in short header
    }
}
