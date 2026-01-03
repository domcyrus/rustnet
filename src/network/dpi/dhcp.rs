//! DHCP (Dynamic Host Configuration Protocol) Deep Packet Inspection
//!
//! Parses DHCP packets according to RFC 2131.
//! DHCP uses UDP ports 67 (server) and 68 (client).

use crate::network::types::{DhcpInfo, DhcpMessageType};

/// Minimum DHCP packet size (fixed header + magic cookie)
const MIN_DHCP_SIZE: usize = 240;

/// DHCP magic cookie: 99.130.83.99 (0x63825363)
const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// DHCP option codes
const DHCP_OPT_HOSTNAME: u8 = 12;
const DHCP_OPT_MESSAGE_TYPE: u8 = 53;
const DHCP_OPT_END: u8 = 255;

/// Analyze a DHCP packet and extract key information.
///
/// Returns `None` if the packet is too small or doesn't have the DHCP magic cookie.
pub fn analyze_dhcp(payload: &[u8]) -> Option<DhcpInfo> {
    // Early size check
    if payload.len() < MIN_DHCP_SIZE {
        return None;
    }

    // Verify DHCP magic cookie at offset 236-239
    if payload[236..240] != DHCP_MAGIC_COOKIE {
        return None;
    }

    // Extract client MAC address from bytes 28-33 (chaddr field, first 6 bytes)
    let client_mac = format_mac(&payload[28..34]);

    // Parse DHCP options starting at byte 240
    let (message_type, hostname) = parse_dhcp_options(&payload[240..])?;

    Some(DhcpInfo {
        message_type,
        hostname,
        client_mac: Some(client_mac),
    })
}

/// Format a 6-byte MAC address as a string
fn format_mac(bytes: &[u8]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// Parse DHCP options and extract message type and hostname
fn parse_dhcp_options(options: &[u8]) -> Option<(DhcpMessageType, Option<String>)> {
    let mut message_type = None;
    let mut hostname = None;
    let mut offset = 0;

    while offset < options.len() {
        let opt_code = options[offset];

        // Option 255 = End
        if opt_code == DHCP_OPT_END {
            break;
        }

        // Option 0 = Pad (no length)
        if opt_code == 0 {
            offset += 1;
            continue;
        }

        // Need at least 1 more byte for length
        if offset + 1 >= options.len() {
            break;
        }

        let opt_len = options[offset + 1] as usize;

        // Bounds check for option data
        if offset + 2 + opt_len > options.len() {
            break;
        }

        let opt_data = &options[offset + 2..offset + 2 + opt_len];

        match opt_code {
            DHCP_OPT_MESSAGE_TYPE => {
                if opt_len >= 1 {
                    message_type = Some(parse_message_type(opt_data[0]));
                }
            }
            DHCP_OPT_HOSTNAME => {
                if let Ok(name) = std::str::from_utf8(opt_data) {
                    hostname = Some(name.to_string());
                }
            }
            _ => {}
        }

        offset += 2 + opt_len;
    }

    // Message type is required
    Some((message_type?, hostname))
}

/// Parse DHCP message type from option 53 value
fn parse_message_type(value: u8) -> DhcpMessageType {
    match value {
        1 => DhcpMessageType::Discover,
        2 => DhcpMessageType::Offer,
        3 => DhcpMessageType::Request,
        4 => DhcpMessageType::Decline,
        5 => DhcpMessageType::Ack,
        6 => DhcpMessageType::Nak,
        7 => DhcpMessageType::Release,
        8 => DhcpMessageType::Inform,
        other => DhcpMessageType::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dhcp_packet(msg_type: u8, hostname: Option<&str>, mac: &[u8; 6]) -> Vec<u8> {
        let mut packet = vec![0u8; 240];

        // Set client MAC at offset 28
        packet[28..34].copy_from_slice(mac);

        // Set magic cookie at offset 236
        packet[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

        // Add options
        // Option 53: DHCP Message Type
        packet.push(DHCP_OPT_MESSAGE_TYPE);
        packet.push(1); // length
        packet.push(msg_type);

        // Option 12: Hostname (if provided)
        if let Some(name) = hostname {
            packet.push(DHCP_OPT_HOSTNAME);
            packet.push(name.len() as u8);
            packet.extend_from_slice(name.as_bytes());
        }

        // Option 255: End
        packet.push(DHCP_OPT_END);

        packet
    }

    #[test]
    fn test_dhcp_discover() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let packet = build_dhcp_packet(1, Some("myhost"), &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Discover);
        assert_eq!(info.hostname, Some("myhost".to_string()));
        assert_eq!(info.client_mac, Some("aa:bb:cc:dd:ee:ff".to_string()));
    }

    #[test]
    fn test_dhcp_offer() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let packet = build_dhcp_packet(2, None, &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Offer);
        assert!(info.hostname.is_none());
    }

    #[test]
    fn test_dhcp_request() {
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let packet = build_dhcp_packet(3, Some("workstation-01"), &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Request);
        assert_eq!(info.hostname, Some("workstation-01".to_string()));
    }

    #[test]
    fn test_dhcp_ack() {
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let packet = build_dhcp_packet(5, None, &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Ack);
    }

    #[test]
    fn test_dhcp_too_short() {
        let packet = vec![0u8; 100];
        assert!(analyze_dhcp(&packet).is_none());
    }

    #[test]
    fn test_dhcp_bad_magic_cookie() {
        let mut packet = vec![0u8; 250];
        packet[236..240].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Wrong cookie
        assert!(analyze_dhcp(&packet).is_none());
    }

    #[test]
    fn test_dhcp_release() {
        let mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let packet = build_dhcp_packet(7, None, &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Release);
    }

    #[test]
    fn test_dhcp_inform() {
        let mac = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let packet = build_dhcp_packet(8, Some("printer"), &mac);
        let info = analyze_dhcp(&packet).expect("should parse");
        assert_eq!(info.message_type, DhcpMessageType::Inform);
        assert_eq!(info.hostname, Some("printer".to_string()));
    }
}
