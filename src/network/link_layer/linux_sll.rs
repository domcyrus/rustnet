//! Linux "cooked" capture parsing
//!
//! Handles DLT_LINUX_SLL (113) and DLT_LINUX_SLL2 (276)
//! Used by the Linux "any" pseudo-interface

use crate::network::parser::{PacketParser, ParsedPacket};

/// Parse Linux Cooked Capture v1 packet (DLT_LINUX_SLL)
///
/// Header format (16 bytes):
/// - Packet type (2 bytes)
/// - ARPHRD type (2 bytes)
/// - Link-layer address length (2 bytes)
/// - Link-layer address (8 bytes)
/// - Protocol type (2 bytes) - EtherType
///
/// IP payload starts at byte 16
pub fn parse_sll(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.len() < 16 {
        log::debug!("Linux SLL packet too small: {} bytes", data.len());
        return None;
    }

    // Protocol type is at bytes 14-15 (EtherType)
    let protocol = u16::from_be_bytes([data[14], data[15]]);

    match protocol {
        0x0800 => {
            // IPv4 - payload starts at byte 16
            log::trace!("Linux SLL: IPv4 packet detected");
            let ip_data = &data[16..];
            parser.parse_raw_ipv4_packet(ip_data, process_name, process_id)
        }
        0x86dd => {
            // IPv6 - payload starts at byte 16
            log::trace!("Linux SLL: IPv6 packet detected");
            let ip_data = &data[16..];
            parser.parse_raw_ipv6_packet(ip_data, process_name, process_id)
        }
        _ => {
            log::debug!("Linux SLL: Unknown protocol: 0x{:04x}", protocol);
            None
        }
    }
}

/// Parse Linux Cooked Capture v2 packet (DLT_LINUX_SLL2)
///
/// Header format (20 bytes):
/// - Protocol type (2 bytes) - EtherType
/// - Reserved (2 bytes)
/// - Interface index (4 bytes)
/// - ARPHRD type (2 bytes)
/// - Packet type (1 byte)
/// - Link-layer address length (1 byte)
/// - Link-layer address (8 bytes)
///
/// IP payload starts at byte 20
pub fn parse_sll2(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.len() < 20 {
        log::debug!("Linux SLL2 packet too small: {} bytes", data.len());
        return None;
    }

    // Protocol type is at bytes 0-1 (EtherType)
    let protocol = u16::from_be_bytes([data[0], data[1]]);

    match protocol {
        0x0800 => {
            // IPv4 - payload starts at byte 20
            log::trace!("Linux SLL2: IPv4 packet detected");
            let ip_data = &data[20..];
            parser.parse_raw_ipv4_packet(ip_data, process_name, process_id)
        }
        0x86dd => {
            // IPv6 - payload starts at byte 20
            log::trace!("Linux SLL2: IPv6 packet detected");
            let ip_data = &data[20..];
            parser.parse_raw_ipv6_packet(ip_data, process_name, process_id)
        }
        _ => {
            log::debug!("Linux SLL2: Unknown protocol: 0x{:04x}", protocol);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sll_packet_too_small() {
        let small_packet = vec![0x00; 10];
        let parser = PacketParser::new();
        assert!(parse_sll(&small_packet, &parser, None, None).is_none());
    }

    #[test]
    fn test_sll2_packet_too_small() {
        let small_packet = vec![0x00; 15];
        let parser = PacketParser::new();
        assert!(parse_sll2(&small_packet, &parser, None, None).is_none());
    }
}
