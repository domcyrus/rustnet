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
    parse_cooked(data, parser, 16, 14, "Linux SLL", process_name, process_id)
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
    parse_cooked(data, parser, 20, 0, "Linux SLL2", process_name, process_id)
}

/// Shared body for both cooked-capture versions.
///
/// `header_len` is the cooked header size, `proto_offset` the position of the
/// EtherType field within it. A VLAN tag (SLL: reconstructed by libpcap from
/// kernel metadata; SLL2: visible when rx-vlan-offload is disabled, libpcap
/// does not reconstruct tags for SLL2, see libpcap#1105) puts TPID 0x8100 in
/// the EtherType field and appends TCI (2 bytes) + inner EtherType (2 bytes),
/// so the payload then starts at `header_len + 4`.
fn parse_cooked(
    data: &[u8],
    parser: &PacketParser,
    header_len: usize,
    proto_offset: usize,
    name: &str,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.len() < header_len {
        log::debug!("{} packet too small: {} bytes", name, data.len());
        return None;
    }

    let protocol = u16::from_be_bytes([data[proto_offset], data[proto_offset + 1]]);

    let (protocol, payload_offset) = if protocol == 0x8100 {
        if data.len() < header_len + 4 {
            log::debug!("{}: VLAN frame too small: {} bytes", name, data.len());
            return None;
        }
        let inner_proto = u16::from_be_bytes([data[header_len + 2], data[header_len + 3]]);
        log::trace!("{}: 802.1Q VLAN tag detected", name);
        (inner_proto, header_len + 4)
    } else {
        (protocol, header_len)
    };

    match protocol {
        0x0800 => {
            // IPv4 - the cooked header is sliced off, so packet_len excludes it
            log::trace!("{}: IPv4 packet detected", name);
            parser.parse_raw_ipv4_packet(&data[payload_offset..], process_name, process_id)
        }
        0x86dd => {
            // IPv6 - the cooked header is sliced off, so packet_len excludes it
            log::trace!("{}: IPv6 packet detected", name);
            parser.parse_raw_ipv6_packet(&data[payload_offset..], process_name, process_id)
        }
        0x0806 => {
            // ARP - packet_len covers the whole captured frame
            log::trace!("{}: ARP packet detected", name);
            parser.parse_arp_packet_with_offset(data, payload_offset, process_name, process_id)
        }
        _ => {
            log::debug!("{}: Unknown protocol: 0x{:04x}", name, protocol);
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

    #[test]
    fn test_sll_vlan_too_small() {
        // SLL VLAN frame needs at least 20 bytes (16 header + 4 VLAN tag)
        let mut packet = vec![0x00; 19];
        packet[14] = 0x81; // Protocol = 0x8100 (VLAN)
        packet[15] = 0x00;
        let parser = PacketParser::new();
        assert!(parse_sll(&packet, &parser, None, None).is_none());
    }

    #[test]
    fn test_sll2_vlan_too_small() {
        // SLL2 VLAN frame needs at least 24 bytes (20 header + 4 VLAN tag)
        let mut packet = vec![0x00; 23];
        packet[0] = 0x81; // Protocol = 0x8100 (VLAN)
        packet[1] = 0x00;
        let parser = PacketParser::new();
        assert!(parse_sll2(&packet, &parser, None, None).is_none());
    }
}
