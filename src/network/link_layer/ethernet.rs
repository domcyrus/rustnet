//! Ethernet (IEEE 802.3) frame parsing
//!
//! Handles DLT_EN10MB (Ethernet) frames with 14-byte header

use crate::network::parser::{PacketParser, ParsedPacket};

/// Parse an Ethernet frame and extract the network layer packet
///
/// Ethernet frame format (14 bytes):
/// - Destination MAC (6 bytes)
/// - Source MAC (6 bytes)
/// - EtherType (2 bytes)
///
/// Returns the parsed packet if successful
pub fn parse(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.len() < 14 {
        log::debug!("Ethernet frame too small: {} bytes", data.len());
        return None;
    }

    // Extract EtherType from bytes 12-13
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    match ethertype {
        0x0800 => {
            // IPv4
            log::trace!("Ethernet: IPv4 packet detected");
            parser.parse_ipv4_packet_inner(data, process_name, process_id)
        }
        0x86dd => {
            // IPv6
            log::trace!("Ethernet: IPv6 packet detected");
            parser.parse_ipv6_packet_inner(data, process_name, process_id)
        }
        0x0806 => {
            // ARP
            log::trace!("Ethernet: ARP packet detected");
            parser.parse_arp_packet_inner(data, process_name, process_id)
        }
        _ => {
            log::debug!("Ethernet: Unknown EtherType: 0x{:04x}", ethertype);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethernet_frame_too_small() {
        // Ethernet frames must be at least 14 bytes
        let small_frame = vec![0x00, 0x11, 0x22];
        let parser = PacketParser::new();
        assert!(parse(&small_frame, &parser, None, None).is_none());
    }
}
