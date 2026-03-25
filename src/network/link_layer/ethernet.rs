//! Ethernet (IEEE 802.3) frame parsing
//!
//! Handles DLT_EN10MB (Ethernet) frames with 14-byte headers and
//! 802.1Q VLAN-tagged frames with 18-byte headers.

use crate::network::parser::{PacketParser, ParsedPacket};

/// Extract the effective EtherType and payload offset from an Ethernet frame.
///
/// Returns `(ethertype, offset)` where `offset` is the number of bytes before
/// the IP/ARP payload:
/// - Standard frame: offset = 14
/// - 802.1Q VLAN-tagged frame: offset = 18 (extra 4-byte VLAN tag)
fn extract_ethertype(data: &[u8]) -> Option<(u16, usize)> {
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype == 0x8100 {
        if data.len() < 18 {
            log::debug!("VLAN frame too small: {} bytes", data.len());
            return None;
        }
        let vlan_id = u16::from_be_bytes([data[14], data[15]]) & 0x0FFF;
        log::trace!("Ethernet: 802.1Q VLAN tag detected (VID={})", vlan_id);
        Some((u16::from_be_bytes([data[16], data[17]]), 18))
    } else {
        Some((ethertype, 14))
    }
}

/// Parse an Ethernet frame and extract the network layer packet
///
/// Standard Ethernet frame format (14 bytes):
/// - Destination MAC (6 bytes)
/// - Source MAC (6 bytes)
/// - EtherType (2 bytes)
///
/// 802.1Q VLAN-tagged frame format (18 bytes):
/// - Destination MAC (6 bytes)
/// - Source MAC (6 bytes)
/// - TPID: 0x8100 (2 bytes)
/// - TCI: PCP (3 bits) | DEI (1 bit) | VID (12 bits) (2 bytes)
/// - Inner EtherType (2 bytes)
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

    let (ethertype, offset) = extract_ethertype(data)?;

    match ethertype {
        0x0800 => {
            // IPv4
            log::trace!("Ethernet: IPv4 packet detected");
            parser.parse_ipv4_packet_inner(data, offset, process_name, process_id)
        }
        0x86dd => {
            // IPv6
            log::trace!("Ethernet: IPv6 packet detected");
            parser.parse_ipv6_packet_inner(data, offset, process_name, process_id)
        }
        0x0806 => {
            // ARP
            log::trace!("Ethernet: ARP packet detected");
            parser.parse_arp_packet_inner(data, offset, process_name, process_id)
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

    #[test]
    fn test_extract_ethertype_vlan() {
        // Build an 18-byte 802.1Q VLAN-tagged frame:
        //   bytes 0-11:  MACs (zeroed)
        //   bytes 12-13: TPID 0x8100
        //   bytes 14-15: TCI  (VID = 42)
        //   bytes 16-17: inner EtherType 0x0800 (IPv4)
        let mut frame = vec![0u8; 18];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[14] = 0x00;
        frame[15] = 0x2a; // VID = 42
        frame[16] = 0x08;
        frame[17] = 0x00;

        let (ethertype, offset) = extract_ethertype(&frame).unwrap();
        assert_eq!(ethertype, 0x0800);
        assert_eq!(offset, 18);
    }

    #[test]
    fn test_extract_ethertype_vlan_ipv6() {
        let mut frame = vec![0u8; 18];
        frame[12] = 0x81;
        frame[13] = 0x00;
        frame[14] = 0x00;
        frame[15] = 0x2a; // VID = 42
        frame[16] = 0x86;
        frame[17] = 0xdd; // inner EtherType = IPv6

        let (ethertype, offset) = extract_ethertype(&frame).unwrap();
        assert_eq!(ethertype, 0x86dd);
        assert_eq!(offset, 18);
    }

    #[test]
    fn test_extract_ethertype_vlan_too_small() {
        // VLAN frame must be at least 18 bytes; 17 should return None
        let mut frame = vec![0u8; 17];
        frame[12] = 0x81;
        frame[13] = 0x00;

        assert!(extract_ethertype(&frame).is_none());
    }
}
