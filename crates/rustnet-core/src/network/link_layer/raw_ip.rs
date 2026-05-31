//! Raw IP packet parsing (no link-layer header)
//!
//! Handles DLT_RAW (12), DLT_NULL (0), LINKTYPE_RAW (101),
//! LINKTYPE_IPV4 (228), and LINKTYPE_IPV6 (229)
//!
//! Used by TUN devices which operate at Layer 3 (network layer)

use crate::network::parser::{PacketParser, ParsedPacket};

/// Parse a raw IP packet (auto-detect IPv4 or IPv6)
///
/// TUN devices typically send raw IP packets without any link-layer header.
/// The first nibble of the packet indicates the IP version.
pub fn parse(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.is_empty() {
        log::debug!("Raw IP: Empty packet");
        return None;
    }

    // Check IP version from first nibble
    let version = data[0] >> 4;
    match version {
        4 => {
            log::trace!("Raw IP: IPv4 packet detected");
            parser.parse_raw_ipv4_packet(data, process_name, process_id)
        }
        6 => {
            log::trace!("Raw IP: IPv6 packet detected");
            parser.parse_raw_ipv6_packet(data, process_name, process_id)
        }
        _ => {
            log::debug!("Raw IP: Unknown IP version: {}", version);
            None
        }
    }
}

/// Parse a raw IPv4 packet only
///
/// Used when the link type explicitly indicates IPv4 (LINKTYPE_IPV4 = 228)
pub fn parse_ipv4(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.is_empty() || data.len() < 20 {
        log::debug!("Raw IPv4: Packet too small");
        return None;
    }

    let version = data[0] >> 4;
    if version != 4 {
        log::warn!("Raw IPv4: Expected IPv4 but got version {}", version);
        return None;
    }

    log::trace!("Raw IPv4: Parsing IPv4 packet");
    parser.parse_raw_ipv4_packet(data, process_name, process_id)
}

/// Parse a raw IPv6 packet only
///
/// Used when the link type explicitly indicates IPv6 (LINKTYPE_IPV6 = 229)
pub fn parse_ipv6(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    if data.is_empty() || data.len() < 40 {
        log::debug!("Raw IPv6: Packet too small");
        return None;
    }

    let version = data[0] >> 4;
    if version != 6 {
        log::warn!("Raw IPv6: Expected IPv6 but got version {}", version);
        return None;
    }

    log::trace!("Raw IPv6: Parsing IPv6 packet");
    parser.parse_raw_ipv6_packet(data, process_name, process_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_ip_empty_packet() {
        let empty = vec![];
        let parser = PacketParser::new();
        assert!(parse(&empty, &parser, None, None).is_none());
    }

    #[test]
    fn test_raw_ipv4_version_check() {
        // Create a minimal IPv6 packet but try to parse as IPv4
        let ipv6_packet = vec![0x60, 0x00, 0x00, 0x00]; // Version 6
        let parser = PacketParser::new();
        assert!(parse_ipv4(&ipv6_packet, &parser, None, None).is_none());
    }

    #[test]
    fn test_raw_ipv6_version_check() {
        // Create a minimal IPv4 packet but try to parse as IPv6
        let ipv4_packet = vec![0x45, 0x00, 0x00, 0x00]; // Version 4
        let parser = PacketParser::new();
        assert!(parse_ipv6(&ipv4_packet, &parser, None, None).is_none());
    }
}
