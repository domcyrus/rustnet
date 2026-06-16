//! TUN/TAP interface support
//!
//! TUN (Layer 3) and TAP (Layer 2) virtual network interfaces
//!
//! - TUN: Operates at IP layer, carries raw IP packets (DLT_RAW or DLT_NULL)
//! - TAP: Operates at Ethernet layer, carries Ethernet frames (DLT_EN10MB)

use crate::network::link_layer::{ethernet, raw_ip};
use crate::network::parser::{PacketParser, ParsedPacket};

/// Detect if an interface name is a TUN interface
///
/// TUN interface naming conventions:
/// - Linux: `tun0`, `tun1`, etc.
/// - macOS: `utun0`, `utun1`, etc.
/// - BSD: `tun0`, `tun1`, etc.
pub fn is_tun_interface(name: &str) -> bool {
    name.starts_with("tun") || name.starts_with("utun")
}

/// Detect if an interface name is a TAP interface
///
/// TAP interface naming conventions:
/// - Linux: `tap0`, `tap1`, etc.
/// - macOS: `tap0`, `tap1`, etc. (requires third-party drivers)
/// - BSD: `tap0`, `tap1`, etc.
pub fn is_tap_interface(name: &str) -> bool {
    name.starts_with("tap")
}

/// Detect if an interface name is any tunnel interface (TUN or TAP)
pub fn is_tunnel_interface(name: &str) -> bool {
    is_tun_interface(name) || is_tap_interface(name)
}

/// Parse a TUN packet (raw IP, no link-layer header)
///
/// TUN devices operate at the network layer (Layer 3) and carry raw IP packets.
/// This is a convenience wrapper around raw_ip::parse()
pub fn parse_tun(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    log::trace!("TUN: Parsing raw IP packet ({} bytes)", data.len());
    raw_ip::parse(data, parser, process_name, process_id)
}

/// Parse a TAP packet (Ethernet frame with full header)
///
/// TAP devices operate at the data-link layer (Layer 2) and carry Ethernet frames.
/// This is a convenience wrapper around ethernet::parse()
pub fn parse_tap(
    data: &[u8],
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    log::trace!("TAP: Parsing Ethernet frame ({} bytes)", data.len());
    ethernet::parse(data, parser, process_name, process_id)
}

/// Determine the appropriate parser based on DLT type
///
/// This is the main entry point for parsing TUN/TAP packets when you know the DLT type.
pub fn parse_by_dlt(
    data: &[u8],
    dlt: i32,
    parser: &PacketParser,
    process_name: Option<String>,
    process_id: Option<u32>,
) -> Option<ParsedPacket> {
    match dlt {
        // DLT_NULL - BSD/macOS loopback: a 4-byte address-family header (host
        // byte order) precedes the raw IP packet, so strip it before parsing.
        // The inner IP version nibble selects v4/v6, so the family value itself
        // need not be decoded (its endianness varies by platform). Without this
        // skip, raw IP parsing reads the family header's first byte as the IP
        // version and silently drops every loopback packet.
        0 => {
            log::trace!("TUN/TAP: DLT_NULL (0)");
            if data.len() < 4 {
                return None;
            }
            parse_tun(&data[4..], parser, process_name, process_id)
        }
        // TAP devices use Ethernet (Layer 2)
        1 => {
            log::trace!("TUN/TAP: DLT_EN10MB (1) - TAP");
            parse_tap(data, parser, process_name, process_id)
        }
        // DLT_RAW - Raw IP packets (no link layer)
        12 | 101 => {
            log::trace!("TUN/TAP: DLT_RAW ({}) - TUN", dlt);
            parse_tun(data, parser, process_name, process_id)
        }
        // IPv4-only packets
        228 => {
            log::trace!("TUN/TAP: LINKTYPE_IPV4 (228) - TUN");
            raw_ip::parse_ipv4(data, parser, process_name, process_id)
        }
        // IPv6-only packets
        229 => {
            log::trace!("TUN/TAP: LINKTYPE_IPV6 (229) - TUN");
            raw_ip::parse_ipv6(data, parser, process_name, process_id)
        }
        _ => {
            log::warn!("TUN/TAP: Unsupported DLT type: {}", dlt);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_interface_detection() {
        assert!(is_tun_interface("tun0"));
        assert!(is_tun_interface("tun1"));
        assert!(is_tun_interface("tun10"));
        assert!(is_tun_interface("utun0")); // macOS
        assert!(is_tun_interface("utun1"));
        assert!(!is_tun_interface("eth0"));
        assert!(!is_tun_interface("tap0"));
        assert!(!is_tun_interface("wlan0"));
    }

    #[test]
    fn test_tap_interface_detection() {
        assert!(is_tap_interface("tap0"));
        assert!(is_tap_interface("tap1"));
        assert!(is_tap_interface("tap10"));
        assert!(!is_tap_interface("tun0"));
        assert!(!is_tap_interface("eth0"));
        assert!(!is_tap_interface("wlan0"));
    }

    #[test]
    fn test_tunnel_interface_detection() {
        assert!(is_tunnel_interface("tun0"));
        assert!(is_tunnel_interface("tap0"));
        assert!(is_tunnel_interface("utun0"));
        assert!(!is_tunnel_interface("eth0"));
        assert!(!is_tunnel_interface("wlan0"));
        assert!(!is_tunnel_interface("lo"));
    }

    #[test]
    fn test_parse_by_dlt() {
        use crate::network::parser::PacketParser;

        let parser = PacketParser::new();

        // Test with empty packet - should return None
        let empty = vec![];
        assert!(parse_by_dlt(&empty, 12, &parser, None, None).is_none());
        assert!(parse_by_dlt(&empty, 1, &parser, None, None).is_none());
    }

    #[test]
    fn test_parse_tun_tap() {
        use crate::network::parser::PacketParser;

        let parser = PacketParser::new();
        let empty = vec![];

        // TUN parsing should fail on empty packet
        assert!(parse_tun(&empty, &parser, None, None).is_none());

        // TAP parsing should fail on empty packet
        assert!(parse_tap(&empty, &parser, None, None).is_none());
    }

    #[test]
    fn test_parse_by_dlt_null_strips_loopback_family_header() {
        use crate::network::parser::PacketParser;
        use crate::network::types::Protocol;

        let parser = PacketParser::new();

        // Inner IPv4/UDP packet: 192.168.1.100:1234 -> 8.8.8.8:53 (DNS).
        let inner_ip: &[u8] = &[
            // IPv4 header (protocol 0x11 = UDP)
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1,
            100, 8, 8, 8, 8, // UDP header: src 1234, dst 53
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ];

        // A DLT_NULL frame is a 4-byte address-family header (AF_INET = 2, host
        // byte order / little-endian here) followed by the raw IP packet.
        let mut null_frame = vec![0x02, 0x00, 0x00, 0x00];
        null_frame.extend_from_slice(inner_ip);

        // The family header's first byte (0x02) has IP version nibble 0, so
        // parsing the frame as raw IP without stripping the header drops it.
        // This is exactly what the old DLT_NULL arm did.
        assert!(
            raw_ip::parse(&null_frame, &parser, None, None).is_none(),
            "raw IP parse must fail when the 4-byte family header is not stripped",
        );

        // parse_by_dlt(DLT_NULL) must strip the header and parse the inner packet.
        let parsed = parse_by_dlt(&null_frame, 0, &parser, None, None)
            .expect("DLT_NULL loopback frame should parse after stripping the family header");
        assert_eq!(parsed.protocol, Protocol::Udp);
        // Orientation (which side is local) depends on configured local IPs, so
        // assert on the port set rather than a fixed local/remote split.
        let ports = [parsed.local_addr.port(), parsed.remote_addr.port()];
        assert!(
            ports.contains(&1234) && ports.contains(&53),
            "inner UDP ports 1234/53 must survive the header strip, got {ports:?}",
        );

        // A truncated DLT_NULL frame (header only / shorter) must not panic.
        assert!(parse_by_dlt(&[0x02, 0x00, 0x00, 0x00], 0, &parser, None, None).is_none());
        assert!(parse_by_dlt(&[0x02, 0x00], 0, &parser, None, None).is_none());
    }
}
