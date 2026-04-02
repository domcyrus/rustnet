//! UDP-Lite (Lightweight User Datagram Protocol) parsing
//!
//! UDP-Lite (RFC 3828) uses IP protocol number 136. Its header is identical
//! to UDP except bytes 4-5 carry a checksum coverage field instead of length.
//! Port extraction is the same as UDP.

use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::TransportParams;
use crate::network::types::{Protocol, ProtocolState};
use std::net::SocketAddr;

/// Parse a UDP-Lite packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    _config: &ParserConfig,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

    let is_outgoing = local_ips.contains(&params.src_ip);

    let (local_addr, remote_addr) = if is_outgoing {
        (
            SocketAddr::new(params.src_ip, src_port),
            SocketAddr::new(params.dst_ip, dst_port),
        )
    } else {
        (
            SocketAddr::new(params.dst_ip, dst_port),
            SocketAddr::new(params.src_ip, src_port),
        )
    };

    Some(ParsedPacket {
        connection_key: format!("UDPLite:{}-UDPLite:{}", local_addr, remote_addr),
        protocol: Protocol::UdpLite,
        local_addr,
        remote_addr,
        tcp_header: None,
        protocol_state: ProtocolState::UdpLite,
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None,
        process_name: params.process_name,
        process_id: params.process_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::parser::ParserConfig;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn local_ips(ip: impl Into<IpAddr>) -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        set.insert(ip.into());
        set
    }

    fn params_v4(src: Ipv4Addr, dst: Ipv4Addr) -> TransportParams {
        TransportParams::new(IpAddr::V4(src), IpAddr::V4(dst), 20, None, None)
    }

    fn params_v6(src: Ipv6Addr, dst: Ipv6Addr) -> TransportParams {
        TransportParams::new(IpAddr::V6(src), IpAddr::V6(dst), 28, None, None)
    }

    /// Minimal valid UDP-Lite header: src_port=5000, dst_port=6000,
    /// checksum_coverage=8 (header only), checksum=0x0000, no payload.
    fn header(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut h = Vec::with_capacity(8);
        h.extend_from_slice(&src_port.to_be_bytes()); // bytes 0-1: source port
        h.extend_from_slice(&dst_port.to_be_bytes()); // bytes 2-3: dest port
        h.extend_from_slice(&8u16.to_be_bytes()); // bytes 4-5: checksum coverage
        h.extend_from_slice(&0u16.to_be_bytes()); // bytes 6-7: checksum
        h
    }

    // --- parse rejects undersized input ---

    #[test]
    fn test_too_short_returns_none() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let local = local_ips(src);
        let config = ParserConfig::default();

        assert!(parse(&[], params_v4(src, dst), &config, &local).is_none());
        assert!(parse(&[0u8; 7], params_v4(src, dst), &config, &local).is_none());
    }

    // --- outgoing packet: local is src ---

    #[test]
    fn test_outgoing_packet() {
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(203, 0, 113, 5);
        let data = header(5000, 6000);
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v4(src, dst), &config, &local_ips(src)).unwrap();

        assert_eq!(pkt.protocol, Protocol::UdpLite);
        assert!(pkt.is_outgoing);
        assert_eq!(pkt.local_addr, "192.168.1.10:5000".parse().unwrap());
        assert_eq!(pkt.remote_addr, "203.0.113.5:6000".parse().unwrap());
        assert!(matches!(pkt.protocol_state, ProtocolState::UdpLite));
        assert!(pkt.tcp_header.is_none());
        assert!(pkt.dpi_result.is_none());
    }

    // --- incoming packet: local is dst ---

    #[test]
    fn test_incoming_packet() {
        let src = Ipv4Addr::new(203, 0, 113, 5);
        let dst = Ipv4Addr::new(192, 168, 1, 10);
        let data = header(6000, 5000);
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v4(src, dst), &config, &local_ips(dst)).unwrap();

        assert!(!pkt.is_outgoing);
        // local_addr should flip to dst
        assert_eq!(pkt.local_addr, "192.168.1.10:5000".parse().unwrap());
        assert_eq!(pkt.remote_addr, "203.0.113.5:6000".parse().unwrap());
    }

    // --- connection_key format ---

    #[test]
    fn test_connection_key_format() {
        let src = Ipv4Addr::new(10, 1, 1, 1);
        let dst = Ipv4Addr::new(10, 1, 1, 2);
        let data = header(1111, 2222);
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v4(src, dst), &config, &local_ips(src)).unwrap();

        assert_eq!(pkt.connection_key, "UDPLite:10.1.1.1:1111-UDPLite:10.1.1.2:2222");
    }

    // --- packet_len is forwarded from TransportParams ---

    #[test]
    fn test_packet_len_forwarded() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let data = header(100, 200);
        let params = TransportParams::new(IpAddr::V4(src), IpAddr::V4(dst), 1234, None, None);
        let config = ParserConfig::default();

        let pkt = parse(&data, params, &config, &local_ips(src)).unwrap();

        assert_eq!(pkt.packet_len, 1234);
    }

    // --- process info is forwarded from TransportParams ---

    #[test]
    fn test_process_info_forwarded() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let data = header(100, 200);
        let params = TransportParams::new(
            IpAddr::V4(src),
            IpAddr::V4(dst),
            20,
            Some("myapp".to_string()),
            Some(42),
        );
        let config = ParserConfig::default();

        let pkt = parse(&data, params, &config, &local_ips(src)).unwrap();

        assert_eq!(pkt.process_name.as_deref(), Some("myapp"));
        assert_eq!(pkt.process_id, Some(42));
    }

    // --- exactly 8 bytes (header only, no payload) is accepted ---

    #[test]
    fn test_exact_minimum_length_accepted() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let config = ParserConfig::default();

        assert!(parse(&[0u8; 8], params_v4(src, dst), &config, &local_ips(src)).is_some());
    }

    // --- payload bytes beyond the 8-byte header are ignored (no DPI) ---

    #[test]
    fn test_payload_ignored() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let mut data = header(7777, 8888);
        data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v4(src, dst), &config, &local_ips(src)).unwrap();

        assert!(pkt.dpi_result.is_none());
        assert_eq!(pkt.local_addr.port(), 7777);
        assert_eq!(pkt.remote_addr.port(), 8888);
    }

    // --- IPv6 outgoing ---

    #[test]
    fn test_ipv6_outgoing() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let data = header(9000, 9001);
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v6(src, dst), &config, &local_ips(src)).unwrap();

        assert_eq!(pkt.protocol, Protocol::UdpLite);
        assert!(pkt.is_outgoing);
        assert_eq!(pkt.local_addr.port(), 9000);
        assert_eq!(pkt.remote_addr.port(), 9001);
        assert!(matches!(pkt.local_addr.ip(), IpAddr::V6(_)));
    }

    // --- IPv6 incoming ---

    #[test]
    fn test_ipv6_incoming() {
        let src: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let data = header(9001, 9000);
        let config = ParserConfig::default();

        let pkt = parse(&data, params_v6(src, dst), &config, &local_ips(dst)).unwrap();

        assert!(!pkt.is_outgoing);
        assert_eq!(pkt.local_addr.port(), 9000);
        assert_eq!(pkt.remote_addr.port(), 9001);
    }
}
