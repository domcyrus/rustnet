//! ICMP (Internet Control Message Protocol) parsing
//! Handles both ICMPv4 and ICMPv6

use crate::network::parser::ParsedPacket;
use crate::network::protocol::TransportParams;
use crate::network::types::{AddrKind, Protocol, ProtocolState};
use std::net::SocketAddr;

/// Parse an ICMP (IPv4) packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let icmp_type = transport_data[0];

    // Echo requests and replies carry an identifier plus a sequence number.
    // Both are needed to pair several concurrent requests from one ping flow.
    let (icmp_id, icmp_sequence) =
        if transport_data.len() >= 8 && (icmp_type == 8 || icmp_type == 0) {
            (
                Some(u16::from_be_bytes([transport_data[4], transport_data[5]])),
                Some(u16::from_be_bytes([transport_data[6], transport_data[7]])),
            )
        } else {
            (None, None)
        };

    // Determine direction based on local IPs
    let is_outgoing = local_ips.contains(&params.src_ip);

    let (local_addr, remote_addr) = if is_outgoing {
        (
            SocketAddr::new(params.src_ip, 0),
            SocketAddr::new(params.dst_ip, 0),
        )
    } else {
        (
            SocketAddr::new(params.dst_ip, 0),
            SocketAddr::new(params.src_ip, 0),
        )
    };

    Some(ParsedPacket {
        protocol: Protocol::Icmp,
        local_addr,
        remote_addr,
        // Overwritten centrally in PacketParser::parse_packet
        local_addr_kind: AddrKind::Unicast,
        remote_addr_kind: AddrKind::Unicast,
        remote_is_gateway: false,
        tcp_header: None,
        protocol_state: ProtocolState::Icmp {
            icmp_type,
            icmp_id,
            icmp_sequence,
        },
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None,
        process_name: params.process_name,
        process_id: params.process_id,
        ndp_neighbor: None,
    })
}

/// Parse an ICMPv6 packet
pub fn parse_v6(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let icmp_type = transport_data[0];

    // ICMPv6 echo uses the same identifier and sequence layout as ICMPv4.
    let (icmp_id, icmp_sequence) =
        if transport_data.len() >= 8 && (icmp_type == 128 || icmp_type == 129) {
            (
                Some(u16::from_be_bytes([transport_data[4], transport_data[5]])),
                Some(u16::from_be_bytes([transport_data[6], transport_data[7]])),
            )
        } else {
            (None, None)
        };

    // Determine direction based on local IPs
    let is_outgoing = local_ips.contains(&params.src_ip);

    let (local_addr, remote_addr) = if is_outgoing {
        (
            SocketAddr::new(params.src_ip, 0),
            SocketAddr::new(params.dst_ip, 0),
        )
    } else {
        (
            SocketAddr::new(params.dst_ip, 0),
            SocketAddr::new(params.src_ip, 0),
        )
    };

    Some(ParsedPacket {
        protocol: Protocol::Icmp,
        local_addr,
        remote_addr,
        // Overwritten centrally in PacketParser::parse_packet
        local_addr_kind: AddrKind::Unicast,
        remote_addr_kind: AddrKind::Unicast,
        remote_is_gateway: false,
        tcp_header: None,
        protocol_state: ProtocolState::Icmp {
            icmp_type,
            icmp_id,
            icmp_sequence,
        },
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None, // No DPI for ICMPv6
        process_name: params.process_name,
        process_id: params.process_id,
        // Filled by the parser for NDP messages that pass the hop-limit gate.
        ndp_neighbor: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ipv4_echo_identifier_and_sequence() {
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let remote = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let locals = HashSet::from([local]);
        let packet = parse(
            &[8, 0, 0, 0, 0x12, 0x34, 0x56, 0x78],
            TransportParams::new(local, remote, 28, None, None),
            &locals,
        )
        .expect("echo request should parse");

        assert!(packet.is_outgoing);
        assert!(matches!(
            packet.protocol_state,
            ProtocolState::Icmp {
                icmp_type: 8,
                icmp_id: Some(0x1234),
                icmp_sequence: Some(0x5678),
            }
        ));
    }

    #[test]
    fn parses_ipv6_echo_identifier_and_sequence() {
        let local = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let remote = IpAddr::V6("2001:4860:4860::8888".parse().unwrap());
        let locals = HashSet::from([local]);
        let packet = parse_v6(
            &[129, 0, 0, 0, 0xab, 0xcd, 0x00, 0x2a],
            TransportParams::new(remote, local, 48, None, None),
            &locals,
        )
        .expect("echo reply should parse");

        assert!(!packet.is_outgoing);
        assert!(matches!(
            packet.protocol_state,
            ProtocolState::Icmp {
                icmp_type: 129,
                icmp_id: Some(0xabcd),
                icmp_sequence: Some(42),
            }
        ));
    }
}
