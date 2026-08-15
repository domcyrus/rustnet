//! ICMP (Internet Control Message Protocol) parsing
//! Handles both ICMPv4 and ICMPv6

use crate::network::parser::ParsedPacket;
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{Protocol, ProtocolState};

/// Parse an ICMP (IPv4) packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    parse_icmp(transport_data, params, local_ips, (8, 0))
}

/// Parse an ICMPv6 packet
pub fn parse_v6(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    parse_icmp(transport_data, params, local_ips, (128, 129))
}

/// Shared ICMPv4/ICMPv6 parse; `echo_types` carries the version's echo
/// request and reply type values, the only place the two formats differ.
fn parse_icmp(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
    echo_types: (u8, u8),
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let icmp_type = transport_data[0];
    let (echo_request, echo_reply) = echo_types;

    // Echo requests and replies carry an identifier plus a sequence number.
    // Both are needed to pair several concurrent requests from one ping flow.
    let (icmp_id, icmp_sequence) =
        if transport_data.len() >= 8 && (icmp_type == echo_request || icmp_type == echo_reply) {
            (
                Some(u16::from_be_bytes([transport_data[4], transport_data[5]])),
                Some(u16::from_be_bytes([transport_data[6], transport_data[7]])),
            )
        } else {
            (None, None)
        };

    let (local_addr, remote_addr, is_outgoing) = orient_endpoints(&params, 0, 0, local_ips);

    Some(ParsedPacket::new(
        Protocol::Icmp,
        local_addr,
        remote_addr,
        ProtocolState::Icmp {
            icmp_type,
            icmp_id,
            icmp_sequence,
            // Filled by the parser for ICMPv6 NDP messages that pass
            // the hop-limit and fragmentation gates.
            ndp_neighbor: None,
        },
        is_outgoing,
        params.packet_len,
        params.process_name,
        params.process_id,
    ))
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
                ndp_neighbor: None,
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
                ndp_neighbor: None,
            }
        ));
    }
}
