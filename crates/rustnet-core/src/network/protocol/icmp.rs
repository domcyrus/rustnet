//! ICMP (Internet Control Message Protocol) parsing
//! Handles both ICMPv4 and ICMPv6

use crate::network::parser::{ParsedIcmpError, ParsedPacket};
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{ConnectionKey, IcmpError, NetworkEventKind, Protocol, ProtocolState};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
/// request and reply type values. Error classification and quote parsing also
/// account for the IP version.
fn parse_icmp(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
    echo_types: (u8, u8),
) -> Option<ParsedPacket> {
    if transport_data.len() < 8 {
        return None;
    }

    let icmp_type = transport_data[0];
    let (echo_request, echo_reply) = echo_types;

    // Echo requests and replies carry an identifier plus a sequence number.
    // Both are needed to pair several concurrent requests from one ping flow.
    let (icmp_id, icmp_sequence) = if icmp_type == echo_request || icmp_type == echo_reply {
        (
            Some(u16::from_be_bytes([transport_data[4], transport_data[5]])),
            Some(u16::from_be_bytes([transport_data[6], transport_data[7]])),
        )
    } else {
        (None, None)
    };

    let (local_addr, remote_addr, is_outgoing) = orient_endpoints(&params, 0, 0, local_ips);

    let ipv6 = params.src_ip.is_ipv6();
    let code = transport_data[1];
    let error = NetworkEventKind::from_icmp(ipv6, icmp_type, code).map(|kind| IcmpError {
        ipv6,
        message_type: icmp_type,
        code,
        kind,
        reporter: params.src_ip,
        mtu: match (ipv6, icmp_type, code) {
            (false, 3, 4) => Some(u32::from(u16::from_be_bytes([
                transport_data[6],
                transport_data[7],
            ]))),
            (true, 2, 0) => Some(u32::from_be_bytes(transport_data[4..8].try_into().unwrap())),
            _ => None,
        }
        .filter(|mtu| *mtu != 0),
    });
    let mut packet = ParsedPacket::new(
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
    );
    packet.icmp_error = error.map(|error| {
        Box::new(ParsedIcmpError {
            error,
            quoted_connection: quoted_connection(&transport_data[8..], ipv6, local_ips),
        })
    });
    Some(packet)
}

/// Read only the quoted IP header and transport ports. Quotes are normally
/// shorter than the original packet, so the full packet parser cannot be used.
/// Fragmented packets and IPv6 extension chains are deliberately left unmatched.
fn quoted_connection(
    data: &[u8],
    ipv6: bool,
    local_ips: &HashSet<IpAddr>,
) -> Option<ConnectionKey> {
    let (source, destination, protocol, offset, length) = match (ipv6, data.first()? >> 4) {
        (false, 4) if data.len() >= 20 => {
            let offset = usize::from(data[0] & 0x0f) * 4;
            if offset < 20 || u16::from_be_bytes([data[6], data[7]]) & 0x3fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15])),
                IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19])),
                data[9],
                offset,
                usize::from(u16::from_be_bytes([data[2], data[3]])),
            )
        }
        (true, 6) if data.len() >= 40 => (
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?)),
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?)),
            data[6],
            40,
            40 + usize::from(u16::from_be_bytes([data[4], data[5]])),
        ),
        _ => return None,
    };
    let protocol = match protocol {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        _ => return None,
    };
    // Require the standard eight quoted transport bytes, within the original
    // IP length too, so trailing bytes cannot invent a transport header.
    let ports = data
        .get(..length.min(data.len()))?
        .get(offset..offset + 8)?;
    let source_addr = SocketAddr::new(source, u16::from_be_bytes([ports[0], ports[1]]));
    let destination_addr = SocketAddr::new(destination, u16::from_be_bytes([ports[2], ports[3]]));
    let (local, remote) = if local_ips.contains(&source) {
        (source_addr, destination_addr)
    } else if local_ips.contains(&destination) {
        (destination_addr, source_addr)
    } else {
        return None;
    };
    Some(ConnectionKey::new(protocol, local, remote))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn quoted_ipv4() -> Vec<u8> {
        vec![
            0x45, 0, 0, 60, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 10, 198, 51, 100, 20, 0xc0, 0, 1,
            0xbb, 0, 0, 0, 1,
        ]
    }

    #[test]
    fn parses_router_error_with_truncated_original_packet_and_mtu() {
        let local = "192.0.2.10".parse().unwrap();
        let router = "192.0.2.1".parse().unwrap();
        let mut bytes = vec![3, 4, 0, 0, 0, 0, 5, 120];
        bytes.extend(quoted_ipv4());
        let packet = parse(
            &bytes,
            TransportParams::new(router, local, 56, None, None),
            &HashSet::from([local]),
        )
        .unwrap();
        let error = packet.icmp_error.as_ref().unwrap();
        assert_eq!(error.error.kind, NetworkEventKind::PacketTooBig);
        assert_eq!(error.error.mtu, Some(1400));
        assert_eq!(error.error.reporter, router);
        let key = packet
            .icmp_error
            .as_ref()
            .unwrap()
            .quoted_connection
            .unwrap();
        assert_eq!(key.protocol, Protocol::Tcp);
        assert_eq!(key.local_addr, "192.0.2.10:49152".parse().unwrap());
        assert_eq!(key.remote_addr, "198.51.100.20:443".parse().unwrap());
        assert!(!packet.is_outgoing);
    }

    #[test]
    fn parses_ipv6_udp_quote_and_packet_too_big() {
        let local: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let remote: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut bytes = vec![2, 0, 0, 0, 0, 0, 5, 0];
        bytes.extend([0x60, 0, 0, 0, 0, 8, 17, 64]);
        bytes.extend(remote.octets());
        bytes.extend(local.octets());
        bytes.extend([0xc0, 0, 0, 53, 0, 8, 0, 0]);
        let packet = parse_v6(
            &bytes,
            TransportParams::new(local.into(), remote.into(), 96, None, None),
            &HashSet::from([local.into()]),
        )
        .unwrap();
        assert!(packet.is_outgoing);
        assert_eq!(packet.icmp_error.as_ref().unwrap().error.mtu, Some(1280));
        let key = packet
            .icmp_error
            .as_ref()
            .unwrap()
            .quoted_connection
            .unwrap();
        assert_eq!(key.protocol, Protocol::Udp);
        assert_eq!(key.local_addr, SocketAddr::new(local.into(), 53));
        assert_eq!(key.remote_addr, SocketAddr::new(remote.into(), 49152));
        // An extension header requires additional parsing; leave it unmatched.
        bytes[14] = 0;
        let packet = parse_v6(
            &bytes,
            TransportParams::new(local.into(), remote.into(), 96, None, None),
            &HashSet::from([local.into()]),
        )
        .unwrap();
        assert!(packet.icmp_error.is_some());
        assert!(
            packet
                .icmp_error
                .as_ref()
                .unwrap()
                .quoted_connection
                .is_none()
        );
    }

    #[test]
    fn incomplete_or_unsupported_quotes_still_count_as_errors() {
        let local = "192.0.2.10".parse().unwrap();
        let router = "192.0.2.1".parse().unwrap();
        let locals = HashSet::from([local]);
        let params = TransportParams::new(router, local, 56, None, None);
        let quote = quoted_ipv4();
        for length in 0..quote.len() {
            let mut bytes = vec![3, 3, 0, 0, 0, 0, 0, 0];
            bytes.extend_from_slice(&quote[..length]);
            let packet = parse(&bytes, params.clone(), &locals).unwrap();
            assert_eq!(
                packet.icmp_error.as_ref().unwrap().error.kind,
                NetworkEventKind::PortUnreachable
            );
            assert!(
                packet
                    .icmp_error
                    .as_ref()
                    .unwrap()
                    .quoted_connection
                    .is_none()
            );
        }
        for (index, value) in [(0, 0x44), (3, 20), (6, 0x20), (7, 1), (9, 1)] {
            let mut malformed = quote.clone();
            malformed[index] = value;
            assert!(quoted_connection(&malformed, false, &locals).is_none());
        }
        assert!(quoted_connection(&quote, false, &HashSet::new()).is_none());
        for length in 0..8 {
            assert!(parse(&[3; 8][..length], params.clone(), &locals).is_none());
        }
    }

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
