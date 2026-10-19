//! IGMP (Internet Group Management Protocol) parsing

use crate::network::parser::ParsedPacket;
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{Protocol, ProtocolState};
use std::net::Ipv4Addr;

/// Parse an IGMP packet
///
/// IGMPv1/v2 header layout:
/// - Byte 0: Type
/// - Byte 1: Max Response Time
/// - Bytes 2–3: Checksum
/// - Bytes 4–7: Group Address
///
/// IGMPv3 Membership Report (type 0x22) layout:
/// - Byte 0: Type
/// - Byte 1: Max Response Time
/// - Bytes 2–3: Checksum
/// - Bytes 4–5: Reserved
/// - Bytes 6–7: Number of Group Records
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.is_empty() {
        return None;
    }

    let igmp_type = transport_data[0];

    // IGMPv3 Membership Reports (0x22) have no single group address:
    // bytes 4–5 are reserved and bytes 6–7 are the number of group records.
    // Only IGMPv1/v2 messages carry a group address in bytes 4–7.
    let group_addr = if igmp_type != 0x22 && transport_data.len() >= 8 {
        Some(Ipv4Addr::new(
            transport_data[4],
            transport_data[5],
            transport_data[6],
            transport_data[7],
        ))
    } else {
        None
    };

    let (local_addr, remote_addr, is_outgoing) = orient_endpoints(&params, 0, 0, local_ips);

    Some(ParsedPacket::new(
        Protocol::Igmp,
        local_addr,
        remote_addr,
        ProtocolState::Igmp {
            igmp_type,
            group_addr,
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
    use std::net::{IpAddr, Ipv4Addr};

    fn local_ips(ip: Ipv4Addr) -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        set.insert(IpAddr::V4(ip));
        set
    }

    fn params(src: Ipv4Addr, dst: Ipv4Addr) -> TransportParams {
        TransportParams::new(IpAddr::V4(src), IpAddr::V4(dst), 64, None, None)
    }

    #[test]
    fn test_igmp_message_types_and_group_addresses() {
        let group = Ipv4Addr::new(239, 255, 255, 250);
        for (name, data, src, dst, expected_group) in [
            (
                "v1 report",
                [0x12, 0, 0, 0, 239, 1, 2, 3],
                [192, 168, 1, 1],
                [239, 1, 2, 3],
                Some(Ipv4Addr::new(239, 1, 2, 3)),
            ),
            (
                "v2 general query",
                [0x11, 0x64, 0, 0, 0, 0, 0, 0],
                [192, 168, 1, 1],
                [224, 0, 0, 1],
                Some(Ipv4Addr::UNSPECIFIED),
            ),
            (
                "v2 group query",
                [0x11, 0x14, 0, 0, 239, 255, 255, 250],
                [10, 0, 0, 1],
                [239, 255, 255, 250],
                Some(group),
            ),
            (
                "v2 report",
                [0x16, 0, 0, 0, 239, 255, 255, 250],
                [192, 168, 0, 5],
                [239, 255, 255, 250],
                Some(group),
            ),
            (
                "v2 leave",
                [0x17, 0, 0, 0, 239, 255, 255, 250],
                [192, 168, 0, 5],
                [224, 0, 0, 2],
                Some(group),
            ),
            // v3 bytes 4-7 are reserved and a record count, not a group address.
            (
                "v3 report",
                [0x22, 0, 0, 0, 0, 0, 0, 2],
                [192, 168, 1, 10],
                [224, 0, 0, 22],
                None,
            ),
        ] {
            let src = Ipv4Addr::from(src);
            let packet = parse(&data, params(src, dst.into()), &local_ips(src)).expect(name);
            assert_eq!(packet.protocol, Protocol::Igmp, "{name}");
            assert!(packet.is_outgoing, "{name}");
            let ProtocolState::Igmp {
                igmp_type,
                group_addr,
            } = packet.protocol_state
            else {
                panic!("unexpected protocol state for {name}");
            };
            assert_eq!(igmp_type, data[0], "{name}");
            assert_eq!(group_addr, expected_group, "{name}");
        }
    }

    // Incoming packet: src is not a local IP, so is_outgoing must be false
    #[test]
    fn test_incoming_direction() {
        let data: &[u8] = &[0x11, 0x64, 0x00, 0x00, 0, 0, 0, 0];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 5);
        let local = Ipv4Addr::new(192, 168, 1, 5);

        let packet = parse(data, params(src, dst), &local_ips(local)).unwrap();

        assert!(!packet.is_outgoing);
        assert_eq!(packet.local_addr.ip(), IpAddr::V4(local));
        assert_eq!(packet.remote_addr.ip(), IpAddr::V4(src));
    }

    // Empty data must return None
    #[test]
    fn test_empty_data_returns_none() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(224, 0, 0, 22);
        assert!(parse(&[], params(src, dst), &local_ips(src)).is_none());
    }

    // Truncated packet (< 8 bytes) yields no group_addr
    #[test]
    fn test_truncated_packet_no_group_addr() {
        let data: &[u8] = &[0x16, 0x00, 0x00, 0x00]; // only 4 bytes
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(239, 255, 255, 250);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        match packet.protocol_state {
            ProtocolState::Igmp {
                igmp_type,
                group_addr,
            } => {
                assert_eq!(igmp_type, 0x16);
                assert_eq!(group_addr, None);
            }
            _ => panic!("unexpected protocol state"),
        }
    }
}
