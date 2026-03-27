//! IGMP (Internet Group Management Protocol) parsing

use crate::network::parser::ParsedPacket;
use crate::network::protocol::TransportParams;
use crate::network::types::{Protocol, ProtocolState};
use std::net::{Ipv4Addr, SocketAddr};

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
/// - Byte 1: Reserved
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

    // IGMPv3 Membership Reports (0x22) have no single group address —
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
        connection_key: format!("IGMP:{}-IGMP:{}", local_addr, remote_addr),
        protocol: Protocol::Igmp,
        local_addr,
        remote_addr,
        tcp_header: None,
        protocol_state: ProtocolState::Igmp {
            igmp_type,
            group_addr,
        },
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
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    fn local_ips(ip: Ipv4Addr) -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        set.insert(IpAddr::V4(ip));
        set
    }

    fn params(src: Ipv4Addr, dst: Ipv4Addr) -> TransportParams {
        TransportParams::new(
            IpAddr::V4(src),
            IpAddr::V4(dst),
            64,
            None,
            None,
        )
    }

    // IGMPv1 Membership Report (type 0x12)
    // Header: [type, unused, checksum(2), group_addr(4)]
    #[test]
    fn test_igmpv1_membership_report() {
        let group = Ipv4Addr::new(239, 1, 2, 3);
        let data: &[u8] = &[0x12, 0x00, 0x00, 0x00, 239, 1, 2, 3];
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(239, 1, 2, 3);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        assert_eq!(packet.protocol, Protocol::Igmp);
        assert!(packet.is_outgoing);
        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x12);
                assert_eq!(group_addr, Some(group));
            }
            _ => panic!("unexpected protocol state"),
        }
    }

    // IGMPv2 General Membership Query (type 0x11, group addr = 0.0.0.0)
    #[test]
    fn test_igmpv2_general_query() {
        let data: &[u8] = &[0x11, 0x64, 0x00, 0x00, 0, 0, 0, 0];
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(224, 0, 0, 1);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        assert_eq!(packet.protocol, Protocol::Igmp);
        assert!(packet.is_outgoing);
        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x11);
                assert_eq!(group_addr, Some(Ipv4Addr::new(0, 0, 0, 0)));
            }
            _ => panic!("unexpected protocol state"),
        }
    }

    // IGMPv2 Group-Specific Query (type 0x11, group addr set)
    #[test]
    fn test_igmpv2_group_specific_query() {
        let group = Ipv4Addr::new(239, 255, 255, 250);
        let data: &[u8] = &[0x11, 0x14, 0x00, 0x00, 239, 255, 255, 250];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(239, 255, 255, 250);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x11);
                assert_eq!(group_addr, Some(group));
            }
            _ => panic!("unexpected protocol state"),
        }
    }

    // IGMPv2 Membership Report (type 0x16)
    #[test]
    fn test_igmpv2_membership_report() {
        let group = Ipv4Addr::new(239, 255, 255, 250);
        let data: &[u8] = &[0x16, 0x00, 0x00, 0x00, 239, 255, 255, 250];
        let src = Ipv4Addr::new(192, 168, 0, 5);
        let dst = Ipv4Addr::new(239, 255, 255, 250);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        assert!(packet.is_outgoing);
        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x16);
                assert_eq!(group_addr, Some(group));
            }
            _ => panic!("unexpected protocol state"),
        }
    }

    // IGMPv2 Leave Group (type 0x17)
    #[test]
    fn test_igmpv2_leave_group() {
        let group = Ipv4Addr::new(239, 255, 255, 250);
        let data: &[u8] = &[0x17, 0x00, 0x00, 0x00, 239, 255, 255, 250];
        let src = Ipv4Addr::new(192, 168, 0, 5);
        let dst = Ipv4Addr::new(224, 0, 0, 2);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x17);
                assert_eq!(group_addr, Some(group));
            }
            _ => panic!("unexpected protocol state"),
        }
    }

    // IGMPv3 Membership Report (type 0x22): bytes 4-5 reserved, 6-7 = num records
    // group_addr must be None
    #[test]
    fn test_igmpv3_membership_report_no_group_addr() {
        // 2 group records
        let data: &[u8] = &[0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(224, 0, 0, 22);

        let packet = parse(data, params(src, dst), &local_ips(src)).unwrap();

        assert!(packet.is_outgoing);
        match packet.protocol_state {
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x22);
                assert_eq!(group_addr, None);
            }
            _ => panic!("unexpected protocol state"),
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
            ProtocolState::Igmp { igmp_type, group_addr } => {
                assert_eq!(igmp_type, 0x16);
                assert_eq!(group_addr, None);
            }
            _ => panic!("unexpected protocol state"),
        }
    }
}
