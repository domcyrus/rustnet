//! ICMP (Internet Control Message Protocol) parsing
//! Handles both ICMPv4 and ICMPv6

use crate::network::parser::ParsedPacket;
use crate::network::protocol::TransportParams;
use crate::network::types::{Protocol, ProtocolState};
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

    // Extract ICMP echo ID for request (8) and reply (0)
    let icmp_id = if transport_data.len() >= 6 && (icmp_type == 8 || icmp_type == 0) {
        Some(u16::from_be_bytes([transport_data[4], transport_data[5]]))
    } else {
        None
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
        connection_key: format!("ICMP:{}-ICMP:{}", local_addr, remote_addr),
        protocol: Protocol::ICMP,
        local_addr,
        remote_addr,
        tcp_header: None,
        protocol_state: ProtocolState::Icmp { icmp_type, icmp_id },
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None,
        process_name: params.process_name,
        process_id: params.process_id,
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

    // Extract ICMPv6 echo ID for request (128) and reply (129)
    let icmp_id = if transport_data.len() >= 6 && (icmp_type == 128 || icmp_type == 129) {
        Some(u16::from_be_bytes([transport_data[4], transport_data[5]]))
    } else {
        None
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
        connection_key: format!("ICMP:{}-ICMP:{}", local_addr, remote_addr),
        protocol: Protocol::ICMP,
        local_addr,
        remote_addr,
        tcp_header: None,
        protocol_state: ProtocolState::Icmp { icmp_type, icmp_id },
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result: None, // No DPI for ICMPv6
        process_name: params.process_name,
        process_id: params.process_id,
    })
}
