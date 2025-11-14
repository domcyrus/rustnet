//! UDP (User Datagram Protocol) parsing

use crate::network::dpi;
use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::TransportParams;
use crate::network::types::{Protocol, ProtocolState};
use std::net::SocketAddr;

/// Parse a UDP packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    config: &ParserConfig,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

    // Determine direction based on local IPs
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

    // Perform DPI if enabled and there's payload
    let dpi_result = if config.enable_dpi && transport_data.len() > 8 {
        let payload = &transport_data[8..];
        dpi::analyze_udp_packet(
            payload,
            local_addr.port(),
            remote_addr.port(),
            is_outgoing,
        )
    } else {
        None
    };

    Some(ParsedPacket {
        connection_key: format!("UDP:{}-UDP:{}", local_addr, remote_addr),
        protocol: Protocol::UDP,
        local_addr,
        remote_addr,
        tcp_header: None,
        protocol_state: ProtocolState::Udp,
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result,
        process_name: params.process_name,
        process_id: params.process_id,
    })
}
