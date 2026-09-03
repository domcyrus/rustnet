//! UDP (User Datagram Protocol) parsing

use crate::network::dpi;
use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{Protocol, ProtocolState};

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

    let (local_addr, remote_addr, is_outgoing) =
        orient_endpoints(&params, src_port, dst_port, local_ips);

    let dpi_result = if config.enable_dpi && transport_data.len() > 8 {
        let payload = &transport_data[8..];
        dpi::analyze_udp_packet(payload, local_addr.port(), remote_addr.port(), is_outgoing)
    } else {
        None
    };

    let mut packet = ParsedPacket::new(
        Protocol::Udp,
        local_addr,
        remote_addr,
        ProtocolState::Udp,
        is_outgoing,
        params.packet_len,
        params.process_name,
        params.process_id,
    );
    packet.dpi_result = dpi_result;
    Some(packet)
}
