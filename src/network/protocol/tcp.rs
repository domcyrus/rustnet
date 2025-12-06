//! TCP (Transmission Control Protocol) parsing

use crate::network::dpi;
use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::TransportParams;
use crate::network::types::{Protocol, ProtocolState, TcpState};
use std::net::SocketAddr;

// Define TCP flags as bit masks
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

/// TCP flags from the TCP header
/// All flags are public fields as they represent the actual TCP flags
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

/// TCP header information extracted from the packet
#[derive(Debug, Clone, Copy)]
pub struct TcpHeaderInfo {
    pub seq: u32,         // Sequence number
    pub ack: u32,         // Acknowledgment number
    pub window: u16,      // Window size
    pub flags: TcpFlags,  // TCP flags
    pub payload_len: u32, // Actual TCP payload length (not including headers)
}

/// Parse TCP flags from the flags byte
pub fn parse_tcp_flags(flags: u8) -> TcpFlags {
    TcpFlags {
        fin: (flags & TCP_FIN) != 0,
        syn: (flags & TCP_SYN) != 0,
        rst: (flags & TCP_RST) != 0,
        psh: (flags & TCP_PSH) != 0,
        ack: (flags & TCP_ACK) != 0,
        urg: (flags & TCP_URG) != 0,
    }
}

/// Parse a TCP packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    config: &ParserConfig,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.len() < 20 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

    // Extract TCP header fields
    let seq = u32::from_be_bytes([
        transport_data[4],
        transport_data[5],
        transport_data[6],
        transport_data[7],
    ]);
    let ack = u32::from_be_bytes([
        transport_data[8],
        transport_data[9],
        transport_data[10],
        transport_data[11],
    ]);
    let window = u16::from_be_bytes([transport_data[14], transport_data[15]]);
    let flags = transport_data[13];

    let tcp_flags = parse_tcp_flags(flags);

    // Calculate actual TCP payload length
    let tcp_header_len = ((transport_data[12] >> 4) as usize) * 4;
    let tcp_payload_len = transport_data.len().saturating_sub(tcp_header_len) as u32;

    let tcp_header = TcpHeaderInfo {
        seq,
        ack,
        window,
        flags: tcp_flags,
        payload_len: tcp_payload_len,
    };

    // Log TCP flags for debugging
    log::trace!(
        "TCP flags: FIN={} SYN={} RST={} PSH={} ACK={} URG={}",
        tcp_flags.fin,
        tcp_flags.syn,
        tcp_flags.rst,
        tcp_flags.psh,
        tcp_flags.ack,
        tcp_flags.urg
    );

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
    let dpi_result = if config.enable_dpi {
        let tcp_header_len = ((transport_data[12] >> 4) as usize) * 4;
        if transport_data.len() > tcp_header_len {
            let payload = &transport_data[tcp_header_len..];
            dpi::analyze_tcp_packet(payload, local_addr.port(), remote_addr.port(), is_outgoing)
        } else {
            None
        }
    } else {
        None
    };

    Some(ParsedPacket {
        connection_key: format!("TCP:{}-TCP:{}", local_addr, remote_addr),
        protocol: Protocol::TCP,
        local_addr,
        remote_addr,
        tcp_header: Some(tcp_header),
        protocol_state: ProtocolState::Tcp(TcpState::Unknown),
        is_outgoing,
        packet_len: params.packet_len,
        dpi_result,
        process_name: params.process_name,
        process_id: params.process_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_parsing() {
        let flags = parse_tcp_flags(0x02); // SYN
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);

        let flags = parse_tcp_flags(0x12); // SYN + ACK
        assert!(flags.syn);
        assert!(flags.ack);

        let flags = parse_tcp_flags(0x11); // FIN + ACK
        assert!(flags.fin);
        assert!(flags.ack);
    }
}
