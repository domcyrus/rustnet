// network/parser.rs - Updated with DPI integration and PKTAP support
use crate::network::dpi::{self, DpiResult};
#[cfg(target_os = "macos")]
use crate::network::pktap;
use crate::network::types::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Common parameters for transport layer parsing
struct TransportParams {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    is_outgoing: bool,
    packet_len: usize,
    process_name: Option<String>,
    process_id: Option<u32>,
}

// Define TCP flags as bit masks
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // PSH and URG flags are legitimate TCP flags, kept for completeness
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

fn parse_tcp_flags(flags: u8) -> TcpFlags {
    TcpFlags {
        fin: (flags & TCP_FIN) != 0,
        syn: (flags & TCP_SYN) != 0,
        rst: (flags & TCP_RST) != 0,
        psh: (flags & TCP_PSH) != 0,
        ack: (flags & TCP_ACK) != 0,
        urg: (flags & TCP_URG) != 0,
    }
}

/// Result of parsing a packet
#[derive(Debug)]
pub struct ParsedPacket {
    pub connection_key: String,
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tcp_flags: Option<TcpFlags>,
    pub protocol_state: ProtocolState,
    pub is_outgoing: bool,
    pub packet_len: usize,
    pub dpi_result: Option<DpiResult>, // DPI results if available
    pub process_name: Option<String>,  // Process name from PKTAP metadata
    pub process_id: Option<u32>,       // Process ID from PKTAP metadata
}

#[derive(Clone)]
pub struct ParserConfig {
    pub enable_dpi: bool,
    #[allow(dead_code)]
    pub dpi_packet_limit: usize, // Only inspect first N packets per connection
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            enable_dpi: true,
            dpi_packet_limit: 10, // Only inspect first 10 packets
        }
    }
}

/// Packet parser - stateless, thread-safe
pub struct PacketParser {
    local_ips: std::collections::HashSet<IpAddr>,
    config: ParserConfig,
    linktype: Option<i32>, // DLT linktype - 149 means PKTAP on macOS
}

impl PacketParser {
    #[allow(dead_code)]
    pub fn new() -> Self {
        let mut local_ips = std::collections::HashSet::new();
        for iface in pnet_datalink::interfaces() {
            for ip_network in iface.ips {
                local_ips.insert(ip_network.ip());
            }
        }
        Self {
            local_ips,
            config: ParserConfig::default(),
            linktype: None,
        }
    }

    pub fn with_config(config: ParserConfig) -> Self {
        let mut local_ips = std::collections::HashSet::new();
        for iface in pnet_datalink::interfaces() {
            for ip_network in iface.ips {
                local_ips.insert(ip_network.ip());
            }
        }
        Self {
            local_ips,
            config,
            linktype: None,
        }
    }

    /// Set the linktype for this parser (needed for PKTAP detection)
    pub fn with_linktype(mut self, linktype: i32) -> Self {
        self.linktype = Some(linktype);
        self
    }

    /// Parse a raw packet
    pub fn parse_packet(&self, data: &[u8]) -> Option<ParsedPacket> {
        // Check if this is PKTAP data
        #[cfg(target_os = "macos")]
        if let Some(linktype) = self.linktype
            && pktap::is_pktap_linktype(linktype)
        {
            return self.parse_pktap_packet(data);
        }

        // Regular Ethernet parsing
        if data.len() < 14 {
            return None;
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => self.parse_ipv4_packet_inner(data, None, None),
            0x86dd => self.parse_ipv6_packet_inner(data, None, None),
            0x0806 => self.parse_arp_packet_inner(data, None, None),
            _ => None,
        }
    }

    #[cfg(target_os = "macos")]
    fn parse_pktap_packet(&self, data: &[u8]) -> Option<ParsedPacket> {
        let (pktap_header, payload) = pktap::parse_pktap_packet(data)?;
        let (process_name, process_id) = pktap_header.get_process_info();

        log::debug!(
            "PKTAP packet: interface={}, process={:?}, pid={:?}, payload_len={}",
            pktap_header.get_interface(),
            process_name,
            process_id,
            payload.len()
        );

        // Now parse the inner packet based on the DLT type
        match pktap_header.inner_dlt() {
            1 => {
                // DLT_EN10MB - Ethernet frame
                if payload.len() < 14 {
                    return None;
                }
                let ethertype = u16::from_be_bytes([payload[12], payload[13]]);
                match ethertype {
                    0x0800 => self.parse_ipv4_packet_inner(payload, process_name, process_id),
                    0x86dd => self.parse_ipv6_packet_inner(payload, process_name, process_id),
                    0x0806 => self.parse_arp_packet_inner(payload, process_name, process_id),
                    _ => None,
                }
            }
            12 => {
                // DLT_RAW - Raw IP packet
                if payload.is_empty() {
                    return None;
                }
                let version = payload[0] >> 4;
                match version {
                    4 => self.parse_raw_ipv4_packet(payload, process_name, process_id),
                    6 => self.parse_raw_ipv6_packet(payload, process_name, process_id),
                    _ => None,
                }
            }
            _ => {
                log::debug!("Unsupported PKTAP inner DLT: {}", pktap_header.inner_dlt());
                None
            }
        }
    }

    fn parse_ipv4_packet_inner(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let ip_data = &data[14..];
        if ip_data.len() < 20 {
            return None;
        }

        let version = ip_data[0] >> 4;
        if version != 4 {
            return None;
        }

        let protocol_num = ip_data[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            ip_data[12],
            ip_data[13],
            ip_data[14],
            ip_data[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            ip_data[16],
            ip_data[17],
            ip_data[18],
            ip_data[19],
        ));

        let ihl = ip_data[0] & 0x0F;
        let ip_header_len = (ihl as usize) * 4;

        if ip_data.len() < ip_header_len {
            return None;
        }

        let transport_data = &ip_data[ip_header_len..];
        let is_outgoing = self.local_ips.contains(&src_ip);

        match protocol_num {
            1 => self.parse_icmp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            6 => self.parse_tcp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            17 => self.parse_udp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            _ => None,
        }
    }

    fn parse_ipv6_packet_inner(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let ip_data = &data[14..];
        if ip_data.len() < 40 {
            return None;
        }

        let version = ip_data[0] >> 4;
        if version != 6 {
            return None;
        }

        let next_header = ip_data[6];

        // Extract IPv6 addresses
        let src_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([ip_data[8], ip_data[9]]),
            u16::from_be_bytes([ip_data[10], ip_data[11]]),
            u16::from_be_bytes([ip_data[12], ip_data[13]]),
            u16::from_be_bytes([ip_data[14], ip_data[15]]),
            u16::from_be_bytes([ip_data[16], ip_data[17]]),
            u16::from_be_bytes([ip_data[18], ip_data[19]]),
            u16::from_be_bytes([ip_data[20], ip_data[21]]),
            u16::from_be_bytes([ip_data[22], ip_data[23]]),
        ));

        let dst_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([ip_data[24], ip_data[25]]),
            u16::from_be_bytes([ip_data[26], ip_data[27]]),
            u16::from_be_bytes([ip_data[28], ip_data[29]]),
            u16::from_be_bytes([ip_data[30], ip_data[31]]),
            u16::from_be_bytes([ip_data[32], ip_data[33]]),
            u16::from_be_bytes([ip_data[34], ip_data[35]]),
            u16::from_be_bytes([ip_data[36], ip_data[37]]),
            u16::from_be_bytes([ip_data[38], ip_data[39]]),
        ));

        let transport_data = &ip_data[40..];
        let is_outgoing = self.local_ips.contains(&src_ip);

        // Handle extension headers if needed
        let (final_next_header, transport_offset) =
            self.parse_ipv6_extension_headers(next_header, transport_data);
        let final_transport_data = &transport_data[transport_offset..];

        match final_next_header {
            58 => self.parse_icmpv6(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            6 => self.parse_tcp(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            17 => self.parse_udp(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            _ => None,
        }
    }

    fn parse_tcp(&self, transport_data: &[u8], params: TransportParams) -> Option<ParsedPacket> {
        if transport_data.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
        let flags = transport_data[13];

        let tcp_flags = parse_tcp_flags(flags);

        let (local_addr, remote_addr) = if params.is_outgoing {
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
        let dpi_result = if self.config.enable_dpi {
            let tcp_header_len = ((transport_data[12] >> 4) as usize) * 4;
            if transport_data.len() > tcp_header_len {
                let payload = &transport_data[tcp_header_len..];
                dpi::analyze_tcp_packet(
                    payload,
                    local_addr.port(),
                    remote_addr.port(),
                    params.is_outgoing,
                )
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
            tcp_flags: Some(tcp_flags),
            protocol_state: ProtocolState::Tcp(TcpState::Unknown),
            is_outgoing: params.is_outgoing,
            packet_len: params.packet_len,
            dpi_result,
            process_name: params.process_name,
            process_id: params.process_id,
        })
    }

    fn parse_udp(&self, transport_data: &[u8], params: TransportParams) -> Option<ParsedPacket> {
        if transport_data.len() < 8 {
            return None;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

        let (local_addr, remote_addr) = if params.is_outgoing {
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
        let dpi_result = if self.config.enable_dpi && transport_data.len() > 8 {
            let payload = &transport_data[8..];
            dpi::analyze_udp_packet(
                payload,
                local_addr.port(),
                remote_addr.port(),
                params.is_outgoing,
            )
        } else {
            None
        };

        Some(ParsedPacket {
            connection_key: format!("UDP:{}-UDP:{}", local_addr, remote_addr),
            protocol: Protocol::UDP,
            local_addr,
            remote_addr,
            tcp_flags: None,
            protocol_state: ProtocolState::Udp,
            is_outgoing: params.is_outgoing,
            packet_len: params.packet_len,
            dpi_result,
            process_name: params.process_name,
            process_id: params.process_id,
        })
    }

    fn parse_icmp(&self, transport_data: &[u8], params: TransportParams) -> Option<ParsedPacket> {
        if transport_data.is_empty() {
            return None;
        }

        let icmp_type = transport_data[0];
        let icmp_code = if transport_data.len() > 1 {
            transport_data[1]
        } else {
            0
        };

        let (local_addr, remote_addr) = if params.is_outgoing {
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
            tcp_flags: None,
            protocol_state: ProtocolState::Icmp {
                icmp_type,
                icmp_code,
            },
            is_outgoing: params.is_outgoing,
            packet_len: params.packet_len,
            dpi_result: None,
            process_name: params.process_name,
            process_id: params.process_id,
        })
    }

    fn parse_icmpv6(&self, transport_data: &[u8], params: TransportParams) -> Option<ParsedPacket> {
        if transport_data.is_empty() {
            return None;
        }

        let icmp_type = transport_data[0];
        let icmp_code = if transport_data.len() > 1 {
            transport_data[1]
        } else {
            0
        };

        let (local_addr, remote_addr) = if params.is_outgoing {
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
            tcp_flags: None,
            protocol_state: ProtocolState::Icmp {
                icmp_type,
                icmp_code,
            },
            is_outgoing: params.is_outgoing,
            packet_len: params.packet_len,
            dpi_result: None, // No DPI for ICMPv6
            process_name: params.process_name,
            process_id: params.process_id,
        })
    }

    fn parse_arp_packet_inner(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let arp_data = &data[14..];
        if arp_data.len() < 28 {
            return None;
        }

        let hardware_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
        let protocol_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
        let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

        if hardware_type != 1 || protocol_type != 0x0800 {
            return None;
        }

        let sender_ip = IpAddr::from([arp_data[14], arp_data[15], arp_data[16], arp_data[17]]);
        let target_ip = IpAddr::from([arp_data[24], arp_data[25], arp_data[26], arp_data[27]]);

        let operation = match opcode {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return None,
        };

        let is_outgoing = self.local_ips.contains(&sender_ip);
        let (local_addr, remote_addr) = if is_outgoing {
            (SocketAddr::new(sender_ip, 0), SocketAddr::new(target_ip, 0))
        } else {
            (SocketAddr::new(target_ip, 0), SocketAddr::new(sender_ip, 0))
        };

        Some(ParsedPacket {
            connection_key: format!("ARP:{}-ARP:{}", local_addr, remote_addr),
            protocol: Protocol::ARP,
            local_addr,
            remote_addr,
            tcp_flags: None,
            protocol_state: ProtocolState::Arp { operation },
            is_outgoing,
            packet_len: data.len(),
            dpi_result: None,
            process_name,
            process_id,
        })
    }

    // Raw IP packet parsing for PKTAP DLT_RAW
    #[cfg(target_os = "macos")]
    fn parse_raw_ipv4_packet(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        if data.len() < 20 {
            return None;
        }

        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }

        let protocol_num = data[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        let ihl = data[0] & 0x0F;
        let ip_header_len = (ihl as usize) * 4;

        if data.len() < ip_header_len {
            return None;
        }

        let transport_data = &data[ip_header_len..];
        let is_outgoing = self.local_ips.contains(&src_ip);

        match protocol_num {
            1 => self.parse_icmp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            6 => self.parse_tcp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            17 => self.parse_udp(
                transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            _ => None,
        }
    }

    #[cfg(target_os = "macos")]
    fn parse_raw_ipv6_packet(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        if data.len() < 40 {
            return None;
        }

        let version = data[0] >> 4;
        if version != 6 {
            return None;
        }

        let next_header = data[6];

        // Extract IPv6 addresses
        let src_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([data[8], data[9]]),
            u16::from_be_bytes([data[10], data[11]]),
            u16::from_be_bytes([data[12], data[13]]),
            u16::from_be_bytes([data[14], data[15]]),
            u16::from_be_bytes([data[16], data[17]]),
            u16::from_be_bytes([data[18], data[19]]),
            u16::from_be_bytes([data[20], data[21]]),
            u16::from_be_bytes([data[22], data[23]]),
        ));

        let dst_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([data[24], data[25]]),
            u16::from_be_bytes([data[26], data[27]]),
            u16::from_be_bytes([data[28], data[29]]),
            u16::from_be_bytes([data[30], data[31]]),
            u16::from_be_bytes([data[32], data[33]]),
            u16::from_be_bytes([data[34], data[35]]),
            u16::from_be_bytes([data[36], data[37]]),
            u16::from_be_bytes([data[38], data[39]]),
        ));

        let transport_data = &data[40..];
        let is_outgoing = self.local_ips.contains(&src_ip);

        // Handle extension headers if needed
        let (final_next_header, transport_offset) =
            self.parse_ipv6_extension_headers(next_header, transport_data);
        let final_transport_data = &transport_data[transport_offset..];

        match final_next_header {
            58 => self.parse_icmpv6(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            6 => self.parse_tcp(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            17 => self.parse_udp(
                final_transport_data,
                TransportParams {
                    src_ip,
                    dst_ip,
                    is_outgoing,
                    packet_len: data.len(),
                    process_name,
                    process_id,
                },
            ),
            _ => None,
        }
    }

    fn parse_ipv6_extension_headers(&self, mut next_header: u8, data: &[u8]) -> (u8, usize) {
        let mut offset = 0;

        const HOP_BY_HOP: u8 = 0;
        const ROUTING: u8 = 43;
        const FRAGMENT: u8 = 44;
        const ENCAPSULATING_SECURITY: u8 = 50;
        const AUTHENTICATION: u8 = 51;
        const DESTINATION_OPTIONS: u8 = 60;

        loop {
            match next_header {
                HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS => {
                    if data.len() < offset + 2 {
                        return (next_header, offset);
                    }
                    next_header = data[offset];
                    let header_len = ((data[offset + 1] as usize) + 1) * 8;
                    offset += header_len;
                }
                FRAGMENT => {
                    if data.len() < offset + 8 {
                        return (next_header, offset);
                    }
                    next_header = data[offset];
                    offset += 8;
                }
                AUTHENTICATION => {
                    if data.len() < offset + 2 {
                        return (next_header, offset);
                    }
                    next_header = data[offset];
                    let header_len = ((data[offset + 1] as usize) + 2) * 4;
                    offset += header_len;
                }
                ENCAPSULATING_SECURITY => {
                    return (next_header, offset);
                }
                _ => {
                    return (next_header, offset);
                }
            }

            if offset >= data.len() {
                return (next_header, offset);
            }
        }
    }
}
