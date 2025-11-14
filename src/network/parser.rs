// network/parser.rs - Updated with DPI integration, PKTAP, and link_layer support
use crate::network::dpi::DpiResult;
use crate::network::link_layer;
#[cfg(target_os = "macos")]
use crate::network::link_layer::pktap;
use crate::network::protocol;
use crate::network::protocol::TransportParams;
use crate::network::types::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// Re-export TCP types
pub use crate::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};

/// Result of parsing a packet
#[derive(Debug)]
pub struct ParsedPacket {
    pub connection_key: String,
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub tcp_header: Option<TcpHeaderInfo>, // TCP header info (seq, ack, window, flags)
    pub protocol_state: ProtocolState,
    pub is_outgoing: bool,
    pub packet_len: usize,
    pub dpi_result: Option<DpiResult>, // DPI results if available
    pub process_name: Option<String>,  // Process name from PKTAP metadata
    pub process_id: Option<u32>,       // Process ID from PKTAP metadata
}

/// Configuration for packet parsing
///
/// # Example
///
/// ```rust,ignore
/// // Create parser with custom DPI limit
/// let config = ParserConfig {
///     enable_dpi: true,
///     dpi_packet_limit: 5,  // Only inspect first 5 packets per connection
/// };
/// let parser = PacketParser::with_config(config);
///
/// // In connection tracking code:
/// if config.should_perform_dpi(connection.packet_count) {
///     // Perform DPI on this packet
/// }
/// ```
#[derive(Clone)]
pub struct ParserConfig {
    pub enable_dpi: bool,
    /// Maximum number of packets per connection to inspect with DPI
    /// Use `should_perform_dpi()` method to check if DPI should be applied
    pub dpi_packet_limit: usize,
}

impl Default for ParserConfig {
    fn default() -> Self {
        let config = Self {
            enable_dpi: true,
            dpi_packet_limit: 10, // Only inspect first 10 packets
        };

        // Log DPI configuration for debugging
        log::trace!(
            "ParserConfig: DPI {} (limit: {} packets per connection)",
            if config.enable_dpi { "enabled" } else { "disabled" },
            config.dpi_packet_limit
        );

        // Demonstrate usage: check if we should perform DPI on hypothetical packet counts
        if config.enable_dpi {
            log::trace!(
                "  - Packet 0: DPI = {}",
                config.should_perform_dpi(0)
            );
            log::trace!(
                "  - Packet {}: DPI = {}",
                config.dpi_packet_limit - 1,
                config.should_perform_dpi(config.dpi_packet_limit - 1)
            );
            log::trace!(
                "  - Packet {}: DPI = {}",
                config.dpi_packet_limit,
                config.should_perform_dpi(config.dpi_packet_limit)
            );
        }

        config
    }
}

impl ParserConfig {
    /// Check if DPI should be performed based on packet count
    /// Returns true if packet_count is less than dpi_packet_limit
    pub fn should_perform_dpi(&self, packet_count: usize) -> bool {
        let should_dpi = self.enable_dpi && packet_count < self.dpi_packet_limit;
        if !should_dpi && self.enable_dpi {
            log::trace!(
                "DPI skipped: packet {} exceeds limit {}",
                packet_count,
                self.dpi_packet_limit
            );
        }
        should_dpi
    }
}

/// Packet parser - stateless, thread-safe
pub struct PacketParser {
    local_ips: std::collections::HashSet<IpAddr>,
    config: ParserConfig,
    linktype: Option<i32>, // DLT linktype - 149 means PKTAP on macOS
}

impl Default for PacketParser {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketParser {
    /// Create a new packet parser with default configuration
    /// Automatically detects local IP addresses from network interfaces
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

        // Log linktype info for debugging, including TUN/TAP support
        let link_type = link_layer::LinkLayerType::from_dlt(linktype);
        if link_type.is_tunnel() {
            log::debug!(
                "Parser configured for tunnel interface: linktype {} ({:?})",
                linktype,
                link_type
            );

            // Log TUN/TAP parsing capabilities for documentation
            log::trace!("TUN/TAP parsing available via link_layer::tun_tap module");
            log::trace!("  - TUN interfaces (Layer 3): tun*, utun*");
            log::trace!("  - TAP interfaces (Layer 2): tap*");
        } else {
            log::trace!("Parser configured with linktype {} ({:?})", linktype, link_type);
        }

        self
    }

    /// Parse a raw packet using the appropriate link-layer parser
    pub fn parse_packet(&self, data: &[u8]) -> Option<ParsedPacket> {
        if let Some(linktype) = self.linktype {
            // Determine the link layer type
            let link_type = link_layer::LinkLayerType::from_dlt(linktype);
            log::trace!("Parsing packet with linktype {} ({:?})", linktype, link_type);

            match linktype {
                // PKTAP (macOS process metadata)
                #[cfg(target_os = "macos")]
                149 | 258 if pktap::is_pktap_linktype(linktype) => {
                    log::debug!("Parsing as PKTAP (linktype {})", linktype);
                    return self.parse_pktap_packet(data);
                }
                // Linux SLL (Linux "any" interface)
                113 => {
                    log::debug!("Parsing as Linux SLL (linktype 113)");
                    return link_layer::linux_sll::parse_sll(data, self, None, None);
                }
                // Linux SLL2
                276 => {
                    log::debug!("Parsing as Linux SLL2 (linktype 276)");
                    return link_layer::linux_sll::parse_sll2(data, self, None, None);
                }
                // TUN/TAP interfaces - use unified parser
                0 | 1 | 12 | 101 | link_layer::dlt::LINKTYPE_IPV4 | link_layer::dlt::LINKTYPE_IPV6 => {
                    log::debug!("Parsing TUN/TAP packet (linktype {})", linktype);
                    return link_layer::tun_tap::parse_by_dlt(data, linktype, self, None, None);
                }
                _ => {
                    log::debug!("Unknown linktype {}, trying Ethernet", linktype);
                }
            }
        }

        // Fallback: try Ethernet parsing if no linktype or unknown linktype
        log::debug!("Using fallback Ethernet parsing");
        link_layer::ethernet::parse(data, self, None, None)
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

    /// Parse an IPv4 packet from Ethernet frame data
    /// (data includes the 14-byte Ethernet header)
    pub fn parse_ipv4_packet_inner(
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

        // Extract actual packet length from IP header (bytes 2-3: Total Length field)
        let ip_total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]) as usize;
        // Actual packet size = Ethernet header (14 bytes) + IP total length
        let actual_packet_len = 14 + ip_total_length;

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

        let params = TransportParams::new(
            src_ip,
            dst_ip,
            actual_packet_len,
            process_name,
            process_id,
        );

        match protocol_num {
            1 => protocol::icmp::parse(transport_data, params, &self.local_ips),
            6 => protocol::tcp::parse(transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(transport_data, params, &self.config, &self.local_ips),
            _ => None,
        }
    }

    /// Parse an IPv6 packet from Ethernet frame data
    /// (data includes the 14-byte Ethernet header)
    pub fn parse_ipv6_packet_inner(
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

        // Extract actual packet length from IPv6 header (bytes 4-5: Payload Length field)
        let ipv6_payload_length = u16::from_be_bytes([ip_data[4], ip_data[5]]) as usize;
        // Actual packet size = Ethernet header (14 bytes) + IPv6 header (40 bytes) + payload length
        let actual_packet_len = 14 + 40 + ipv6_payload_length;

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

        // Handle extension headers if needed
        let (final_next_header, transport_offset) =
            self.parse_ipv6_extension_headers(next_header, transport_data);
        let final_transport_data = &transport_data[transport_offset..];

        let params = TransportParams::new(
            src_ip,
            dst_ip,
            actual_packet_len,
            process_name,
            process_id,
        );

        match final_next_header {
            58 => protocol::icmp::parse_v6(final_transport_data, params, &self.local_ips),
            6 => protocol::tcp::parse(final_transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(final_transport_data, params, &self.config, &self.local_ips),
            _ => None,
        }
    }





    /// Parse an ARP packet from Ethernet frame data
    /// (data includes the 14-byte Ethernet header)
    pub fn parse_arp_packet_inner(
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
            tcp_header: None,
            protocol_state: ProtocolState::Arp { operation },
            is_outgoing,
            packet_len: data.len(),
            dpi_result: None,
            process_name,
            process_id,
        })
    }

    /// Parse a raw IPv4 packet (no link-layer header)
    /// Used by TUN devices, PKTAP DLT_RAW, and Linux Cooked Capture
    pub fn parse_raw_ipv4_packet(
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

        // Extract actual packet length from IP header (bytes 2-3: Total Length field)
        // For raw IP packets, there's no Ethernet header
        let actual_packet_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let protocol_num = data[9];
        let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        let ihl = data[0] & 0x0F;
        let ip_header_len = (ihl as usize) * 4;

        if data.len() < ip_header_len {
            return None;
        }

        let transport_data = &data[ip_header_len..];

        let params = TransportParams::new(
            src_ip,
            dst_ip,
            actual_packet_len,
            process_name,
            process_id,
        );

        match protocol_num {
            1 => protocol::icmp::parse(transport_data, params, &self.local_ips),
            6 => protocol::tcp::parse(transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(transport_data, params, &self.config, &self.local_ips),
            _ => None,
        }
    }

    /// Parse a raw IPv6 packet (no link-layer header)
    /// Used by TUN devices, PKTAP DLT_RAW, and Linux Cooked Capture
    pub fn parse_raw_ipv6_packet(
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

        // Extract actual packet length from IPv6 header (bytes 4-5: Payload Length field)
        // For raw IP packets, actual size = IPv6 header (40 bytes) + payload length
        let ipv6_payload_length = u16::from_be_bytes([data[4], data[5]]) as usize;
        let actual_packet_len = 40 + ipv6_payload_length;

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

        // Handle extension headers if needed
        let (final_next_header, transport_offset) =
            self.parse_ipv6_extension_headers(next_header, transport_data);
        let final_transport_data = &transport_data[transport_offset..];

        let params = TransportParams::new(
            src_ip,
            dst_ip,
            actual_packet_len,
            process_name,
            process_id,
        );

        match final_next_header {
            58 => protocol::icmp::parse_v6(final_transport_data, params, &self.local_ips),
            6 => protocol::tcp::parse(final_transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(final_transport_data, params, &self.config, &self.local_ips),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    /// Helper to create a parser with a specific linktype and controlled local IPs
    /// This adds 192.168.1.100 to the local_ips set so test packets are correctly identified
    fn create_parser_with_linktype(linktype: i32) -> PacketParser {
        let mut parser = PacketParser::with_config(ParserConfig::default()).with_linktype(linktype);
        // Add test IP to local_ips so the parser treats it as local
        parser.local_ips.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        parser
    }

    // Test fixture generators - inline versions of test packets
    fn ethernet_ipv4_tcp_syn() -> Vec<u8> {
        vec![
            // Ethernet header
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
            // IPv4 header
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1,
            100, 93, 184, 216, 34,
            // TCP header (SYN flag)
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn ethernet_ipv4_udp_dns() -> Vec<u8> {
        vec![
            // Ethernet
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
            // IPv4
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1,
            100, 8, 8, 8, 8,
            // UDP
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ]
    }

    fn ethernet_ipv6_tcp() -> Vec<u8> {
        vec![
            // Ethernet
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd,
            // IPv6 header
            0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x06, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            // TCP
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn linux_sll_ipv4_tcp() -> Vec<u8> {
        vec![
            // Linux SLL header
            0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
            0x08, 0x00,
            // IPv4
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1,
            100, 93, 184, 216, 34,
            // TCP
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn linux_sll2_ipv4_udp() -> Vec<u8> {
        vec![
            // Linux SLL2 header
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
            // IPv4
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1,
            100, 8, 8, 8, 8,
            // UDP
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ]
    }

    // ====== DLT_EN10MB (Ethernet) Tests ======

    #[test]
    fn test_ethernet_ipv4_tcp_parsing() {
        let parser = create_parser_with_linktype(1); // DLT_EN10MB
        let packet = ethernet_ipv4_tcp_syn();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse valid Ethernet IPv4 TCP packet");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::TCP);
        // Source is 192.168.1.100:1234, Dest is 93.184.216.34:80
        // Since source is local IP, local_addr should be source, remote should be dest
        assert_eq!(p.local_addr.port(), 1234, "Local port should be 1234");
        assert_eq!(p.remote_addr.port(), 80, "Remote port should be 80");
        assert!(p.tcp_header.is_some());
        assert!(p.tcp_header.unwrap().flags.syn, "SYN flag should be set");
    }

    #[test]
    fn test_ethernet_ipv4_udp_parsing() {
        let parser = create_parser_with_linktype(1);
        let packet = ethernet_ipv4_udp_dns();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some());

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::UDP);
        // Source: 192.168.1.100:1234, Dest: 8.8.8.8:53
        assert_eq!(p.local_addr.port(), 1234);
        assert_eq!(p.remote_addr.port(), 53, "Should detect DNS port");
    }

    #[test]
    fn test_ethernet_ipv6_tcp_parsing() {
        let parser = create_parser_with_linktype(1);
        let packet = ethernet_ipv6_tcp();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse IPv6 packets");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::TCP);
        assert!(matches!(p.local_addr.ip(), IpAddr::V6(_)), "Should be IPv6");
    }

    #[test]
    fn test_truncated_ethernet_packet() {
        let parser = create_parser_with_linktype(1);
        let truncated = vec![0x00, 0x11, 0x22]; // Only 3 bytes

        let parsed = parser.parse_packet(&truncated);
        assert!(parsed.is_none(), "Should reject truncated packets");
    }

    #[test]
    fn test_unknown_ethertype() {
        let parser = create_parser_with_linktype(1);
        let packet = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff,
            0xff, // Unknown EtherType
        ];

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_none(), "Should reject unknown EtherType");
    }

    // ====== DLT_LINUX_SLL Tests ======

    #[test]
    fn test_linux_sll_ipv4_tcp_parsing() {
        let parser = create_parser_with_linktype(113); // DLT_LINUX_SLL
        let packet = linux_sll_ipv4_tcp();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse Linux SLL packets");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::TCP);
        assert_eq!(p.local_addr.port(), 1234);
        assert_eq!(p.remote_addr.port(), 80);
    }

    #[test]
    fn test_linux_sll_truncated() {
        let parser = create_parser_with_linktype(113);
        let truncated = vec![0x00, 0x00, 0x00]; // Too short

        let parsed = parser.parse_packet(&truncated);
        assert!(parsed.is_none(), "Should reject truncated SLL packets");
    }

    // ====== DLT_LINUX_SLL2 Tests ======

    #[test]
    fn test_linux_sll2_ipv4_udp_parsing() {
        let parser = create_parser_with_linktype(276); // DLT_LINUX_SLL2
        let packet = linux_sll2_ipv4_udp();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse Linux SLL2 packets");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::UDP);
        assert_eq!(p.local_addr.port(), 1234);
        assert_eq!(p.remote_addr.port(), 53);
    }

    #[test]
    fn test_linux_sll2_truncated() {
        let parser = create_parser_with_linktype(276);
        let truncated = vec![0x08, 0x00]; // Too short for SLL2

        let parsed = parser.parse_packet(&truncated);
        assert!(parsed.is_none(), "Should reject truncated SLL2 packets");
    }

    // ====== TCP Flags Tests ======

    #[test]
    fn test_tcp_flags_parsing() {
        use crate::network::protocol::tcp::parse_tcp_flags;

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

    // ====== Parser Configuration Tests ======

    #[test]
    fn test_parser_default_config() {
        let config = ParserConfig::default();
        assert!(config.enable_dpi, "DPI should be enabled by default");
        assert_eq!(config.dpi_packet_limit, 10);
    }

    #[test]
    fn test_parser_with_linktype() {
        let parser = PacketParser::with_config(ParserConfig::default()).with_linktype(1);
        assert_eq!(parser.linktype, Some(1));
    }

    // ====== Local IP Detection Tests ======

    #[test]
    fn test_local_ip_detection() {
        let parser = PacketParser::new();
        // Should have at least loopback
        assert!(!parser.local_ips.is_empty(), "Should detect local IPs");
    }

    // ====== Edge Cases ======

    #[test]
    fn test_empty_packet() {
        let parser = create_parser_with_linktype(1);
        let empty = vec![];
        assert!(parser.parse_packet(&empty).is_none());
    }

    #[test]
    fn test_ipv4_with_options() {
        let parser = create_parser_with_linktype(1);
        let mut packet = vec![
            // Ethernet
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
            // IPv4 with IHL=6 (24 bytes header with 4 bytes options)
            0x46, 0x00, 0x00, 0x2c, // IHL=6, Total=44
            0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 100, 93, 184, 216,
            34, // IP options (4 bytes)
            0x01, 0x01, 0x00, 0x00,
        ];
        // TCP header
        packet.extend_from_slice(&[
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should handle IPv4 with options");
    }

    #[test]
    fn test_packet_length_calculation_ipv4() {
        let parser = create_parser_with_linktype(1);
        let packet = ethernet_ipv4_tcp_syn();

        let parsed = parser.parse_packet(&packet).unwrap();
        // IPv4 total length is 40 bytes (0x0028), plus 14 bytes Ethernet = 54
        assert_eq!(parsed.packet_len, 54);
    }

    #[test]
    fn test_packet_length_calculation_ipv6() {
        let parser = create_parser_with_linktype(1);
        let packet = ethernet_ipv6_tcp();

        let parsed = parser.parse_packet(&packet).unwrap();
        // IPv6: 14 (Ethernet) + 40 (IPv6 header) + 20 (payload) = 74
        assert_eq!(parsed.packet_len, 74);
    }
}
