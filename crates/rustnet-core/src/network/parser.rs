use crate::network::dpi::DpiResult;
use crate::network::link_layer;
#[cfg(target_os = "macos")]
use crate::network::link_layer::ethernet;
#[cfg(target_os = "macos")]
use crate::network::link_layer::pktap;
use crate::network::local_addresses::{LocalAddresses, collect_local_addresses};
use crate::network::oui::OuiLookup;
use crate::network::protocol;
use crate::network::protocol::TransportParams;
use crate::network::types::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const AMBIGUOUS_ENDPOINT_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const AMBIGUOUS_ENDPOINT_REFRESH_MAX_INTERVAL: Duration = Duration::from_secs(60);

pub use crate::network::protocol::tcp::{SynWindowScale, TcpFlags, TcpHeaderInfo};

/// Result of parsing a packet
#[derive(Debug)]
pub struct ParsedPacket {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Endpoint address kinds, stamped centrally in `PacketParser::parse_packet`
    /// (subnet-broadcast detection needs the parser's interface snapshot).
    pub local_addr_kind: AddrKind,
    pub remote_addr_kind: AddrKind,
    /// Whether the remote endpoint is a default-gateway address, stamped
    /// centrally alongside the address kinds from the parser's route snapshot.
    pub remote_is_gateway: bool,
    pub tcp_header: Option<TcpHeaderInfo>, // TCP header info (seq, ack, window, flags)
    pub protocol_state: ProtocolState,
    pub is_outgoing: bool,
    pub packet_len: usize,
    pub dpi_result: Option<DpiResult>, // DPI results if available
    pub process_name: Option<String>,  // Process name from PKTAP metadata
    pub process_id: Option<u32>,       // Process ID from PKTAP metadata
}

impl ParsedPacket {
    /// Packet with the given flow fields and process attribution. The address
    /// kinds and gateway flag start at their unicast/false defaults (they are
    /// overwritten centrally in `PacketParser::parse_packet`), and
    /// `tcp_header`/`dpi_result` start as `None` for the caller to fill in
    /// where applicable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol_state: ProtocolState,
        is_outgoing: bool,
        packet_len: usize,
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Self {
        Self {
            protocol,
            local_addr,
            remote_addr,
            local_addr_kind: AddrKind::Unicast,
            remote_addr_kind: AddrKind::Unicast,
            remote_is_gateway: false,
            tcp_header: None,
            protocol_state,
            is_outgoing,
            packet_len,
            dpi_result: None,
            process_name,
            process_id,
        }
    }

    /// The flow identity this packet belongs to, derived from protocol and
    /// addresses. `ConnectionKey` is `Copy`, so this costs nothing on the
    /// per-packet path.
    #[inline]
    pub fn connection_key(&self) -> ConnectionKey {
        ConnectionKey::new(self.protocol, self.local_addr, self.remote_addr)
    }
}

/// Shared test constructors so each test module builds only the fields its
/// scenario exercises instead of repeating the full struct literal.
#[cfg(test)]
impl ParsedPacket {
    /// Baseline test packet: unicast endpoints, no TCP header, no DPI result,
    /// no process attribution. Callers override the fields they care about.
    pub(crate) fn test_base(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        protocol_state: ProtocolState,
    ) -> Self {
        Self::new(
            protocol,
            local_addr,
            remote_addr,
            protocol_state,
            false,
            0,
            None,
            None,
        )
    }

    /// TCP test packet carrying the given header.
    pub(crate) fn test_tcp(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        tcp_header: TcpHeaderInfo,
    ) -> Self {
        let mut packet = Self::test_base(
            Protocol::Tcp,
            local_addr,
            remote_addr,
            ProtocolState::Tcp(TcpState::Unknown),
        );
        packet.tcp_header = Some(tcp_header);
        packet
    }

    /// UDP test packet classified by DPI as `application`.
    pub(crate) fn test_udp(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        application: ApplicationProtocol,
    ) -> Self {
        let mut packet =
            Self::test_base(Protocol::Udp, local_addr, remote_addr, ProtocolState::Udp);
        packet.dpi_result = Some(DpiResult { application });
        packet
    }
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

        log::trace!(
            "ParserConfig: DPI {} (limit: {} packets per connection)",
            if config.enable_dpi {
                "enabled"
            } else {
                "disabled"
            },
            config.dpi_packet_limit
        );

        // Demonstrate usage: check if we should perform DPI on hypothetical packet counts
        if config.enable_dpi {
            log::trace!("  - Packet 0: DPI = {}", config.should_perform_dpi(0));
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

/// Packet parser with a refreshable snapshot of the host's local addresses.
pub struct PacketParser {
    local_ips: std::collections::HashSet<IpAddr>,
    /// Subnet-directed broadcast addresses of the host's IPv4 networks,
    /// refreshed together with `local_ips`.
    v4_broadcasts: std::collections::HashSet<Ipv4Addr>,
    /// Default-gateway addresses from the host's routing table, refreshed
    /// together with `local_ips`.
    gateways: std::collections::HashSet<IpAddr>,
    last_local_ip_refresh: Instant,
    last_ambiguous_endpoint_refresh: Option<Instant>,
    unchanged_ambiguous_refreshes: u32,
    config: ParserConfig,
    linktype: Option<i32>, // DLT linktype - 149 means PKTAP on macOS
    oui_lookup: Option<std::sync::Arc<OuiLookup>>,
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
        Self::with_config(ParserConfig::default())
    }

    pub fn with_config(config: ParserConfig) -> Self {
        let local = collect_local_addresses();
        Self {
            local_ips: local.ips,
            v4_broadcasts: local.v4_broadcasts,
            gateways: local.gateways,
            last_local_ip_refresh: Instant::now(),
            last_ambiguous_endpoint_refresh: None,
            unchanged_ambiguous_refreshes: 0,
            config,
            linktype: None,
            oui_lookup: None,
        }
    }

    /// Set the OUI lookup for MAC vendor resolution. Accepts either an owned
    /// `OuiLookup` or an `Arc<OuiLookup>`, so the ~3 MB vendor table can be
    /// shared between processor threads instead of cloned.
    pub fn with_oui_lookup(mut self, oui_lookup: impl Into<std::sync::Arc<OuiLookup>>) -> Self {
        self.oui_lookup = Some(oui_lookup.into());
        self
    }

    /// Set the linktype for this parser (needed for PKTAP detection)
    pub fn with_linktype(mut self, linktype: i32) -> Self {
        self.linktype = Some(linktype);

        let link_type = link_layer::LinkLayerType::from_dlt(linktype);
        if link_type.is_tunnel() {
            log::debug!(
                "Parser configured for tunnel interface: linktype {} ({:?})",
                linktype,
                link_type
            );

            log::trace!("TUN/TAP parsing available via link_layer::tun_tap module");
            log::trace!("  - TUN interfaces (Layer 3): tun*, utun*");
            log::trace!("  - TAP interfaces (Layer 2): tap*");
        } else {
            log::trace!(
                "Parser configured with linktype {} ({:?})",
                linktype,
                link_type
            );
        }

        self
    }

    /// Refresh the local-address snapshot from the operating system.
    ///
    /// Returns `true` when the set changed. Capture workers call this
    /// periodically so DHCP renewals, VPN interfaces, and IPv6 privacy-address
    /// rotation do not leave endpoint orientation stale for the lifetime of
    /// the process.
    pub fn refresh_local_ips(&mut self) -> bool {
        self.refresh_local_ips_with(collect_local_addresses)
    }

    /// Refresh the local-address snapshot once `interval` has elapsed.
    pub fn refresh_local_ips_if_due(&mut self, interval: Duration) -> bool {
        if self.last_local_ip_refresh.elapsed() < interval {
            return false;
        }
        self.refresh_local_ips()
    }

    /// Parse a packet and retry once after refreshing local addresses when
    /// neither unicast endpoint is known to be local.
    ///
    /// This self-heals the first packet observed after an address is added,
    /// rather than waiting for the periodic refresh. Refresh attempts caused
    /// by unrelated forwarded traffic are rate-limited with exponential
    /// backoff while they keep observing no change.
    pub fn parse_packet_with_refresh(&mut self, data: &[u8]) -> Option<ParsedPacket> {
        self.parse_packet_with_local_ip_collector(data, collect_local_addresses)
    }

    /// Classify an endpoint address against the current interface snapshot.
    fn classify_addr(&self, ip: IpAddr) -> AddrKind {
        match ip {
            IpAddr::V4(v4) if v4.is_multicast() => AddrKind::Multicast,
            IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST || self.v4_broadcasts.contains(&v4) => {
                AddrKind::Broadcast
            }
            IpAddr::V6(v6) if v6.is_multicast() => AddrKind::Multicast,
            _ => AddrKind::Unicast,
        }
    }

    /// Whether `ip` can plausibly be a local unicast endpoint. Subnet-directed
    /// broadcasts are recognized via the interface prefix snapshot, so they do
    /// not trigger ambiguous-endpoint interface re-enumeration.
    fn is_unicast_endpoint(&self, ip: IpAddr) -> bool {
        !ip.is_unspecified() && self.classify_addr(ip) == AddrKind::Unicast
    }

    /// Parse a raw packet and stamp both endpoint address kinds.
    ///
    /// The kinds are stamped here, at the single chokepoint every link-layer
    /// path funnels through, because subnet-broadcast detection needs this
    /// parser's interface snapshot.
    pub fn parse_packet(&self, data: &[u8]) -> Option<ParsedPacket> {
        let mut parsed = self.parse_packet_link_layer(data)?;
        parsed.local_addr_kind = self.classify_addr(parsed.local_addr.ip());
        parsed.remote_addr_kind = self.classify_addr(parsed.remote_addr.ip());
        parsed.remote_is_gateway = parsed.remote_addr_kind == AddrKind::Unicast
            && self.gateways.contains(&parsed.remote_addr.ip());
        Some(parsed)
    }

    /// Parse a raw packet using the appropriate link-layer parser
    fn parse_packet_link_layer(&self, data: &[u8]) -> Option<ParsedPacket> {
        if let Some(linktype) = self.linktype {
            let link_type = link_layer::LinkLayerType::from_dlt(linktype);
            log::trace!(
                "Parsing packet with linktype {} ({:?})",
                linktype,
                link_type
            );

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
                0
                | 1
                | 12
                | 101
                | link_layer::dlt::LINKTYPE_IPV4
                | link_layer::dlt::LINKTYPE_IPV6 => {
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

    fn parse_packet_with_local_ip_collector<F>(
        &mut self,
        data: &[u8],
        collector: F,
    ) -> Option<ParsedPacket>
    where
        F: FnOnce() -> LocalAddresses,
    {
        let parsed = self.parse_packet(data)?;
        let local_ip = parsed.local_addr.ip();
        let remote_ip = parsed.remote_addr.ip();

        if self.local_ips.contains(&local_ip)
            || self.local_ips.contains(&remote_ip)
            || !self.is_unicast_endpoint(local_ip)
            || !self.is_unicast_endpoint(remote_ip)
        {
            return Some(parsed);
        }

        let now = Instant::now();
        if self
            .last_ambiguous_endpoint_refresh
            .is_some_and(|last| now.duration_since(last) < self.ambiguous_refresh_interval())
        {
            return Some(parsed);
        }
        self.last_ambiguous_endpoint_refresh = Some(now);

        if self.refresh_local_ips_with(collector) {
            self.parse_packet(data)
        } else {
            self.unchanged_ambiguous_refreshes =
                self.unchanged_ambiguous_refreshes.saturating_add(1);
            Some(parsed)
        }
    }

    /// Interval between ambiguous-endpoint refresh attempts.
    ///
    /// Sustained traffic with no local endpoint (e.g. mirrored or forwarded
    /// traffic) would otherwise re-enumerate interfaces every second forever,
    /// so each fruitless refresh doubles the interval up to a cap. Any refresh
    /// that observes a change resets it. Subnet-directed broadcasts are
    /// recognized by `is_unicast_endpoint` via the interface prefix snapshot
    /// and never reach this path.
    fn ambiguous_refresh_interval(&self) -> Duration {
        let factor = 1u32 << self.unchanged_ambiguous_refreshes.min(6);
        AMBIGUOUS_ENDPOINT_REFRESH_INTERVAL
            .saturating_mul(factor)
            .min(AMBIGUOUS_ENDPOINT_REFRESH_MAX_INTERVAL)
    }

    fn refresh_local_ips_with<F>(&mut self, collector: F) -> bool
    where
        F: FnOnce() -> LocalAddresses,
    {
        let refreshed = collector();
        self.last_local_ip_refresh = Instant::now();
        if refreshed.ips == self.local_ips
            && refreshed.v4_broadcasts == self.v4_broadcasts
            && refreshed.gateways == self.gateways
        {
            return false;
        }

        log::debug!(
            "Local address set changed: {} -> {} address(es)",
            self.local_ips.len(),
            refreshed.ips.len()
        );
        self.local_ips = refreshed.ips;
        self.v4_broadcasts = refreshed.v4_broadcasts;
        self.gateways = refreshed.gateways;
        self.unchanged_ambiguous_refreshes = 0;
        true
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

        match pktap_header.inner_dlt() {
            1 => {
                // DLT_EN10MB - Ethernet frame
                // Note: macOS/XNU strips 802.1Q VLAN tags in ether_demux() before
                // packets reach PKTAP, and libpcap on macOS does not reconstruct them.
                // VLAN-tagged frames will never have EtherType 0x8100 here, but we
                // delegate to ethernet::parse() to avoid duplicating the parsing logic.
                ethernet::parse(payload, self, process_name, process_id)
            }
            12 => {
                // DLT_RAW - Raw IP packet
                link_layer::raw_ip::parse(payload, self, process_name, process_id)
            }
            _ => {
                log::debug!("Unsupported PKTAP inner DLT: {}", pktap_header.inner_dlt());
                None
            }
        }
    }

    /// Parse an IPv4 packet from link-layer frame data
    /// (data includes the link-layer header of `offset` bytes)
    pub fn parse_ipv4_packet_inner(
        &self,
        data: &[u8],
        offset: usize,
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let ip_data = &data[offset..];
        if ip_data.len() < 20 {
            return None;
        }

        let version = ip_data[0] >> 4;
        if version != 4 {
            return None;
        }

        // Extract actual packet length from IP header (bytes 2-3: Total Length field)
        let ip_total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]) as usize;
        // Actual packet size = link-layer header (offset bytes) + IP total length
        let actual_packet_len = offset + ip_total_length;

        // Bytes 6-7: flags + fragment offset. A non-first fragment carries
        // no transport header; parsing it would read mid-payload bytes as
        // ports and fabricate connections.
        let fragment_offset = u16::from_be_bytes([ip_data[6], ip_data[7]]) & 0x1FFF;
        if fragment_offset != 0 {
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
        // IHL below 5 is invalid (the fixed header alone is 20 bytes);
        // treating it as a header length would overlap header and payload.
        if ihl < 5 {
            return None;
        }
        let ip_header_len = (ihl as usize) * 4;

        if ip_data.len() < ip_header_len {
            return None;
        }

        let transport_data = &ip_data[ip_header_len..];

        // A captured frame can carry bytes past the end of the IP datagram:
        // Ethernet pads anything below the 60-byte minimum, and some senders
        // append trailers. Those bytes are not transport payload, so trim the
        // slice to the declared Total Length. Keep the untrimmed slice when the
        // field is unusable (0 under TSO/LRO, or below the header length), and
        // clamp to what was captured when the snaplen truncated the packet.
        let transport_data = match ip_total_length.checked_sub(ip_header_len) {
            Some(payload_len) => &transport_data[..payload_len.min(transport_data.len())],
            None => transport_data,
        };

        let params =
            TransportParams::new(src_ip, dst_ip, actual_packet_len, process_name, process_id);

        match protocol_num {
            1 => protocol::icmp::parse(transport_data, params, &self.local_ips),
            2 => protocol::igmp::parse(transport_data, params, &self.local_ips),
            6 => protocol::tcp::parse(transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(transport_data, params, &self.config, &self.local_ips),
            _ => None,
        }
    }

    /// Parse an IPv6 packet from link-layer frame data
    /// (data includes the link-layer header of `offset` bytes)
    pub fn parse_ipv6_packet_inner(
        &self,
        data: &[u8],
        offset: usize,
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let ip_data = &data[offset..];
        if ip_data.len() < 40 {
            return None;
        }

        let version = ip_data[0] >> 4;
        if version != 6 {
            return None;
        }

        // Extract actual packet length from IPv6 header (bytes 4-5: Payload Length field)
        let ipv6_payload_length = u16::from_be_bytes([ip_data[4], ip_data[5]]) as usize;
        // Actual packet size = link-layer header (offset bytes) + IPv6 header (40 bytes) + payload length
        let actual_packet_len = offset + 40 + ipv6_payload_length;

        let next_header = ip_data[6];

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

        // Same trailing-bytes problem as IPv4: trim to the declared Payload
        // Length so Ethernet padding is not read as transport payload. A zero
        // means the field carries no usable length (TSO/LRO, or a jumbogram
        // whose real size lives in a Hop-by-Hop option, RFC 2675), so the
        // untrimmed slice is kept in that case.
        let transport_data = if ipv6_payload_length == 0 {
            transport_data
        } else {
            &transport_data[..ipv6_payload_length.min(transport_data.len())]
        };

        // Handle extension headers if needed (`None` = non-first fragment,
        // which carries no transport header)
        let (final_next_header, transport_offset, saw_fragment) =
            self.parse_ipv6_extension_headers(next_header, transport_data)?;
        // A crafted extension header can declare a length that runs past the
        // captured bytes, so `transport_offset` may exceed the slice length.
        // Clamp before slicing to avoid an out-of-bounds panic (one-packet DoS).
        let final_transport_data = &transport_data[transport_offset.min(transport_data.len())..];

        let params =
            TransportParams::new(src_ip, dst_ip, actual_packet_len, process_name, process_id);

        match final_next_header {
            58 => self.parse_icmpv6(final_transport_data, params, ip_data[7], saw_fragment),
            6 => protocol::tcp::parse(final_transport_data, params, &self.config, &self.local_ips),
            17 => protocol::udp::parse(final_transport_data, params, &self.config, &self.local_ips),
            _ => None,
        }
    }

    /// Parse an ICMPv6 transport payload and, when the enclosing IPv6 header
    /// proves on-link origin, attach any NDP-carried neighbor mapping to the
    /// resulting `ProtocolState::Icmp`.
    ///
    /// NDP receivers require hop limit 255 (RFC 4861): a forged message
    /// routed from off-link cannot arrive with it, which keeps the neighbor
    /// cache on-link the way ARP's non-routability does for IPv4. Messages
    /// whose extension-header chain included a Fragment Header are never
    /// learned from: RFC 6980 forbids fragmented NDP precisely because
    /// fragmentation lets crafted options evade validation.
    fn parse_icmpv6(
        &self,
        transport_data: &[u8],
        params: TransportParams,
        hop_limit: u8,
        saw_fragment: bool,
    ) -> Option<ParsedPacket> {
        let src_ip = params.src_ip;
        let mut packet = protocol::icmp::parse_v6(transport_data, params, &self.local_ips)?;
        if hop_limit == 255
            && !saw_fragment
            && let ProtocolState::Icmp { ndp_neighbor, .. } = &mut packet.protocol_state
        {
            *ndp_neighbor =
                protocol::ndp::extract_neighbor(transport_data, src_ip, self.oui_lookup.as_deref());
        }
        Some(packet)
    }

    /// Parse an ARP packet from link-layer frame data
    /// (data includes the link-layer header of `header_len` bytes)
    pub fn parse_arp_packet_with_offset(
        &self,
        data: &[u8],
        header_len: usize,
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        let arp_data = &data[header_len..];
        if arp_data.len() < 28 {
            return None;
        }

        let hardware_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
        let protocol_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
        let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

        if hardware_type != 1 || protocol_type != 0x0800 {
            return None;
        }

        let sender_mac = crate::network::oui::format_mac(&arp_data[8..14]);
        let target_mac = crate::network::oui::format_mac(&arp_data[18..24]);

        let sender_ip = IpAddr::from([arp_data[14], arp_data[15], arp_data[16], arp_data[17]]);
        let target_ip = IpAddr::from([arp_data[24], arp_data[25], arp_data[26], arp_data[27]]);

        let operation = match opcode {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return None,
        };

        let sender_vendor = self
            .oui_lookup
            .as_ref()
            .and_then(|oui| oui.lookup(&sender_mac).map(String::from));
        let target_vendor = self
            .oui_lookup
            .as_ref()
            .and_then(|oui| oui.lookup(&target_mac).map(String::from));

        let arp_info = ArpInfo {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            sender_vendor,
            target_vendor,
        };

        let is_outgoing = self.local_ips.contains(&sender_ip);
        let (local_addr, remote_addr) = if is_outgoing {
            (SocketAddr::new(sender_ip, 0), SocketAddr::new(target_ip, 0))
        } else {
            (SocketAddr::new(target_ip, 0), SocketAddr::new(sender_ip, 0))
        };

        Some(ParsedPacket::new(
            Protocol::Arp,
            local_addr,
            remote_addr,
            ProtocolState::Arp(arp_info),
            is_outgoing,
            data.len(),
            process_name,
            process_id,
        ))
    }

    /// Parse a raw IPv4 packet (no link-layer header)
    /// Used by TUN devices, PKTAP DLT_RAW, and Linux Cooked Capture
    pub fn parse_raw_ipv4_packet(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        self.parse_ipv4_packet_inner(data, 0, process_name, process_id)
    }

    /// Parse a raw IPv6 packet (no link-layer header)
    /// Used by TUN devices, PKTAP DLT_RAW, and Linux Cooked Capture
    pub fn parse_raw_ipv6_packet(
        &self,
        data: &[u8],
        process_name: Option<String>,
        process_id: Option<u32>,
    ) -> Option<ParsedPacket> {
        self.parse_ipv6_packet_inner(data, 0, process_name, process_id)
    }

    /// Walk the IPv6 extension-header chain. Returns the final next-header
    /// value, the offset of the transport header, and whether a Fragment
    /// Header was traversed (a first/atomic fragment still carries the
    /// transport header, but NDP must not be learned from it, RFC 6980).
    /// `None` for a non-first fragment: its "transport header" position
    /// holds mid-payload bytes that must not be parsed as ports.
    fn parse_ipv6_extension_headers(
        &self,
        mut next_header: u8,
        data: &[u8],
    ) -> Option<(u8, usize, bool)> {
        let mut offset = 0;
        let mut saw_fragment = false;

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
                        return Some((next_header, offset, saw_fragment));
                    }
                    next_header = data[offset];
                    let header_len = ((data[offset + 1] as usize) + 1) * 8;
                    offset += header_len;
                }
                FRAGMENT => {
                    saw_fragment = true;
                    if data.len() < offset + 8 {
                        return Some((next_header, offset, saw_fragment));
                    }
                    // Bytes 2-3: fragment offset (upper 13 bits). Only the
                    // first fragment (offset 0) carries the transport header.
                    let fragment_offset =
                        u16::from_be_bytes([data[offset + 2], data[offset + 3]]) >> 3;
                    if fragment_offset != 0 {
                        return None;
                    }
                    next_header = data[offset];
                    offset += 8;
                }
                AUTHENTICATION => {
                    if data.len() < offset + 2 {
                        return Some((next_header, offset, saw_fragment));
                    }
                    next_header = data[offset];
                    let header_len = ((data[offset + 1] as usize) + 2) * 4;
                    offset += header_len;
                }
                ENCAPSULATING_SECURITY => {
                    return Some((next_header, offset, saw_fragment));
                }
                _ => {
                    return Some((next_header, offset, saw_fragment));
                }
            }

            if offset >= data.len() {
                return Some((next_header, offset, saw_fragment));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn local_addresses(ips: impl IntoIterator<Item = IpAddr>) -> LocalAddresses {
        LocalAddresses {
            ips: ips.into_iter().collect(),
            ..LocalAddresses::default()
        }
    }

    fn local_addresses_with_gateways(
        ips: impl IntoIterator<Item = IpAddr>,
        gateways: impl IntoIterator<Item = IpAddr>,
    ) -> LocalAddresses {
        LocalAddresses {
            gateways: gateways.into_iter().collect(),
            ..local_addresses(ips)
        }
    }

    /// Helper to create a parser with a specific linktype and controlled local IPs
    /// This adds 192.168.1.100 to the local_ips set so test packets are correctly identified
    fn create_parser_with_linktype(linktype: i32) -> PacketParser {
        let mut parser = PacketParser::with_config(ParserConfig::default()).with_linktype(linktype);
        // Add test IP to local_ips so the parser treats it as local
        parser
            .local_ips
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        parser
    }

    // Test fixture generators
    fn ethernet_ipv4_tcp_syn() -> Vec<u8> {
        vec![
            // Ethernet header
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
            // IPv4 header
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1,
            100, 93, 184, 216, 34, // TCP header (SYN flag)
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
            100, 8, 8, 8, 8, // UDP
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ]
    }

    fn ethernet_ipv4_udp(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        vec![
            // Ethernet
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
            // IPv4
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, src[0], src[1],
            src[2], src[3], dst[0], dst[1], dst[2], dst[3], // UDP: 60236 -> 51234
            0xeb, 0x4c, 0xc8, 0x22, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
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

    /// Ethernet IPv6 ICMPv6 Neighbor Solicitation from fe80::2 for fe80::1,
    /// carrying a source link-layer option, hop limit 255. `fragmented`
    /// inserts an atomic Fragment Header (offset 0) before the ICMPv6 header.
    fn ethernet_ipv6_ndp_solicitation(fragmented: bool) -> Vec<u8> {
        let mut icmpv6 = vec![135, 0, 0, 0, 0, 0, 0, 0]; // NS header
        icmpv6.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // target fe80::1
        ]);
        icmpv6.extend_from_slice(&[1, 1, 0x68, 0x5e, 0xdd, 0x09, 0x15, 0x5e]); // source LL option

        let (next_header, payload) = if fragmented {
            let mut p = vec![58, 0, 0, 0, 0, 0, 0, 1]; // atomic fragment, offset 0
            p.extend_from_slice(&icmpv6);
            (44u8, p)
        } else {
            (58u8, icmpv6)
        };

        let mut frame = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd,
            0x60, 0x00, 0x00, 0x00,
        ];
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.push(next_header);
        frame.push(255); // hop limit
        frame.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, // src fe80::2
        ]);
        frame.extend_from_slice(&[
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // dst fe80::1
        ]);
        frame.extend_from_slice(&payload);
        frame
    }

    fn linux_sll_ipv4_tcp() -> Vec<u8> {
        vec![
            // Linux SLL header
            0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00,
            0x08, 0x00, // IPv4
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1,
            100, 93, 184, 216, 34, // TCP
            0x04, 0xd2, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]
    }

    fn linux_sll2_ipv4_udp() -> Vec<u8> {
        vec![
            // Linux SLL2 header
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff, 0x00, 0x00, // IPv4
            0x45, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1,
            100, 8, 8, 8, 8, // UDP
            0x04, 0xd2, 0x00, 0x35, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
        ]
    }

    #[test]
    fn test_ethernet_ipv4_tcp_parsing() {
        let parser = create_parser_with_linktype(1); // DLT_EN10MB
        let packet = ethernet_ipv4_tcp_syn();

        let parsed = parser.parse_packet(&packet);
        assert!(
            parsed.is_some(),
            "Should parse valid Ethernet IPv4 TCP packet"
        );

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::Tcp);
        // Source is 192.168.1.100:1234, Dest is 93.184.216.34:80
        // Since source is local IP, local_addr should be source, remote should be dest
        assert_eq!(p.local_addr.port(), 1234, "Local port should be 1234");
        assert_eq!(p.remote_addr.port(), 80, "Remote port should be 80");
        assert!(p.tcp_header.is_some());
        assert!(p.tcp_header.unwrap().flags.syn, "SYN flag should be set");
    }

    #[test]
    fn ndp_is_learned_at_hop_limit_255_but_never_from_fragments() {
        let parser = create_parser_with_linktype(1); // DLT_EN10MB

        let parsed = parser
            .parse_packet(&ethernet_ipv6_ndp_solicitation(false))
            .expect("NDP solicitation should parse");
        match &parsed.protocol_state {
            ProtocolState::Icmp {
                ndp_neighbor: Some(neighbor),
                ..
            } => {
                assert_eq!(neighbor.ip, "fe80::2".parse::<IpAddr>().unwrap());
                assert_eq!(neighbor.mac, "68:5e:dd:09:15:5e");
            }
            other => panic!("expected a learned NDP neighbor, got {:?}", other),
        }

        // RFC 6980: an NDP message whose header chain includes a Fragment
        // Header must be ignored, even a first/atomic fragment.
        let parsed = parser
            .parse_packet(&ethernet_ipv6_ndp_solicitation(true))
            .expect("fragmented solicitation should still parse as ICMPv6");
        assert!(matches!(
            &parsed.protocol_state,
            ProtocolState::Icmp {
                ndp_neighbor: None,
                ..
            }
        ));
    }

    #[test]
    fn test_ethernet_ipv4_udp_parsing() {
        let parser = create_parser_with_linktype(1);
        let packet = ethernet_ipv4_udp_dns();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some());

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::Udp);
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
        assert_eq!(p.protocol, Protocol::Tcp);
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

    #[test]
    fn test_linux_sll_ipv4_tcp_parsing() {
        let parser = create_parser_with_linktype(113); // DLT_LINUX_SLL
        let packet = linux_sll_ipv4_tcp();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse Linux SLL packets");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::Tcp);
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

    #[test]
    fn test_linux_sll2_ipv4_udp_parsing() {
        let parser = create_parser_with_linktype(276); // DLT_LINUX_SLL2
        let packet = linux_sll2_ipv4_udp();

        let parsed = parser.parse_packet(&packet);
        assert!(parsed.is_some(), "Should parse Linux SLL2 packets");

        let p = parsed.unwrap();
        assert_eq!(p.protocol, Protocol::Udp);
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

    #[test]
    fn test_local_ip_detection() {
        let parser = PacketParser::new();
        // Should have at least loopback
        assert!(!parser.local_ips.is_empty(), "Should detect local IPs");
    }

    #[test]
    fn classify_addr_recognizes_broadcast_and_multicast() {
        let mut parser = create_parser_with_linktype(1);
        parser.v4_broadcasts.insert(Ipv4Addr::new(192, 168, 1, 255));

        assert_eq!(
            parser.classify_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            AddrKind::Broadcast,
            "subnet-directed broadcast from the interface snapshot"
        );
        assert_eq!(
            parser.classify_addr(IpAddr::V4(Ipv4Addr::BROADCAST)),
            AddrKind::Broadcast
        );
        assert_eq!(
            parser.classify_addr(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))),
            AddrKind::Multicast
        );
        assert_eq!(
            parser.classify_addr(IpAddr::V6(
                "ff02::fb".parse().expect("valid fixture address")
            )),
            AddrKind::Multicast
        );
        assert_eq!(
            parser.classify_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254))),
            AddrKind::Unicast,
            "adjacent host must not be mistaken for the broadcast address"
        );
        assert_eq!(
            parser.classify_addr(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            AddrKind::Unicast
        );
    }

    #[test]
    fn incoming_subnet_broadcast_is_stamped_and_skips_refresh() {
        use std::cell::Cell;

        let mut parser = create_parser_with_linktype(1);
        parser.v4_broadcasts.insert(Ipv4Addr::new(192, 168, 1, 255));
        // Peer -> subnet broadcast; neither endpoint is a local unicast address
        let packet = ethernet_ipv4_udp([192, 168, 1, 52], [192, 168, 1, 255]);
        let collector_calls = Cell::new(0u32);

        let parsed = parser
            .parse_packet_with_local_ip_collector(&packet, || {
                collector_calls.set(collector_calls.get() + 1);
                LocalAddresses::default()
            })
            .expect("packet should parse");

        assert_eq!(
            parsed.local_addr.ip(),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert_eq!(parsed.local_addr_kind, AddrKind::Broadcast);
        assert_eq!(parsed.remote_addr_kind, AddrKind::Unicast);
        assert_eq!(
            collector_calls.get(),
            0,
            "a recognized subnet broadcast must not re-enumerate interfaces"
        );
    }

    #[test]
    fn outgoing_broadcast_marks_the_remote_side() {
        let mut parser = create_parser_with_linktype(1);
        parser.v4_broadcasts.insert(Ipv4Addr::new(192, 168, 1, 255));
        // The local host (192.168.1.100) sends to the subnet broadcast
        let packet = ethernet_ipv4_udp([192, 168, 1, 100], [192, 168, 1, 255]);

        let parsed = parser.parse_packet(&packet).expect("packet should parse");

        assert!(parsed.is_outgoing);
        assert_eq!(parsed.local_addr_kind, AddrKind::Unicast);
        assert_eq!(parsed.remote_addr_kind, AddrKind::Broadcast);
    }

    #[test]
    fn gateway_remote_endpoint_is_stamped() {
        let mut parser = create_parser_with_linktype(1);
        parser
            .gateways
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        // The local host (192.168.1.100) talks to the gateway
        let packet = ethernet_ipv4_udp([192, 168, 1, 100], [192, 168, 1, 1]);
        let parsed = parser.parse_packet(&packet).expect("packet should parse");
        assert_eq!(parsed.remote_addr_kind, AddrKind::Unicast);
        assert!(parsed.remote_is_gateway);

        // An ordinary peer on the same subnet must not be marked
        let packet = ethernet_ipv4_udp([192, 168, 1, 100], [192, 168, 1, 52]);
        let parsed = parser.parse_packet(&packet).expect("packet should parse");
        assert!(!parsed.remote_is_gateway);
    }

    #[test]
    fn broadcast_remote_is_never_marked_as_gateway() {
        let mut parser = create_parser_with_linktype(1);
        parser.v4_broadcasts.insert(Ipv4Addr::new(192, 168, 1, 255));
        parser
            .gateways
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));

        let packet = ethernet_ipv4_udp([192, 168, 1, 100], [192, 168, 1, 255]);
        let parsed = parser.parse_packet(&packet).expect("packet should parse");
        assert_eq!(parsed.remote_addr_kind, AddrKind::Broadcast);
        assert!(!parsed.remote_is_gateway);
    }

    #[test]
    fn refresh_picks_up_gateway_changes() {
        let mut parser = create_parser_with_linktype(1);
        parser.local_ips = [IpAddr::V4(Ipv4Addr::LOCALHOST)].into_iter().collect();
        parser.v4_broadcasts.clear();
        parser.gateways.clear();
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let collector =
            || local_addresses_with_gateways([IpAddr::V4(Ipv4Addr::LOCALHOST)], [gateway]);

        assert!(
            parser.refresh_local_ips_with(collector),
            "a gateway-only change must count as a snapshot change"
        );
        assert!(parser.gateways.contains(&gateway));
        assert!(
            !parser.refresh_local_ips_with(collector),
            "an unchanged snapshot must not report a change"
        );
    }

    #[test]
    fn ambiguous_ipv6_packet_refreshes_local_addresses_and_reorients_endpoints() {
        let mut parser = create_parser_with_linktype(1);
        parser.local_ips.clear();
        parser.local_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        parser.local_ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let packet = ethernet_ipv6_tcp();

        let stale = parser.parse_packet(&packet).expect("packet should parse");
        assert!(!stale.is_outgoing);
        assert_eq!(stale.local_addr.port(), 80);

        let new_local = IpAddr::V6("2001:db8::1".parse().expect("valid fixture address"));
        let corrected = parser
            .parse_packet_with_local_ip_collector(&packet, || {
                local_addresses([
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    new_local,
                ])
            })
            .expect("packet should be reparsed");

        assert!(corrected.is_outgoing);
        assert_eq!(corrected.local_addr.ip(), new_local);
        assert_eq!(corrected.local_addr.port(), 1234);
        assert_eq!(corrected.remote_addr.port(), 80);
    }

    #[test]
    fn refresh_replaces_addresses_that_are_no_longer_assigned() {
        let mut parser = create_parser_with_linktype(1);
        let old = IpAddr::V6("2001:db8::1".parse().expect("valid old address"));
        let new = IpAddr::V6("2001:db8::2".parse().expect("valid new address"));
        parser.local_ips = [old].into_iter().collect();

        assert!(parser.refresh_local_ips_with(|| local_addresses([new])));
        assert!(!parser.local_ips.contains(&old));
        assert!(parser.local_ips.contains(&new));
    }

    #[test]
    fn ambiguous_refresh_is_rate_limited_between_packets() {
        use std::cell::Cell;

        let mut parser = create_parser_with_linktype(1);
        parser.local_ips.clear();
        parser.local_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let packet = ethernet_ipv6_tcp();
        let collector_calls = Cell::new(0u32);
        let unchanged_collector = || {
            collector_calls.set(collector_calls.get() + 1);
            local_addresses([IpAddr::V4(Ipv4Addr::LOCALHOST)])
        };

        parser
            .parse_packet_with_local_ip_collector(&packet, unchanged_collector)
            .expect("packet should parse");
        parser
            .parse_packet_with_local_ip_collector(&packet, unchanged_collector)
            .expect("packet should parse");

        assert_eq!(
            collector_calls.get(),
            1,
            "second ambiguous packet within the refresh interval must not re-enumerate"
        );
    }

    #[test]
    fn fruitless_ambiguous_refreshes_back_off_exponentially() {
        let mut parser = create_parser_with_linktype(1);
        assert_eq!(parser.ambiguous_refresh_interval(), Duration::from_secs(1));

        parser.unchanged_ambiguous_refreshes = 3;
        assert_eq!(parser.ambiguous_refresh_interval(), Duration::from_secs(8));

        parser.unchanged_ambiguous_refreshes = 100;
        assert_eq!(
            parser.ambiguous_refresh_interval(),
            AMBIGUOUS_ENDPOINT_REFRESH_MAX_INTERVAL
        );

        let new = IpAddr::V6("2001:db8::99".parse().expect("valid address"));
        assert!(parser.refresh_local_ips_with(|| local_addresses([new])));
        assert_eq!(
            parser.unchanged_ambiguous_refreshes, 0,
            "a refresh that observes a change must reset the backoff"
        );
    }

    #[test]
    fn periodic_refresh_waits_for_interval() {
        let mut parser = create_parser_with_linktype(1);
        let bogus = IpAddr::V6("2001:db8::dead".parse().expect("valid address"));
        parser.local_ips = [bogus].into_iter().collect();

        assert!(!parser.refresh_local_ips_if_due(Duration::from_secs(3600)));
        assert!(
            parser.local_ips.contains(&bogus),
            "snapshot must be untouched before the interval elapses"
        );

        assert!(parser.refresh_local_ips_if_due(Duration::ZERO));
        assert!(!parser.local_ips.contains(&bogus));
    }

    #[test]
    fn test_empty_packet() {
        let parser = create_parser_with_linktype(1);
        let empty = vec![];
        assert!(parser.parse_packet(&empty).is_none());
    }

    #[test]
    fn test_ipv6_extension_header_overflow_does_not_panic() {
        // A crafted IPv6 extension header can declare a length that runs far
        // past the captured bytes; the parser must clamp and return cleanly
        // rather than slice past the end (one-packet DoS of the capture thread).
        let parser = create_parser_with_linktype(1);
        let mut packet = vec![
            // Ethernet (ethertype 0x86dd = IPv6)
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd,
        ];
        packet.extend_from_slice(&[
            // IPv6 header: version 6, next_header = 0 (Hop-by-Hop Options)
            0x60, 0x00, 0x00, 0x00, // version / traffic class / flow label
            0x00, 0x02, // payload length = 2
            0x00, // next header = Hop-by-Hop Options
            0x40, // hop limit
            // src addr (::1)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // dst addr (::2)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ]);
        // Hop-by-Hop extension header that claims (0xFF + 1) * 8 = 2048 bytes
        // while only 2 bytes are present.
        packet.extend_from_slice(&[0x3b /* next = no next header */, 0xff]);

        // Must not panic.
        let _ = parser.parse_packet(&packet);
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

    #[test]
    fn test_ethernet_padding_is_not_counted_as_tcp_payload() {
        let parser = create_parser_with_linktype(1);
        // A bare SYN is 54 bytes on the wire, so the NIC pads it to the
        // 60-byte Ethernet minimum. Those 6 bytes sit past the end of the
        // IP datagram and must not be reported as payload.
        let mut packet = ethernet_ipv4_tcp_syn();
        assert_eq!(packet.len(), 54);
        packet.extend_from_slice(&[0x00; 6]);

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
    }

    #[test]
    fn test_trailing_bytes_are_not_read_as_tcp_payload() {
        let parser = create_parser_with_linktype(1);
        // The IPv4 Total Length still says 40 (header + bare TCP header), so
        // everything appended here is outside the datagram. Reading it as
        // payload would hand DPI bytes the sender never put in the segment.
        let mut packet = ethernet_ipv4_tcp_syn();
        packet.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
        assert!(parsed.dpi_result.is_none());
    }

    #[test]
    fn test_ipv6_padding_is_not_counted_as_tcp_payload() {
        let parser = create_parser_with_linktype(1);
        // IPv6 Payload Length is 20 (TCP header only); the appended bytes are
        // past the end of the datagram.
        let mut packet = ethernet_ipv6_tcp();
        packet.extend_from_slice(&[0x00; 6]);

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
    }

    #[test]
    fn test_real_payload_is_preserved() {
        let parser = create_parser_with_linktype(1);
        // Total Length 0x002c = 44: 20 IPv4 + 20 TCP + 4 payload bytes.
        let mut packet = ethernet_ipv4_tcp_syn();
        packet[16] = 0x00;
        packet[17] = 0x2c;
        packet.extend_from_slice(b"data");

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 4);
    }

    #[test]
    fn test_truncated_capture_keeps_captured_payload() {
        let parser = create_parser_with_linktype(1);
        // Total Length claims 1500 bytes but the snaplen cut the capture
        // short. The payload must be what was captured, not what was claimed.
        let mut packet = ethernet_ipv4_tcp_syn();
        packet[16] = 0x05;
        packet[17] = 0xdc;
        packet.extend_from_slice(b"data");

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 4);
    }

    #[test]
    fn test_sll_padding_is_not_counted_as_tcp_payload() {
        let parser = create_parser_with_linktype(113); // LINUX_SLL
        // Cooked captures keep the Ethernet padding of short frames, so the
        // bytes past the IP Total Length must be trimmed here as well.
        let mut packet = linux_sll_ipv4_tcp();
        packet.extend_from_slice(&[0x00; 6]);

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
    }

    #[test]
    fn test_raw_ip_trailing_bytes_are_not_read_as_tcp_payload() {
        let parser = create_parser_with_linktype(12); // DLT_RAW
        // Raw IP capture: strip the Ethernet header from the fixture and
        // append bytes past the datagram end.
        let mut packet = ethernet_ipv4_tcp_syn()[14..].to_vec();
        packet.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
        assert!(parsed.dpi_result.is_none());
    }

    #[test]
    fn test_raw_ipv6_padding_is_not_counted_as_tcp_payload() {
        let parser = create_parser_with_linktype(12); // DLT_RAW
        let mut packet = ethernet_ipv6_tcp()[14..].to_vec();
        packet.extend_from_slice(&[0x00; 6]);

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 0);
    }

    #[test]
    fn test_zero_total_length_keeps_full_payload() {
        let parser = create_parser_with_linktype(1);
        // TSO/LRO can hand up a segment with Total Length 0. The field is
        // unusable, so the captured bytes are kept rather than dropped.
        let mut packet = ethernet_ipv4_tcp_syn();
        packet[16] = 0x00;
        packet[17] = 0x00;
        packet.extend_from_slice(b"data");

        let parsed = parser.parse_packet(&packet).unwrap();
        assert_eq!(parsed.tcp_header.unwrap().payload_len, 4);
    }
}
