use anyhow::{Result, anyhow};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::time::{Duration, Instant, SystemTime};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

#[cfg(target_os = "macos")]
mod macos;

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    ARP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::ARP => write!(f, "ARP"),
        }
    }
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Closing,
    Closed,
}

/// Protocol-specific state information
#[derive(Debug, Clone, Copy)]
pub enum ProtocolState {
    Tcp(TcpState),
    Udp, // UDP is stateless
    Icmp {
        icmp_type: u8, // 8=Echo Request, 0=Echo Reply, etc.
        icmp_code: u8,
    },
    Arp {
        operation: ArpOperation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// Application layer protocol detection
#[derive(Debug, Clone)]
pub enum ApplicationProtocol {
    Http(HttpInfo),
    Https(TlsInfo),
    Dns(DnsInfo),
    Ssh,
    Quic, // Basic QUIC detection without deep parsing
    Unknown,
}

/// HTTP information
#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub version: HttpVersion,
    pub method: Option<String>,     // GET, POST, etc.
    pub host: Option<String>,       // From Host header
    pub path: Option<String>,       // Request path
    pub status_code: Option<u16>,   // For responses
    pub user_agent: Option<String>, // Useful for identifying clients
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
    Http3, // Inferred from QUIC
}

/// TLS/HTTPS information
#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: Option<TlsVersion>,
    pub sni: Option<String>,
    pub alpn: Vec<String>, // Application protocols like "h2", "http/1.1"
    pub cipher_suite: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

/// DNS information
#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub response_ips: Vec<IpAddr>,
    pub is_response: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQueryType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    Other(u16),
}

/// Deep packet inspection results
#[derive(Debug, Clone)]
pub struct DpiInfo {
    pub application: ApplicationProtocol,
    pub first_packet_time: Instant,
    pub last_update_time: Instant,
}

/// Rate information
#[derive(Debug, Clone)]
pub struct RateInfo {
    pub incoming_bps: f64,
    pub outgoing_bps: f64,
    pub last_calculation: Instant,
}

impl Default for RateInfo {
    fn default() -> Self {
        Self {
            incoming_bps: 0.0,
            outgoing_bps: 0.0,
            last_calculation: Instant::now(),
        }
    }
}

/// Network connection
#[derive(Debug, Clone)]
pub struct Connection {
    // Core identification
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,

    // Protocol state
    pub protocol_state: ProtocolState,

    // Process information
    pub pid: Option<u32>,
    pub process_name: Option<String>,

    // Traffic statistics
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,

    // Timing
    pub created_at: SystemTime,
    pub last_activity: SystemTime,

    // Service identification
    pub service_name: Option<String>, // From port lookup

    // Deep packet inspection
    pub dpi_info: Option<DpiInfo>,

    // Performance metrics
    pub current_rate_bps: RateInfo,
    pub rtt_estimate: Option<Duration>, // Round-trip time if measurable

    // Backward compatibility fields
    pub current_incoming_rate_bps: f64,
    pub current_outgoing_rate_bps: f64,
}

// Add a simple state field for backward compatibility
impl Connection {
    pub fn state(&self) -> String {
        match &self.protocol_state {
            ProtocolState::Tcp(tcp_state) => format!("{:?}", tcp_state),
            ProtocolState::Udp => "ACTIVE".to_string(),
            ProtocolState::Icmp { icmp_type, .. } => match icmp_type {
                8 => "ECHO_REQUEST".to_string(),
                0 => "ECHO_REPLY".to_string(),
                3 => "DEST_UNREACH".to_string(),
                11 => "TIME_EXCEEDED".to_string(),
                _ => "UNKNOWN".to_string(),
            },
            ProtocolState::Arp { operation } => match operation {
                ArpOperation::Request => "ARP_REQUEST".to_string(),
                ArpOperation::Reply => "ARP_REPLY".to_string(),
            },
        }
    }
}

impl Connection {
    /// Create a new connection
    pub fn new(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: ProtocolState,
    ) -> Self {
        let now = SystemTime::now();
        Self {
            protocol,
            local_addr,
            remote_addr,
            protocol_state: state,
            pid: None,
            process_name: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            created_at: now,
            last_activity: now,
            service_name: None,
            dpi_info: None,
            current_rate_bps: RateInfo::default(),
            rtt_estimate: None,
            // Backward compatibility
            current_incoming_rate_bps: 0.0,
            current_outgoing_rate_bps: 0.0,
        }
    }

    /// Check if connection is active (had activity in the last minute)
    pub fn is_active(&self) -> bool {
        self.last_activity.elapsed().unwrap_or_default() < Duration::from_secs(60)
    }

    /// Get the age of the connection (time since creation)
    pub fn age(&self) -> Duration {
        self.created_at.elapsed().unwrap_or_default()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed().unwrap_or_default()
    }

    /// Update transfer rates
    pub fn update_rates(&mut self, new_sent: u64, new_received: u64) {
        let now = Instant::now();
        let elapsed = now
            .duration_since(self.current_rate_bps.last_calculation)
            .as_secs_f64();

        if elapsed > 0.1 {
            // Update rates every 100ms minimum
            let sent_diff = new_sent.saturating_sub(self.bytes_sent) as f64;
            let recv_diff = new_received.saturating_sub(self.bytes_received) as f64;

            self.current_rate_bps = RateInfo {
                outgoing_bps: (sent_diff * 8.0) / elapsed,
                incoming_bps: (recv_diff * 8.0) / elapsed,
                last_calculation: now,
            };

            // Update backward compatibility fields
            self.current_incoming_rate_bps = self.current_rate_bps.incoming_bps;
            self.current_outgoing_rate_bps = self.current_rate_bps.outgoing_bps;
        }
    }
}

/// Process information
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
}

/// Main function for the packet capture thread
pub fn packet_capture_thread(
    interface_name: Option<String>,
    packet_tx: Sender<Vec<u8>>,
    should_stop: Arc<AtomicBool>,
) -> Result<()> {
    let cap_device = match interface_name {
        Some(iface) => {
            info!("Searching for specified interface: {}", iface);
            Device::list()?
                .into_iter()
                .find(|d| d.name == iface)
                .ok_or_else(|| anyhow!("Interface '{}' not found", iface))?
        }
        None => {
            info!("No interface specified, looking up default.");
            Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?
        }
    };

    info!("Opening capture on device: {}", cap_device.name);
    let mut cap = Capture::from_device(cap_device)?
        .promisc(true)
        .snaplen(1024) // Increased for DPI
        .buffer_size(2_000_000)
        .timeout(0)
        .immediate_mode(true)
        .open()?;

    info!("Applying BPF filter for IPv4 and IPv6");
    cap.filter(
        "(ip and (tcp or udp or icmp)) or (ip6 and (tcp or udp or icmp6)) or arp",
        true,
    )?;

    loop {
        if should_stop.load(Ordering::Relaxed) {
            info!("Stop signal received, shutting down capture thread.");
            break;
        }
        match cap.next_packet() {
            Ok(packet) => {
                if packet_tx.send(packet.data.to_vec()).is_err() {
                    info!("Packet receiver has disconnected, stopping capture thread.");
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                debug!("Timeout expired, no packet captured this iteration.");
                continue;
            }
            Err(e) => {
                error!("Error capturing packet: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Network monitor
pub struct NetworkMonitor {
    connections: HashMap<String, Connection>,
    service_lookup: ServiceLookup,
    filter_localhost: bool,
    local_ips: std::collections::HashSet<IpAddr>,
}

/// Manages lookup of service names from a services file
#[derive(Debug)]
struct ServiceLookup {
    services: HashMap<(u16, Protocol), String>,
}

impl ServiceLookup {
    fn new(file_path_str: &str) -> Result<Self> {
        let mut services = HashMap::new();
        let file_path = Path::new(file_path_str);

        if !file_path.exists() {
            warn!(
                "Service definition file not found at '{}'. Service names will not be available.",
                file_path_str
            );
            return Ok(Self { services });
        }

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) => l,
                Err(e) => {
                    warn!("Error reading line from services file: {}", e);
                    continue;
                }
            };

            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                debug!("Skipping malformed line in services file: {}", line);
                continue;
            }

            let service_name = parts[0].to_string();
            let port_protocol_str = parts[1];

            let port_protocol_parts: Vec<&str> = port_protocol_str.split('/').collect();
            if port_protocol_parts.len() != 2 {
                debug!(
                    "Skipping malformed port/protocol in services file: {} from line: {}",
                    port_protocol_str, line
                );
                continue;
            }

            let port = match port_protocol_parts[0].parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    debug!(
                        "Skipping invalid port in services file: {} from line: {}",
                        port_protocol_parts[0], line
                    );
                    continue;
                }
            };

            let protocol = match port_protocol_parts[1].to_lowercase().as_str() {
                "tcp" => Protocol::TCP,
                "udp" => Protocol::UDP,
                _ => continue,
            };

            services.entry((port, protocol)).or_insert(service_name);
        }
        debug!(
            "ServiceLookup initialized with {} entries from '{}'",
            services.len(),
            file_path_str
        );
        Ok(Self { services })
    }

    fn get(&self, port: u16, protocol: Protocol) -> Option<String> {
        self.services.get(&(port, protocol)).cloned()
    }
}

/// Sets the service name for a given connection based on its port and protocol
fn set_connection_service_name_for_connection(
    conn: &mut Connection,
    service_lookup: &ServiceLookup,
) {
    let local_port = conn.local_addr.port();
    let remote_port = conn.remote_addr.port();
    let protocol = conn.protocol;

    let mut final_service_name: Option<String> = None;

    match conn.protocol_state {
        ProtocolState::Tcp(TcpState::Listen) => {
            final_service_name = service_lookup.get(local_port, protocol);
        }
        _ => {
            let local_service_name_opt = service_lookup.get(local_port, protocol);
            if local_service_name_opt.is_some() {
                final_service_name = local_service_name_opt;
            } else {
                let remote_service_name_opt = service_lookup.get(remote_port, protocol);
                if remote_service_name_opt.is_some() {
                    final_service_name = remote_service_name_opt;
                }
            }
        }
    }
    conn.service_name = final_service_name;
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(_interface: Option<String>, filter_localhost: bool) -> Result<Self> {
        log::info!("NetworkMonitor::new - Initializing");

        let mut local_ips = std::collections::HashSet::new();
        for iface in pnet_datalink::interfaces() {
            for ip_network in iface.ips {
                local_ips.insert(ip_network.ip());
            }
        }

        if local_ips.is_empty() {
            warn!(
                "Could not determine any local IP addresses. Connection directionality might be inaccurate."
            );
        } else {
            debug!("Found local IPs: {:?}", local_ips);
        }

        let services_file_path = "assets/services";
        let service_lookup = ServiceLookup::new(services_file_path).unwrap_or_else(|e| {
            error!(
                "Failed to load service definitions from '{}': {}. Proceeding without service names.",
                services_file_path, e
            );
            ServiceLookup {
                services: HashMap::new(),
            }
        });

        log::info!("NetworkMonitor::new - Initialization complete");
        Ok(Self {
            local_ips,
            service_lookup,
            connections: HashMap::new(),
            filter_localhost,
        })
    }

    /// Get active connections
    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        // Start with pcap-captured connections as the primary source
        let mut result_connections: Vec<Connection> = self
            .connections
            .values()
            .filter(|conn| conn.is_active())
            .cloned()
            .collect();

        debug!(
            "get_connections: Found {} active pcap connections",
            result_connections.len()
        );

        // Enrich pcap connections with process information from platform
        if !result_connections.is_empty() {
            // Get connection info with processes from platform
            let mut platform_conns: Vec<Connection> = Vec::new();

            #[cfg(target_os = "linux")]
            {
                if let Err(e) = linux::get_connections_with_process_info(&mut platform_conns) {
                    error!("Error getting process info from platform: {}", e);
                }
            }
            #[cfg(target_os = "macos")]
            {
                if let Err(e) = macos::get_connections_with_process_info(&mut platform_conns) {
                    error!("Error getting process info from platform: {}", e);
                }
            }
            #[cfg(target_os = "windows")]
            {
                if let Err(e) = windows::get_connections_with_process_info(&mut platform_conns) {
                    error!("Error getting process info from platform: {}", e);
                }
            }

            debug!(
                "Found {} platform connections for process enrichment",
                platform_conns.len()
            );

            // Create a lookup map for platform connections
            let mut platform_lookup: HashMap<String, (u32, String)> = HashMap::new();
            for conn in platform_conns {
                if let (Some(pid), Some(name)) = (conn.pid, conn.process_name) {
                    let key = format!(
                        "{:?}:{}-{:?}:{}",
                        conn.protocol, conn.local_addr, conn.protocol, conn.remote_addr
                    );
                    platform_lookup.insert(key, (pid, name));
                }
            }

            // Enrich pcap connections with process names
            for conn in &mut result_connections {
                if conn.process_name.is_none() {
                    let key = self.get_connection_key_for_merge(conn);
                    if let Some((pid, name)) = platform_lookup.get(&key) {
                        debug!(
                            "Enriching connection {}:{} with process {} (PID: {})",
                            conn.local_addr, conn.remote_addr, name, pid
                        );
                        conn.process_name = Some(name.clone());
                    }
                }
            }
        }

        // Sort by last activity (most recent first)
        result_connections.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        // Apply localhost filter if enabled
        if self.filter_localhost {
            result_connections.retain(|conn| {
                !(conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback())
            });
        }

        // Set service names
        for conn in &mut result_connections {
            set_connection_service_name_for_connection(conn, &self.service_lookup);
            if conn.current_rate_bps.incoming_bps > 0.0 || conn.current_rate_bps.outgoing_bps > 0.0
            {
                debug!(
                    "Connection: {:?}, Incoming: {:.2} bps, Outgoing: {:.2} bps",
                    conn.local_addr,
                    conn.current_rate_bps.incoming_bps,
                    conn.current_rate_bps.outgoing_bps
                );
            }
        }

        debug!(
            "get_connections: Returning {} total connections",
            result_connections.len()
        );
        Ok(result_connections)
    }

    fn determine_addresses(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        is_outgoing: bool,
    ) -> (SocketAddr, SocketAddr) {
        if is_outgoing {
            (
                SocketAddr::new(src_ip, src_port),
                SocketAddr::new(dst_ip, dst_port),
            )
        } else {
            (
                SocketAddr::new(dst_ip, dst_port),
                SocketAddr::new(src_ip, src_port),
            )
        }
    }

    /// Process a single raw packet from the queue
    pub fn process_packet(&mut self, data: &[u8]) {
        if data.len() < 14 {
            return;
        }

        // Check EtherType to determine packet type
        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            0x0800 => {
                // IPv4 packet
                self.process_ipv4_packet(data);
            }
            0x86dd => {
                // IPv6 packet
                self.process_ipv6_packet(data);
            }
            0x0806 => {
                // ARP packet
                self.process_arp_packet(data);
            }
            _ => {
                // Other packet types - ignore
            }
        }
    }

    fn process_ipv4_packet(&mut self, data: &[u8]) {
        let ip_data = &data[14..];
        if ip_data.len() < 20 {
            return;
        }

        let version = ip_data[0] >> 4;
        if version != 4 {
            return;
        }

        let protocol = ip_data[9];
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
            return;
        }
        let transport_data = &ip_data[ip_header_len..];

        let is_outgoing = self.local_ips.contains(&src_ip);

        match protocol {
            1 => self.process_icmp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            6 => self.process_tcp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            17 => self.process_udp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            _ => {}
        }
    }

    fn process_ipv6_packet(&mut self, data: &[u8]) {
        let ip_data = &data[14..];
        if ip_data.len() < 40 {
            // IPv6 header is fixed 40 bytes
            return;
        }

        let version = ip_data[0] >> 4;
        if version != 6 {
            return;
        }

        let next_header = ip_data[6]; // Protocol type

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

        let transport_data = &ip_data[40..]; // IPv6 header is always 40 bytes
        let is_outgoing = self.local_ips.contains(&src_ip);

        // Handle extension headers if present
        let (final_next_header, transport_offset) =
            self.parse_ipv6_extension_headers(next_header, transport_data);
        let final_transport_data = &transport_data[transport_offset..];

        match final_next_header {
            58 => {
                self.process_icmpv6_packet(data, is_outgoing, final_transport_data, src_ip, dst_ip)
            }
            6 => self.process_tcp_packet(data, is_outgoing, final_transport_data, src_ip, dst_ip),
            17 => self.process_udp_packet(data, is_outgoing, final_transport_data, src_ip, dst_ip),
            _ => {}
        }
    }

    fn parse_ipv6_extension_headers(&self, mut next_header: u8, data: &[u8]) -> (u8, usize) {
        let mut offset = 0;

        // Common IPv6 extension headers
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
                    offset += 8; // Fragment header is fixed 8 bytes
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
                    // ESP is complex, just skip for now
                    return (next_header, offset);
                }
                _ => {
                    // Not an extension header, this is the final protocol
                    return (next_header, offset);
                }
            }

            if offset >= data.len() {
                return (next_header, offset);
            }
        }
    }

    fn process_icmp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        if transport_data.is_empty() {
            return;
        }

        let icmp_type = transport_data[0];
        let icmp_code = if transport_data.len() > 1 {
            transport_data[1]
        } else {
            0
        };

        let (local_addr, remote_addr) = self.determine_addresses(src_ip, 0, dst_ip, 0, is_outgoing);

        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            Protocol::ICMP,
            local_addr,
            Protocol::ICMP,
            remote_addr
        );

        let state = ProtocolState::Icmp {
            icmp_type,
            icmp_code,
        };

        let conn = self
            .connections
            .entry(conn_key)
            .or_insert_with(|| Connection::new(Protocol::ICMP, local_addr, remote_addr, state));

        // Update connection state
        conn.protocol_state = state;
        conn.last_activity = SystemTime::now();

        // Update statistics
        if is_outgoing {
            conn.packets_sent += 1;
            conn.bytes_sent += data.len() as u64;
        } else {
            conn.packets_received += 1;
            conn.bytes_received += data.len() as u64;
        }

        // Update rates
        conn.update_rates(conn.bytes_sent, conn.bytes_received);

        // Set service name
        set_connection_service_name_for_connection(conn, &self.service_lookup);
    }

    fn process_icmpv6_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        if transport_data.is_empty() {
            return;
        }

        let icmp_type = transport_data[0];
        let icmp_code = if transport_data.len() > 1 {
            transport_data[1]
        } else {
            0
        };

        // ICMPv6 types are different from ICMPv4
        // 128 = Echo Request, 129 = Echo Reply, 1 = Destination Unreachable, 3 = Time Exceeded

        let (local_addr, remote_addr) = self.determine_addresses(src_ip, 0, dst_ip, 0, is_outgoing);

        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            Protocol::ICMP,
            local_addr,
            Protocol::ICMP,
            remote_addr
        );

        let state = ProtocolState::Icmp {
            icmp_type,
            icmp_code,
        };

        let conn = self
            .connections
            .entry(conn_key)
            .or_insert_with(|| Connection::new(Protocol::ICMP, local_addr, remote_addr, state));

        // Rest of the processing is the same as ICMPv4
        conn.protocol_state = state;
        conn.last_activity = SystemTime::now();

        if is_outgoing {
            conn.packets_sent += 1;
            conn.bytes_sent += data.len() as u64;
        } else {
            conn.packets_received += 1;
            conn.bytes_received += data.len() as u64;
        }

        conn.update_rates(conn.bytes_sent, conn.bytes_received);
        set_connection_service_name_for_connection(conn, &self.service_lookup);
    }

    fn process_tcp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        if transport_data.len() < 20 {
            return;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);
        let flags = transport_data[13];

        // Determine TCP state from flags
        let tcp_state = match flags {
            0x02 => TcpState::SynSent,
            0x12 => TcpState::SynReceived,
            0x10 => TcpState::Established,
            0x01 => TcpState::FinWait1,
            0x11 => TcpState::FinWait2,
            0x04 => TcpState::Closed,
            0x14 => TcpState::Closing,
            _ => TcpState::Established,
        };

        let (local_addr, remote_addr) =
            self.determine_addresses(src_ip, src_port, dst_ip, dst_port, is_outgoing);

        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            Protocol::TCP,
            local_addr,
            Protocol::TCP,
            remote_addr
        );

        let state = ProtocolState::Tcp(tcp_state);

        // Extract TCP payload for DPI
        let tcp_header_len = ((transport_data[12] >> 4) as usize) * 4;
        let needs_dpi = if transport_data.len() > tcp_header_len {
            let tcp_payload = &transport_data[tcp_header_len..];
            !tcp_payload.is_empty() && !self.connections.contains_key(&conn_key)
        } else {
            false
        };

        let conn = self
            .connections
            .entry(conn_key.clone())
            .or_insert_with(|| Connection::new(Protocol::TCP, local_addr, remote_addr, state));

        // Update connection state
        conn.protocol_state = state;
        conn.last_activity = SystemTime::now();

        // Update statistics
        if is_outgoing {
            conn.packets_sent += 1;
            conn.bytes_sent += data.len() as u64;
        } else {
            conn.packets_received += 1;
            conn.bytes_received += data.len() as u64;
        }

        // Update rates
        conn.update_rates(conn.bytes_sent, conn.bytes_received);

        // Set service name
        set_connection_service_name_for_connection(conn, &self.service_lookup);

        // Do DPI after releasing the mutable borrow
        if needs_dpi && transport_data.len() > tcp_header_len {
            let tcp_payload = &transport_data[tcp_header_len..];
            self.process_tcp_payload_for_dpi(
                &conn_key,
                tcp_payload,
                local_addr.port(),
                remote_addr.port(),
            );
        }
    }

    fn process_udp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        if transport_data.len() < 8 {
            return;
        }

        let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
        let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

        let (local_addr, remote_addr) =
            self.determine_addresses(src_ip, src_port, dst_ip, dst_port, is_outgoing);

        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            Protocol::UDP,
            local_addr,
            Protocol::UDP,
            remote_addr
        );

        let state = ProtocolState::Udp;

        // Check if we need DPI
        let needs_dpi = if transport_data.len() > 8 {
            let udp_payload = &transport_data[8..];
            !udp_payload.is_empty() && !self.connections.contains_key(&conn_key)
        } else {
            false
        };

        let conn = self
            .connections
            .entry(conn_key.clone())
            .or_insert_with(|| Connection::new(Protocol::UDP, local_addr, remote_addr, state));

        // Update connection
        conn.last_activity = SystemTime::now();

        if is_outgoing {
            conn.packets_sent += 1;
            conn.bytes_sent += data.len() as u64;
        } else {
            conn.packets_received += 1;
            conn.bytes_received += data.len() as u64;
        }

        // Update rates
        conn.update_rates(conn.bytes_sent, conn.bytes_received);

        // Set service name
        set_connection_service_name_for_connection(conn, &self.service_lookup);

        // Do DPI after releasing the mutable borrow
        if needs_dpi && transport_data.len() > 8 {
            let udp_payload = &transport_data[8..];
            self.process_udp_payload_for_dpi(
                &conn_key,
                udp_payload,
                local_addr.port(),
                remote_addr.port(),
            );
        }
    }

    fn process_arp_packet(&mut self, data: &[u8]) {
        let arp_data = &data[14..];
        if arp_data.len() < 28 {
            return;
        }

        // Parse ARP header
        let hardware_type = u16::from_be_bytes([arp_data[0], arp_data[1]]);
        let protocol_type = u16::from_be_bytes([arp_data[2], arp_data[3]]);
        let opcode = u16::from_be_bytes([arp_data[6], arp_data[7]]);

        // We only handle Ethernet (1) and IPv4 (0x0800)
        if hardware_type != 1 || protocol_type != 0x0800 {
            return;
        }

        let sender_ip = IpAddr::from([arp_data[14], arp_data[15], arp_data[16], arp_data[17]]);
        let target_ip = IpAddr::from([arp_data[24], arp_data[25], arp_data[26], arp_data[27]]);

        let operation = match opcode {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            _ => return,
        };

        let is_outgoing = self.local_ips.contains(&sender_ip);
        let (local_addr, remote_addr) = if is_outgoing {
            (SocketAddr::new(sender_ip, 0), SocketAddr::new(target_ip, 0))
        } else {
            (SocketAddr::new(target_ip, 0), SocketAddr::new(sender_ip, 0))
        };

        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            Protocol::ARP,
            local_addr,
            Protocol::ARP,
            remote_addr
        );

        let state = ProtocolState::Arp { operation };

        let conn = self
            .connections
            .entry(conn_key)
            .or_insert_with(|| Connection::new(Protocol::ARP, local_addr, remote_addr, state));

        // Update connection
        conn.protocol_state = state;
        conn.last_activity = SystemTime::now();

        if is_outgoing {
            conn.packets_sent += 1;
            conn.bytes_sent += data.len() as u64;
        } else {
            conn.packets_received += 1;
            conn.bytes_received += data.len() as u64;
        }

        // Update rates
        conn.update_rates(conn.bytes_sent, conn.bytes_received);
    }

    // DPI helper methods
    fn process_tcp_payload_for_dpi(
        &mut self,
        conn_key: &str,
        payload: &[u8],
        local_port: u16,
        remote_port: u16,
    ) {
        if let Some(app_protocol) =
            self.identify_tcp_application_from_payload(payload, local_port, remote_port)
        {
            if let Some(conn) = self.connections.get_mut(conn_key) {
                conn.dpi_info = Some(DpiInfo {
                    application: app_protocol,
                    first_packet_time: Instant::now(),
                    last_update_time: Instant::now(),
                });
            }
        }
    }

    fn process_udp_payload_for_dpi(
        &mut self,
        conn_key: &str,
        payload: &[u8],
        local_port: u16,
        remote_port: u16,
    ) {
        if let Some(app_protocol) =
            self.identify_udp_application_from_payload(payload, local_port, remote_port)
        {
            if let Some(conn) = self.connections.get_mut(conn_key) {
                conn.dpi_info = Some(DpiInfo {
                    application: app_protocol,
                    first_packet_time: Instant::now(),
                    last_update_time: Instant::now(),
                });
            }
        }
    }

    fn identify_tcp_application_from_payload(
        &self,
        payload: &[u8],
        local_port: u16,
        remote_port: u16,
    ) -> Option<ApplicationProtocol> {
        // Check for HTTP/1.x
        if self.is_http_payload(payload) {
            return Some(ApplicationProtocol::Http(self.parse_http_info(payload)));
        }

        // Check for TLS/HTTPS
        if (local_port == 443 || remote_port == 443) || self.is_tls_handshake(payload) {
            if let Some(tls_info) = self.extract_tls_info(payload) {
                return Some(ApplicationProtocol::Https(tls_info));
            }
        }

        // Check for SSH
        if (local_port == 22 || remote_port == 22) || payload.starts_with(b"SSH-") {
            return Some(ApplicationProtocol::Ssh);
        }

        None
    }

    fn identify_udp_application_from_payload(
        &self,
        payload: &[u8],
        local_port: u16,
        remote_port: u16,
    ) -> Option<ApplicationProtocol> {
        // DNS
        if local_port == 53 || remote_port == 53 {
            if let Some(dns_info) = self.parse_dns_packet(payload) {
                return Some(ApplicationProtocol::Dns(dns_info));
            }
        }

        // QUIC/HTTP3
        if (local_port == 443 || remote_port == 443) && self.is_quic_packet(payload) {
            return Some(ApplicationProtocol::Quic);
        }

        None
    }

    // DPI implementation methods
    /// Check if payload looks like HTTP/1.x
    fn is_http_payload(&self, payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }

        // HTTP request methods
        payload.starts_with(b"GET ") ||
        payload.starts_with(b"POST ") ||
        payload.starts_with(b"PUT ") ||
        payload.starts_with(b"DELETE ") ||
        payload.starts_with(b"HEAD ") ||
        payload.starts_with(b"OPTIONS ") ||
        payload.starts_with(b"CONNECT ") ||
        payload.starts_with(b"TRACE ") ||
        payload.starts_with(b"PATCH ") ||
        // HTTP responses
        payload.starts_with(b"HTTP/1.0 ") ||
        payload.starts_with(b"HTTP/1.1 ")
    }

    /// Parse HTTP information from payload
    fn parse_http_info(&self, payload: &[u8]) -> HttpInfo {
        let mut info = HttpInfo {
            version: HttpVersion::Http11, // Default
            method: None,
            host: None,
            path: None,
            status_code: None,
            user_agent: None,
        };

        // Convert to string for easier parsing (only what we can safely convert)
        let text = String::from_utf8_lossy(payload);
        let lines: Vec<&str> = text.lines().collect();

        if lines.is_empty() {
            return info;
        }

        // Parse first line (request or response)
        let first_line = lines[0];
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() >= 3 {
            if first_line.starts_with("HTTP/") {
                // Response line: HTTP/1.1 200 OK
                info.version = if parts[0] == "HTTP/1.0" {
                    HttpVersion::Http10
                } else {
                    HttpVersion::Http11
                };
                info.status_code = parts[1].parse::<u16>().ok();
            } else {
                // Request line: GET /path HTTP/1.1
                info.method = Some(parts[0].to_string());
                info.path = Some(parts[1].to_string());
                info.version = if parts[2] == "HTTP/1.0" {
                    HttpVersion::Http10
                } else {
                    HttpVersion::Http11
                };
            }
        }

        // Parse headers
        for line in lines.iter().skip(1) {
            if line.is_empty() {
                break; // End of headers
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "host" => info.host = Some(value.to_string()),
                    "user-agent" => info.user_agent = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        info
    }

    /// Check if this is a TLS handshake packet
    fn is_tls_handshake(&self, payload: &[u8]) -> bool {
        if payload.len() < 6 {
            return false;
        }

        // TLS record header:
        // - Content type (1 byte): 0x16 for handshake
        // - Version (2 bytes): 0x0301-0x0304 for TLS 1.0-1.3
        // - Length (2 bytes)

        payload[0] == 0x16 && // Handshake content type
        payload[1] == 0x03 && // Major version 3
        (payload[2] >= 0x01 && payload[2] <= 0x04) // Minor version 1-4
    }

    /// Extract TLS information from handshake
    fn extract_tls_info(&self, payload: &[u8]) -> Option<TlsInfo> {
        if !self.is_tls_handshake(payload) || payload.len() < 9 {
            return None;
        }

        let mut info = TlsInfo {
            version: None,
            sni: None,
            alpn: Vec::new(),
            cipher_suite: None,
        };

        // Record layer version
        let record_version = match payload[2] {
            0x01 => Some(TlsVersion::Tls10),
            0x02 => Some(TlsVersion::Tls11),
            0x03 => Some(TlsVersion::Tls12),
            0x04 => Some(TlsVersion::Tls13),
            _ => None,
        };

        // Skip TLS record header (5 bytes)
        let handshake_data = &payload[5..];

        if handshake_data.len() < 4 {
            return Some(info);
        }

        let handshake_type = handshake_data[0];

        match handshake_type {
            0x01 => {
                // Client Hello
                info.version = record_version;
                if let Some((sni, alpn)) = self.parse_client_hello_extensions(handshake_data) {
                    info.sni = sni;
                    info.alpn = alpn;
                }
            }
            0x02 => {
                // Server Hello
                info.version = record_version;
                // Could parse cipher suite here if needed
            }
            _ => {}
        }

        Some(info)
    }

    /// Parse Client Hello extensions for SNI and ALPN
    fn parse_client_hello_extensions(
        &self,
        handshake_data: &[u8],
    ) -> Option<(Option<String>, Vec<String>)> {
        if handshake_data.len() < 38 {
            return None;
        }

        // Skip to extensions:
        // - Handshake type (1) + Length (3) + Version (2) + Random (32) = 38
        let mut offset = 38;

        // Session ID
        if offset >= handshake_data.len() {
            return None;
        }
        let session_id_len = handshake_data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites
        if offset + 2 > handshake_data.len() {
            return None;
        }
        let cipher_suites_len =
            u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
        offset += 2 + cipher_suites_len;

        // Compression methods
        if offset >= handshake_data.len() {
            return None;
        }
        let compression_len = handshake_data[offset] as usize;
        offset += 1 + compression_len;

        // Extensions length
        if offset + 2 > handshake_data.len() {
            return None;
        }
        let extensions_len =
            u16::from_be_bytes([handshake_data[offset], handshake_data[offset + 1]]) as usize;
        offset += 2;

        if offset + extensions_len > handshake_data.len() {
            return None;
        }

        // Parse extensions
        let mut sni = None;
        let mut alpn = Vec::new();
        let extensions_data = &handshake_data[offset..offset + extensions_len];
        let mut ext_offset = 0;

        while ext_offset + 4 <= extensions_data.len() {
            let ext_type =
                u16::from_be_bytes([extensions_data[ext_offset], extensions_data[ext_offset + 1]]);
            let ext_len = u16::from_be_bytes([
                extensions_data[ext_offset + 2],
                extensions_data[ext_offset + 3],
            ]) as usize;

            if ext_offset + 4 + ext_len > extensions_data.len() {
                break;
            }

            match ext_type {
                0x0000 => {
                    // SNI
                    sni = self.parse_sni_extension(
                        &extensions_data[ext_offset + 4..ext_offset + 4 + ext_len],
                    );
                }
                0x0010 => {
                    // ALPN
                    alpn = self.parse_alpn_extension(
                        &extensions_data[ext_offset + 4..ext_offset + 4 + ext_len],
                    );
                }
                _ => {}
            }

            ext_offset += 4 + ext_len;
        }

        Some((sni, alpn))
    }

    /// Parse SNI extension
    fn parse_sni_extension(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // Skip server name list length (2 bytes)
        let mut offset = 2;

        while offset + 3 <= data.len() {
            let name_type = data[offset];
            let name_len = u16::from_be_bytes([data[offset + 1], data[offset + 2]]) as usize;

            if name_type == 0x00 {
                // host_name
                if offset + 3 + name_len <= data.len() {
                    let hostname_bytes = &data[offset + 3..offset + 3 + name_len];
                    if let Ok(hostname) = std::str::from_utf8(hostname_bytes) {
                        return Some(hostname.to_string());
                    }
                }
            }

            offset += 3 + name_len;
        }

        None
    }

    /// Parse ALPN extension
    fn parse_alpn_extension(&self, data: &[u8]) -> Vec<String> {
        let mut protocols = Vec::new();

        if data.len() < 2 {
            return protocols;
        }

        // Skip ALPN extension length
        let mut offset = 2;

        while offset < data.len() {
            let proto_len = data[offset] as usize;
            if offset + 1 + proto_len <= data.len() {
                if let Ok(proto) = std::str::from_utf8(&data[offset + 1..offset + 1 + proto_len]) {
                    protocols.push(proto.to_string());
                }
            }
            offset += 1 + proto_len;
        }

        protocols
    }

    /// Parse DNS packet
    fn parse_dns_packet(&self, payload: &[u8]) -> Option<DnsInfo> {
        if payload.len() < 12 {
            return None;
        }

        let mut info = DnsInfo {
            query_name: None,
            query_type: None,
            response_ips: Vec::new(),
            is_response: false,
        };

        // DNS header flags
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        info.is_response = (flags & 0x8000) != 0; // QR bit

        // Question count
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

        if qdcount > 0 {
            // Parse first question
            let mut offset = 12;
            let mut name = String::new();

            // Parse domain name
            while offset < payload.len() {
                let label_len = payload[offset] as usize;
                if label_len == 0 {
                    offset += 1;
                    break;
                }

                if label_len >= 0xC0 {
                    // Compressed name - skip for simplicity
                    offset += 2;
                    break;
                }

                if offset + 1 + label_len > payload.len() {
                    break;
                }

                if !name.is_empty() {
                    name.push('.');
                }

                if let Ok(label) = std::str::from_utf8(&payload[offset + 1..offset + 1 + label_len])
                {
                    name.push_str(label);
                }

                offset += 1 + label_len;
            }

            if !name.is_empty() {
                info.query_name = Some(name);
            }

            // Query type
            if offset + 2 <= payload.len() {
                let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                info.query_type = Some(match qtype {
                    1 => DnsQueryType::A,
                    28 => DnsQueryType::AAAA,
                    5 => DnsQueryType::CNAME,
                    15 => DnsQueryType::MX,
                    16 => DnsQueryType::TXT,
                    other => DnsQueryType::Other(other),
                });
            }
        }

        Some(info)
    }

    /// Check if this is a QUIC packet
    fn is_quic_packet(&self, payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }

        // Check for QUIC long header (bit 7 set)
        if (payload[0] & 0x80) != 0 {
            // Check version
            let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);

            // Known QUIC versions
            return version == 0x00000001 || // QUIC v1
                   version == 0x6b3343cf || // QUIC v2
                   version == 0x51303530 || // Google QUIC
                   version == 0; // Version negotiation
        }

        // Could be short header QUIC packet
        // These are harder to identify definitively, but if we see them on port 443 UDP,
        // they're likely QUIC
        true
    }

    fn get_connection_key_for_merge(&self, conn: &Connection) -> String {
        format!(
            "{:?}:{}-{:?}:{}",
            conn.protocol, conn.local_addr, conn.protocol, conn.remote_addr
        )
    }
}

fn parse_addr(addr_str: &str) -> Option<std::net::SocketAddr> {
    let addr_str = addr_str.trim();

    if let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() {
        return Some(socket_addr);
    }

    if let Ok(port) = addr_str.parse::<u16>() {
        return Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }

    if let Some(dot_idx) = addr_str.rfind('.') {
        if let Some(socket_addr) = parse_with_separator(addr_str, dot_idx) {
            return Some(socket_addr);
        }
    }

    if let Some(colon_idx) = addr_str.rfind(':') {
        if let Some(socket_addr) = parse_with_separator(addr_str, colon_idx) {
            return Some(socket_addr);
        }
    }

    None
}

fn parse_with_separator(addr_str: &str, sep_idx: usize) -> Option<std::net::SocketAddr> {
    let (host_part, port_part) = addr_str.split_at(sep_idx);
    let port_part = &port_part[1..];

    let host = if host_part.starts_with('[') && host_part.ends_with(']') {
        &host_part[1..host_part.len() - 1]
    } else {
        host_part
    };

    let ip_addr = host.parse::<std::net::IpAddr>().ok()?;
    let port = if port_part == "*" {
        0
    } else {
        port_part.parse::<u16>().ok()?
    };

    Some(std::net::SocketAddr::new(ip_addr, port))
}
