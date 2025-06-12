use anyhow::{anyhow, Result};
use log::{debug, error, info, warn}; // Added debug, warn
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::fs::File; // Added for file operations
use std::io::{BufRead, BufReader}; // Added for buffered reading
use std::net::{IpAddr, SocketAddr};
use std::path::Path; // Added for path operations
use std::time::{Duration, Instant, SystemTime};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

#[cfg(target_os = "macos")]
mod macos;

/// Connection protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)] // Added Hash
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    Closed,
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Reset,
    IcmpEchoRequest,
    IcmpEchoReply,
    IcmpDestinationUnreachable,
    IcmpTimeExceeded,
    Unknown,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::SynSent => write!(f, "SYN_SENT"),
            ConnectionState::SynReceived => write!(f, "SYN_RECEIVED"),
            ConnectionState::FinWait1 => write!(f, "FIN_WAIT_1"),
            ConnectionState::FinWait2 => write!(f, "FIN_WAIT_2"),
            ConnectionState::TimeWait => write!(f, "TIME_WAIT"),
            ConnectionState::Closed => write!(f, "CLOSED"),
            ConnectionState::CloseWait => write!(f, "CLOSE_WAIT"),
            ConnectionState::LastAck => write!(f, "LAST_ACK"),
            ConnectionState::Listen => write!(f, "LISTEN"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::Reset => write!(f, "RESET"),
            ConnectionState::IcmpEchoRequest => write!(f, "ICMP_ECHO_REQUEST"),
            ConnectionState::IcmpEchoReply => write!(f, "ICMP_ECHO_REPLY"),
            ConnectionState::IcmpDestinationUnreachable => write!(f, "ICMP_DEST_UNREACH"),
            ConnectionState::IcmpTimeExceeded => write!(f, "ICMP_TIME_EXCEEDED"),
            ConnectionState::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Network connection
#[derive(Debug, Clone)]
pub struct Connection {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub state: ConnectionState,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub service_name: Option<String>,
    pub current_incoming_rate_bps: f64,
    pub current_outgoing_rate_bps: f64,
    pub rate_history: Vec<(Instant, u64, u64)>, // Stores (timestamp, total_bytes_sent, total_bytes_received)
}

impl Connection {
    /// Create a new connection
    pub fn new(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: ConnectionState,
    ) -> Self {
        let now = SystemTime::now();
        let new_conn = Self {
            protocol,
            local_addr,
            remote_addr,
            state,
            pid: None,
            process_name: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            created_at: now,
            last_activity: now,
            service_name: None, // Service name will be set by NetworkMonitor
            current_incoming_rate_bps: 0.0,
            current_outgoing_rate_bps: 0.0,
            rate_history: Vec::new(),
        };
        new_conn
    }

    /// Get connection age as duration
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.created_at)
            .unwrap_or(Duration::from_secs(0))
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.last_activity)
            .unwrap_or(Duration::from_secs(0))
    }

    /// Check if connection is active (had activity in the last minute)
    pub fn is_active(&self) -> bool {
        self.idle_time() < Duration::from_secs(60)
    }
}

/// Process information
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
}

/// Network monitor
pub struct NetworkMonitor {
    interface: Option<String>,
    capture: Option<Capture<pcap::Active>>,
    connections: HashMap<String, Connection>,
    service_lookup: ServiceLookup,
    filter_localhost: bool,
    local_ips: std::collections::HashSet<IpAddr>,
}

/// Manages lookup of service names from a services file.
#[derive(Debug)]
struct ServiceLookup {
    services: HashMap<(u16, Protocol), String>,
}

impl ServiceLookup {
    /// Creates a new ServiceLookup by parsing a services file.
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

            // Split the line into parts. Expecting: name  port/protocol  [aliases...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                debug!("Skipping malformed line in services file: {}", line);
                continue;
            }

            let service_name = parts[0].to_string();
            let port_protocol_str = parts[1];

            // Split port/protocol
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

            let protocol_str = port_protocol_parts[1].to_lowercase();
            let protocol = match protocol_str.as_str() {
                "tcp" => Protocol::TCP,
                "udp" => Protocol::UDP,
                _ => {
                    debug!(
                        "Skipping unknown protocol in services file: {} from line: {}",
                        protocol_str, line
                    );
                    continue;
                }
            };

            // Insert the primary service name. Aliases are ignored for simplicity.
            // If a port/protocol combo is already defined, the first one encountered wins.
            services.entry((port, protocol)).or_insert(service_name);
        }
        debug!(
            "ServiceLookup initialized with {} entries from '{}'",
            services.len(),
            file_path_str
        );
        Ok(Self { services })
    }

    /// Gets the service name for a given port and protocol.
    fn get(&self, port: u16, protocol: Protocol) -> Option<String> {
        self.services.get(&(port, protocol)).cloned()
    }
}

/// Sets the service name for a given connection based on its port and protocol.
/// This function encapsulates the logic for choosing which port (local or remote)
/// determines the service.
fn set_connection_service_name_for_connection(
    conn: &mut Connection,
    service_lookup: &ServiceLookup,
) {
    let local_port = conn.local_addr.port();
    let remote_port = conn.remote_addr.port();
    let protocol = conn.protocol;

    let mut final_service_name: Option<String> = None;

    if conn.state == ConnectionState::Listen {
        // For listening sockets, the service is always on the local port
        final_service_name = service_lookup.get(local_port, protocol);
    } else {
        let local_service_name_opt = service_lookup.get(local_port, protocol);
        if local_service_name_opt.is_some() {
            final_service_name = local_service_name_opt;
        } else {
            // If local port is not a well-known service, check the remote port.
            let remote_service_name_opt = service_lookup.get(remote_port, protocol);
            if remote_service_name_opt.is_some() {
                final_service_name = remote_service_name_opt;
            }
        }
    }
    conn.service_name = final_service_name;
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(interface: Option<String>, filter_localhost: bool) -> Result<Self> {
        log::info!("NetworkMonitor::new - Initializing");
        let mut capture = if let Some(iface) = &interface {
            // Open capture on specific interface
            log::info!(
                "NetworkMonitor::new - Listing devices for specific interface: {}",
                iface
            );
            let device_list = Device::list()?;
            log::info!("NetworkMonitor::new - Device list obtained");
            let device = device_list
                .into_iter()
                .find(|dev| dev.name == *iface)
                .ok_or_else(|| anyhow!("Interface not found: {}", iface))?;

            info!("Opening capture on interface: {}", iface);
            let cap = Capture::from_device(device.clone())? // Clone device as it's used for logging too
                .immediate_mode(true)
                .timeout(0) // Return immediately if no packets are available
                .snaplen(65535)
                .promisc(true)
                .open()?;
            log::info!(
                "NetworkMonitor::new - Capture opened on interface: {}",
                device.name
            );
            Some(cap)
        } else {
            // Get default interface if none specified
            log::info!("NetworkMonitor::new - Looking up default device");
            let device = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;
            log::info!(
                "NetworkMonitor::new - Default device found: {}",
                device.name
            );

            info!("Opening capture on default interface: {}", device.name);
            let cap = Capture::from_device(device.clone())? // Clone device for logging
                .immediate_mode(true)
                .timeout(0) // Return immediately if no packets are available
                .snaplen(65535)
                .promisc(true)
                .open()?;
            log::info!(
                "NetworkMonitor::new - Capture opened on default interface: {}",
                device.name
            );
            Some(cap)
        };

        // Set BPF filter to capture all TCP, UDP and ICMP traffic
        if let Some(ref mut cap) = capture {
            log::info!("NetworkMonitor::new - Applying BPF filter 'tcp or udp or icmp'");
            match cap.filter("tcp or udp or icmp", true) {
                Ok(_) => info!("NetworkMonitor::new - Applied packet filter: tcp or udp or icmp"),
                Err(e) => error!("NetworkMonitor::new - Error setting packet filter: {}", e),
            }
        }

        // Get all local IP addresses
        log::info!("NetworkMonitor::new - Getting local IP addresses using pnet_datalink");
        let mut local_ips = std::collections::HashSet::new();
        let pnet_interfaces = pnet_datalink::interfaces();
        log::info!(
            "NetworkMonitor::new - pnet_datalink::interfaces() returned {} interfaces",
            pnet_interfaces.len()
        );
        for iface in pnet_interfaces {
            for ip_network in iface.ips {
                local_ips.insert(ip_network.ip());
            }
        }

        if local_ips.is_empty() {
            log::warn!("NetworkMonitor::new - Could not determine any local IP addresses. Connection directionality might be inaccurate.");
        } else {
            log::debug!("NetworkMonitor::new - Found local IPs: {:?}", local_ips);
        }

        // Initialize ServiceLookup
        let services_file_path = "assets/services";
        log::info!(
            "NetworkMonitor::new - Attempting to load service definitions from: {}",
            services_file_path
        );
        let service_lookup = match ServiceLookup::new(services_file_path) {
            Ok(sl) => sl,
            Err(e) => {
                error!("NetworkMonitor::new - Failed to load service definitions from '{}': {}. Proceeding without service names.", services_file_path, e);
                // Fallback to an empty ServiceLookup if loading fails
                ServiceLookup {
                    services: HashMap::new(),
                }
            }
        };

        log::info!("NetworkMonitor::new - Initialization complete");
        Ok(Self {
            interface,
            capture,
            local_ips,
            service_lookup,
            connections: HashMap::new(),
            filter_localhost,
        })
    }

    /// Get active connections
    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        log::debug!("NetworkMonitor::get_connections - Starting to fetch connections (without packet processing)");
        // Get connections from system methods (ss, netstat)
        let mut platform_conns_vec = Vec::new();
        log::debug!("NetworkMonitor::get_connections - Attempting to populate platform_conns_vec via get_platform_connections.");
        match self.get_platform_connections(&mut platform_conns_vec) {
            Ok(_) => log::debug!("NetworkMonitor::get_connections - get_platform_connections call completed. platform_conns_vec now has {} entries.", platform_conns_vec.len()),
            Err(e) => {
                log::error!("NetworkMonitor::get_connections - Error from get_platform_connections: {}. platform_conns_vec might be empty or partially filled.", e);
            }
        }
        if platform_conns_vec.is_empty() {
            log::warn!("NetworkMonitor::get_connections - platform_conns_vec is empty after get_platform_connections call.");
        }

        // Use a HashMap to merge, ensuring packet data (especially rate_history) is prioritized.
        // Key: String representation of (protocol, local_addr, remote_addr)
        let mut merged_connections: HashMap<String, Connection> = HashMap::new();

        // 1. Add all connections from packet capture (self.connections HashMap) first.
        //    These have the byte counts and rate_history.
        for (key, packet_conn) in &self.connections {
            // Consider active connections or those also seen by platform tools for merging
            if packet_conn.is_active()
                || platform_conns_vec
                    .iter()
                    .any(|pc| self.get_connection_key_for_merge(pc) == *key)
            {
                merged_connections.insert(key.clone(), packet_conn.clone());
            }
        }
        log::debug!(
            "NetworkMonitor::get_connections - Initial merge map size from packet data: {}",
            merged_connections.len()
        );

        // 2. Iterate through platform connections. If a match is found in merged_connections,
        //    update its state, PID, and process name. If not found, add it.
        for platform_conn in platform_conns_vec {
            let key = self.get_connection_key_for_merge(&platform_conn);
            if let Some(existing_conn) = merged_connections.get_mut(&key) {
                // Connection exists from packet capture (which has rate_history and byte counts).
                // Update it with potentially more accurate state, PID, and process_name from platform tools.
                existing_conn.state = platform_conn.state;
                if platform_conn.pid.is_some() {
                    existing_conn.pid = platform_conn.pid;
                }
                if platform_conn.process_name.is_some() {
                    existing_conn.process_name = platform_conn.process_name;
                }
            } else {
                // Connection only found by platform tools, add it.
                // It will have 0 byte/packet counts and empty rate_history initially,
                // as these are primarily populated by packet capture.
                log::debug!("NetworkMonitor::get_connections - Adding new connection from platform data: {:?}", platform_conn);
                merged_connections.insert(key, platform_conn);
            }
        }
        log::debug!(
            "NetworkMonitor::get_connections - Merge map size after platform data: {}",
            merged_connections.len()
        );

        let mut result_connections: Vec<Connection> = merged_connections.into_values().collect();
        // For connections that might still lack PID/process name (e.g., purely from packets
        // and platform lookup failed before, or purely from platform and it didn't have it),
        // try one more pass of platform-specific PID resolution.
        for conn_mut in &mut result_connections {
            if conn_mut.pid.is_none() {
                if let Some(process_details) = self.get_platform_process_for_connection(conn_mut) {
                    conn_mut.pid = Some(process_details.pid);
                    conn_mut.process_name = Some(process_details.name);
                }
            }
        }

        // Sort connections by last activity (or other criteria as needed)
        result_connections.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        // Filter localhost connections if the flag is set
        if self.filter_localhost {
            result_connections.retain(|conn| {
                !(conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback())
            });
        }

        // Set service names for all connections
        for conn in &mut result_connections {
            set_connection_service_name_for_connection(conn, &self.service_lookup);
        }

        log::info!(
            "NetworkMonitor::get_connections - Finished fetching connections. Total: {}",
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
            (SocketAddr::new(dst_ip, 0), SocketAddr::new(src_ip, 0))
        }
    }

    /// Process packets from capture
    pub fn process_packets(&mut self) -> Result<()> {
        log::debug!("NetworkMonitor::process_packets - Entered process_packets");

        // We need to break this up into a separate helper function that uses owned data to avoid Rust's borrowing issues
        self.process_packets_impl()
    }

    /// Implementation helper for process_packets to avoid borrowing issues
    fn process_packets_impl(&mut self) -> Result<()> {
        // First, gather all the packets into a Vec to avoid borrowing issues
        if self.capture.is_none() {
            log::warn!("NetworkMonitor::process_packets_impl - No capture device available.");
            return Ok(());
        }

        let mut packets_to_process = Vec::new();
        let loop_start_time = Instant::now();

        // Process a moderate number of packets per call to balance responsiveness and data capture
        const MAX_PACKETS_PER_CALL: usize = 100;

        // Collect packets first to avoid borrowing issues
        if let Some(ref mut cap) = self.capture {
            log::debug!("NetworkMonitor::process_packets_impl - Starting packet collection loop");

            for i in 0..MAX_PACKETS_PER_CALL {
                match cap.next_packet() {
                    Ok(packet) => {
                        // Clone the packet data into our Vec
                        packets_to_process.push(packet.data.to_vec());
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // This is expected if timeout(0) is working and no packets are available
                        log::trace!("NetworkMonitor::process_packets_impl - cap.next_packet() timed out (iteration {})", i);
                        break; // No more packets for now, exit loop
                    }
                    Err(e) => {
                        error!("NetworkMonitor::process_packets_impl - Error reading packet (iteration {}): {}", i, e);
                        break; // Error reading packet
                    }
                }
            }
        }

        let packets_count = packets_to_process.len();
        log::debug!(
            "NetworkMonitor::process_packets_impl - Collected {} packets to process",
            packets_count
        );

        // Now process all the collected packets
        for packet_data in packets_to_process {
            self.process_single_packet(&packet_data);
        }

        let loop_duration = loop_start_time.elapsed();
        log::debug!(
            "NetworkMonitor::process_packets_impl - Packet processing finished in {:?}. Processed {} packets.",
            loop_duration,
            packets_count
        );

        Ok(())
    }

    /// Process a single packet
    fn process_single_packet(&mut self, data: &[u8]) {
        // Check if it's an ethernet frame
        if data.len() < 14 {
            return; // Too short for Ethernet
        }

        // Skip Ethernet header (14 bytes) to get to IP header
        let ip_data = &data[14..];

        // Make sure we have enough data for an IP header
        if ip_data.len() < 20 {
            return; // Too short for IP
        }

        // Check if it's IPv4
        let version_ihl = ip_data[0];
        let version = version_ihl >> 4;
        if version != 4 {
            return; // Not IPv4
        }

        // Extract protocol (TCP=6, UDP=17)
        let protocol = ip_data[9];

        // Extract source and destination IP
        let src_ip = IpAddr::from([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
        let dst_ip = IpAddr::from([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);

        // Calculate IP header length
        let ihl = version_ihl & 0x0F;
        let ip_header_len = (ihl as usize) * 4;

        // Skip to TCP/UDP header
        let transport_data = &ip_data[ip_header_len..];
        if transport_data.len() < 8 {
            return; // Too short for TCP/UDP
        }

        // Determine if packet is outgoing based on IP address
        let is_outgoing = self.local_ips.contains(&src_ip);

        match protocol {
            1 => self.process_icmp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            6 => self.process_tcp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            17 => self.process_udp_packet(data, is_outgoing, transport_data, src_ip, dst_ip),
            _ => {} // Ignore other protocols
        }
    }

    /// Process an ICMP packet
    fn process_icmp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        // Extract ICMP type
        let icmp_type = transport_data[0];
        let state = match icmp_type {
            8 => ConnectionState::IcmpEchoRequest,
            0 => ConnectionState::IcmpEchoReply,
            3 => ConnectionState::IcmpDestinationUnreachable,
            11 => ConnectionState::IcmpTimeExceeded,
            _ => ConnectionState::Unknown,
        };

        let (local_addr, remote_addr) = self.determine_addresses(src_ip, 0, dst_ip, 0, is_outgoing);

        // Create or update connection
        let conn_protocol = Protocol::ICMP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        if let Some(conn) = self.connections.get_mut(&conn_key) {
            conn.last_activity = SystemTime::now();
            if is_outgoing {
                conn.packets_sent += 1;
                conn.bytes_sent += data.len() as u64;
            } else {
                conn.packets_received += 1;
                conn.bytes_received += data.len() as u64;
            }
            conn.state = state;
            conn.rate_history
                .push((Instant::now(), conn.bytes_sent, conn.bytes_received));
            // Update service name for existing connection
            set_connection_service_name_for_connection(conn, &self.service_lookup);
        } else {
            let mut new_conn = Connection::new(Protocol::ICMP, local_addr, remote_addr, state);
            new_conn.last_activity = SystemTime::now();
            if is_outgoing {
                new_conn.packets_sent += 1;
                new_conn.bytes_sent += data.len() as u64;
            } else {
                new_conn.packets_received += 1;
                new_conn.bytes_received += data.len() as u64;
            }
            new_conn.rate_history.push((
                Instant::now(),
                new_conn.bytes_sent,
                new_conn.bytes_received,
            ));
            // Set service name for new connection before inserting
            set_connection_service_name_for_connection(&mut new_conn, &self.service_lookup);
            self.connections.insert(conn_key, new_conn);
        }
    }

    /// Process a TCP packet
    fn process_tcp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        if transport_data.len() < 20 {
            return; // Too short for TCP
        }

        // Extract ports
        let src_port = ((transport_data[0] as u16) << 8) | transport_data[1] as u16;
        let dst_port = ((transport_data[2] as u16) << 8) | transport_data[3] as u16;

        // Extract TCP flags
        let flags = transport_data[13];

        // Determine connection state from flags
        let state = match flags {
            0x02 => ConnectionState::SynSent,     // SYN
            0x12 => ConnectionState::SynReceived, // SYN+ACK
            0x10 => ConnectionState::Established, // ACK
            0x01 => ConnectionState::FinWait1,    // FIN
            0x11 => ConnectionState::FinWait2,    // FIN+ACK
            0x04 => ConnectionState::Reset,       // RST
            0x14 => ConnectionState::Closing,     // RST+ACK
            _ => ConnectionState::Established,    // Default to established
        };

        // Determine local and remote addresses
        let (local_addr, remote_addr) =
            self.determine_addresses(src_ip, src_port, dst_ip, dst_port, is_outgoing);

        // Create or update connection
        let conn_protocol = Protocol::TCP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        if let Some(conn) = self.connections.get_mut(&conn_key) {
            conn.last_activity = SystemTime::now();
            if is_outgoing {
                conn.packets_sent += 1;
                conn.bytes_sent += data.len() as u64;
            } else {
                conn.packets_received += 1;
                conn.bytes_received += data.len() as u64;
            }
            conn.state = state;
            conn.rate_history
                .push((Instant::now(), conn.bytes_sent, conn.bytes_received));
            // Update service name for existing connection
            set_connection_service_name_for_connection(conn, &self.service_lookup);
        } else {
            let mut new_conn = Connection::new(Protocol::TCP, local_addr, remote_addr, state);
            new_conn.last_activity = SystemTime::now();
            if is_outgoing {
                new_conn.packets_sent += 1;
                new_conn.bytes_sent += data.len() as u64;
            } else {
                new_conn.packets_received += 1;
                new_conn.bytes_received += data.len() as u64;
            }
            new_conn.rate_history.push((
                Instant::now(),
                new_conn.bytes_sent,
                new_conn.bytes_received,
            ));
            // Set service name for new connection before inserting
            set_connection_service_name_for_connection(&mut new_conn, &self.service_lookup);
            self.connections.insert(conn_key, new_conn);
        }
    }

    /// Process a UDP packet
    fn process_udp_packet(
        &mut self,
        data: &[u8],
        is_outgoing: bool,
        transport_data: &[u8],
        src_ip: IpAddr,
        dst_ip: IpAddr,
    ) {
        // Extract ports
        let src_port = ((transport_data[0] as u16) << 8) | transport_data[1] as u16;
        let dst_port = ((transport_data[2] as u16) << 8) | transport_data[3] as u16;

        // Determine local and remote addresses
        let (local_addr, remote_addr) =
            self.determine_addresses(src_ip, src_port, dst_ip, dst_port, is_outgoing);

        // Create or update connection
        let conn_protocol = Protocol::UDP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        if let Some(conn) = self.connections.get_mut(&conn_key) {
            conn.last_activity = SystemTime::now();
            if is_outgoing {
                conn.packets_sent += 1;
                conn.bytes_sent += data.len() as u64;
            } else {
                conn.packets_received += 1;
                conn.bytes_received += data.len() as u64;
            }
            conn.rate_history
                .push((Instant::now(), conn.bytes_sent, conn.bytes_received));
            // Update service name for existing connection
            set_connection_service_name_for_connection(conn, &self.service_lookup);
        } else {
            let mut new_conn = Connection::new(
                Protocol::UDP,
                local_addr,
                remote_addr,
                ConnectionState::Unknown,
            );
            new_conn.last_activity = SystemTime::now();
            if is_outgoing {
                new_conn.packets_sent += 1;
                new_conn.bytes_sent += data.len() as u64;
            } else {
                new_conn.packets_received += 1;
                new_conn.bytes_received += data.len() as u64;
            }
            new_conn.rate_history.push((
                Instant::now(),
                new_conn.bytes_sent,
                new_conn.bytes_received,
            ));
            // Set service name for new connection before inserting
            set_connection_service_name_for_connection(&mut new_conn, &self.service_lookup);
            self.connections.insert(conn_key, new_conn);
        }
    }

    /// We don't need this method anymore since packet processing is done inline
    // fn process_packet(&mut self, packet: Packet) { ... }

    /// Get platform-specific process for a connection
    pub fn get_platform_process_for_connection(&self, connection: &Connection) -> Option<Process> {
        #[cfg(target_os = "linux")]
        {
            return self.get_linux_process_for_connection(connection);
        }
        #[cfg(target_os = "macos")]
        {
            // Try lsof first (more detailed)
            if let Some(process) = macos::try_lsof_command(connection) {
                return Some(process);
            }
            // Fall back to netstat (limited on macOS)
            return macos::try_netstat_command(connection);
        }
        #[cfg(target_os = "windows")]
        {
            // Try netstat
            if let Some(process) = windows::try_netstat_command(connection) {
                return Some(process);
            }
            // Fall back to API calls if we implement them
            return windows::try_windows_api(connection);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    /// Get platform-specific connections
    fn get_platform_connections(&mut self, connections: &mut Vec<Connection>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            // Use Linux-specific implementation
            linux::get_platform_connections(self, connections)?;
        }
        #[cfg(target_os = "macos")]
        {
            // Use macOS-specific implementation
            macos::get_platform_connections(self, connections)?;
        }
        #[cfg(target_os = "windows")]
        {
            // Use Windows-specific implementation
            windows::get_platform_connections(self, connections)?;
        }

        Ok(())
    }

    /// Parse an address string into a SocketAddr
    /// Helper to generate a consistent key for merging connections.
    /// This key should match the one used for `self.connections` HashMap.
    fn get_connection_key_for_merge(&self, conn: &Connection) -> String {
        format!(
            "{:?}:{}-{:?}:{}",
            conn.protocol, conn.local_addr, conn.protocol, conn.remote_addr
        )
    }
}
/// Parse an address string into a SocketAddr
fn parse_addr(addr_str: &str) -> Option<std::net::SocketAddr> {
    let addr_str = addr_str.trim();

    // 1. Try standard "host:port" or "[ipv6]:port" format
    if let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() {
        return Some(socket_addr);
    }

    // 2. Try to handle port-only case (for localhost)
    if let Ok(port) = addr_str.parse::<u16>() {
        return Some(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
        ));
    }

    // 3. Handle "ip.port" format (dot notation)
    if let Some(dot_idx) = addr_str.rfind('.') {
        if let Some(socket_addr) = parse_with_separator(addr_str, dot_idx) {
            return Some(socket_addr);
        }
    }

    // 4. Handle "host:port" format with special port handling
    if let Some(colon_idx) = addr_str.rfind(':') {
        if let Some(socket_addr) = parse_with_separator(addr_str, colon_idx) {
            return Some(socket_addr);
        }
    }

    None
}

/// Helper method to parse address with either dot or colon separator
fn parse_with_separator(addr_str: &str, sep_idx: usize) -> Option<std::net::SocketAddr> {
    let (host_part, port_part) = addr_str.split_at(sep_idx);
    // Skip the separator character
    let port_part = &port_part[1..];

    // Extract host, handling possible IPv6 brackets
    let host = if host_part.starts_with('[') && host_part.ends_with(']') {
        &host_part[1..host_part.len() - 1]
    } else {
        host_part
    };

    // Parse the host to an IP address
    let ip_addr = host.parse::<std::net::IpAddr>().ok()?;

    // Parse the port, handling wildcard "*"
    let port = if port_part == "*" {
        0 // Map wildcard port to 0
    } else {
        port_part.parse::<u16>().ok()?
    };

    Some(std::net::SocketAddr::new(ip_addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_parse_addr() {
        // Create an instance of NetworkMonitor to test its methods
        // Table of test cases: (input, expected_output)
        let test_cases = [
            // Standard IPv4
            (
                "192.168.1.1:80",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    80,
                )),
            ),
            // Standard IPv6
            (
                "[::1]:8080",
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    8080,
                )),
            ),
            // Port only
            (
                "8080",
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)),
            ),
            // Wrong dot notation
            ("192.168.1.80", None),
            // Correct dot notation
            (
                "192.168.1.80.80",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 80)),
                    80,
                )),
            ),
            // Wildcard port
            (
                "192.168.1.1:*",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    0,
                )),
            ),
            // Wildcard dot notation is not valid
            ("192.168.1.*", None),
            // With whitespace
            (
                " 192.168.1.1:80 ",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    80,
                )),
            ),
            // Invalid inputs
            ("invalid", None),
            ("256.256.256.256:80", None),
            ("192.168.1.1:99999", None),
        ];

        for (input, expected) in test_cases {
            let result = parse_addr(input);
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }
}
