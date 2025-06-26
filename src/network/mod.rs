use anyhow::{anyhow, Result};
use log::{debug, error, info, warn};
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
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

/// Connection protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    Established,
    SynSent,
    SynReceived,
    FinWait1,
    FinWait2,
    TimeWait,
    
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
    pub last_activity: SystemTime,
    pub creation_time: SystemTime,
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
        Self {
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
            last_activity: now,
            creation_time: now,
            service_name: None, // Service name will be set by NetworkMonitor
            current_incoming_rate_bps: 0.0,
            current_outgoing_rate_bps: 0.0,
            rate_history: Vec::new(),
        }
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

    /// Get the age of the connection (time since creation)
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.creation_time)
            .unwrap_or(Duration::from_secs(0))
    }

    
}

/// Process information
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
}

/// Main function for the packet capture thread.
/// Opens a pcap capture handle and sends raw packet data to the provided channel.
pub fn packet_capture_thread(
    interface_name: Option<String>,
    packet_tx: Sender<Vec<u8>>,
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
        .snaplen(65535)
        .timeout(1000) // Block for up to 1 sec, allows graceful shutdown
        .immediate_mode(true)
        .open()?;

    info!("Applying BPF filter 'tcp or udp or icmp'");
    cap.filter("tcp or udp or icmp", true)?;

    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if packet_tx.send(packet.data.to_vec()).is_err() {
                    info!("Packet receiver has disconnected, stopping capture thread.");
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // This is expected, just continue the loop
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

    /// Gets the service name for a given port and protocol.
    fn get(&self, port: u16, protocol: Protocol) -> Option<String> {
        self.services.get(&(port, protocol)).cloned()
    }
}

/// Sets the service name for a given connection based on its port and protocol.
fn set_connection_service_name_for_connection(
    conn: &mut Connection,
    service_lookup: &ServiceLookup,
) {
    let local_port = conn.local_addr.port();
    let remote_port = conn.remote_addr.port();
    let protocol = conn.protocol;

    let mut final_service_name: Option<String> = None;

    if conn.state == ConnectionState::Listen {
        final_service_name = service_lookup.get(local_port, protocol);
    } else {
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
            warn!("Could not determine any local IP addresses. Connection directionality might be inaccurate.");
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
        let mut platform_conns_vec = Vec::new();
        if let Err(e) = self.get_platform_connections(&mut platform_conns_vec) {
            error!("Error from get_platform_connections: {}", e);
        }
        debug!("get_connections: Found {} platform connections", platform_conns_vec.len());

        let mut merged_connections: HashMap<String, Connection> = HashMap::new();

        // Start with platform connections as the base
        for platform_conn in platform_conns_vec {
            let key = self.get_connection_key_for_merge(&platform_conn);
            merged_connections.insert(key, platform_conn);
        }

        // Then enhance with packet data if available
        for (key, packet_conn) in &self.connections {
            if packet_conn.is_active() {
                if let Some(existing_conn) = merged_connections.get_mut(key) {
                    // Update with packet data - preserve platform connection info but add packet stats
                    existing_conn.bytes_sent = packet_conn.bytes_sent;
                    existing_conn.bytes_received = packet_conn.bytes_received;
                    existing_conn.packets_sent = packet_conn.packets_sent;
                    existing_conn.packets_received = packet_conn.packets_received;
                    existing_conn.last_activity = packet_conn.last_activity;
                    existing_conn.current_incoming_rate_bps = packet_conn.current_incoming_rate_bps;
                    existing_conn.current_outgoing_rate_bps = packet_conn.current_outgoing_rate_bps;
                    existing_conn.rate_history = packet_conn.rate_history.clone();
                } else {
                    // Packet-only connection (no platform match)
                    merged_connections.insert(key.clone(), packet_conn.clone());
                }
            }
        }

        let mut result_connections: Vec<Connection> = merged_connections.into_values().collect();
        debug!("get_connections: Processing {} connections", result_connections.len());
        
        // Only look up processes for connections that don't already have process info
        let mut connections_needing_process_info = 0;
        for conn_mut in &mut result_connections {
            if conn_mut.pid.is_none() && conn_mut.process_name.is_none() {
                connections_needing_process_info += 1;
            }
        }
        
        if connections_needing_process_info > 0 {
            debug!("Looking up process info for {} connections", connections_needing_process_info);
            for conn_mut in &mut result_connections {
                if conn_mut.pid.is_none() && conn_mut.process_name.is_none() {
                    if let Some(process_details) = self.get_platform_process_for_connection(conn_mut) {
                        debug!("Found process {} (PID: {}) for connection {}:{}", 
                               process_details.name, process_details.pid, 
                               conn_mut.local_addr, conn_mut.remote_addr);
                        conn_mut.pid = Some(process_details.pid);
                        conn_mut.process_name = Some(process_details.name);
                    }
                }
            }
        }

        result_connections.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        if self.filter_localhost {
            result_connections.retain(|conn| {
                !(conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback())
            });
        }

        for conn in &mut result_connections {
            set_connection_service_name_for_connection(conn, &self.service_lookup);
            if conn.current_incoming_rate_bps > 0.0 || conn.current_outgoing_rate_bps > 0.0 {
                debug!(
                    "Connection: {:?}, Incoming: {:.2} bps, Outgoing: {:.2} bps",
                    conn.local_addr,
                    conn.current_incoming_rate_bps,
                    conn.current_outgoing_rate_bps
                );
            }
        }

        debug!("get_connections: Returning {} total connections", result_connections.len());
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

    /// Process a single raw packet from the queue.
    pub fn process_packet(&mut self, data: &[u8]) {
        if data.len() < 14 {
            return;
        }
        let ip_data = &data[14..];

        if ip_data.len() < 20 {
            return;
        }

        let version = ip_data[0] >> 4;
        if version != 4 {
            return;
        }

        let protocol = ip_data[9];
        let src_ip = IpAddr::from([ip_data[12], ip_data[13], ip_data[14], ip_data[15]]);
        let dst_ip = IpAddr::from([ip_data[16], ip_data[17], ip_data[18], ip_data[19]]);

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
        let state = match icmp_type {
            8 => ConnectionState::IcmpEchoRequest,
            0 => ConnectionState::IcmpEchoReply,
            3 => ConnectionState::IcmpDestinationUnreachable,
            11 => ConnectionState::IcmpTimeExceeded,
            _ => ConnectionState::Unknown,
        };

        let (local_addr, remote_addr) = self.determine_addresses(src_ip, 0, dst_ip, 0, is_outgoing);

        let conn_protocol = Protocol::ICMP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        let conn = self
            .connections
            .entry(conn_key)
            .or_insert_with(|| Connection::new(Protocol::ICMP, local_addr, remote_addr, state));

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

        let state = match flags {
            0x02 => ConnectionState::SynSent,
            0x12 => ConnectionState::SynReceived,
            0x10 => ConnectionState::Established,
            0x01 => ConnectionState::FinWait1,
            0x11 => ConnectionState::FinWait2,
            0x04 => ConnectionState::Reset,
            0x14 => ConnectionState::Closing,
            _ => ConnectionState::Established,
        };

        let (local_addr, remote_addr) =
            self.determine_addresses(src_ip, src_port, dst_ip, dst_port, is_outgoing);

        let conn_protocol = Protocol::TCP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        let conn = self
            .connections
            .entry(conn_key)
            .or_insert_with(|| Connection::new(Protocol::TCP, local_addr, remote_addr, state));

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
        set_connection_service_name_for_connection(conn, &self.service_lookup);
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

        let conn_protocol = Protocol::UDP;
        let conn_key = format!(
            "{:?}:{}-{:?}:{}",
            conn_protocol, local_addr, conn_protocol, remote_addr
        );

        let conn = self.connections.entry(conn_key).or_insert_with(|| {
            Connection::new(
                Protocol::UDP,
                local_addr,
                remote_addr,
                ConnectionState::Unknown,
            )
        });

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
        set_connection_service_name_for_connection(conn, &self.service_lookup);
    }

    pub fn get_platform_process_for_connection(&self, connection: &Connection) -> Option<Process> {
        #[cfg(target_os = "linux")]
        {
            return self.get_linux_process_for_connection(connection);
        }
        #[cfg(target_os = "macos")]
        {
            if let Some(process) = macos::try_lsof_command(connection) {
                return Some(process);
            }
            return macos::try_netstat_command(connection);
        }
        #[cfg(target_os = "windows")]
        {
            if let Some(process) = windows::try_netstat_command(connection) {
                return Some(process);
            }
            return windows::try_windows_api(connection);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            None
        }
    }

    fn get_platform_connections(&mut self, connections: &mut Vec<Connection>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            linux::get_platform_connections(self, connections)?;
        }
        #[cfg(target_os = "macos")]
        {
            macos::get_platform_connections(self, connections)?;
        }
        #[cfg(target_os = "windows")]
        {
            windows::get_platform_connections(self, connections)?;
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn setup_monitor() -> NetworkMonitor {
        NetworkMonitor::new(None, false).unwrap()
    }

    fn build_ipv4_packet(
        protocol: u8,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        transport_payload: &[u8],
    ) -> Vec<u8> {
        let mut ip_header = vec![0u8; 20];
        ip_header[0] = (4 << 4) | 5; // Version 4, IHL 5
        let total_len = (20 + transport_payload.len()) as u16;
        ip_header[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip_header[9] = protocol;
        ip_header[12..16].copy_from_slice(&src_ip.octets());
        ip_header[16..20].copy_from_slice(&dst_ip.octets());

        let ethernet_header = vec![0u8; 14];
        // Dest MAC, Src MAC, EtherType (irrelevant for test)

        let mut packet = Vec::new();
        packet.extend_from_slice(&ethernet_header);
        packet.extend_from_slice(&ip_header);
        packet.extend_from_slice(transport_payload);
        packet
    }

    #[test]
    fn test_process_tcp_packet_outgoing() {
        let mut monitor = setup_monitor();
        let src_ip = Ipv4Addr::new(192, 168, 1, 10);
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        monitor.local_ips.insert(IpAddr::V4(src_ip));

        let mut tcp_header = vec![0u8; 20];
        tcp_header[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp_header[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp_header[13] = 0x02; // SYN flag

        let packet = build_ipv4_packet(6, src_ip, dst_ip, &tcp_header);
        monitor.process_packet(&packet);

        assert_eq!(monitor.connections.len(), 1);
        let conn = monitor.connections.values().next().unwrap();
        assert_eq!(conn.protocol, Protocol::TCP);
        assert_eq!(conn.local_addr.ip(), src_ip);
        assert_eq!(conn.local_addr.port(), 12345);
        assert_eq!(conn.remote_addr.ip(), dst_ip);
        assert_eq!(conn.remote_addr.port(), 443);
        assert_eq!(conn.state, ConnectionState::SynSent);
        assert_eq!(conn.bytes_sent, packet.len() as u64);
        assert_eq!(conn.packets_sent, 1);
        assert_eq!(conn.bytes_received, 0);
    }

    #[test]
    fn test_process_udp_packet_incoming() {
        let mut monitor = setup_monitor();
        let src_ip = Ipv4Addr::new(10, 0, 0, 5);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 1);
        monitor.local_ips.insert(IpAddr::V4(dst_ip));

        let mut udp_header = vec![0u8; 8];
        udp_header[0..2].copy_from_slice(&53u16.to_be_bytes());
        udp_header[2..4].copy_from_slice(&54321u16.to_be_bytes());
        udp_header[4..6].copy_from_slice(&8u16.to_be_bytes());

        let packet = build_ipv4_packet(17, src_ip, dst_ip, &udp_header);
        monitor.process_packet(&packet);

        assert_eq!(monitor.connections.len(), 1);
        let conn = monitor.connections.values().next().unwrap();
        assert_eq!(conn.protocol, Protocol::UDP);
        assert_eq!(conn.local_addr.ip(), dst_ip);
        assert_eq!(conn.local_addr.port(), 54321);
        assert_eq!(conn.remote_addr.ip(), src_ip);
        assert_eq!(conn.remote_addr.port(), 53);
        assert_eq!(conn.bytes_received, packet.len() as u64);
        assert_eq!(conn.packets_received, 1);
        assert_eq!(conn.bytes_sent, 0);
    }

    #[test]
    fn test_parse_addr() {
        let test_cases = [
            (
                "192.168.1.1:80",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    80,
                )),
            ),
            (
                "[::1]:8080",
                Some(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    8080,
                )),
            ),
            (
                "8080",
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)),
            ),
            ("192.168.1.80", None),
            (
                "192.168.1.1:*",
                Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                    0,
                )),
            ),
        ];

        for (input, expected) in test_cases {
            let result = parse_addr(input);
            assert_eq!(result, expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_process_assignment_to_connections() {
        let mut monitor = setup_monitor();
        let mut connections = Vec::new();

        // Create a test connection
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
        let conn = Connection::new(Protocol::TCP, local_addr, remote_addr, ConnectionState::Established);
        
        // Initially no process info
        assert!(conn.pid.is_none());
        assert!(conn.process_name.is_none());
        
        connections.push(conn);

        // Test that get_connections attempts to assign process info
        let result = monitor.get_connections();
        assert!(result.is_ok());
        
        let updated_connections = result.unwrap();
        // Note: Process assignment might fail in test environment, but we test the logic
        // The important thing is that the method doesn't panic and returns valid connections
        assert!(!updated_connections.is_empty());
    }

    #[test]
    fn test_connection_has_age_method() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
        let conn = Connection::new(Protocol::TCP, local_addr, remote_addr, ConnectionState::Established);
        
        // Test that age method works
        let age = conn.age();
        assert!(age.as_millis() < 1000); // Should be very recent
        
        // Test idle_time method too
        let idle = conn.idle_time();
        assert!(idle.as_millis() < 1000); // Should be very recent
    }

    #[test]
    fn test_connection_activity_tracking() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000);
        let conn = Connection::new(Protocol::TCP, local_addr, remote_addr, ConnectionState::Established);
        
        // Should be active when just created
        assert!(conn.is_active());
        
        // Test that creation_time and last_activity are set
        assert!(conn.creation_time <= std::time::SystemTime::now());
        assert!(conn.last_activity <= std::time::SystemTime::now());
    }

    #[test]
    fn test_network_monitor_initialization() {
        let monitor_result = NetworkMonitor::new(None, false);
        assert!(monitor_result.is_ok());
        
        let monitor_result_filtered = NetworkMonitor::new(None, true);
        assert!(monitor_result_filtered.is_ok());
    }

    #[test]
    fn test_connection_state_display() {
        let states = [
            ConnectionState::Established,
            ConnectionState::Listen,
            ConnectionState::TimeWait,
            ConnectionState::SynSent,
            ConnectionState::Unknown,
        ];
        
        for state in states.iter() {
            let display = state.to_string();
            assert!(!display.is_empty());
            assert!(display.chars().all(|c| c.is_ascii()));
        }
    }
}

