use anyhow::{anyhow, Result};
use log::{error, info};
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    // ICMP, // Variant removed as unused
    // Other(u8), // Variant removed as unused
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            // Protocol::ICMP => write!(f, "ICMP"), // Variant removed
            // Protocol::Other(proto) => write!(f, "Proto({})", proto), // Variant removed
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
    // Closed, // Variant removed as unused
    CloseWait,
    LastAck,
    Listen,
    Closing,
    Reset, // Added Reset variant
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
            // ConnectionState::Closed => write!(f, "CLOSED"), // Variant removed
            ConnectionState::CloseWait => write!(f, "CLOSE_WAIT"),
            ConnectionState::LastAck => write!(f, "LAST_ACK"),
            ConnectionState::Listen => write!(f, "LISTEN"),
            ConnectionState::Closing => write!(f, "CLOSING"),
            ConnectionState::Reset => write!(f, "RESET"),
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
    // pub service_port: Option<u16>, // Field removed as it's unused
    pub service_name: Option<String>,
}

/// Returns the common service name for a given port and protocol.
fn get_service_name_raw(port: u16, protocol: Protocol) -> Option<&'static str> {
    match (protocol, port) {
        (Protocol::TCP, 20) => Some("FTP-Data"),
        (Protocol::TCP, 21) => Some("FTP"),
        (Protocol::TCP, 22) => Some("SSH"),
        (Protocol::TCP, 23) => Some("Telnet"),
        (Protocol::TCP, 25) => Some("SMTP"),
        (Protocol::TCP, 53) => Some("DNS"),
        (Protocol::UDP, 53) => Some("DNS"),
        (Protocol::TCP, 80) => Some("HTTP"),
        (Protocol::TCP, 110) => Some("POP3"),
        (Protocol::UDP, 123) => Some("NTP"),
        (Protocol::TCP, 143) => Some("IMAP"),
        (Protocol::UDP, 161) => Some("SNMP"),
        (Protocol::UDP, 162) => Some("SNMPTRAP"),
        (Protocol::TCP, 389) => Some("LDAP"),
        (Protocol::TCP, 443) => Some("HTTPS"),
        (Protocol::TCP, 465) => Some("SMTPS"), // SMTP over SSL
        (Protocol::TCP, 587) => Some("SMTP"),  // SMTP Submission
        (Protocol::TCP, 636) => Some("LDAPS"),
        (Protocol::TCP, 993) => Some("IMAPS"),
        (Protocol::TCP, 995) => Some("POP3S"),
        // Add more common services as needed
        _ => None,
    }
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
        let mut new_conn = Self {
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
            service_name: None, // Will be set below
        };

        // Determine service name
        let mut determined_service_name_str: Option<&'static str> = None;

        if state == ConnectionState::Listen {
            // For listening sockets, the service is always on the local port
            if let Some(name_str) = get_service_name_raw(local_addr.port(), protocol) {
                determined_service_name_str = Some(name_str);
            }
        } else {
            // For other states, check if local port is a well-known service port
            let local_is_service = local_addr.port() <= 1023 && get_service_name_raw(local_addr.port(), protocol).is_some();
            // Check if remote port is a well-known service port
            let remote_is_service = remote_addr.port() <= 1023 && get_service_name_raw(remote_addr.port(), protocol).is_some();

            if local_is_service {
                // If local port is a service (e.g., running a server), prioritize it
                if let Some(name_str) = get_service_name_raw(local_addr.port(), protocol) {
                    determined_service_name_str = Some(name_str);
                }
            } else if remote_is_service {
                // If local is not a service (or ephemeral) and remote is, then remote defines the service
                if let Some(name_str) = get_service_name_raw(remote_addr.port(), protocol) {
                    determined_service_name_str = Some(name_str);
                }
            }
        }
        
        new_conn.service_name = determined_service_name_str.map(|s| s.to_string());
        new_conn // Return the fully initialized connection
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
    pub command_line: Option<String>,
    pub user: Option<String>,
    pub cpu_usage: Option<f32>,
    pub memory_usage: Option<u64>,
}

// IP location information - struct removed as unused (dependent on get_ip_location)

/// Network monitor
pub struct NetworkMonitor {
    interface: Option<String>,
    capture: Option<Capture<pcap::Active>>,
    connections: HashMap<String, Connection>,
    // geo_db: Option<maxminddb::Reader<Vec<u8>>>, // Field removed as unused (dependent on get_ip_location)
    collect_process_info: bool,
    filter_localhost: bool,
    local_ips: std::collections::HashSet<IpAddr>,
    last_packet_check: Instant,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(interface: Option<String>, filter_localhost: bool) -> Result<Self> {
        let mut capture = if let Some(iface) = &interface {
            // Open capture on specific interface
            let device = Device::list()?
                .into_iter()
                .find(|dev| dev.name == *iface)
                .ok_or_else(|| anyhow!("Interface not found: {}", iface))?;

            info!("Opening capture on interface: {}", iface);
            let cap = Capture::from_device(device)?
                .immediate_mode(true)
                .timeout(0) // Return immediately if no packets are available
                .snaplen(65535)
                .promisc(true)
                .open()?;

            Some(cap)
        } else {
            // Get default interface if none specified
            let device = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;

            info!("Opening capture on default interface: {}", device.name);
            let cap = Capture::from_device(device)?
                .immediate_mode(true)
                .timeout(0) // Return immediately if no packets are available
                .snaplen(65535)
                .promisc(true)
                .open()?;

            Some(cap)
        };

        // Set BPF filter to capture all TCP and UDP traffic
        if let Some(ref mut cap) = capture {
            match cap.filter("tcp or udp", true) {
                Ok(_) => info!("Applied packet filter: tcp or udp"),
                Err(e) => error!("Error setting packet filter: {}", e),
            }
        }

        // Try to load MaxMind database if available - logic removed as geo_db field is removed
        // let geo_db = std::fs::read("GeoLite2-City.mmdb")
        //     .ok()
        //     .map(|data| maxminddb::Reader::from_source(data).ok())
        //     .flatten();

        // if geo_db.is_some() {
        //     info!("Loaded MaxMind GeoIP database");
        // } else {
        //     debug!("MaxMind GeoIP database not found");
        // }

        // Get all local IP addresses
        let mut local_ips = std::collections::HashSet::new();
        let interfaces = pnet_datalink::interfaces();
        for iface in interfaces {
            for ip_network in iface.ips {
                local_ips.insert(ip_network.ip());
            }
        }

        if local_ips.is_empty() {
            log::warn!("Could not determine any local IP addresses. Connection directionality might be inaccurate.");
        } else {
            log::debug!("Found local IPs: {:?}", local_ips);
        }

        Ok(Self {
            interface,
            capture,
            local_ips,
            connections: HashMap::new(),
            // geo_db, // Field removed
            collect_process_info: false,
            filter_localhost,
            // Initialize last_packet_check to a time in the past
            // to ensure the first call to process_packets runs.
            last_packet_check: Instant::now() - Duration::from_millis(200),
        })
    }

    /// Set whether to collect process information for connections
    pub fn set_collect_process_info(&mut self, collect: bool) {
        self.collect_process_info = collect;
    }

    /// Get active connections
    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        // Process packets from capture
        self.process_packets()?;

        // Get connections from system methods
        let mut connections = Vec::new();

        // Use platform-specific code to get connections
        self.get_platform_connections(&mut connections)?;

        // Add connections from packet capture
        for (_, conn) in &self.connections {
            // Check if this connection exists in the list already
            let exists = connections.iter().any(|c| {
                c.protocol == conn.protocol
                    && c.local_addr == conn.local_addr
                    && c.remote_addr == conn.remote_addr
            });

            if !exists && conn.is_active() {
                connections.push(conn.clone());
            }
        }

        // Update with processes only if flag is set
        if self.collect_process_info {
            for conn in &mut connections {
                if conn.pid.is_none() {
                    // Use the platform-specific method
                    if let Some(process) = self.get_platform_process_for_connection(conn) {
                        conn.pid = Some(process.pid);
                        conn.process_name = Some(process.name.clone());
                    }
                }
            }
        }

        // Sort connections by last activity
        connections.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        // Filter localhost connections if the flag is set
        if self.filter_localhost {
            connections.retain(|conn| {
                !(conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback())
            });
        }

        Ok(connections)
    }

    /// Process packets from capture
    fn process_packets(&mut self) -> Result<()> {
        // Only check packets every 100ms to avoid too frequent checks
        if self.last_packet_check.elapsed() < Duration::from_millis(100) {
            return Ok(());
        }
        self.last_packet_check = Instant::now();

        // Define a helper function to process a single packet
        // This avoids the borrowing issues
        // Define a helper function to process a single packet
        // This avoids some borrowing issues with self.local_ips if it were passed directly
        // Instead, we pass the HashMap and the local_ips set.
        let process_single_packet = |data: &[u8],
                                     monitor_connections: &mut HashMap<String, Connection>,
                                     local_ips_set: &std::collections::HashSet<IpAddr>,
                                     _interface: &Option<String>| {
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
                let is_outgoing = local_ips_set.contains(&src_ip);

                match protocol {
                    6 => {
                        // TCP
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
                        let (local_addr, remote_addr) = if is_outgoing {
                            (
                                SocketAddr::new(src_ip, src_port),
                                SocketAddr::new(dst_ip, dst_port),
                            )
                        } else {
                            (
                                SocketAddr::new(dst_ip, dst_port),
                                SocketAddr::new(src_ip, src_port),
                            )
                        };

                        // Create or update connection
                        let conn_key = format!(
                            "{:?}:{}-{:?}:{}",
                            Protocol::TCP,
                            local_addr,
                            Protocol::TCP,
                            remote_addr
                        );

                        if let Some(conn) = monitor_connections.get_mut(&conn_key) {
                            conn.last_activity = SystemTime::now();
                            if is_outgoing {
                                conn.packets_sent += 1;
                                conn.bytes_sent += data.len() as u64;
                            } else {
                                conn.packets_received += 1;
                                conn.bytes_received += data.len() as u64;
                            }
                            conn.state = state;
                        } else {
                            let mut conn =
                                Connection::new(Protocol::TCP, local_addr, remote_addr, state);
                            conn.last_activity = SystemTime::now();
                            if is_outgoing {
                                conn.packets_sent += 1;
                                conn.bytes_sent += data.len() as u64;
                            } else {
                                conn.packets_received += 1;
                                conn.bytes_received += data.len() as u64;
                            }
                            monitor_connections.insert(conn_key, conn);
                        }
                    }
                    17 => {
                        // UDP
                        // Extract ports
                        let src_port = ((transport_data[0] as u16) << 8) | transport_data[1] as u16;
                        let dst_port = ((transport_data[2] as u16) << 8) | transport_data[3] as u16;

                        // Determine local and remote addresses
                        let (local_addr, remote_addr) = if is_outgoing {
                            (
                                SocketAddr::new(src_ip, src_port),
                                SocketAddr::new(dst_ip, dst_port),
                            )
                        } else {
                            (
                                SocketAddr::new(dst_ip, dst_port),
                                SocketAddr::new(src_ip, src_port),
                            )
                        };

                        // Create or update connection
                        let conn_key = format!(
                            "{:?}:{}-{:?}:{}",
                            Protocol::UDP,
                            local_addr,
                            Protocol::UDP,
                            remote_addr
                        );

                        if let Some(conn) = monitor_connections.get_mut(&conn_key) {
                            conn.last_activity = SystemTime::now();
                            if is_outgoing {
                                conn.packets_sent += 1;
                                conn.bytes_sent += data.len() as u64;
                            } else {
                                conn.packets_received += 1;
                                conn.bytes_received += data.len() as u64;
                            }
                        } else {
                            let mut conn = Connection::new(
                                Protocol::UDP,
                                local_addr,
                                remote_addr,
                                ConnectionState::Unknown,
                            );
                            conn.last_activity = SystemTime::now();
                            if is_outgoing {
                                conn.packets_sent += 1;
                                conn.bytes_sent += data.len() as u64;
                            } else {
                                conn.packets_received += 1;
                                conn.bytes_received += data.len() as u64;
                            }
                            monitor_connections.insert(conn_key, conn);
                        }
                    }
                    _ => {} // Ignore other protocols
                }
            };

        // Get packets from the capture
        if let Some(ref mut cap) = self.capture {
            // Process up to 100 packets
            for _ in 0..100 {
                match cap.next_packet() {
                    Ok(packet) => {
                        // Use the local helper function to avoid borrowing issues
                        process_single_packet(packet.data, &mut self.connections, &self.local_ips, &self.interface);
                    }
                    Err(_) => {
                        break; // No more packets or error
                    }
                }
            }
        }

        Ok(())
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
    fn parse_addr(&self, addr_str: &str) -> Option<std::net::SocketAddr> {
        // Handle IPv6 address format [addr]:port
        let addr_str = addr_str.trim();

        // Direct parse attempt
        if let Ok(addr) = addr_str.parse() {
            return Some(addr);
        }

        // Handle common formats
        if addr_str.contains(':') {
            // Try parsing as "addr:port"
            return addr_str.parse().ok();
        } else {
            // If only port is provided, assume 127.0.0.1:port
            if let Ok(port) = addr_str.parse::<u16>() {
                return Some(std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    port,
                ));
            }
        }

        None
    }
}
