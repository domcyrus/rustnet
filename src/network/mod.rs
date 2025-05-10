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
    pub service_name: Option<String>,
    // Fields for current rate calculation
    pub prev_bytes_sent: u64, // Still used by NetworkMonitor for cumulative tracking if needed elsewhere
    pub prev_bytes_received: u64, // Still used by NetworkMonitor for cumulative tracking if needed elsewhere
    pub last_rate_update_time: Instant, // Still used by NetworkMonitor for cumulative tracking if needed elsewhere
    pub current_incoming_rate_bps: f64,
    pub current_outgoing_rate_bps: f64,
    pub rate_history: Vec<(Instant, u64, u64)>, // Stores (timestamp, total_bytes_sent, total_bytes_received)
}

// get_service_name_raw function is removed.

impl Connection {
    /// Create a new connection
    pub fn new(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: ConnectionState,
    ) -> Self {
        let now = SystemTime::now();
        let new_conn = Self { // Removed mut
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
            // Initialize new fields for rate calculation
            prev_bytes_sent: 0,
            prev_bytes_received: 0,
            last_rate_update_time: Instant::now(),
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
    // pub command_line: Option<String>, // Field removed as unused
    // pub user: Option<String>, // Field removed as unused
    // pub cpu_usage: Option<f32>, // Field removed as unused
    // pub memory_usage: Option<u64>, // Field removed as unused
}

// IP location information - struct removed as unused (dependent on get_ip_location)

/// Network monitor
pub struct NetworkMonitor {
    interface: Option<String>,
    capture: Option<Capture<pcap::Active>>,
    connections: HashMap<String, Connection>,
    // geo_db: Option<maxminddb::Reader<Vec<u8>>>, // Field removed as unused (dependent on get_ip_location)
    service_lookup: ServiceLookup, // Added ServiceLookup
    // collect_process_info: bool, // Removed, App will manage process info fetching
    filter_localhost: bool,
    local_ips: std::collections::HashSet<IpAddr>,
    // last_packet_check: Instant, // Removed for continuous processing by default
    // initial_packet_processing_done: bool, // Removed
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
            warn!("Service definition file not found at '{}'. Service names will not be available.", file_path_str);
            return Ok(Self { services }); // Return empty lookup if file not found
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
                debug!("Skipping malformed port/protocol in services file: {} from line: {}", port_protocol_str, line);
                continue;
            }

            let port = match port_protocol_parts[0].parse::<u16>() {
                Ok(p) => p,
                Err(_) => {
                    debug!("Skipping invalid port in services file: {} from line: {}", port_protocol_parts[0], line);
                    continue;
                }
            };

            let protocol_str = port_protocol_parts[1].to_lowercase();
            let protocol = match protocol_str.as_str() {
                "tcp" => Protocol::TCP,
                "udp" => Protocol::UDP,
                _ => {
                    debug!("Skipping unknown protocol in services file: {} from line: {}", protocol_str, line);
                    continue;
                }
            };

            // Insert the primary service name. Aliases are ignored for simplicity.
            // If a port/protocol combo is already defined, the first one encountered wins.
            services.entry((port, protocol)).or_insert(service_name);
        }
        debug!("ServiceLookup initialized with {} entries from '{}'", services.len(), file_path_str);
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
fn set_connection_service_name_for_connection(conn: &mut Connection, service_lookup: &ServiceLookup) {
    let local_port = conn.local_addr.port();
    let remote_port = conn.remote_addr.port();
    let protocol = conn.protocol;

    let mut final_service_name: Option<String> = None;

    if conn.state == ConnectionState::Listen {
        // For listening sockets, the service is always on the local port
        final_service_name = service_lookup.get(local_port, protocol);
    } else {
        // For other states, check if local port is a well-known service port
        // and has a known service name.
        let local_service_name_opt = service_lookup.get(local_port, protocol);
        let local_is_well_known_port = local_port <= 1023; // Standard service port range
        
        if local_is_well_known_port && local_service_name_opt.is_some() {
            final_service_name = local_service_name_opt;
        } else {
            // If local port is not a well-known service, check the remote port.
            let remote_service_name_opt = service_lookup.get(remote_port, protocol);
            let remote_is_well_known_port = remote_port <= 1023;

            if remote_is_well_known_port && remote_service_name_opt.is_some() {
                final_service_name = remote_service_name_opt;
            }
            // If neither are "well-known services" on standard ports with known names,
            // the service name remains None, matching the original logic's strictness.
            // More sophisticated heuristics (e.g. for non-standard ports) could be added here if desired.
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
            log::info!("NetworkMonitor::new - Listing devices for specific interface: {}", iface);
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
            log::info!("NetworkMonitor::new - Capture opened on interface: {}", device.name);
            Some(cap)
        } else {
            // Get default interface if none specified
            log::info!("NetworkMonitor::new - Looking up default device");
            let device = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;
            log::info!("NetworkMonitor::new - Default device found: {}", device.name);

            info!("Opening capture on default interface: {}", device.name);
            let cap = Capture::from_device(device.clone())? // Clone device for logging
                .immediate_mode(true)
                .timeout(0) // Return immediately if no packets are available
                .snaplen(65535)
                .promisc(true)
                .open()?;
            log::info!("NetworkMonitor::new - Capture opened on default interface: {}", device.name);
            Some(cap)
        };

        // Set BPF filter to capture all TCP and UDP traffic
        if let Some(ref mut cap) = capture {
            log::info!("NetworkMonitor::new - Applying BPF filter 'tcp or udp'");
            match cap.filter("tcp or udp", true) {
                Ok(_) => info!("NetworkMonitor::new - Applied packet filter: tcp or udp"),
                Err(e) => error!("NetworkMonitor::new - Error setting packet filter: {}", e),
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
        log::info!("NetworkMonitor::new - Getting local IP addresses using pnet_datalink");
        let mut local_ips = std::collections::HashSet::new();
        let pnet_interfaces = pnet_datalink::interfaces();
        log::info!("NetworkMonitor::new - pnet_datalink::interfaces() returned {} interfaces", pnet_interfaces.len());
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
        // TODO: Consider making the path configurable, e.g., via Config struct or environment variable.
        let services_file_path = "assets/services";
        log::info!("NetworkMonitor::new - Attempting to load service definitions from: {}", services_file_path);
        let service_lookup = match ServiceLookup::new(services_file_path) {
            Ok(sl) => sl,
            Err(e) => {
                error!("NetworkMonitor::new - Failed to load service definitions from '{}': {}. Proceeding without service names.", services_file_path, e);
                // Fallback to an empty ServiceLookup if loading fails
                ServiceLookup { services: HashMap::new() }
            }
        };


        log::info!("NetworkMonitor::new - Initialization complete");
        Ok(Self {
            interface,
            capture,
            local_ips,
            service_lookup, // Added service_lookup
            connections: HashMap::new(),
            // geo_db, // Field removed
            // collect_process_info: false, // Removed
            filter_localhost,
            // last_packet_check and initial_packet_processing_done removed
        })
    }

    // set_collect_process_info method removed

    /// Get active connections
    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        log::debug!("NetworkMonitor::get_connections - Starting to fetch connections (without packet processing)");
        // Packet processing is now handled externally.

        // Get connections from system methods
        let mut connections = Vec::new();

        // Use platform-specific code to get connections
        log::debug!("NetworkMonitor::get_connections - Calling get_platform_connections");
        self.get_platform_connections(&mut connections)?;
        log::debug!("NetworkMonitor::get_connections - get_platform_connections returned {} connections", connections.len());

        // Add connections from packet capture
        log::debug!("NetworkMonitor::get_connections - Merging packet capture connections (current count: {})", self.connections.len());
        let mut packet_conn_updates: Vec<(String, u32, String)> = Vec::new();

        for (key, conn_from_packets) in &self.connections {
            // Check if this connection exists in the list already (from platform tools)
            let exists_in_platform_list = connections.iter().any(|c_plat| {
                c_plat.protocol == conn_from_packets.protocol
                    && c_plat.local_addr == conn_from_packets.local_addr
                    && c_plat.remote_addr == conn_from_packets.remote_addr
            });

            if !exists_in_platform_list && conn_from_packets.is_active() {
                let mut conn_to_add_to_results = conn_from_packets.clone();
                
                // If packet-captured connection doesn't have a PID yet, try to resolve it.
                if conn_to_add_to_results.pid.is_none() {
                    if let Some(process_details) = self.get_platform_process_for_connection(&conn_to_add_to_results) {
                        conn_to_add_to_results.pid = Some(process_details.pid);
                        conn_to_add_to_results.process_name = Some(process_details.name.clone());
                        // Mark this key for PID and name update in self.connections (the HashMap)
                        packet_conn_updates.push((key.clone(), process_details.pid, process_details.name.clone()));
                    }
                }
                connections.push(conn_to_add_to_results);
            }
        }
        
        // Update PIDs and names in self.connections (the HashMap) for packet-only connections where details were just found
        for (key, pid_to_set, name_to_set) in packet_conn_updates {
            if let Some(conn_in_map) = self.connections.get_mut(&key) {
                conn_in_map.pid = Some(pid_to_set);
                conn_in_map.process_name = Some(name_to_set);
            }
        }

        // Process information fetching is now handled by App::on_tick to allow for lazy loading.
        // The self.collect_process_info flag and related block are removed from here.

        // Sort connections by last activity
        connections.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

        // Filter localhost connections if the flag is set
        if self.filter_localhost {
            connections.retain(|conn| {
                !(conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback())
            });
        }

        // Set service names for all connections
        for conn in &mut connections {
            set_connection_service_name_for_connection(conn, &self.service_lookup);
        }

        log::info!("NetworkMonitor::get_connections - Finished fetching connections. Total: {}", connections.len());
        Ok(connections)
    }

// Moved set_connection_service_name to be a free function to avoid borrow checker issues in process_packets.

    /// Process packets from capture
    pub fn process_packets(&mut self) -> Result<()> {
        log::debug!("NetworkMonitor::process_packets - Entered process_packets");

        // Define a helper function to process a single packet
        // This avoids some borrowing issues with self.local_ips if it were passed directly
        // Instead, we pass the HashMap, the local_ips set, and the service_lookup.
        let process_single_packet = |data: &[u8],
                                     monitor_connections: &mut HashMap<String, Connection>,
                                     local_ips_set: &std::collections::HashSet<IpAddr>,
                                     _interface: &Option<String>,
                                     service_lookup: &ServiceLookup| { // Added service_lookup
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
                            conn.rate_history.push((Instant::now(), conn.bytes_sent, conn.bytes_received));
                            // Update service name for existing connection
                            set_connection_service_name_for_connection(conn, service_lookup);
                        } else {
                            let mut new_conn =
                                Connection::new(Protocol::TCP, local_addr, remote_addr, state);
                            new_conn.last_activity = SystemTime::now();
                            if is_outgoing {
                                new_conn.packets_sent += 1;
                                new_conn.bytes_sent += data.len() as u64;
                            } else {
                                new_conn.packets_received += 1;
                                new_conn.bytes_received += data.len() as u64;
                            }
                            new_conn.rate_history.push((Instant::now(), new_conn.bytes_sent, new_conn.bytes_received));
                            // Set service name for new connection before inserting
                            set_connection_service_name_for_connection(&mut new_conn, service_lookup);
                            monitor_connections.insert(conn_key, new_conn);
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
                            conn.rate_history.push((Instant::now(), conn.bytes_sent, conn.bytes_received));
                            // Update service name for existing connection
                            set_connection_service_name_for_connection(conn, service_lookup);
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
                            new_conn.rate_history.push((Instant::now(), new_conn.bytes_sent, new_conn.bytes_received));
                            // Set service name for new connection before inserting
                            set_connection_service_name_for_connection(&mut new_conn, service_lookup);
                            monitor_connections.insert(conn_key, new_conn);
                        }
                    }
                    _ => {} // Ignore other protocols
                } // This closes the `match protocol`
            }; // This closes the `process_single_packet` closure definition

        // Removed initial_packet_processing_done logic and last_packet_check cooldown.
        // The loop will now attempt to process packets more continuously,
        // controlled by the sleep interval in the app.rs background thread.

        // Get packets from the capture
        if let Some(ref mut cap) = self.capture {
            log::debug!("NetworkMonitor::process_packets - Starting packet processing loop (up to 20 iterations)");
            let loop_start_time = Instant::now();
            let mut packets_processed_in_loop = 0;
            // Process up to a smaller number of packets to reduce blocking time
            const MAX_PACKETS_PER_CALL: usize = 20;
            for i in 0..MAX_PACKETS_PER_CALL {
                match cap.next_packet() {
                    Ok(packet) => {
                        packets_processed_in_loop += 1;
                        // Use the local helper function to avoid borrowing issues
                        process_single_packet(packet.data, &mut self.connections, &self.local_ips, &self.interface, &self.service_lookup);
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // This is expected if timeout(0) is working and no packets are available
                        log::trace!("NetworkMonitor::process_packets - cap.next_packet() timed out (iteration {})", i);
                        break; // No more packets for now, exit loop
                    }
                    Err(e) => {
                        error!("NetworkMonitor::process_packets - Error reading packet (iteration {}): {}", i, e);
                        break; // Error reading packet
                    }
                }
            }
            let loop_duration = loop_start_time.elapsed();
            log::debug!(
                "NetworkMonitor::process_packets - Packet processing loop finished in {:?}. Packets processed: {}/{} iterations.",
                loop_duration,
                packets_processed_in_loop,
                MAX_PACKETS_PER_CALL
            );
        } else {
            log::warn!("NetworkMonitor::process_packets - No capture device available.");
        }
        log::debug!("NetworkMonitor::process_packets - Exiting process_packets");
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
        let addr_str = addr_str.trim();

        // Attempt direct parsing first, which handles common cases like "1.2.3.4:80" or "[::1]:8080"
        if let Ok(socket_addr) = addr_str.parse::<std::net::SocketAddr>() {
            return Some(socket_addr);
        }

        // If direct parsing fails, try to handle formats like "host:*" or "ip:*"
        // by splitting host and port.
        if let Some(last_colon_idx) = addr_str.rfind(':') {
            let (host_str_candidate, port_str) = addr_str.split_at(last_colon_idx);
            let port_str = &port_str[1..]; // Skip the colon

            let host_str = if host_str_candidate.starts_with('[') && host_str_candidate.ends_with(']') {
                // IPv6 like [::1]
                &host_str_candidate[1..host_str_candidate.len() - 1]
            } else {
                host_str_candidate
            };

            if let Ok(ip_addr) = host_str.parse::<std::net::IpAddr>() {
                let port_num = if port_str == "*" {
                    0 // Map wildcard port to 0
                } else {
                    match port_str.parse::<u16>() {
                        Ok(p) => p,
                        Err(_) => return None, // Invalid port string
                    }
                };
                return Some(std::net::SocketAddr::new(ip_addr, port_num));
            }
        } else {
            // If no colon, it might be just a port number (for localhost)
            if let Ok(port_num) = addr_str.parse::<u16>() {
                // Default to localhost if only port is provided
                let local_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
                return Some(std::net::SocketAddr::new(local_ip, port_num));
            }
        }

        None
    }
}
