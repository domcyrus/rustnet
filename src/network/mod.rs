use anyhow::{anyhow, Result};
use log::{debug, error, info, trace, warn};
use maxminddb::geoip2;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::*;

/// Connection protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::Other(proto) => write!(f, "Proto({})", proto),
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
            created_at: now,
            last_activity: now,
        }
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

/// IP location information
#[derive(Debug, Clone)]
pub struct IpLocation {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city_name: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub isp: Option<String>,
}

/// Network monitor
pub struct NetworkMonitor {
    interface: Option<String>,
    capture: Option<Capture<pcap::Active>>,
    connections: HashMap<String, Connection>,
    geo_db: Option<maxminddb::Reader<Vec<u8>>>,
}

impl NetworkMonitor {
    /// Create a new network monitor
    pub fn new(interface: Option<String>) -> Result<Self> {
        let mut capture = if let Some(iface) = &interface {
            // Open capture on specific interface
            let device = Device::list()?
                .into_iter()
                .find(|dev| dev.name == *iface)
                .ok_or_else(|| anyhow!("Interface not found: {}", iface))?;

            info!("Opening capture on interface: {}", iface);
            Some(
                Capture::from_device(device)?
                    .immediate_mode(true)
                    .timeout(500)
                    .snaplen(65535)
                    .promisc(true)
                    .open()?,
            )
        } else {
            // Get default interface if none specified
            let device = Device::lookup()?.ok_or_else(|| anyhow!("No default device found"))?;

            info!("Opening capture on default interface: {}", device.name);
            Some(
                Capture::from_device(device)?
                    .immediate_mode(true)
                    .timeout(500)
                    .snaplen(65535)
                    .promisc(true)
                    .open()?,
            )
        };

        // Set BPF filter to capture all TCP and UDP traffic
        if let Some(ref mut cap) = capture {
            match cap.filter("tcp or udp", true) {
                Ok(_) => info!("Applied packet filter: tcp or udp"),
                Err(e) => error!("Error setting packet filter: {}", e),
            }
        }

        // Try to load MaxMind database if available
        let geo_db = std::fs::read("GeoLite2-City.mmdb")
            .ok()
            .map(|data| maxminddb::Reader::from_source(data).ok())
            .flatten();
            
        if geo_db.is_some() {
            info!("Loaded MaxMind GeoIP database");
        } else {
            debug!("MaxMind GeoIP database not found");
        }

        Ok(Self {
            interface,
            capture,
            connections: HashMap::new(),
            geo_db,
        })
    }

    /// Get network device list
    pub fn get_devices() -> Result<Vec<String>> {
        let devices = Device::list()?;
        Ok(devices.into_iter().map(|dev| dev.name).collect())
    }

    /// Get active connections
    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        // Get connections from system
        let mut connections = Vec::new();

        // Use platform-specific code to get connections
        self.get_platform_connections(&mut connections)?;

        // Update with processes
        for conn in &mut connections {
            if conn.pid.is_none() {
                // Use the platform-specific method
                if let Some(process) = self.get_platform_process_for_connection(conn) {
                    conn.pid = Some(process.pid);
                    conn.process_name = Some(process.name.clone());
                }
            }
        }

        Ok(connections)
    }

    /// Parse socket address from string
    fn parse_addr(&self, addr_str: &str) -> Option<SocketAddr> {
        // Handle different address formats
        let addr_str = addr_str.trim_end_matches('.');

        if addr_str == "*" || addr_str == "*:*" {
            // Default to 0.0.0.0:0 for wildcard
            return Some(SocketAddr::from(([0, 0, 0, 0], 0)));
        }

        // Try to parse directly
        if let Ok(addr) = addr_str.parse::<SocketAddr>() {
            return Some(addr);
        }

        // Try to parse IPv4:port format
        if let Some(colon_pos) = addr_str.rfind(':') {
            let ip_part = &addr_str[..colon_pos];
            let port_part = &addr_str[colon_pos + 1..];

            if let (Ok(ip), Ok(port)) = (ip_part.parse::<IpAddr>(), port_part.parse::<u16>()) {
                return Some(SocketAddr::new(ip, port));
            }
        }

        None
    }

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

    /// Get location information for an IP address
    pub fn get_ip_location(&self, ip: IpAddr) -> Option<IpLocation> {
        if let Some(ref reader) = self.geo_db {
            // Access fields directly on the lookup result (geoip2::City)
            if let Ok(lookup_result) = reader.lookup::<geoip2::City>(ip) {
                let country = lookup_result.country.as_ref().and_then(|c| {
                    let code = c.iso_code.map(String::from);
                    let name = c
                        .names
                        .as_ref()
                        .and_then(|n| n.get("en").map(|s| s.to_string()));
                    if code.is_some() || name.is_some() {
                        Some((code, name))
                    } else {
                        None
                    }
                });

                let city_name = lookup_result
                    .city
                    .as_ref()
                    .and_then(|c| c.names.as_ref())
                    .and_then(|n| n.get("en"))
                    .map(|s| s.to_string());

                let location = lookup_result
                    .location
                    .as_ref()
                    .map(|l| (l.latitude, l.longitude));

                return Some(IpLocation {
                    country_code: country.as_ref().and_then(|(code, _)| code.clone()),
                    country_name: country.as_ref().and_then(|(_, name)| name.clone()),
                    city_name,
                    latitude: location.and_then(|(lat, _)| lat),
                    longitude: location.and_then(|(_, lon)| lon),
                    isp: None, // Not available in GeoLite2-City
                });
            }
        }

        None
    }
}
