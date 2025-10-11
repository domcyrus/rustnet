// network/platform/linux.rs - Linux process lookup
use super::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub struct LinuxProcessLookup {
    // Cache: ConnectionKey -> (pid, process_name)
    cache: RwLock<ProcessCache>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, (u32, String)>,
    last_refresh: Instant,
}

impl LinuxProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: Instant::now() - Duration::from_secs(3600),
            }),
        })
    }

    /// Build connection -> process mapping
    fn build_process_map() -> Result<HashMap<ConnectionKey, (u32, String)>> {
        let mut process_map = HashMap::new();

        // First, build inode -> process mapping
        let inode_to_process = Self::build_inode_map()?;

        // Then, parse network files to map connections -> inodes -> processes
        Self::parse_and_map(
            "/proc/net/tcp",
            Protocol::TCP,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/tcp6",
            Protocol::TCP,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/udp",
            Protocol::UDP,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/udp6",
            Protocol::UDP,
            &inode_to_process,
            &mut process_map,
        )?;

        Ok(process_map)
    }

    /// Build inode -> (pid, process_name) mapping
    fn build_inode_map() -> Result<HashMap<u64, (u32, String)>> {
        let mut inode_map = HashMap::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();

            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str())
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                if pid == 0 {
                    continue;
                }

                // Get process name
                let comm_path = path.join("comm");
                let process_name = fs::read_to_string(&comm_path)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                // Check file descriptors
                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path())
                            && let Some(link_str) = link.to_str()
                            && let Some(inode) = Self::extract_socket_inode(link_str)
                        {
                            inode_map.insert(inode, (pid, process_name.clone()));
                        }
                    }
                }
            }
        }

        Ok(inode_map)
    }

    /// Parse /proc/net file and map connections to processes
    fn parse_and_map(
        path: &str,
        protocol: Protocol,
        inode_map: &HashMap<u64, (u32, String)>,
        result: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // File might not exist
        };

        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue; // Skip header
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // Parse addresses
            let local_addr = match Self::parse_hex_address(parts[1]) {
                Some(addr) => addr,
                None => continue,
            };

            let remote_addr = match Self::parse_hex_address(parts[2]) {
                Some(addr) => addr,
                None => continue,
            };

            // Get inode
            if let Ok(inode) = parts[9].parse::<u64>()
                && let Some((pid, name)) = inode_map.get(&inode)
            {
                let key = ConnectionKey {
                    protocol,
                    local_addr,
                    remote_addr,
                };
                result.insert(key, (*pid, name.clone()));
            }
        }

        Ok(())
    }

    fn parse_hex_address(hex_addr: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = hex_addr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        if ip_hex.len() == 8 {
            // IPv4
            let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = Ipv4Addr::from(ip_bytes.to_le_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        } else if ip_hex.len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let chunk = &ip_hex[i * 8..(i + 1) * 8];
                let value = u32::from_str_radix(chunk, 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&value.to_le_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            None
        }
    }

    fn extract_socket_inode(link: &str) -> Option<u64> {
        if link.starts_with("socket:[") && link.ends_with(']') {
            let inode_str = &link[8..link.len() - 1];
            inode_str.parse().ok()
        } else {
            None
        }
    }
}

impl ProcessLookup for LinuxProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);

        // Simple cache lookup with no refresh on cache miss.
        // The enrichment thread (app.rs:495-500) handles periodic refresh every 5 seconds.
        // IMPORTANT: Do NOT refresh here as it caused high CPU usage when called for every
        // connection without process info (flamegraph showed this was the main bottleneck).
        let cache = self.cache.read().unwrap();
        cache.lookup.get(&key).cloned()
    }

    fn refresh(&self) -> Result<()> {
        let process_map = Self::build_process_map()?;

        let mut cache = self.cache.write().unwrap();
        cache.lookup = process_map;
        cache.last_refresh = Instant::now();

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "procfs"
    }
}
