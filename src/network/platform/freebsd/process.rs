// network/platform/freebsd/process.rs - FreeBSD sockstat-based process lookup

use crate::network::platform::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub struct FreeBSDProcessLookup {
    // Cache: ConnectionKey -> (pid, process_name)
    cache: RwLock<ProcessCache>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, (u32, String)>,
    last_refresh: Instant,
}

impl FreeBSDProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: Instant::now() - Duration::from_secs(3600),
            }),
        })
    }

    /// Build connection -> process mapping using sysctl
    fn build_process_map() -> Result<HashMap<ConnectionKey, (u32, String)>> {
        let mut process_map = HashMap::new();

        // Parse TCP connections
        if let Ok(tcp_connections) = Self::parse_sockstat_output("tcp") {
            process_map.extend(tcp_connections);
        }

        // Parse TCP6 connections
        if let Ok(tcp6_connections) = Self::parse_sockstat_output("tcp6") {
            process_map.extend(tcp6_connections);
        }

        // Parse UDP connections
        if let Ok(udp_connections) = Self::parse_sockstat_output("udp") {
            process_map.extend(udp_connections);
        }

        // Parse UDP6 connections
        if let Ok(udp6_connections) = Self::parse_sockstat_output("udp6") {
            process_map.extend(udp6_connections);
        }

        Ok(process_map)
    }

    /// Parse sockstat output for a given protocol
    /// Format: user command pid fd proto local_addr foreign_addr
    fn parse_sockstat_output(proto: &str) -> Result<HashMap<ConnectionKey, (u32, String)>> {
        use std::process::Command;

        let mut result = HashMap::new();

        // Determine protocol type
        let protocol = if proto.starts_with("tcp") {
            Protocol::TCP
        } else {
            Protocol::UDP
        };

        // Run sockstat command
        // -4: IPv4, -6: IPv6, -c: connected sockets, -l: listening sockets, -n: numeric
        let ipv6_flag = proto.ends_with('6');

        let output = Command::new("sockstat")
            .arg(if ipv6_flag { "-6" } else { "-4" })
            .arg("-n") // numeric output
            .arg("-P")
            .arg(if proto.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            })
            .output()
            .context("Failed to execute sockstat")?;

        if !output.status.success() {
            return Ok(result);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Expected format:
            // USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
            // root     sshd       1234  3  tcp4   192.168.1.1:22        192.168.1.2:54321

            if parts.len() < 7 {
                continue;
            }

            // Extract fields
            let process_name = parts[1].to_string();
            let pid = match parts[2].parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Parse local address (index 5)
            let local_addr = match Self::parse_address(parts[5]) {
                Some(addr) => addr,
                None => continue,
            };

            // Parse foreign address (index 6)
            let foreign_addr = match Self::parse_address(parts[6]) {
                Some(addr) => addr,
                None => continue,
            };

            let key = ConnectionKey {
                protocol,
                local_addr,
                remote_addr: foreign_addr,
            };

            result.insert(key, (pid, process_name));
        }

        Ok(result)
    }

    /// Parse address in format "ip:port", "*:port", or "[ipv6]:port"
    fn parse_address(addr_str: &str) -> Option<SocketAddr> {
        // Handle wildcard addresses
        if addr_str.starts_with("*:") {
            let port = addr_str.strip_prefix("*:")?.parse::<u16>().ok()?;
            // Use unspecified address for wildcards
            return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
        }

        // Handle IPv6 with brackets: [::1]:8080
        if addr_str.starts_with('[') {
            let closing_bracket = addr_str.find(']')?;
            let ip_str = &addr_str[1..closing_bracket];
            let port_str = addr_str.get(closing_bracket + 2..)?; // Skip "]:"
            let port = port_str.parse::<u16>().ok()?;
            let ip = IpAddr::V6(ip_str.parse().ok()?);
            return Some(SocketAddr::new(ip, port));
        }

        // Split by last colon to handle addresses
        let last_colon = addr_str.rfind(':')?;
        let (ip_str, port_str) = addr_str.split_at(last_colon);
        let port_str = &port_str[1..]; // Remove the colon

        let port = port_str.parse::<u16>().ok()?;

        // Detect IPv6 (contains colons) vs IPv4
        let ip = if ip_str.contains(':') {
            // IPv6 address without brackets (e.g., "::1" or "fe80::1")
            IpAddr::V6(ip_str.parse().ok()?)
        } else {
            // IPv4 address
            IpAddr::V4(ip_str.parse().ok()?)
        };

        Some(SocketAddr::new(ip, port))
    }
}

impl ProcessLookup for FreeBSDProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);

        // Simple cache lookup with no refresh on cache miss.
        // The enrichment thread handles periodic refresh.
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
        "sockstat"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_parse_ipv4_address() {
        let addr = FreeBSDProcessLookup::parse_address("192.168.1.1:8080");
        assert_eq!(
            addr,
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                8080
            ))
        );
    }

    #[test]
    fn test_parse_ipv4_loopback() {
        let addr = FreeBSDProcessLookup::parse_address("127.0.0.1:80");
        assert_eq!(
            addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80))
        );
    }

    #[test]
    fn test_parse_ipv6_with_brackets() {
        let addr = FreeBSDProcessLookup::parse_address("[::1]:8080");
        assert_eq!(
            addr,
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
        );
    }

    #[test]
    fn test_parse_ipv6_full_address_with_brackets() {
        let addr = FreeBSDProcessLookup::parse_address("[2001:db8::1]:443");
        assert_eq!(
            addr,
            Some(SocketAddr::new(
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                443
            ))
        );
    }

    #[test]
    fn test_parse_ipv6_link_local_with_brackets() {
        let addr = FreeBSDProcessLookup::parse_address("[fe80::1]:22");
        assert_eq!(
            addr,
            Some(SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 22))
        );
    }

    #[test]
    fn test_parse_ipv6_without_brackets() {
        // This may occur in some sockstat outputs
        let addr = FreeBSDProcessLookup::parse_address("::1:8080");
        // This should parse as IPv6 ::1 with port 8080
        // Note: This is ambiguous, but our logic treats multiple colons as IPv6
        assert!(addr.is_some());
        if let Some(socket_addr) = addr {
            assert_eq!(socket_addr.port(), 8080);
        }
    }

    #[test]
    fn test_parse_wildcard_address() {
        let addr = FreeBSDProcessLookup::parse_address("*:80");
        assert_eq!(
            addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80))
        );
    }

    #[test]
    fn test_parse_wildcard_high_port() {
        let addr = FreeBSDProcessLookup::parse_address("*:65535");
        assert_eq!(
            addr,
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 65535))
        );
    }

    #[test]
    fn test_parse_invalid_address() {
        // Missing port
        assert_eq!(FreeBSDProcessLookup::parse_address("192.168.1.1"), None);
    }

    #[test]
    fn test_parse_invalid_ipv6_brackets() {
        // Missing closing bracket
        assert_eq!(FreeBSDProcessLookup::parse_address("[::1:8080"), None);
    }

    #[test]
    fn test_parse_invalid_port() {
        // Port out of range
        assert_eq!(
            FreeBSDProcessLookup::parse_address("192.168.1.1:99999"),
            None
        );
    }

    #[test]
    fn test_parse_empty_string() {
        assert_eq!(FreeBSDProcessLookup::parse_address(""), None);
    }

    #[test]
    fn test_parse_ipv4_mapped_ipv6() {
        // IPv4-mapped IPv6 address
        let addr = FreeBSDProcessLookup::parse_address("[::ffff:192.168.1.1]:80");
        assert_eq!(
            addr,
            Some(SocketAddr::new(
                IpAddr::V6("::ffff:192.168.1.1".parse().unwrap()),
                80
            ))
        );
    }
}
