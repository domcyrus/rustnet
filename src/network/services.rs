use crate::network::types::Protocol;
use anyhow::Result;
use log::debug;
use std::collections::HashMap;

const SERVICES_DATA: &str = include_str!("../../assets/services");

/// Service name lookup table
#[derive(Debug, Clone)]
pub struct ServiceLookup {
    /// Map of (port, protocol) -> service name
    services: HashMap<(u16, Protocol), String>,
}

impl ServiceLookup {
    /// Create an empty service lookup
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    // Load services from embedded data.
    pub fn from_embedded() -> Result<Self> {
        let mut services = HashMap::new();

        for line in SERVICES_DATA.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse line format: service-name port/protocol [aliases...]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let service_name = parts[0];
            let port_protocol = parts[1];

            // Parse port/protocol
            let port_parts: Vec<&str> = port_protocol.split('/').collect();
            if port_parts.len() != 2 {
                continue;
            }

            let port = match port_parts[0].parse::<u16>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let protocol = match port_parts[1].to_lowercase().as_str() {
                "tcp" => Protocol::TCP,
                "udp" => Protocol::UDP,
                _ => continue,
            };

            // Store the service
            services
                .entry((port, protocol))
                .or_insert_with(|| service_name.to_string());
        }
        if services.is_empty() {
            return Err(anyhow::anyhow!("No services found in embedded data"));
        }
        debug!("Loaded {} services from embedded data", services.len());

        Ok(Self { services })
    }

    /// Create with common well-known services
    pub fn with_defaults() -> Self {
        let mut lookup = Self::new();

        // Common TCP services
        lookup.add_service(20, Protocol::TCP, "ftp-data");
        lookup.add_service(21, Protocol::TCP, "ftp");
        lookup.add_service(22, Protocol::TCP, "ssh");
        lookup.add_service(23, Protocol::TCP, "telnet");
        lookup.add_service(25, Protocol::TCP, "smtp");
        lookup.add_service(53, Protocol::TCP, "dns");
        lookup.add_service(80, Protocol::TCP, "http");
        lookup.add_service(110, Protocol::TCP, "pop3");
        lookup.add_service(143, Protocol::TCP, "imap");
        lookup.add_service(443, Protocol::TCP, "https");
        lookup.add_service(445, Protocol::TCP, "microsoft-ds");
        lookup.add_service(587, Protocol::TCP, "submission");
        lookup.add_service(993, Protocol::TCP, "imaps");
        lookup.add_service(995, Protocol::TCP, "pop3s");
        lookup.add_service(1433, Protocol::TCP, "mssql");
        lookup.add_service(3306, Protocol::TCP, "mysql");
        lookup.add_service(3389, Protocol::TCP, "rdp");
        lookup.add_service(5432, Protocol::TCP, "postgresql");
        lookup.add_service(5900, Protocol::TCP, "vnc");
        lookup.add_service(6379, Protocol::TCP, "redis");
        lookup.add_service(8080, Protocol::TCP, "http-alt");
        lookup.add_service(8443, Protocol::TCP, "https-alt");
        lookup.add_service(27017, Protocol::TCP, "mongodb");

        // Common UDP services
        lookup.add_service(53, Protocol::UDP, "dns");
        lookup.add_service(67, Protocol::UDP, "dhcp-server");
        lookup.add_service(68, Protocol::UDP, "dhcp-client");
        lookup.add_service(123, Protocol::UDP, "ntp");
        lookup.add_service(161, Protocol::UDP, "snmp");
        lookup.add_service(443, Protocol::UDP, "https"); // QUIC
        lookup.add_service(500, Protocol::UDP, "isakmp");
        lookup.add_service(1194, Protocol::UDP, "openvpn");
        lookup.add_service(4500, Protocol::UDP, "ipsec-nat");
        lookup.add_service(5060, Protocol::UDP, "sip");

        lookup
    }

    /// Add a service mapping
    pub fn add_service(&mut self, port: u16, protocol: Protocol, name: &str) {
        self.services.insert((port, protocol), name.to_string());
    }

    /// Look up a service name by port and protocol
    pub fn lookup(&self, port: u16, protocol: Protocol) -> Option<&str> {
        self.services.get(&(port, protocol)).map(|s| s.as_str())
    }
}

impl Default for ServiceLookup {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_services() {
        let lookup = ServiceLookup::with_defaults();

        assert_eq!(lookup.lookup(80, Protocol::TCP), Some("http"));
        assert_eq!(lookup.lookup(443, Protocol::TCP), Some("https"));
        assert_eq!(lookup.lookup(22, Protocol::TCP), Some("ssh"));
        assert_eq!(lookup.lookup(53, Protocol::UDP), Some("dns"));
    }
}
