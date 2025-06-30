use crate::network::types::Protocol;
use anyhow::Result;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Service name lookup table
#[derive(Debug, Clone)]
pub struct ServiceLookup {
    /// Map of (port, protocol) -> service name
    services: HashMap<(u16, Protocol), String>,
    /// Common alternative names for services
    #[allow(dead_code)]
    aliases: HashMap<String, String>,
}

impl ServiceLookup {
    /// Create an empty service lookup
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Load services from a file (typically /etc/services format)
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut services = HashMap::new();
        let mut aliases = HashMap::new();

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
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

            // Store aliases if any
            for &alias in &parts[2..] {
                if !alias.starts_with('#') {
                    aliases.insert(alias.to_string(), service_name.to_string());
                } else {
                    break; // Rest is comment
                }
            }
        }

        Ok(Self { services, aliases })
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

    /// Look up service name with fallback to common names
    #[allow(dead_code)]
    pub fn lookup_with_fallback(&self, port: u16, protocol: Protocol) -> Option<String> {
        if let Some(name) = self.lookup(port, protocol) {
            return Some(name.to_string());
        }

        // Common dynamic port ranges with generic names
        match port {
            1024..=5000 => Some("user-port".to_string()),
            5001..=32767 => Some("dynamic".to_string()),
            32768..=60999 => Some("private".to_string()),
            61000..=65535 => Some("ephemeral".to_string()),
            _ => None,
        }
    }

    /// Get a display name for a service (formats well-known services better)
    #[allow(dead_code)]
    pub fn display_name(&self, port: u16, protocol: Protocol) -> String {
        match self.lookup(port, protocol) {
            Some("http") => "HTTP".to_string(),
            Some("https") => "HTTPS".to_string(),
            Some("ssh") => "SSH".to_string(),
            Some("ftp") => "FTP".to_string(),
            Some("smtp") => "SMTP".to_string(),
            Some("imap") => "IMAP".to_string(),
            Some("pop3") => "POP3".to_string(),
            Some("dns") => "DNS".to_string(),
            Some("dhcp-server") => "DHCP Server".to_string(),
            Some("dhcp-client") => "DHCP Client".to_string(),
            Some("ntp") => "NTP".to_string(),
            Some("rdp") => "RDP".to_string(),
            Some("vnc") => "VNC".to_string(),
            Some(name) => {
                // Capitalize first letter
                let mut chars = name.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            }
            None => format!("{}/{}", port, protocol),
        }
    }

    /// Get all services for a specific protocol
    #[allow(dead_code)]
    pub fn services_by_protocol(&self, protocol: Protocol) -> Vec<(u16, &str)> {
        let mut services: Vec<(u16, &str)> = self
            .services
            .iter()
            .filter_map(|((port, proto), name)| {
                if *proto == protocol {
                    Some((*port, name.as_str()))
                } else {
                    None
                }
            })
            .collect();

        services.sort_by_key(|(port, _)| *port);
        services
    }

    /// Get the number of services loaded
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Check if the lookup table is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
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

    #[test]
    fn test_display_names() {
        let lookup = ServiceLookup::with_defaults();

        assert_eq!(lookup.display_name(80, Protocol::TCP), "HTTP");
        assert_eq!(lookup.display_name(443, Protocol::TCP), "HTTPS");
        assert_eq!(lookup.display_name(12345, Protocol::TCP), "12345/TCP");
    }

    #[test]
    fn test_lookup_with_fallback() {
        let lookup = ServiceLookup::with_defaults();

        assert_eq!(
            lookup.lookup_with_fallback(80, Protocol::TCP),
            Some("http".to_string())
        );
        assert_eq!(
            lookup.lookup_with_fallback(50000, Protocol::TCP),
            Some("private".to_string())
        );
        assert_eq!(
            lookup.lookup_with_fallback(65000, Protocol::TCP),
            Some("ephemeral".to_string())
        );
    }

    #[test]
    fn test_services_by_protocol() {
        let lookup = ServiceLookup::with_defaults();

        let tcp_services = lookup.services_by_protocol(Protocol::TCP);
        assert!(tcp_services.iter().any(|(port, _)| *port == 80));
        assert!(tcp_services.iter().any(|(port, _)| *port == 443));

        let udp_services = lookup.services_by_protocol(Protocol::UDP);
        assert!(udp_services.iter().any(|(port, _)| *port == 53));
    }
}
