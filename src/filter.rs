use crate::network::types::{ApplicationProtocol, Connection};

#[derive(Debug, Clone)]
pub enum FilterCriteria {
    /// Match any field containing this text
    General(String),
    /// Match port number containing this string (fuzzy port matching)
    Port(String),
    /// Match source port containing this string
    SourcePort(String),
    /// Match destination port containing this string  
    DestinationPort(String),
    /// Match source IP address (partial match allowed)
    SourceIp(String),
    /// Match destination IP address (partial match allowed)
    DestinationIp(String),
    /// Match protocol (TCP, UDP, etc.)
    Protocol(String),
    /// Match process name
    Process(String),
    /// Match service name
    Service(String),
    /// Match SNI hostname from TLS/QUIC
    Sni(String),
    /// Match DPI application protocol
    Application(String),
    /// Match connection state (e.g., ESTABLISHED, SYN_RECV)
    State(String),
}

pub struct ConnectionFilter {
    pub criteria: Vec<FilterCriteria>,
}

impl ConnectionFilter {
    /// Parse filter query string into filter criteria
    pub fn parse(query: &str) -> Self {
        let mut criteria = Vec::new();

        if query.trim().is_empty() {
            return Self { criteria };
        }

        // Split by whitespace and process each part
        let parts: Vec<&str> = query.split_whitespace().collect();

        for part in parts {
            if let Some((keyword, value)) = part.split_once(':') {
                // Handle keyword-based filters
                let value = value.to_lowercase();
                match keyword.to_lowercase().as_str() {
                    "port" => {
                        // Always use partial matching for better fuzzy search experience
                        // This allows "44" to match 443, 8080, 8443, etc.
                        criteria.push(FilterCriteria::Port(value));
                    }
                    "sport" | "srcport" | "source-port" => {
                        criteria.push(FilterCriteria::SourcePort(value));
                    }
                    "dport" | "dstport" | "dest-port" | "destination-port" => {
                        criteria.push(FilterCriteria::DestinationPort(value));
                    }
                    "src" | "source" => {
                        criteria.push(FilterCriteria::SourceIp(value));
                    }
                    "dst" | "dest" | "destination" => {
                        criteria.push(FilterCriteria::DestinationIp(value));
                    }
                    "proto" | "protocol" => {
                        criteria.push(FilterCriteria::Protocol(value));
                    }
                    "process" | "proc" => {
                        criteria.push(FilterCriteria::Process(value));
                    }
                    "service" | "svc" => {
                        criteria.push(FilterCriteria::Service(value));
                    }
                    "sni" | "host" | "hostname" => {
                        criteria.push(FilterCriteria::Sni(value));
                    }
                    "app" | "application" => {
                        criteria.push(FilterCriteria::Application(value));
                    }
                    "state" => {
                        criteria.push(FilterCriteria::State(value));
                    }
                    _ => {
                        // Unknown keyword, treat as general search
                        criteria.push(FilterCriteria::General(part.to_lowercase()));
                    }
                }
            } else {
                // General text search
                criteria.push(FilterCriteria::General(part.to_lowercase()));
            }
        }

        Self { criteria }
    }

    /// Check if a connection matches all filter criteria
    pub fn matches(&self, connection: &Connection) -> bool {
        if self.criteria.is_empty() {
            return true;
        }

        // All criteria must match (AND operation)
        self.criteria.iter().all(|criterion| match criterion {
            FilterCriteria::General(text) => self.matches_general(connection, text),
            FilterCriteria::Port(port_text) => {
                connection.local_addr.port().to_string().contains(port_text)
                    || connection
                        .remote_addr
                        .port()
                        .to_string()
                        .contains(port_text)
            }
            FilterCriteria::SourcePort(port_text) => {
                connection.local_addr.port().to_string().contains(port_text)
            }
            FilterCriteria::DestinationPort(port_text) => connection
                .remote_addr
                .port()
                .to_string()
                .contains(port_text),
            FilterCriteria::SourceIp(ip_text) => connection
                .local_addr
                .ip()
                .to_string()
                .to_lowercase()
                .contains(ip_text),
            FilterCriteria::DestinationIp(ip_text) => connection
                .remote_addr
                .ip()
                .to_string()
                .to_lowercase()
                .contains(ip_text),
            FilterCriteria::Protocol(proto_text) => connection
                .protocol
                .to_string()
                .to_lowercase()
                .contains(proto_text),
            FilterCriteria::Process(process_text) => {
                if let Some(ref process_name) = connection.process_name {
                    process_name.to_lowercase().contains(process_text)
                } else {
                    false
                }
            }
            FilterCriteria::Service(service_text) => {
                if let Some(ref service_name) = connection.service_name {
                    service_name.to_lowercase().contains(service_text)
                } else {
                    false
                }
            }
            FilterCriteria::Sni(sni_text) => self.matches_sni(connection, sni_text),
            FilterCriteria::Application(app_text) => self.matches_application(connection, app_text),
            FilterCriteria::State(state_text) => {
                connection.state().to_lowercase().contains(state_text)
            }
        })
    }

    /// Check if connection matches general text search across all fields
    fn matches_general(&self, connection: &Connection, text: &str) -> bool {
        // Check basic connection info
        if connection
            .protocol
            .to_string()
            .to_lowercase()
            .contains(text)
            || connection
                .local_addr
                .to_string()
                .to_lowercase()
                .contains(text)
            || connection
                .remote_addr
                .to_string()
                .to_lowercase()
                .contains(text)
        {
            return true;
        }

        // Check process info
        if let Some(ref process_name) = connection.process_name
            && process_name.to_lowercase().contains(text)
        {
            return true;
        }

        // Check service info
        if let Some(ref service_name) = connection.service_name
            && service_name.to_lowercase().contains(text)
        {
            return true;
        }

        // Check DPI info
        if let Some(ref dpi_info) = connection.dpi_info
            && self.matches_dpi_general(&dpi_info.application, text)
        {
            return true;
        }

        false
    }

    /// Check if SNI matches the search text
    fn matches_sni(&self, connection: &Connection, sni_text: &str) -> bool {
        if let Some(ref dpi_info) = connection.dpi_info {
            match &dpi_info.application {
                ApplicationProtocol::Https(info) => {
                    if let Some(ref tls_info) = info.tls_info
                        && let Some(ref sni) = tls_info.sni
                    {
                        return sni.to_lowercase().contains(sni_text);
                    }
                }
                ApplicationProtocol::Quic(info) => {
                    if let Some(ref tls_info) = info.tls_info
                        && let Some(ref sni) = tls_info.sni
                    {
                        return sni.to_lowercase().contains(sni_text);
                    }
                }
                ApplicationProtocol::Http(info) => {
                    if let Some(ref host) = info.host {
                        return host.to_lowercase().contains(sni_text);
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if application protocol matches the search text
    fn matches_application(&self, connection: &Connection, app_text: &str) -> bool {
        if let Some(ref dpi_info) = connection.dpi_info {
            dpi_info
                .application
                .to_string()
                .to_lowercase()
                .contains(app_text)
        } else {
            false
        }
    }

    /// Check if DPI info matches general search
    fn matches_dpi_general(&self, application: &ApplicationProtocol, text: &str) -> bool {
        // Check the application type display
        if application.to_string().to_lowercase().contains(text) {
            return true;
        }

        // Check specific protocol details
        match application {
            ApplicationProtocol::Http(info) => {
                if let Some(ref host) = info.host
                    && host.to_lowercase().contains(text)
                {
                    return true;
                }
                if let Some(ref path) = info.path
                    && path.to_lowercase().contains(text)
                {
                    return true;
                }
                if let Some(ref method) = info.method
                    && method.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && sni.to_lowercase().contains(text)
                    {
                        return true;
                    }
                    // Check ALPN protocols
                    for alpn in &tls_info.alpn {
                        if alpn.to_lowercase().contains(text) {
                            return true;
                        }
                    }
                }
            }
            ApplicationProtocol::Dns(info) => {
                if let Some(ref query_name) = info.query_name
                    && query_name.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && sni.to_lowercase().contains(text)
                    {
                        return true;
                    }
                    // Check ALPN protocols
                    for alpn in &tls_info.alpn {
                        if alpn.to_lowercase().contains(text) {
                            return true;
                        }
                    }
                }
            }
            ApplicationProtocol::Ssh(info) => {
                if "ssh".contains(text) {
                    return true;
                }

                // Check software names
                if let Some(ref software) = info.server_software
                    && software.to_lowercase().contains(text)
                {
                    return true;
                }
                if let Some(ref software) = info.client_software
                    && software.to_lowercase().contains(text)
                {
                    return true;
                }

                // Check connection state
                let state_str = format!("{:?}", info.connection_state).to_lowercase();
                if state_str.contains(text) {
                    return true;
                }

                // Check algorithms
                for algo in &info.algorithms {
                    if algo.to_lowercase().contains(text) {
                        return true;
                    }
                }
            }
            ApplicationProtocol::Ntp(_) => {
                if "ntp".contains(text) {
                    return true;
                }
            }
            ApplicationProtocol::Mdns(info) => {
                if let Some(ref query_name) = info.query_name
                    && query_name.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Llmnr(info) => {
                if let Some(ref query_name) = info.query_name
                    && query_name.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Dhcp(info) => {
                if let Some(ref hostname) = info.hostname
                    && hostname.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Snmp(info) => {
                if let Some(ref community) = info.community
                    && community.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Ssdp(info) => {
                if let Some(ref service_type) = info.service_type
                    && service_type.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::NetBios(info) => {
                if let Some(ref name) = info.name
                    && name.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::BitTorrent(info) => {
                if "bittorrent".contains(text) {
                    return true;
                }
                if let Some(ref client) = info.client
                    && client.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Stun(info) => {
                if "stun".contains(text) {
                    return true;
                }
                if let Some(ref software) = info.software
                    && software.to_lowercase().contains(text)
                {
                    return true;
                }
            }
            ApplicationProtocol::Mqtt(info) => {
                if "mqtt".contains(text) {
                    return true;
                }
                if let Some(ref client_id) = info.client_id
                    && client_id.to_lowercase().contains(text)
                {
                    return true;
                }
                if let Some(ref topic) = info.topic
                    && topic.to_lowercase().contains(text)
                {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_general_filter() {
        let filter = ConnectionFilter::parse("google");
        assert_eq!(filter.criteria.len(), 1);
        matches!(filter.criteria[0], FilterCriteria::General(_));
    }

    #[test]
    fn test_parse_port_filter() {
        let filter = ConnectionFilter::parse("port:443");
        assert_eq!(filter.criteria.len(), 1);
        // Now uses partial matching for fuzzy search
        match &filter.criteria[0] {
            FilterCriteria::Port(text) => assert_eq!(text, "443"),
            _ => panic!("Expected Port filter"),
        }
    }

    #[test]
    fn test_parse_multiple_filters() {
        let filter = ConnectionFilter::parse("port:443 src:192.168");
        assert_eq!(filter.criteria.len(), 2);
    }

    #[test]
    fn test_parse_partial_port_filter() {
        let filter = ConnectionFilter::parse("port:44");
        assert_eq!(filter.criteria.len(), 1);
        // Port filters use partial matching for better fuzzy search
        match &filter.criteria[0] {
            FilterCriteria::Port(text) => assert_eq!(text, "44"),
            _ => panic!("Expected Port filter"),
        }
    }

    #[test]
    fn test_parse_sport_dport_filters() {
        let filter = ConnectionFilter::parse("sport:80 dport:443");
        assert_eq!(filter.criteria.len(), 2);

        // Check source port filter
        match &filter.criteria[0] {
            FilterCriteria::SourcePort(text) => assert_eq!(text, "80"),
            _ => panic!("Expected SourcePort filter"),
        }

        // Check destination port filter
        match &filter.criteria[1] {
            FilterCriteria::DestinationPort(text) => assert_eq!(text, "443"),
            _ => panic!("Expected DestinationPort filter"),
        }
    }

    #[test]
    fn test_parse_state_filter() {
        let filter = ConnectionFilter::parse("state:established");
        assert_eq!(filter.criteria.len(), 1);
        match &filter.criteria[0] {
            FilterCriteria::State(text) => assert_eq!(text, "established"),
            _ => panic!("Expected State filter"),
        }
    }

    #[test]
    fn test_state_filter_tcp_states() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Create a test connection in ESTABLISHED state
        let mut conn = Connection::new(
            Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );

        // Test matching established state
        let established_filter = ConnectionFilter::parse("state:established");
        assert!(established_filter.matches(&conn));

        // Test partial matching
        let est_filter = ConnectionFilter::parse("state:est");
        assert!(est_filter.matches(&conn));

        // Test case insensitive matching
        let upper_filter = ConnectionFilter::parse("state:ESTABLISHED");
        assert!(upper_filter.matches(&conn));

        // Test non-matching state
        let syn_filter = ConnectionFilter::parse("state:syn_recv");
        assert!(!syn_filter.matches(&conn));

        // Change connection to SYN_RECV state
        conn.protocol_state = ProtocolState::Tcp(TcpState::SynReceived);
        assert!(syn_filter.matches(&conn));
        assert!(!established_filter.matches(&conn));
    }

    #[test]
    fn test_state_filter_udp_states() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Create a fresh UDP connection (should show as UDP_ACTIVE)
        let conn = Connection::new(
            Protocol::UDP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            ProtocolState::Udp,
        );

        let active_filter = ConnectionFilter::parse("state:udp_active");
        assert!(active_filter.matches(&conn));

        let udp_filter = ConnectionFilter::parse("state:udp");
        assert!(udp_filter.matches(&conn));
    }

    #[test]
    fn test_combined_state_and_port_filter() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let conn = Connection::new(
            Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321),
            ProtocolState::Tcp(TcpState::SynReceived),
        );

        // Test combined filter: source port 443 AND SYN_RECV state
        let combined_filter = ConnectionFilter::parse("sport:443 state:syn_recv");
        assert!(combined_filter.matches(&conn));

        // Test that both conditions must match
        let wrong_port_filter = ConnectionFilter::parse("sport:80 state:syn_recv");
        assert!(!wrong_port_filter.matches(&conn));

        let wrong_state_filter = ConnectionFilter::parse("sport:443 state:established");
        assert!(!wrong_state_filter.matches(&conn));
    }

    #[test]
    fn test_state_filter_case_insensitive() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let conn = Connection::new(
            Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );

        // Test various case combinations
        let filters = vec![
            "state:established",
            "state:ESTABLISHED",
            "state:Established",
            "state:EstAbLiShEd",
        ];

        for filter_str in filters {
            let filter = ConnectionFilter::parse(filter_str);
            assert!(
                filter.matches(&conn),
                "Filter '{}' should match ESTABLISHED state",
                filter_str
            );
        }
    }
}
