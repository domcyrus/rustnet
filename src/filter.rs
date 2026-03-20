use crate::network::types::{ApplicationProtocol, Connection, ProtocolState};
use regex_lite::Regex;

/// How to match a text field (case-insensitive for literals; regex handles its own flags)
#[derive(Debug, Clone)]
pub enum FilterValue {
    /// Case-insensitive substring match (existing default)
    Literal(String),
    /// Pre-compiled regex (compiled with (?i) prefix for case-insensitive matching)
    Regex(Regex),
}

/// How to match a port number
#[derive(Debug, Clone)]
pub enum PortMatch {
    /// Exact equality — default when the filter value is all digits
    Exact(u16),
    /// Substring match — fallback for non-numeric, non-regex values
    Partial(String),
    /// Pre-compiled regex
    Regex(Regex),
}

#[derive(Debug, Clone)]
pub enum FilterCriteria {
    /// Match any field containing this text
    General(FilterValue),
    /// Match port number (local or remote)
    Port(PortMatch),
    /// Match source port
    SourcePort(PortMatch),
    /// Match destination port
    DestinationPort(PortMatch),
    /// Match source IP address
    SourceIp(FilterValue),
    /// Match destination IP address
    DestinationIp(FilterValue),
    /// Match protocol (TCP, UDP, etc.)
    Protocol(FilterValue),
    /// Match process name
    Process(FilterValue),
    /// Match service name
    Service(FilterValue),
    /// Match SNI hostname from TLS/QUIC
    Sni(FilterValue),
    /// Match DPI application protocol
    Application(FilterValue),
    /// Match connection state (e.g., ESTABLISHED, SYN_RECV)
    State(FilterValue),
}

pub struct ConnectionFilter {
    pub criteria: Vec<FilterCriteria>,
}

/// Parse a filter value string into a `PortMatch`.
/// - `/pattern/`  → regex
/// - all-digit    → exact u16 equality
/// - anything else → substring contains
fn parse_port_match(value: &str) -> PortMatch {
    if value.starts_with('/') && value.ends_with('/') && value.len() > 2 {
        let pattern = &value[1..value.len() - 1];
        match Regex::new(pattern) {
            Ok(re) => PortMatch::Regex(re),
            Err(_) => PortMatch::Partial(value.to_string()),
        }
    } else if value.chars().all(|c| c.is_ascii_digit()) {
        value
            .parse::<u16>()
            .map(PortMatch::Exact)
            .unwrap_or_else(|_| PortMatch::Partial(value.to_string()))
    } else {
        PortMatch::Partial(value.to_string())
    }
}

/// Parse a filter value string into a `FilterValue`.
/// - `/pattern/`  → case-insensitive regex
/// - anything else → case-insensitive literal contains
fn parse_filter_value(value: &str) -> FilterValue {
    if value.starts_with('/') && value.ends_with('/') && value.len() > 2 {
        let pattern = &value[1..value.len() - 1];
        match Regex::new(&format!("(?i){pattern}")) {
            Ok(re) => FilterValue::Regex(re),
            Err(_) => FilterValue::Literal(value.to_string()),
        }
    } else {
        FilterValue::Literal(value.to_string())
    }
}

/// Match a port number against a `PortMatch`.
fn match_port(port: u16, m: &PortMatch) -> bool {
    match m {
        PortMatch::Exact(n) => port == *n,
        PortMatch::Partial(s) => port.to_string().contains(s.as_str()),
        PortMatch::Regex(re) => re.is_match(&port.to_string()),
    }
}

/// Match a haystack string against a `FilterValue`.
fn match_text(haystack: &str, fv: &FilterValue) -> bool {
    match fv {
        FilterValue::Literal(s) => haystack.to_lowercase().contains(s.as_str()),
        FilterValue::Regex(re) => re.is_match(haystack),
    }
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
                let value = value.to_lowercase();
                match keyword.to_lowercase().as_str() {
                    "port" => {
                        criteria.push(FilterCriteria::Port(parse_port_match(&value)));
                    }
                    "sport" | "srcport" | "source-port" => {
                        criteria.push(FilterCriteria::SourcePort(parse_port_match(&value)));
                    }
                    "dport" | "dstport" | "dest-port" | "destination-port" => {
                        criteria.push(FilterCriteria::DestinationPort(parse_port_match(&value)));
                    }
                    "src" | "source" => {
                        criteria.push(FilterCriteria::SourceIp(parse_filter_value(&value)));
                    }
                    "dst" | "dest" | "destination" => {
                        criteria.push(FilterCriteria::DestinationIp(parse_filter_value(&value)));
                    }
                    "proto" | "protocol" => {
                        criteria.push(FilterCriteria::Protocol(parse_filter_value(&value)));
                    }
                    "process" | "proc" => {
                        criteria.push(FilterCriteria::Process(parse_filter_value(&value)));
                    }
                    "service" | "svc" => {
                        criteria.push(FilterCriteria::Service(parse_filter_value(&value)));
                    }
                    "sni" | "host" | "hostname" => {
                        criteria.push(FilterCriteria::Sni(parse_filter_value(&value)));
                    }
                    "app" | "application" => {
                        criteria.push(FilterCriteria::Application(parse_filter_value(&value)));
                    }
                    "state" => {
                        criteria.push(FilterCriteria::State(parse_filter_value(&value)));
                    }
                    _ => {
                        // Unknown keyword, treat as general search
                        criteria.push(FilterCriteria::General(parse_filter_value(
                            &part.to_lowercase(),
                        )));
                    }
                }
            } else {
                // General text search
                criteria.push(FilterCriteria::General(parse_filter_value(
                    &part.to_lowercase(),
                )));
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
            FilterCriteria::General(fv) => self.matches_general(connection, fv),
            FilterCriteria::Port(pm) => {
                match_port(connection.local_addr.port(), pm)
                    || match_port(connection.remote_addr.port(), pm)
            }
            FilterCriteria::SourcePort(pm) => match_port(connection.local_addr.port(), pm),
            FilterCriteria::DestinationPort(pm) => match_port(connection.remote_addr.port(), pm),
            FilterCriteria::SourceIp(fv) => match_text(&connection.local_addr.ip().to_string(), fv),
            FilterCriteria::DestinationIp(fv) => {
                match_text(&connection.remote_addr.ip().to_string(), fv)
            }
            FilterCriteria::Protocol(fv) => match_text(&connection.protocol.to_string(), fv),
            FilterCriteria::Process(fv) => {
                if let Some(ref process_name) = connection.process_name {
                    match_text(process_name, fv)
                } else {
                    false
                }
            }
            FilterCriteria::Service(fv) => {
                if let Some(ref service_name) = connection.service_name {
                    match_text(service_name, fv)
                } else {
                    false
                }
            }
            FilterCriteria::Sni(fv) => self.matches_sni(connection, fv),
            FilterCriteria::Application(fv) => self.matches_application(connection, fv),
            FilterCriteria::State(fv) => match_text(&connection.state(), fv),
        })
    }

    /// Check if connection matches general text search across all fields
    fn matches_general(&self, connection: &Connection, fv: &FilterValue) -> bool {
        // Check basic connection info
        if match_text(&connection.protocol.to_string(), fv)
            || match_text(&connection.local_addr.to_string(), fv)
            || match_text(&connection.remote_addr.to_string(), fv)
        {
            return true;
        }

        // Check process info
        if let Some(ref process_name) = connection.process_name
            && match_text(process_name, fv)
        {
            return true;
        }

        // Check service info
        if let Some(ref service_name) = connection.service_name
            && match_text(service_name, fv)
        {
            return true;
        }

        // Check DPI info
        if let Some(ref dpi_info) = connection.dpi_info
            && self.matches_dpi_general(&dpi_info.application, fv)
        {
            return true;
        }

        // Check ARP vendor names
        if let ProtocolState::Arp(ref arp_info) = connection.protocol_state {
            if let Some(ref vendor) = arp_info.sender_vendor
                && match_text(vendor, fv)
            {
                return true;
            }
            if let Some(ref vendor) = arp_info.target_vendor
                && match_text(vendor, fv)
            {
                return true;
            }
        }

        false
    }

    /// Check if SNI matches the filter value
    fn matches_sni(&self, connection: &Connection, fv: &FilterValue) -> bool {
        if let Some(ref dpi_info) = connection.dpi_info {
            match &dpi_info.application {
                ApplicationProtocol::Https(info) => {
                    if let Some(ref tls_info) = info.tls_info
                        && let Some(ref sni) = tls_info.sni
                    {
                        return match_text(sni, fv);
                    }
                }
                ApplicationProtocol::Quic(info) => {
                    if let Some(ref tls_info) = info.tls_info
                        && let Some(ref sni) = tls_info.sni
                    {
                        return match_text(sni, fv);
                    }
                }
                ApplicationProtocol::Http(info) => {
                    if let Some(ref host) = info.host {
                        return match_text(host, fv);
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Check if application protocol matches the filter value
    fn matches_application(&self, connection: &Connection, fv: &FilterValue) -> bool {
        if let Some(ref dpi_info) = connection.dpi_info {
            match_text(&dpi_info.application.to_string(), fv)
        } else {
            false
        }
    }

    /// Check if DPI info matches general search
    fn matches_dpi_general(&self, application: &ApplicationProtocol, fv: &FilterValue) -> bool {
        // Check the application type display
        if match_text(&application.to_string(), fv) {
            return true;
        }

        // Check specific protocol details
        match application {
            ApplicationProtocol::Http(info) => {
                if let Some(ref host) = info.host
                    && match_text(host, fv)
                {
                    return true;
                }
                if let Some(ref path) = info.path
                    && match_text(path, fv)
                {
                    return true;
                }
                if let Some(ref method) = info.method
                    && match_text(method, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && match_text(sni, fv)
                    {
                        return true;
                    }
                    // Check ALPN protocols
                    for alpn in &tls_info.alpn {
                        if match_text(alpn, fv) {
                            return true;
                        }
                    }
                }
            }
            ApplicationProtocol::Dns(info) => {
                if let Some(ref query_name) = info.query_name
                    && match_text(query_name, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && match_text(sni, fv)
                    {
                        return true;
                    }
                    // Check ALPN protocols
                    for alpn in &tls_info.alpn {
                        if match_text(alpn, fv) {
                            return true;
                        }
                    }
                }
            }
            ApplicationProtocol::Ssh(info) => {
                if match_text("ssh", fv) {
                    return true;
                }

                // Check software names
                if let Some(ref software) = info.server_software
                    && match_text(software, fv)
                {
                    return true;
                }
                if let Some(ref software) = info.client_software
                    && match_text(software, fv)
                {
                    return true;
                }

                // Check connection state
                let state_str = format!("{:?}", info.connection_state).to_lowercase();
                if match_text(&state_str, fv) {
                    return true;
                }

                // Check algorithms
                for algo in &info.algorithms {
                    if match_text(algo, fv) {
                        return true;
                    }
                }
            }
            ApplicationProtocol::Ntp(_) => {
                if match_text("ntp", fv) {
                    return true;
                }
            }
            ApplicationProtocol::Mdns(info) => {
                if let Some(ref query_name) = info.query_name
                    && match_text(query_name, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Llmnr(info) => {
                if let Some(ref query_name) = info.query_name
                    && match_text(query_name, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Dhcp(info) => {
                if let Some(ref hostname) = info.hostname
                    && match_text(hostname, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Snmp(info) => {
                if let Some(ref community) = info.community
                    && match_text(community, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Ssdp(info) => {
                if let Some(ref service_type) = info.service_type
                    && match_text(service_type, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::NetBios(info) => {
                if let Some(ref name) = info.name
                    && match_text(name, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::BitTorrent(info) => {
                if match_text("bittorrent", fv) {
                    return true;
                }
                if let Some(ref client) = info.client
                    && match_text(client, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Stun(info) => {
                if match_text("stun", fv) {
                    return true;
                }
                if let Some(ref software) = info.software
                    && match_text(software, fv)
                {
                    return true;
                }
            }
            ApplicationProtocol::Mqtt(info) => {
                if match_text("mqtt", fv) {
                    return true;
                }
                if let Some(ref client_id) = info.client_id
                    && match_text(client_id, fv)
                {
                    return true;
                }
                if let Some(ref topic) = info.topic
                    && match_text(topic, fv)
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
        match &filter.criteria[0] {
            FilterCriteria::Port(PortMatch::Exact(n)) => assert_eq!(*n, 443),
            _ => panic!("Expected Port(Exact(443))"),
        }
    }

    #[test]
    fn test_parse_multiple_filters() {
        let filter = ConnectionFilter::parse("port:443 src:192.168");
        assert_eq!(filter.criteria.len(), 2);
    }

    #[test]
    fn test_parse_port_exact_match() {
        // port:44 should now be an exact match for port 44, not partial
        let filter = ConnectionFilter::parse("port:44");
        match &filter.criteria[0] {
            FilterCriteria::Port(PortMatch::Exact(n)) => assert_eq!(*n, 44),
            _ => panic!("Expected Port(Exact(44))"),
        }
    }

    #[test]
    fn test_parse_port_regex() {
        let filter = ConnectionFilter::parse("port:/22/");
        match &filter.criteria[0] {
            FilterCriteria::Port(PortMatch::Regex(_)) => {}
            _ => panic!("Expected Port(Regex)"),
        }
    }

    #[test]
    fn test_parse_sport_dport_filters() {
        let filter = ConnectionFilter::parse("sport:80 dport:443");
        assert_eq!(filter.criteria.len(), 2);

        match &filter.criteria[0] {
            FilterCriteria::SourcePort(PortMatch::Exact(n)) => assert_eq!(*n, 80),
            _ => panic!("Expected SourcePort(Exact(80))"),
        }

        match &filter.criteria[1] {
            FilterCriteria::DestinationPort(PortMatch::Exact(n)) => assert_eq!(*n, 443),
            _ => panic!("Expected DestinationPort(Exact(443))"),
        }
    }

    #[test]
    fn test_parse_state_filter() {
        let filter = ConnectionFilter::parse("state:established");
        assert_eq!(filter.criteria.len(), 1);
        match &filter.criteria[0] {
            FilterCriteria::State(_) => {}
            _ => panic!("Expected State filter"),
        }
    }

    #[test]
    fn test_port_exact_no_partial_match() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // port:22 should NOT match port 2223 or 5522
        let conn_2223 = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 2223),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );
        let conn_5522 = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5522),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );
        let conn_22 = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 22),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );

        let filter = ConnectionFilter::parse("port:22");
        assert!(
            !filter.matches(&conn_2223),
            "port:22 must not match port 2223"
        );
        assert!(
            !filter.matches(&conn_5522),
            "port:22 must not match port 5522"
        );
        assert!(filter.matches(&conn_22), "port:22 must match port 22");
    }

    #[test]
    fn test_port_regex_partial_match() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // port:/22/ should match 22, 220, 2200, 5522
        let make_conn = |local_port: u16| {
            Connection::new(
                Protocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), local_port),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
                ProtocolState::Tcp(TcpState::Established),
            )
        };

        let filter = ConnectionFilter::parse("port:/22/");
        assert!(filter.matches(&make_conn(22)));
        assert!(filter.matches(&make_conn(220)));
        assert!(filter.matches(&make_conn(2200)));
        assert!(filter.matches(&make_conn(5522)));
        assert!(!filter.matches(&make_conn(80)));
    }

    #[test]
    fn test_state_filter_tcp_states() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );

        let established_filter = ConnectionFilter::parse("state:established");
        assert!(established_filter.matches(&conn));

        let est_filter = ConnectionFilter::parse("state:est");
        assert!(est_filter.matches(&conn));

        let upper_filter = ConnectionFilter::parse("state:ESTABLISHED");
        assert!(upper_filter.matches(&conn));

        let syn_filter = ConnectionFilter::parse("state:syn_recv");
        assert!(!syn_filter.matches(&conn));

        conn.protocol_state = ProtocolState::Tcp(TcpState::SynReceived);
        assert!(syn_filter.matches(&conn));
        assert!(!established_filter.matches(&conn));
    }

    #[test]
    fn test_state_filter_udp_states() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let conn = Connection::new(
            Protocol::Udp,
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
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321),
            ProtocolState::Tcp(TcpState::SynReceived),
        );

        let combined_filter = ConnectionFilter::parse("sport:443 state:syn_recv");
        assert!(combined_filter.matches(&conn));

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
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        );

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

    #[test]
    fn test_regex_general_search() {
        use crate::network::types::*;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443),
            ProtocolState::Tcp(TcpState::Established),
        );

        // Regex matching IP pattern
        let filter = ConnectionFilter::parse("/192\\.168\\.[0-9]+/");
        assert!(filter.matches(&conn));

        // Should not match unrelated connection
        let conn2 = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            ProtocolState::Tcp(TcpState::Established),
        );
        assert!(!filter.matches(&conn2));
    }

    #[test]
    fn test_invalid_regex_falls_back_to_literal() {
        // An invalid regex pattern should fall back to literal match without panicking
        let filter = ConnectionFilter::parse("port:/[invalid/");
        // Should have created a PortMatch::Partial (fallback)
        match &filter.criteria[0] {
            FilterCriteria::Port(PortMatch::Partial(_)) => {}
            _ => panic!("Expected fallback to Partial for invalid regex"),
        }
    }
}
