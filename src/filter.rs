//! Vim/fzf-style connection filter: parses `port:`, `src:`, `dst:`,
//! `sni:`, `process:`, `state:`, `proto:`, (and `pod:`, `ns:`,
//! `container:` when the `kubernetes` feature is enabled) keyword
//! expressions (with
//! optional `(?i)…` regex literals via `regex-lite`) and matches them
//! against live `Connection` records.

use crate::network::types::{ApplicationProtocol, Connection, ProtocolState};
use regex_lite::Regex;

/// How to match a text field (case-insensitive for literals; regex handles its own flags)
#[derive(Debug, Clone)]
enum FilterValue {
    /// Case-insensitive substring match (existing default)
    Literal(String),
    /// Pre-compiled regex (compiled with (?i) prefix for case-insensitive matching)
    Regex(Regex),
}

/// How to match a port number
#[derive(Debug, Clone)]
enum PortMatch {
    /// Exact equality — default when the filter value is all digits
    Exact(u16),
    /// Substring match — fallback for non-numeric, non-regex values
    Partial(String),
    /// Pre-compiled regex
    Regex(Regex),
}

#[derive(Debug, Clone)]
enum FilterCriteria {
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
    /// Match Kubernetes pod name or UID
    #[cfg(feature = "kubernetes")]
    Pod(FilterValue),
    /// Match Kubernetes pod namespace
    #[cfg(feature = "kubernetes")]
    Namespace(FilterValue),
    /// Match Kubernetes container name or ID
    #[cfg(feature = "kubernetes")]
    Container(FilterValue),
}

pub struct ConnectionFilter {
    criteria: Vec<FilterCriteria>,
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

/// True when any of the present (`Some`) optional text fields matches the
/// filter value; absent fields are skipped.
fn any_text_matches<'a>(
    fv: &FilterValue,
    fields: impl IntoIterator<Item = Option<&'a str>>,
) -> bool {
    fields.into_iter().flatten().any(|s| match_text(s, fv))
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
                    #[cfg(feature = "kubernetes")]
                    "pod" => {
                        criteria.push(FilterCriteria::Pod(parse_filter_value(&value)));
                    }
                    #[cfg(feature = "kubernetes")]
                    "ns" | "namespace" => {
                        criteria.push(FilterCriteria::Namespace(parse_filter_value(&value)));
                    }
                    #[cfg(feature = "kubernetes")]
                    "container" | "cont" => {
                        criteria.push(FilterCriteria::Container(parse_filter_value(&value)));
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
            FilterCriteria::Protocol(fv) => match_text(connection.protocol.as_str(), fv),
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
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Pod(fv) => connection.k8s_info.as_ref().is_some_and(|k| {
                k.pod_name.as_deref().is_some_and(|n| match_text(n, fv))
                    || k.pod_uid.as_deref().is_some_and(|u| match_text(u, fv))
            }),
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Namespace(fv) => connection.k8s_info.as_ref().is_some_and(|k| {
                k.pod_namespace
                    .as_deref()
                    .is_some_and(|ns| match_text(ns, fv))
            }),
            #[cfg(feature = "kubernetes")]
            FilterCriteria::Container(fv) => connection.k8s_info.as_ref().is_some_and(|k| {
                k.container_name
                    .as_deref()
                    .is_some_and(|n| match_text(n, fv))
                    || k.container_id.as_deref().is_some_and(|c| match_text(c, fv))
            }),
        })
    }

    /// Check if connection matches general text search across all fields:
    /// basic connection info, process, service, DPI details, the
    /// DNS-attributed hostname and ARP vendor names
    fn matches_general(&self, connection: &Connection, fv: &FilterValue) -> bool {
        let (arp_sender_vendor, arp_target_vendor) = match connection.protocol_state {
            ProtocolState::Arp(ref arp_info) => (
                arp_info.sender_vendor.as_deref(),
                arp_info.target_vendor.as_deref(),
            ),
            _ => (None, None),
        };

        match_text(connection.protocol.as_str(), fv)
            || match_text(&connection.local_addr.to_string(), fv)
            || match_text(&connection.remote_addr.to_string(), fv)
            || any_text_matches(
                fv,
                [
                    connection.process_name.as_deref(),
                    connection.service_name.as_deref(),
                    connection
                        .attributed_hostname
                        .as_ref()
                        .map(|att| att.name.as_str()),
                    arp_sender_vendor,
                    arp_target_vendor,
                ],
            )
            || connection
                .dpi_info
                .as_ref()
                .is_some_and(|dpi_info| self.matches_dpi_general(&dpi_info.application, fv))
    }

    /// Check if SNI or a DNS-attributed hostname matches the filter
    /// value (DNS query names are not considered; use the DNS-aware
    /// filters for those)
    fn matches_sni(&self, connection: &Connection, fv: &FilterValue) -> bool {
        if let Some(ref dpi_info) = connection.dpi_info
            && let Some(hostname) = dpi_info.application.hostname()
            && match_text(hostname, fv)
        {
            return true;
        }
        connection
            .attributed_hostname
            .as_ref()
            .is_some_and(|att| match_text(&att.name, fv))
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
            ApplicationProtocol::Http(info) => any_text_matches(
                fv,
                [
                    info.host.as_deref(),
                    info.path.as_deref(),
                    info.method.as_deref(),
                ],
            ),
            ApplicationProtocol::Https(_) | ApplicationProtocol::Quic(_) => {
                application.tls_info().is_some_and(|tls_info| {
                    // Check SNI and ALPN protocols
                    any_text_matches(
                        fv,
                        std::iter::once(tls_info.sni.as_deref())
                            .chain(tls_info.alpn.iter().map(|alpn| Some(alpn.as_str()))),
                    )
                })
            }
            ApplicationProtocol::Dns(info) => any_text_matches(fv, [info.query_name.as_deref()]),
            ApplicationProtocol::Ssh(info) => {
                // Check the connection state alongside software names and
                // algorithms
                let state_str = format!("{:?}", info.connection_state).to_lowercase();
                match_text("ssh", fv)
                    || any_text_matches(
                        fv,
                        [
                            info.server_software.as_deref(),
                            info.client_software.as_deref(),
                            Some(state_str.as_str()),
                        ]
                        .into_iter()
                        .chain(info.algorithms.iter().map(|algo| Some(algo.as_str()))),
                    )
            }
            ApplicationProtocol::Ntp(_) => match_text("ntp", fv),
            ApplicationProtocol::Ftp(info) => {
                let response_code = info.response_code.map(|code| code.to_string());
                match_text("ftp", fv)
                    || any_text_matches(
                        fv,
                        [
                            info.command.as_deref(),
                            info.username.as_deref(),
                            info.server_software.as_deref(),
                            info.system_type.as_deref(),
                            response_code.as_deref(),
                        ],
                    )
            }
            ApplicationProtocol::Mdns(info) => any_text_matches(fv, [info.query_name.as_deref()]),
            ApplicationProtocol::Llmnr(info) => any_text_matches(fv, [info.query_name.as_deref()]),
            ApplicationProtocol::Dhcp(info) => any_text_matches(fv, [info.hostname.as_deref()]),
            ApplicationProtocol::Snmp(info) => any_text_matches(fv, [info.community.as_deref()]),
            ApplicationProtocol::Ssdp(info) => any_text_matches(fv, [info.service_type.as_deref()]),
            ApplicationProtocol::NetBios(info) => any_text_matches(fv, [info.name.as_deref()]),
            ApplicationProtocol::BitTorrent(info) => {
                match_text("bittorrent", fv) || any_text_matches(fv, [info.client.as_deref()])
            }
            ApplicationProtocol::Stun(info) => {
                match_text("stun", fv) || any_text_matches(fv, [info.software.as_deref()])
            }
            ApplicationProtocol::Mqtt(info) => {
                match_text("mqtt", fv)
                    || any_text_matches(fv, [info.client_id.as_deref(), info.topic.as_deref()])
            }
            ApplicationProtocol::WireGuard(info) => match_text(&info.packet_type.to_string(), fv),
            ApplicationProtocol::OpenVpn(info) => {
                match_text(&info.packet_type.to_string(), fv)
                    || match_text(&info.key_id.to_string(), fv)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, TcpState};

    /// Connection fixture: TCP flows come up `Established`, UDP flows in the
    /// plain `Udp` state. Tests needing another state override
    /// `protocol_state` after construction.
    fn conn(protocol: Protocol, local: &str, remote: &str) -> Connection {
        let state = match protocol {
            Protocol::Udp => ProtocolState::Udp,
            _ => ProtocolState::Tcp(TcpState::Established),
        };
        Connection::new(
            protocol,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            state,
        )
    }

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
        // port:22 should NOT match port 2223 or 5522
        let conn_2223 = conn(Protocol::Tcp, "127.0.0.1:2223", "10.0.0.1:80");
        let conn_5522 = conn(Protocol::Tcp, "127.0.0.1:5522", "10.0.0.1:80");
        let conn_22 = conn(Protocol::Tcp, "127.0.0.1:22", "10.0.0.1:80");

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
        // port:/22/ should match 22, 220, 2200, 5522
        let make_conn = |local_port: u16| {
            conn(
                Protocol::Tcp,
                &format!("127.0.0.1:{local_port}"),
                "10.0.0.1:80",
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
        let mut conn = conn(Protocol::Tcp, "127.0.0.1:12345", "10.0.0.1:80");

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
        let conn = conn(Protocol::Udp, "127.0.0.1:12345", "8.8.8.8:53");

        let active_filter = ConnectionFilter::parse("state:udp_active");
        assert!(active_filter.matches(&conn));

        let udp_filter = ConnectionFilter::parse("state:udp");
        assert!(udp_filter.matches(&conn));
    }

    #[test]
    fn test_combined_state_and_port_filter() {
        let mut conn = conn(Protocol::Tcp, "0.0.0.0:443", "192.168.1.100:54321");
        conn.protocol_state = ProtocolState::Tcp(TcpState::SynReceived);

        let combined_filter = ConnectionFilter::parse("sport:443 state:syn_recv");
        assert!(combined_filter.matches(&conn));

        let wrong_port_filter = ConnectionFilter::parse("sport:80 state:syn_recv");
        assert!(!wrong_port_filter.matches(&conn));

        let wrong_state_filter = ConnectionFilter::parse("sport:443 state:established");
        assert!(!wrong_state_filter.matches(&conn));
    }

    #[test]
    fn test_state_filter_case_insensitive() {
        let conn = conn(Protocol::Tcp, "127.0.0.1:12345", "10.0.0.1:80");

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
        let conn_private = conn(Protocol::Tcp, "192.168.1.100:12345", "10.0.0.1:443");

        // Regex matching IP pattern
        let filter = ConnectionFilter::parse("/192\\.168\\.[0-9]+/");
        assert!(filter.matches(&conn_private));

        // Should not match unrelated connection
        let conn2 = conn(Protocol::Tcp, "10.0.0.1:12345", "8.8.8.8:53");
        assert!(!filter.matches(&conn2));
    }

    #[test]
    fn test_attributed_hostname_matches_hostname_and_general_filters() {
        use crate::network::types::{AttributedHostname, AttributionSource};
        use std::time::SystemTime;

        let mut conn = conn(Protocol::Tcp, "192.168.1.100:12345", "142.250.1.1:443");
        conn.attributed_hostname = Some(AttributedHostname {
            name: "youtube.com".to_string(),
            source: AttributionSource::CapturedDns,
            observed_at: SystemTime::now(),
        });

        // The attributed name has no SNI/Host backing, but a row shown
        // as ~youtube.com must still be findable by name.
        assert!(ConnectionFilter::parse("hostname:youtube.com").matches(&conn));
        assert!(ConnectionFilter::parse("youtube").matches(&conn));
        assert!(!ConnectionFilter::parse("hostname:example.org").matches(&conn));
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

    #[cfg(feature = "kubernetes")]
    #[test]
    fn test_kubernetes_filter_keywords() {
        use crate::network::types::K8sInfo;

        // Built up front: `conn` below shadows the fixture fn.
        let bare = conn(Protocol::Tcp, "127.0.0.1:12345", "10.0.0.1:80");
        let mut conn = conn(Protocol::Tcp, "127.0.0.1:12345", "10.0.0.1:80");
        conn.k8s_info = Some(K8sInfo {
            pod_uid: Some("c3b4d893-473e-43c2-8013-8ee2955a4630".to_string()),
            pod_name: Some("nginx-86644db9cc-mf5lx".to_string()),
            pod_namespace: Some("demo-traffic".to_string()),
            container_id: Some(
                "c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b".to_string(),
            ),
            container_name: Some("nginx".to_string()),
            cgroup_path: None,
        });

        // pod: matches by name (substring)
        assert!(ConnectionFilter::parse("pod:nginx").matches(&conn));
        // pod: matches by UID prefix
        assert!(ConnectionFilter::parse("pod:c3b4d893").matches(&conn));
        // ns: matches namespace
        assert!(ConnectionFilter::parse("ns:demo-traffic").matches(&conn));
        assert!(ConnectionFilter::parse("namespace:demo").matches(&conn));
        // container: matches by name and by ID prefix
        assert!(ConnectionFilter::parse("container:nginx").matches(&conn));
        assert!(ConnectionFilter::parse("container:c16c7605").matches(&conn));
        // Negative cases
        assert!(!ConnectionFilter::parse("pod:redis").matches(&conn));
        assert!(!ConnectionFilter::parse("ns:kube-system").matches(&conn));
        assert!(!ConnectionFilter::parse("container:redis").matches(&conn));

        // Combined filter
        assert!(ConnectionFilter::parse("ns:demo-traffic pod:nginx").matches(&conn));

        // Filter on connections without K8s info returns no match for any pod filter.
        assert!(!ConnectionFilter::parse("pod:nginx").matches(&bare));
        assert!(!ConnectionFilter::parse("ns:demo").matches(&bare));
        assert!(!ConnectionFilter::parse("container:nginx").matches(&bare));
    }
}
