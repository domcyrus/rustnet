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
        self.criteria.iter().all(|criterion| {
            match criterion {
                FilterCriteria::General(text) => self.matches_general(connection, text),
                FilterCriteria::Port(port_text) => {
                    connection.local_addr.port().to_string().contains(port_text)
                        || connection.remote_addr.port().to_string().contains(port_text)
                }
                FilterCriteria::SourcePort(port_text) => {
                    connection.local_addr.port().to_string().contains(port_text)
                }
                FilterCriteria::DestinationPort(port_text) => {
                    connection.remote_addr.port().to_string().contains(port_text)
                }
                FilterCriteria::SourceIp(ip_text) => {
                    connection.local_addr.ip().to_string().to_lowercase().contains(ip_text)
                }
                FilterCriteria::DestinationIp(ip_text) => {
                    connection.remote_addr.ip().to_string().to_lowercase().contains(ip_text)
                }
                FilterCriteria::Protocol(proto_text) => {
                    connection.protocol.to_string().to_lowercase().contains(proto_text)
                }
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
            }
        })
    }

    /// Check if connection matches general text search across all fields
    fn matches_general(&self, connection: &Connection, text: &str) -> bool {
        // Check basic connection info
        if connection.protocol.to_string().to_lowercase().contains(text)
            || connection.local_addr.to_string().to_lowercase().contains(text)
            || connection.remote_addr.to_string().to_lowercase().contains(text)
        {
            return true;
        }

        // Check process info
        if let Some(ref process_name) = connection.process_name
            && process_name.to_lowercase().contains(text) {
                return true;
            }

        // Check service info
        if let Some(ref service_name) = connection.service_name
            && service_name.to_lowercase().contains(text) {
                return true;
            }

        // Check DPI info
        if let Some(ref dpi_info) = connection.dpi_info
            && self.matches_dpi_general(&dpi_info.application, text) {
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
                        && let Some(ref sni) = tls_info.sni {
                            return sni.to_lowercase().contains(sni_text);
                        }
                }
                ApplicationProtocol::Quic(info) => {
                    if let Some(ref tls_info) = info.tls_info
                        && let Some(ref sni) = tls_info.sni {
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
            dpi_info.application.to_string().to_lowercase().contains(app_text)
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
                    && host.to_lowercase().contains(text) {
                        return true;
                    }
                if let Some(ref path) = info.path
                    && path.to_lowercase().contains(text) {
                        return true;
                    }
                if let Some(ref method) = info.method
                    && method.to_lowercase().contains(text) {
                        return true;
                    }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && sni.to_lowercase().contains(text) {
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
                    && query_name.to_lowercase().contains(text) {
                        return true;
                    }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(ref tls_info) = info.tls_info {
                    if let Some(ref sni) = tls_info.sni
                        && sni.to_lowercase().contains(text) {
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
            ApplicationProtocol::Ssh => {
                if "ssh".contains(text) {
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
}