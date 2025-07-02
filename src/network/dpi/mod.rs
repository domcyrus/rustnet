use crate::network::types::ApplicationProtocol;

mod dns;
mod http;
mod quic;
mod tls;

/// Result of DPI analysis
#[derive(Debug, Clone)]
pub struct DpiResult {
    pub application: ApplicationProtocol,
    #[allow(dead_code)]
    pub confidence: f32, // 0.0 to 1.0 (not used for merging per user request)
    #[allow(dead_code)]
    pub needs_more_data: bool, // True if more packets would help
}

/// Analyze a TCP packet payload
pub fn analyze_tcp_packet(
    payload: &[u8],
    local_port: u16,
    remote_port: u16,
    _is_outgoing: bool,
) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    // Try protocols in order of likelihood/speed

    // 1. Check for HTTP (fast string matching)
    if let Some(http_result) = http::analyze_http(payload) {
        return Some(DpiResult {
            application: ApplicationProtocol::Http(http_result),
            confidence: 1.0,
            needs_more_data: false,
        });
    }

    // 2. Check for TLS/HTTPS (port 443 or TLS handshake)
    if local_port == 443 || remote_port == 443 || tls::is_tls_handshake(payload) {
        if let Some(tls_result) = tls::analyze_tls(payload) {
            return Some(DpiResult {
                application: ApplicationProtocol::Https(tls_result),
                confidence: 1.0,
                needs_more_data: false,
            });
        }
    }

    // 3. Check for SSH (port 22 or SSH banner)
    if local_port == 22 || remote_port == 22 || payload.starts_with(b"SSH-") {
        return Some(DpiResult {
            application: ApplicationProtocol::Ssh,
            confidence: 1.0,
            needs_more_data: false,
        });
    }

    // More protocols here...

    None
}

/// Analyze a UDP packet payload
pub fn analyze_udp_packet(
    payload: &[u8],
    local_port: u16,
    remote_port: u16,
    _is_outgoing: bool,
) -> Option<DpiResult> {
    if payload.is_empty() {
        return None;
    }

    // 1. DNS (port 53)
    if local_port == 53 || remote_port == 53 {
        if let Some(dns_result) = dns::analyze_dns(payload) {
            return Some(DpiResult {
                application: ApplicationProtocol::Dns(dns_result),
                confidence: 1.0,
                needs_more_data: false,
            });
        }
    }

    // 2. QUIC/HTTP3 (port 443)
    if (local_port == 443 || remote_port == 443) && quic::is_quic_packet(payload) {
        return Some(DpiResult {
            application: ApplicationProtocol::Quic,
            confidence: 0.9, // QUIC detection is less certain
            needs_more_data: true,
        });
    }

    None
}
