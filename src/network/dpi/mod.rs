use crate::network::types::ApplicationProtocol;

mod dns;
mod http;
mod quic;
mod tls;

/// Result of DPI analysis
#[derive(Debug, Clone)]
pub struct DpiResult {
    pub application: ApplicationProtocol,
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
        });
    }

    // 2. Check for TLS/HTTPS (port 443 or TLS handshake)
    if local_port == 443 || remote_port == 443 || tls::is_tls_handshake(payload) {
        if let Some(tls_result) = tls::analyze_tls(payload) {
            return Some(DpiResult {
                application: ApplicationProtocol::Https(tls_result),
            });
        }
    }

    // 3. Check for SSH (port 22 or SSH banner)
    if local_port == 22 || remote_port == 22 || payload.starts_with(b"SSH-") {
        return Some(DpiResult {
            application: ApplicationProtocol::Ssh,
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
            });
        }
    }

    // 2. QUIC/HTTP3 (port 443)
    if (local_port == 443 || remote_port == 443) && quic::is_quic_packet(payload) {
        return Some(DpiResult {
            application: ApplicationProtocol::Quic,
        });
    }

    None
}
