use crate::network::types::{ApplicationProtocol, QuicInfo};
use log::{debug, warn};

mod cipher_suites;
mod dns;
mod http;
mod https;
mod quic;
mod ssh;

pub use cipher_suites::{format_cipher_suite, is_secure_cipher_suite};
pub use quic::{is_partial_sni, try_extract_tls_from_reassembler};

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
    if (local_port == 443 || remote_port == 443 || https::is_tls_handshake(payload))
        && let Some(tls_result) = https::analyze_https(payload)
    {
        return Some(DpiResult {
            application: ApplicationProtocol::Https(tls_result),
        });
    }

    // 3. Check for SSH (port 22 or SSH banner)
    if (local_port == 22 || remote_port == 22 || ssh::is_likely_ssh(payload))
        && let Some(ssh_result) = ssh::analyze_ssh(payload, _is_outgoing)
    {
        return Some(DpiResult {
            application: ApplicationProtocol::Ssh(ssh_result),
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
    if (local_port == 53 || remote_port == 53)
        && let Some(dns_result) = dns::analyze_dns(payload)
    {
        return Some(DpiResult {
            application: ApplicationProtocol::Dns(dns_result),
        });
    }

    // 2. QUIC/HTTP3 (port 443)
    if (local_port == 443 || remote_port == 443) && quic::is_quic_packet(payload) {
        let quic_info = quic::parse_quic_packet(payload);
        if let Some(quic_info) = quic_info {
            debug!("QUIC packet detected: {:?}", quic_info);
            return Some(DpiResult {
                application: ApplicationProtocol::Quic(Box::new(quic_info)),
            });
        } else {
            warn!("Failed to parse QUIC packet");
            let empty_quic_info = QuicInfo::new(0);

            return Some(DpiResult {
                application: ApplicationProtocol::Quic(Box::new(empty_quic_info)),
            });
        }
    }

    None
}
