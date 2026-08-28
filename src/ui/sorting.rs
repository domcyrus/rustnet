//! Connection-list sort comparators, one per `SortColumn`. Pure
//! function: no UI state, no I/O — just reorders the slice in
//! place.

use crate::network::types::Connection;
use crate::ui::SortColumn;
use crate::ui::connection_table::{HealthKind, health_counts};

/// Sort `connections` in place by the chosen column. `ascending`
/// flips the comparator's ordering after the column-specific cmp.
pub fn sort_connections(connections: &mut [Connection], sort_column: SortColumn, ascending: bool) {
    connections.sort_by(|a, b| {
        let ordering = match sort_column {
            SortColumn::CreatedAt => a.created_at.cmp(&b.created_at),

            SortColumn::BandwidthTotal => {
                // Compare combined up+down bandwidth, handle NaN cases
                let a_total = if a.is_historic {
                    0.0
                } else {
                    a.current_incoming_rate_bps + a.current_outgoing_rate_bps
                };
                let b_total = if b.is_historic {
                    0.0
                } else {
                    b.current_incoming_rate_bps + b.current_outgoing_rate_bps
                };
                a_total
                    .partial_cmp(&b_total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::Process => {
                let a_process = a.process_name.as_deref().unwrap_or("");
                let b_process = b.process_name.as_deref().unwrap_or("");
                // Case-insensitive, so macOS-style mixed-case names don't
                // split into separate alphabetical runs.
                a_process
                    .to_lowercase()
                    .cmp(&b_process.to_lowercase())
                    .then_with(|| a_process.cmp(b_process))
            }

            SortColumn::LocalAddress => a
                .local_addr
                .ip()
                .cmp(&b.local_addr.ip())
                .then_with(|| a.local_addr.port().cmp(&b.local_addr.port())),

            SortColumn::RemoteAddress => a
                .remote_addr
                .ip()
                .cmp(&b.remote_addr.ip())
                .then_with(|| a.remote_addr.port().cmp(&b.remote_addr.port())),

            SortColumn::Application => {
                // The App column shows "{proto}·{application}", so rows
                // without DPI info (None sorts first) still order
                // meaningfully by the protocol tie-break.
                let a_app = a.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                let b_app = b.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                a_app.cmp(&b_app).then_with(|| a.protocol.cmp(&b.protocol))
            }

            SortColumn::Service => {
                let a_service = a.service_name.as_deref().unwrap_or("");
                let b_service = b.service_name.as_deref().unwrap_or("");
                a_service
                    .to_lowercase()
                    .cmp(&b_service.to_lowercase())
                    .then_with(|| a_service.cmp(b_service))
            }

            SortColumn::State => Ord::cmp(&a.state(), &b.state()),

            SortColumn::Rtt => {
                // Connections without a measurement compare as zero, so the
                // default descending order puts them last, after the slowest
                // measured connection.
                let a_rtt = a.current_rtt().unwrap_or_default();
                let b_rtt = b.current_rtt().unwrap_or_default();
                a_rtt.cmp(&b_rtt)
            }

            SortColumn::Health => health_sort_key(a).cmp(&health_sort_key(b)),

            SortColumn::Location => {
                let a_loc = a
                    .geoip_info
                    .as_ref()
                    .and_then(|g| g.country_code.as_deref())
                    .unwrap_or("");
                let b_loc = b
                    .geoip_info
                    .as_ref()
                    .and_then(|g| g.country_code.as_deref())
                    .unwrap_or("");
                a_loc.cmp(b_loc)
            }
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

/// Rank observed health by severity first, then by total and severe events.
/// A timeout or TCP retransmit stays above any number of warning-only signals.
fn health_sort_key(connection: &Connection) -> (u8, u64, u64) {
    let (severe, warning) = match health_counts(connection) {
        Some((HealthKind::Tcp, retransmits, out_of_order)) => (retransmits, out_of_order),
        Some((HealthKind::Quic, retries, version_negotiations)) => {
            (0, retries.saturating_add(version_negotiations))
        }
        Some((HealthKind::Transaction, retries, timeouts)) => (timeouts, retries),
        None => (0, 0),
    };
    let severity = if severe > 0 {
        2
    } else if warning > 0 {
        1
    } else {
        0
    };
    (severity, severe.saturating_add(warning), severe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{
        ApplicationProtocol, DnsInfo, DnsQueryType, DpiInfo, Protocol, ProtocolState, QuicInfo,
        TcpState,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn connection(port: u16) -> Connection {
        Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ProtocolState::Udp,
        )
    }

    fn tcp_connection(port: u16) -> Connection {
        Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    fn dns_connection(port: u16) -> Connection {
        let mut conn = connection(port);
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(DnsInfo {
                query_name: Some("example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_ips: Vec::new(),
                is_response: false,
                txid: 1,
                rcode: None,
                nodata: None,
            }),
        });
        conn.protocol_health.request_observed = true;
        conn
    }

    fn quic_connection(port: u16) -> Connection {
        let mut conn = connection(port);
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(QuicInfo::new(1))),
        });
        conn
    }

    #[test]
    fn historic_cached_rate_does_not_affect_bandwidth_sort() {
        let mut live = connection(40_000);
        live.current_incoming_rate_bps = 1.0;

        let mut historic = connection(40_001);
        historic.is_historic = true;
        historic.current_incoming_rate_bps = 1_000.0;

        let mut connections = vec![historic, live];
        sort_connections(&mut connections, SortColumn::BandwidthTotal, false);

        assert!(!connections[0].is_historic);
        assert!(connections[1].is_historic);
    }

    #[test]
    fn process_sort_ignores_case() {
        let mut upper = connection(40_000);
        upper.process_name = Some("Safari".to_string());
        let mut lower = connection(40_001);
        lower.process_name = Some("curl".to_string());
        let mut upper2 = connection(40_002);
        upper2.process_name = Some("WindowServer".to_string());

        let mut connections = vec![upper, lower, upper2];
        sort_connections(&mut connections, SortColumn::Process, true);

        let names: Vec<_> = connections
            .iter()
            .map(|c| c.process_name.as_deref().unwrap())
            .collect();
        assert_eq!(names, ["curl", "Safari", "WindowServer"]);
    }

    #[test]
    fn health_sort_puts_most_affected_connections_first() {
        let healthy = tcp_connection(40_000);
        let mut out_of_order = tcp_connection(40_001);
        out_of_order
            .tcp_analytics
            .as_mut()
            .unwrap()
            .out_of_order_count = 2;
        let mut retransmits = tcp_connection(40_002);
        retransmits.tcp_analytics.as_mut().unwrap().retransmit_count = 3;

        let mut connections = vec![healthy, out_of_order, retransmits];
        sort_connections(&mut connections, SortColumn::Health, false);

        let event_counts: Vec<_> = connections
            .iter()
            .map(|connection| {
                connection.tcp_analytics.as_ref().map_or(0, |analytics| {
                    analytics.retransmit_count + analytics.out_of_order_count
                })
            })
            .collect();
        assert_eq!(event_counts, [3, 2, 0]);
    }

    #[test]
    fn health_sort_uses_protocol_aware_severity_tiers() {
        let healthy = connection(40_000);
        let mut retries = dns_connection(40_001);
        retries.protocol_health.request_retry_count = 4;
        let mut quic = quic_connection(40_002);
        quic.protocol_health.quic_retry_count = 6;
        let mut timeout = dns_connection(40_003);
        timeout.protocol_health.request_timeout_count = 1;

        let mut connections = vec![healthy, retries, quic, timeout];
        sort_connections(&mut connections, SortColumn::Health, false);

        let ports: Vec<_> = connections
            .iter()
            .map(|connection| connection.local_addr.port())
            .collect();
        assert_eq!(ports, [40_003, 40_002, 40_001, 40_000]);
        assert_eq!(health_sort_key(&connections[0]), (2, 1, 1));
        assert_eq!(health_sort_key(&connections[1]), (1, 6, 0));
    }
}
