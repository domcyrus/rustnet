//! Connection-list sort comparators, one per `SortColumn`. Pure
//! function: no UI state, no I/O — just reorders the slice in
//! place.

use crate::network::types::Connection;
use crate::ui::SortColumn;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn connection(port: u16) -> Connection {
        Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ProtocolState::Udp,
        )
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
}
