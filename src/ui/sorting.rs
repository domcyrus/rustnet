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
                let a_total = a.current_incoming_rate_bps + a.current_outgoing_rate_bps;
                let b_total = b.current_incoming_rate_bps + b.current_outgoing_rate_bps;
                a_total
                    .partial_cmp(&b_total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::Process => {
                let a_process = a.process_name.as_deref().unwrap_or("");
                let b_process = b.process_name.as_deref().unwrap_or("");
                a_process.cmp(b_process)
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
                let a_app = a.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                let b_app = b.dpi_info.as_ref().map(|dpi| dpi.application.sort_key());
                a_app.cmp(&b_app)
            }

            SortColumn::Service => {
                let a_service = a.service_name.as_deref().unwrap_or("");
                let b_service = b.service_name.as_deref().unwrap_or("");
                a_service.cmp(b_service)
            }

            SortColumn::State => Ord::cmp(&a.state(), &b.state()),

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

            SortColumn::Protocol => a.protocol.cmp(&b.protocol),
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}
