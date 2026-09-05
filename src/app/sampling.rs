//! Periodic sampling threads: UI snapshots, idle-rate refresh, interface
//! stats, traffic history, and connection cleanup.

use anyhow::Result;
use dashmap::DashMap;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime};

use crate::network::{
    interface_stats::InterfaceStats,
    services::ServiceLookup,
    tracker::ConnectionTracker,
    types::{Connection, ConnectionLifecycleSample},
};

use super::logging::log_connection_closed;
use super::runtime::RuntimeSupervisor;
use super::state::App;
use super::{LIVE_RATE_INTERVAL, MIN_RATE_SAMPLE_SECONDS, TRAFFIC_HISTORY_CAPACITY};

/// Spawn a named worker thread that runs `body` every `interval` until
/// shutdown is requested.
///
/// The started/stopping log lines are passed in verbatim rather than derived
/// from the thread name: the existing workers' labels are not derivable from
/// their names ("state_refresh" logs as "Rate refresh"), and the interface
/// stats worker's two lines already disagree with each other.
pub(super) fn spawn_loop(
    runtime: &mut RuntimeSupervisor,
    thread_name: &'static str,
    started_msg: &'static str,
    stopping_msg: &'static str,
    interval: Duration,
    mut body: impl FnMut() + Send + 'static,
) -> std::io::Result<()> {
    let shutdown = runtime.shutdown_signal();
    runtime.spawn_monitored(thread_name, move || {
        info!("{started_msg}");
        loop {
            if shutdown.is_requested() {
                info!("{stopping_msg}");
                break;
            }
            body();
            if shutdown.wait_timeout(interval) {
                info!("{stopping_msg}");
                break;
            }
        }
    })
}

/// Clone-and-filter one connection table (active or historic) into snapshot
/// records.
///
/// snapshot_clone: leave the live tracker as unique owner of its rate
/// samples, otherwise the next per-packet update pays an `Arc::make_mut`
/// deep copy.
fn snapshot_source<K: Eq + std::hash::Hash, S: std::hash::BuildHasher + Clone>(
    source: &DashMap<K, Connection, S>,
    enrich_and_filter: impl Fn(&mut Connection) -> bool,
) -> Vec<Connection> {
    source
        .iter()
        .filter_map(|entry| {
            let mut conn = entry.value().snapshot_clone();
            enrich_and_filter(&mut conn).then_some(conn)
        })
        .collect()
}

fn passes_localhost_filter(connection: &Connection, filter_localhost: bool) -> bool {
    !(filter_localhost
        && connection.local_addr.ip().is_loopback()
        && connection.remote_addr.ip().is_loopback())
}

/// Build the same deterministic, service-enriched connection view used by
/// interactive and headless frontends. Calling this after workers have joined
/// captures the fully drained tracker state for final machine output.
pub(super) fn build_connection_snapshot(
    tracker: &ConnectionTracker,
    service_lookup: &ServiceLookup,
    filter_localhost: bool,
    include_historic: bool,
) -> Vec<Connection> {
    let enrich_and_filter = |connection: &mut Connection| {
        if connection.service_name.is_none() {
            if let Some(service) =
                service_lookup.lookup(connection.remote_addr.port(), connection.protocol)
            {
                connection.service_name = Some(service.to_string());
            } else if let Some(service) =
                service_lookup.lookup(connection.local_addr.port(), connection.protocol)
            {
                connection.service_name = Some(service.to_string());
            }
        }
        passes_localhost_filter(connection, filter_localhost)
    };

    let mut snapshot = snapshot_source(tracker.connections(), enrich_and_filter);
    if include_historic {
        snapshot.extend(snapshot_source(tracker.historic(), enrich_and_filter));
    }
    snapshot.sort_by_key(|connection| connection.created_at);
    snapshot
}

impl App {
    pub(super) fn start_snapshot_provider(
        &mut self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<()> {
        let snapshot = Arc::clone(&self.connections_snapshot);
        let snapshot_generation = Arc::clone(&self.snapshot_generation);
        let stats = Arc::clone(&self.stats);
        let service_lookup = Arc::clone(&self.service_lookup);
        let process_activity = Arc::clone(&self.process_activity);
        let show_historic = Arc::clone(&self.show_historic);
        let filter_localhost = self.config.filter_localhost;
        let refresh_interval = Duration::from_millis(self.config.refresh_interval);
        let loop_interval = refresh_interval.min(Duration::from_secs(1));

        let mut last_ui_publish: Option<Instant> = None;
        let mut last_activity_sample: Option<Instant> = None;

        spawn_loop(
            &mut self.runtime,
            "snapshot_ui",
            "Snapshot provider thread started",
            "Snapshot provider thread stopping",
            loop_interval,
            move || {
                let start = Instant::now();
                let total_connections = tracker.len();

                let snapshot_data = build_connection_snapshot(
                    &tracker,
                    &service_lookup,
                    filter_localhost,
                    show_historic.load(Ordering::Relaxed),
                );

                let filtered_count = snapshot_data.len();

                let activity_due = last_activity_sample
                    .is_none_or(|sampled| sampled.elapsed() >= Duration::from_secs(1));
                if activity_due {
                    if let Ok(mut activity) = process_activity.write() {
                        tracker.with_retained_sources(|active, historic| {
                            activity.observe_sources(
                                SystemTime::now(),
                                |observe| {
                                    for entry in active.iter() {
                                        let conn = entry.value();
                                        if passes_localhost_filter(conn, filter_localhost) {
                                            observe(conn);
                                        }
                                    }
                                },
                                |observe| {
                                    for entry in historic.iter() {
                                        let conn = entry.value();
                                        if passes_localhost_filter(conn, filter_localhost) {
                                            observe(conn);
                                        }
                                    }
                                },
                            );
                        });
                    }
                    last_activity_sample = Some(Instant::now());
                }

                let ui_publish_due =
                    last_ui_publish.is_none_or(|published| published.elapsed() >= refresh_interval);
                if ui_publish_due {
                    let mut published = snapshot.write().unwrap();
                    *published = snapshot_data;
                    snapshot_generation.fetch_add(1, Ordering::Release);
                    drop(published);
                    last_ui_publish = Some(Instant::now());

                    // Counts active connections only.
                    stats
                        .connections_tracked
                        .store(total_connections as u64, Ordering::Relaxed);
                    *stats.last_update.write().unwrap() = Instant::now();
                }

                debug!(
                    "Snapshot updated in {:?} - Total: {}, Filtered: {}",
                    start.elapsed(),
                    total_connections,
                    filtered_count
                );
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn snapshot_ui worker: {error}"))?;

        Ok(())
    }

    /// Start rate refresh thread to update rates for idle connections
    pub(super) fn start_rate_refresh_thread(
        &mut self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<()> {
        // Keep idle-rate decay aligned with the live graph cadence.
        spawn_loop(
            &mut self.runtime,
            "state_refresh",
            "Rate refresh thread started",
            "Rate refresh thread stopping",
            LIVE_RATE_INTERVAL,
            move || {
                // Refresh rates for connections that may still have non-zero rates.
                // Skip connections idle >30s whose rates are already zero.
                let sweep_start = Instant::now();
                let mut refreshed = 0usize;
                for mut entry in tracker.connections().iter_mut() {
                    let conn = entry.value_mut();
                    let idle_secs = conn.last_activity.elapsed().unwrap_or_default().as_secs();
                    if idle_secs <= 30 || conn.has_nonzero_rates() {
                        conn.refresh_rates();
                        refreshed += 1;
                    }
                }
                debug!(
                    "State refresh sweep took {:?} for {} refreshed connections",
                    sweep_start.elapsed(),
                    refreshed
                );
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn state_refresh worker: {error}"))?;

        Ok(())
    }

    pub(super) fn start_interface_stats_thread(&mut self) -> Result<()> {
        let interface_stats = Arc::clone(&self.interface_stats);
        let interface_rates = Arc::clone(&self.interface_rates);
        let interface_traffic_windows = Arc::clone(&self.interface_traffic_windows);
        let interface_traffic_history = Arc::clone(&self.interface_traffic_history);

        let provider = crate::network::interface_stats::create_stats_provider();
        let mut previous_stats: HashMap<String, InterfaceStats> = HashMap::new();
        // Warn once if stat collection ever fails so a permission/sandbox
        // regression (e.g. Landlock denying /sys) is visible at the
        // default log level instead of being silently swallowed.
        let mut warned_collect_failure = false;

        // Keep interface rates fresh for the live graphs.
        spawn_loop(
            &mut self.runtime,
            "ifstats_poll",
            "Interface stats collection thread started",
            "Interface stats thread stopping",
            LIVE_RATE_INTERVAL,
            move || {
                match provider.get_all_stats() {
                    Ok(stats_vec) => {
                        let mut stats_history = interface_traffic_history
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        interface_stats.clear();
                        interface_rates.clear();
                        interface_traffic_windows.clear();

                        for stat in stats_vec {
                            if let Some(prev) = previous_stats.get(&stat.interface_name) {
                                let rates = stat.calculate_rates(prev);
                                interface_rates.insert(stat.interface_name.clone(), rates);
                            }

                            let name = stat.interface_name.clone();
                            interface_stats.insert(name.clone(), stat.clone());
                            previous_stats.insert(name.clone(), stat.clone());

                            let history = stats_history.entry(name.clone()).or_default();
                            history.push_back(stat.clone());
                            while history.len() > 2
                                && history.get(1).is_some_and(|sample| {
                                    stat.timestamp
                                        .duration_since(sample.timestamp)
                                        .unwrap_or_default()
                                        >= Duration::from_secs(60)
                                })
                            {
                                history.pop_front();
                            }
                            if let Some(oldest) = history.front() {
                                interface_traffic_windows.insert(name, stat.traffic_since(oldest));
                            }
                        }
                        stats_history.retain(|name, _| interface_stats.contains_key(name));
                    }
                    Err(e) => {
                        if !warned_collect_failure {
                            warn!(
                                "Failed to collect interface stats: {} (interface panel will be empty; on Linux this is often a sandbox/permission issue reading /sys/class/net)",
                                e
                            );
                            warned_collect_failure = true;
                        } else {
                            debug!("Failed to collect interface stats: {}", e);
                        }
                    }
                }
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn ifstats_poll worker: {error}"))?;

        Ok(())
    }

    pub(super) fn start_traffic_history_thread(&mut self) -> Result<()> {
        let traffic_history = Arc::clone(&self.traffic_history);
        let conn_rate_history = Arc::clone(&self.conn_rate_history);
        let interface_rates = Arc::clone(&self.interface_rates);
        let connections_snapshot = Arc::clone(&self.connections_snapshot);
        let stats = Arc::clone(&self.stats);
        let tracker = Arc::clone(&self.tracker);

        let mut prev_packets = stats.packets_processed.load(Ordering::Relaxed);
        let mut prev_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
        let mut prev_connections_created = stats.total_connections_created.load(Ordering::Relaxed);
        let mut prev_connections_archived =
            stats.total_connections_archived.load(Ordering::Relaxed);
        let mut previous_sample_at = Instant::now();

        // Update twice per second for a more responsive graph.
        spawn_loop(
            &mut self.runtime,
            "graph_ui",
            "Traffic history thread started",
            "Traffic history thread stopping",
            LIVE_RATE_INTERVAL,
            move || {
                let (total_rx, total_tx) =
                    interface_rates
                        .iter()
                        .fold((0u64, 0u64), |(rx, tx), entry| {
                            (
                                rx + entry.value().rx_bytes_per_sec,
                                tx + entry.value().tx_bytes_per_sec,
                            )
                        });

                // Get active connection count from snapshot (excludes
                // historic) and record per-connection rate samples on
                // the same cadence as the aggregate history.
                let connection_count = connections_snapshot
                    .read()
                    .map(|snap| {
                        if let Ok(mut rates) = conn_rate_history.write() {
                            let alive: std::collections::HashSet<String> = snap
                                .iter()
                                .filter(|c| !c.is_historic)
                                .map(|c| c.key())
                                .collect();
                            rates.retain(|key, _| alive.contains(key));
                            for conn in snap.iter().filter(|c| !c.is_historic) {
                                rates.entry(conn.key()).or_default().push_for_generation(
                                    conn.created_at,
                                    conn.current_incoming_rate_bps as u64,
                                    conn.current_outgoing_rate_bps as u64,
                                    TRAFFIC_HISTORY_CAPACITY,
                                );
                            }
                        }
                        snap.iter().filter(|c| !c.is_historic).count()
                    })
                    .unwrap_or(0);

                let current_packets = stats.packets_processed.load(Ordering::Relaxed);
                let current_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
                let current_connections_created =
                    stats.total_connections_created.load(Ordering::Relaxed);
                let current_connections_archived =
                    stats.total_connections_archived.load(Ordering::Relaxed);

                let packets_delta = current_packets.saturating_sub(prev_packets);
                let retransmits_delta = current_retransmits.saturating_sub(prev_retransmits);
                let connections_created_delta =
                    current_connections_created.saturating_sub(prev_connections_created);
                let connections_archived_delta =
                    current_connections_archived.saturating_sub(prev_connections_archived);

                let sampled_at = Instant::now();
                let sample_seconds = sampled_at.duration_since(previous_sample_at).as_secs_f64();
                let packets_per_sec = per_second_rate(packets_delta, sample_seconds, 1.0);
                let retransmits_per_sec = per_second_rate(retransmits_delta, sample_seconds, 1.0);
                let opened_per_sec_tenths =
                    per_second_rate(connections_created_delta, sample_seconds, 10.0);
                let closed_per_sec_tenths =
                    per_second_rate(connections_archived_delta, sample_seconds, 10.0);

                prev_packets = current_packets;
                prev_retransmits = current_retransmits;
                prev_connections_created = current_connections_created;
                prev_connections_archived = current_connections_archived;
                previous_sample_at = sampled_at;

                // Last 1 second window.
                let avg_rtt_ms = tracker.take_average_rtt(1);

                if let Ok(mut history) = traffic_history.write() {
                    history.add_sample_with_lifecycle(
                        total_rx,
                        total_tx,
                        ConnectionLifecycleSample {
                            active: connection_count,
                            retained: tracker.historic_len(),
                            opened_per_sec_tenths,
                            closed_per_sec_tenths,
                        },
                        packets_per_sec,
                        retransmits_per_sec,
                        avg_rtt_ms,
                    );
                }
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn graph_ui worker: {error}"))?;

        Ok(())
    }

    pub(super) fn start_cleanup_thread(&mut self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let json_log_file = self.json_log_file.clone();
        let pcap_sidecar_file = self.pcap_sidecar_file.clone();
        let dns_resolver = self.dns_resolver.clone();
        let stats = Arc::clone(&self.stats);

        spawn_loop(
            &mut self.runtime,
            "cleanup_thread",
            "Cleanup thread started",
            "Cleanup thread stopping",
            Duration::from_secs(5),
            move || {
                // Remove inactive connections. The tracker handles the timeout
                // sweep, historic archiving + eviction, and QUIC-mapping cleanup;
                // we layer the app's close-event logging on the returned set.
                let now = SystemTime::now();
                let removed = tracker.cleanup(now);
                stats
                    .total_connections_archived
                    .fetch_add(removed.len() as u64, Ordering::Relaxed);

                for conn in &removed {
                    log_connection_closed(
                        conn,
                        now,
                        json_log_file.as_deref(),
                        pcap_sidecar_file.as_deref(),
                        dns_resolver.as_deref(),
                    );

                    let conn_timeout = conn.get_timeout();
                    let cleanup_age = conn.cleanup_age(now);
                    debug!(
                        "Cleanup: Removing {} connection {} -> {} (cleanup age: {:?}, timeout: {:?}, state: {})",
                        conn.protocol,
                        conn.local_addr,
                        conn.remote_addr,
                        cleanup_age,
                        conn_timeout,
                        conn.state()
                    );
                }

                if !removed.is_empty() {
                    debug!(
                        "Removed {} inactive connections and cleaned up QUIC mappings",
                        removed.len()
                    );
                }
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn cleanup worker: {error}"))?;

        Ok(())
    }
}

/// Convert a counter delta into a per-second rate in the given unit scale
/// (1.0 for whole units, 10.0 for tenths). Windows shorter than
/// [`MIN_RATE_SAMPLE_SECONDS`] yield 0 instead of an amplified outlier.
fn per_second_rate(delta: u64, elapsed_seconds: f64, unit_scale: f64) -> u64 {
    if elapsed_seconds < MIN_RATE_SAMPLE_SECONDS {
        return 0;
    }
    (delta as f64 * unit_scale / elapsed_seconds).round() as u64
}

#[cfg(test)]
mod live_rate_sampling_tests {
    use super::*;

    /// The traffic-history thread's first pass measures only its own setup
    /// time; a startup burst divided by that sliver must not become a
    /// thousands-per-second outlier that pins the graph scale.
    #[test]
    fn sliver_measurement_windows_produce_no_rate() {
        assert_eq!(per_second_rate(1, 0.001, 10.0), 0);
        assert_eq!(per_second_rate(500, 0.01, 1.0), 0);
    }

    #[test]
    fn full_windows_produce_per_second_rates() {
        assert_eq!(per_second_rate(5, 0.5, 1.0), 10);
        assert_eq!(per_second_rate(1, 0.5, 10.0), 20);
        assert_eq!(per_second_rate(0, 0.5, 10.0), 0);
    }
}
