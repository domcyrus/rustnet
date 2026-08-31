//! Periodic sampling threads: UI snapshots, idle-rate refresh, interface
//! stats, traffic history, and connection cleanup.

use anyhow::Result;
use dashmap::DashMap;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::network::{
    interface_stats::{InterfaceRates, InterfaceStats, LinkCapacity},
    services::ServiceLookup,
    tracker::ConnectionTracker,
    types::{Connection, ConnectionLifecycleSample},
};

use super::logging::{log_connection_event, log_pcap_connection};
use super::state::App;
use super::{LIVE_RATE_INTERVAL, MIN_RATE_SAMPLE_SECONDS, TRAFFIC_HISTORY_CAPACITY};

/// One coherent aggregate of the interface rates used by the host traffic
/// graphs. A direction has a trustworthy capacity only when at least one
/// contributing interface reports it and no unknown-capacity interface is
/// currently carrying traffic in that direction.
#[derive(Debug, Default, PartialEq, Eq)]
struct AggregateInterfaceRates {
    rx_bytes_per_sec: u64,
    tx_bytes_per_sec: u64,
    rx_capacity_bps: u64,
    tx_capacity_bps: u64,
    has_rx_capacity: bool,
    has_tx_capacity: bool,
    unknown_rx_active: bool,
    unknown_tx_active: bool,
}

impl AggregateInterfaceRates {
    fn include(&mut self, rates: &InterfaceRates) {
        self.rx_bytes_per_sec = self.rx_bytes_per_sec.saturating_add(rates.rx_bytes_per_sec);
        self.tx_bytes_per_sec = self.tx_bytes_per_sec.saturating_add(rates.tx_bytes_per_sec);

        match rates.link_capacity.rx_bps {
            Some(capacity) if capacity > 0 => {
                self.has_rx_capacity = true;
                self.rx_capacity_bps = self.rx_capacity_bps.saturating_add(capacity);
            }
            _ if rates.rx_bytes_per_sec > 0 => self.unknown_rx_active = true,
            _ => {}
        }
        match rates.link_capacity.tx_bps {
            Some(capacity) if capacity > 0 => {
                self.has_tx_capacity = true;
                self.tx_capacity_bps = self.tx_capacity_bps.saturating_add(capacity);
            }
            _ if rates.tx_bytes_per_sec > 0 => self.unknown_tx_active = true,
            _ => {}
        }
    }

    fn link_capacity(&self) -> LinkCapacity {
        LinkCapacity {
            rx_bps: (self.has_rx_capacity && !self.unknown_rx_active)
                .then_some(self.rx_capacity_bps),
            tx_bps: (self.has_tx_capacity && !self.unknown_tx_active)
                .then_some(self.tx_capacity_bps),
        }
    }
}

/// Spawn a named worker thread that runs `body` every `interval` until
/// `should_stop` is set.
///
/// The started/stopping log lines are passed in verbatim rather than derived
/// from the thread name: the existing workers' labels are not derivable from
/// their names ("state_refresh" logs as "Rate refresh"), and the interface
/// stats worker's two lines already disagree with each other.
pub(super) fn spawn_loop(
    thread_name: &'static str,
    started_msg: &'static str,
    stopping_msg: &'static str,
    interval: Duration,
    should_stop: Arc<AtomicBool>,
    mut body: impl FnMut() + Send + 'static,
) -> std::io::Result<()> {
    thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            info!("{started_msg}");
            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("{stopping_msg}");
                    break;
                }
                body();
                thread::sleep(interval);
            }
        })
        .map(|_| ())
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

impl App {
    /// Start snapshot provider thread for UI updates
    pub(super) fn start_snapshot_provider(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let snapshot = Arc::clone(&self.connections_snapshot);
        let snapshot_generation = Arc::clone(&self.snapshot_generation);
        let stats = Arc::clone(&self.stats);
        let service_lookup = Arc::clone(&self.service_lookup);
        let process_activity = Arc::clone(&self.process_activity);
        let show_historic = Arc::clone(&self.show_historic);
        let filter_localhost = self.config.filter_localhost;
        let refresh_interval = Duration::from_millis(self.config.refresh_interval);
        let loop_interval = refresh_interval.min(Duration::from_secs(1));

        let passes_localhost_filter = move |conn: &Connection| -> bool {
            !(filter_localhost
                && conn.local_addr.ip().is_loopback()
                && conn.remote_addr.ip().is_loopback())
        };

        let enrich_and_filter = move |conn: &mut Connection,
                                      service_lookup: &ServiceLookup|
              -> bool {
            // Enrich with service name
            if conn.service_name.is_none() {
                if let Some(service) = service_lookup.lookup(conn.remote_addr.port(), conn.protocol)
                {
                    conn.service_name = Some(service.to_string());
                } else if let Some(service) =
                    service_lookup.lookup(conn.local_addr.port(), conn.protocol)
                {
                    conn.service_name = Some(service.to_string());
                }
            }
            // Apply localhost filter
            passes_localhost_filter(conn)
        };

        let mut last_ui_publish: Option<Instant> = None;
        let mut last_activity_sample: Option<Instant> = None;

        spawn_loop(
            "snapshot_ui",
            "Snapshot provider thread started",
            "Snapshot provider thread stopping",
            loop_interval,
            Arc::clone(&self.should_stop),
            move || {
                // Create snapshot
                let start = Instant::now();
                let total_connections = tracker.len();

                let mut snapshot_data = snapshot_source(tracker.connections(), |conn| {
                    enrich_and_filter(conn, &service_lookup)
                });

                // Append historic connections when toggle is on
                if show_historic.load(Ordering::Relaxed) {
                    snapshot_data.extend(snapshot_source(tracker.historic(), |conn| {
                        enrich_and_filter(conn, &service_lookup)
                    }));
                }

                // Sort by creation time (oldest first, newest last for maximum stability)
                snapshot_data.sort_by_key(|a| a.created_at);

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
                                        if passes_localhost_filter(conn) {
                                            observe(conn);
                                        }
                                    }
                                },
                                |observe| {
                                    for entry in historic.iter() {
                                        let conn = entry.value();
                                        if passes_localhost_filter(conn) {
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
                    // Publish the connection vector used by the UI.
                    *snapshot.write().unwrap() = snapshot_data;
                    snapshot_generation.fetch_add(1, Ordering::Release);
                    last_ui_publish = Some(Instant::now());

                    // Update stats (only count active connections)
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
        .expect("Failed to spawn snapshot_ui thread");

        Ok(())
    }

    /// Start rate refresh thread to update rates for idle connections
    pub(super) fn start_rate_refresh_thread(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        // Keep idle-rate decay aligned with the live graph cadence.
        spawn_loop(
            "state_refresh",
            "Rate refresh thread started",
            "Rate refresh thread stopping",
            LIVE_RATE_INTERVAL,
            Arc::clone(&self.should_stop),
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
        .expect("Failed to spawn state_refresh thread");

        Ok(())
    }

    /// Start interface statistics collection thread
    pub(super) fn start_interface_stats_thread(&self) -> Result<()> {
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
            "ifstats_poll",
            "Interface stats collection thread started",
            "Interface stats thread stopping",
            LIVE_RATE_INTERVAL,
            Arc::clone(&self.should_stop),
            move || {
                // Collect stats from all interfaces
                match provider.get_all_stats() {
                    Ok(stats_vec) => {
                        let mut stats_history = interface_traffic_history
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        // Clear old entries
                        interface_stats.clear();
                        interface_rates.clear();
                        interface_traffic_windows.clear();

                        for stat in stats_vec {
                            // Calculate rates if we have previous data
                            if let Some(prev) = previous_stats.get(&stat.interface_name) {
                                let rates = stat.calculate_rates(prev);
                                interface_rates.insert(stat.interface_name.clone(), rates);
                            }

                            // Store current stats
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
        .expect("Failed to spawn ifstats_poll thread");

        Ok(())
    }

    /// Start traffic history thread for graph visualization
    pub(super) fn start_traffic_history_thread(&self) -> Result<()> {
        let traffic_history = Arc::clone(&self.traffic_history);
        let conn_rate_history = Arc::clone(&self.conn_rate_history);
        let interface_rates = Arc::clone(&self.interface_rates);
        let connections_snapshot = Arc::clone(&self.connections_snapshot);
        let stats = Arc::clone(&self.stats);
        let tracker = Arc::clone(&self.tracker);

        // Track previous values for delta calculation
        let mut prev_packets = stats.packets_processed.load(Ordering::Relaxed);
        let mut prev_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
        let mut prev_connections_created = stats.total_connections_created.load(Ordering::Relaxed);
        let mut prev_connections_archived =
            stats.total_connections_archived.load(Ordering::Relaxed);
        let mut previous_sample_at = Instant::now();

        // Update twice per second for a more responsive graph.
        spawn_loop(
            "graph_ui",
            "Traffic history thread started",
            "Traffic history thread stopping",
            LIVE_RATE_INTERVAL,
            Arc::clone(&self.should_stop),
            move || {
                // Aggregate rates from all interfaces
                let aggregate = interface_rates.iter().fold(
                    AggregateInterfaceRates::default(),
                    |mut aggregate, entry| {
                        aggregate.include(entry.value());
                        aggregate
                    },
                );

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

                // Get packet and retransmit counts (calculate deltas)
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

                // Get average RTT from tracker (last 1 second window)
                let avg_rtt_ms = tracker.take_average_rtt(1);

                // Add sample to traffic history
                if let Ok(mut history) = traffic_history.write() {
                    let link_capacity = aggregate.link_capacity();
                    history.observe_link_capacity(link_capacity.rx_bps, link_capacity.tx_bps);
                    history.add_sample_with_lifecycle(
                        aggregate.rx_bytes_per_sec,
                        aggregate.tx_bytes_per_sec,
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
        .expect("Failed to spawn graph_ui thread");

        Ok(())
    }

    /// Start cleanup thread to remove old connections
    pub(super) fn start_cleanup_thread(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let json_log_file = self.json_log_file.clone();
        let pcap_sidecar_file = self.pcap_sidecar_file.clone();
        let dns_resolver = self.dns_resolver.clone();
        let stats = Arc::clone(&self.stats);

        spawn_loop(
            "cleanup_thread",
            "Cleanup thread started",
            "Cleanup thread stopping",
            Duration::from_secs(5),
            Arc::clone(&self.should_stop),
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
                    // Calculate connection duration
                    let duration_secs = now
                        .duration_since(conn.created_at)
                        .map(|d| d.as_secs())
                        .ok();

                    // Log connection_closed event if JSON logging is enabled
                    if let Some(writer) = &json_log_file {
                        log_connection_event(
                            writer,
                            "connection_closed",
                            conn,
                            duration_secs,
                            dns_resolver.as_deref(),
                        );
                    }

                    // Log to PCAP sidecar file if PCAP export is enabled
                    if let Some(writer) = &pcap_sidecar_file {
                        log_pcap_connection(writer, conn);
                    }

                    // Log cleanup reason for debugging
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
        .expect("Failed to spawn cleanup_thread");

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

    #[test]
    fn aggregates_directional_rates_and_capacities() {
        let mut aggregate = AggregateInterfaceRates::default();
        aggregate.include(&InterfaceRates {
            rx_bytes_per_sec: 10,
            tx_bytes_per_sec: 20,
            link_capacity: LinkCapacity {
                rx_bps: Some(1_000),
                tx_bps: Some(2_000),
            },
        });
        aggregate.include(&InterfaceRates {
            rx_bytes_per_sec: 30,
            tx_bytes_per_sec: 40,
            link_capacity: LinkCapacity {
                rx_bps: Some(3_000),
                tx_bps: Some(4_000),
            },
        });

        assert_eq!(aggregate.rx_bytes_per_sec, 40);
        assert_eq!(aggregate.tx_bytes_per_sec, 60);
        assert_eq!(
            aggregate.link_capacity(),
            LinkCapacity {
                rx_bps: Some(4_000),
                tx_bps: Some(6_000),
            }
        );
    }

    #[test]
    fn active_unknown_interfaces_disable_only_their_direction() {
        let mut aggregate = AggregateInterfaceRates::default();
        aggregate.include(&InterfaceRates {
            link_capacity: LinkCapacity::symmetric(1_000),
            ..InterfaceRates::default()
        });
        aggregate.include(&InterfaceRates {
            rx_bytes_per_sec: 10,
            tx_bytes_per_sec: 0,
            ..InterfaceRates::default()
        });

        assert_eq!(
            aggregate.link_capacity(),
            LinkCapacity {
                rx_bps: None,
                tx_bps: Some(1_000),
            }
        );
    }
}
