//! Plain data shared across the `app` module: configuration, output handles,
//! statistics, process-detection status, and per-connection rate history.
//! Sandbox status is `rustnet_sandbox::SandboxReport`.

use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use crate::network::types::{Connection, GraphScale, Protocol};

/// Process detection status information for UI display
#[derive(Debug, Clone, Default)]
pub struct ProcessDetectionStatus {
    /// The active detection method (e.g., "eBPF + procfs", "pktap", "lsof")
    pub method: String,
    /// Whether the detection is degraded from optimal
    pub is_degraded: bool,
    /// Human-readable reason for degradation (if any)
    pub degradation_reason: Option<String>,
    /// What feature is unavailable (e.g., "eBPF", "PKTAP")
    pub unavailable_feature: Option<String>,
}

impl ProcessDetectionStatus {
    /// Create a new status with just a method (no degradation)
    pub fn with_method(method: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            is_degraded: false,
            degradation_reason: None,
            unavailable_feature: None,
        }
    }

    /// Create a new degraded status
    pub fn degraded(
        method: impl Into<String>,
        unavailable_feature: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            method: method.into(),
            is_degraded: true,
            degradation_reason: Some(reason.into()),
            unavailable_feature: Some(unavailable_feature.into()),
        }
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Network interface to capture from (None for default)
    pub interface: Option<String>,
    /// Filter localhost connections
    pub filter_localhost: bool,
    /// UI refresh interval in milliseconds
    pub refresh_interval: u64,
    /// Enable deep packet inspection
    pub enable_dpi: bool,
    /// BPF filter for packet capture
    pub bpf_filter: Option<String>,
    /// JSON log file path for connection events
    pub json_log_file: Option<String>,
    /// PCAP export file path for Wireshark analysis
    pub pcap_export_file: Option<String>,
    /// Annotated PCAPNG export file path for Wireshark analysis
    pub pcapng_export_file: Option<String>,
    /// Enable reverse DNS resolution for IP addresses
    pub resolve_dns: bool,
    /// Show PTR lookup connections in UI (when DNS resolution is enabled)
    pub show_ptr_lookups: bool,
    /// Path to GeoLite2-Country.mmdb database (None for auto-discovery)
    pub geoip_country_path: Option<String>,
    /// Path to GeoLite2-ASN.mmdb database (None for auto-discovery)
    pub geoip_asn_path: Option<String>,
    /// Path to GeoLite2-City.mmdb database (None for auto-discovery)
    pub geoip_city_path: Option<String>,
    /// Disable GeoIP lookups entirely
    pub disable_geoip: bool,
    /// Kubernetes pod/container attribution mode
    #[cfg(feature = "kubernetes")]
    pub kubernetes_mode: crate::network::kubernetes::KubernetesMode,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            filter_localhost: true,
            refresh_interval: 500,
            enable_dpi: true,
            bpf_filter: None, // No filter by default to see all packets
            json_log_file: None,
            pcap_export_file: None,
            pcapng_export_file: None,
            resolve_dns: true,
            show_ptr_lookups: false,
            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: false,
            #[cfg(feature = "kubernetes")]
            kubernetes_mode: crate::network::kubernetes::KubernetesMode::default(),
        }
    }
}

#[derive(Default)]
pub struct AppOutputHandles {
    pub json_log: Option<File>,
    pub pcap_sidecar: Option<File>,
    pub pcapng_export: Option<File>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ConnectionCounts {
    pub tcp: usize,
    pub udp: usize,
    pub active: usize,
    pub historic: usize,
    pub processes: usize,
    pub tcp_retransmits: u64,
    pub tcp_out_of_order: u64,
    pub tcp_fast_retransmits: u64,
    pub tcp_flows_with_analytics: usize,
}

impl ConnectionCounts {
    pub(crate) fn from_connections<'a>(
        connections: impl IntoIterator<Item = &'a Connection>,
    ) -> Self {
        let mut counts = Self::default();
        let mut processes: HashSet<&str> = HashSet::new();

        for connection in connections {
            if let Some(analytics) = &connection.tcp_analytics {
                counts.tcp_retransmits += analytics.retransmit_count;
                counts.tcp_out_of_order += analytics.out_of_order_count;
                counts.tcp_fast_retransmits += analytics.fast_retransmit_count;
                counts.tcp_flows_with_analytics += 1;
            }

            if connection.is_historic {
                counts.historic += 1;
                continue;
            }

            counts.active += 1;
            match connection.protocol {
                Protocol::Tcp => counts.tcp += 1,
                Protocol::Udp => counts.udp += 1,
                _ => {}
            }
            processes.insert(crate::network::process_activity::process_group_label(
                connection,
            ));
        }

        counts.processes = processes.len();
        counts
    }
}

/// Application statistics
#[derive(Debug)]
pub struct AppStats {
    pub packets_processed: AtomicU64,
    /// Packets rejected by the bounded capture-to-processor queue.
    pub packets_dropped: AtomicU64,
    /// Packets libpcap reports dropping because its capture buffer was full.
    pub capture_packets_dropped: AtomicU64,
    /// Packets libpcap reports dropping at the network interface or driver.
    pub interface_packets_dropped: AtomicU64,
    /// Windows packets captured before ETW attribution became active. Raw
    /// exports retain them, but connection tracking intentionally skips them.
    pub pre_attribution_packets: AtomicU64,
    pub connections_tracked: AtomicU64,
    pub total_connections_created: AtomicU64,
    pub total_connections_archived: AtomicU64,
    pub last_update: RwLock<Instant>,
    // TCP analytics totals (since program start)
    pub total_tcp_retransmits: AtomicU64,
    pub total_tcp_out_of_order: AtomicU64,
    pub total_tcp_fast_retransmits: AtomicU64,
    pub pcap_records_written: AtomicU64,
    pub pcap_export_errors: AtomicU64,
    pub pcapng_records_queued: AtomicU64,
    pub pcapng_records_written: AtomicU64,
    pub pcapng_records_annotated: AtomicU64,
    pub pcapng_records_unannotated: AtomicU64,
    pub pcapng_records_dropped: AtomicU64,
    pub pcapng_export_errors: AtomicU64,
    /// Monotonic export failures used for the final process result. Unlike the
    /// visible session counters, this is intentionally not cleared by the UI.
    output_errors_total: AtomicU64,
}

impl Default for AppStats {
    fn default() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            capture_packets_dropped: AtomicU64::new(0),
            interface_packets_dropped: AtomicU64::new(0),
            pre_attribution_packets: AtomicU64::new(0),
            connections_tracked: AtomicU64::new(0),
            total_connections_created: AtomicU64::new(0),
            total_connections_archived: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
            total_tcp_retransmits: AtomicU64::new(0),
            total_tcp_out_of_order: AtomicU64::new(0),
            total_tcp_fast_retransmits: AtomicU64::new(0),
            pcap_records_written: AtomicU64::new(0),
            pcap_export_errors: AtomicU64::new(0),
            pcapng_records_queued: AtomicU64::new(0),
            pcapng_records_written: AtomicU64::new(0),
            pcapng_records_annotated: AtomicU64::new(0),
            pcapng_records_unannotated: AtomicU64::new(0),
            pcapng_records_dropped: AtomicU64::new(0),
            pcapng_export_errors: AtomicU64::new(0),
            output_errors_total: AtomicU64::new(0),
        }
    }
}

impl AppStats {
    /// Every atomic counter, in declaration order. This is the single place
    /// a new counter has to be registered so that snapshots and resets stay
    /// complete.
    fn counters(&self) -> [&AtomicU64; 19] {
        [
            &self.packets_processed,
            &self.packets_dropped,
            &self.capture_packets_dropped,
            &self.interface_packets_dropped,
            &self.pre_attribution_packets,
            &self.connections_tracked,
            &self.total_connections_created,
            &self.total_connections_archived,
            &self.total_tcp_retransmits,
            &self.total_tcp_out_of_order,
            &self.total_tcp_fast_retransmits,
            &self.pcap_records_written,
            &self.pcap_export_errors,
            &self.pcapng_records_queued,
            &self.pcapng_records_written,
            &self.pcapng_records_annotated,
            &self.pcapng_records_unannotated,
            &self.pcapng_records_dropped,
            &self.pcapng_export_errors,
        ]
    }

    /// Reset every counter to zero (the last-update timestamp is kept).
    pub(crate) fn reset_counters(&self) {
        for counter in self.counters() {
            counter.store(0, Ordering::Relaxed);
        }
    }

    /// Copy of the current counter values and last-update timestamp.
    pub(crate) fn snapshot(&self) -> AppStats {
        let snapshot = AppStats {
            last_update: RwLock::new(*self.last_update.read().unwrap()),
            ..AppStats::default()
        };
        for (dst, src) in snapshot.counters().into_iter().zip(self.counters()) {
            dst.store(src.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        snapshot
    }

    pub(super) fn record_pcap_export_error(&self) {
        self.pcap_export_errors.fetch_add(1, Ordering::Relaxed);
        self.output_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn record_pcapng_export_error(&self) {
        self.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
        self.output_errors_total.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn output_errors_total(&self) -> u64 {
        self.output_errors_total.load(Ordering::Relaxed)
    }
}

/// Ring buffers of per-connection RX/TX rates (bytes/sec), capped at
/// the same 60-second window as [`TrafficHistory`](crate::network::types::TrafficHistory).
#[derive(Debug, Clone, Default)]
pub struct ConnRateHistory {
    pub rx: VecDeque<u64>,
    pub tx: VecDeque<u64>,
    pub(super) rx_scale: GraphScale,
    pub(super) tx_scale: GraphScale,
    generation: Option<SystemTime>,
}

impl ConnRateHistory {
    /// Push one sample for the connection generation stamped `created_at`.
    /// Live connection keys are tuple-only, so a replacement generation reuses
    /// its predecessor's map entry; a new generation resets the rings (and
    /// the sticky graph scales) instead of inheriting the old connection's
    /// graph and ceiling.
    pub(super) fn push_for_generation(
        &mut self,
        created_at: SystemTime,
        rx: u64,
        tx: u64,
        cap: usize,
    ) {
        if self.generation != Some(created_at) {
            *self = Self {
                generation: Some(created_at),
                ..Self::default()
            };
        }
        self.push(rx, tx, cap);
    }

    pub(super) fn push(&mut self, rx: u64, tx: u64, cap: usize) {
        if self.rx.len() >= cap {
            self.rx.pop_front();
        }
        if self.tx.len() >= cap {
            self.tx.pop_front();
        }
        self.rx.push_back(rx);
        self.tx.push_back(tx);
        self.rx_scale
            .update_peak(self.rx.iter().copied().max().unwrap_or(0));
        self.tx_scale
            .update_peak(self.tx.iter().copied().max().unwrap_or(0));
    }
}

#[derive(Debug, Clone)]
pub struct ConnRateHistorySnapshot {
    pub rx: Vec<u64>,
    pub tx: Vec<u64>,
    pub rx_graph_ceiling: f64,
    pub tx_graph_ceiling: f64,
}

#[cfg(test)]
mod conn_rate_history_tests {
    use super::*;
    use std::time::Duration;

    /// Live connection keys are tuple-only, so a replacement generation lands
    /// on its predecessor's map entry; it must start with a fresh graph
    /// instead of inheriting the old connection's history.
    #[test]
    fn replacement_generation_starts_with_fresh_rate_history() {
        let mut history = ConnRateHistory::default();
        let first_generation = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        history.push_for_generation(first_generation, 1_000_000, 2_000_000, 10);
        history.push_for_generation(first_generation, 1_000_000, 2_000_000, 10);
        assert_eq!(history.rx.len(), 2);

        let second_generation = first_generation + Duration::from_secs(5);
        history.push_for_generation(second_generation, 10, 20, 10);
        assert_eq!(history.rx, [10]);
        assert_eq!(history.tx, [20]);
    }
}

#[cfg(test)]
mod app_stats_tests {
    use super::*;

    #[test]
    fn snapshots_and_resets_every_counter() {
        let stats = AppStats::default();
        for (index, counter) in stats.counters().into_iter().enumerate() {
            counter.store(index as u64 + 1, Ordering::Relaxed);
        }

        let snapshot = stats.snapshot();
        for (index, counter) in snapshot.counters().into_iter().enumerate() {
            assert_eq!(counter.load(Ordering::Relaxed), index as u64 + 1);
        }

        stats.reset_counters();
        for counter in stats.counters() {
            assert_eq!(counter.load(Ordering::Relaxed), 0);
        }
    }

    #[test]
    fn clearing_visible_counters_preserves_lifetime_output_failures() {
        let stats = AppStats::default();
        stats.record_pcap_export_error();
        stats.record_pcapng_export_error();

        stats.reset_counters();

        assert_eq!(stats.pcap_export_errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.pcapng_export_errors.load(Ordering::Relaxed), 0);
        assert_eq!(stats.output_errors_total(), 2);
    }
}
