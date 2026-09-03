//! The [`App`] orchestrator: construction, the privileged/worker startup
//! phases, UI accessors, clearing, and shutdown.

use anyhow::Result;
use crossbeam::channel::Receiver;
use dashmap::DashMap;
use log::{info, warn};
use rustnet_host::SocketSnapshot;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::{self, JoinHandle};
#[cfg(test)]
use std::time::SystemTime;
use std::time::{Duration, Instant};

use crate::filter::ConnectionFilter;
use crate::headless::sink::{EventSink, FileSink};
#[cfg(test)]
use crate::network::parser::ParsedPacket;
use crate::network::{
    capture::CapturedPacket,
    dns::DnsResolver,
    geoip::{GeoIpConfig, GeoIpResolver},
    interface_stats::{InterfaceRates, InterfaceStats, InterfaceTrafficWindow},
    neighbors::NeighborEntry,
    oui::OuiLookup,
    process_activity::{ProcessActivitySnapshot, ProcessActivityTracker},
    services::ServiceLookup,
    tracker::ConnectionTracker,
    types::{ApplicationProtocol, Connection, DnsQueryType, Protocol, TrafficHistory},
};

use super::capture::CaptureStatus;
use super::logging::log_pcap_connection;
use super::types::{
    AppOutputHandles, AppStats, Config, ConnRateHistory, ConnRateHistorySnapshot, ConnectionCounts,
    ProcessDetectionStatus,
};
use super::{STARTUP_SPLASH_DURATION, TRAFFIC_HISTORY_CAPACITY, WORKER_JOIN_TIMEOUT};
use rustnet_sandbox::SandboxReport;

fn is_ptr_lookup(connection: &Connection) -> bool {
    matches!(
        connection.dpi_info.as_ref().map(|dpi| &dpi.application),
        Some(ApplicationProtocol::Dns(dns_info))
            if dns_info.query_type == Some(DnsQueryType::PTR)
    )
}

/// Main application state
pub struct App {
    /// Configuration
    pub(super) config: Config,

    /// Control flag for graceful shutdown
    pub(super) should_stop: Arc<AtomicBool>,

    /// Live connection tracker (active + historic tables, RTT, QUIC coalescing,
    /// and lifecycle cleanup). Shared with background threads. This is the same
    /// `rustnet_core::network::tracker::ConnectionTracker` headless tools use,
    /// the single source of truth for connection state.
    pub(super) tracker: Arc<ConnectionTracker>,

    /// Current connections snapshot for UI
    pub(super) connections_snapshot: Arc<RwLock<Vec<Connection>>>,

    /// Bumped by the snapshot thread after each snapshot write. Lets the UI
    /// loop skip re-cloning and re-sorting an unchanged snapshot (the
    /// snapshot refreshes every `refresh_interval` ms, the UI ticks every
    /// 200ms; without this, most ticks redo identical work).
    pub(super) snapshot_generation: Arc<AtomicU64>,

    /// Whether to include historic connections in the snapshot
    pub(super) show_historic: Arc<AtomicBool>,

    /// Service name lookup
    pub(super) service_lookup: Arc<ServiceLookup>,

    /// OUI vendor lookup for MAC addresses
    pub(super) oui_lookup: Option<Arc<OuiLookup>>,

    /// Application statistics
    pub(super) stats: Arc<AppStats>,

    /// Loading state
    pub(super) is_loading: Arc<AtomicBool>,

    /// Current network interface name
    pub(super) current_interface: Arc<RwLock<Option<String>>>,

    /// Data link type for packet parsing (needed for PKTAP detection)
    pub(super) linktype: Arc<RwLock<Option<i32>>>,

    /// Packet-capture lifecycle state. Runtime failures are retained so the
    /// TUI does not look healthy after its capture thread has exited.
    pub(super) capture_status: Arc<RwLock<CaptureStatus>>,

    /// Whether PKTAP is active (macOS only) - used to disable process enrichment
    pub(super) pktap_active: Arc<AtomicBool>,

    /// Current process detection status (method and degradation info)
    pub(super) process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,

    /// Latest operating-system socket table, independent of captured packets.
    pub(super) socket_snapshot: Arc<RwLock<SocketSnapshot>>,

    /// Interface statistics (cumulative totals)
    pub(super) interface_stats: Arc<DashMap<String, InterfaceStats>>,

    /// Interface rates (per-second rates)
    pub(super) interface_rates: Arc<DashMap<String, InterfaceRates>>,

    /// Traffic transferred over the latest rolling 60-second interface window.
    pub(super) interface_traffic_windows: Arc<DashMap<String, InterfaceTrafficWindow>>,

    /// Cumulative interface samples backing the rolling traffic windows.
    /// Shared with the clear path so both sides of Activity coverage reset
    /// atomically instead of the polling thread restoring pre-clear samples.
    pub(super) interface_traffic_history: Arc<Mutex<HashMap<String, VecDeque<InterfaceStats>>>>,

    /// Traffic history for graph visualization
    pub(super) traffic_history: Arc<RwLock<TrafficHistory>>,

    /// Per-connection RX/TX rate history (bytes/sec, oldest→newest),
    /// keyed by `Connection::key()`. Sampled by the traffic-history
    /// thread on the same 500ms cadence as `traffic_history`, so the
    /// Details tab can draw per-connection waves that scroll in sync
    /// with the aggregate graphs. Entries for vanished connections are
    /// dropped each sample.
    pub(super) conn_rate_history: Arc<RwLock<HashMap<String, ConnRateHistory>>>,

    /// Process traffic derived from active and bounded historic connections.
    pub(super) process_activity: Arc<RwLock<ProcessActivityTracker>>,

    /// DNS resolver for reverse DNS lookups
    pub(super) dns_resolver: Option<Arc<DnsResolver>>,

    /// GeoIP resolver for location/ASN lookups
    pub(super) geoip_resolver: Option<Arc<GeoIpResolver>>,

    /// Receiver half of the packet channel, stashed between the privileged
    /// startup phase (`start`: capture/eBPF threads that need capabilities) and
    /// the worker phase (`start_workers`: the DPI parser threads, spawned after
    /// the sandbox is applied so they inherit it). Taken by `start_workers`.
    pub(super) packet_rx: Option<Receiver<Vec<CapturedPacket>>>,

    /// Connection-event sinks: the `--json-log` file and any stream the
    /// front-end added. Worker threads share these handles so they never
    /// need to traverse a configured path after privileges have been reduced.
    pub(super) event_sinks: Vec<Arc<dyn EventSink>>,
    /// The PCAP sidecar JSONL, opened before sandboxing and uid drop.
    pub(super) pcap_sidecar_file: Option<Arc<FileSink>>,

    /// Pre-created PCAPNG output file. Held until worker startup so the writer
    /// thread can use the exact file handle allowed by the sandbox.
    pub(super) pcapng_export_file: Option<File>,

    /// Sandbox status (Linux Landlock / macOS Seatbelt / Windows restricted token)
    pub(super) sandbox_info: Arc<RwLock<SandboxReport>>,

    /// Every background thread spawned by `start` and `start_workers`, joined
    /// by [`App::stop`] so the export writers have flushed before the process
    /// exits.
    workers: Mutex<Vec<JoinHandle<()>>>,
}

/// Build the GeoIP resolver from explicit database paths when any are
/// configured, otherwise by auto-discovery. Returns `None` when GeoIP is
/// disabled or no database could be opened; a miss at explicitly configured
/// paths is logged as a warning, an auto-discovery miss as info.
fn build_geoip_resolver(config: &Config) -> Option<Arc<GeoIpResolver>> {
    if config.disable_geoip {
        info!("GeoIP resolution disabled by configuration");
        return None;
    }
    let explicit = config.geoip_country_path.is_some()
        || config.geoip_asn_path.is_some()
        || config.geoip_city_path.is_some();
    let resolver = if explicit {
        GeoIpResolver::new(GeoIpConfig {
            country_db_path: config
                .geoip_country_path
                .as_ref()
                .map(std::path::PathBuf::from),
            asn_db_path: config.geoip_asn_path.as_ref().map(std::path::PathBuf::from),
            city_db_path: config
                .geoip_city_path
                .as_ref()
                .map(std::path::PathBuf::from),
            ..Default::default()
        })
    } else {
        GeoIpResolver::with_auto_discovery()
    };
    if resolver.is_available() {
        let (has_country, has_asn, has_city) = resolver.get_status();
        info!(
            "GeoIP resolution enabled - Country: {}, ASN: {}, City: {}",
            has_country, has_asn, has_city
        );
        Some(Arc::new(resolver))
    } else if explicit {
        warn!("GeoIP databases not found at specified paths - location display disabled");
        None
    } else {
        info!("GeoIP databases not found - location display disabled");
        None
    }
}

impl App {
    /// Create an application instance with default output handles. Tests only:
    /// production goes through [`new_with_output_handles`](Self::new_with_output_handles).
    #[cfg(test)]
    pub(crate) fn new(config: Config) -> Result<Self> {
        Self::new_with_output_handles(config, AppOutputHandles::default())
    }

    pub fn new_with_output_handles(
        config: Config,
        output_handles: AppOutputHandles,
    ) -> Result<Self> {
        let AppOutputHandles {
            json_log,
            pcap_sidecar,
            pcapng_export,
            mut event_sinks,
        } = output_handles;
        if config.json_log_file.is_some() != json_log.is_some() {
            anyhow::bail!("JSON logging requires exactly one matching pre-opened output handle");
        }
        if config.pcap_export_file.is_some() != pcap_sidecar.is_some() {
            anyhow::bail!(
                "PCAP export requires exactly one matching pre-opened sidecar output handle"
            );
        }
        if config.pcapng_export_file.is_some() != pcapng_export.is_some() {
            anyhow::bail!("PCAPNG export requires exactly one matching pre-opened output handle");
        }

        if let Some(file) = json_log {
            event_sinks.push(Arc::new(FileSink::new(
                file,
                config.json_log_file.clone().unwrap_or_default(),
            )));
        }
        let pcap_sidecar_file = pcap_sidecar.map(|file| {
            Arc::new(FileSink::new(
                file,
                config
                    .pcap_export_file
                    .as_ref()
                    .map(|path| format!("{path}.connections.jsonl"))
                    .unwrap_or_default(),
            ))
        });

        let service_lookup = ServiceLookup::from_embedded().unwrap_or_else(|e| {
            warn!("Failed to load embedded services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

        let oui_lookup = match OuiLookup::from_embedded() {
            Ok(oui) => Some(Arc::new(oui)),
            Err(e) => {
                warn!("Failed to load OUI vendor database: {}", e);
                None
            }
        };

        let dns_resolver = if config.resolve_dns {
            info!("DNS resolution enabled - starting background resolver");
            Some(Arc::new(DnsResolver::with_defaults()))
        } else {
            None
        };

        let geoip_resolver = build_geoip_resolver(&config);
        let is_loading = config.show_startup_splash;

        Ok(Self {
            config,
            should_stop: Arc::new(AtomicBool::new(false)),
            tracker: Arc::new(ConnectionTracker::new()),
            connections_snapshot: Arc::new(RwLock::new(Vec::new())),
            snapshot_generation: Arc::new(AtomicU64::new(0)),
            show_historic: Arc::new(AtomicBool::new(false)),
            service_lookup: Arc::new(service_lookup),
            oui_lookup,
            stats: Arc::new(AppStats::default()),
            is_loading: Arc::new(AtomicBool::new(is_loading)),
            current_interface: Arc::new(RwLock::new(None)),
            linktype: Arc::new(RwLock::new(None)),
            capture_status: Arc::new(RwLock::new(CaptureStatus::default())),
            pktap_active: Arc::new(AtomicBool::new(false)),
            process_detection_status: Arc::new(RwLock::new(ProcessDetectionStatus::with_method(
                "initializing...",
            ))),
            socket_snapshot: Arc::new(RwLock::new(SocketSnapshot::default())),
            interface_stats: Arc::new(DashMap::new()),
            interface_rates: Arc::new(DashMap::new()),
            interface_traffic_windows: Arc::new(DashMap::new()),
            interface_traffic_history: Arc::new(Mutex::new(HashMap::new())),
            traffic_history: Arc::new(RwLock::new(TrafficHistory::new(TRAFFIC_HISTORY_CAPACITY))),
            conn_rate_history: Arc::new(RwLock::new(HashMap::new())),
            process_activity: Arc::new(RwLock::new(ProcessActivityTracker::new())),
            dns_resolver,
            geoip_resolver,
            packet_rx: None,
            event_sinks,
            pcap_sidecar_file,
            pcapng_export_file: pcapng_export,
            sandbox_info: Arc::new(RwLock::new(SandboxReport::default())),
            workers: Mutex::new(Vec::new()),
        })
    }

    /// Keep a spawned thread's handle so [`App::stop`] can join it.
    pub(super) fn retain_worker(&self, handle: JoinHandle<()>) {
        self.workers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(handle);
    }

    /// Start the privileged-init background threads only: packet capture (which
    /// opens the raw socket, needs CAP_NET_RAW) and process enrichment (which
    /// loads eBPF, needs CAP_BPF/CAP_PERFMON). These must run BEFORE the sandbox
    /// is applied.
    ///
    /// The DPI parser/worker threads are intentionally NOT started here: the
    /// caller must apply the sandbox and then call [`App::start_workers`]. On
    /// Linux the Landlock domain and dropped capabilities are per-thread and are
    /// only inherited by threads spawned *after* `restrict_self`, so spawning the
    /// parser threads in the worker phase is what places the untrusted-input DPI
    /// code inside the sandbox, even when rustnet runs as root.
    ///
    /// Returns two receivers that signal when privileged initialization is
    /// complete: the first when process detection (including eBPF loading) is
    /// ready, the second when the capture thread has opened the capture
    /// device (or failed to). The caller should wait on both before applying
    /// the sandbox or dropping root: the capture open runs on a background
    /// thread and still needs the privileges.
    pub fn start(
        &mut self,
    ) -> Result<(std::sync::mpsc::Receiver<()>, std::sync::mpsc::Receiver<()>)> {
        info!("Starting network monitor application");

        let tracker = Arc::clone(&self.tracker);

        // Privileged init: opens the raw socket, stashes the packet receiver.
        let capture_ready_rx = self.start_packet_capture_pipeline()?;

        let (process_ready_tx, process_ready_rx) = std::sync::mpsc::sync_channel(1);

        // Delayed on macOS until PKTAP detection has run.
        self.start_process_enrichment_conditional(tracker.clone(), process_ready_tx)?;

        Ok((process_ready_rx, capture_ready_rx))
    }

    /// Start the worker threads: the DPI packet processors plus enrichment,
    /// snapshot, cleanup, and the rate/stats/history collectors.
    ///
    /// Call this AFTER the sandbox has been applied on the main thread (see
    /// [`App::start`]); these threads then inherit the sandbox. Spawning the
    /// packet processors here rather than in `start` is what places the
    /// untrusted-input DPI parsers inside the Landlock domain on Linux.
    pub fn start_workers(&mut self) -> Result<()> {
        let tracker = Arc::clone(&self.tracker);

        for sink in &self.event_sinks {
            sink.start();
        }

        let pcapng_tx = self.start_pcapng_export_thread(tracker.clone())?;

        self.start_packet_processors(tracker.clone(), pcapng_tx)?;

        self.start_geoip_enrichment_thread(tracker.clone())?;

        self.start_snapshot_provider(tracker.clone())?;

        self.start_cleanup_thread(tracker.clone())?;

        self.start_rate_refresh_thread(tracker)?;

        self.start_interface_stats_thread()?;

        self.start_traffic_history_thread()?;

        // Required capture and attribution initialization is already complete.
        // Keep the splash briefly so it reads as an intentional transition.
        if self.config.show_startup_splash {
            let is_loading = Arc::clone(&self.is_loading);
            thread::Builder::new()
                .name("startup_flag".to_string())
                .spawn(move || {
                    thread::sleep(STARTUP_SPLASH_DURATION);
                    is_loading.store(false, Ordering::Relaxed);
                })
                .expect("Failed to spawn startup_flag thread");
        }

        Ok(())
    }

    pub fn get_connections(&self) -> Vec<Connection> {
        self.get_filtered_connections("")
    }

    /// Generation of the current snapshot; bumped on every snapshot rebuild.
    /// The UI loop compares this against the last generation it consumed to
    /// skip re-cloning and re-sorting unchanged data.
    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation.load(Ordering::Acquire)
    }

    /// Count the unfiltered UI snapshot without cloning connection records.
    pub(crate) fn get_connection_counts(&self) -> ConnectionCounts {
        let hide_ptr_lookups = self.dns_resolver.is_some() && !self.config.show_ptr_lookups;
        let snapshot = self.connections_snapshot.read().unwrap();
        ConnectionCounts::from_connections(
            snapshot
                .iter()
                .filter(|connection| !hide_ptr_lookups || !is_ptr_lookup(connection)),
        )
    }

    pub fn get_filtered_connections(&self, filter_query: &str) -> Vec<Connection> {
        let hide_ptr_lookups = self.dns_resolver.is_some() && !self.config.show_ptr_lookups;
        let filter = if filter_query.trim().is_empty() {
            None
        } else {
            Some(ConnectionFilter::parse(filter_query))
        };

        // Filter by reference under the read guard and clone only the
        // matches, instead of cloning the whole snapshot first.
        let snapshot = self.connections_snapshot.read().unwrap();
        snapshot
            .iter()
            .filter(|conn| {
                // Hide DNS PTR queries/responses (used for reverse DNS lookups)
                if hide_ptr_lookups && is_ptr_lookup(conn) {
                    return false;
                }
                filter.as_ref().is_none_or(|f| f.matches(conn))
            })
            .cloned()
            .collect()
    }

    pub(crate) fn get_interface_stats(&self) -> Vec<InterfaceStats> {
        self.interface_stats
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get interface rates (bytes/sec)
    pub(crate) fn get_interface_rates(&self) -> HashMap<String, InterfaceRates> {
        self.interface_rates
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get traffic transferred over each interface's rolling 60-second window.
    pub(crate) fn get_interface_traffic_windows(&self) -> HashMap<String, InterfaceTrafficWindow> {
        self.interface_traffic_windows
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get the latest retained process traffic snapshot.
    pub(crate) fn get_process_activity_snapshot(&self) -> ProcessActivitySnapshot {
        self.process_activity
            .read()
            .map(|activity| activity.snapshot())
            .unwrap_or_default()
    }

    /// RX/TX rate history for one connection (by `Connection::key()`),
    /// as (rx, tx) bytes/sec vectors oldest→newest. None until the
    /// traffic-history thread has sampled the connection at least once.
    pub(crate) fn get_connection_rate_history(&self, key: &str) -> Option<ConnRateHistorySnapshot> {
        self.conn_rate_history
            .read()
            .ok()?
            .get(key)
            .map(|history| ConnRateHistorySnapshot {
                rx: history.rx.iter().copied().collect(),
                tx: history.tx.iter().copied().collect(),
                rx_graph_ceiling: history.rx_scale.ceiling(),
                tx_graph_ceiling: history.tx_scale.ceiling(),
            })
    }

    pub(crate) fn get_traffic_history(&self) -> TrafficHistory {
        self.traffic_history
            .read()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    pub fn get_stats(&self) -> AppStats {
        self.stats.snapshot()
    }

    /// Whether annotated PCAPNG export is active for this run.
    pub(crate) fn is_pcapng_export_enabled(&self) -> bool {
        self.config.pcapng_export_file.is_some()
    }

    /// Whether classic PCAP export is active for this run.
    pub(crate) fn is_pcap_export_enabled(&self) -> bool {
        self.config.pcap_export_file.is_some()
    }

    pub fn is_loading(&self) -> bool {
        self.is_loading.load(Ordering::Relaxed)
    }

    pub(crate) fn get_current_interface(&self) -> Option<String> {
        self.current_interface.read().unwrap().clone()
    }

    /// Get the persistent packet-capture failure shown by the TUI.
    pub(crate) fn get_capture_error(&self) -> Option<String> {
        self.capture_status
            .read()
            .ok()
            .and_then(|status| match &*status {
                CaptureStatus::Failed(message) => Some(message.clone()),
                CaptureStatus::Healthy => None,
            })
    }

    /// Get the current process detection status (method and degradation info)
    pub(crate) fn get_process_detection_status(&self) -> ProcessDetectionStatus {
        self.process_detection_status
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Get the latest host socket inventory.
    pub(crate) fn get_socket_snapshot(&self) -> SocketSnapshot {
        self.socket_snapshot
            .read()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    /// Resolve a conventional service name for a local endpoint.
    pub(crate) fn get_service_name(&self, port: u16, protocol: Protocol) -> Option<&str> {
        self.service_lookup.lookup(port, protocol)
    }

    /// Get sandbox status information. Rendered by the Linux, Windows, and
    /// macOS (with `macos-sandbox`) UIs.
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub(crate) fn get_sandbox_info(&self) -> SandboxReport {
        self.sandbox_info
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn set_sandbox_info(&self, info: SandboxReport) {
        if let Ok(mut guard) = self.sandbox_info.write() {
            *guard = info;
        }
    }

    /// Get link layer information for the current interface
    /// Returns (link_layer_type_name, is_tunnel)
    pub(crate) fn get_link_layer_info(&self) -> (String, bool) {
        use crate::network::link_layer::LinkLayerType;

        if let Ok(linktype_opt) = self.linktype.read()
            && let Some(dlt) = *linktype_opt
        {
            let interface_name = self
                .current_interface
                .read()
                .ok()
                .and_then(|opt| opt.clone())
                .unwrap_or_default();

            let link_type = LinkLayerType::from_dlt_and_name(dlt, &interface_name);
            let type_name = format!("{:?}", link_type);
            let is_tunnel = link_type.is_tunnel();
            return (type_name, is_tunnel);
        }
        (String::from("Unknown"), false)
    }

    pub(crate) fn get_dns_resolver(&self) -> Option<Arc<DnsResolver>> {
        self.dns_resolver.clone()
    }

    pub(crate) fn is_dns_resolution_enabled(&self) -> bool {
        self.dns_resolver.is_some()
    }

    /// The ARP/NDP-learned MAC/vendor mapping for `ip`, if one has been
    /// observed.
    pub(crate) fn lookup_neighbor(&self, ip: std::net::IpAddr) -> Option<NeighborEntry> {
        self.tracker.neighbor(&ip)
    }

    /// Get GeoIP database availability status.
    /// Returns (has_location, has_asn, has_city) where has_location is true when
    /// either the country or city database is loaded.
    pub fn get_geoip_status(&self) -> (bool, bool, bool) {
        match &self.geoip_resolver {
            Some(resolver) => resolver.get_status(),
            None => (false, false, false),
        }
    }

    pub(crate) fn toggle_show_historic(&self) {
        let prev = self.show_historic.load(Ordering::Relaxed);
        self.show_historic.store(!prev, Ordering::Relaxed);
    }

    pub(crate) fn set_show_historic(&self, value: bool) {
        self.show_historic.store(value, Ordering::Relaxed);
    }

    /// Seed the UI snapshot directly. Tests only.
    #[cfg(test)]
    pub(crate) fn set_connections_snapshot_for_test(&self, snapshot: Vec<Connection>) {
        self.snapshot_generation.fetch_add(1, Ordering::Release);
        *self.connections_snapshot.write().unwrap() = snapshot;
    }

    /// Override the loading flag. Tests only.
    #[cfg(test)]
    pub(crate) fn set_loading_for_test(&self, value: bool) {
        self.is_loading.store(value, Ordering::Relaxed);
    }

    /// Seed the tracker's neighbor cache through a real ARP ingest. Tests only.
    #[cfg(test)]
    pub(crate) fn ingest_packet_for_test(&self, parsed: &ParsedPacket) {
        self.tracker.ingest_at(parsed, SystemTime::now());
    }

    /// Override the current interface label. Tests only.
    #[cfg(test)]
    pub(crate) fn set_current_interface_for_test(&self, iface: Option<String>) {
        *self.current_interface.write().unwrap() = iface;
    }

    /// Override packet-capture failure state. Tests only.
    #[cfg(test)]
    pub(crate) fn set_capture_error_for_test(&self, error: Option<&str>) {
        *self.capture_status.write().unwrap() = match error {
            Some(message) => CaptureStatus::Failed(message.to_string()),
            None => CaptureStatus::Healthy,
        };
    }

    /// Seed an interface's cumulative stats. Tests only.
    #[cfg(test)]
    pub(crate) fn set_interface_stats_for_test(&self, name: &str, stats: InterfaceStats) {
        self.interface_stats.insert(name.to_string(), stats);
    }

    /// Seed the host socket inventory. Tests only.
    #[cfg(test)]
    pub(crate) fn set_socket_snapshot_for_test(&self, snapshot: SocketSnapshot) {
        *self.socket_snapshot.write().unwrap() = snapshot;
    }

    /// Seed an interface's rate counters. Tests only.
    #[cfg(test)]
    pub(crate) fn set_interface_rates_for_test(&self, name: &str, rates: InterfaceRates) {
        self.interface_rates.insert(name.to_string(), rates);
    }

    /// Seed an interface's rolling traffic window. Tests only.
    #[cfg(test)]
    pub(crate) fn set_interface_traffic_window_for_test(
        &self,
        name: &str,
        window: InterfaceTrafficWindow,
    ) {
        self.interface_traffic_windows
            .insert(name.to_string(), window);
    }

    /// Override the traffic history ring. Tests only.
    #[cfg(test)]
    pub(crate) fn set_traffic_history_for_test(&self, history: TrafficHistory) {
        *self.traffic_history.write().unwrap() = history;
    }

    /// Feed a deterministic process-activity sample. Tests only.
    #[cfg(test)]
    pub(crate) fn observe_process_activity_for_test(
        &self,
        connections: &[Connection],
        now: SystemTime,
    ) {
        self.process_activity.write().unwrap().observe_sources(
            now,
            |observe| {
                for connection in connections.iter().filter(|conn| !conn.is_historic) {
                    observe(connection);
                }
            },
            |observe| {
                for connection in connections.iter().filter(|conn| conn.is_historic) {
                    observe(connection);
                }
            },
        );
    }

    /// Drop every tracked connection, the UI snapshot, all traffic history,
    /// and reset the statistics counters.
    pub(crate) fn clear_all_connections(&self) {
        info!("Clearing all connections and resetting statistics");

        self.tracker.clear();
        self.show_historic.store(false, Ordering::Relaxed);

        if let Ok(mut snapshot) = self.connections_snapshot.write() {
            snapshot.clear();
        }

        if let Ok(mut history) = self.traffic_history.write() {
            history.clear();
        }

        if let Ok(mut activity) = self.process_activity.write() {
            activity.clear();
        }

        // Keep the process and interface sides of Activity coverage on the
        // same post-clear window. Holding this lock prevents the collector
        // from republishing a window based on pre-clear samples.
        let mut interface_history = self
            .interface_traffic_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        interface_history.clear();
        self.interface_traffic_windows.clear();
        drop(interface_history);

        self.stats.reset_counters();

        info!("All connections cleared successfully");
    }

    /// Signal every worker thread to stop and join them, waiting at most
    /// [`WORKER_JOIN_TIMEOUT`] overall. Idempotent: a second call returns
    /// immediately.
    pub fn stop(&self) {
        if self.should_stop.swap(true, Ordering::Relaxed) {
            return;
        }
        info!("Stopping application");

        // Connections not yet cleaned up still need their sidecar record.
        if let Some(writer) = &self.pcap_sidecar_file
            && let Ok(connections) = self.connections_snapshot.read()
        {
            let count = connections.len();
            let with_pids = connections.iter().filter(|c| c.pid.is_some()).count();

            for conn in connections.iter() {
                log_pcap_connection(writer, conn);
            }

            info!(
                "Wrote {} remaining connections ({} with PIDs) to JSONL",
                count, with_pids
            );
        }

        self.join_workers();

        // Producers are gone, so the sinks' writer threads see the complete
        // event stream before they drain and exit.
        let mut sink_threads: Vec<JoinHandle<()>> = self
            .event_sinks
            .iter()
            .filter_map(|sink| sink.shutdown())
            .collect();
        join_with_timeout(&mut sink_threads);
    }

    fn join_workers(&self) {
        let mut workers = self.workers.lock().unwrap_or_else(PoisonError::into_inner);
        join_with_timeout(&mut workers);
    }
}

/// Join every finished thread, waiting at most [`WORKER_JOIN_TIMEOUT`] for
/// the rest; whatever is still running is detached.
fn join_with_timeout(threads: &mut Vec<JoinHandle<()>>) {
    let deadline = Instant::now() + WORKER_JOIN_TIMEOUT;
    loop {
        for handle in threads.extract_if(.., |handle| handle.is_finished()) {
            let name = thread_label(&handle);
            if handle.join().is_err() {
                warn!("Worker thread {name} panicked");
            }
        }
        if threads.is_empty() || Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !threads.is_empty() {
        let names: Vec<String> = threads.iter().map(thread_label).collect();
        warn!(
            "Worker threads still running after {:?}, exiting without them: {}",
            WORKER_JOIN_TIMEOUT,
            names.join(", ")
        );
        // Dropping the handles detaches the threads; process exit reaps them.
        threads.clear();
    }
}

fn thread_label(handle: &JoinHandle<()>) -> String {
    handle.thread().name().unwrap_or("<unnamed>").to_string()
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod activity_reset_tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use std::net::SocketAddr;

    fn interface_sample(timestamp: SystemTime, rx_bytes: u64, tx_bytes: u64) -> InterfaceStats {
        InterfaceStats {
            interface_name: "eth0".to_string(),
            rx_bytes,
            tx_bytes,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp,
        }
    }

    #[test]
    fn clear_resets_both_activity_coverage_windows() {
        let app = crate::ui::test_support::test_app();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 40_000)),
            SocketAddr::from(([198, 51, 100, 1], 443)),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.bytes_sent = 2_000;
        app.observe_process_activity_for_test(&[conn], now);

        let first = interface_sample(now, 1_000, 500);
        let second = interface_sample(now + Duration::from_secs(30), 5_000, 2_500);
        app.interface_traffic_history
            .lock()
            .unwrap()
            .insert("eth0".to_string(), VecDeque::from([first, second]));
        app.interface_traffic_windows.insert(
            "eth0".to_string(),
            InterfaceTrafficWindow {
                rx_bytes: 4_000,
                tx_bytes: 2_000,
            },
        );

        app.clear_all_connections();

        assert_eq!(app.get_process_activity_snapshot().window_tx_bytes, 0);
        assert!(app.get_interface_traffic_windows().is_empty());
        assert!(app.interface_traffic_history.lock().unwrap().is_empty());
    }
}
