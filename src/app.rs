//! Application orchestration: spins up the packet-capture pipeline, the
//! DNS resolver, the GeoIP resolver, and the interface-stats collector,
//! and owns the shared `DashMap` connection table that the TUI renders.
//!
//! Threads communicate over `crossbeam` channels; counters use atomics.

use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::filter::ConnectionFilter;

use crate::export::pcapng::{self, PcapngWriter};
use crate::network::{
    capture::{CaptureConfig, CapturedPacket, PacketReader, setup_packet_capture},
    dns::DnsResolver,
    geoip::{GeoIpConfig, GeoIpResolver},
    interface_stats::{
        InterfaceRates, InterfaceStats, InterfaceStatsProvider, InterfaceTrafficWindow,
    },
    oui::OuiLookup,
    parser::{PacketParser, ParsedPacket, ParserConfig},
    platform::create_process_lookup,
    process_activity::{ProcessActivitySnapshot, ProcessActivityTracker},
    services::ServiceLookup,
    tracker::{ConnectionTracker, IngestOutcome},
    types::{
        ApplicationProtocol, Connection, ConnectionKey, DnsQueryType, Protocol, TrafficHistory,
    },
};

// Platform-specific interface stats provider
#[cfg(target_os = "freebsd")]
use crate::network::platform::FreeBSDStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "linux")]
use crate::network::platform::LinuxStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "macos")]
use crate::network::platform::MacOSStatsProvider as PlatformStatsProvider;
#[cfg(target_os = "windows")]
use crate::network::platform::WindowsStatsProvider as PlatformStatsProvider;

use std::collections::{HashMap, VecDeque};

/// Sandbox status information for UI display
#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    all(target_os = "macos", feature = "macos-sandbox")
))]
#[derive(Debug, Clone, Default)]
pub struct SandboxInfo {
    /// Overall status description
    pub status: String,
    /// Whether network connections are blocked
    #[cfg(any(
        target_os = "linux",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub net_restricted: bool,
    // Linux-specific fields (Landlock + capabilities)
    /// Whether CAP_NET_RAW was dropped
    #[cfg(target_os = "linux")]
    pub cap_dropped: bool,
    /// Whether CAP_BPF/CAP_PERFMON were dropped
    #[cfg(target_os = "linux")]
    pub ebpf_caps_dropped: bool,
    /// Whether the root uid/gid were dropped (setresuid to the sudo user or nobody)
    #[cfg(target_os = "linux")]
    pub uid_dropped: bool,
    /// Whether Landlock is available on this kernel
    #[cfg(target_os = "linux")]
    pub landlock_available: bool,
    /// Whether Landlock filesystem restrictions are applied
    #[cfg(target_os = "linux")]
    pub fs_restricted: bool,
    /// Whether Landlock scope restrictions (abstract UNIX sockets + signals) are applied
    #[cfg(target_os = "linux")]
    pub scope_restricted: bool,
    /// Effective Landlock ABI negotiated with the kernel (e.g. `Some(6)`), or `None`
    #[cfg(target_os = "linux")]
    pub landlock_abi: Option<u8>,
    /// Whether PR_SET_NO_NEW_PRIVS is set (applied even with `--no-sandbox`)
    #[cfg(target_os = "linux")]
    pub no_new_privs: bool,
    // macOS-specific fields (Seatbelt)
    /// Whether Seatbelt sandbox was applied
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    pub seatbelt_applied: bool,
    /// Whether the root uid/gid were dropped (setuid to the sudo user or nobody)
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    pub uid_dropped: bool,
    /// Whether filesystem write restrictions are applied
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    pub fs_restricted: bool,
    // Windows-specific fields (Restricted token + Job Object)
    /// Whether dangerous privileges were removed
    #[cfg(target_os = "windows")]
    pub privileges_removed: bool,
    /// Number of privileges removed
    #[cfg(target_os = "windows")]
    pub privileges_removed_count: u32,
    /// Whether job object was applied
    #[cfg(target_os = "windows")]
    pub job_object_applied: bool,
}

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

// Connection-table limits (max connections, historic retention, QUIC mappings)
// now live in `rustnet_core::network::tracker::TrackerConfig`, which the
// `ConnectionTracker` enforces. The defaults match the previous constants.

/// Maximum queued packets before backpressure drops packets.
/// At ~1500 bytes per packet, 10,000 packets ≈ 15 MB of buffer.
const MAX_PACKET_QUEUE: usize = 10_000;
const MAX_PCAPNG_QUEUE: usize = 10_000;
const MAX_PCAPNG_RETRY_RECORDS: usize = 10_000;
const MAX_PCAPNG_RETRY_BYTES: usize = 64 * 1024 * 1024;
const PCAPNG_ATTRIBUTION_WAIT: Duration = Duration::from_secs(2);
const STARTUP_SPLASH_DURATION: Duration = Duration::from_millis(750);

#[derive(Debug)]
struct PcapngRecord {
    data: Vec<u8>,
    timestamp: SystemTime,
    original_len: u32,
    key: Option<ConnectionKey>,
    deadline: Instant,
}

/// Open or create a file for appending with restrictive permissions (0o600 on Unix).
///
/// Ensures log files containing connection metadata are not world-readable, and
/// refuses to follow symlinks (`O_NOFOLLOW`) so a planted symlink can't redirect
/// the privileged write elsewhere.
///
/// On failure this surfaces a single warning (rather than aborting the running
/// monitor): the callers run in the per-event hot path, so silently dropping the
/// error — as the previous `if let Ok(..)` did — would disable connection logging
/// with no indication. We warn once to avoid per-event log spam.
fn open_log_file(path: &str) -> std::io::Result<File> {
    let result = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            OpenOptions::new()
                .create(true)
                .append(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(path)
        }

        #[cfg(not(unix))]
        {
            OpenOptions::new().create(true).append(true).open(path)
        }
    };

    if let Err(ref e) = result {
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            // The log file is opened with O_NOFOLLOW, so a symlinked path is
            // refused. Depending on privilege and `fs.protected_symlinks`, that
            // surfaces as ELOOP (raw O_NOFOLLOW) or EACCES (kernel symlink
            // protection denies first), so we mention symlinks for both rather
            // than keying on a single errno.
            #[cfg(unix)]
            let symlink_hint = matches!(
                e.raw_os_error(),
                Some(code) if code == libc::ELOOP || code == libc::EACCES
            );
            #[cfg(not(unix))]
            let symlink_hint = false;

            if symlink_hint {
                warn!(
                    "Refusing to write log to '{}': {} (path may be a symlink; \
                     symlinks are rejected via O_NOFOLLOW). Connection logging is disabled.",
                    path, e
                );
            } else {
                warn!(
                    "Failed to open log file '{}': {}. Connection logging is disabled.",
                    path, e
                );
            }
        }
    }

    result
}

fn system_time_to_timeval(timestamp: SystemTime) -> libc::timeval {
    let duration = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    #[cfg(unix)]
    {
        libc::timeval {
            tv_sec: duration.as_secs() as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        }
    }
    #[cfg(windows)]
    {
        libc::timeval {
            tv_sec: duration.as_secs() as libc::c_long,
            tv_usec: duration.subsec_micros() as libc::c_long,
        }
    }
}

/// Helper function to log connection events as JSON
fn log_connection_event(
    json_log_path: &str,
    event_type: &str,
    conn: &Connection,
    duration_secs: Option<u64>,
    dns_resolver: Option<&DnsResolver>,
) {
    // Build JSON object based on event type
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event": event_type,
        "protocol": conn.protocol.to_string(),
        "source_ip": conn.local_addr.ip().to_string(),
        "source_port": conn.local_addr.port(),
        "destination_ip": conn.remote_addr.ip().to_string(),
        "destination_port": conn.remote_addr.port(),
    });

    // Add hostname fields if DNS resolution is enabled and hostnames are resolved
    // Skip ARP connections to avoid feedback loop (DNS lookups generate ARP traffic)
    if let Some(resolver) = dns_resolver.filter(|_| conn.protocol != Protocol::Arp) {
        if let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip()) {
            event["destination_hostname"] = json!(hostname);
        }
        if let Some(hostname) = resolver.get_hostname(&conn.local_addr.ip()) {
            event["source_hostname"] = json!(hostname);
        }
    }

    // Add process information if available
    if let Some(pid) = conn.pid {
        event["pid"] = json!(pid);
    }
    if let Some(process_name) = &conn.process_name {
        event["process_name"] = json!(process_name);
    }

    // Add Kubernetes attribution if the process is part of a pod
    #[cfg(feature = "kubernetes")]
    if let Some(k8s) = &conn.k8s_info {
        let mut obj = serde_json::Map::new();
        if let Some(v) = &k8s.pod_uid {
            obj.insert("pod_uid".into(), json!(v));
        }
        if let Some(v) = &k8s.pod_name {
            obj.insert("pod_name".into(), json!(v));
        }
        if let Some(v) = &k8s.pod_namespace {
            obj.insert("pod_namespace".into(), json!(v));
        }
        if let Some(v) = &k8s.container_id {
            obj.insert("container_id".into(), json!(v));
        }
        if let Some(v) = &k8s.container_name {
            obj.insert("container_name".into(), json!(v));
        }
        if let Some(v) = &k8s.cgroup_path {
            obj.insert("cgroup_path".into(), json!(v));
        }
        if !obj.is_empty() {
            event["kubernetes"] = serde_json::Value::Object(obj);
        }
    }

    // Add service name if available
    if let Some(service_name) = &conn.service_name {
        event["service_name"] = json!(service_name);
    }

    // Add connection direction (only for TCP when we observed the handshake)
    if let Some(is_outgoing) = conn.connection_direction {
        event["direction"] = json!(if is_outgoing { "outgoing" } else { "incoming" });
    }

    // Add DPI information if available
    if let Some(dpi) = &conn.dpi_info {
        event["dpi_protocol"] = json!(dpi.application.to_string());

        // Extract domain/hostname from DPI info
        match &dpi.application {
            ApplicationProtocol::Dns(info) => {
                if let Some(domain) = &info.query_name {
                    event["dpi_domain"] = json!(domain);
                }
            }
            ApplicationProtocol::Http(info) => {
                if let Some(host) = &info.host {
                    event["dpi_domain"] = json!(host);
                }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(tls_info) = &info.tls_info
                    && let Some(sni) = &tls_info.sni
                {
                    event["dpi_domain"] = json!(sni);
                }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(tls_info) = &info.tls_info
                    && let Some(sni) = &tls_info.sni
                {
                    event["dpi_domain"] = json!(sni);
                }
            }
            _ => {}
        }
    }

    // Add GeoIP information if available
    if let Some(ref geoip) = conn.geoip_info {
        if let Some(ref cc) = geoip.country_code {
            event["geoip_country_code"] = json!(cc);
        }
        if let Some(ref name) = geoip.country_name {
            event["geoip_country_name"] = json!(name);
        }
        if let Some(asn) = geoip.asn {
            event["geoip_asn"] = json!(asn);
        }
        if let Some(ref org) = geoip.as_org {
            event["geoip_as_org"] = json!(org);
        }
        if let Some(ref city) = geoip.city {
            event["geoip_city"] = json!(city);
        }
        if let Some(ref postal) = geoip.postal_code {
            event["geoip_postal_code"] = json!(postal);
        }
    }

    // Add connection statistics for closed events
    if event_type == "connection_closed" {
        event["bytes_sent"] = json!(conn.bytes_sent);
        event["bytes_received"] = json!(conn.bytes_received);
        if let Some(duration) = duration_secs {
            event["duration_secs"] = json!(duration);
        }
    }

    // Write to file (restrictive permissions: 0o600 on Unix)
    if let Ok(mut file) = open_log_file(json_log_path)
        && let Ok(json_str) = serde_json::to_string(&event)
    {
        let _ = writeln!(file, "{}", json_str);
    }
}

/// Helper function to log connection info to PCAP sidecar file (JSONL format)
fn log_pcap_connection(pcap_path: &str, conn: &Connection) {
    let json_path = format!("{}.connections.jsonl", pcap_path);

    // Build base event without GeoIP fields
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "protocol": conn.protocol.to_string(),
        "local_addr": conn.local_addr.to_string(),
        "remote_addr": conn.remote_addr.to_string(),
        "pid": conn.pid,
        "process_name": conn.process_name,
        "first_seen": conn.created_at,
        "last_seen": conn.last_activity,
        "bytes_sent": conn.bytes_sent,
        "bytes_received": conn.bytes_received,
        "state": conn.state(),
    });

    // Add Kubernetes attribution if the process is part of a pod
    #[cfg(feature = "kubernetes")]
    if let Some(k8s) = &conn.k8s_info {
        let mut obj = serde_json::Map::new();
        if let Some(v) = &k8s.pod_uid {
            obj.insert("pod_uid".into(), json!(v));
        }
        if let Some(v) = &k8s.pod_name {
            obj.insert("pod_name".into(), json!(v));
        }
        if let Some(v) = &k8s.pod_namespace {
            obj.insert("pod_namespace".into(), json!(v));
        }
        if let Some(v) = &k8s.container_id {
            obj.insert("container_id".into(), json!(v));
        }
        if let Some(v) = &k8s.container_name {
            obj.insert("container_name".into(), json!(v));
        }
        if let Some(v) = &k8s.cgroup_path {
            obj.insert("cgroup_path".into(), json!(v));
        }
        if !obj.is_empty() {
            event["kubernetes"] = serde_json::Value::Object(obj);
        }
    }

    // Only add GeoIP fields when they have actual values
    if let Some(ref geoip) = conn.geoip_info {
        if let Some(ref cc) = geoip.country_code {
            event["geoip_country_code"] = json!(cc);
        }
        if let Some(ref name) = geoip.country_name {
            event["geoip_country_name"] = json!(name);
        }
        if let Some(asn) = geoip.asn {
            event["geoip_asn"] = json!(asn);
        }
        if let Some(ref org) = geoip.as_org {
            event["geoip_as_org"] = json!(org);
        }
        if let Some(ref postal) = geoip.postal_code {
            event["geoip_postal_code"] = json!(postal);
        }
        if let Some(ref city) = geoip.city {
            event["geoip_city"] = json!(city);
        }
    }

    if let Ok(mut file) = open_log_file(&json_path)
        && let Ok(json_str) = serde_json::to_string(&event)
    {
        let _ = writeln!(file, "{}", json_str);
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
            refresh_interval: 1000,
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
    pub pcapng_export: Option<File>,
}

/// Application statistics
#[derive(Debug)]
pub struct AppStats {
    pub packets_processed: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub connections_tracked: AtomicU64,
    pub last_update: RwLock<Instant>,
    // TCP analytics totals (since program start)
    pub total_tcp_retransmits: AtomicU64,
    pub total_tcp_out_of_order: AtomicU64,
    pub total_tcp_fast_retransmits: AtomicU64,
    pub pcap_records_written: AtomicU64,
    pub pcapng_records_queued: AtomicU64,
    pub pcapng_records_written: AtomicU64,
    pub pcapng_records_annotated: AtomicU64,
    pub pcapng_records_unannotated: AtomicU64,
    pub pcapng_records_dropped: AtomicU64,
    pub pcapng_export_errors: AtomicU64,
}

impl Default for AppStats {
    fn default() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            connections_tracked: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
            total_tcp_retransmits: AtomicU64::new(0),
            total_tcp_out_of_order: AtomicU64::new(0),
            total_tcp_fast_retransmits: AtomicU64::new(0),
            pcap_records_written: AtomicU64::new(0),
            pcapng_records_queued: AtomicU64::new(0),
            pcapng_records_written: AtomicU64::new(0),
            pcapng_records_annotated: AtomicU64::new(0),
            pcapng_records_unannotated: AtomicU64::new(0),
            pcapng_records_dropped: AtomicU64::new(0),
            pcapng_export_errors: AtomicU64::new(0),
        }
    }
}

/// Ring buffers of per-connection RX/TX rates (bytes/sec), capped at
/// the same 60-sample window as [`TrafficHistory`].
#[derive(Debug, Clone, Default)]
pub struct ConnRateHistory {
    pub rx: VecDeque<u64>,
    pub tx: VecDeque<u64>,
}

impl ConnRateHistory {
    fn push(&mut self, rx: u64, tx: u64, cap: usize) {
        if self.rx.len() >= cap {
            self.rx.pop_front();
        }
        if self.tx.len() >= cap {
            self.tx.pop_front();
        }
        self.rx.push_back(rx);
        self.tx.push_back(tx);
    }
}

/// Main application state
pub struct App {
    /// Configuration
    config: Config,

    /// Control flag for graceful shutdown
    should_stop: Arc<AtomicBool>,

    /// Live connection tracker (active + historic tables, RTT, QUIC coalescing,
    /// and lifecycle cleanup). Shared with background threads. This is the same
    /// `rustnet_core::network::tracker::ConnectionTracker` headless tools use —
    /// the single source of truth for connection state.
    tracker: Arc<ConnectionTracker>,

    /// Current connections snapshot for UI
    connections_snapshot: Arc<RwLock<Vec<Connection>>>,

    /// Bumped by the snapshot thread after each snapshot write. Lets the UI
    /// loop skip re-cloning and re-sorting an unchanged snapshot (the
    /// snapshot refreshes every `refresh_interval` ms, the UI ticks every
    /// 200ms — without this, most ticks redo identical work).
    snapshot_generation: Arc<AtomicU64>,

    /// Whether to include historic connections in the snapshot
    show_historic: Arc<AtomicBool>,

    /// Service name lookup
    service_lookup: Arc<ServiceLookup>,

    /// OUI vendor lookup for MAC addresses
    oui_lookup: Option<Arc<OuiLookup>>,

    /// Application statistics
    stats: Arc<AppStats>,

    /// Loading state
    is_loading: Arc<AtomicBool>,

    /// Current network interface name
    current_interface: Arc<RwLock<Option<String>>>,

    /// Data link type for packet parsing (needed for PKTAP detection)
    linktype: Arc<RwLock<Option<i32>>>,

    /// Set when capture setup fails before a linktype can be discovered.
    capture_failed: Arc<AtomicBool>,

    /// Whether PKTAP is active (macOS only) - used to disable process enrichment
    pktap_active: Arc<AtomicBool>,

    /// Current process detection status (method and degradation info)
    process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,

    /// Interface statistics (cumulative totals)
    interface_stats: Arc<DashMap<String, InterfaceStats>>,

    /// Interface rates (per-second rates)
    interface_rates: Arc<DashMap<String, InterfaceRates>>,

    /// Traffic transferred over the latest rolling 60-second interface window.
    interface_traffic_windows: Arc<DashMap<String, InterfaceTrafficWindow>>,

    /// Cumulative interface samples backing the rolling traffic windows.
    /// Shared with the clear path so both sides of Activity coverage reset
    /// atomically instead of the polling thread restoring pre-clear samples.
    interface_traffic_history: Arc<Mutex<HashMap<String, VecDeque<InterfaceStats>>>>,

    /// Traffic history for graph visualization
    traffic_history: Arc<RwLock<TrafficHistory>>,

    /// Per-connection RX/TX rate history (bytes/sec, oldest→newest),
    /// keyed by `Connection::key()`. Sampled by the traffic-history
    /// thread on the same 1s cadence as `traffic_history`, so the
    /// Details tab can draw per-connection waves that scroll in sync
    /// with the aggregate graphs. Entries for vanished connections are
    /// dropped each sample.
    conn_rate_history: Arc<RwLock<HashMap<String, ConnRateHistory>>>,

    /// Process traffic derived from active and bounded historic connections.
    process_activity: Arc<RwLock<ProcessActivityTracker>>,

    /// DNS resolver for reverse DNS lookups
    dns_resolver: Option<Arc<DnsResolver>>,

    /// GeoIP resolver for location/ASN lookups
    geoip_resolver: Option<Arc<GeoIpResolver>>,

    /// Receiver half of the packet channel, stashed between the privileged
    /// startup phase (`start`: capture/eBPF threads that need capabilities) and
    /// the worker phase (`start_workers`: the DPI parser threads, spawned after
    /// the sandbox is applied so they inherit it). Taken by `start_workers`.
    packet_rx: Option<Receiver<Vec<CapturedPacket>>>,

    /// Pre-created PCAPNG output file. Held until worker startup so the writer
    /// thread can use the exact file handle allowed by the sandbox.
    pcapng_export_file: Option<File>,

    /// Sandbox status (Linux Landlock / macOS Seatbelt / Windows restricted token)
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    sandbox_info: Arc<RwLock<SandboxInfo>>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config) -> Result<Self> {
        if config.pcapng_export_file.is_some() {
            anyhow::bail!(
                "PCAPNG export requires a pre-created output handle; use App::new_with_output_handles"
            );
        }
        Self::new_with_output_handles(config, AppOutputHandles::default())
    }

    pub fn new_with_output_handles(
        config: Config,
        mut output_handles: AppOutputHandles,
    ) -> Result<Self> {
        // Load service definitions
        let service_lookup = ServiceLookup::from_embedded().unwrap_or_else(|e| {
            warn!("Failed to load embedded services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

        // Load OUI vendor database
        let oui_lookup = match OuiLookup::from_embedded() {
            Ok(oui) => Some(Arc::new(oui)),
            Err(e) => {
                warn!("Failed to load OUI vendor database: {}", e);
                None
            }
        };

        // Initialize DNS resolver if enabled
        let dns_resolver = if config.resolve_dns {
            info!("DNS resolution enabled - starting background resolver");
            Some(Arc::new(DnsResolver::with_defaults()))
        } else {
            None
        };

        // Initialize GeoIP resolver
        let geoip_resolver = if config.disable_geoip {
            info!("GeoIP resolution disabled by configuration");
            None
        } else if config.geoip_country_path.is_some()
            || config.geoip_asn_path.is_some()
            || config.geoip_city_path.is_some()
        {
            // Use explicit paths from config
            let geoip_config = GeoIpConfig {
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
            };
            let resolver = GeoIpResolver::new(geoip_config);
            if resolver.is_available() {
                let (has_country, has_asn, has_city) = resolver.get_status();
                info!(
                    "GeoIP resolution enabled - Country: {}, ASN: {}, City: {}",
                    has_country, has_asn, has_city
                );
                Some(Arc::new(resolver))
            } else {
                warn!("GeoIP databases not found at specified paths - location display disabled");
                None
            }
        } else {
            // Auto-discover databases
            let resolver = GeoIpResolver::with_auto_discovery();
            if resolver.is_available() {
                let (has_country, has_asn, has_city) = resolver.get_status();
                info!(
                    "GeoIP resolution enabled - Country: {}, ASN: {}, City: {}",
                    has_country, has_asn, has_city
                );
                Some(Arc::new(resolver))
            } else {
                info!("GeoIP databases not found - location display disabled");
                None
            }
        };

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
            is_loading: Arc::new(AtomicBool::new(true)),
            current_interface: Arc::new(RwLock::new(None)),
            linktype: Arc::new(RwLock::new(None)),
            capture_failed: Arc::new(AtomicBool::new(false)),
            pktap_active: Arc::new(AtomicBool::new(false)),
            process_detection_status: Arc::new(RwLock::new(ProcessDetectionStatus::with_method(
                "initializing...",
            ))),
            interface_stats: Arc::new(DashMap::new()),
            interface_rates: Arc::new(DashMap::new()),
            interface_traffic_windows: Arc::new(DashMap::new()),
            interface_traffic_history: Arc::new(Mutex::new(HashMap::new())),
            traffic_history: Arc::new(RwLock::new(TrafficHistory::new(60))), // 60 seconds of history
            conn_rate_history: Arc::new(RwLock::new(HashMap::new())),
            process_activity: Arc::new(RwLock::new(ProcessActivityTracker::new())),
            dns_resolver,
            geoip_resolver,
            packet_rx: None,
            pcapng_export_file: output_handles.pcapng_export.take(),
            #[cfg(any(
                target_os = "linux",
                target_os = "windows",
                all(target_os = "macos", feature = "macos-sandbox")
            ))]
            sandbox_info: Arc::new(RwLock::new(SandboxInfo::default())),
        })
    }

    /// Start the privileged-init background threads only: packet capture (which
    /// opens the raw socket — needs CAP_NET_RAW) and process enrichment (which
    /// loads eBPF — needs CAP_BPF/CAP_PERFMON). These must run BEFORE the sandbox
    /// is applied.
    ///
    /// The DPI parser/worker threads are intentionally NOT started here — the
    /// caller must apply the sandbox and then call [`App::start_workers`]. On
    /// Linux the Landlock domain and dropped capabilities are per-thread and are
    /// only inherited by threads spawned *after* `restrict_self`, so spawning the
    /// parser threads in the worker phase is what places the untrusted-input DPI
    /// code inside the sandbox — even when rustnet runs as root.
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

        // Shared connection tracker (active + historic tables, RTT, QUIC)
        let tracker = Arc::clone(&self.tracker);

        // Phase 1: privileged init. Start the capture pipeline (opens the raw
        // socket and stashes the packet receiver for the worker phase).
        let capture_ready_rx = self.start_packet_capture_pipeline()?;

        // Create channel to signal when process detection (incl. eBPF) is ready
        let (process_ready_tx, process_ready_rx) = std::sync::mpsc::sync_channel(1);

        // Start process enrichment thread (but delay for PKTAP detection on macOS)
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

        let pcapng_tx = self.start_pcapng_export_thread(tracker.clone())?;

        // Start the DPI packet processing threads (drain the stashed channel).
        self.start_packet_processors(tracker.clone(), pcapng_tx)?;

        // Start GeoIP enrichment thread
        self.start_geoip_enrichment_thread(tracker.clone())?;

        // Start snapshot provider for UI
        self.start_snapshot_provider(tracker.clone())?;

        // Start cleanup thread
        self.start_cleanup_thread(tracker.clone())?;

        // Start rate refresh thread
        self.start_rate_refresh_thread(tracker)?;

        // Start interface stats collection thread
        self.start_interface_stats_thread()?;

        // Start traffic history thread for graph visualization
        self.start_traffic_history_thread()?;

        // Required capture and attribution initialization is already complete.
        // Keep the splash briefly so it reads as an intentional transition.
        let is_loading = Arc::clone(&self.is_loading);
        thread::Builder::new()
            .name("startup_flag".to_string())
            .spawn(move || {
                thread::sleep(STARTUP_SPLASH_DURATION);
                is_loading.store(false, Ordering::Relaxed);
            })
            .expect("Failed to spawn startup_flag thread");

        Ok(())
    }

    /// Phase 1 of the capture pipeline: create the packet channel and start the
    /// capture thread (which opens the raw socket). The receiver is stashed in
    /// `self.packet_rx` for [`App::start_packet_processors`], which runs in the
    /// worker phase after the sandbox has been applied.
    ///
    /// Returns a receiver that fires once the capture thread has finished its
    /// privileged setup (capture device opened, or setup failed).
    fn start_packet_capture_pipeline(&mut self) -> Result<std::sync::mpsc::Receiver<()>> {
        // Create packet channel — sender batches packets, receiver gets Vec<CapturedPacket> per batch
        let (packet_tx, packet_rx) = channel::bounded::<Vec<CapturedPacket>>(MAX_PACKET_QUEUE);

        // Start capture thread
        let capture_ready_rx = self.start_capture_thread(packet_tx)?;

        // Stash the receiver; the processor threads are spawned post-sandbox.
        self.packet_rx = Some(packet_rx);

        Ok(capture_ready_rx)
    }

    /// Spawn the DPI packet-processor threads, draining the channel stashed by
    /// [`App::start_packet_capture_pipeline`].
    fn start_packet_processors(
        &mut self,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) -> Result<()> {
        let packet_rx = self.packet_rx.take().ok_or_else(|| {
            anyhow::anyhow!("packet receiver missing; start() must run before start_workers()")
        })?;

        // Start multiple packet processing threads
        let num_processors = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(4);

        for i in 0..num_processors {
            self.start_packet_processor(i, packet_rx.clone(), tracker.clone(), pcapng_tx.clone());
        }

        Ok(())
    }

    /// Start packet capture thread.
    ///
    /// Returns a receiver that fires once the capture device has been opened
    /// (or the open failed). Callers use it to keep root privileges alive
    /// until the open, which needs them, has actually happened.
    fn start_capture_thread(
        &self,
        packet_tx: Sender<Vec<CapturedPacket>>,
    ) -> Result<std::sync::mpsc::Receiver<()>> {
        // Validate interface exists before spawning thread (fail fast)
        crate::network::capture::validate_interface(&self.config.interface)?;

        let capture_config = CaptureConfig {
            interface: self.config.interface.clone(),
            filter: self.config.bpf_filter.clone(),
            ..Default::default()
        };

        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let current_interface = Arc::clone(&self.current_interface);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_failed = Arc::clone(&self.capture_failed);
        let _pktap_active = Arc::clone(&self.pktap_active);
        let pcap_export_file = self.config.pcap_export_file.clone();
        capture_failed.store(false, Ordering::Relaxed);

        // Fires once the privileged part of capture setup is done (device
        // opened or open failed), so the main thread can drop privileges.
        let (capture_ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel::<()>(1);

        thread::Builder::new()
            .name("pcap_tx".to_string())
            .spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok((capture, device_name, linktype)) => {
                    // Store the actual interface name and linktype being used
                    *current_interface.write().unwrap() = Some(device_name.clone());
                    *linktype_storage.write().unwrap() = Some(linktype);

                    // Drop CAP_NET_RAW now that the socket is open (Linux only)
                    #[cfg(all(target_os = "linux", feature = "landlock"))]
                    {
                        if let Err(e) =
                            crate::network::platform::sandbox::capabilities::drop_cap_net_raw()
                        {
                            warn!("Failed to drop CAP_NET_RAW in capture thread: {}", e);
                        } else {
                            debug!("Dropped CAP_NET_RAW in capture thread");
                        }
                    }

                    // Check if PKTAP is active (linktype 149 or 258)
                    #[cfg(target_os = "macos")]
                    {
                        use crate::network::link_layer::pktap;
                        if pktap::is_pktap_linktype(linktype) {
                            _pktap_active.store(true, Ordering::Relaxed);
                            info!("✓ PKTAP is active - process metadata will be provided directly");
                        } else {
                            // PKTAP not active: bridge the capture layer's reason into
                            // the process-attribution degradation reason. This keeps
                            // rustnet-host decoupled from rustnet-capture — the app
                            // (which orchestrates both) does the translation.
                            use crate::network::capture::PktapUnavailable;
                            use crate::network::platform::{
                                DegradationReason, report_pktap_degradation,
                            };
                            let reason = match crate::network::capture::PKTAP_DEGRADATION_REASON
                                .get()
                            {
                                Some(PktapUnavailable::NoBpfDeviceAccess) => {
                                    DegradationReason::NoBpfDeviceAccess
                                }
                                Some(PktapUnavailable::InterfaceSpecified) => {
                                    DegradationReason::InterfaceSpecified
                                }
                                Some(PktapUnavailable::BpfFilterIncompatible) => {
                                    DegradationReason::BpfFilterIncompatible
                                }
                                Some(PktapUnavailable::MissingRootPrivileges) | None => {
                                    DegradationReason::MissingRootPrivileges
                                }
                            };
                            report_pktap_degradation(reason);
                        }
                    }

                    info!(
                        "Packet capture started successfully on interface: {} (linktype: {})",
                        device_name, linktype
                    );

                    // Initialize PCAP export if configured (must be before PacketReader consumes capture)
                    let mut pcap_savefile = if let Some(ref pcap_path) = pcap_export_file {
                        match capture.savefile(pcap_path) {
                            Ok(savefile) => {
                                info!("PCAP export started: {}", pcap_path);
                                Some(savefile)
                            }
                            Err(e) => {
                                error!("Failed to create PCAP savefile: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    // Privileged setup is complete; the main thread may now
                    // drop root / apply the sandbox.
                    let _ = capture_ready_tx.send(());

                    let mut reader = PacketReader::new(capture);
                    let mut packets_read = 0u64;
                    let mut last_log = Instant::now();
                    let mut last_stats_check = Instant::now();
                    let mut batch: Vec<CapturedPacket> = Vec::with_capacity(100);
                    let mut batch_deadline = Instant::now() + Duration::from_millis(100);

                    loop {
                        if should_stop.load(Ordering::Relaxed) {
                            info!("Capture thread stopping");
                            break;
                        }

                        match reader.next_packet() {
                            Ok(Some(packet)) => {
                                packets_read += 1;

                                // Log first packet immediately
                                if packets_read == 1 {
                                    info!(
                                        "First packet captured! Size: {} bytes",
                                        packet.data.len()
                                    );
                                }

                                // Log every 10000 packets or every 5 seconds
                                if packets_read.is_multiple_of(10000)
                                    || last_log.elapsed() > Duration::from_secs(5)
                                {
                                    info!("Read {} packets so far", packets_read);
                                    last_log = Instant::now();
                                }

                                // Write to PCAP file if enabled
                                if let Some(ref mut savefile) = pcap_savefile {
                                    let ts = system_time_to_timeval(packet.timestamp);
                                    let header = pcap::PacketHeader {
                                        ts,
                                        caplen: packet.data.len() as u32,
                                        len: packet.original_len.max(packet.data.len() as u32),
                                    };
                                    savefile.write(&pcap::Packet {
                                        header: &header,
                                        data: &packet.data,
                                    });
                                    stats.pcap_records_written.fetch_add(1, Ordering::Relaxed);
                                }

                                batch.push(packet);

                                // Send batch when full or deadline reached
                                if batch.len() >= 100 || Instant::now() >= batch_deadline {
                                    let to_send = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let batch_size = to_send.len() as u64;
                                    debug!("try_send: sending batch of {} packets", batch_size);
                                    match packet_tx.try_send(to_send) {
                                        Ok(()) => {}
                                        Err(crossbeam::channel::TrySendError::Full(_)) => {
                                            stats.packets_dropped.fetch_add(batch_size, Ordering::Relaxed);
                                        }
                                        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                                            warn!("Packet channel closed");
                                            break;
                                        }
                                    }
                                    batch_deadline = Instant::now() + Duration::from_millis(100);
                                }
                            }
                            Ok(None) => {
                                // Timeout - flush partial batch if deadline reached
                                if !batch.is_empty() && Instant::now() >= batch_deadline {
                                    let to_send = std::mem::replace(&mut batch, Vec::with_capacity(100));
                                    let batch_size = to_send.len() as u64;
                                    debug!("try_send: flushing partial batch of {} packets", batch_size);
                                    match packet_tx.try_send(to_send) {
                                        Ok(()) => {}
                                        Err(crossbeam::channel::TrySendError::Full(_)) => {
                                            stats.packets_dropped.fetch_add(batch_size, Ordering::Relaxed);
                                        }
                                        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                                            warn!("Packet channel closed");
                                            break;
                                        }
                                    }
                                    batch_deadline = Instant::now() + Duration::from_millis(100);
                                }

                                // Check stats every second
                                if last_stats_check.elapsed() > Duration::from_secs(1) {
                                    if let Ok(capture_stats) = reader.stats() {
                                        if capture_stats.received > 0 {
                                            debug!(
                                                "Capture stats - Received: {}, Dropped: {}",
                                                capture_stats.received, capture_stats.dropped
                                            );
                                        }
                                        stats
                                            .packets_dropped
                                            .store(capture_stats.dropped as u64, Ordering::Relaxed);
                                    }
                                    last_stats_check = Instant::now();
                                }
                            }
                            Err(e) => {
                                error!("Capture error: {}", e);
                                break;
                            }
                        }
                    }

                    // Flush PCAP savefile before exiting
                    if let Some(ref mut savefile) = pcap_savefile {
                        if let Err(e) = savefile.flush() {
                            error!("Failed to flush PCAP savefile: {}", e);
                        } else {
                            info!("PCAP export completed");
                        }
                    }

                    info!(
                        "Capture thread exiting, total packets read: {}",
                        packets_read
                    );
                }
                Err(e) => {
                    capture_failed.store(true, Ordering::Relaxed);
                    let _ = capture_ready_tx.send(());
                    let error_msg = format!("{}", e);

                    // Check if this is a privilege error
                    if error_msg.contains("Insufficient privileges") {
                        error!("Failed to start packet capture due to insufficient privileges:");
                        // The error message already contains detailed instructions
                        for line in error_msg.lines() {
                            error!("{}", line);
                        }
                    } else {
                        error!("Failed to start packet capture: {}", e);
                        error!(
                            "Make sure you have permission to capture packets (try running with sudo)"
                        );
                    }

                    warn!("Application will run in process-only mode");
                }
            }
        })
        .expect("Failed to spawn pcap_tx thread");

        Ok(capture_ready_rx)
    }

    /// Start a packet processor thread
    fn start_packet_processor(
        &self,
        id: usize,
        packet_rx: Receiver<Vec<CapturedPacket>>,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) {
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_failed = Arc::clone(&self.capture_failed);
        let json_log_path = self.config.json_log_file.clone();
        let dns_resolver = self.dns_resolver.clone();
        let oui_lookup = self.oui_lookup.clone();
        let parser_config = ParserConfig {
            enable_dpi: self.config.enable_dpi,
            ..Default::default()
        };

        thread::Builder::new()
            .name(format!("pcap_rx_{}", id))
            .spawn(move || {
                info!("Packet processor {} started", id);

                // Drop CAP_NET_RAW immediately as this thread doesn't need it (Linux only)
                #[cfg(all(target_os = "linux", feature = "landlock"))]
                {
                    if let Err(e) =
                        crate::network::platform::sandbox::capabilities::drop_cap_net_raw()
                    {
                        warn!(
                            "Failed to drop CAP_NET_RAW in processor thread {}: {}",
                            id, e
                        );
                    } else {
                        debug!("Dropped CAP_NET_RAW in processor thread {}", id);
                    }
                }

                // Wait for linktype to be available
                let parser = loop {
                    if let Some(linktype) = *linktype_storage.read().unwrap() {
                        let mut parser = PacketParser::with_config(parser_config.clone())
                            .with_linktype(linktype);
                        if let Some(ref oui) = oui_lookup {
                            parser = parser.with_oui_lookup((**oui).clone());
                        }
                        break parser;
                    }
                    if capture_failed.load(Ordering::Relaxed) || should_stop.load(Ordering::Relaxed)
                    {
                        info!("pcap_rx_{} exiting before linktype was available", id);
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let mut total_processed = 0u64;
                let mut last_log = Instant::now();

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Packet processor {} stopping", id);
                        break;
                    }

                    // Block until sender delivers a full batch (no spin, no polling)
                    let batch = match packet_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(batch) => {
                            debug!("pcap_rx_{}: received batch of {} packets", id, batch.len());
                            batch
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                            info!("pcap_rx_{}: channel disconnected, exiting", id);
                            return;
                        }
                    };

                    // Process batch. Each packet parse is isolated with
                    // catch_unwind so that a single malformed/adversarial
                    // packet that panics a DPI parser cannot take down the
                    // whole pcap_rx thread and leave the monitor running
                    // blind.
                    // One wall-clock read per batch instead of per packet.
                    // Batches hold ≤100 packets and flush at least every
                    // 100ms, so the timestamp skew is far below any
                    // connection timeout or rate window.
                    let batch_time = SystemTime::now();
                    let mut parsed_count = 0;
                    let batch_len = batch.len();
                    let pcapng_enabled = pcapng_tx.is_some();
                    for packet in batch {
                        let packet_timestamp = packet.timestamp;
                        let packet_original_len = packet.original_len;
                        let parse_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                parser.parse_packet(&packet.data)
                            }));
                        let key = match parse_result {
                            Ok(Some(parsed)) => {
                                let outcome = update_connection(
                                    &tracker,
                                    parsed,
                                    batch_time,
                                    &stats,
                                    &json_log_path,
                                    dns_resolver.as_deref(),
                                );
                                parsed_count += 1;
                                if outcome.dropped {
                                    None
                                } else {
                                    Some(outcome.key)
                                }
                            }
                            Ok(None) => None,
                            Err(_) => {
                                warn!(
                                    "pcap_rx_{}: parser panicked on a packet ({} bytes); skipping",
                                    id,
                                    packet.data.len()
                                );
                                None
                            }
                        };
                        if pcapng_enabled {
                            send_pcapng_record(
                                pcapng_tx.as_ref(),
                                &stats,
                                PcapngRecord {
                                    data: packet.data,
                                    timestamp: packet_timestamp,
                                    original_len: packet_original_len,
                                    key,
                                    deadline: if key.is_some() {
                                        Instant::now() + PCAPNG_ATTRIBUTION_WAIT
                                    } else {
                                        Instant::now()
                                    },
                                },
                            );
                        }
                    }

                    total_processed += batch_len as u64;
                    stats
                        .packets_processed
                        .fetch_add(batch_len as u64, Ordering::Relaxed);

                    // Log progress
                    if total_processed.is_multiple_of(10000)
                        || last_log.elapsed() > Duration::from_secs(5)
                    {
                        debug!(
                            "Processor {}: {} packets processed ({} parsed)",
                            id, total_processed, parsed_count
                        );
                        last_log = Instant::now();
                    }
                }

                info!(
                    "Packet processor {} exiting, total processed: {}",
                    id, total_processed
                );
            })
            .unwrap_or_else(|_| panic!("Failed to spawn pcap_rx_{} thread", id));
    }

    fn start_pcapng_export_thread(
        &mut self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<Option<Sender<PcapngRecord>>> {
        if self.config.pcapng_export_file.is_none() {
            return Ok(None);
        }

        let stats = Arc::clone(&self.stats);
        let Some(file) = self.pcapng_export_file.take() else {
            warn!(
                "PCAPNG export configured but no pre-created file handle was provided; skipping export"
            );
            stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let export_path = self.config.pcapng_export_file.clone().unwrap_or_default();
        let (tx, rx) = channel::bounded::<PcapngRecord>(MAX_PCAPNG_QUEUE);
        let should_stop = Arc::clone(&self.should_stop);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_failed = Arc::clone(&self.capture_failed);
        let current_interface = Arc::clone(&self.current_interface);

        thread::Builder::new()
            .name("pcapng-export".to_string())
            .spawn(move || {
                info!("PCAPNG export thread starting: {}", export_path);
                let linktype = loop {
                    if let Some(linktype) = *linktype_storage.read().unwrap() {
                        break Some(linktype);
                    }
                    if capture_failed.load(Ordering::Relaxed) {
                        warn!(
                            "PCAPNG export could not observe capture linktype because capture setup failed; writing empty fallback section"
                        );
                        stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                        break None;
                    }
                    if should_stop.load(Ordering::Relaxed) {
                        info!(
                            "PCAPNG export did not observe capture linktype before shutdown; writing empty fallback section"
                        );
                        break None;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let if_name = current_interface.read().unwrap().clone();
                let linktype = linktype.map(pcapng::linktype_to_u16).unwrap_or(1);
                let writer = std::io::BufWriter::new(file);
                let mut writer = match PcapngWriter::new(
                    writer,
                    linktype,
                    CaptureConfig::default().snaplen as u32,
                    if_name.as_deref(),
                ) {
                    Ok(writer) => writer,
                    Err(e) => {
                        error!("Failed to initialize PCAPNG writer: {}", e);
                        stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };

                let mut pending = VecDeque::<PcapngRecord>::new();
                let mut pending_bytes = 0usize;
                let mut next_retry_scan = Instant::now() + Duration::from_millis(50);

                loop {
                    if should_stop.load(Ordering::Relaxed) && rx.is_empty() {
                        break;
                    }

                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(record) => {
                            handle_pcapng_record(
                                record,
                                &tracker,
                                &mut writer,
                                &mut pending,
                                &mut pending_bytes,
                                &stats,
                            );
                            enforce_pcapng_retry_limits(
                                &tracker,
                                &mut writer,
                                &mut pending,
                                &mut pending_bytes,
                                &stats,
                            );
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
                    }

                    if Instant::now() >= next_retry_scan {
                        flush_ready_pcapng_records(
                            &tracker,
                            &mut writer,
                            &mut pending,
                            &mut pending_bytes,
                            &stats,
                            false,
                        );
                        next_retry_scan = Instant::now() + Duration::from_millis(50);
                    }
                }

                while let Ok(record) = rx.try_recv() {
                    handle_pcapng_record(
                        record,
                        &tracker,
                        &mut writer,
                        &mut pending,
                        &mut pending_bytes,
                        &stats,
                    );
                    enforce_pcapng_retry_limits(
                        &tracker,
                        &mut writer,
                        &mut pending,
                        &mut pending_bytes,
                        &stats,
                    );
                }
                flush_ready_pcapng_records(
                    &tracker,
                    &mut writer,
                    &mut pending,
                    &mut pending_bytes,
                    &stats,
                    true,
                );
                if let Err(e) = writer.flush() {
                    error!("Failed to flush PCAPNG export: {}", e);
                    stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                }
                let dropped = stats.pcapng_records_dropped.load(Ordering::Relaxed);
                if dropped > 0 {
                    warn!(
                        "PCAPNG export dropped {} records under backpressure",
                        dropped
                    );
                }
                info!("PCAPNG export completed: {}", export_path);
            })
            .expect("Failed to spawn pcapng-export thread");

        Ok(Some(tx))
    }

    /// Start process enrichment thread conditionally based on PKTAP status
    fn start_process_enrichment_conditional(
        &self,
        tracker: Arc<ConnectionTracker>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
    ) -> Result<()> {
        let pktap_active = Arc::clone(&self.pktap_active);
        let should_stop = Arc::clone(&self.should_stop);
        let process_detection_status = Arc::clone(&self.process_detection_status);
        #[cfg(feature = "kubernetes")]
        let kubernetes_mode = self.config.kubernetes_mode;

        thread::Builder::new()
            .name("process-enrichment".to_string())
            .spawn(move || {
            // On macOS, wait for PKTAP detection to avoid unnecessary lsof calls
            #[cfg(target_os = "macos")]
            {
                // Wait up to 5 seconds for PKTAP detection with shorter polling intervals
                let wait_start = Instant::now();
                while wait_start.elapsed() < Duration::from_secs(5)
                    && !should_stop.load(Ordering::Relaxed)
                {
                    if pktap_active.load(Ordering::Relaxed) {
                        info!(
                            "🚫 Skipping process enrichment thread - PKTAP is active and provides process metadata"
                        );
                        if let Ok(mut status) = process_detection_status.write() {
                            *status = ProcessDetectionStatus::with_method("pktap");
                        }
                        let _ = process_ready_tx.send(());
                        return;
                    }
                    // Check more frequently for faster detection
                    thread::sleep(Duration::from_millis(50));
                }

                // Final check after timeout
                if pktap_active.load(Ordering::Relaxed) {
                    info!(
                        "🚫 Skipping process enrichment thread - PKTAP became active during startup"
                    );
                    if let Ok(mut status) = process_detection_status.write() {
                        *status = ProcessDetectionStatus::with_method("pktap");
                    }
                    let _ = process_ready_tx.send(());
                    return;
                } else {
                    info!(
                        "⚠️  PKTAP not detected after 5 seconds, starting process enrichment thread with lsof"
                    );
                    info!(
                        "    This may cause process name formatting differences with PKTAP if it activates later"
                    );
                }
            }

            // Start the actual process enrichment
            if let Err(e) = Self::run_process_enrichment(
                tracker,
                should_stop,
                pktap_active,
                process_detection_status,
                process_ready_tx,
                #[cfg(feature = "kubernetes")]
                kubernetes_mode,
            ) {
                error!("Process enrichment thread failed: {}", e);
            }
        })
        .expect("Failed to spawn process-enrichment thread");

        Ok(())
    }

    /// Run the actual process enrichment logic
    fn run_process_enrichment(
        tracker: Arc<ConnectionTracker>,
        should_stop: Arc<AtomicBool>,
        pktap_active: Arc<AtomicBool>,
        process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
        #[cfg(feature = "kubernetes")] kubernetes_mode: crate::network::kubernetes::KubernetesMode,
    ) -> Result<()> {
        use crate::network::platform::DegradationReason;

        // Check PKTAP status before creating process lookup
        let use_pktap = pktap_active.load(Ordering::Relaxed);

        let process_lookup = create_process_lookup(use_pktap)?;

        // Kubernetes pod/container attribution. `auto` enables only when rustnet
        // is itself running inside a pod, so the resolver and the cross-namespace
        // socket table are only built when enabled and non-Kubernetes hosts do
        // no extra /proc work. The table stays empty when disabled.
        #[cfg(feature = "kubernetes")]
        let kubernetes_resolver = kubernetes_mode
            .enabled()
            .then(crate::network::kubernetes::KubernetesResolver::new);
        #[cfg(feature = "kubernetes")]
        if kubernetes_resolver.is_some() {
            info!("Kubernetes pod/container attribution enabled");
        }
        #[cfg(feature = "kubernetes")]
        let mut k8s_socket_table = crate::network::kubernetes::KubernetesSocketTable::empty();
        #[cfg(feature = "kubernetes")]
        if let Some(resolver) = &kubernetes_resolver {
            k8s_socket_table = crate::network::kubernetes::KubernetesSocketTable::build(resolver);
        }

        // Signal that process detection (including eBPF loading) is complete.
        // The main thread waits for this before dropping eBPF capabilities.
        let _ = process_ready_tx.send(());

        // Fast/slow enrichment cadence. Young connections are retried on a
        // quick tick so their process name appears almost immediately (the
        // eBPF map entry exists from the moment the socket connects — a
        // slower cadence only buys a visible "-" in the UI). Older
        // stragglers (e.g. NAT-translated container traffic the lookup can
        // never resolve) are retried only on the full pass so the fast
        // tick stays cheap, and fully attributed connections are skipped
        // entirely.
        let tick = Duration::from_millis(250);
        let full_pass_interval = Duration::from_secs(2);
        // Connections younger than this are retried on every fast tick.
        const YOUNG_CONNECTION_SECS: u64 = 10;
        let mut last_full_pass = Instant::now() - full_pass_interval;

        // Build and set the detection status from the process lookup implementation
        // Only set if not already detected as pktap (to handle race conditions)
        if let Ok(mut status) = process_detection_status.write()
            && status.method != "pktap"
        {
            let method = process_lookup.get_detection_method().to_string();
            let degradation = process_lookup.get_degradation_reason();

            *status = if degradation != DegradationReason::None {
                ProcessDetectionStatus::degraded(
                    method,
                    degradation.unavailable_feature().unwrap_or("enhanced"),
                    degradation.description(),
                )
            } else {
                ProcessDetectionStatus::with_method(method)
            };
        }

        info!(
            "Process enrichment thread started with detection method: {}",
            process_lookup.get_detection_method()
        );
        let mut last_refresh = Instant::now();

        loop {
            if should_stop.load(Ordering::Relaxed) {
                info!("Process enrichment thread stopping");
                break;
            }

            // Check if PKTAP became active (abort immediately to prevent conflicts)
            #[cfg(target_os = "macos")]
            if pktap_active.load(Ordering::Relaxed) {
                info!(
                    "🚫 PKTAP became active, stopping process enrichment thread to prevent conflicts"
                );
                break;
            }

            // Refresh process lookup periodically
            if last_refresh.elapsed() > Duration::from_secs(5) {
                if let Err(e) = process_lookup.refresh() {
                    debug!("Process lookup refresh failed: {}", e);
                }
                // Refresh pod-name metadata and rebuild the cross-namespace
                // socket table on the same cadence.
                #[cfg(feature = "kubernetes")]
                if let Some(resolver) = &kubernetes_resolver {
                    resolver.refresh_metadata();
                    k8s_socket_table =
                        crate::network::kubernetes::KubernetesSocketTable::build(resolver);
                }
                last_refresh = Instant::now();
            }

            let full_pass = last_full_pass.elapsed() >= full_pass_interval;
            if full_pass {
                last_full_pass = Instant::now();
            }

            // Enrich connections without process info
            let mut enriched = 0;
            for mut entry in tracker.connections().iter_mut() {
                // Fully attributed — nothing to do (names are permanent).
                if entry.process_name.is_some() && entry.pid.is_some() {
                    continue;
                }
                // Fast ticks only retry young connections; older ones wait
                // for the full pass.
                if !full_pass {
                    let young = entry
                        .created_at
                        .elapsed()
                        .map(|age| age.as_secs() < YOUNG_CONNECTION_SECS)
                        .unwrap_or(true);
                    if !young {
                        continue;
                    }
                }

                // Allow partial enrichment - fill in missing pieces without overwriting existing data
                if let Some((pid, name)) = process_lookup.get_process_for_connection(&entry) {
                    let mut did_enrich = false;

                    if entry.process_name.is_none() {
                        entry.process_name = Some(name.clone());
                        did_enrich = true;
                        debug!(
                            "✓ Set process name for connection {}: {}",
                            entry.key(),
                            name
                        );
                    }
                    if entry.pid.is_none() {
                        entry.pid = Some(pid);
                        did_enrich = true;
                        debug!("✓ Set PID for connection {}: {}", entry.key(), pid);
                    }

                    if did_enrich {
                        enriched += 1;
                    }

                    // Look up Kubernetes pod/container metadata for the PID.
                    // Cheap after the first hit per PID (cached in the resolver).
                    #[cfg(feature = "kubernetes")]
                    if let Some(resolver) = &kubernetes_resolver
                        && entry.k8s_info.is_none()
                        && let Some(k8s) = resolver.enrich(pid)
                    {
                        entry.k8s_info = Some(k8s);
                    }
                } else {
                    // The primary lookup couldn't attribute this connection.
                    // Under hostNetwork, that includes every pod-owned socket
                    // living in another network namespace. The socket table
                    // walks per-PID /proc/<pid>/net/* (netns-aware) for kubepods
                    // PIDs and matches the 4-tuple, yielding both the PID and
                    // its pod/container metadata.
                    #[cfg(feature = "kubernetes")]
                    if entry.pid.is_none()
                        && let Some((pid, k8s)) = k8s_socket_table.lookup_connection(&entry)
                    {
                        entry.pid = Some(pid);
                        if entry.process_name.is_none() {
                            entry.process_name = crate::network::kubernetes::read_process_name(pid);
                        }
                        if entry.k8s_info.is_none() {
                            entry.k8s_info = Some(k8s);
                        }
                        enriched += 1;
                    }
                }
            }

            if enriched > 0 {
                debug!("Enriched {} connections with process info", enriched);
            }

            thread::sleep(tick);
        }

        Ok(())
    }

    /// Start snapshot provider thread for UI updates
    fn start_snapshot_provider(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let snapshot = Arc::clone(&self.connections_snapshot);
        let snapshot_generation = Arc::clone(&self.snapshot_generation);
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let service_lookup = Arc::clone(&self.service_lookup);
        let process_activity = Arc::clone(&self.process_activity);
        let show_historic = Arc::clone(&self.show_historic);
        let filter_localhost = self.config.filter_localhost;
        let refresh_interval = Duration::from_millis(self.config.refresh_interval);
        let loop_interval = refresh_interval.min(Duration::from_secs(1));

        let enrich_and_filter = move |conn: &mut Connection,
                                      service_lookup: &ServiceLookup,
                                      filter_localhost: bool|
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
            if filter_localhost
                && conn.local_addr.ip().is_loopback()
                && conn.remote_addr.ip().is_loopback()
            {
                return false;
            }
            true
        };

        thread::Builder::new()
            .name("snapshot_ui".to_string())
            .spawn(move || {
                info!("Snapshot provider thread started");
                let mut last_ui_publish: Option<Instant> = None;
                let mut last_activity_sample: Option<Instant> = None;

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Snapshot provider thread stopping");
                        break;
                    }

                    // Create snapshot
                    let start = Instant::now();
                    let total_connections = tracker.len();

                    let mut snapshot_data: Vec<Connection> = tracker
                        .connections()
                        .iter()
                        .filter_map(|entry| {
                            // snapshot_clone: leave the live tracker as unique
                            // owner of its rate samples, otherwise the next
                            // per-packet update pays an Arc::make_mut deep copy.
                            let mut conn = entry.value().snapshot_clone();
                            if enrich_and_filter(&mut conn, &service_lookup, filter_localhost)
                                && conn.is_active()
                            {
                                Some(conn)
                            } else {
                                None
                            }
                        })
                        .collect();

                    // Append historic connections when toggle is on
                    if show_historic.load(Ordering::Relaxed) {
                        let historic: Vec<Connection> = tracker
                            .historic()
                            .iter()
                            .filter_map(|entry| {
                                let mut conn = entry.value().snapshot_clone();
                                if enrich_and_filter(&mut conn, &service_lookup, filter_localhost) {
                                    Some(conn)
                                } else {
                                    None
                                }
                            })
                            .collect();
                        snapshot_data.extend(historic);
                    }

                    // Sort by creation time (oldest first, newest last for maximum stability)
                    snapshot_data.sort_by_key(|a| a.created_at);

                    let filtered_count = snapshot_data.len();

                    let activity_due = last_activity_sample
                        .is_none_or(|sampled| sampled.elapsed() >= Duration::from_secs(1));
                    if activity_due {
                        if let Ok(mut activity) = process_activity.write() {
                            tracker.with_retained_sources(|active, historic| {
                                let include = |conn: &Connection| {
                                    !(filter_localhost
                                        && conn.local_addr.ip().is_loopback()
                                        && conn.remote_addr.ip().is_loopback())
                                };
                                activity.observe_sources(
                                    SystemTime::now(),
                                    |observe| {
                                        for entry in active.iter() {
                                            let conn = entry.value();
                                            if include(conn) {
                                                observe(conn);
                                            }
                                        }
                                    },
                                    |observe| {
                                        for entry in historic.iter() {
                                            let conn = entry.value();
                                            if include(conn) {
                                                observe(conn);
                                            }
                                        }
                                    },
                                );
                            });
                        }
                        last_activity_sample = Some(Instant::now());
                    }

                    let ui_publish_due = last_ui_publish
                        .is_none_or(|published| published.elapsed() >= refresh_interval);
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

                    thread::sleep(loop_interval);
                }
            })
            .expect("Failed to spawn snapshot_ui thread");

        Ok(())
    }

    /// Start rate refresh thread to update rates for idle connections
    fn start_rate_refresh_thread(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);

        thread::Builder::new()
            .name("state_refresh".to_string())
            .spawn(move || {
                info!("Rate refresh thread started");

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Rate refresh thread stopping");
                        break;
                    }

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

                    // Run every 1 second to balance responsiveness with performance
                    thread::sleep(Duration::from_secs(1));
                }
            })
            .expect("Failed to spawn state_refresh thread");

        Ok(())
    }

    /// Start interface statistics collection thread
    fn start_interface_stats_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let interface_stats = Arc::clone(&self.interface_stats);
        let interface_rates = Arc::clone(&self.interface_rates);
        let interface_traffic_windows = Arc::clone(&self.interface_traffic_windows);
        let interface_traffic_history = Arc::clone(&self.interface_traffic_history);

        thread::Builder::new()
            .name("ifstats_poll".to_string())
            .spawn(move || {
                info!("Interface stats collection thread started");

                let provider = PlatformStatsProvider;
                let mut previous_stats: HashMap<String, InterfaceStats> = HashMap::new();
                // Warn once if stat collection ever fails so a permission/sandbox
                // regression (e.g. Landlock denying /sys) is visible at the
                // default log level instead of being silently swallowed.
                let mut warned_collect_failure = false;

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Interface stats thread stopping");
                        break;
                    }

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
                                    interface_traffic_windows
                                        .insert(name, stat.traffic_since(oldest));
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

                    // Refresh every 2 seconds
                    thread::sleep(Duration::from_secs(2));
                }
            })
            .expect("Failed to spawn ifstats_poll thread");

        Ok(())
    }

    /// Start traffic history thread for graph visualization
    fn start_traffic_history_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let traffic_history = Arc::clone(&self.traffic_history);
        let conn_rate_history = Arc::clone(&self.conn_rate_history);
        let interface_rates = Arc::clone(&self.interface_rates);
        let connections_snapshot = Arc::clone(&self.connections_snapshot);
        let stats = Arc::clone(&self.stats);
        let tracker = Arc::clone(&self.tracker);

        thread::Builder::new()
            .name("graph_ui".to_string())
            .spawn(move || {
                info!("Traffic history thread started");

                // Track previous values for delta calculation
                let mut prev_packets: u64 = 0;
                let mut prev_retransmits: u64 = 0;

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Traffic history thread stopping");
                        break;
                    }

                    // Aggregate rates from all interfaces
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
                                    rates.entry(conn.key()).or_default().push(
                                        conn.current_incoming_rate_bps as u64,
                                        conn.current_outgoing_rate_bps as u64,
                                        60,
                                    );
                                }
                            }
                            snap.iter().filter(|c| !c.is_historic).count()
                        })
                        .unwrap_or(0);

                    // Get packet and retransmit counts (calculate deltas)
                    let current_packets = stats.packets_processed.load(Ordering::Relaxed);
                    let current_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);

                    let packets_delta = current_packets.saturating_sub(prev_packets);
                    let retransmits_delta = current_retransmits.saturating_sub(prev_retransmits);

                    prev_packets = current_packets;
                    prev_retransmits = current_retransmits;

                    // Get average RTT from tracker (last 1 second window)
                    let avg_rtt_ms = tracker.take_average_rtt(1);

                    // Add sample to traffic history
                    if let Ok(mut history) = traffic_history.write() {
                        history.add_sample(
                            total_rx,
                            total_tx,
                            connection_count,
                            packets_delta,
                            retransmits_delta,
                            avg_rtt_ms,
                        );
                    }

                    // Update every 1 second
                    thread::sleep(Duration::from_secs(1));
                }
            })
            .expect("Failed to spawn graph_ui thread");

        Ok(())
    }

    /// Start GeoIP enrichment thread to populate location/ASN info for connections
    fn start_geoip_enrichment_thread(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let geoip_resolver = match &self.geoip_resolver {
            Some(resolver) => Arc::clone(resolver),
            None => return Ok(()), // No resolver available
        };

        let should_stop = Arc::clone(&self.should_stop);

        thread::Builder::new()
            .name("geoip-enrichment".to_string())
            .spawn(move || {
                info!("GeoIP enrichment thread started");
                let interval = Duration::from_millis(500);

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("GeoIP enrichment thread stopping");
                        break;
                    }

                    // Enrich connections without GeoIP info
                    let mut enriched = 0;
                    for mut entry in tracker.connections().iter_mut() {
                        if entry.geoip_info.is_none() {
                            let remote_ip = entry.remote_addr.ip();
                            let info = geoip_resolver.lookup(remote_ip);
                            if info.has_data() {
                                entry.geoip_info = Some(info);
                                enriched += 1;
                            }
                        }
                    }

                    if enriched > 0 {
                        debug!("Enriched {} connections with GeoIP info", enriched);
                    }

                    thread::sleep(interval);
                }
            })
            .expect("Failed to spawn GeoIP enrichment thread");

        Ok(())
    }

    /// Start cleanup thread to remove old connections
    fn start_cleanup_thread(&self, tracker: Arc<ConnectionTracker>) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let json_log_path = self.config.json_log_file.clone();
        let pcap_export_path = self.config.pcap_export_file.clone();
        let dns_resolver = self.dns_resolver.clone();

        thread::Builder::new()
            .name("cleanup_thread".to_string())
            .spawn(move || {
            info!("Cleanup thread started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Cleanup thread stopping");
                    break;
                }

                // Remove inactive connections. The tracker handles the timeout
                // sweep, historic archiving + eviction, and QUIC-mapping cleanup;
                // we layer the app's close-event logging on the returned set.
                let now = SystemTime::now();
                let removed = tracker.cleanup(now);

                for conn in &removed {
                    // Calculate connection duration
                    let duration_secs = now
                        .duration_since(conn.created_at)
                        .map(|d| d.as_secs())
                        .ok();

                    // Log connection_closed event if JSON logging is enabled
                    if let Some(log_path) = &json_log_path {
                        log_connection_event(
                            log_path,
                            "connection_closed",
                            conn,
                            duration_secs,
                            dns_resolver.as_deref(),
                        );
                    }

                    // Log to PCAP sidecar file if PCAP export is enabled
                    if let Some(pcap_path) = &pcap_export_path {
                        log_pcap_connection(pcap_path, conn);
                    }

                    // Log cleanup reason for debugging
                    let conn_timeout = conn.get_timeout();
                    let idle_time = now.duration_since(conn.last_activity).unwrap_or_default();
                    debug!(
                        "Cleanup: Removing {} connection {} -> {} (idle: {:?}, timeout: {:?}, state: {})",
                        conn.protocol,
                        conn.local_addr,
                        conn.remote_addr,
                        idle_time,
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

                thread::sleep(Duration::from_secs(5));
            }
        })
        .expect("Failed to spawn cleanup_thread");

        Ok(())
    }

    /// Get current connections for UI display
    pub fn get_connections(&self) -> Vec<Connection> {
        self.get_filtered_connections("")
    }

    /// Generation of the current snapshot; bumped on every snapshot rebuild.
    /// The UI loop compares this against the last generation it consumed to
    /// skip re-cloning and re-sorting unchanged data.
    pub fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation.load(Ordering::Acquire)
    }

    /// Get filtered connections for UI display
    pub fn get_filtered_connections(&self, filter_query: &str) -> Vec<Connection> {
        // Filter out DNS PTR queries/responses when reverse DNS is enabled
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
                if hide_ptr_lookups
                    && let Some(ref dpi) = conn.dpi_info
                    && let ApplicationProtocol::Dns(ref dns_info) = dpi.application
                    && dns_info.query_type == Some(DnsQueryType::PTR)
                {
                    return false;
                }
                filter.as_ref().is_none_or(|f| f.matches(conn))
            })
            .cloned()
            .collect()
    }

    /// Get interface statistics
    pub fn get_interface_stats(&self) -> Vec<InterfaceStats> {
        self.interface_stats
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get interface rates (bytes/sec)
    pub fn get_interface_rates(&self) -> HashMap<String, InterfaceRates> {
        self.interface_rates
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get traffic transferred over each interface's rolling 60-second window.
    pub fn get_interface_traffic_windows(&self) -> HashMap<String, InterfaceTrafficWindow> {
        self.interface_traffic_windows
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get the latest retained process traffic snapshot.
    pub fn get_process_activity_snapshot(&self) -> ProcessActivitySnapshot {
        self.process_activity
            .read()
            .map(|activity| activity.snapshot())
            .unwrap_or_default()
    }

    /// Get traffic history for graph visualization
    /// RX/TX rate history for one connection (by `Connection::key()`),
    /// as (rx, tx) bytes/sec vectors oldest→newest. None until the
    /// traffic-history thread has sampled the connection at least once.
    pub fn get_connection_rate_history(&self, key: &str) -> Option<(Vec<u64>, Vec<u64>)> {
        self.conn_rate_history.read().ok()?.get(key).map(|h| {
            (
                h.rx.iter().copied().collect(),
                h.tx.iter().copied().collect(),
            )
        })
    }

    pub fn get_traffic_history(&self) -> TrafficHistory {
        self.traffic_history
            .read()
            .map(|h| h.clone())
            .unwrap_or_default()
    }

    /// Get application statistics
    pub fn get_stats(&self) -> AppStats {
        AppStats {
            packets_processed: AtomicU64::new(self.stats.packets_processed.load(Ordering::Relaxed)),
            packets_dropped: AtomicU64::new(self.stats.packets_dropped.load(Ordering::Relaxed)),
            connections_tracked: AtomicU64::new(
                self.stats.connections_tracked.load(Ordering::Relaxed),
            ),
            last_update: RwLock::new(*self.stats.last_update.read().unwrap()),
            total_tcp_retransmits: AtomicU64::new(
                self.stats.total_tcp_retransmits.load(Ordering::Relaxed),
            ),
            total_tcp_out_of_order: AtomicU64::new(
                self.stats.total_tcp_out_of_order.load(Ordering::Relaxed),
            ),
            total_tcp_fast_retransmits: AtomicU64::new(
                self.stats
                    .total_tcp_fast_retransmits
                    .load(Ordering::Relaxed),
            ),
            pcap_records_written: AtomicU64::new(
                self.stats.pcap_records_written.load(Ordering::Relaxed),
            ),
            pcapng_records_queued: AtomicU64::new(
                self.stats.pcapng_records_queued.load(Ordering::Relaxed),
            ),
            pcapng_records_written: AtomicU64::new(
                self.stats.pcapng_records_written.load(Ordering::Relaxed),
            ),
            pcapng_records_annotated: AtomicU64::new(
                self.stats.pcapng_records_annotated.load(Ordering::Relaxed),
            ),
            pcapng_records_unannotated: AtomicU64::new(
                self.stats
                    .pcapng_records_unannotated
                    .load(Ordering::Relaxed),
            ),
            pcapng_records_dropped: AtomicU64::new(
                self.stats.pcapng_records_dropped.load(Ordering::Relaxed),
            ),
            pcapng_export_errors: AtomicU64::new(
                self.stats.pcapng_export_errors.load(Ordering::Relaxed),
            ),
        }
    }

    /// Whether annotated PCAPNG export is active for this run.
    pub fn is_pcapng_export_enabled(&self) -> bool {
        self.config.pcapng_export_file.is_some()
    }

    /// Whether classic PCAP export is active for this run.
    pub fn is_pcap_export_enabled(&self) -> bool {
        self.config.pcap_export_file.is_some()
    }

    /// Check if application is still loading
    pub fn is_loading(&self) -> bool {
        self.is_loading.load(Ordering::Relaxed)
    }

    /// Get the current network interface name
    pub fn get_current_interface(&self) -> Option<String> {
        self.current_interface.read().unwrap().clone()
    }

    /// Get the current process detection status (method and degradation info)
    pub fn get_process_detection_status(&self) -> ProcessDetectionStatus {
        self.process_detection_status
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Get sandbox status information
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub fn get_sandbox_info(&self) -> SandboxInfo {
        self.sandbox_info
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Set sandbox status information
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    pub fn set_sandbox_info(&self, info: SandboxInfo) {
        if let Ok(mut guard) = self.sandbox_info.write() {
            *guard = info;
        }
    }

    /// Get link layer information for the current interface
    /// Returns (link_layer_type_name, is_tunnel)
    pub fn get_link_layer_info(&self) -> (String, bool) {
        use crate::network::link_layer::LinkLayerType;

        if let Ok(linktype_opt) = self.linktype.read()
            && let Some(dlt) = *linktype_opt
        {
            // Get interface name to detect TUN/TAP more accurately
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

    /// Get the DNS resolver if enabled
    pub fn get_dns_resolver(&self) -> Option<Arc<DnsResolver>> {
        self.dns_resolver.clone()
    }

    /// Check if DNS resolution is enabled
    pub fn is_dns_resolution_enabled(&self) -> bool {
        self.dns_resolver.is_some()
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

    /// Toggle the show_historic flag
    pub fn toggle_show_historic(&self) {
        let prev = self.show_historic.load(Ordering::Relaxed);
        self.show_historic.store(!prev, Ordering::Relaxed);
    }

    /// Set the show_historic flag directly
    pub fn set_show_historic(&self, value: bool) {
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

    /// Override the current interface label. Tests only.
    #[cfg(test)]
    pub(crate) fn set_current_interface_for_test(&self, iface: Option<String>) {
        *self.current_interface.write().unwrap() = iface;
    }

    /// Seed an interface's cumulative stats. Tests only.
    #[cfg(test)]
    pub(crate) fn set_interface_stats_for_test(&self, name: &str, stats: InterfaceStats) {
        self.interface_stats.insert(name.to_string(), stats);
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
        self.process_activity
            .write()
            .unwrap()
            .observe_connections(connections, now);
    }

    /// Clear all connections and related data, starting fresh
    /// This clears:
    /// - All tracked connections
    /// - Traffic history (graph data)
    /// - RTT measurements
    /// - QUIC connection mappings
    /// - Resets statistics counters
    pub fn clear_all_connections(&self) {
        info!("Clearing all connections and resetting statistics");

        // Clear the tracker (active + historic tables, RTT, and QUIC mappings)
        // and reset the historic-view toggle.
        self.tracker.clear();
        self.show_historic.store(false, Ordering::Relaxed);

        // Clear the UI snapshot
        if let Ok(mut snapshot) = self.connections_snapshot.write() {
            snapshot.clear();
        }

        // Clear traffic history
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

        // Reset statistics counters
        self.stats.packets_processed.store(0, Ordering::Relaxed);
        self.stats.packets_dropped.store(0, Ordering::Relaxed);
        self.stats.connections_tracked.store(0, Ordering::Relaxed);
        self.stats.total_tcp_retransmits.store(0, Ordering::Relaxed);
        self.stats
            .total_tcp_out_of_order
            .store(0, Ordering::Relaxed);
        self.stats
            .total_tcp_fast_retransmits
            .store(0, Ordering::Relaxed);
        self.stats.pcap_records_written.store(0, Ordering::Relaxed);
        self.stats.pcapng_records_queued.store(0, Ordering::Relaxed);
        self.stats
            .pcapng_records_written
            .store(0, Ordering::Relaxed);
        self.stats
            .pcapng_records_annotated
            .store(0, Ordering::Relaxed);
        self.stats
            .pcapng_records_unannotated
            .store(0, Ordering::Relaxed);
        self.stats
            .pcapng_records_dropped
            .store(0, Ordering::Relaxed);
        self.stats.pcapng_export_errors.store(0, Ordering::Relaxed);

        info!("All connections cleared successfully");
    }

    /// Stop all threads gracefully
    pub fn stop(&self) {
        info!("Stopping application");
        self.should_stop.store(true, Ordering::Relaxed);

        // Write remaining active connections to PCAP sidecar JSONL file
        // (connections that haven't been cleaned up yet)
        if let Some(ref pcap_path) = self.config.pcap_export_file
            && let Ok(connections) = self.connections_snapshot.read()
        {
            let count = connections.len();
            let with_pids = connections.iter().filter(|c| c.pid.is_some()).count();

            for conn in connections.iter() {
                log_pcap_connection(pcap_path, conn);
            }

            info!(
                "Wrote {} remaining connections ({} with PIDs) to JSONL",
                count, with_pids
            );
        }
    }
}

/// Update or create a connection from a parsed packet.
///
/// The connection table, RTT tracking, QUIC coalescing, and the connection
/// limit all live in the shared [`ConnectionTracker`]; this wrapper layers the
/// app-specific concerns (global statistics and JSON event logging) on top of
/// the tracker's [`IngestOutcome`].
fn update_connection(
    tracker: &ConnectionTracker,
    parsed: ParsedPacket,
    now: SystemTime,
    stats: &AppStats,
    json_log_path: &Option<String>,
    dns_resolver: Option<&DnsResolver>,
) -> IngestOutcome {
    let outcome = tracker.ingest_at(&parsed, now);

    // Fold TCP anomaly counts into the global statistics.
    if outcome.retransmits > 0 {
        stats
            .total_tcp_retransmits
            .fetch_add(outcome.retransmits, Ordering::Relaxed);
    }
    if outcome.out_of_order > 0 {
        stats
            .total_tcp_out_of_order
            .fetch_add(outcome.out_of_order, Ordering::Relaxed);
    }
    if outcome.fast_retransmits > 0 {
        stats
            .total_tcp_fast_retransmits
            .fetch_add(outcome.fast_retransmits, Ordering::Relaxed);
    }

    if outcome.dropped {
        debug!(
            "Connection limit reached, dropping new connection: {}",
            outcome.key
        );
        return outcome;
    }

    // Log a new-connection event if JSON logging is enabled.
    if outcome.created {
        debug!("New connection detected: {}", outcome.key);
        if let Some(log_path) = json_log_path
            && let Some(conn) = tracker.connections().get(&outcome.key)
        {
            log_connection_event(log_path, "new_connection", conn.value(), None, dns_resolver);
        }
    }

    outcome
}

fn send_pcapng_record(
    pcapng_tx: Option<&Sender<PcapngRecord>>,
    stats: &AppStats,
    record: PcapngRecord,
) {
    let Some(tx) = pcapng_tx else {
        return;
    };
    match tx.try_send(record) {
        Ok(()) => {
            stats.pcapng_records_queued.fetch_add(1, Ordering::Relaxed);
        }
        Err(crossbeam::channel::TrySendError::Full(_)) => {
            stats.pcapng_records_dropped.fetch_add(1, Ordering::Relaxed);
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                warn!("PCAPNG export queue full; dropping export records under load");
            }
        }
        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {}
    }
}

fn handle_pcapng_record<W: Write>(
    record: PcapngRecord,
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
) {
    // Always enqueue so records leave in arrival order: an attributed packet
    // must not be written ahead of an older packet still waiting for
    // attribution, or the export file ends up out of timestamp order.
    *pending_bytes = pending_bytes.saturating_add(record.data.len());
    pending.push_back(record);
    flush_ready_pcapng_records(tracker, writer, pending, pending_bytes, stats, false);
}

/// Write out pending records in FIFO order, stopping at the first record that
/// is still waiting for process attribution (unless `force`d or expired).
fn flush_ready_pcapng_records<W: Write>(
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
    force: bool,
) {
    let now = Instant::now();
    while let Some(record) = pending.front() {
        let comment = pcapng_comment(record, tracker);
        let attributed = comment.is_some();
        let expired = force || record.deadline <= now;
        if record.key.is_some() && !attributed && !expired {
            break;
        }
        let record = pending.pop_front().expect("front() was Some");
        *pending_bytes = pending_bytes.saturating_sub(record.data.len());
        // A record that expired unattributed may still have partial metadata
        // (direction, DPI, GeoIP) worth annotating.
        let comment = comment.or_else(|| pcapng_comment_if_any_metadata(&record, tracker));
        write_pcapng_record(writer, &record, comment.as_deref(), stats);
    }
}

fn enforce_pcapng_retry_limits<W: Write>(
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
) {
    while pending.len() > MAX_PCAPNG_RETRY_RECORDS || *pending_bytes > MAX_PCAPNG_RETRY_BYTES {
        if let Some(record) = pending.pop_front() {
            *pending_bytes = pending_bytes.saturating_sub(record.data.len());
            let comment = pcapng_comment_if_any_metadata(&record, tracker);
            write_pcapng_record(writer, &record, comment.as_deref(), stats);
        } else {
            break;
        }
    }
}

fn write_pcapng_record<W: Write>(
    writer: &mut PcapngWriter<W>,
    record: &PcapngRecord,
    comment: Option<&str>,
    stats: &AppStats,
) {
    if let Err(e) =
        writer.write_packet(record.timestamp, &record.data, record.original_len, comment)
    {
        stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            error!("Failed to write PCAPNG packet: {}", e);
        }
        return;
    }

    stats.pcapng_records_written.fetch_add(1, Ordering::Relaxed);
    if comment.is_some() {
        stats
            .pcapng_records_annotated
            .fetch_add(1, Ordering::Relaxed);
    } else {
        stats
            .pcapng_records_unannotated
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// Comment for a record whose connection already has process attribution;
/// `None` while attribution is still pending (or for keyless records).
fn pcapng_comment(record: &PcapngRecord, tracker: &ConnectionTracker) -> Option<String> {
    let key = record.key?;
    let conn = tracker.connections().get(&key)?;
    if conn.pid.is_none() && conn.process_name.is_none() {
        return None;
    }
    build_pcapng_comment(&conn)
}

fn pcapng_comment_if_any_metadata(
    record: &PcapngRecord,
    tracker: &ConnectionTracker,
) -> Option<String> {
    let key = record.key?;
    let conn = tracker.connections().get(&key)?;
    build_pcapng_comment(&conn)
}

fn build_pcapng_comment(conn: &Connection) -> Option<String> {
    let mut fields = vec!["rustnet".to_string()];
    if let Some(process) = &conn.process_name {
        fields.push(format!("process={}", sanitize_comment_value(process)));
    }
    if let Some(pid) = conn.pid {
        fields.push(format!("pid={pid}"));
    }
    #[cfg(feature = "kubernetes")]
    if let Some(k8s) = &conn.k8s_info {
        if let Some(name) = &k8s.pod_name {
            fields.push(format!("pod={}", sanitize_comment_value(name)));
        }
        if let Some(ns) = &k8s.pod_namespace {
            fields.push(format!("ns={}", sanitize_comment_value(ns)));
        }
        if let Some(uid) = &k8s.pod_uid {
            fields.push(format!("pod_uid={}", sanitize_comment_value(uid)));
        }
        if let Some(name) = &k8s.container_name {
            fields.push(format!("container={}", sanitize_comment_value(name)));
        }
        if let Some(id) = &k8s.container_id {
            fields.push(format!("container_id={}", sanitize_comment_value(id)));
        }
    }
    if let Some(is_outgoing) = conn.connection_direction {
        fields.push(format!(
            "direction={}",
            if is_outgoing { "outgoing" } else { "incoming" }
        ));
    }
    if let Some(dpi) = &conn.dpi_info {
        fields.push(format!(
            "app={}",
            sanitize_comment_value(&dpi.application.to_string())
        ));
        if let Some(domain) = dpi_domain(&dpi.application) {
            fields.push(format!("sni={}", sanitize_comment_value(domain)));
        }
    }
    if let Some(geoip) = &conn.geoip_info {
        if let Some(country) = &geoip.country_code {
            fields.push(format!("country={}", sanitize_comment_value(country)));
        }
        if let Some(asn) = geoip.asn {
            fields.push(format!("asn={asn}"));
        }
    }
    if fields.len() == 1 {
        None
    } else {
        Some(fields.join(" "))
    }
}

fn dpi_domain(application: &ApplicationProtocol) -> Option<&str> {
    match application {
        ApplicationProtocol::Dns(info) => info.query_name.as_deref(),
        ApplicationProtocol::Http(info) => info.host.as_deref(),
        ApplicationProtocol::Https(info) => info.tls_info.as_ref()?.sni.as_deref(),
        ApplicationProtocol::Quic(info) => info.tls_info.as_ref()?.sni.as_deref(),
        _ => None,
    }
}

fn sanitize_comment_value(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|c| {
            if c.is_control() || c.is_whitespace() || c == '\0' {
                '_'
            } else {
                c
            }
        })
        .collect();
    sanitized.trim_matches('_').to_string()
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
        // Give threads time to stop gracefully
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod activity_reset_tests {
    use super::*;
    use crate::network::types::{ProtocolState, TcpState};
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
        let app = App::new(Config {
            enable_dpi: false,
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .unwrap();
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
                sampled_for: Duration::from_secs(30),
            },
        );

        app.clear_all_connections();

        assert_eq!(app.get_process_activity_snapshot().window_tx_bytes, 0);
        assert!(app.get_interface_traffic_windows().is_empty());
        assert!(app.interface_traffic_history.lock().unwrap().is_empty());
    }
}

#[cfg(all(test, unix))]
mod open_log_file_tests {
    use super::open_log_file;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// Per-test scratch directory under the system temp dir, removed on drop.
    /// Avoids a `tempfile` dependency; uniqueness comes from the pid + the
    /// caller-supplied tag (test names are unique).
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rustnet-log-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            ScratchDir(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_file_with_0600_permissions() {
        let dir = ScratchDir::new("perms");
        let path = dir.path("events.log");

        let file = open_log_file(path.to_str().unwrap()).expect("fresh open should succeed");
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new log file must be created mode 0o600");
    }

    #[test]
    fn appends_rather_than_truncates() {
        let dir = ScratchDir::new("append");
        let path = dir.path("events.log");
        let p = path.to_str().unwrap();

        writeln!(open_log_file(p).unwrap(), "line1").unwrap();
        writeln!(open_log_file(p).unwrap(), "line2").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("line1"), "first write must be preserved");
        assert!(contents.contains("line2"), "second write must be appended");
    }

    #[test]
    fn refuses_symlinked_path() {
        let dir = ScratchDir::new("symlink");
        let target = dir.path("real_target.log");
        let link = dir.path("evil.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = open_log_file(link.to_str().unwrap())
            .expect_err("O_NOFOLLOW must refuse a symlinked path");

        // As the symlink's owner (the test process), `fs.protected_symlinks`
        // does not intervene, so this is the raw O_NOFOLLOW rejection: ELOOP.
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got: {err}"
        );

        // The privileged write must not have been redirected through the link.
        let target_contents = std::fs::read_to_string(&target).unwrap();
        assert!(
            target_contents.is_empty(),
            "symlink target must be untouched"
        );
    }
}

#[cfg(test)]
mod pcapng_export_tests {
    use super::*;
    use std::net::SocketAddr;

    fn record(data: u8, key: Option<ConnectionKey>, deadline: Instant) -> PcapngRecord {
        PcapngRecord {
            data: vec![data],
            timestamp: std::time::UNIX_EPOCH,
            original_len: 1,
            key,
            deadline,
        }
    }

    /// Kubernetes attribution must be carried into the per-packet comment so
    /// annotated PCAPNG files are pod-aware without the sidecar JSONL.
    #[cfg(feature = "kubernetes")]
    #[test]
    fn comment_includes_kubernetes_attribution() {
        use crate::network::types::{K8sInfo, ProtocolState, TcpState};

        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::from(([10, 0, 0, 1], 4000)),
            SocketAddr::from(([10, 0, 0, 2], 443)),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.k8s_info = Some(K8sInfo {
            pod_uid: Some("c3b4d893-473e-43c2-8013-8ee2955a4630".to_string()),
            pod_name: Some("nginx-86644db9cc-mf5lx".to_string()),
            pod_namespace: Some("demo-traffic".to_string()),
            container_id: Some(
                "c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b".to_string(),
            ),
            container_name: Some("nginx".to_string()),
            cgroup_path: None,
        });

        let comment = build_pcapng_comment(&conn).expect("k8s info alone must produce a comment");
        assert!(comment.contains("pod=nginx-86644db9cc-mf5lx"));
        assert!(comment.contains("ns=demo-traffic"));
        assert!(comment.contains("pod_uid=c3b4d893-473e-43c2-8013-8ee2955a4630"));
        assert!(comment.contains("container=nginx"));
        assert!(comment.contains(
            "container_id=c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b"
        ));
    }

    /// Records must leave the pending queue in arrival order: a keyless
    /// (immediately writable) record queued behind one still waiting for
    /// attribution may not jump ahead of it in the export file.
    #[test]
    fn export_preserves_arrival_order_across_pending_records() {
        let tracker = ConnectionTracker::new();
        let stats = AppStats::default();
        let mut out = Vec::new();
        let mut writer = PcapngWriter::new(&mut out, 1, 1514, None).unwrap();
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0usize;

        let key = ConnectionKey::new(
            Protocol::Tcp,
            SocketAddr::from(([127, 0, 0, 1], 1000)),
            SocketAddr::from(([127, 0, 0, 2], 2000)),
        );
        let far_deadline = Instant::now() + Duration::from_secs(3600);
        handle_pcapng_record(
            record(0xAA, Some(key), far_deadline),
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
        );
        handle_pcapng_record(
            record(0xBB, None, Instant::now()),
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
        );

        // Both records are held: the head is still waiting for attribution.
        assert_eq!(stats.pcapng_records_written.load(Ordering::Relaxed), 0);
        assert_eq!(pending.len(), 2);

        flush_ready_pcapng_records(
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
            true,
        );
        writer.flush().unwrap();

        assert_eq!(stats.pcapng_records_written.load(Ordering::Relaxed), 2);
        assert!(pending.is_empty());
        assert_eq!(pending_bytes, 0);
        let pos_a = out.iter().position(|&b| b == 0xAA).unwrap();
        let pos_b = out.iter().position(|&b| b == 0xBB).unwrap();
        assert!(pos_a < pos_b, "records were written out of arrival order");
    }
}
