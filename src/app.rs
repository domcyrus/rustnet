// app.rs - Main application orchestration (with debug logging)
use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use serde_json::json;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::filter::ConnectionFilter;

use crate::network::{
    capture::{CaptureConfig, PacketReader, setup_packet_capture},
    dns::DnsResolver,
    geoip::{GeoIpConfig, GeoIpResolver},
    interface_stats::{InterfaceRates, InterfaceStats, InterfaceStatsProvider},
    merge::{create_connection_from_packet, merge_packet_into_connection},
    parser::{PacketParser, ParsedPacket, ParserConfig},
    platform::create_process_lookup,
    services::ServiceLookup,
    types::{
        ApplicationProtocol, Connection, ConnectionKey, DnsQueryType, Protocol, RttTracker,
        TrafficHistory,
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

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Sandbox status information for UI display
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default)]
pub struct SandboxInfo {
    /// Overall status description
    pub status: String,
    /// Whether CAP_NET_RAW was dropped
    pub cap_dropped: bool,
    /// Whether Landlock is available on this kernel
    pub landlock_available: bool,
    /// Whether Landlock filesystem restrictions are applied
    pub fs_restricted: bool,
    /// Whether Landlock network restrictions are applied
    pub net_restricted: bool,
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

/// Global QUIC connection ID to connection key mapping
/// This allows tracking QUIC connections across connection ID changes
static QUIC_CONNECTION_MAPPING: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
    if let Some(resolver) = dns_resolver {
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

    // Write to file
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(json_log_path)
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
        "protocol": format!("{:?}", conn.protocol),
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

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&json_path)
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
            resolve_dns: false,
            show_ptr_lookups: false,
            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: false,
        }
    }
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
        }
    }
}

/// Main application state
pub struct App {
    /// Configuration
    config: Config,

    /// Control flag for graceful shutdown
    should_stop: Arc<AtomicBool>,

    /// Active connections map (shared with background threads)
    connections: Arc<DashMap<String, Connection>>,

    /// Current connections snapshot for UI
    connections_snapshot: Arc<RwLock<Vec<Connection>>>,

    /// Service name lookup
    service_lookup: Arc<ServiceLookup>,

    /// Application statistics
    stats: Arc<AppStats>,

    /// Loading state
    is_loading: Arc<AtomicBool>,

    /// Current network interface name
    current_interface: Arc<RwLock<Option<String>>>,

    /// Data link type for packet parsing (needed for PKTAP detection)
    linktype: Arc<RwLock<Option<i32>>>,

    /// Whether PKTAP is active (macOS only) - used to disable process enrichment
    pktap_active: Arc<AtomicBool>,

    /// Current process detection status (method and degradation info)
    process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,

    /// Interface statistics (cumulative totals)
    interface_stats: Arc<DashMap<String, InterfaceStats>>,

    /// Interface rates (per-second rates)
    interface_rates: Arc<DashMap<String, InterfaceRates>>,

    /// Traffic history for graph visualization
    traffic_history: Arc<RwLock<TrafficHistory>>,

    /// RTT tracker for latency measurement
    rtt_tracker: Arc<Mutex<RttTracker>>,

    /// DNS resolver for reverse DNS lookups
    dns_resolver: Option<Arc<DnsResolver>>,

    /// GeoIP resolver for location/ASN lookups
    geoip_resolver: Option<Arc<GeoIpResolver>>,

    /// Sandbox status (Linux Landlock)
    #[cfg(target_os = "linux")]
    sandbox_info: Arc<RwLock<SandboxInfo>>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config) -> Result<Self> {
        // Load service definitions
        let service_lookup = ServiceLookup::from_embedded().unwrap_or_else(|e| {
            warn!("Failed to load embedded services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

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
            connections: Arc::new(DashMap::new()),
            connections_snapshot: Arc::new(RwLock::new(Vec::new())),
            service_lookup: Arc::new(service_lookup),
            stats: Arc::new(AppStats::default()),
            is_loading: Arc::new(AtomicBool::new(true)),
            current_interface: Arc::new(RwLock::new(None)),
            linktype: Arc::new(RwLock::new(None)),
            pktap_active: Arc::new(AtomicBool::new(false)),
            process_detection_status: Arc::new(RwLock::new(ProcessDetectionStatus::with_method(
                "initializing...",
            ))),
            interface_stats: Arc::new(DashMap::new()),
            interface_rates: Arc::new(DashMap::new()),
            traffic_history: Arc::new(RwLock::new(TrafficHistory::new(60))), // 60 seconds of history
            rtt_tracker: Arc::new(Mutex::new(RttTracker::new())),
            dns_resolver,
            geoip_resolver,
            #[cfg(target_os = "linux")]
            sandbox_info: Arc::new(RwLock::new(SandboxInfo::default())),
        })
    }

    /// Start all background threads
    pub fn start(&mut self) -> Result<()> {
        info!("Starting network monitor application");

        // Use stored connection map
        let connections = Arc::clone(&self.connections);

        // Start packet capture pipeline
        self.start_packet_capture_pipeline(connections.clone())?;

        // Start process enrichment thread (but delay for PKTAP detection on macOS)
        self.start_process_enrichment_conditional(connections.clone())?;

        // Start GeoIP enrichment thread
        self.start_geoip_enrichment_thread(connections.clone())?;

        // Start snapshot provider for UI
        self.start_snapshot_provider(connections.clone())?;

        // Start cleanup thread
        self.start_cleanup_thread(connections.clone())?;

        // Start rate refresh thread
        self.start_rate_refresh_thread(connections)?;

        // Start interface stats collection thread
        self.start_interface_stats_thread()?;

        // Start traffic history thread for graph visualization
        self.start_traffic_history_thread()?;

        // Mark loading as complete after a short delay
        let is_loading = Arc::clone(&self.is_loading);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(500));
            is_loading.store(false, Ordering::Relaxed);
        });

        Ok(())
    }

    /// Start packet capture and processing pipeline
    fn start_packet_capture_pipeline(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        // Create packet channel
        let (packet_tx, packet_rx) = channel::unbounded();

        // Start capture thread
        self.start_capture_thread(packet_tx)?;

        // Start multiple packet processing threads
        let num_processors = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(4);

        for i in 0..num_processors {
            self.start_packet_processor(i, packet_rx.clone(), connections.clone());
        }

        Ok(())
    }

    /// Start packet capture thread
    fn start_capture_thread(&self, packet_tx: Sender<Vec<u8>>) -> Result<()> {
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
        let _pktap_active = Arc::clone(&self.pktap_active);
        let pcap_export_file = self.config.pcap_export_file.clone();

        thread::spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok((capture, device_name, linktype)) => {
                    // Store the actual interface name and linktype being used
                    *current_interface.write().unwrap() = Some(device_name.clone());
                    *linktype_storage.write().unwrap() = Some(linktype);

                    // Check if PKTAP is active (linktype 149 or 258)
                    #[cfg(target_os = "macos")]
                    {
                        use crate::network::link_layer::pktap;
                        if pktap::is_pktap_linktype(linktype) {
                            _pktap_active.store(true, Ordering::Relaxed);
                            info!("✓ PKTAP is active - process metadata will be provided directly");
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

                    let mut reader = PacketReader::new(capture);
                    let mut packets_read = 0u64;
                    let mut last_log = Instant::now();
                    let mut last_stats_check = Instant::now();

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
                                    info!("First packet captured! Size: {} bytes", packet.len());
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
                                    use std::time::{SystemTime, UNIX_EPOCH};
                                    let now = SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default();
                                    #[cfg(unix)]
                                    let ts = libc::timeval {
                                        tv_sec: now.as_secs() as libc::time_t,
                                        tv_usec: now.subsec_micros() as libc::suseconds_t,
                                    };
                                    #[cfg(windows)]
                                    let ts = libc::timeval {
                                        tv_sec: now.as_secs() as libc::c_long,
                                        tv_usec: now.subsec_micros() as libc::c_long,
                                    };
                                    let header = pcap::PacketHeader {
                                        ts,
                                        caplen: packet.len() as u32,
                                        len: packet.len() as u32,
                                    };
                                    savefile.write(&pcap::Packet {
                                        header: &header,
                                        data: &packet,
                                    });
                                }

                                if packet_tx.send(packet).is_err() {
                                    warn!("Packet channel closed");
                                    break;
                                }
                            }
                            Ok(None) => {
                                // Timeout - check stats every second
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
        });

        Ok(())
    }

    /// Start a packet processor thread
    fn start_packet_processor(
        &self,
        id: usize,
        packet_rx: Receiver<Vec<u8>>,
        connections: Arc<DashMap<String, Connection>>,
    ) {
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let linktype_storage = Arc::clone(&self.linktype);
        let json_log_path = self.config.json_log_file.clone();
        let rtt_tracker = Arc::clone(&self.rtt_tracker);
        let dns_resolver = self.dns_resolver.clone();
        let parser_config = ParserConfig {
            enable_dpi: self.config.enable_dpi,
            ..Default::default()
        };

        thread::spawn(move || {
            info!("Packet processor {} started", id);

            // Wait for linktype to be available
            let parser = loop {
                if let Some(linktype) = *linktype_storage.read().unwrap() {
                    break PacketParser::with_config(parser_config.clone()).with_linktype(linktype);
                }
                thread::sleep(Duration::from_millis(10));
            };
            let mut batch = Vec::new();
            let mut total_processed = 0u64;
            let mut last_log = Instant::now();

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Packet processor {} stopping", id);
                    break;
                }

                // Collect packets in batches
                batch.clear();
                let deadline = Instant::now() + Duration::from_millis(10);

                while batch.len() < 100 && Instant::now() < deadline {
                    match packet_rx.recv_timeout(Duration::from_millis(1)) {
                        Ok(packet) => batch.push(packet),
                        Err(_) => break,
                    }
                }

                // Process batch
                let mut parsed_count = 0;
                for packet_data in &batch {
                    if let Some(parsed) = parser.parse_packet(packet_data) {
                        update_connection(
                            &connections,
                            parsed,
                            &stats,
                            &json_log_path,
                            &rtt_tracker,
                            dns_resolver.as_deref(),
                        );
                        parsed_count += 1;
                    }
                }

                if !batch.is_empty() {
                    total_processed += batch.len() as u64;
                    stats
                        .packets_processed
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);

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
            }

            info!(
                "Packet processor {} exiting, total processed: {}",
                id, total_processed
            );
        });
    }

    /// Start process enrichment thread conditionally based on PKTAP status
    fn start_process_enrichment_conditional(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let pktap_active = Arc::clone(&self.pktap_active);
        let should_stop = Arc::clone(&self.should_stop);
        let process_detection_status = Arc::clone(&self.process_detection_status);

        thread::spawn(move || {
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
                connections,
                should_stop,
                pktap_active,
                process_detection_status,
            ) {
                error!("Process enrichment thread failed: {}", e);
            }
        });

        Ok(())
    }

    /// Run the actual process enrichment logic
    fn run_process_enrichment(
        connections: Arc<DashMap<String, Connection>>,
        should_stop: Arc<AtomicBool>,
        pktap_active: Arc<AtomicBool>,
        process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,
    ) -> Result<()> {
        use crate::network::platform::DegradationReason;

        // Check PKTAP status before creating process lookup
        let use_pktap = pktap_active.load(Ordering::Relaxed);

        let process_lookup = create_process_lookup(use_pktap)?;
        let interval = Duration::from_secs(2); // Use default interval

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
                last_refresh = Instant::now();
            }

            // Enrich connections without process info
            let mut enriched = 0;
            for mut entry in connections.iter_mut() {
                // Allow partial enrichment - fill in missing pieces without overwriting existing data
                if let Some((pid, name)) = process_lookup.get_process_for_connection(&entry) {
                    let mut did_enrich = false;

                    // Only set process name if it's missing
                    if let Some(existing_name) = &entry.process_name {
                        // Check if the existing name differs significantly (for debugging)
                        let existing_normalized = existing_name
                            .split_whitespace()
                            .collect::<Vec<&str>>()
                            .join(" ");
                        let new_normalized =
                            name.split_whitespace().collect::<Vec<&str>>().join(" ");

                        if existing_normalized != new_normalized {
                            debug!(
                                "⚠️  Process name differs: existing='{}' vs lsof='{}'",
                                existing_name, name
                            );
                        }
                    } else {
                        entry.process_name = Some(name.clone());
                        did_enrich = true;
                        debug!(
                            "✓ Set process name for connection {}: {}",
                            entry.key(),
                            name
                        );
                    }

                    // Only set PID if it's missing
                    if entry.pid.is_none() {
                        entry.pid = Some(pid);
                        did_enrich = true;
                        debug!("✓ Set PID for connection {}: {}", entry.key(), pid);
                    } else if entry.pid != Some(pid) {
                        // PID differs - log for debugging
                        debug!(
                            "⚠️  PID differs for {}: existing={:?} vs lsof={}",
                            entry.key(),
                            entry.pid,
                            pid
                        );
                    }

                    if did_enrich {
                        enriched += 1;
                    }
                }
            }

            if enriched > 0 {
                debug!("Enriched {} connections with process info", enriched);
            }

            thread::sleep(interval);
        }

        Ok(())
    }

    /// Start snapshot provider thread for UI updates
    fn start_snapshot_provider(&self, connections: Arc<DashMap<String, Connection>>) -> Result<()> {
        let snapshot = Arc::clone(&self.connections_snapshot);
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let service_lookup = Arc::clone(&self.service_lookup);
        let filter_localhost = self.config.filter_localhost;
        let refresh_interval = Duration::from_millis(self.config.refresh_interval);

        thread::spawn(move || {
            info!("Snapshot provider thread started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Snapshot provider thread stopping");
                    break;
                }

                // Create snapshot
                let start = Instant::now();
                let total_connections = connections.len();

                let mut snapshot_data: Vec<Connection> = connections
                    .iter()
                    .map(|entry| {
                        let mut conn = entry.value().clone();

                        // Enrich with service name (prefer remote port, which is
                        // typically the server/well-known port, over the local
                        // ephemeral port)
                        if conn.service_name.is_none() {
                            if let Some(service) =
                                service_lookup.lookup(conn.remote_addr.port(), conn.protocol)
                            {
                                conn.service_name = Some(service.to_string());
                            } else if let Some(service) =
                                service_lookup.lookup(conn.local_addr.port(), conn.protocol)
                            {
                                conn.service_name = Some(service.to_string());
                            }
                        }

                        conn
                    })
                    .filter(|conn| {
                        // Apply filters
                        if filter_localhost {
                            !(conn.local_addr.ip().is_loopback()
                                && conn.remote_addr.ip().is_loopback())
                        } else {
                            true
                        }
                    })
                    .filter(|conn| conn.is_active())
                    .collect();

                // Sort by creation time (oldest first, newest last for maximum stability)
                snapshot_data.sort_by(|a, b| a.created_at.cmp(&b.created_at));

                let filtered_count = snapshot_data.len();

                // Update snapshot
                *snapshot.write().unwrap() = snapshot_data;

                // Update stats
                stats
                    .connections_tracked
                    .store(total_connections as u64, Ordering::Relaxed);
                *stats.last_update.write().unwrap() = Instant::now();

                debug!(
                    "Snapshot updated in {:?} - Total: {}, Filtered: {}",
                    start.elapsed(),
                    total_connections,
                    filtered_count
                );

                thread::sleep(refresh_interval);
            }
        });

        Ok(())
    }

    /// Start rate refresh thread to update rates for idle connections
    fn start_rate_refresh_thread(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);

        thread::spawn(move || {
            info!("Rate refresh thread started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Rate refresh thread stopping");
                    break;
                }

                // Refresh rates for all connections
                // This ensures rates decay to zero for idle connections
                for mut entry in connections.iter_mut() {
                    entry.value_mut().refresh_rates();
                }

                // Run every 1 second to balance responsiveness with performance
                thread::sleep(Duration::from_secs(1));
            }
        });

        Ok(())
    }

    /// Start interface statistics collection thread
    fn start_interface_stats_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let interface_stats = Arc::clone(&self.interface_stats);
        let interface_rates = Arc::clone(&self.interface_rates);

        thread::spawn(move || {
            info!("Interface stats collection thread started");

            let provider = PlatformStatsProvider;
            let mut previous_stats: HashMap<String, InterfaceStats> = HashMap::new();

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Interface stats thread stopping");
                    break;
                }

                // Collect stats from all interfaces
                match provider.get_all_stats() {
                    Ok(stats_vec) => {
                        // Clear old entries
                        interface_stats.clear();
                        interface_rates.clear();

                        for stat in stats_vec {
                            // Calculate rates if we have previous data
                            if let Some(prev) = previous_stats.get(&stat.interface_name) {
                                let rates = stat.calculate_rates(prev);
                                interface_rates.insert(stat.interface_name.clone(), rates);
                            }

                            // Store current stats
                            interface_stats.insert(stat.interface_name.clone(), stat.clone());
                            previous_stats.insert(stat.interface_name.clone(), stat);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to collect interface stats: {}", e);
                    }
                }

                // Refresh every 2 seconds
                thread::sleep(Duration::from_secs(2));
            }
        });

        Ok(())
    }

    /// Start traffic history thread for graph visualization
    fn start_traffic_history_thread(&self) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let traffic_history = Arc::clone(&self.traffic_history);
        let interface_rates = Arc::clone(&self.interface_rates);
        let connections_snapshot = Arc::clone(&self.connections_snapshot);
        let stats = Arc::clone(&self.stats);
        let rtt_tracker = Arc::clone(&self.rtt_tracker);

        thread::spawn(move || {
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

                // Get connection count from snapshot
                let connection_count = connections_snapshot
                    .read()
                    .map(|snap| snap.len())
                    .unwrap_or(0);

                // Get packet and retransmit counts (calculate deltas)
                let current_packets = stats.packets_processed.load(Ordering::Relaxed);
                let current_retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);

                let packets_delta = current_packets.saturating_sub(prev_packets);
                let retransmits_delta = current_retransmits.saturating_sub(prev_retransmits);

                prev_packets = current_packets;
                prev_retransmits = current_retransmits;

                // Get average RTT from tracker (last 1 second window)
                let avg_rtt_ms = rtt_tracker
                    .lock()
                    .ok()
                    .and_then(|mut tracker| tracker.take_average_rtt(1));

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
        });

        Ok(())
    }

    /// Start GeoIP enrichment thread to populate location/ASN info for connections
    fn start_geoip_enrichment_thread(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
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
                    for mut entry in connections.iter_mut() {
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
    fn start_cleanup_thread(&self, connections: Arc<DashMap<String, Connection>>) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let json_log_path = self.config.json_log_file.clone();
        let pcap_export_path = self.config.pcap_export_file.clone();
        let dns_resolver = self.dns_resolver.clone();

        thread::spawn(move || {
            info!("Cleanup thread started");

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Cleanup thread stopping");
                    break;
                }

                // Remove inactive connections
                let now = SystemTime::now();
                let mut removed = 0;

                // Collect keys of connections to be removed
                let mut removed_keys = Vec::new();

                connections.retain(|key, conn| {
                    // Use dynamic timeout based on connection type and state
                    let should_keep = !conn.should_cleanup(now);

                    if !should_keep {
                        removed += 1;
                        removed_keys.push(key.clone());

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
                            "Cleanup: Removing {} connection {} (idle: {:?}, timeout: {:?}, state: {})",
                            conn.protocol,
                            key,
                            idle_time,
                            conn_timeout,
                            conn.state()
                        );
                    }

                    should_keep
                });

                // Clean up QUIC connection ID mappings for removed connections
                if !removed_keys.is_empty()
                    && let Ok(mut mapping) = QUIC_CONNECTION_MAPPING.lock()
                {
                    mapping.retain(|_, conn_key| !removed_keys.contains(conn_key));
                    debug!(
                        "Cleaned up QUIC mappings for {} removed connections",
                        removed_keys.len()
                    );
                }

                if removed > 0 {
                    debug!(
                        "Removed {} inactive connections and cleaned up QUIC mappings",
                        removed
                    );
                }

                thread::sleep(Duration::from_secs(10));
            }
        });

        Ok(())
    }

    /// Get current connections for UI display
    pub fn get_connections(&self) -> Vec<Connection> {
        self.get_filtered_connections("")
    }

    /// Get filtered connections for UI display
    pub fn get_filtered_connections(&self, filter_query: &str) -> Vec<Connection> {
        let connections = self.connections_snapshot.read().unwrap().clone();

        // Filter out DNS PTR queries/responses when reverse DNS is enabled
        let hide_ptr_lookups = self.dns_resolver.is_some() && !self.config.show_ptr_lookups;

        let connections: Vec<Connection> = if hide_ptr_lookups {
            connections
                .into_iter()
                .filter(|conn| {
                    // Hide DNS PTR queries/responses (used for reverse DNS lookups)
                    if let Some(ref dpi) = conn.dpi_info
                        && let ApplicationProtocol::Dns(ref dns_info) = dpi.application
                        && dns_info.query_type == Some(DnsQueryType::PTR)
                    {
                        return false;
                    }
                    true
                })
                .collect()
        } else {
            connections
        };

        if filter_query.trim().is_empty() {
            return connections;
        }

        let filter = ConnectionFilter::parse(filter_query);
        connections
            .into_iter()
            .filter(|conn| filter.matches(conn))
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

    /// Get traffic history for graph visualization
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
        }
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
    #[cfg(target_os = "linux")]
    pub fn get_sandbox_info(&self) -> SandboxInfo {
        self.sandbox_info
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Set sandbox status information
    #[cfg(target_os = "linux")]
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

    /// Clear all connections and related data, starting fresh
    /// This clears:
    /// - All tracked connections
    /// - Traffic history (graph data)
    /// - RTT measurements
    /// - QUIC connection mappings
    /// - Resets statistics counters
    pub fn clear_all_connections(&self) {
        info!("Clearing all connections and resetting statistics");

        // Clear the main connections map
        self.connections.clear();

        // Clear the UI snapshot
        if let Ok(mut snapshot) = self.connections_snapshot.write() {
            snapshot.clear();
        }

        // Clear traffic history
        if let Ok(mut history) = self.traffic_history.write() {
            history.clear();
        }

        // Clear RTT tracker
        if let Ok(mut tracker) = self.rtt_tracker.lock() {
            tracker.clear();
        }

        // Clear QUIC connection ID mappings
        if let Ok(mut mapping) = QUIC_CONNECTION_MAPPING.lock() {
            mapping.clear();
        }

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

/// Update or create a connection from a parsed packet
fn update_connection(
    connections: &DashMap<String, Connection>,
    parsed: ParsedPacket,
    _stats: &AppStats,
    json_log_path: &Option<String>,
    rtt_tracker: &Arc<Mutex<RttTracker>>,
    dns_resolver: Option<&DnsResolver>,
) {
    let mut key = parsed.connection_key.clone();
    let now = SystemTime::now();

    // Track RTT for TCP connections using SYN/SYN-ACK timing
    let mut measured_rtt: Option<std::time::Duration> = None;
    if parsed.protocol == Protocol::TCP
        && let Some(tcp_header) = &parsed.tcp_header
    {
        let conn_key = ConnectionKey::new(parsed.local_addr, parsed.remote_addr);

        if tcp_header.flags.syn && !tcp_header.flags.ack {
            // This is a SYN packet (outgoing connection initiation)
            if let Ok(mut tracker) = rtt_tracker.lock() {
                tracker.record_syn(conn_key);
            }
        } else if tcp_header.flags.syn && tcp_header.flags.ack {
            // This is a SYN-ACK packet (connection response)
            if let Ok(mut tracker) = rtt_tracker.lock() {
                measured_rtt = tracker.record_syn_ack(&conn_key);
            }
        }
    }

    // For QUIC packets, check if we have a connection ID mapping
    if parsed.protocol == Protocol::UDP
        && let Some(dpi_result) = &parsed.dpi_result
        && let ApplicationProtocol::Quic(quic_info) = &dpi_result.application
        && let Some(conn_id_hex) = &quic_info.connection_id_hex
        && let Ok(mut mapping) = QUIC_CONNECTION_MAPPING.lock()
    {
        if let Some(existing_key) = mapping.get(conn_id_hex) {
            key = existing_key.clone();
            debug!(
                "QUIC: Using existing connection key {} for Connection ID {}",
                key, conn_id_hex
            );
        } else {
            // New QUIC connection ID, create mapping
            mapping.insert(conn_id_hex.clone(), key.clone());
            debug!(
                "QUIC: Created new mapping {} -> {} for Connection ID {}",
                conn_id_hex, key, conn_id_hex
            );
        }
    }

    connections
        .entry(key.clone())
        .and_modify(|conn| {
            let (mut updated_conn, (new_retransmits, new_out_of_order, new_fast_retransmits)) =
                merge_packet_into_connection(conn.clone(), &parsed, now);

            // Store RTT measurement if we got one from SYN-ACK
            if let Some(rtt) = measured_rtt
                && updated_conn.initial_rtt.is_none()
            {
                updated_conn.initial_rtt = Some(rtt);
                debug!("RTT measured for {}: {:?}", key, rtt);
            }

            *conn = updated_conn;

            // Update global statistics
            if new_retransmits > 0 {
                _stats
                    .total_tcp_retransmits
                    .fetch_add(new_retransmits, Ordering::Relaxed);
            }
            if new_out_of_order > 0 {
                _stats
                    .total_tcp_out_of_order
                    .fetch_add(new_out_of_order, Ordering::Relaxed);
            }
            if new_fast_retransmits > 0 {
                _stats
                    .total_tcp_fast_retransmits
                    .fetch_add(new_fast_retransmits, Ordering::Relaxed);
            }
        })
        .or_insert_with(|| {
            debug!("New connection detected: {}", key);
            let mut conn = create_connection_from_packet(&parsed, now);

            // Store RTT measurement if we got one (unlikely for new connection, but handle it)
            if let Some(rtt) = measured_rtt {
                conn.initial_rtt = Some(rtt);
            }

            // Log new connection event if JSON logging is enabled
            if let Some(log_path) = json_log_path {
                log_connection_event(log_path, "new_connection", &conn, None, dns_resolver);
            }

            conn
        });
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
        // Give threads time to stop gracefully
        thread::sleep(Duration::from_millis(100));
    }
}
