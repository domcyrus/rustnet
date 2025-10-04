// app.rs - Main application orchestration (with debug logging)
use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::filter::ConnectionFilter;

use crate::network::{
    capture::{CaptureConfig, PacketReader, setup_packet_capture},
    merge::{create_connection_from_packet, merge_packet_into_connection},
    parser::{PacketParser, ParsedPacket, ParserConfig},
    platform::create_process_lookup_with_pktap_status,
    services::ServiceLookup,
    types::{ApplicationProtocol, Connection, Protocol},
};

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Global QUIC connection ID to connection key mapping
/// This allows tracking QUIC connections across connection ID changes
static QUIC_CONNECTION_MAPPING: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            filter_localhost: true,
            refresh_interval: 1000,
            enable_dpi: true,
            bpf_filter: None, // No filter by default to see all packets
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
}

impl Default for AppStats {
    fn default() -> Self {
        Self {
            packets_processed: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            connections_tracked: AtomicU64::new(0),
            last_update: RwLock::new(Instant::now()),
        }
    }
}

/// Main application state
pub struct App {
    /// Configuration
    config: Config,

    /// Control flag for graceful shutdown
    should_stop: Arc<AtomicBool>,

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

    /// Current process detection method (e.g., "eBPF + procfs", "pktap", "lsof", "N/A")
    process_detection_method: Arc<RwLock<String>>,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config) -> Result<Self> {
        // Load service definitions
        let service_lookup = ServiceLookup::from_embedded().unwrap_or_else(|e| {
            warn!("Failed to load embedded services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

        Ok(Self {
            config,
            should_stop: Arc::new(AtomicBool::new(false)),
            connections_snapshot: Arc::new(RwLock::new(Vec::new())),
            service_lookup: Arc::new(service_lookup),
            stats: Arc::new(AppStats::default()),
            is_loading: Arc::new(AtomicBool::new(true)),
            current_interface: Arc::new(RwLock::new(None)),
            linktype: Arc::new(RwLock::new(None)),
            pktap_active: Arc::new(AtomicBool::new(false)),
            process_detection_method: Arc::new(RwLock::new(String::from("initializing..."))),
        })
    }

    /// Start all background threads
    pub fn start(&mut self) -> Result<()> {
        info!("Starting network monitor application");

        // Create shared connection map
        let connections: Arc<DashMap<String, Connection>> = Arc::new(DashMap::new());

        // Start packet capture pipeline
        self.start_packet_capture_pipeline(connections.clone())?;

        // Start process enrichment thread (but delay for PKTAP detection on macOS)
        self.start_process_enrichment_conditional(connections.clone())?;

        // Start snapshot provider for UI
        self.start_snapshot_provider(connections.clone())?;

        // Start cleanup thread
        self.start_cleanup_thread(connections.clone())?;

        // Start rate refresh thread
        self.start_rate_refresh_thread(connections)?;

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

        thread::spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok((capture, device_name, linktype)) => {
                    // Store the actual interface name and linktype being used
                    *current_interface.write().unwrap() = Some(device_name.clone());
                    *linktype_storage.write().unwrap() = Some(linktype);

                    // Check if PKTAP is active (linktype 149 or 258)
                    #[cfg(target_os = "macos")]
                    {
                        use crate::network::pktap;
                        if pktap::is_pktap_linktype(linktype) {
                            _pktap_active.store(true, Ordering::Relaxed);
                            info!("✓ PKTAP is active - process metadata will be provided directly");
                        }
                    }

                    info!(
                        "Packet capture started successfully on interface: {} (linktype: {})",
                        device_name, linktype
                    );
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
                        update_connection(&connections, parsed, &stats);
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
        let process_detection_method = Arc::clone(&self.process_detection_method);

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
                        if let Ok(mut method) = process_detection_method.write() {
                            *method = String::from("pktap");
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
                    if let Ok(mut method) = process_detection_method.write() {
                        *method = String::from("pktap");
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
            if let Err(e) = Self::run_process_enrichment(connections, should_stop, pktap_active, process_detection_method) {
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
        process_detection_method: Arc<RwLock<String>>,
    ) -> Result<()> {
        // Check PKTAP status before creating process lookup
        let is_pktap = pktap_active.load(Ordering::Relaxed);

        let process_lookup = create_process_lookup_with_pktap_status(is_pktap)?;
        let interval = Duration::from_secs(2); // Use default interval

        // Get and set the detection method from the process lookup implementation
        // Only set if not already detected as pktap (to handle race conditions)
        if let Ok(mut method) = process_detection_method.write()
            && method.as_str() != "pktap"
        {
            *method = process_lookup.get_detection_method().to_string();
        }

        info!("Process enrichment thread started with detection method: {}",
              process_lookup.get_detection_method());
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
                    if entry.process_name.is_none() {
                        entry.process_name = Some(name.clone());
                        did_enrich = true;
                        debug!(
                            "✓ Set process name for connection {}: {}",
                            entry.key(),
                            name
                        );
                    } else {
                        // Check if the existing name differs significantly (for debugging)
                        let existing_name = entry.process_name.as_ref().unwrap();
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

                        // Enrich with service name
                        if conn.service_name.is_none() {
                            if let Some(service) =
                                service_lookup.lookup(conn.local_addr.port(), conn.protocol)
                            {
                                conn.service_name = Some(service.to_string());
                            } else if let Some(service) =
                                service_lookup.lookup(conn.remote_addr.port(), conn.protocol)
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

    /// Start cleanup thread to remove old connections
    fn start_cleanup_thread(&self, connections: Arc<DashMap<String, Connection>>) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);

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
        self.connections_snapshot.read().unwrap().clone()
    }

    /// Get filtered connections for UI display
    pub fn get_filtered_connections(&self, filter_query: &str) -> Vec<Connection> {
        let connections = self.connections_snapshot.read().unwrap().clone();

        if filter_query.trim().is_empty() {
            return connections;
        }

        let filter = ConnectionFilter::parse(filter_query);
        connections
            .into_iter()
            .filter(|conn| filter.matches(conn))
            .collect()
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

    /// Get the current process detection method
    pub fn get_process_detection_method(&self) -> String {
        self.process_detection_method
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| String::from("unknown"))
    }

    /// Stop all threads gracefully
    pub fn stop(&self) {
        info!("Stopping application");
        self.should_stop.store(true, Ordering::Relaxed);
    }
}

/// Update or create a connection from a parsed packet
fn update_connection(
    connections: &DashMap<String, Connection>,
    parsed: ParsedPacket,
    _stats: &AppStats,
) {
    let mut key = parsed.connection_key.clone();
    let now = SystemTime::now();

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
            *conn = merge_packet_into_connection(conn.clone(), &parsed, now);
        })
        .or_insert_with(|| {
            debug!("New connection detected: {}", key);
            create_connection_from_packet(&parsed, now)
        });
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop();
        // Give threads time to stop gracefully
        thread::sleep(Duration::from_millis(100));
    }
}
