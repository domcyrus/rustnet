// app.rs - Main application orchestration (with debug logging)
use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::network::{
    capture::{CaptureConfig, PacketReader, setup_packet_capture},
    merge::{
        create_connection_from_packet, enrich_with_process_info, enrich_with_service_name,
        merge_packet_into_connection,
    },
    parser::{PacketParser, ParsedPacket, ParserConfig},
    platform::{ProcessLookup, create_process_lookup},
    services::ServiceLookup,
    types::Connection,
};

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
    /// Process lookup interval in seconds
    pub process_lookup_interval: u64,
    /// Connection timeout in seconds (remove inactive connections)
    pub connection_timeout: u64,
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
            process_lookup_interval: 2,
            connection_timeout: 60,
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
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config) -> Result<Self> {
        // Load service definitions
        let service_lookup = ServiceLookup::from_file("/etc/services").unwrap_or_else(|e| {
            warn!("Failed to load /etc/services: {}, using defaults", e);
            ServiceLookup::with_defaults()
        });

        Ok(Self {
            config,
            should_stop: Arc::new(AtomicBool::new(false)),
            connections_snapshot: Arc::new(RwLock::new(Vec::new())),
            service_lookup: Arc::new(service_lookup),
            stats: Arc::new(AppStats::default()),
            is_loading: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Start all background threads
    pub fn start(&mut self) -> Result<()> {
        info!("Starting network monitor application");

        // Create shared connection map
        let connections: Arc<DashMap<String, Connection>> = Arc::new(DashMap::new());

        // Start packet capture pipeline
        self.start_packet_capture_pipeline(connections.clone())?;

        // Start process enrichment thread
        self.start_process_enrichment(connections.clone())?;

        // Start snapshot provider for UI
        self.start_snapshot_provider(connections.clone())?;

        // Start cleanup thread
        self.start_cleanup_thread(connections)?;

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

        thread::spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok(capture) => {
                    info!("Packet capture started successfully");
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

                                // Log every 100 packets or every 5 seconds
                                if packets_read % 100 == 0
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
                    error!("Failed to start packet capture: {}", e);
                    error!(
                        "Make sure you have permission to capture packets (try running with sudo)"
                    );
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
        let parser_config = ParserConfig {
            enable_dpi: self.config.enable_dpi,
            ..Default::default()
        };

        thread::spawn(move || {
            info!("Packet processor {} started", id);
            let parser = PacketParser::with_config(parser_config);
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
                    if total_processed % 100 == 0 || last_log.elapsed() > Duration::from_secs(5) {
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

    /// Start process enrichment thread
    fn start_process_enrichment(
        &self,
        connections: Arc<DashMap<String, Connection>>,
    ) -> Result<()> {
        let process_lookup = create_process_lookup()?;
        let should_stop = Arc::clone(&self.should_stop);
        let interval = Duration::from_secs(self.config.process_lookup_interval);

        thread::spawn(move || {
            info!("Process enrichment thread started");
            let mut last_refresh = Instant::now();

            loop {
                if should_stop.load(Ordering::Relaxed) {
                    info!("Process enrichment thread stopping");
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
                    if entry.process_name.is_none() {
                        if let Some((pid, name)) = process_lookup.get_process_for_connection(&entry)
                        {
                            entry.pid = Some(pid);
                            entry.process_name = Some(name);
                            enriched += 1;
                        }
                    }
                }

                if enriched > 0 {
                    debug!("Enriched {} connections with process info", enriched);
                }

                thread::sleep(interval);
            }
        });

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

                // Sort by last activity
                snapshot_data.sort_by(|a, b| b.last_activity.cmp(&a.last_activity));

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

    /// Start cleanup thread to remove old connections
    fn start_cleanup_thread(&self, connections: Arc<DashMap<String, Connection>>) -> Result<()> {
        let should_stop = Arc::clone(&self.should_stop);
        let timeout = Duration::from_secs(self.config.connection_timeout);

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

                connections.retain(|_, conn| {
                    let should_keep = now
                        .duration_since(conn.last_activity)
                        .unwrap_or(Duration::from_secs(0))
                        < timeout;

                    if !should_keep {
                        removed += 1;
                    }

                    should_keep
                });

                if removed > 0 {
                    debug!("Removed {} inactive connections", removed);
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
    stats: &AppStats,
) {
    let key = parsed.connection_key.clone();
    let now = SystemTime::now();

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
