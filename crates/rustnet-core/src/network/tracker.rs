//! Live connection tracking.
//!
//! [`ConnectionTracker`] folds parsed packets into a long-lived, lifecycle-
//! managed table of [`Connection`]s. It owns everything needed to turn a stream
//! of [`ParsedPacket`]s into the same connection view the `rustnet` TUI shows —
//! the active table, an archive of recently-closed ("historic") connections,
//! RTT estimation from TCP SYN/SYN-ACK timing, QUIC connection-ID coalescing,
//! and timeout-based cleanup — **without** any UI, capture, or process-lookup
//! dependency.
//!
//! This is the piece that makes headless tools easy: pair a capture source with
//! a parser, then feed each parsed packet to [`ConnectionTracker::ingest`] and
//! periodically call [`ConnectionTracker::cleanup`]. A Prometheus exporter, a
//! pcap post-processor, or a test harness can all reuse the exact connection
//! semantics of the main application. Offline consumers replaying a saved trace
//! should use [`ConnectionTracker::ingest_at`] with each packet's capture
//! timestamp so connection lifetimes and timeouts follow trace time rather than
//! the replay wall clock.
//!
//! ```no_run
//! use rustnet_core::network::parser::PacketParser;
//! use rustnet_core::network::tracker::ConnectionTracker;
//! use std::time::SystemTime;
//!
//! let parser = PacketParser::new();
//! let tracker = ConnectionTracker::new();
//! # let frames: Vec<Vec<u8>> = Vec::new();
//! for frame in frames {
//!     if let Some(parsed) = parser.parse_packet(&frame) {
//!         tracker.ingest(&parsed);
//!     }
//! }
//! tracker.cleanup(SystemTime::now()); // expire idle/closed connections
//! for conn in tracker.snapshot() {
//!     println!("{} {} -> {}", conn.protocol, conn.local_addr, conn.remote_addr);
//! }
//! ```
//!
//! All methods take `&self` (the internal tables use interior mutability), so a
//! single tracker can be wrapped in an [`std::sync::Arc`] and shared across a
//! capture thread, a cleanup thread, and a reader thread.

use crate::network::merge::{create_connection_from_packet, merge_packet_into_connection};
use crate::network::parser::ParsedPacket;
use crate::network::types::{ApplicationProtocol, Connection, ConnectionKey, Protocol, RttTracker};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime};

/// The active connection table: flow key -> connection.
///
/// Keys are compact `Copy` structs, and the map uses FxHash — with a small
/// fixed-size key, hashing is a handful of multiplies instead of SipHash over
/// a formatted string. (Hash-flooding resistance isn't needed here: the table
/// is bounded by `max_connections` and keyed by addresses, not attacker-chosen
/// bytes of arbitrary length.)
pub type ConnectionMap = DashMap<ConnectionKey, Connection, FxBuildHasher>;

/// The historic (recently-closed) connection table.
pub type HistoricMap = DashMap<HistoricKey, Connection, FxBuildHasher>;

/// Identity of an archived (closed) connection: the flow key plus the
/// connection's creation time, so multiple closed connections that reused the
/// same 4-tuple don't clobber each other. (Replaces the former
/// `"<key>:<created_at_nanos>"` string suffix.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HistoricKey {
    pub key: ConnectionKey,
    pub created_nanos: u128,
}

impl std::fmt::Display for HistoricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.key, self.created_nanos)
    }
}

/// Tuning knobs for a [`ConnectionTracker`].
#[derive(Debug, Clone)]
pub struct TrackerConfig {
    /// Maximum number of concurrent active connections. New connections beyond
    /// this limit are dropped (existing ones still update) to bound memory
    /// under port scans or connection floods.
    pub max_connections: usize,
    /// Maximum number of recently-closed ("historic") connections retained.
    /// Oldest-closed entries are evicted first.
    pub max_historic: usize,
    /// Maximum number of QUIC connection-ID -> connection-key mappings kept for
    /// coalescing migrated QUIC connections. Cleared wholesale when exceeded.
    pub max_quic_mappings: usize,
    /// Whether [`ConnectionTracker::cleanup`] archives removed connections into
    /// the historic table. Headless tools that don't need a closed-connection
    /// view can set this to `false` to save memory.
    pub keep_historic: bool,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            max_connections: 50_000,
            max_historic: 5_000,
            max_quic_mappings: 10_000,
            keep_historic: true,
        }
    }
}

/// What happened when a packet was [`ingest`](ConnectionTracker::ingest)ed.
///
/// Returned so callers can layer their own concerns — global statistics,
/// structured logging, DNS enrichment — on top of the core table update without
/// the tracker needing to know about them.
#[derive(Debug, Clone)]
pub struct IngestOutcome {
    /// The (possibly QUIC-coalesced) key under which the connection is stored.
    /// `Copy`, and its `Display` form matches the historical string key
    /// (`"TCP:1.2.3.4:80-TCP:5.6.7.8:443"`).
    pub key: ConnectionKey,
    /// `true` if this packet created a new connection entry.
    pub created: bool,
    /// `true` if the packet was dropped because `max_connections` was reached
    /// (the connection did not already exist and was not inserted).
    pub dropped: bool,
    /// New TCP retransmissions detected by this packet.
    pub retransmits: u64,
    /// New out-of-order TCP segments detected by this packet.
    pub out_of_order: u64,
    /// New TCP fast-retransmits detected by this packet.
    pub fast_retransmits: u64,
    /// An RTT sample, if this packet was a TCP SYN-ACK that matched a prior SYN.
    pub measured_rtt: Option<Duration>,
}

/// A live, lifecycle-managed table of network connections built from parsed
/// packets. See the [module docs](self) for the intended usage.
pub struct ConnectionTracker {
    connections: ConnectionMap,
    historic: HistoricMap,
    /// Coordinates moves between the active and historic maps with readers
    /// that need one consistent retained-connection view.
    lifecycle: RwLock<()>,
    rtt: Mutex<RttTracker>,
    quic_map: Mutex<HashMap<String, ConnectionKey>>,
    config: TrackerConfig,
    /// Active-connection count maintained by `ingest_at`/`cleanup`/`clear`.
    /// Lets the per-packet `max_connections` check be a single atomic load
    /// instead of a `DashMap::len()` (which read-locks every shard) plus an
    /// extra `contains_key` lookup. May transiently lag `connections.len()`
    /// by a few entries under concurrent ingest near the limit — acceptable
    /// for a flood-protection bound.
    active_count: AtomicUsize,
}

impl ConnectionTracker {
    /// Create a tracker with [default](TrackerConfig::default) configuration.
    pub fn new() -> Self {
        Self::with_config(TrackerConfig::default())
    }

    /// Create a tracker with custom [`TrackerConfig`].
    pub fn with_config(config: TrackerConfig) -> Self {
        Self {
            connections: ConnectionMap::with_hasher(FxBuildHasher),
            historic: HistoricMap::with_hasher(FxBuildHasher),
            lifecycle: RwLock::new(()),
            rtt: Mutex::new(RttTracker::new()),
            quic_map: Mutex::new(HashMap::new()),
            config,
            active_count: AtomicUsize::new(0),
        }
    }

    /// Fold a parsed packet into the connection table, creating or updating the
    /// matching connection, timestamping the update with the current wall clock.
    ///
    /// This is the right call for live capture. Offline consumers replaying a
    /// pcap should use [`ingest_at`](Self::ingest_at) and pass the packet's own
    /// capture time so connection lifetimes and [`cleanup`](Self::cleanup)
    /// timeouts reflect the trace rather than the replay wall clock.
    pub fn ingest(&self, parsed: &ParsedPacket) -> IngestOutcome {
        self.ingest_at(parsed, SystemTime::now())
    }

    /// Like [`ingest`](Self::ingest), but stamps the connection update with the
    /// supplied `now` instead of the wall clock.
    ///
    /// Use this for deterministic offline processing (pcap replay, tests): pass
    /// the packet's capture timestamp so `created_at`/`last_activity` and the
    /// `cleanup` timeout sweep operate on trace time, not real time.
    pub fn ingest_at(&self, parsed: &ParsedPacket, now: SystemTime) -> IngestOutcome {
        let mut key = parsed.connection_key();

        // Track RTT for TCP connections using SYN/SYN-ACK timing.
        let mut measured_rtt: Option<Duration> = None;
        if parsed.protocol == Protocol::Tcp
            && let Some(tcp_header) = &parsed.tcp_header
        {
            if tcp_header.flags.syn && !tcp_header.flags.ack {
                if let Ok(mut tracker) = self.rtt.lock() {
                    tracker.record_syn(key);
                }
            } else if tcp_header.flags.syn
                && tcp_header.flags.ack
                && let Ok(mut tracker) = self.rtt.lock()
            {
                measured_rtt = tracker.record_syn_ack(&key);
            }
        }

        // For QUIC packets, coalesce by connection ID so connection migration
        // (address change) maps back to the original connection key.
        if parsed.protocol == Protocol::Udp
            && let Some(dpi_result) = &parsed.dpi_result
            && let ApplicationProtocol::Quic(quic_info) = &dpi_result.application
            && let Some(conn_id_hex) = &quic_info.connection_id_hex
            && let Ok(mut mapping) = self.quic_map.lock()
        {
            if let Some(existing_key) = mapping.get(conn_id_hex) {
                key = *existing_key;
            } else {
                // Prevent unbounded growth of QUIC connection-ID mappings.
                if mapping.len() >= self.config.max_quic_mappings {
                    mapping.clear();
                }
                mapping.insert(conn_id_hex.clone(), key);
            }
        }

        // Prevent unbounded growth from port scans or connection floods. Only
        // limit new connections; existing ones always get updated. The fast
        // path is a single atomic load; only when at the cap do we pay a
        // lookup to distinguish update-existing from drop-new. (Never call
        // `len()` here or while holding an entry guard — it read-locks every
        // shard.)
        if self.active_count.load(Ordering::Relaxed) >= self.config.max_connections
            && !self.connections.contains_key(&key)
        {
            return IngestOutcome {
                key,
                created: false,
                dropped: true,
                retransmits: 0,
                out_of_order: 0,
                fast_retransmits: 0,
                measured_rtt,
            };
        }

        let mut created = false;
        let mut deltas = (0u64, 0u64, 0u64);
        self.connections
            .entry(key)
            .and_modify(|conn| {
                deltas = merge_packet_into_connection(conn, parsed, now);
                if let Some(rtt) = measured_rtt
                    && conn.initial_rtt.is_none()
                {
                    conn.initial_rtt = Some(rtt);
                }
            })
            .or_insert_with(|| {
                created = true;
                let mut conn = create_connection_from_packet(parsed, now);
                if let Some(rtt) = measured_rtt {
                    conn.initial_rtt = Some(rtt);
                }
                conn
            });
        if created {
            self.active_count.fetch_add(1, Ordering::Relaxed);
        }

        IngestOutcome {
            key,
            created,
            dropped: false,
            retransmits: deltas.0,
            out_of_order: deltas.1,
            fast_retransmits: deltas.2,
            measured_rtt,
        }
    }

    /// Remove connections whose protocol-aware timeout has elapsed as of `now`.
    ///
    /// Removed connections are archived into the historic table (when
    /// [`keep_historic`](TrackerConfig::keep_historic) is set, subject to
    /// [`max_historic`](TrackerConfig::max_historic) eviction) and their QUIC
    /// mappings are dropped. Returns the removed connections (in their original,
    /// pre-archive form) so callers can emit close events or export them.
    pub fn cleanup(&self, now: SystemTime) -> Vec<Connection> {
        let _lifecycle = self
            .lifecycle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut removed: Vec<Connection> = Vec::new();
        let mut removed_keys: Vec<ConnectionKey> = Vec::new();
        let mut to_archive: Vec<(HistoricKey, Connection)> = Vec::new();
        let keep_historic = self.config.keep_historic;

        self.connections.retain(|key, conn| {
            let should_keep = !conn.should_cleanup(now);
            if !should_keep {
                removed_keys.push(*key);
                removed.push(conn.clone());

                // Archive a historic copy. The historic key includes created_at
                // so multiple closed connections sharing a 4-tuple don't clobber
                // each other. snapshot_clone: historic connections never refresh
                // their rates, so don't pin the (potentially large) sample
                // buffer in the archive.
                if keep_historic {
                    let mut historic = conn.snapshot_clone();
                    historic.is_historic = true;
                    historic.closed_at = Some(now);
                    let historic_key = HistoricKey {
                        key: *key,
                        created_nanos: conn
                            .created_at
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos(),
                    };
                    to_archive.push((historic_key, historic));
                }
            }
            should_keep
        });
        if !removed.is_empty() {
            self.active_count
                .fetch_sub(removed.len(), Ordering::Relaxed);
        }

        if keep_historic {
            for (key, conn) in to_archive {
                self.historic.insert(key, conn);
            }

            // Enforce max_historic by evicting oldest-closed first.
            if self.historic.len() > self.config.max_historic {
                let mut entries: Vec<(HistoricKey, SystemTime)> = self
                    .historic
                    .iter()
                    .map(|entry| {
                        let closed = entry.value().closed_at.unwrap_or(entry.value().created_at);
                        (*entry.key(), closed)
                    })
                    .collect();
                entries.sort_by_key(|(_, closed)| *closed);
                let to_remove = self.historic.len() - self.config.max_historic;
                for (key, _) in entries.into_iter().take(to_remove) {
                    self.historic.remove(&key);
                }
            }
        }

        // Clean up QUIC connection-ID mappings pointing at removed connections.
        if !removed_keys.is_empty()
            && let Ok(mut mapping) = self.quic_map.lock()
        {
            mapping.retain(|_, conn_key| !removed_keys.contains(conn_key));
        }

        removed
    }

    /// A point-in-time copy of the active connections.
    ///
    /// Note: this is a full clone, including each connection's rate-sample
    /// buffer — the buffer is shared via `Arc`, so the *next* per-packet
    /// update on a live connection pays a copy-on-write deep copy. Callers
    /// that only need the cached `current_*_rate_bps` fields (any read-only
    /// view) should prefer [`Connection::snapshot_clone`] over the entries of
    /// [`connections`](Self::connections) to keep the packet path allocation-
    /// free.
    pub fn snapshot(&self) -> Vec<Connection> {
        self.connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// A point-in-time copy of the historic (recently-closed) connections.
    pub fn historic_snapshot(&self) -> Vec<Connection> {
        self.historic
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Inspect the active and historic maps as one consistent retained view.
    ///
    /// Cleanup cannot move a connection between the maps while `inspect` is
    /// running. Packet updates may still update active rows through DashMap's
    /// per-entry locking.
    pub fn with_retained_sources<R>(
        &self,
        inspect: impl FnOnce(&ConnectionMap, &HistoricMap) -> R,
    ) -> R {
        let _lifecycle = self
            .lifecycle
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inspect(&self.connections, &self.historic)
    }

    /// Number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// `true` if there are no active connections.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// Number of historic (recently-closed) connections.
    pub fn historic_len(&self) -> usize {
        self.historic.len()
    }

    /// Drop all active and historic connections and reset RTT/QUIC state.
    pub fn clear(&self) {
        let _lifecycle = self
            .lifecycle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.connections.clear();
        self.active_count.store(0, Ordering::Relaxed);
        self.historic.clear();
        if let Ok(mut tracker) = self.rtt.lock() {
            tracker.clear();
        }
        if let Ok(mut mapping) = self.quic_map.lock() {
            mapping.clear();
        }
    }

    /// The tracker's configuration.
    pub fn config(&self) -> &TrackerConfig {
        &self.config
    }

    /// Direct access to the active connection table.
    ///
    /// Use this for in-place enrichment (e.g. attaching process, DNS, or GeoIP
    /// information via `iter_mut`) or custom reads. Lifecycle changes should go
    /// through [`ingest`](Self::ingest) and [`cleanup`](Self::cleanup) so the
    /// connection-count limit, RTT, and QUIC coalescing stay consistent —
    /// inserting or removing entries directly desyncs the internal counter
    /// backing the `max_connections` check.
    pub fn connections(&self) -> &ConnectionMap {
        &self.connections
    }

    /// Direct access to the historic (recently-closed) connection table.
    pub fn historic(&self) -> &HistoricMap {
        &self.historic
    }

    /// Average RTT (in milliseconds) over the last `window_secs` seconds of
    /// SYN/SYN-ACK samples, consuming the samples in that window. `None` if no
    /// samples are available.
    pub fn take_average_rtt(&self, window_secs: u64) -> Option<f64> {
        self.rtt
            .lock()
            .ok()
            .and_then(|mut tracker| tracker.take_average_rtt(window_secs))
    }
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::parser::PacketParser;

    /// A minimal Ethernet+IPv4+UDP frame, parsed into a `ParsedPacket` so we can
    /// exercise the tracker with a realistic input.
    fn udp_frame(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet header: dst mac, src mac, ethertype IPv4 (0x0800)
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4 header (20 bytes)
        let ip_total_len = (20 + 8u16).to_be_bytes(); // ip header + udp header
        f.extend_from_slice(&[0x45, 0x00]);
        f.extend_from_slice(&ip_total_len);
        f.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
        f.push(64); // ttl
        f.push(17); // protocol = UDP
        f.extend_from_slice(&[0, 0]); // checksum
        f.extend_from_slice(&[192, 168, 0, 1]); // src ip
        f.extend_from_slice(&[192, 168, 0, 2]); // dst ip
        // UDP header (8 bytes)
        f.extend_from_slice(&src_port.to_be_bytes());
        f.extend_from_slice(&dst_port.to_be_bytes());
        f.extend_from_slice(&8u16.to_be_bytes()); // length
        f.extend_from_slice(&[0, 0]); // checksum
        f
    }

    fn parse(frame: &[u8]) -> ParsedPacket {
        PacketParser::new()
            .parse_packet(frame)
            .expect("frame should parse")
    }

    #[test]
    fn ingest_creates_then_updates() {
        let tracker = ConnectionTracker::new();
        let p = parse(&udp_frame(40000, 53));

        let first = tracker.ingest(&p);
        assert!(first.created, "first packet should create a connection");
        assert!(!first.dropped);
        assert_eq!(tracker.len(), 1);

        let second = tracker.ingest(&p);
        assert!(!second.created, "second packet should update, not create");
        assert_eq!(second.key, first.key);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn distinct_flows_are_separate_connections() {
        let tracker = ConnectionTracker::new();
        tracker.ingest(&parse(&udp_frame(40000, 53)));
        tracker.ingest(&parse(&udp_frame(40001, 53)));
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn max_connections_limit_drops_new_only() {
        let tracker = ConnectionTracker::with_config(TrackerConfig {
            max_connections: 1,
            ..TrackerConfig::default()
        });
        let a = tracker.ingest(&parse(&udp_frame(40000, 53)));
        assert!(a.created && !a.dropped);

        // A different flow can't be inserted (limit reached) and is dropped.
        let b = tracker.ingest(&parse(&udp_frame(40001, 53)));
        assert!(b.dropped, "new connection beyond the limit must be dropped");
        assert!(!b.created);
        assert_eq!(tracker.len(), 1);

        // The existing flow still updates despite the limit.
        let a2 = tracker.ingest(&parse(&udp_frame(40000, 53)));
        assert!(!a2.dropped && !a2.created);
    }

    #[test]
    fn connection_limit_recovers_after_cleanup() {
        let tracker = ConnectionTracker::with_config(TrackerConfig {
            max_connections: 1,
            ..TrackerConfig::default()
        });
        assert!(tracker.ingest(&parse(&udp_frame(40000, 53))).created);
        assert!(tracker.ingest(&parse(&udp_frame(40001, 53))).dropped);

        // Expire everything; the limit accounting must follow the removals.
        tracker.cleanup(SystemTime::now() + Duration::from_secs(86_400));
        assert_eq!(tracker.len(), 0);

        let c = tracker.ingest(&parse(&udp_frame(40002, 53)));
        assert!(
            c.created && !c.dropped,
            "slot freed by cleanup must be reusable"
        );
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn connection_limit_recovers_after_clear() {
        let tracker = ConnectionTracker::with_config(TrackerConfig {
            max_connections: 1,
            ..TrackerConfig::default()
        });
        assert!(tracker.ingest(&parse(&udp_frame(40000, 53))).created);
        tracker.clear();
        let b = tracker.ingest(&parse(&udp_frame(40001, 53)));
        assert!(b.created && !b.dropped, "clear() must reset the limit");
    }

    #[test]
    fn cleanup_archives_to_historic() {
        let tracker = ConnectionTracker::new();
        tracker.ingest(&parse(&udp_frame(40000, 53)));
        assert_eq!(tracker.len(), 1);

        // A far-future `now` forces every connection past its timeout.
        let far_future = SystemTime::now() + Duration::from_secs(86_400);
        let removed = tracker.cleanup(far_future);

        assert_eq!(removed.len(), 1, "the idle connection should be removed");
        assert!(!removed[0].is_historic, "returned form is the original");
        assert_eq!(tracker.len(), 0);
        assert_eq!(
            tracker.historic_len(),
            1,
            "removed conn archived as historic"
        );
    }

    #[test]
    fn retained_source_view_is_atomic_across_cleanup() {
        let tracker = std::sync::Arc::new(ConnectionTracker::new());
        tracker.ingest(&parse(&udp_frame(40000, 53)));

        let (active_scanned_tx, active_scanned_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let reader_tracker = std::sync::Arc::clone(&tracker);
        let reader = std::thread::spawn(move || {
            reader_tracker.with_retained_sources(|active, historic| {
                let active_count = active.iter().count();
                active_scanned_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                active_count + historic.iter().count()
            })
        });

        active_scanned_rx.recv().unwrap();
        let (cleanup_started_tx, cleanup_started_rx) = std::sync::mpsc::channel();
        let (cleanup_done_tx, cleanup_done_rx) = std::sync::mpsc::channel();
        let cleanup_tracker = std::sync::Arc::clone(&tracker);
        let cleanup = std::thread::spawn(move || {
            cleanup_started_tx.send(()).unwrap();
            let removed = cleanup_tracker.cleanup(SystemTime::now() + Duration::from_secs(86_400));
            cleanup_done_tx.send(removed.len()).unwrap();
        });

        cleanup_started_rx.recv().unwrap();
        assert!(
            cleanup_done_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "cleanup must wait for the retained source view"
        );
        release_tx.send(()).unwrap();

        assert_eq!(reader.join().unwrap(), 1);
        assert_eq!(cleanup_done_rx.recv().unwrap(), 1);
        cleanup.join().unwrap();
        assert_eq!(tracker.len(), 0);
        assert_eq!(tracker.historic_len(), 1);
    }

    #[test]
    fn cleanup_without_keep_historic_skips_archive() {
        let tracker = ConnectionTracker::with_config(TrackerConfig {
            keep_historic: false,
            ..TrackerConfig::default()
        });
        tracker.ingest(&parse(&udp_frame(40000, 53)));
        let far_future = SystemTime::now() + Duration::from_secs(86_400);
        let removed = tracker.cleanup(far_future);
        assert_eq!(removed.len(), 1);
        assert_eq!(tracker.historic_len(), 0, "historic disabled");
    }

    #[test]
    fn ingest_at_uses_supplied_time_for_cleanup() {
        // A packet ingested "in the past" must be eligible for cleanup at a
        // `now` only slightly later than its supplied capture time — proving the
        // tracker stamps the connection with the caller's time, not the wall
        // clock. (Wall-clock stamping would make `created_at` ~= real now, so a
        // cleanup at trace-time + a few minutes would NOT expire it.)
        let tracker = ConnectionTracker::new();
        let capture_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&parse(&udp_frame(40000, 53)), capture_time);
        assert_eq!(tracker.len(), 1);

        // One day after the capture time the UDP flow is well past its timeout.
        let removed = tracker.cleanup(capture_time + Duration::from_secs(86_400));
        assert_eq!(
            removed.len(),
            1,
            "flow stamped at capture time should expire"
        );
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn clear_empties_everything() {
        let tracker = ConnectionTracker::new();
        tracker.ingest(&parse(&udp_frame(40000, 53)));
        tracker.cleanup(SystemTime::now() + Duration::from_secs(86_400));
        assert_eq!(tracker.historic_len(), 1);
        tracker.clear();
        assert!(tracker.is_empty());
        assert_eq!(tracker.historic_len(), 0);
    }
}
