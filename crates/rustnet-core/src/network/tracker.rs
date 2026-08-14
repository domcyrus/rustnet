//! Live connection tracking.
//!
//! [`ConnectionTracker`] folds parsed packets into a long-lived, lifecycle-
//! managed table of [`Connection`]s. It owns everything needed to turn a stream
//! of [`ParsedPacket`]s into the same connection view the `rustnet` TUI shows —
//! the active table, an archive of recently-closed ("historic") connections,
//! RTT estimation from TCP, QUIC handshakes, and ICMP echo, plus DNS response
//! timing, QUIC connection-ID coalescing, and timeout-based cleanup, all
//! without any UI, capture, or process-lookup
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

use crate::network::merge::{
    TcpMergeEvents, create_connection_from_packet, merge_packet_into_connection,
};
use crate::network::neighbors::{NeighborCache, NeighborEntry};
use crate::network::parser::ParsedPacket;
use crate::network::types::{
    ApplicationProtocol, Connection, ConnectionKey, Protocol, ProtocolState, QuicPacketType,
    RttTracker,
};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime};

/// Recently archived TCP tuples remain tombstoned briefly so delayed teardown
/// packets do not create phantom established connections.
const RECENTLY_CLOSED_TTL: Duration = Duration::from_secs(30);

/// Tombstone capacity floor. `max_historic` sizes the user-facing archive,
/// but tombstones guard correctness, so a tiny or zero `max_historic` must
/// not strip them and reopen the phantom-connection window. Entries are a
/// key and a timestamp; the TTL above bounds how long any of them live.
const RECENTLY_CLOSED_MIN_ENTRIES: usize = 1024;

/// Whether a QUIC packet belongs to the handshake exchange that RTT timing
/// pairs up.
///
/// 0-RTT is deliberately excluded: it is client-only application data sent
/// alongside the Initial, so treating it as a fresh send would restart the
/// timer and report a fraction of the real round trip. 1-RTT packets carry a
/// short header and reveal nothing to time against.
fn is_quic_handshake_packet(packet_type: QuicPacketType) -> bool {
    matches!(
        packet_type,
        QuicPacketType::Initial
            | QuicPacketType::Handshake
            | QuicPacketType::Retry
            | QuicPacketType::VersionNegotiation
    )
}

/// Whether a UDP packet's DPI classification is one the RTT tracker times.
/// Gates the rtt lock in `measure_timings` so untimed UDP traffic (QUIC 1-RTT
/// bulk data, SSDP, mDNS, ...) never touches the mutex on the packet path.
fn udp_application_is_timed(application: &ApplicationProtocol) -> bool {
    match application {
        ApplicationProtocol::Quic(quic) => is_quic_handshake_packet(quic.packet_type),
        ApplicationProtocol::Dns(_)
        | ApplicationProtocol::NetBios(_)
        | ApplicationProtocol::Stun(_)
        | ApplicationProtocol::Ntp(_) => true,
        _ => false,
    }
}

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
    /// `true` when a delayed packet matched a recently archived TCP tuple and
    /// was intentionally not turned into a new active connection.
    pub ignored_late: bool,
    /// Previous live generation archived by a strong new-session signal.
    /// Historic storage receives an immutable snapshot of this connection.
    pub archived: Option<Connection>,
    /// New TCP retransmissions detected by this packet.
    pub retransmits: u64,
    /// New out-of-order TCP segments detected by this packet.
    pub out_of_order: u64,
    /// New TCP fast-retransmits detected by this packet.
    pub fast_retransmits: u64,
    /// An RTT sample, if this packet completed a handshake round trip: a TCP
    /// SYN-ACK matching a prior SYN, or a QUIC handshake packet answering one
    /// sent the other way.
    pub measured_rtt: Option<Duration>,
    /// The latest completed DNS query→response round trip, if this packet was
    /// a response matching a pending query by transaction ID.
    pub dns_response_time: Option<Duration>,
    /// The latest completed NetBIOS request-to-response round trip, if this
    /// packet matched a pending request by transaction ID.
    pub netbios_response_time: Option<Duration>,
    /// The latest completed ICMP echo round trip, if this packet was a reply
    /// matching an outgoing request by identifier and sequence number.
    pub icmp_echo_rtt: Option<Duration>,
    /// The latest completed STUN request→response round trip, if this packet
    /// was a response matching a pending request by transaction ID.
    pub stun_rtt: Option<Duration>,
    /// The latest completed NTP request→response round trip, if this packet
    /// was a server response echoing a pending client transmit timestamp.
    pub ntp_rtt: Option<Duration>,
}

/// Timing measurements extracted from one packet, carried together through
/// the connection-table update into the resulting [`IngestOutcome`].
#[derive(Clone, Copy, Default)]
struct PacketTimings {
    measured_rtt: Option<Duration>,
    dns_response_time: Option<Duration>,
    netbios_response_time: Option<Duration>,
    icmp_echo_rtt: Option<Duration>,
    stun_rtt: Option<Duration>,
    ntp_rtt: Option<Duration>,
}

impl PacketTimings {
    /// An [`IngestOutcome`] carrying these timings, with every other field at
    /// its quiescent value for the caller to override via struct update.
    fn outcome(self, key: ConnectionKey) -> IngestOutcome {
        IngestOutcome {
            key,
            created: false,
            dropped: false,
            ignored_late: false,
            archived: None,
            retransmits: 0,
            out_of_order: 0,
            fast_retransmits: 0,
            measured_rtt: self.measured_rtt,
            dns_response_time: self.dns_response_time,
            netbios_response_time: self.netbios_response_time,
            icmp_echo_rtt: self.icmp_echo_rtt,
            stun_rtt: self.stun_rtt,
            ntp_rtt: self.ntp_rtt,
        }
    }
}

/// Stamp any round trips this packet completed onto its connection.
fn apply_timings(conn: &mut Connection, timings: &PacketTimings) {
    if let Some(rtt) = timings.measured_rtt
        && conn.initial_rtt.is_none()
    {
        conn.initial_rtt = Some(rtt);
    }
    // Last-wins, unlike `initial_rtt`: each completed query refreshes the
    // displayed response time.
    if let Some(rtt) = timings.dns_response_time {
        conn.dns_response_time = Some(rtt);
    }
    if let Some(rtt) = timings.netbios_response_time {
        conn.netbios_response_time = Some(rtt);
    }
    if let Some(rtt) = timings.icmp_echo_rtt {
        conn.icmp_echo_rtt = Some(rtt);
    }
    if let Some(rtt) = timings.stun_rtt {
        conn.stun_rtt = Some(rtt);
    }
    if let Some(rtt) = timings.ntp_rtt {
        conn.ntp_rtt = Some(rtt);
    }
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
    recently_closed: Mutex<HashMap<ConnectionKey, SystemTime>>,
    config: TrackerConfig,
    /// Active-connection count maintained by `ingest_at`/`cleanup`/`clear`.
    /// Lets the per-packet `max_connections` check be a single atomic load
    /// instead of a `DashMap::len()` (which read-locks every shard) plus an
    /// extra `contains_key` lookup. May transiently lag `connections.len()`
    /// by a few entries under concurrent ingest near the limit — acceptable
    /// for a flood-protection bound.
    active_count: AtomicUsize,
    /// IP -> MAC/vendor mappings learned passively from ingested ARP (IPv4)
    /// and NDP (IPv6) packets. Outlives the connections themselves, so LAN
    /// peers stay identified after their ARP/NDP rows are cleaned up.
    neighbors: NeighborCache,
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
            recently_closed: Mutex::new(HashMap::new()),
            config,
            active_count: AtomicUsize::new(0),
            neighbors: NeighborCache::default(),
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
    ///
    /// Live callers should pass each packet's own capture timestamp too, not one
    /// clock read shared across a batch of packets. Handshake RTT is the
    /// difference between two packets' `now` values, so a shared timestamp
    /// collapses every round trip that completes within one batch to zero.
    pub fn ingest_at(&self, parsed: &ParsedPacket, now: SystemTime) -> IngestOutcome {
        // Harvest IP -> MAC mappings from ARP and NDP packets; only they pay
        // this cost.
        match &parsed.protocol_state {
            ProtocolState::Arp(arp_info) => self.neighbors.learn_from_arp(arp_info, now),
            ProtocolState::Icmp {
                ndp_neighbor: Some(neighbor),
                ..
            } => self.neighbors.learn_from_ndp(neighbor, now),
            _ => {}
        }

        let timings = self.measure_timings(parsed, now);

        // A read guard makes ordinary packet updates atomic with cleanup. The
        // uncommon generation-split path drops it and reacquires a write guard
        // so retained-source readers also see one consistent move.
        let lifecycle = self
            .lifecycle
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = self.resolve_connection_key(parsed);

        if !self.connections.contains_key(&key) && self.is_recent_late_packet(key, parsed, now) {
            return IngestOutcome {
                ignored_late: true,
                ..timings.outcome(key)
            };
        }

        let starts_new_generation = self
            .connections
            .get(&key)
            .is_some_and(|conn| Self::packet_starts_new_generation(&conn, parsed));
        if starts_new_generation {
            drop(lifecycle);
            return self.ingest_new_generation(parsed, now, key, timings);
        }

        self.ingest_into_active(parsed, now, key, timings)
    }

    /// Run this packet through the RTT tracker and collect any round trips it
    /// completed.
    fn measure_timings(&self, parsed: &ParsedPacket, now: SystemTime) -> PacketTimings {
        // Track RTT for TCP connections using SYN/SYN-ACK timing, and for QUIC
        // using the long-header handshake exchange. Everything QUIC sends after
        // the handshake is behind header protection, so this initial flight is
        // the only round trip an on-path observer can time.
        let mut measured_rtt: Option<Duration> = None;
        let mut dns_response_time: Option<Duration> = None;
        let mut netbios_response_time: Option<Duration> = None;
        let mut stun_rtt: Option<Duration> = None;
        let mut ntp_rtt: Option<Duration> = None;
        let base_key = parsed.connection_key();
        if parsed.protocol == Protocol::Tcp
            && let Some(tcp_header) = &parsed.tcp_header
        {
            if tcp_header.flags.syn && !tcp_header.flags.ack {
                if let Ok(mut tracker) = self.rtt.lock() {
                    tracker.record_syn(base_key, now);
                }
            } else if tcp_header.flags.syn
                && tcp_header.flags.ack
                && let Ok(mut tracker) = self.rtt.lock()
            {
                measured_rtt = tracker.record_syn_ack(&base_key, now);
            }
        } else if parsed.protocol == Protocol::Udp
            && let Some(dpi) = &parsed.dpi_result
            && udp_application_is_timed(&dpi.application)
            && let Ok(mut tracker) = self.rtt.lock()
        {
            // One lock acquisition covers every timed UDP application; a
            // packet carries one DPI result, so at most one arm runs.
            match &dpi.application {
                ApplicationProtocol::Quic(_) => {
                    measured_rtt = tracker.record_quic_handshake(base_key, parsed.is_outgoing, now);
                }
                // Time DNS query→response pairs by transaction ID. Port-53
                // gating already happened in DPI dispatch, so any Dns result
                // here is unicast DNS (mDNS/LLMNR map to their own variants).
                ApplicationProtocol::Dns(dns) => {
                    dns_response_time = tracker.record_dns_packet(
                        base_key,
                        dns.txid,
                        parsed.is_outgoing,
                        dns.is_response,
                        now,
                    );
                }
                // NetBIOS Name Service broadcasts are answered from a host's
                // unicast address, so the RTT tracker pairs on local socket,
                // service, and transaction ID rather than the full connection
                // key.
                ApplicationProtocol::NetBios(netbios) => {
                    let completed =
                        tracker.record_netbios_packet(base_key, netbios, parsed.is_outgoing, now);
                    if let Some((rtt, request_key)) = completed {
                        netbios_response_time = Some(rtt);
                        // A broadcast request and its unicast reply live under
                        // different keys. Stamp the requesting connection too,
                        // so the row showing the query also shows its round
                        // trip; this packet's own connection is updated in the
                        // ingest path below.
                        if request_key != base_key
                            && let Some(mut conn) = self.connections.get_mut(&request_key)
                        {
                            conn.netbios_response_time = Some(rtt);
                        }
                    }
                }
                // STUN requests and responses share a 96-bit transaction ID
                // that retransmits reuse, so request→response pairing is
                // exact.
                ApplicationProtocol::Stun(stun) => {
                    stun_rtt = tracker.record_stun(
                        base_key,
                        stun.transaction_id,
                        parsed.is_outgoing,
                        stun.message_class,
                        now,
                    );
                }
                // NTP servers echo the client's transmit timestamp as the
                // originate timestamp, pairing each poll with its response.
                ApplicationProtocol::Ntp(ntp) => {
                    ntp_rtt = tracker.record_ntp(base_key, ntp, parsed.is_outgoing, now);
                }
                _ => {}
            }
        }

        // ICMP echo requests reuse one identifier for the life of a ping
        // process, so sequence number is part of the key. That allows several
        // subsecond requests to be pending at once and replies to arrive out of
        // order without cross-pairing samples.
        let echo_metadata = match &parsed.protocol_state {
            ProtocolState::Icmp {
                icmp_type,
                icmp_id: Some(identifier),
                icmp_sequence: Some(sequence),
                ..
            } => match icmp_type {
                8 | 128 => Some((*identifier, *sequence, false)),
                0 | 129 => Some((*identifier, *sequence, true)),
                _ => None,
            },
            _ => None,
        };
        let mut icmp_echo_rtt: Option<Duration> = None;
        if let Some((identifier, sequence, is_reply)) = echo_metadata
            && let Ok(mut tracker) = self.rtt.lock()
        {
            // Loopback captures classify the reply as outgoing too (both
            // endpoints are local), so reclassify it as incoming to let it
            // match the pending request.
            let is_outgoing = parsed.is_outgoing
                && !(is_reply && parsed.local_addr.ip() == parsed.remote_addr.ip());
            icmp_echo_rtt = tracker.record_icmp_echo(
                base_key,
                (identifier, sequence),
                is_outgoing,
                is_reply,
                now,
            );
        }

        PacketTimings {
            measured_rtt,
            dns_response_time,
            netbios_response_time,
            icmp_echo_rtt,
            stun_rtt,
            ntp_rtt,
        }
    }

    fn ingest_into_active(
        &self,
        parsed: &ParsedPacket,
        now: SystemTime,
        key: ConnectionKey,
        timings: PacketTimings,
    ) -> IngestOutcome {
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
                dropped: true,
                ..timings.outcome(key)
            };
        }

        let mut created = false;
        let mut deltas = TcpMergeEvents::default();
        self.connections
            .entry(key)
            .and_modify(|conn| {
                deltas = merge_packet_into_connection(conn, parsed, now);
                apply_timings(conn, &timings);
            })
            .or_insert_with(|| {
                created = true;
                let mut conn = create_connection_from_packet(parsed, now);
                apply_timings(&mut conn, &timings);
                conn
            });
        if created {
            self.active_count.fetch_add(1, Ordering::Relaxed);
        }

        // Feed completed data round trips into the aggregate view, so the
        // average RTT reflects established connections rather than only the
        // handshakes of freshly opened ones.
        if let Some(rtt) = deltas.rtt_sample
            && let Ok(mut tracker) = self.rtt.lock()
        {
            tracker.record_data_rtt(rtt);
        }

        IngestOutcome {
            created,
            retransmits: deltas.retransmits,
            out_of_order: deltas.out_of_order,
            fast_retransmits: deltas.fast_retransmits,
            ..timings.outcome(key)
        }
    }

    fn ingest_new_generation(
        &self,
        parsed: &ParsedPacket,
        now: SystemTime,
        key: ConnectionKey,
        timings: PacketTimings,
    ) -> IngestOutcome {
        let _lifecycle = self
            .lifecycle
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut replacement_now = now;

        let still_needs_split = self
            .connections
            .get(&key)
            .is_some_and(|conn| Self::packet_starts_new_generation(&conn, parsed));
        let archived = if still_needs_split {
            self.connections.remove(&key).map(|(_, conn)| {
                // Historic keys include `created_at`, so two generations of
                // the same tuple must not share a creation timestamp. This is
                // possible when several captured packets use one batch time.
                if replacement_now <= conn.created_at {
                    replacement_now = conn
                        .created_at
                        .checked_add(Duration::from_nanos(1))
                        .unwrap_or(replacement_now);
                }
                self.active_count.fetch_sub(1, Ordering::Relaxed);
                self.archive_snapshot(key, &conn, now);
                self.record_recently_closed(key, &conn, now);
                self.remove_quic_mappings_for_key(key);
                conn
            })
        } else {
            None
        };

        // Cleanup may have removed the old generation while this packet was
        // waiting to acquire the write guard. Reassociate any visible QUIC ID
        // before creating the replacement.
        self.associate_quic_id(parsed, key);
        let mut outcome = self.ingest_into_active(parsed, replacement_now, key, timings);
        outcome.archived = archived;
        self.enforce_historic_limit();
        self.prune_recently_closed(now);
        outcome
    }

    fn resolve_connection_key(&self, parsed: &ParsedPacket) -> ConnectionKey {
        let mut key = parsed.connection_key();
        let Some(conn_id_hex) = Self::parsed_quic_id(parsed) else {
            return key;
        };
        let Ok(mut mapping) = self.quic_map.lock() else {
            return key;
        };
        if let Some(existing_key) = mapping.get(conn_id_hex) {
            key = *existing_key;
        } else {
            if mapping.len() >= self.config.max_quic_mappings {
                mapping.clear();
            }
            mapping.insert(conn_id_hex.to_string(), key);
        }
        key
    }

    fn parsed_quic_id(parsed: &ParsedPacket) -> Option<&str> {
        let dpi = parsed.dpi_result.as_ref()?;
        let ApplicationProtocol::Quic(quic) = &dpi.application else {
            return None;
        };
        quic.connection_id_hex.as_deref()
    }

    fn associate_quic_id(&self, parsed: &ParsedPacket, key: ConnectionKey) {
        let Some(conn_id_hex) = Self::parsed_quic_id(parsed) else {
            return;
        };
        if let Ok(mut mapping) = self.quic_map.lock() {
            if mapping.len() >= self.config.max_quic_mappings {
                mapping.clear();
            }
            mapping.insert(conn_id_hex.to_string(), key);
        }
    }

    fn packet_starts_new_generation(conn: &Connection, parsed: &ParsedPacket) -> bool {
        if !conn.is_closing_or_terminal() {
            return false;
        }
        match parsed.protocol {
            Protocol::Tcp => parsed
                .tcp_header
                .as_ref()
                .is_some_and(|header| header.flags.syn),
            Protocol::Udp => {
                let Some(new_id) = Self::parsed_quic_id(parsed) else {
                    return false;
                };
                let Some(dpi) = conn.dpi_info.as_ref() else {
                    return false;
                };
                let ApplicationProtocol::Quic(old_quic) = &dpi.application else {
                    return false;
                };
                old_quic
                    .connection_id_hex
                    .as_deref()
                    .is_some_and(|old_id| old_id != new_id)
            }
            _ => false,
        }
    }

    fn is_recent_late_packet(
        &self,
        key: ConnectionKey,
        parsed: &ParsedPacket,
        now: SystemTime,
    ) -> bool {
        if parsed.protocol != Protocol::Tcp {
            return false;
        }
        let Some(header) = parsed.tcp_header.as_ref() else {
            return false;
        };
        let is_teardown_only = !header.flags.syn
            && (header.flags.fin
                || header.flags.rst
                || (header.flags.ack && header.payload_len == 0));
        if !is_teardown_only {
            return false;
        }
        self.recently_closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .is_some_and(|closed_at| {
                now.duration_since(*closed_at).unwrap_or_default() <= RECENTLY_CLOSED_TTL
            })
    }

    fn archive_snapshot(&self, key: ConnectionKey, conn: &Connection, now: SystemTime) {
        if !self.config.keep_historic {
            return;
        }
        let mut historic = conn.snapshot_clone();
        historic.is_historic = true;
        historic.closed_at = Some(now);
        let historic_key = HistoricKey {
            key,
            created_nanos: conn
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        };
        self.historic.insert(historic_key, historic);
    }

    fn enforce_historic_limit(&self) {
        if self.historic.len() <= self.config.max_historic {
            return;
        }
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

    fn record_recently_closed(&self, key: ConnectionKey, conn: &Connection, now: SystemTime) {
        if !conn.is_terminal() {
            return;
        }
        self.recently_closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, now);
    }

    fn prune_recently_closed(&self, now: SystemTime) {
        let mut recently_closed = self
            .recently_closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        recently_closed.retain(|_, closed_at| {
            now.duration_since(*closed_at).unwrap_or_default() <= RECENTLY_CLOSED_TTL
        });
        let max_entries = self.config.max_historic.max(RECENTLY_CLOSED_MIN_ENTRIES);
        if recently_closed.len() > max_entries {
            let mut entries: Vec<(ConnectionKey, SystemTime)> = recently_closed
                .iter()
                .map(|(key, closed_at)| (*key, *closed_at))
                .collect();
            entries.sort_by_key(|(_, closed_at)| *closed_at);
            let to_remove = recently_closed.len() - max_entries;
            for (key, _) in entries.into_iter().take(to_remove) {
                recently_closed.remove(&key);
            }
        }
    }

    fn remove_quic_mappings_for_key(&self, key: ConnectionKey) {
        if let Ok(mut mapping) = self.quic_map.lock() {
            mapping.retain(|_, conn_key| *conn_key != key);
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
                    // Cached rates describe live traffic. Carrying them into a
                    // closed record makes Overview and Details report traffic
                    // that can no longer occur, and leaves a moving fallback
                    // point after the live rate history is retired.
                    historic.current_incoming_rate_bps = 0.0;
                    historic.current_outgoing_rate_bps = 0.0;
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
            for (key, conn) in removed_keys.iter().zip(&removed) {
                self.record_recently_closed(*key, conn, now);
            }
        }

        if keep_historic {
            for (key, conn) in to_archive {
                self.historic.insert(key, conn);
            }

            self.enforce_historic_limit();
        }

        // Clean up QUIC connection-ID mappings pointing at removed connections.
        if !removed_keys.is_empty()
            && let Ok(mut mapping) = self.quic_map.lock()
        {
            mapping.retain(|_, conn_key| !removed_keys.contains(conn_key));
        }
        self.prune_recently_closed(now);

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

    /// Drop all active and historic connections and reset RTT/QUIC state and
    /// the learned-neighbor cache.
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
        self.recently_closed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.neighbors.clear();
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

    /// The ARP/NDP-learned MAC/vendor mapping for `ip`, if one has been
    /// observed.
    pub fn neighbor(&self, ip: &std::net::IpAddr) -> Option<NeighborEntry> {
        self.neighbors.get(ip)
    }

    /// Average network RTT (in milliseconds) over the last `window_secs`
    /// seconds of handshake, TCP data, and ICMP echo samples. `None` if no
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
    use crate::network::types::NetBiosOpcode;

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

    fn tcp_packet(syn: bool, ack: bool, fin: bool, rst: bool, is_outgoing: bool) -> ParsedPacket {
        use crate::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 40_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 443),
            TcpHeaderInfo {
                seq: 1_000,
                ack: 2_000,
                window: 65_535,
                flags: TcpFlags { syn, ack, fin, rst },
                payload_len: 0,
            },
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 60;
        packet
    }

    fn quic_packet(packet_type: QuicPacketType, is_outgoing: bool) -> ParsedPacket {
        use crate::network::types::QuicInfo;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut quic = QuicInfo::new(1);
        quic.packet_type = packet_type;

        let mut packet = ParsedPacket::test_udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 40_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 443),
            ApplicationProtocol::Quic(Box::new(quic)),
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 1_200;
        packet
    }

    fn dns_packet(txid: u16, is_outgoing: bool, is_response: bool, rcode: u8) -> ParsedPacket {
        use crate::network::types::{DnsInfo, DnsQueryType};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 40_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)), 53),
            ApplicationProtocol::Dns(DnsInfo {
                query_name: Some("example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_ips: Vec::new(),
                is_response,
                txid,
                rcode: is_response.then_some(rcode),
                nodata: None,
            }),
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 80;
        packet
    }

    fn netbios_packet(
        transaction_id: u16,
        is_outgoing: bool,
        opcode: NetBiosOpcode,
        is_response: bool,
        remote_ip: [u8; 4],
    ) -> ParsedPacket {
        use crate::network::types::{AddrKind, NetBiosInfo, NetBiosResponseStatus, NetBiosService};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 137),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(remote_ip)), 137),
            ApplicationProtocol::NetBios(NetBiosInfo {
                service: NetBiosService::NameService,
                opcode,
                name: Some("FILESERVER".to_string()),
                transaction_id,
                is_response,
                response_status: is_response.then_some(NetBiosResponseStatus::NameService(0)),
            }),
        );
        if remote_ip == [255, 255, 255, 255] {
            packet.remote_addr_kind = AddrKind::Broadcast;
        }
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 80;
        packet
    }

    fn icmp_echo_packet(
        identifier: u16,
        sequence: u16,
        is_outgoing: bool,
        is_reply: bool,
    ) -> ParsedPacket {
        use crate::network::types::ProtocolState;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_base(
            Protocol::Icmp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0),
            ProtocolState::Icmp {
                icmp_type: if is_reply { 0 } else { 8 },
                icmp_id: Some(identifier),
                icmp_sequence: Some(sequence),
                ndp_neighbor: None,
            },
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 84;
        packet
    }

    /// Capture time for a packet `millis` into a synthetic trace. Tests drive
    /// `ingest_at` with these rather than the wall clock so an RTT assertion
    /// pins a real duration instead of however long the test loop took.
    fn capture_time(millis: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_millis(millis)
    }

    fn arp_packet(operation: crate::network::types::ArpOperation) -> ParsedPacket {
        use crate::network::types::{ArpInfo, ProtocolState};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_base(
            Protocol::Arp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 132)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 0),
            ProtocolState::Arp(ArpInfo {
                operation,
                sender_mac: "04:d9:f5:c5:ed:e8".to_string(),
                sender_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                target_mac: "68:5e:dd:09:15:5e".to_string(),
                target_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 132)),
                sender_vendor: Some("ASUSTek COMPUTER INC.".to_string()),
                target_vendor: Some("Apple, Inc.".to_string()),
            }),
        );
        packet.packet_len = 42;
        packet
    }

    /// Ingesting an ARP reply must populate the neighbor cache for both the
    /// answering host and the requester, and the mapping must outlive the ARP
    /// connection row itself.
    #[test]
    fn arp_ingest_learns_neighbors() {
        use crate::network::types::ArpOperation;
        use std::net::{IpAddr, Ipv4Addr};

        let tracker = ConnectionTracker::new();
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let laptop = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 132));
        assert!(tracker.neighbor(&gateway).is_none());

        let outcome = tracker.ingest_at(&arp_packet(ArpOperation::Reply), capture_time(0));

        let entry = tracker.neighbor(&gateway).expect("gateway learned");
        assert_eq!(entry.mac, "04:d9:f5:c5:ed:e8");
        assert_eq!(entry.vendor.as_deref(), Some("ASUSTek COMPUTER INC."));
        assert_eq!(
            tracker.neighbor(&laptop).expect("requester learned").mac,
            "68:5e:dd:09:15:5e"
        );

        // The mapping survives removal of the ARP connection entry.
        tracker.connections().remove(&outcome.key);
        assert!(tracker.neighbor(&gateway).is_some());
    }

    /// A full Ethernet+IPv6 frame carrying an NDP neighbor advertisement,
    /// so the test exercises the parser's hop-limit gate end to end.
    fn ndp_advertisement_frame(hop_limit: u8) -> Vec<u8> {
        let mut f = Vec::new();
        // Ethernet header: dst mac, src mac, ethertype IPv6 (0x86dd)
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x86, 0xdd]);
        // IPv6 header (40 bytes)
        f.extend_from_slice(&[0x60, 0, 0, 0]); // version/tc/flow
        f.extend_from_slice(&32u16.to_be_bytes()); // payload length
        f.push(58); // next header = ICMPv6
        f.push(hop_limit);
        let src: std::net::Ipv6Addr = "fe80::cafe".parse().unwrap();
        let dst: std::net::Ipv6Addr = "ff02::1".parse().unwrap();
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        // ICMPv6 neighbor advertisement: header, target address, then the
        // target link-layer address option.
        f.extend_from_slice(&[136, 0, 0, 0, 0x20, 0, 0, 0]); // override flag
        let target: std::net::Ipv6Addr = "2001:db8::10".parse().unwrap();
        f.extend_from_slice(&target.octets());
        f.extend_from_slice(&[2, 1, 0x68, 0x5e, 0xdd, 0x09, 0x15, 0x5e]);
        f
    }

    /// Ingesting an NDP neighbor advertisement must populate the neighbor
    /// cache for the advertised target address — but only when the frame
    /// arrived with hop limit 255, which proves it was not routed (RFC 4861).
    #[test]
    fn ndp_ingest_learns_advertised_target_at_hop_limit_255_only() {
        let target: std::net::IpAddr = "2001:db8::10".parse().unwrap();

        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&parse(&ndp_advertisement_frame(255)), capture_time(0));
        assert_eq!(
            tracker.neighbor(&target).expect("target learned").mac,
            "68:5e:dd:09:15:5e"
        );

        let routed = ConnectionTracker::new();
        routed.ingest_at(&parse(&ndp_advertisement_frame(64)), capture_time(0));
        assert!(routed.neighbor(&target).is_none());
    }

    /// QUIC's handshake is the only round trip an on-path observer can time,
    /// so the client Initial and the server's reply must pair up into the
    /// connection's initial RTT the way SYN/SYN-ACK does for TCP.
    ///
    /// The RTT must come from the packets' capture timestamps. Capture hands
    /// packets to processing in batches spanning up to 100 packets or 100ms, so
    /// a handshake this quick is processed as one microseconds-wide burst; a
    /// tracker that read its own clock would report 0.0ms here.
    #[test]
    fn quic_handshake_exchange_measures_initial_rtt() {
        let tracker = ConnectionTracker::new();

        let client_initial =
            tracker.ingest_at(&quic_packet(QuicPacketType::Initial, true), capture_time(0));
        assert!(
            client_initial.measured_rtt.is_none(),
            "the opening Initial has nothing to pair with yet"
        );

        let server_initial = tracker.ingest_at(
            &quic_packet(QuicPacketType::Initial, false),
            capture_time(18),
        );
        assert_eq!(
            server_initial.measured_rtt,
            Some(Duration::from_millis(18)),
            "the RTT is the gap between the two capture timestamps"
        );
        assert_eq!(
            tracker
                .connections()
                .get(&server_initial.key)
                .and_then(|conn| conn.initial_rtt),
            Some(Duration::from_millis(18)),
            "the measured RTT should land on the connection"
        );
    }

    /// A repeated client Initial is a retransmission, not a reply, so it must
    /// not be read as a completed round trip.
    #[test]
    fn repeated_quic_initial_in_one_direction_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&quic_packet(QuicPacketType::Initial, true), capture_time(0));
        let retransmit = tracker.ingest_at(
            &quic_packet(QuicPacketType::Initial, true),
            capture_time(250),
        );
        assert!(retransmit.measured_rtt.is_none());
        assert!(
            tracker
                .connections()
                .get(&retransmit.key)
                .and_then(|conn| conn.initial_rtt)
                .is_none()
        );
    }

    /// rustnet watches from an endpoint, so an arriving packet followed by this
    /// host's own answer spans no network at all — it times the local stack's
    /// turnaround. Only an outbound packet may start the clock.
    ///
    /// A server's first flight is several datagrams, so this ordering shows up
    /// on ordinary connections once the first datagram has been paired off.
    #[test]
    fn inbound_quic_handshake_packet_does_not_start_the_clock() {
        let tracker = ConnectionTracker::new();

        tracker.ingest_at(
            &quic_packet(QuicPacketType::Handshake, false),
            capture_time(0),
        );
        let local_reply = tracker.ingest_at(
            &quic_packet(QuicPacketType::Handshake, true),
            capture_time(1),
        );
        assert!(
            local_reply.measured_rtt.is_none(),
            "this host's own turnaround is not a round trip"
        );
        assert!(
            tracker
                .connections()
                .get(&local_reply.key)
                .and_then(|conn| conn.initial_rtt)
                .is_none()
        );
    }

    /// Once the client Initial has been paired with the server's first
    /// datagram, the rest of the server's flight must not overwrite the real
    /// measurement with a local-turnaround one.
    #[test]
    fn later_server_flight_does_not_replace_the_handshake_rtt() {
        let tracker = ConnectionTracker::new();

        tracker.ingest_at(&quic_packet(QuicPacketType::Initial, true), capture_time(0));
        tracker.ingest_at(
            &quic_packet(QuicPacketType::Initial, false),
            capture_time(18),
        );

        // Remainder of the server's first flight, then this host's ACK.
        tracker.ingest_at(
            &quic_packet(QuicPacketType::Handshake, false),
            capture_time(19),
        );
        let ack = tracker.ingest_at(
            &quic_packet(QuicPacketType::Handshake, true),
            capture_time(19),
        );
        assert!(ack.measured_rtt.is_none());

        assert_eq!(
            tracker
                .connections()
                .get(&ack.key)
                .and_then(|conn| conn.initial_rtt),
            Some(Duration::from_millis(18))
        );
    }

    /// A DNS response pairs with its query by transaction ID, and the delta
    /// between the two capture timestamps lands on the connection. The
    /// transport-level `initial_rtt` must stay untouched: DNS time includes
    /// resolver processing.
    #[test]
    fn dns_query_response_measures_response_time() {
        let tracker = ConnectionTracker::new();

        let query = tracker.ingest_at(&dns_packet(0x1234, true, false, 0), capture_time(0));
        assert!(query.dns_response_time.is_none());

        let response = tracker.ingest_at(&dns_packet(0x1234, false, true, 0), capture_time(35));
        assert_eq!(
            response.dns_response_time,
            Some(Duration::from_millis(35)),
            "the response time is the gap between the two capture timestamps"
        );
        let conn = tracker.connections().get(&response.key).unwrap().clone();
        assert_eq!(conn.dns_response_time, Some(Duration::from_millis(35)));
        assert!(
            conn.initial_rtt.is_none(),
            "DNS timing must not pollute the transport RTT"
        );
    }

    /// A response whose transaction ID matches no pending query (spoofed,
    /// expired, or captured mid-exchange) measures nothing.
    #[test]
    fn dns_response_with_unknown_txid_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&dns_packet(0x1234, true, false, 0), capture_time(0));
        let response = tracker.ingest_at(&dns_packet(0x9999, false, true, 0), capture_time(20));
        assert!(response.dns_response_time.is_none());
        assert!(
            tracker
                .connections()
                .get(&response.key)
                .and_then(|conn| conn.dns_response_time)
                .is_none()
        );
    }

    /// Stub resolvers reuse one socket for many queries, so each completed
    /// exchange refreshes the connection's response time (last wins, unlike
    /// the one-shot `initial_rtt`).
    #[test]
    fn later_dns_exchange_updates_the_response_time() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&dns_packet(1, true, false, 0), capture_time(0));
        tracker.ingest_at(&dns_packet(1, false, true, 0), capture_time(35));
        tracker.ingest_at(&dns_packet(2, true, false, 0), capture_time(1_000));
        let second = tracker.ingest_at(&dns_packet(2, false, true, 0), capture_time(1_012));
        assert_eq!(second.dns_response_time, Some(Duration::from_millis(12)));
        assert_eq!(
            tracker
                .connections()
                .get(&second.key)
                .and_then(|conn| conn.dns_response_time),
            Some(Duration::from_millis(12))
        );
    }

    /// When the local host is the DNS server, the inbound query followed by
    /// our own answer times the local resolver's turnaround, not the network,
    /// so it must measure nothing (mirrors the QUIC direction rule).
    #[test]
    fn local_dns_server_role_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&dns_packet(0x1234, false, false, 0), capture_time(0));
        let reply = tracker.ingest_at(&dns_packet(0x1234, true, true, 0), capture_time(1));
        assert!(reply.dns_response_time.is_none());
    }

    /// A re-sent query restarts the timer from the most recent send, so the
    /// measurement reflects the answered attempt, not the retry wait.
    #[test]
    fn retransmitted_dns_query_measures_from_the_last_send() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&dns_packet(0x1234, true, false, 0), capture_time(0));
        tracker.ingest_at(&dns_packet(0x1234, true, false, 0), capture_time(1_000));
        let response = tracker.ingest_at(&dns_packet(0x1234, false, true, 0), capture_time(1_018));
        assert_eq!(response.dns_response_time, Some(Duration::from_millis(18)));
    }

    /// SERVFAIL is still an answer: the round trip completed, so it is a valid
    /// timing sample. The response code is surfaced separately in the UI.
    #[test]
    fn dns_servfail_response_still_measures_response_time() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&dns_packet(0x1234, true, false, 0), capture_time(0));
        let response = tracker.ingest_at(&dns_packet(0x1234, false, true, 2), capture_time(40));
        assert_eq!(response.dns_response_time, Some(Duration::from_millis(40)));
    }

    /// Name Service requests are normally broadcast, then answered from a
    /// host's unicast address. The transaction still pairs even though the
    /// request and response belong to different connection-table keys.
    #[test]
    fn netbios_broadcast_request_measures_unicast_response_time() {
        let tracker = ConnectionTracker::new();
        let query = tracker.ingest_at(
            &netbios_packet(
                0x1234,
                true,
                NetBiosOpcode::Query,
                false,
                [255, 255, 255, 255],
            ),
            capture_time(0),
        );
        assert!(query.netbios_response_time.is_none());

        let response = tracker.ingest_at(
            &netbios_packet(
                0x1234,
                false,
                NetBiosOpcode::Response,
                true,
                [192, 168, 0, 20],
            ),
            capture_time(27),
        );
        assert_ne!(query.key, response.key);
        assert_eq!(
            response.netbios_response_time,
            Some(Duration::from_millis(27))
        );
        let conn = tracker.connections().get(&response.key).unwrap().clone();
        assert_eq!(conn.netbios_response_time, Some(Duration::from_millis(27)));
        assert!(conn.initial_rtt.is_none());

        // The broadcast row is the one a user naturally inspects, so the
        // round trip must land there as well, not only on the responder.
        let query_conn = tracker.connections().get(&query.key).unwrap().clone();
        assert_eq!(
            query_conn.netbios_response_time,
            Some(Duration::from_millis(27))
        );
    }

    #[test]
    fn netbios_response_with_unknown_transaction_id_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(
            &netbios_packet(
                0x1234,
                true,
                NetBiosOpcode::Query,
                false,
                [255, 255, 255, 255],
            ),
            capture_time(0),
        );
        let response = tracker.ingest_at(
            &netbios_packet(
                0x9999,
                false,
                NetBiosOpcode::Response,
                true,
                [192, 168, 0, 20],
            ),
            capture_time(27),
        );
        assert!(response.netbios_response_time.is_none());
    }

    /// A WACK extends an NBNS transaction and must not consume its pending
    /// request. The eventual final response completes the original timing.
    #[test]
    fn netbios_wack_keeps_request_pending() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(
            &netbios_packet(
                0x1234,
                true,
                NetBiosOpcode::Registration,
                false,
                [192, 168, 0, 2],
            ),
            capture_time(0),
        );
        let wack = tracker.ingest_at(
            &netbios_packet(0x1234, false, NetBiosOpcode::Wack, false, [192, 168, 0, 2]),
            capture_time(10),
        );
        assert!(wack.netbios_response_time.is_none());

        let response = tracker.ingest_at(
            &netbios_packet(
                0x1234,
                false,
                NetBiosOpcode::Response,
                true,
                [192, 168, 0, 2],
            ),
            capture_time(40),
        );
        assert_eq!(
            response.netbios_response_time,
            Some(Duration::from_millis(40))
        );
    }

    /// Subsecond ping intervals can leave several requests outstanding. The
    /// sequence number keeps each reply attached to its own send timestamp,
    /// even when replies complete out of order.
    #[test]
    fn fast_ping_pairs_each_echo_by_identifier_and_sequence() {
        let tracker = ConnectionTracker::new();

        tracker.ingest_at(&icmp_echo_packet(0x1234, 1, true, false), capture_time(0));
        tracker.ingest_at(&icmp_echo_packet(0x1234, 2, true, false), capture_time(200));
        let second_reply =
            tracker.ingest_at(&icmp_echo_packet(0x1234, 2, false, true), capture_time(225));
        let first_reply =
            tracker.ingest_at(&icmp_echo_packet(0x1234, 1, false, true), capture_time(350));

        assert_eq!(second_reply.icmp_echo_rtt, Some(Duration::from_millis(25)));
        assert_eq!(first_reply.icmp_echo_rtt, Some(Duration::from_millis(350)));

        tracker.ingest_at(&icmp_echo_packet(0x1234, 3, true, false), capture_time(400));
        let third_reply =
            tracker.ingest_at(&icmp_echo_packet(0x1234, 3, false, true), capture_time(418));
        let conn = tracker
            .connections()
            .get(&third_reply.key)
            .expect("ping connection should exist")
            .clone();
        assert_eq!(third_reply.icmp_echo_rtt, Some(Duration::from_millis(18)));
        assert_eq!(conn.icmp_echo_rtt, Some(Duration::from_millis(18)));
        assert_eq!(conn.current_rtt(), Some(Duration::from_millis(18)));
    }

    #[test]
    fn echo_reply_with_unknown_sequence_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&icmp_echo_packet(7, 10, true, false), capture_time(0));
        let reply = tracker.ingest_at(&icmp_echo_packet(7, 11, false, true), capture_time(12));

        assert!(reply.icmp_echo_rtt.is_none());
        assert!(
            tracker
                .connections()
                .get(&reply.key)
                .and_then(|conn| conn.icmp_echo_rtt)
                .is_none()
        );
    }

    #[test]
    fn local_echo_responder_turnaround_measures_nothing() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&icmp_echo_packet(7, 1, false, false), capture_time(0));
        let reply = tracker.ingest_at(&icmp_echo_packet(7, 1, true, true), capture_time(1));

        assert!(reply.icmp_echo_rtt.is_none());
    }

    fn loopback_echo_packet(identifier: u16, sequence: u16, is_reply: bool) -> ParsedPacket {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = icmp_echo_packet(identifier, sequence, true, is_reply);
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        packet.local_addr = loopback;
        packet.remote_addr = loopback;
        packet
    }

    /// Loopback captures classify both the request and its reply as outgoing
    /// because both endpoints are local. The reply must still pair up.
    #[test]
    fn loopback_ping_measures_rtt() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&loopback_echo_packet(9, 1, false), capture_time(0));
        let reply = tracker.ingest_at(&loopback_echo_packet(9, 1, true), capture_time(1));

        assert_eq!(reply.icmp_echo_rtt, Some(Duration::from_millis(1)));
    }

    /// Echo requests reveal who initiated the flow; the Details tab uses the
    /// direction to hide the RTT row on flows this host only answers.
    #[test]
    fn echo_request_sets_connection_direction() {
        let tracker = ConnectionTracker::new();
        let outgoing = tracker.ingest_at(&icmp_echo_packet(7, 1, true, false), capture_time(0));
        let direction = tracker
            .connections()
            .get(&outgoing.key)
            .and_then(|conn| conn.connection_direction);
        assert_eq!(direction, Some(true));

        let tracker = ConnectionTracker::new();
        let inbound = tracker.ingest_at(&icmp_echo_packet(7, 1, false, false), capture_time(0));
        tracker.ingest_at(&icmp_echo_packet(7, 1, true, true), capture_time(1));
        let direction = tracker
            .connections()
            .get(&inbound.key)
            .and_then(|conn| conn.connection_direction);
        assert_eq!(direction, Some(false), "our reply must not flip it");
    }

    fn stun_packet(
        transaction_id: [u8; 12],
        is_outgoing: bool,
        class: crate::network::types::StunMessageClass,
    ) -> ParsedPacket {
        use crate::network::types::{StunInfo, StunMethod};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 54_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 3478),
            ApplicationProtocol::Stun(StunInfo {
                message_class: class,
                method: StunMethod::Binding,
                transaction_id,
                software: None,
            }),
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 48;
        packet
    }

    /// STUN binding requests and responses pair by transaction ID, giving a
    /// UDP flow with no handshake a real request→response time.
    #[test]
    fn stun_binding_response_measures_rtt() {
        use crate::network::types::StunMessageClass;

        let tracker = ConnectionTracker::new();
        let txid = [3u8; 12];
        tracker.ingest_at(
            &stun_packet(txid, true, StunMessageClass::Request),
            capture_time(0),
        );
        let response = tracker.ingest_at(
            &stun_packet(txid, false, StunMessageClass::SuccessResponse),
            capture_time(31),
        );

        assert_eq!(response.stun_rtt, Some(Duration::from_millis(31)));
        let conn = tracker
            .connections()
            .get(&response.key)
            .expect("stun connection should exist")
            .clone();
        assert_eq!(conn.stun_rtt, Some(Duration::from_millis(31)));
    }

    fn ntp_packet(
        mode: crate::network::types::NtpMode,
        is_outgoing: bool,
        origin_timestamp: u64,
        transmit_timestamp: u64,
    ) -> ParsedPacket {
        use crate::network::types::NtpInfo;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut packet = ParsedPacket::test_udp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 47_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 123),
            ApplicationProtocol::Ntp(NtpInfo {
                version: 4,
                mode,
                stratum: 2,
                origin_timestamp,
                transmit_timestamp,
            }),
        );
        packet.is_outgoing = is_outgoing;
        packet.packet_len = 90;
        packet
    }

    /// An NTP poll pairs with its response through the originate timestamp
    /// echo, giving the UDP flow a request→response time.
    #[test]
    fn ntp_server_response_measures_rtt() {
        use crate::network::types::NtpMode;

        let tracker = ConnectionTracker::new();
        tracker.ingest_at(
            &ntp_packet(NtpMode::Client, true, 0, 0xAABB),
            capture_time(0),
        );
        let response = tracker.ingest_at(
            &ntp_packet(NtpMode::Server, false, 0xAABB, 0xCCDD),
            capture_time(21),
        );

        assert_eq!(response.ntp_rtt, Some(Duration::from_millis(21)));
        let conn = tracker
            .connections()
            .get(&response.key)
            .expect("ntp connection should exist")
            .clone();
        assert_eq!(conn.ntp_rtt, Some(Duration::from_millis(21)));
    }

    #[test]
    fn stun_response_with_unknown_transaction_measures_nothing() {
        use crate::network::types::StunMessageClass;

        let tracker = ConnectionTracker::new();
        tracker.ingest_at(
            &stun_packet([3u8; 12], true, StunMessageClass::Request),
            capture_time(0),
        );
        let response = tracker.ingest_at(
            &stun_packet([4u8; 12], false, StunMessageClass::SuccessResponse),
            capture_time(31),
        );

        assert!(response.stun_rtt.is_none());
    }

    /// 1-RTT packets carry a short header with nothing timeable in the clear.
    #[test]
    fn quic_one_rtt_packets_do_not_measure_rtt() {
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&quic_packet(QuicPacketType::OneRtt, true), capture_time(0));
        let inbound = tracker.ingest_at(
            &quic_packet(QuicPacketType::OneRtt, false),
            capture_time(18),
        );
        assert!(inbound.measured_rtt.is_none());
    }

    /// The TCP handshake is timed from capture timestamps for the same reason
    /// the QUIC one is: SYN and SYN-ACK routinely land in a single batch.
    #[test]
    fn tcp_handshake_rtt_comes_from_capture_timestamps() {
        let tracker = ConnectionTracker::new();

        tracker.ingest_at(
            &tcp_packet(true, false, false, false, true),
            capture_time(0),
        );
        let syn_ack = tracker.ingest_at(
            &tcp_packet(true, true, false, false, false),
            capture_time(12),
        );
        assert_eq!(syn_ack.measured_rtt, Some(Duration::from_millis(12)));
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

        for mut entry in tracker.connections().iter_mut() {
            entry.current_incoming_rate_bps = 2048.0;
            entry.current_outgoing_rate_bps = 1024.0;
        }

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
        let historic = tracker.historic().iter().next().unwrap();
        assert_eq!(historic.current_incoming_rate_bps, 0.0);
        assert_eq!(historic.current_outgoing_rate_bps, 0.0);
    }

    #[test]
    fn traffic_refreshes_a_stale_nonterminal_connection() {
        let tracker = ConnectionTracker::new();
        let packet = parse(&udp_frame(40000, 9999));
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&packet, started);

        assert!(
            tracker
                .cleanup(started + Duration::from_secs(59))
                .is_empty()
        );
        tracker.ingest_at(&packet, started + Duration::from_secs(59));
        assert!(
            tracker
                .cleanup(started + Duration::from_secs(61))
                .is_empty()
        );
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn terminal_retransmissions_do_not_postpone_archival() {
        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, false, false, true, true), started);
        tracker.ingest_at(
            &tcp_packet(false, true, false, false, false),
            started + Duration::from_secs(10),
        );

        let conn = tracker.connections().iter().next().unwrap();
        assert_eq!(conn.last_activity, started + Duration::from_secs(10));
        assert_eq!(conn.terminal_since, Some(started));
        drop(conn);

        let removed = tracker.cleanup(started + Duration::from_secs(16));
        assert_eq!(removed.len(), 1);
        assert_eq!(tracker.historic_len(), 1);
    }

    #[test]
    fn syn_after_terminal_state_starts_a_new_generation() {
        use crate::network::types::{ProtocolState, TcpState};

        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, false, false, true, true), started);

        let outcome = tracker.ingest_at(&tcp_packet(true, false, false, false, true), started);
        assert!(outcome.created);
        assert!(outcome.archived.is_some());
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.historic_len(), 1);

        let active = tracker.connections().iter().next().unwrap();
        assert_eq!(
            active.created_at,
            started + Duration::from_nanos(1),
            "a same-batch replacement needs a distinct historic identity"
        );
        assert!(matches!(
            active.protocol_state,
            ProtocolState::Tcp(TcpState::SynSent)
        ));
        assert!(!active.is_historic);
        drop(active);

        let historic = tracker.historic().iter().next().unwrap();
        assert_eq!(historic.created_at, started);
        assert!(historic.is_historic);
        assert_eq!(historic.closed_at, Some(started));
        drop(historic);

        tracker.cleanup(started + Duration::from_secs(61));
        assert_eq!(
            tracker.historic_len(),
            2,
            "archiving the replacement must not overwrite the old generation"
        );
    }

    #[test]
    fn delayed_ack_after_archival_is_not_a_phantom_connection() {
        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, false, false, true, true), started);
        tracker.cleanup(started + Duration::from_secs(16));

        let outcome = tracker.ingest_at(
            &tcp_packet(false, true, false, false, false),
            started + Duration::from_secs(17),
        );
        assert!(outcome.ignored_late);
        assert!(!outcome.created);
        assert!(tracker.is_empty());
        assert_eq!(tracker.historic_len(), 1);
    }

    #[test]
    fn payload_after_terminal_archival_starts_a_new_generation() {
        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, false, false, true, true), started);
        tracker.cleanup(started + Duration::from_secs(16));

        let mut packet = tcp_packet(false, true, false, false, false);
        packet.tcp_header.as_mut().unwrap().payload_len = 100;
        let outcome = tracker.ingest_at(&packet, started + Duration::from_secs(17));

        assert!(!outcome.ignored_late);
        assert!(outcome.created);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.historic_len(), 1);
    }

    #[test]
    fn traffic_after_idle_archival_starts_a_new_generation_immediately() {
        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, true, false, false, true), started);
        tracker.cleanup(started + Duration::from_secs(301));

        let outcome = tracker.ingest_at(
            &tcp_packet(false, true, false, false, false),
            started + Duration::from_secs(302),
        );
        assert!(!outcome.ignored_late);
        assert!(outcome.created);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.historic_len(), 1);
    }

    #[test]
    fn midstream_ack_is_allowed_after_recent_tombstone_expires() {
        use crate::network::types::{ProtocolState, TcpState};

        let tracker = ConnectionTracker::new();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&tcp_packet(false, false, false, true, true), started);
        tracker.cleanup(started + Duration::from_secs(16));

        let outcome = tracker.ingest_at(
            &tcp_packet(false, true, false, false, false),
            started + Duration::from_secs(47),
        );
        assert!(!outcome.ignored_late);
        assert!(outcome.created);
        let active = tracker.connections().iter().next().unwrap();
        assert!(matches!(
            active.protocol_state,
            ProtocolState::Tcp(TcpState::Established)
        ));
    }

    #[test]
    fn new_activity_does_not_mutate_a_historic_snapshot() {
        let tracker = ConnectionTracker::new();
        let packet = parse(&udp_frame(40000, 9999));
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        tracker.ingest_at(&packet, started);
        tracker.cleanup(started + Duration::from_secs(61));

        let historic_before = tracker.historic_snapshot().pop().unwrap();
        tracker.ingest_at(&packet, started + Duration::from_secs(62));
        tracker.ingest_at(&packet, started + Duration::from_secs(63));
        let historic_after = tracker.historic_snapshot().pop().unwrap();

        assert_eq!(historic_after.bytes_sent, historic_before.bytes_sent);
        assert_eq!(
            historic_after.bytes_received,
            historic_before.bytes_received
        );
        assert_eq!(historic_after.last_activity, historic_before.last_activity);
        assert_eq!(historic_after.closed_at, historic_before.closed_at);
        assert_eq!(tracker.len(), 1);
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

    /// `max_historic` sizes the user-facing archive; it must not shrink the
    /// tombstone table below the floor, or closing more flows than the cap
    /// lets delayed teardown packets resurrect phantom connections.
    #[test]
    fn zero_max_historic_keeps_tombstones_for_all_closed_flows() {
        let tracker = ConnectionTracker::with_config(TrackerConfig {
            keep_historic: false,
            max_historic: 0,
            ..TrackerConfig::default()
        });

        let start = SystemTime::now();
        for port in [40_000u16, 40_001] {
            let mut syn = tcp_packet(true, false, false, false, true);
            syn.local_addr.set_port(port);
            tracker.ingest_at(&syn, start);
            let mut rst = tcp_packet(false, false, false, true, true);
            rst.local_addr.set_port(port);
            tracker.ingest_at(&rst, start + Duration::from_secs(1));
        }
        assert_eq!(tracker.len(), 2);

        let closed_at = start + Duration::from_secs(86_400);
        let removed = tracker.cleanup(closed_at);
        assert_eq!(removed.len(), 2);

        for port in [40_000u16, 40_001] {
            let mut late_fin = tcp_packet(false, true, true, false, true);
            late_fin.local_addr.set_port(port);
            let outcome = tracker.ingest_at(&late_fin, closed_at + Duration::from_secs(1));
            assert!(
                outcome.ignored_late,
                "delayed teardown for port {port} must hit a tombstone"
            );
        }
        assert!(tracker.is_empty(), "no phantom connections may be created");
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
