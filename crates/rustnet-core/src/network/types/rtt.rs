use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use super::identity::ConnectionKey;
use super::protocol_info::{
    LlmnrInfo, NetBiosInfo, NetBiosService, NtpInfo, NtpMode, StunMessageClass,
};

// ============================================================================
// RTT Tracking Types (for latency measurement)
// ============================================================================

/// Capture time of a pending entry, for staleness pruning.
trait PendingStamp {
    fn stamp(&self) -> SystemTime;
}

impl PendingStamp for SystemTime {
    fn stamp(&self) -> SystemTime {
        *self
    }
}

impl PendingStamp for (SystemTime, ConnectionKey) {
    fn stamp(&self) -> SystemTime {
        self.0
    }
}

/// Bounded map of in-flight requests awaiting their matching reply.
///
/// New entries are dropped at the cap, so a request flood costs unmatched
/// samples, never memory. A retransmit of an already-pending request still
/// refreshes its timestamp even at the cap, so the eventual reply measures
/// from the most recent send.
#[derive(Debug)]
struct PendingTable<K, V = SystemTime> {
    map: HashMap<K, V>,
    cap: usize,
    max_age: Duration,
}

impl<K: Eq + std::hash::Hash, V: PendingStamp + Copy> PendingTable<K, V> {
    fn new(cap: usize, max_age: Duration) -> Self {
        Self {
            map: HashMap::new(),
            cap,
            max_age,
        }
    }

    /// Record a request, dropping new keys at the cap.
    fn start(&mut self, key: K, value: V) -> bool {
        let was_pending = self.map.contains_key(&key);
        if self.map.len() < self.cap || was_pending {
            self.map.insert(key, value);
        }
        was_pending
    }

    /// Take the pending entry a reply matches, if its request was tracked.
    fn complete(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    /// Drop entries older than `max_age` relative to the capture time of the
    /// packet being processed.
    fn prune(&mut self, now: SystemTime) -> Vec<V> {
        let Some(cutoff) = now.checked_sub(self.max_age) else {
            return Vec::new();
        };
        let mut expired = Vec::new();
        self.map.retain(|_, v| {
            let keep = v.stamp() > cutoff;
            if !keep {
                expired.push(*v);
            }
            keep
        });
        expired
    }

    fn clear(&mut self) {
        self.map.clear();
    }
}

/// Which half of a timed request/response exchange a packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExchangeHalf {
    Request,
    Response,
    /// Neither: a STUN indication, a NetBIOS WACK, an NTP broadcast.
    Untimed,
}

impl ExchangeHalf {
    /// For protocols where every packet is a query or a response (DNS, LLMNR).
    fn from_is_response(is_response: bool) -> Self {
        if is_response {
            Self::Response
        } else {
            Self::Request
        }
    }
}

impl<K: Eq + std::hash::Hash> PendingTable<K, (SystemTime, ConnectionKey)> {
    /// Record the client side of a request/response exchange, or complete it
    /// when the matching response arrives. The connection key is retained so
    /// multicast or broadcast requests can be updated when their unicast
    /// response is stored under a different connection.
    ///
    /// Only the client role is timed: an outgoing request starts the timer
    /// and an incoming response stops it. Requests that expired by `at` are
    /// noted as timeouts in `events`, and a re-sent pending request as a
    /// retry.
    fn record_exchange(
        &mut self,
        events: &mut RequestHealthEvents,
        pending_key: K,
        connection_key: ConnectionKey,
        is_outgoing: bool,
        half: ExchangeHalf,
        at: SystemTime,
    ) -> Option<(Duration, ConnectionKey)> {
        events.note_timeouts(self.prune(at));
        match (is_outgoing, half) {
            (true, ExchangeHalf::Request) => {
                if self.start(pending_key, (at, connection_key)) {
                    events.retries.push(connection_key);
                }
                None
            }
            (false, ExchangeHalf::Response) => {
                let (sent_at, request_key) = self.complete(&pending_key)?;
                Some((at.duration_since(sent_at).unwrap_or_default(), request_key))
            }
            _ => None,
        }
    }
}

/// Per-connection request health events collected while correlating packets.
#[derive(Debug, Default)]
pub(crate) struct RequestHealthEvents {
    pub(crate) retries: Vec<ConnectionKey>,
    pub(crate) timeouts: Vec<ConnectionKey>,
}

impl RequestHealthEvents {
    /// Note the requesting connection of every expired pending request.
    fn note_timeouts(&mut self, expired: impl IntoIterator<Item = (SystemTime, ConnectionKey)>) {
        self.timeouts
            .extend(expired.into_iter().map(|(_, key)| key));
    }
}

/// Correlation scope for protocols that use the DNS transaction ID.
///
/// Unicast DNS can pair on the full connection. LLMNR queries are multicast
/// and their responses are unicast, so they pair on the local socket instead.
/// Keeping both variants in one table shares bounds and expiry while avoiding
/// cross-protocol collisions when the same socket and ID happen to be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum DnsTransactionKey {
    Unicast(ConnectionKey, u16),
    Llmnr(SocketAddr, u16),
}

/// Tracks pending handshake packets and recent RTT measurements.
///
/// Every pending timestamp here is the packet's **capture** time, supplied by
/// the caller, never a clock read taken while processing. Capture threads hand
/// packets to processing in batches of up to 100 (or every 100ms), so a
/// handshake that completes inside one batch window — which is most of them —
/// is processed as a burst microseconds wide. Timing that burst measures the
/// batch loop, not the network, and reports round trips as 0.0ms. Using capture
/// time also makes RTTs correct when a saved pcap is replayed.
#[derive(Debug)]
pub struct RttTracker {
    /// Pending SYN packets awaiting SYN-ACK: (connection_key -> capture time)
    pending_syns: PendingTable<ConnectionKey>,
    /// Outbound QUIC handshake packets awaiting a reply from the peer:
    /// (connection_key -> capture time)
    pending_quic_handshakes: PendingTable<ConnectionKey>,
    /// Outbound DNS and LLMNR queries awaiting their response. Both use the
    /// DNS transaction ID, but LLMNR uses a local-socket scope because its
    /// multicast query and unicast response have different remote endpoints.
    pending_dns: PendingTable<DnsTransactionKey, (SystemTime, ConnectionKey)>,
    /// Outbound NetBIOS requests awaiting a response. The remote endpoint is
    /// intentionally absent from the map key because Name Service requests are
    /// commonly sent to a broadcast address and answered by an individual
    /// host. The requesting connection's key is stored so a reply arriving
    /// under the responder's unicast key can stamp the request row too.
    pending_netbios: PendingTable<(SocketAddr, NetBiosService, u16), (SystemTime, ConnectionKey)>,
    /// Outbound ICMP echo requests awaiting replies, keyed by connection,
    /// identifier, and sequence number. The sequence keeps fast pings distinct.
    pending_icmp_echoes: PendingTable<(ConnectionKey, u16, u16)>,
    /// Outbound STUN requests awaiting their response, keyed by connection
    /// and the 96-bit transaction ID.
    pending_stun: PendingTable<(ConnectionKey, [u8; 12]), (SystemTime, ConnectionKey)>,
    /// Outbound NTP client requests awaiting a server response, keyed by
    /// connection and the transmit timestamp the response echoes back.
    pending_ntp: PendingTable<(ConnectionKey, u64), (SystemTime, ConnectionKey)>,
    /// Health events waiting for the connection table to consume them.
    request_health_events: RequestHealthEvents,
    /// Recent RTT measurements for aggregation: (timestamp, rtt_duration)
    recent_rtts: VecDeque<(Instant, Duration)>,
    /// Maximum number of recent RTTs to keep
    max_recent_rtts: usize,
}

/// Hard cap on each pending table. At `ping -i .2`, the 10-second expiry
/// limits an unanswered flow to about 50 entries, far below this guardrail.
const MAX_PENDING: usize = 4096;

impl RttTracker {
    pub fn new() -> Self {
        // Pending handshakes stay matchable for 30 seconds; the
        // request/response protocols expire after 10 seconds, well past any
        // resolver timeout, the RFC 5389 STUN retransmit window's useful
        // range, or any sane NTP response.
        let max_handshake_age = Duration::from_secs(30);
        let max_request_age = Duration::from_secs(10);
        Self {
            pending_syns: PendingTable::new(MAX_PENDING, max_handshake_age),
            pending_quic_handshakes: PendingTable::new(MAX_PENDING, max_handshake_age),
            pending_dns: PendingTable::new(MAX_PENDING, max_request_age),
            pending_netbios: PendingTable::new(MAX_PENDING, max_request_age),
            pending_icmp_echoes: PendingTable::new(MAX_PENDING, max_request_age),
            pending_stun: PendingTable::new(MAX_PENDING, max_request_age),
            pending_ntp: PendingTable::new(MAX_PENDING, max_request_age),
            request_health_events: RequestHealthEvents::default(),
            recent_rtts: VecDeque::new(),
            max_recent_rtts: 100,
        }
    }

    /// Record a SYN packet being sent/received, stamped with its capture time.
    pub fn record_syn(&mut self, key: ConnectionKey, at: SystemTime) {
        self.pending_syns.prune(at);
        self.pending_syns.start(key, at);
    }

    /// Try to match a SYN-ACK to a pending SYN and calculate RTT
    /// Returns the RTT if a match was found
    pub fn record_syn_ack(&mut self, key: &ConnectionKey, at: SystemTime) -> Option<Duration> {
        // SYN and SYN-ACK have the same (local_addr, remote_addr) from parser's perspective
        self.pending_syns.prune(at);
        let syn_time = self.pending_syns.complete(key)?;
        let rtt = at.duration_since(syn_time).unwrap_or_default();
        self.add_rtt_sample(rtt);
        Some(rtt)
    }

    /// Record a QUIC long-header handshake packet, returning the RTT when it
    /// completes a round trip with the peer.
    ///
    /// QUIC has no SYN/SYN-ACK flag to key on, so direction stands in for it —
    /// but only in one order. rustnet observes from an endpoint, not from a
    /// midpoint, so the timer must start on a packet leaving this host and stop
    /// on the peer's answer coming back: that spans the network twice. Timing
    /// the opposite order would measure how fast the local stack turned an
    /// arriving packet around, which is tens of microseconds and reads as a
    /// 0.0ms RTT. An inbound packet with nothing pending therefore starts
    /// nothing, and a second outbound packet is a retransmission or a follow-up
    /// flight, so it restarts the timer from the most recent send.
    ///
    /// This still measures connections where the local host is the QUIC server:
    /// the client's Initial arrives and is ignored, our reply starts the timer,
    /// and the client's next flight stops it.
    pub fn record_quic_handshake(
        &mut self,
        key: ConnectionKey,
        is_outgoing: bool,
        at: SystemTime,
    ) -> Option<Duration> {
        self.pending_quic_handshakes.prune(at);
        if is_outgoing {
            self.pending_quic_handshakes.start(key, at);
            return None;
        }
        let sent_at = self.pending_quic_handshakes.complete(&key)?;
        let rtt = at.duration_since(sent_at).unwrap_or_default();
        self.add_rtt_sample(rtt);
        Some(rtt)
    }

    /// Record a DNS packet, returning the query→response time when an incoming
    /// response matches a pending outgoing query.
    ///
    /// Only the client role is timed: the timer starts on an outgoing query and
    /// stops on the incoming response with the same transaction ID (the reverse
    /// order would time the local resolver's turnaround, not the network). A
    /// re-sent query overwrites its pending timestamp, so like QUIC handshakes
    /// the measurement runs from the most recent send. The result is not fed
    /// into the aggregate RTT samples: it includes resolver processing time,
    /// which would pollute the transport-level average.
    pub fn record_dns_packet(
        &mut self,
        key: ConnectionKey,
        txid: u16,
        is_outgoing: bool,
        is_response: bool,
        at: SystemTime,
    ) -> Option<Duration> {
        self.pending_dns
            .record_exchange(
                &mut self.request_health_events,
                DnsTransactionKey::Unicast(key, txid),
                key,
                is_outgoing,
                ExchangeHalf::from_is_response(is_response),
                at,
            )
            .map(|(rtt, _)| rtt)
    }

    /// Record an LLMNR packet and return the first response time together with
    /// the multicast query's connection key.
    ///
    /// RFC 4795 responses copy the query's 16-bit ID, but a multicast query is
    /// answered via unicast. Pairing on the local socket and ID bridges those
    /// different connection keys. Only the first response completes the
    /// pending query, which is the useful resolver latency for a multi-responder
    /// exchange.
    pub fn record_llmnr_packet(
        &mut self,
        key: ConnectionKey,
        info: &LlmnrInfo,
        is_outgoing: bool,
        at: SystemTime,
    ) -> Option<(Duration, ConnectionKey)> {
        self.pending_dns.record_exchange(
            &mut self.request_health_events,
            DnsTransactionKey::Llmnr(key.local_addr, info.txid),
            key,
            is_outgoing,
            ExchangeHalf::from_is_response(info.is_response),
            at,
        )
    }

    /// Record a NetBIOS packet and, when an incoming final response matches an
    /// outgoing request, return the request-to-response time together with the
    /// requesting connection's key.
    ///
    /// NetBIOS Name Service usually sends requests to a broadcast address,
    /// while the responding host replies from its unicast address. Pairing by
    /// local socket, service, and transaction ID handles both broadcast and
    /// unicast exchanges; the returned key lets the caller stamp the round
    /// trip on the requesting connection when the reply arrives under a
    /// different one. Like DNS timing, the result includes remote service
    /// processing and is not added to transport RTT aggregates.
    pub fn record_netbios_packet(
        &mut self,
        key: ConnectionKey,
        info: &NetBiosInfo,
        is_outgoing: bool,
        at: SystemTime,
    ) -> Option<(Duration, ConnectionKey)> {
        // WACK is neither: a later final response completes the request.
        let half = if info.is_request() {
            ExchangeHalf::Request
        } else if info.is_response {
            ExchangeHalf::Response
        } else {
            ExchangeHalf::Untimed
        };
        self.pending_netbios.record_exchange(
            &mut self.request_health_events,
            (key.local_addr, info.service, info.transaction_id),
            key,
            is_outgoing,
            half,
            at,
        )
    }

    /// Record an ICMP echo packet, returning the RTT when an incoming reply
    /// matches a pending outgoing request.
    ///
    /// Identifier alone is not enough because one ping process reuses it for
    /// every request. Pairing identifier and sequence supports many requests
    /// in flight at once, including subsecond intervals and reordered replies.
    /// Only the client role is timed, so an inbound request followed by this
    /// host's reply is not mistaken for a network round trip. `echo_key` is
    /// `(identifier, sequence)` in the on-wire order.
    pub fn record_icmp_echo(
        &mut self,
        key: ConnectionKey,
        echo_key: (u16, u16),
        is_outgoing: bool,
        is_reply: bool,
        at: SystemTime,
    ) -> Option<Duration> {
        self.pending_icmp_echoes.prune(at);
        let (identifier, sequence) = echo_key;
        let pending_key = (key, identifier, sequence);
        match (is_outgoing, is_reply) {
            (true, false) => {
                self.pending_icmp_echoes.start(pending_key, at);
                None
            }
            (false, true) => {
                let sent_at = self.pending_icmp_echoes.complete(&pending_key)?;
                let rtt = at.duration_since(sent_at).unwrap_or_default();
                self.add_rtt_sample(rtt);
                Some(rtt)
            }
            _ => None,
        }
    }

    /// Record a STUN packet, returning the RTT when an incoming success or
    /// error response matches a pending outgoing request by transaction ID.
    ///
    /// Retransmitted requests reuse their transaction ID (RFC 5389 §7.2.1),
    /// so a retransmit refreshes the pending timestamp and the eventual
    /// response measures from the most recent send. Indications have no
    /// response and are never recorded.
    pub fn record_stun(
        &mut self,
        key: ConnectionKey,
        transaction_id: [u8; 12],
        is_outgoing: bool,
        class: StunMessageClass,
        at: SystemTime,
    ) -> Option<Duration> {
        let half = match class {
            StunMessageClass::Request => ExchangeHalf::Request,
            StunMessageClass::SuccessResponse | StunMessageClass::ErrorResponse => {
                ExchangeHalf::Response
            }
            StunMessageClass::Indication => ExchangeHalf::Untimed,
        };
        self.pending_stun
            .record_exchange(
                &mut self.request_health_events,
                (key, transaction_id),
                key,
                is_outgoing,
                half,
                at,
            )
            .map(|(rtt, _)| rtt)
    }

    /// Record an NTP packet, returning the round trip when an incoming
    /// server response matches a pending outgoing client request.
    ///
    /// A server echoes the client's transmit timestamp back as the originate
    /// timestamp (RFC 5905 §8), which pairs each exchange exactly even when
    /// a daemon polls several servers from one socket. Broadcast and
    /// symmetric modes have no such echo and are not timed.
    pub fn record_ntp(
        &mut self,
        key: ConnectionKey,
        info: &NtpInfo,
        is_outgoing: bool,
        at: SystemTime,
    ) -> Option<Duration> {
        let half = match info.mode {
            NtpMode::Client => ExchangeHalf::Request,
            NtpMode::Server => ExchangeHalf::Response,
            _ => ExchangeHalf::Untimed,
        };
        // Our request is keyed by what we transmitted; the server's response
        // is keyed by the originate echo of it.
        let timestamp = if is_outgoing {
            info.transmit_timestamp
        } else {
            info.origin_timestamp
        };
        self.pending_ntp
            .record_exchange(
                &mut self.request_health_events,
                (key, timestamp),
                key,
                is_outgoing,
                half,
                at,
            )
            .map(|(rtt, _)| rtt)
    }

    /// Expire all tracked request protocols and return their health events.
    pub(crate) fn expire_requests(&mut self, now: SystemTime) -> RequestHealthEvents {
        let events = &mut self.request_health_events;
        events.note_timeouts(self.pending_dns.prune(now));
        events.note_timeouts(self.pending_netbios.prune(now));
        events.note_timeouts(self.pending_stun.prune(now));
        events.note_timeouts(self.pending_ntp.prune(now));
        self.take_request_health_events()
    }

    pub(crate) fn take_request_health_events(&mut self) -> RequestHealthEvents {
        std::mem::take(&mut self.request_health_events)
    }

    /// Record a completed data round trip (segment to covering ACK) measured
    /// by the per-connection estimator, so the aggregate RTT view reflects
    /// established connections rather than only fresh handshakes.
    pub fn record_data_rtt(&mut self, rtt: Duration) {
        self.add_rtt_sample(rtt);
    }

    /// Add an RTT sample
    fn add_rtt_sample(&mut self, rtt: Duration) {
        let now = Instant::now();
        if self.recent_rtts.len() >= self.max_recent_rtts {
            self.recent_rtts.pop_front();
        }
        self.recent_rtts.push_back((now, rtt));
    }

    /// Get average RTT for the last N seconds, clearing consumed samples
    pub fn take_average_rtt(&mut self, window_secs: u64) -> Option<f64> {
        let cutoff = Instant::now() - Duration::from_secs(window_secs);
        let samples: Vec<Duration> = self
            .recent_rtts
            .iter()
            .filter(|(ts, _)| *ts >= cutoff)
            .map(|(_, rtt)| *rtt)
            .collect();

        if samples.is_empty() {
            None
        } else {
            let total_ms: f64 = samples.iter().map(|d| d.as_secs_f64() * 1000.0).sum();
            Some(total_ms / samples.len() as f64)
        }
    }

    /// Clear all RTT tracking data
    pub fn clear(&mut self) {
        self.pending_syns.clear();
        self.pending_quic_handshakes.clear();
        self.pending_dns.clear();
        self.pending_netbios.clear();
        self.pending_icmp_echoes.clear();
        self.pending_stun.clear();
        self.pending_ntp.clear();
        self.request_health_events = RequestHealthEvents::default();
        self.recent_rtts.clear();
    }
}

impl Default for RttTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::test_support::{addr, key};
    use crate::network::types::{
        DnsQueryType, LlmnrInfo, NetBiosOpcode, NetBiosResponseStatus, Protocol,
    };

    // ========================================================================
    // RTT Tracker Tests
    // ========================================================================

    /// Capture time `millis` into a synthetic trace. RTT is the difference
    /// between two packets' capture timestamps, so tests supply them directly
    /// rather than sleeping and reading a clock.
    fn rtt_capture_time(millis: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_millis(millis)
    }

    fn netbios_test_info(
        service: NetBiosService,
        transaction_id: u16,
        is_response: bool,
    ) -> NetBiosInfo {
        NetBiosInfo {
            service,
            opcode: if is_response {
                NetBiosOpcode::Response
            } else {
                NetBiosOpcode::Query
            },
            name: Some("FILESERVER".to_string()),
            transaction_id,
            is_response,
            response_status: is_response.then_some(NetBiosResponseStatus::NameService(0)),
        }
    }

    fn llmnr_test_info(txid: u16, is_response: bool) -> LlmnrInfo {
        LlmnrInfo {
            query_name: Some("workstation".to_string()),
            query_type: Some(DnsQueryType::A),
            is_response,
            response_ips: Vec::new(),
            txid,
        }
    }

    #[test]
    fn test_rtt_tracker_new() {
        let tracker = RttTracker::new();
        assert!(tracker.pending_syns.map.is_empty());
        assert!(tracker.recent_rtts.is_empty());
    }

    #[test]
    fn test_rtt_tracker_record_syn() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Tcp, "192.168.1.1:12345", "93.184.216.34:443");

        tracker.record_syn(key, rtt_capture_time(0));
        assert_eq!(tracker.pending_syns.map.len(), 1);
        assert!(tracker.pending_syns.map.contains_key(&key));
    }

    #[test]
    fn test_rtt_tracker_record_syn_ack_no_match() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Tcp, "192.168.1.1:12345", "93.184.216.34:443");

        // Try to record SYN-ACK without prior SYN
        let rtt = tracker.record_syn_ack(&key, rtt_capture_time(0));
        assert!(rtt.is_none());
    }

    #[test]
    fn test_rtt_tracker_record_syn_ack_match() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:12345");
        let remote = addr("93.184.216.34:443");

        // Record SYN (outgoing: local -> remote)
        let syn_key = ConnectionKey::new(Protocol::Tcp, local, remote);
        tracker.record_syn(syn_key, rtt_capture_time(0));

        // Record SYN-ACK (same key - parser normalizes to local,remote) one
        // network round trip later, per the packets' capture timestamps.
        let syn_ack_key = ConnectionKey::new(Protocol::Tcp, local, remote);
        let rtt = tracker.record_syn_ack(&syn_ack_key, rtt_capture_time(10));

        assert_eq!(rtt, Some(Duration::from_millis(10)));
        assert!(tracker.pending_syns.map.is_empty());
        assert_eq!(tracker.recent_rtts.len(), 1);
    }

    /// At the hard cap, new pending SYNs are dropped (losing samples under a
    /// SYN flood is harmless; growing without bound is not), but a
    /// retransmitted SYN of a tracked key still refreshes its timestamp.
    #[test]
    fn test_rtt_tracker_pending_syns_capped() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:10000");
        let remote = addr("93.184.216.34:443");

        for port in 0..MAX_PENDING as u16 {
            let key = ConnectionKey::new(
                Protocol::Tcp,
                SocketAddr::new(local.ip(), 10_000 + port),
                remote,
            );
            tracker.record_syn(key, rtt_capture_time(0));
        }
        assert_eq!(tracker.pending_syns.map.len(), MAX_PENDING);

        // One more distinct SYN is rejected...
        let overflow_key = ConnectionKey::new(Protocol::Tcp, addr("192.168.1.2:10000"), remote);
        tracker.record_syn(overflow_key, rtt_capture_time(1));
        assert_eq!(tracker.pending_syns.map.len(), MAX_PENDING);
        let rtt = tracker.record_syn_ack(&overflow_key, rtt_capture_time(20));
        assert!(rtt.is_none(), "a rejected SYN has no pending timestamp");

        // ...but a retransmit of a tracked SYN still restarts its timer.
        let tracked_key = ConnectionKey::new(Protocol::Tcp, addr("192.168.1.1:10000"), remote);
        tracker.record_syn(tracked_key, rtt_capture_time(1_000));
        let rtt = tracker.record_syn_ack(&tracked_key, rtt_capture_time(1_015));
        assert_eq!(rtt, Some(Duration::from_millis(15)));
    }

    #[test]
    fn test_rtt_tracker_pending_quic_handshakes_capped() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:10000");
        let remote = addr("142.250.74.78:443");

        for port in 0..MAX_PENDING as u16 {
            let key = ConnectionKey::new(
                Protocol::Udp,
                SocketAddr::new(local.ip(), 10_000 + port),
                remote,
            );
            tracker.record_quic_handshake(key, true, rtt_capture_time(0));
        }
        assert_eq!(tracker.pending_quic_handshakes.map.len(), MAX_PENDING);

        let overflow_key = ConnectionKey::new(Protocol::Udp, addr("192.168.1.2:10000"), remote);
        tracker.record_quic_handshake(overflow_key, true, rtt_capture_time(1));
        assert_eq!(tracker.pending_quic_handshakes.map.len(), MAX_PENDING);
        let rtt = tracker.record_quic_handshake(overflow_key, false, rtt_capture_time(20));
        assert!(
            rtt.is_none(),
            "a rejected handshake has no pending timestamp"
        );

        let tracked_key = ConnectionKey::new(Protocol::Udp, addr("192.168.1.1:10000"), remote);
        tracker.record_quic_handshake(tracked_key, true, rtt_capture_time(1_000));
        let rtt = tracker.record_quic_handshake(tracked_key, false, rtt_capture_time(1_015));
        assert_eq!(rtt, Some(Duration::from_millis(15)));
    }

    #[test]
    fn test_rtt_tracker_take_average_rtt() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:12345");
        let remote = addr("93.184.216.34:443");

        // Record multiple RTT measurements
        for port in 12345..12348 {
            let local_with_port = SocketAddr::new(local.ip(), port);
            let key = ConnectionKey::new(Protocol::Tcp, local_with_port, remote);
            tracker.record_syn(key, rtt_capture_time(0));
            tracker.record_syn_ack(&key, rtt_capture_time(5));
        }

        // Get average RTT
        let avg = tracker.take_average_rtt(60);
        assert!(avg.is_some());
        let avg = avg.unwrap();
        assert!(avg >= 5.0); // At least 5ms
    }

    /// Pending DNS queries expire after `max_pending_dns_age`: a response that
    /// arrives later matches nothing, so an abandoned query can't produce a
    /// bogus multi-minute sample.
    #[test]
    fn test_rtt_tracker_pending_dns_expires() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:40000", "9.9.9.9:53");

        tracker.record_dns_packet(key, 0x1234, true, false, rtt_capture_time(0));
        let rtt = tracker.record_dns_packet(key, 0x1234, false, true, rtt_capture_time(11_000));
        assert!(rtt.is_none(), "the pending query expired after 10s");
        assert!(tracker.pending_dns.map.is_empty());
    }

    /// At the hard cap, new pending queries are dropped (losing samples under
    /// a query flood is harmless; growing without bound is not), but a
    /// retransmit of an already-pending query still refreshes its timestamp.
    #[test]
    fn test_rtt_tracker_pending_dns_capped() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:40000");
        let remote = addr("9.9.9.9:53");
        let key = ConnectionKey::new(Protocol::Udp, local, remote);

        for txid in 0..MAX_PENDING as u16 {
            tracker.record_dns_packet(key, txid, true, false, rtt_capture_time(0));
        }
        assert_eq!(tracker.pending_dns.map.len(), MAX_PENDING);

        // One more distinct query is rejected...
        let overflow_key =
            ConnectionKey::new(Protocol::Udp, SocketAddr::new(local.ip(), 40_001), remote);
        tracker.record_dns_packet(overflow_key, 7, true, false, rtt_capture_time(1));
        assert_eq!(tracker.pending_dns.map.len(), MAX_PENDING);
        let rtt = tracker.record_dns_packet(overflow_key, 7, false, true, rtt_capture_time(20));
        assert!(rtt.is_none(), "a rejected query has no pending timestamp");

        // ...but a retransmit of a tracked query still restarts its timer.
        tracker.record_dns_packet(key, 42, true, false, rtt_capture_time(1_000));
        let rtt = tracker.record_dns_packet(key, 42, false, true, rtt_capture_time(1_015));
        assert_eq!(rtt, Some(Duration::from_millis(15)));
    }

    #[test]
    fn test_rtt_tracker_llmnr_pairs_first_unicast_response() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:40000");
        let query_key = ConnectionKey::new(Protocol::Udp, local, addr("224.0.0.252:5355"));
        let first_response_key =
            ConnectionKey::new(Protocol::Udp, local, addr("192.168.1.20:5355"));
        let second_response_key =
            ConnectionKey::new(Protocol::Udp, local, addr("192.168.1.21:5355"));
        let query = llmnr_test_info(0x1234, false);
        let response = llmnr_test_info(0x1234, true);

        tracker.record_llmnr_packet(query_key, &query, true, rtt_capture_time(0));
        let first =
            tracker.record_llmnr_packet(first_response_key, &response, false, rtt_capture_time(17));
        assert_eq!(first, Some((Duration::from_millis(17), query_key)));

        let second = tracker.record_llmnr_packet(
            second_response_key,
            &response,
            false,
            rtt_capture_time(24),
        );
        assert!(
            second.is_none(),
            "only the first response completes the query"
        );
        assert!(tracker.pending_dns.map.is_empty());
    }

    #[test]
    fn test_rtt_tracker_pending_llmnr_expires() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:40000");
        let query_key = ConnectionKey::new(Protocol::Udp, local, addr("224.0.0.252:5355"));
        let response_key = ConnectionKey::new(Protocol::Udp, local, addr("192.168.1.20:5355"));

        tracker.record_llmnr_packet(
            query_key,
            &llmnr_test_info(0x1234, false),
            true,
            rtt_capture_time(0),
        );
        let rtt = tracker.record_llmnr_packet(
            response_key,
            &llmnr_test_info(0x1234, true),
            false,
            rtt_capture_time(11_000),
        );
        assert!(rtt.is_none(), "the pending query expired after 10s");
        assert!(tracker.pending_dns.map.is_empty());
    }

    #[test]
    fn test_rtt_tracker_pending_netbios_expires() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:137", "192.168.1.255:137");
        let request = netbios_test_info(NetBiosService::NameService, 0x1234, false);
        let response = netbios_test_info(NetBiosService::NameService, 0x1234, true);

        tracker.record_netbios_packet(key, &request, true, rtt_capture_time(0));
        let rtt = tracker.record_netbios_packet(key, &response, false, rtt_capture_time(11_000));
        assert!(rtt.is_none(), "the pending request expired after 10s");
        assert!(tracker.pending_netbios.map.is_empty());
    }

    #[test]
    fn test_rtt_tracker_pending_netbios_capped() {
        let mut tracker = RttTracker::new();
        let local = addr("192.168.1.1:137");
        let remote = addr("192.168.1.255:137");
        let key = ConnectionKey::new(Protocol::Udp, local, remote);

        for transaction_id in 0..MAX_PENDING as u16 {
            let request = netbios_test_info(NetBiosService::NameService, transaction_id, false);
            tracker.record_netbios_packet(key, &request, true, rtt_capture_time(0));
        }
        assert_eq!(tracker.pending_netbios.map.len(), MAX_PENDING);

        let overflow_key = ConnectionKey::new(
            Protocol::Udp,
            SocketAddr::new(local.ip(), 138),
            SocketAddr::new(remote.ip(), 138),
        );
        let overflow_request = netbios_test_info(NetBiosService::DatagramService, 7, false);
        let overflow_response = netbios_test_info(NetBiosService::DatagramService, 7, true);
        tracker.record_netbios_packet(overflow_key, &overflow_request, true, rtt_capture_time(1));
        assert_eq!(tracker.pending_netbios.map.len(), MAX_PENDING);
        let rtt = tracker.record_netbios_packet(
            overflow_key,
            &overflow_response,
            false,
            rtt_capture_time(20),
        );
        assert!(rtt.is_none());

        let request = netbios_test_info(NetBiosService::NameService, 42, false);
        let response = netbios_test_info(NetBiosService::NameService, 42, true);
        tracker.record_netbios_packet(key, &request, true, rtt_capture_time(1_000));
        let rtt = tracker.record_netbios_packet(key, &response, false, rtt_capture_time(1_015));
        assert_eq!(
            rtt,
            Some((Duration::from_millis(15), key)),
            "a match returns the round trip and the requesting connection's key"
        );
    }

    #[test]
    fn test_rtt_tracker_pending_icmp_echo_expires() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Icmp, "192.168.1.1:0", "8.8.8.8:0");

        tracker.record_icmp_echo(key, (7, 1), true, false, rtt_capture_time(0));
        let rtt = tracker.record_icmp_echo(key, (7, 1), false, true, rtt_capture_time(11_000));
        assert!(rtt.is_none(), "the pending echo expired after 10s");
        assert!(tracker.pending_icmp_echoes.map.is_empty());
    }

    #[test]
    fn test_rtt_tracker_pending_icmp_echo_is_capped() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Icmp, "192.168.1.1:0", "8.8.8.8:0");

        for sequence in 0..MAX_PENDING as u16 {
            tracker.record_icmp_echo(key, (7, sequence), true, false, rtt_capture_time(0));
        }
        assert_eq!(tracker.pending_icmp_echoes.map.len(), MAX_PENDING);

        let rejected_sequence = MAX_PENDING as u16;
        tracker.record_icmp_echo(
            key,
            (7, rejected_sequence),
            true,
            false,
            rtt_capture_time(1),
        );
        let rtt = tracker.record_icmp_echo(
            key,
            (7, rejected_sequence),
            false,
            true,
            rtt_capture_time(20),
        );
        assert!(rtt.is_none(), "an echo rejected at the cap has no timer");

        tracker.record_icmp_echo(key, (7, 42), true, false, rtt_capture_time(1_000));
        let rtt = tracker.record_icmp_echo(key, (7, 42), false, true, rtt_capture_time(1_009));
        assert_eq!(rtt, Some(Duration::from_millis(9)));
    }

    #[test]
    fn test_rtt_tracker_stun_pairs_by_transaction_id() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:54000", "203.0.113.5:3478");
        let txid = [7u8; 12];

        tracker.record_stun(
            key,
            txid,
            true,
            StunMessageClass::Request,
            rtt_capture_time(0),
        );
        let rtt = tracker.record_stun(
            key,
            txid,
            false,
            StunMessageClass::SuccessResponse,
            rtt_capture_time(23),
        );
        assert_eq!(rtt, Some(Duration::from_millis(23)));

        // Indications have no response and must not leave a pending timer.
        tracker.record_stun(
            key,
            [9u8; 12],
            true,
            StunMessageClass::Indication,
            rtt_capture_time(100),
        );
        assert!(tracker.pending_stun.map.is_empty());
    }

    #[test]
    fn test_rtt_tracker_pending_stun_expires() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:54000", "203.0.113.5:3478");
        let txid = [7u8; 12];

        tracker.record_stun(
            key,
            txid,
            true,
            StunMessageClass::Request,
            rtt_capture_time(0),
        );
        let rtt = tracker.record_stun(
            key,
            txid,
            false,
            StunMessageClass::ErrorResponse,
            rtt_capture_time(11_000),
        );
        assert!(rtt.is_none(), "the pending request expired after 10s");
        assert!(tracker.pending_stun.map.is_empty());
    }

    fn ntp_info(mode: NtpMode, origin_timestamp: u64, transmit_timestamp: u64) -> NtpInfo {
        NtpInfo {
            version: 4,
            mode,
            stratum: 2,
            origin_timestamp,
            transmit_timestamp,
        }
    }

    #[test]
    fn test_rtt_tracker_ntp_pairs_by_originate_timestamp() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:47000", "203.0.113.9:123");

        tracker.record_ntp(
            key,
            &ntp_info(NtpMode::Client, 0, 0xAABB),
            true,
            rtt_capture_time(0),
        );
        // The server echoes the client's transmit timestamp as originate.
        let rtt = tracker.record_ntp(
            key,
            &ntp_info(NtpMode::Server, 0xAABB, 0xCCDD),
            false,
            rtt_capture_time(17),
        );
        assert_eq!(rtt, Some(Duration::from_millis(17)));

        // A response whose originate echo matches nothing measures nothing.
        let rtt = tracker.record_ntp(
            key,
            &ntp_info(NtpMode::Server, 0x1234, 0xCCDD),
            false,
            rtt_capture_time(30),
        );
        assert!(rtt.is_none());
    }

    #[test]
    fn test_rtt_tracker_pending_ntp_expires() {
        let mut tracker = RttTracker::new();
        let key = key(Protocol::Udp, "192.168.1.1:47000", "203.0.113.9:123");

        tracker.record_ntp(
            key,
            &ntp_info(NtpMode::Client, 0, 0xAABB),
            true,
            rtt_capture_time(0),
        );
        let rtt = tracker.record_ntp(
            key,
            &ntp_info(NtpMode::Server, 0xAABB, 0xCCDD),
            false,
            rtt_capture_time(11_000),
        );
        assert!(rtt.is_none(), "the pending request expired after 10s");
        assert!(tracker.pending_ntp.map.is_empty());
    }
}
