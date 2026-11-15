//! Bounded, passive outbound TCP attempt evidence, independent of flow lifetime.
//!
//! Only an observed initial SYN starts an attempt. Missing packets, local
//! cancellation and asymmetric capture can all prevent observed completion;
//! a timeout is evidence of an incomplete handshake, not proof of packet loss.
use rustc_hash::FxBuildHasher;
use std::collections::{BTreeMap, HashMap, VecDeque, hash_map::Entry};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::protocol::tcp::TcpHeaderInfo;
use super::types::ConnectionKey;

pub const WINDOW: Duration = Duration::from_secs(300);
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING: usize = 4096;
const MAX_RETAINED: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptOutcome {
    Established,
    Reset,
    NoHandshake,
    Superseded,
}

impl AttemptOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Established => "established",
            Self::Reset => "reset",
            Self::NoHandshake => "no_handshake_observed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpAttempt {
    pub key: ConnectionKey,
    pub started_at: SystemTime,
    pub finished_at: SystemTime,
    pub initial_sequence: u32,
    pub expected_acknowledgment: u32,
    pub last_unexpected_acknowledgment: Option<u32>,
    pub outcome: AttemptOutcome,
    pub syn_retries: u64,
    pub unexpected_acks: u64,
    pub invalid_syn_acks: u64,
    pub local_resets: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttemptCounts {
    pub completed: u64,
    pub established: u64,
    pub reset: u64,
    pub no_handshake: u64,
    pub superseded: u64,
    pub syn_retries: u64,
    /// Attempts with anomalous replies, including recovered attempts.
    pub anomalous: u64,
    pub recovered_anomalies: u64,
}

impl AttemptCounts {
    fn record(&mut self, attempt: &TcpAttempt) {
        self.completed += 1;
        match attempt.outcome {
            AttemptOutcome::Established => self.established += 1,
            AttemptOutcome::Reset => self.reset += 1,
            AttemptOutcome::NoHandshake => self.no_handshake += 1,
            AttemptOutcome::Superseded => self.superseded += 1,
        }
        self.syn_retries += attempt.syn_retries;
        let anomalous = attempt.unexpected_acks + attempt.invalid_syn_acks > 0;
        self.anomalous += u64::from(anomalous);
        self.recovered_anomalies +=
            u64::from(anomalous && attempt.outcome == AttemptOutcome::Established);
    }
}

#[derive(Debug, Clone, Default)]
pub struct TcpAttemptSnapshot {
    pub total: AttemptCounts,
    pub destinations: BTreeMap<SocketAddr, AttemptCounts>,
    pub pending: usize,
    /// Cumulative capacity omissions since startup/clear, never failures.
    pub omitted: u64,
    pub recent_issues: Vec<TcpAttempt>,
}

struct PendingAttempt {
    attempt: TcpAttempt,
    /// Sequence and acknowledgment expected in the final outbound ACK.
    final_ack: Option<(u32, u32)>,
}

impl PendingAttempt {
    fn new(key: ConnectionKey, tcp: &TcpHeaderInfo, now: SystemTime) -> Self {
        let syn_end = tcp.seq.wrapping_add(1).wrapping_add(tcp.payload_len);
        Self {
            attempt: TcpAttempt {
                key,
                started_at: now,
                finished_at: now,
                initial_sequence: tcp.seq,
                expected_acknowledgment: syn_end,
                last_unexpected_acknowledgment: None,
                outcome: AttemptOutcome::NoHandshake,
                syn_retries: 0,
                unexpected_acks: 0,
                invalid_syn_acks: 0,
                local_resets: 0,
            },
            final_ack: None,
        }
    }
}

#[derive(Default)]
pub(super) struct TcpAttemptTracker {
    pending: HashMap<ConnectionKey, PendingAttempt, FxBuildHasher>,
    retained: VecDeque<TcpAttempt>,
    finished_syns: HashMap<(ConnectionKey, u32), SystemTime, FxBuildHasher>,
    next_expiration: Option<SystemTime>,
    last_sweep: Option<SystemTime>,
    cached_snapshot: Option<Arc<TcpAttemptSnapshot>>,
    snapshot_dirty: bool,
    clock: Option<SystemTime>,
    omitted: u64,
}

impl TcpAttemptTracker {
    fn advance(&mut self, now: SystemTime) -> SystemTime {
        let now = self.clock.map_or(now, |last| last.max(now));
        self.clock = Some(now);
        now
    }

    fn schedule_expiration(&mut self, deadline: SystemTime) {
        self.next_expiration = Some(
            self.next_expiration
                .map_or(deadline, |old| old.min(deadline)),
        );
    }

    fn retain(&mut self, attempt: TcpAttempt) {
        self.snapshot_dirty = true;
        if self
            .clock
            .is_some_and(|now| now >= attempt.finished_at + WINDOW)
        {
            return;
        }
        self.schedule_expiration(attempt.finished_at + WINDOW);
        if self.retained.len() == MAX_RETAINED
            && let Some(old) = self.retained.pop_front()
        {
            self.finished_syns.remove(&(old.key, old.initial_sequence));
            // A throttled sweep can leave expired entries until the next packet.
            if self.clock.is_none_or(|now| now < old.finished_at + WINDOW) {
                self.omitted = self.omitted.saturating_add(1);
            }
        }
        self.finished_syns
            .insert((attempt.key, attempt.initial_sequence), attempt.finished_at);
        self.retained.push_back(attempt);
    }

    fn expire(&mut self, now: SystemTime, exact: bool) {
        // A removed attempt may leave an earlier deadline behind. That costs
        // one extra scan, but never postpones a live attempt's expiration.
        if self.next_expiration.is_none_or(|deadline| now < deadline) {
            return;
        }
        // Packet ingestion sweeps at most once a second. Snapshots honor exact
        // deadlines, but must not turn staggered timeouts into per-packet scans.
        if !exact
            && self.last_sweep.is_some_and(|last| {
                now.duration_since(last).unwrap_or_default() < Duration::from_secs(1)
            })
        {
            return;
        }
        self.last_sweep = Some(now);
        // Free expired capacity before retaining timeouts. Retention is not time ordered.
        self.finished_syns
            .retain(|_, at| now.duration_since(*at).unwrap_or_default() < WINDOW);
        let previous_len = self.retained.len();
        self.retained
            .retain(|a| now.duration_since(a.finished_at).unwrap_or_default() < WINDOW);
        if self.retained.len() != previous_len {
            self.snapshot_dirty = true;
        }
        let expired: Vec<_> = self
            .pending
            .extract_if(|_, p| {
                now.duration_since(p.attempt.started_at).unwrap_or_default() >= ATTEMPT_TIMEOUT
            })
            .map(|(_, p)| p)
            .collect();
        for pending in expired {
            self.finish_timeout(pending);
        }
        self.next_expiration = self
            .pending
            .values()
            .map(|p| p.attempt.started_at + ATTEMPT_TIMEOUT)
            .chain(self.retained.iter().map(|a| a.finished_at + WINDOW))
            .min();
    }

    fn finish_timeout(&mut self, mut p: PendingAttempt) {
        p.attempt.finished_at = p.attempt.started_at + ATTEMPT_TIMEOUT;
        p.attempt.outcome = AttemptOutcome::NoHandshake;
        self.retain(p.attempt);
    }

    pub fn record(
        &mut self,
        key: ConnectionKey,
        tcp: &TcpHeaderInfo,
        outgoing: bool,
        now: SystemTime,
    ) {
        let now = self.advance(now);
        self.expire(now, false);
        let flags = tcp.flags;
        if outgoing && flags.syn && !flags.ack && !flags.rst && !flags.fin {
            if self.pending.get(&key).is_some_and(|p| {
                now.duration_since(p.attempt.started_at).unwrap_or_default() >= ATTEMPT_TIMEOUT
            }) {
                let expired = self.pending.remove(&key).expect("expired attempt exists");
                self.finish_timeout(expired);
            }
            if self.finished_syns.contains_key(&(key, tcp.seq)) {
                return;
            }
            let has_capacity = self.pending.len() < MAX_PENDING;
            let previous = match self.pending.entry(key) {
                Entry::Occupied(mut entry) => {
                    if entry.get().attempt.initial_sequence == tcp.seq {
                        entry.get_mut().attempt.syn_retries += 1;
                        return;
                    }
                    Some(entry.insert(PendingAttempt::new(key, tcp, now)))
                }
                Entry::Vacant(entry) => {
                    if !has_capacity {
                        self.snapshot_dirty = true;
                        self.omitted = self.omitted.saturating_add(1);
                        return;
                    }
                    entry.insert(PendingAttempt::new(key, tcp, now));
                    None
                }
            };
            if let Some(mut previous) = previous {
                previous.attempt.outcome = AttemptOutcome::Superseded;
                previous.attempt.finished_at = now;
                self.retain(previous.attempt);
            }
            self.snapshot_dirty = true;
            self.schedule_expiration(now + ATTEMPT_TIMEOUT);
            return;
        }
        // Avoid hashing unrelated established packets when no attempts await replies.
        if self.pending.is_empty() {
            return;
        }
        let (mut entry, outgoing) = match self.pending.entry(key) {
            Entry::Occupied(entry) => (entry, outgoing),
            Entry::Vacant(_) if outgoing => {
                // Local-to-local replies are parsed as outgoing with reversed endpoints.
                let reversed = ConnectionKey::new(key.protocol, key.remote_addr, key.local_addr);
                let Entry::Occupied(entry) = self.pending.entry(reversed) else {
                    return;
                };
                (entry, false)
            }
            Entry::Vacant(_) => return,
        };
        let p = entry.get_mut();
        if now.duration_since(p.attempt.started_at).unwrap_or_default() >= ATTEMPT_TIMEOUT {
            let expired = entry.remove();
            self.finish_timeout(expired);
            return;
        }
        let mut outcome = None;
        if outgoing {
            if flags.rst {
                // A corrective RST after an unexpected ACK may be followed by
                // a valid SYN-ACK for this same SYN. Preserve that attempt.
                p.attempt.local_resets += 1;
            } else if flags.ack
                && !flags.syn
                && !flags.fin
                && p.final_ack == Some((tcp.seq, tcp.ack))
            {
                outcome = Some(AttemptOutcome::Established);
            }
        } else if flags.rst {
            if flags.ack && tcp.ack == p.attempt.expected_acknowledgment {
                outcome = Some(AttemptOutcome::Reset);
            }
        } else if flags.syn && flags.ack {
            let syn_ack = p.attempt.initial_sequence.wrapping_add(1);
            // Fast Open may acknowledge only the SYN and defer its data to the final ACK.
            if !flags.fin
                && tcp.ack.wrapping_sub(syn_ack)
                    <= p.attempt.expected_acknowledgment.wrapping_sub(syn_ack)
            {
                p.final_ack = Some((
                    tcp.ack,
                    tcp.seq.wrapping_add(1).wrapping_add(tcp.payload_len),
                ));
            } else {
                p.attempt.invalid_syn_acks += 1;
            }
        } else if flags.ack && p.final_ack.is_none() {
            p.attempt.unexpected_acks += 1;
            p.attempt.last_unexpected_acknowledgment = Some(tcp.ack);
        }
        if let Some(outcome) = outcome {
            let mut p = entry.remove();
            p.attempt.outcome = outcome;
            p.attempt.finished_at = now;
            self.retain(p.attempt);
        }
    }

    pub fn snapshot(&mut self, now: SystemTime) -> Arc<TcpAttemptSnapshot> {
        let now = self.advance(now);
        self.expire(now, true);
        if !self.snapshot_dirty
            && let Some(snapshot) = &self.cached_snapshot
        {
            return Arc::clone(snapshot);
        }
        let mut snapshot = TcpAttemptSnapshot {
            pending: self.pending.len(),
            omitted: self.omitted,
            ..Default::default()
        };
        let mut issues = Vec::new();
        for (index, attempt) in self.retained.iter().enumerate() {
            snapshot.total.record(attempt);
            snapshot
                .destinations
                .entry(attempt.key.remote_addr)
                .or_default()
                .record(attempt);
            if attempt.outcome != AttemptOutcome::Established
                || attempt.unexpected_acks + attempt.invalid_syn_acks > 0
            {
                issues.push((index, attempt));
            }
        }
        // Select only the newest 32 before sorting. Retention order breaks ties
        // deterministically, matching the previous stable full sort.
        let order = |a: &(usize, &TcpAttempt), b: &(usize, &TcpAttempt)| {
            b.1.finished_at.cmp(&a.1.finished_at).then(a.0.cmp(&b.0))
        };
        if issues.len() > 32 {
            issues.select_nth_unstable_by(32, order);
            issues.truncate(32);
        }
        issues.sort_unstable_by(order);
        snapshot.recent_issues = issues.into_iter().map(|(_, a)| a.clone()).collect();
        let snapshot = Arc::new(snapshot);
        // Replace the old snapshot here so packet ingestion never frees a
        // potentially large destination map when marking the cache dirty.
        self.cached_snapshot = Some(Arc::clone(&snapshot));
        self.snapshot_dirty = false;
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::parser::{ParsedPacket, TcpFlags};
    use crate::network::tracker::ConnectionTracker;
    use crate::network::types::Protocol;

    fn key(v6: bool) -> ConnectionKey {
        ConnectionKey::new(
            Protocol::Tcp,
            if v6 {
                "[2001:db8::1]:40000"
            } else {
                "192.0.2.1:40000"
            }
            .parse()
            .unwrap(),
            if v6 {
                "[2001:db8::2]:443"
            } else {
                "198.51.100.1:443"
            }
            .parse()
            .unwrap(),
        )
    }
    fn at(ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1000) + Duration::from_millis(ms)
    }
    fn header(flags: u8, seq: u32, ack: u32) -> TcpHeaderInfo {
        TcpHeaderInfo {
            seq,
            ack,
            window: 65535,
            flags: TcpFlags {
                syn: flags & 2 != 0,
                ack: flags & 16 != 0,
                rst: flags & 4 != 0,
                fin: flags & 1 != 0,
            },
            payload_len: 0,
            window_scale: None,
        }
    }
    fn send(
        t: &mut TcpAttemptTracker,
        k: ConnectionKey,
        ms: u64,
        outgoing: bool,
        h: TcpHeaderInfo,
    ) {
        t.record(k, &h, outgoing, at(ms));
    }

    #[test]
    fn replacement_at_capacity_reuses_slot_and_ignores_retained_syns() {
        let mut t = TcpAttemptTracker::default();
        let mut k = key(false);
        for port in 1..=MAX_PENDING {
            k.local_addr.set_port(port as u16);
            send(&mut t, k, 0, true, header(2, 10, 0));
        }
        k.local_addr.set_port(1);
        send(&mut t, k, 1, true, header(2, 10, 0));
        send(&mut t, k, 2, true, header(2, 20, 0));
        // A delayed SYN from the superseded attempt cannot replace the new one.
        send(&mut t, k, 3, true, header(2, 10, 0));
        let s = t.snapshot(at(3));
        assert_eq!(s.pending, MAX_PENDING);
        assert_eq!(s.omitted, 0);
        assert_eq!(s.total.superseded, 1);
        assert_eq!(s.total.syn_retries, 1);
        assert_eq!(t.pending[&k].attempt.initial_sequence, 20);
        send(&mut t, k, 4, false, header(18, 100, 21));
        send(&mut t, k, 5, true, header(16, 21, 101));
        let s = t.snapshot(at(5));
        assert_eq!(s.pending, MAX_PENDING - 1);
        assert_eq!(s.total.established, 1);
    }

    #[test]
    fn staggered_packet_timeouts_do_not_trigger_repeated_global_sweeps() {
        let mut t = TcpAttemptTracker::default();
        let first = key(false);
        let mut second = first;
        second.local_addr.set_port(40001);
        let mut third = first;
        third.local_addr.set_port(40002);
        send(&mut t, first, 0, true, header(2, 10, 0));
        send(&mut t, second, 10, true, header(2, 10, 0));
        send(&mut t, third, 20, true, header(2, 10, 0));
        send(&mut t, first, 10_000, false, header(18, 20, 11));
        assert_eq!(t.last_sweep, Some(at(10_000)));
        send(&mut t, second, 10_010, false, header(18, 20, 11));
        assert_eq!(t.last_sweep, Some(at(10_000)));
        assert!(!t.pending.contains_key(&second));
        // A read at the third deadline must still expire that pending attempt.
        let s = t.snapshot(at(10_020));
        assert_eq!(s.pending, 0);
        assert_eq!(s.total.no_handshake, 3);
    }

    #[test]
    fn snapshots_share_unchanged_state_but_expire_at_exact_deadlines() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        let empty = t.snapshot(at(0));
        assert!(Arc::ptr_eq(&empty, &t.snapshot(at(1))));
        send(&mut t, k, 2, true, header(2, 10, 0));
        let pending = t.snapshot(at(2));
        assert_eq!(pending.pending, 1);
        assert_eq!(empty.pending, 0);
        assert!(Arc::ptr_eq(&pending, &t.snapshot(at(10_001))));
        let timed_out = t.snapshot(at(10_002));
        assert_eq!(timed_out.pending, 0);
        assert_eq!(timed_out.total.no_handshake, 1);
        assert_eq!(pending.pending, 1); // Existing readers keep an immutable view.
        assert!(Arc::ptr_eq(&timed_out, &t.snapshot(at(310_001))));
        let expired = t.snapshot(at(310_002));
        assert_eq!(expired.total.completed, 0);
        assert!(!Arc::ptr_eq(&timed_out, &expired));
    }

    #[test]
    fn completion_and_capacity_omissions_invalidate_cached_snapshots() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, true, header(2, 10, 0));
        let pending = t.snapshot(at(0));
        send(&mut t, k, 1, false, header(18, 20, 11));
        send(&mut t, k, 2, true, header(16, 11, 21));
        let completed = t.snapshot(at(2));
        assert_eq!(completed.total.established, 1);
        assert_eq!(completed.pending, 0);
        assert_eq!(pending.pending, 1);
        // Established packets and an obsolete pending deadline do not rebuild.
        send(&mut t, k, 3, true, header(16, 12, 21));
        assert!(Arc::ptr_eq(&completed, &t.snapshot(at(10_000))));
        for port in 1..=MAX_PENDING {
            let mut k = k;
            k.local_addr.set_port(port as u16);
            send(&mut t, k, 10_001, true, header(2, 30, 0));
        }
        let full = t.snapshot(at(10_001));
        let mut extra = k;
        extra.local_addr.set_port(50000);
        send(&mut t, extra, 10_002, true, header(2, 30, 0));
        let omitted = t.snapshot(at(10_002));
        assert_eq!(full.omitted, 0);
        assert_eq!(omitted.omitted, 1);
        assert_eq!(omitted.pending, MAX_PENDING);
    }

    #[test]
    fn recent_issue_selection_matches_stable_sort_with_ties_and_late_timeouts() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, true, header(2, 10, 0));
        let template = t.pending[&k].attempt.clone();
        let mut t = TcpAttemptTracker::default();
        for i in 0..100 {
            let mut a = template.clone();
            a.initial_sequence = i;
            a.finished_at = at(u64::from(i * 17 % 43));
            t.retain(a);
        }
        let mut expected: Vec<_> = t.retained.iter().collect();
        expected.sort_by_key(|a| std::cmp::Reverse(a.finished_at));
        let expected: Vec<_> = expected
            .iter()
            .take(32)
            .map(|a| a.initial_sequence)
            .collect();
        let s = t.snapshot(at(100));
        let actual: Vec<_> = s.recent_issues.iter().map(|a| a.initial_sequence).collect();
        assert_eq!(actual, expected);
        assert_eq!(s.total.completed, 100);
        // Retention order is not timestamp order; the oldest entry expires first.
        let after_expiry = t.snapshot(at(300_000));
        assert_eq!(after_expiry.total.completed, 97);
        assert_eq!(after_expiry.recent_issues.len(), 32);
        assert!(
            after_expiry
                .recent_issues
                .iter()
                .all(|a| a.finished_at > at(0))
        );
    }

    #[test]
    fn synthetic_handshakes_survive_flow_removal_for_both_families() {
        for v6 in [false, true] {
            for (anomalous, established) in [(false, true), (true, true), (true, false)] {
                let tracker = ConnectionTracker::new();
                let k = key(v6);
                let ingest = |ms, outgoing, h| {
                    let mut packet = ParsedPacket::test_tcp(k.local_addr, k.remote_addr, h);
                    packet.is_outgoing = outgoing;
                    tracker.ingest_at(&packet, at(ms));
                };
                ingest(0, true, header(2, 10, 0));
                if anomalous {
                    ingest(1, false, header(16, 20, 99));
                    ingest(2, true, header(4, 99, 0));
                    ingest(3, true, header(2, 10, 0));
                }
                if established {
                    ingest(4, false, header(18, 20, 11));
                    ingest(5, true, header(16, 11, 21));
                }
                tracker.connections().clear();
                let s = tracker.tcp_attempt_snapshot_at(at(10_000));
                assert_eq!(s.total.completed, 1);
                assert_eq!(s.total.established, u64::from(established));
                assert_eq!(s.total.no_handshake, u64::from(!established));
                assert_eq!(s.total.anomalous, u64::from(anomalous));
                assert_eq!(
                    s.total.recovered_anomalies,
                    u64::from(anomalous && established)
                );
                assert_eq!(s.total.syn_retries, u64::from(anomalous));
                if anomalous {
                    assert_eq!(s.recent_issues[0].local_resets, 1);
                    assert_eq!(s.recent_issues[0].last_unexpected_acknowledgment, Some(99));
                }
                tracker.clear();
                assert_eq!(
                    tracker.tcp_attempt_snapshot_at(at(10_000)).total.completed,
                    0
                );
            }
        }
    }

    #[test]
    fn midstream_inbound_and_incomplete_handshakes_are_not_successes() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, false, header(2, 42, 0));
        send(&mut t, k, 1, false, header(16, 42, 123));
        assert_eq!(t.snapshot(at(2)).pending, 0);
        send(&mut t, k, 3, true, header(2, 100, 0));
        send(&mut t, k, 4, false, header(18, 200, 102)); // wrong ACK
        send(&mut t, k, 5, true, header(16, 101, 201));
        assert_eq!(t.snapshot(at(6)).total.established, 0);
        send(&mut t, k, 7, false, header(18, 200, 101));
        assert_eq!(t.snapshot(at(8)).pending, 1); // final ACK not yet observed
        send(&mut t, k, 9, true, header(16, 101, 201));
        let s = t.snapshot(at(9));
        assert_eq!(s.total.established, 1);
        assert_eq!(s.recent_issues[0].invalid_syn_acks, 1);
    }

    #[test]
    fn retries_port_reuse_reset_and_sequence_wrap() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, true, header(2, 10, 0));
        send(&mut t, k, 1, true, header(2, 10, 0));
        send(&mut t, k, 2, true, header(2, u32::MAX, 0));
        send(&mut t, k, 3, false, header(20, 0, 11)); // old reset must not close new attempt
        send(&mut t, k, 4, false, header(18, u32::MAX, 0));
        send(&mut t, k, 5, true, header(16, 0, 0));
        let s = t.snapshot(at(6));
        assert_eq!(s.total.superseded, 1);
        assert_eq!(s.total.established, 1);
        assert_eq!(s.total.syn_retries, 1);
        send(&mut t, k, 7, true, header(2, 20, 0));
        send(&mut t, k, 8, false, header(20, 0, 21));
        assert_eq!(t.snapshot(at(8)).total.reset, 1);
    }

    #[test]
    fn timeouts_window_expiry_and_late_retries_do_not_double_count() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, true, header(2, 10, 0));
        assert_eq!(t.snapshot(at(9999)).total.completed, 0);
        // A snapshot must expire at the exact deadline, even after a recent sweep.
        assert_eq!(t.snapshot(at(10_000)).total.no_handshake, 1);
        send(&mut t, k, 11_000, true, header(2, 10, 0));
        assert_eq!(t.snapshot(at(22_000)).total.completed, 1);
        assert_eq!(t.snapshot(at(309_999)).total.completed, 1);
        assert_eq!(t.snapshot(at(310_000)).total.completed, 0);
        assert!(t.snapshot(at(310_000)).recent_issues.is_empty());
    }

    #[test]
    fn capacity_omissions_are_not_network_failures_and_memory_is_bounded() {
        let mut t = TcpAttemptTracker::default();
        for port in 1..=MAX_PENDING + 1 {
            let mut k = key(false);
            k.local_addr.set_port(port as u16);
            send(&mut t, k, 0, true, header(2, 10, 0));
        }
        let s = t.snapshot(at(0));
        assert_eq!(s.pending, MAX_PENDING);
        assert_eq!(s.omitted, 1);
        assert_eq!(s.total.completed, 0);
        for n in 0..MAX_RETAINED + 10 {
            let mut a = t.pending.values().next().unwrap().attempt.clone();
            a.initial_sequence = n as u32;
            t.retain(a);
        }
        assert_eq!(t.retained.len(), MAX_RETAINED);
        assert_eq!(t.finished_syns.len(), MAX_RETAINED);
        assert!(t.snapshot(at(0)).recent_issues.len() <= 32);
        assert_eq!(t.snapshot(at(400_000)).total.completed, 0);
    }

    #[test]
    fn syn_data_and_regressing_timestamps() {
        let mut t = TcpAttemptTracker::default();
        let k = key(true);
        let mut h = header(2, 100, 0);
        h.payload_len = 10;
        send(&mut t, k, 1000, true, h);
        send(&mut t, k, 500, false, header(18, 200, 111));
        send(&mut t, k, 1200, true, header(16, 111, 201));
        assert_eq!(t.snapshot(at(1200)).total.established, 1);
    }

    #[test]
    fn local_handshakes_use_the_initiators_direction() {
        use crate::network::parser::ParserConfig;
        use crate::network::protocol::{TransportParams, tcp};

        for (local, remote) in [
            ("127.0.0.1:40000", "127.0.0.1:443"),
            ("[::1]:40000", "[::1]:443"),
            ("192.0.2.1:40000", "192.0.2.2:443"),
            ("[2001:db8::1]:40000", "[2001:db8::2]:443"),
        ] {
            for reset in [false, true] {
                let k = ConnectionKey::new(
                    Protocol::Tcp,
                    local.parse().unwrap(),
                    remote.parse().unwrap(),
                );
                let locals = [k.local_addr.ip(), k.remote_addr.ip()].into();
                let tracker = ConnectionTracker::new();
                for (ms, source, destination, flags, seq, ack) in [
                    (0, k.local_addr, k.remote_addr, 2, 10_u32, 0_u32),
                    (1, k.remote_addr, k.local_addr, 16, 20, 99),
                    (
                        2,
                        k.remote_addr,
                        k.local_addr,
                        if reset { 20 } else { 18 },
                        20,
                        11,
                    ),
                    (3, k.local_addr, k.remote_addr, 16, 11, 21),
                ] {
                    let mut bytes = [0_u8; 20];
                    bytes[..2].copy_from_slice(&source.port().to_be_bytes());
                    bytes[2..4].copy_from_slice(&destination.port().to_be_bytes());
                    bytes[4..8].copy_from_slice(&seq.to_be_bytes());
                    bytes[8..12].copy_from_slice(&ack.to_be_bytes());
                    bytes[12] = 5 << 4;
                    bytes[13] = flags;
                    let packet = tcp::parse(
                        &bytes,
                        TransportParams::new(source.ip(), destination.ip(), 40, None, None),
                        &ParserConfig::default(),
                        &locals,
                    )
                    .unwrap();
                    assert!(packet.is_outgoing);
                    tracker.ingest_at(&packet, at(ms));
                }
                let s = tracker.tcp_attempt_snapshot_at(at(10_000));
                assert_eq!(s.total.completed, 1);
                assert_eq!(s.total.established, u64::from(!reset));
                assert_eq!(s.total.reset, u64::from(reset));
                assert_eq!(s.total.anomalous, 1);
                assert_eq!(s.total.no_handshake, 0);
                assert_eq!(s.recent_issues[0].key, k);
            }
        }
    }

    #[test]
    fn fast_open_fallback_accepts_syn_only_acknowledgment() {
        for seq in [100_u32, u32::MAX - 5] {
            for retry in [false, true] {
                let mut t = TcpAttemptTracker::default();
                let k = key(false);
                let mut syn = header(2, seq, 0);
                syn.payload_len = 10;
                send(&mut t, k, 0, true, syn);
                if retry {
                    send(&mut t, k, 1, true, header(2, seq, 0));
                }
                let accepted = seq.wrapping_add(1);
                send(&mut t, k, 2, false, header(18, 200, accepted));
                let mut ack = header(16, accepted, 201);
                ack.payload_len = 10;
                send(&mut t, k, 3, true, ack);
                let s = t.snapshot(at(10_000));
                assert_eq!(s.total.established, 1);
                assert_eq!(s.total.no_handshake, 0);
                assert_eq!(s.total.anomalous, 0);
                assert_eq!(s.total.syn_retries, u64::from(retry));
            }
        }
    }

    #[test]
    fn window_expiry_does_not_count_as_capacity_loss() {
        for snapshot_ms in [300_000, 610_000] {
            let mut t = TcpAttemptTracker::default();
            let k = key(false);
            send(&mut t, k, 0, true, header(2, 10, 0));
            send(&mut t, k, 0, false, header(20, 0, 11));
            let template = t.retained[0].clone();
            for seq in 1..MAX_RETAINED as u32 {
                t.retain(TcpAttempt {
                    initial_sequence: seq + 10,
                    ..template.clone()
                });
            }
            send(&mut t, k, 290_000, true, header(2, 20_000, 0));
            let s = t.snapshot(at(snapshot_ms));
            assert_eq!(s.pending, 0);
            assert_eq!(s.omitted, 0);
            assert_eq!(s.total.no_handshake, u64::from(snapshot_ms == 300_000));
        }
        // A timeout already outside the window must still invalidate pending state.
        let mut t = TcpAttemptTracker::default();
        send(&mut t, key(false), 0, true, header(2, 10, 0));
        assert_eq!(t.snapshot(at(0)).pending, 1);
        let s = t.snapshot(at(400_000));
        assert_eq!(s.pending, 0);
        assert_eq!(s.total.completed, 0);
    }

    #[test]
    fn eviction_between_sweeps_does_not_count_expired_records_as_lost() {
        let mut t = TcpAttemptTracker::default();
        let k = key(false);
        send(&mut t, k, 0, true, header(2, 10, 0));
        send(&mut t, k, 0, false, header(20, 0, 11));
        let template = t.retained[0].clone();
        for seq in 1..MAX_RETAINED as u32 - 1 {
            t.retain(TcpAttempt {
                initial_sequence: seq + 10,
                ..template.clone()
            });
        }
        send(&mut t, k, 289_999, true, header(2, 20_000, 0));
        send(&mut t, k, 290_000, false, header(20, 0, 20_001));
        assert_eq!(t.snapshot(at(299_999)).omitted, 0);
        assert_eq!(t.last_sweep, Some(at(299_999)));
        send(&mut t, k, 300_000, true, header(2, 30_000, 0));
        send(&mut t, k, 300_001, false, header(20, 0, 30_001));
        assert_eq!(t.last_sweep, Some(at(299_999)));
        let s = t.snapshot(at(300_001));
        assert_eq!(s.omitted, 0);
        assert_eq!(s.total.reset, 2);
    }
}
