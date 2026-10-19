//! Bounded passive DNS transaction analytics.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use super::types::{ConnectionKey, DnsInfo, DnsQueryType};

mod aggregate;
use aggregate::DnsAggregate;

const DNS_RETENTION_WINDOW: Duration = Duration::from_secs(60 * 60);
const DNS_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_ISSUE_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_DNS_ISSUES: usize = 64;
const MAX_PENDING_DNS_TRANSACTIONS: usize = 4096;
const MAX_RETAINED_DNS_TRANSACTIONS: usize = 8192;
/// Operational-failure share of finalized lookups that degrades DNS health.
pub const DEGRADED_FAILURE_PERCENT: usize = 20;
const DEGRADED_P95: Duration = Duration::from_millis(500);

use super::time_window::TimeWindow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsHealth {
    #[default]
    NotObserved,
    Checking,
    Responsive,
    Degraded,
    Failing,
    NoReplies,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestionStats {
    pub name: String,
    pub query_type: Option<DnsQueryType>,
    pub lookups: usize,
    pub nxdomain: usize,
    pub failures: usize,
    pub latency_p95: Option<Duration>,
}

/// Resolver endpoints are observations, not the host's configured DNS servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolverStats {
    pub address: SocketAddr,
    pub health: DnsHealth,
    pub lookups: usize,
    pub answered: usize,
    pub pending: usize,
    pub timeouts: usize,
    pub servfail: usize,
    pub refused: usize,
    pub other_rcodes: usize,
    pub retries: usize,
    pub oldest_pending: Option<Duration>,
    pub latency_p95: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsIssueKind {
    Timeout,
    Servfail,
    Refused,
    OtherResponse,
    Slow,
}

impl DnsIssueKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Timeout => "no reply",
            Self::Servfail => "SERVFAIL",
            Self::Refused => "REFUSED",
            Self::OtherResponse => "DNS error",
            Self::Slow => "slow reply",
        }
    }
}

/// Bounded evidence retained after it leaves the live health window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsIssue {
    pub resolver: SocketAddr,
    pub kind: DnsIssueKind,
    pub at: SystemTime,
    pub query_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAnalyticsSnapshot {
    pub since_clear: bool,
    pub approximate_latency: bool,
    pub slow_responses: usize,
    /// Cumulative resolver or question cardinality limits omitted detail, not totals.
    pub details_truncated: bool,
    pub window: TimeWindow,
    pub health: DnsHealth,
    pub lookups: usize,
    pub answered: usize,
    pub pending: usize,
    pub timeouts: usize,
    pub noerror: usize,
    pub nxdomain: usize,
    pub servfail: usize,
    pub refused: usize,
    pub other_rcodes: usize,
    pub nodata: usize,
    /// Operational failures among finalized lookups: timeouts plus every
    /// response other than NOERROR or NXDOMAIN.
    pub failures: usize,
    pub latency_samples: usize,
    pub latency_p50: Option<Duration>,
    pub latency_p95: Option<Duration>,
    pub latency_max: Option<Duration>,
    /// Latency buckets: below 10ms, 10ms to below 50ms, 50ms to below
    /// 100ms, and 100ms or slower.
    pub latency_buckets: [usize; 4],
    pub questions: Vec<DnsQuestionStats>,
    pub resolvers: Vec<DnsResolverStats>,
    /// Newest first, at most 64 individual observations from the last 15 minutes.
    pub recent_issues: Vec<DnsIssue>,
    /// True when tracking limits omitted evidence in the selected window.
    /// Cumulative totals ignore raw-history eviction but retain correlation-loss warnings.
    pub truncated: bool,
}

impl DnsAnalyticsSnapshot {
    pub fn window_label(&self) -> &'static str {
        self.window.label_since_clear(self.since_clear)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TransactionKey {
    connection: ConnectionKey,
    txid: u16,
}

#[derive(Debug)]
struct PendingTransaction {
    sent_at: SystemTime,
    last_sent_at: SystemTime,
    retries: usize,
    query_name: Option<String>,
    query_type: Option<DnsQueryType>,
}

#[derive(Debug)]
struct CompletedTransaction {
    completed_at: SystemTime,
    resolver: SocketAddr,
    retries: usize,
    query_name: Option<String>,
    query_type: Option<DnsQueryType>,
    rcode: Option<u8>,
    nodata: bool,
    latency: Option<Duration>,
    timed_out: bool,
}

#[derive(Debug, Default)]
pub(crate) struct DnsAnalyticsTracker {
    pending: HashMap<TransactionKey, PendingTransaction>,
    completed: VecDeque<CompletedTransaction>,
    truncated_at: Option<SystemTime>,
    recent_issues: VecDeque<DnsIssue>,
    session: DnsAggregate,
}

impl DnsAnalyticsTracker {
    pub(crate) fn record_packet(
        &mut self,
        connection: ConnectionKey,
        info: &DnsInfo,
        is_outgoing: bool,
        at: SystemTime,
    ) {
        self.expire_pending(at);
        let key = TransactionKey {
            connection,
            txid: info.txid,
        };

        if is_outgoing && !info.is_response {
            let query_name = normalize_query_name(info.query_name.as_deref());
            if let Some(pending) = self.pending.get_mut(&key)
                && pending.query_name == query_name
                && pending.query_type == info.query_type
            {
                pending.last_sent_at = at;
                pending.retries = pending.retries.saturating_add(1);
                return;
            }
            if self.pending.contains_key(&key) {
                self.session.truncated = true;
                self.mark_truncated(at);
            }
            let pending = PendingTransaction {
                sent_at: at,
                last_sent_at: at,
                retries: 0,
                query_name: normalize_query_name(info.query_name.as_deref()),
                query_type: info.query_type,
            };
            if self.pending.len() < MAX_PENDING_DNS_TRANSACTIONS || self.pending.contains_key(&key)
            {
                self.pending.insert(key, pending);
            } else {
                self.session.truncated = true;
                self.mark_truncated(at);
            }
            return;
        }

        if is_outgoing || !info.is_response {
            return;
        }

        // Do not let an old reply with a reused ID finish a different question.
        if let Some(pending) = self.pending.get(&key)
            && ((pending.query_name.is_some()
                && info.query_name.is_some()
                && pending.query_name != normalize_query_name(info.query_name.as_deref()))
                || (pending.query_type.is_some()
                    && info.query_type.is_some()
                    && pending.query_type != info.query_type))
        {
            return;
        }
        let Some(mut pending) = self.pending.remove(&key) else {
            return;
        };
        if pending.query_name.is_none() {
            pending.query_name = normalize_query_name(info.query_name.as_deref());
        }
        if pending.query_type.is_none() {
            pending.query_type = info.query_type;
        }
        self.push_completed(CompletedTransaction {
            completed_at: at,
            resolver: connection.remote_addr,
            retries: pending.retries,
            query_name: pending.query_name,
            query_type: pending.query_type,
            rcode: info.rcode,
            nodata: info.nodata == Some(true),
            latency: at.duration_since(pending.sent_at).ok(),
            timed_out: false,
        });
    }

    pub(crate) fn snapshot(&mut self, now: SystemTime) -> DnsAnalyticsSnapshot {
        self.snapshot_for_window(now, TimeWindow::OneMinute)
    }

    pub(crate) fn snapshot_for_window(
        &mut self,
        now: SystemTime,
        window: TimeWindow,
    ) -> DnsAnalyticsSnapshot {
        self.expire_pending(now);
        self.prune_history(now);
        let cutoff = window
            .duration()
            .and_then(|duration| now.checked_sub(duration));
        let mut snapshot =
            if window == TimeWindow::SinceStartup {
                self.session.snapshot(now, &self.pending)
            } else {
                let mut aggregate = DnsAggregate::new(window);
                for transaction in self.completed.iter().filter(|transaction| {
                    cutoff.is_none_or(|cutoff| transaction.completed_at > cutoff)
                }) {
                    aggregate.record(transaction);
                }
                aggregate.truncated = self
                    .truncated_at
                    .is_some_and(|at| cutoff.is_none_or(|cutoff| at > cutoff));
                aggregate.snapshot(now, &self.pending)
            };
        snapshot.recent_issues = self.recent_issues.iter().rev().cloned().collect();
        snapshot
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.completed.clear();
        self.truncated_at = None;
        self.recent_issues.clear();
        self.session.clear();
    }

    fn expire_pending(&mut self, now: SystemTime) {
        let pending_cutoff = now.checked_sub(DNS_TRANSACTION_TIMEOUT);
        let expired: Vec<TransactionKey> = pending_cutoff.map_or_else(Vec::new, |cutoff| {
            self.pending
                .iter()
                .filter_map(|(key, pending)| (pending.last_sent_at <= cutoff).then_some(*key))
                .collect()
        });
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                let completed_at = pending
                    .last_sent_at
                    .checked_add(DNS_TRANSACTION_TIMEOUT)
                    .unwrap_or(now);
                self.push_completed(CompletedTransaction {
                    completed_at,
                    resolver: key.connection.remote_addr,
                    retries: pending.retries,
                    query_name: pending.query_name,
                    query_type: pending.query_type,
                    rcode: None,
                    nodata: false,
                    latency: None,
                    timed_out: true,
                });
            }
        }
    }

    // Scan retained history only when collecting a snapshot, never per packet.
    // Ingestion enforces the capacity limits even when snapshots are not requested.
    fn prune_history(&mut self, now: SystemTime) {
        if let Some(cutoff) = now.checked_sub(DNS_ISSUE_WINDOW) {
            self.recent_issues.retain(|issue| issue.at > cutoff);
        }
        let transaction_cutoff = now.checked_sub(DNS_RETENTION_WINDOW);
        if let Some(cutoff) = transaction_cutoff {
            self.completed
                .retain(|transaction| transaction.completed_at > cutoff);
            if self.truncated_at.is_some_and(|at| at <= cutoff) {
                self.truncated_at = None;
            }
        }
    }

    fn push_completed(&mut self, transaction: CompletedTransaction) {
        self.session.record(&transaction);
        let issue = if transaction.timed_out {
            Some(DnsIssueKind::Timeout)
        } else {
            match transaction.rcode {
                Some(2) => Some(DnsIssueKind::Servfail),
                Some(5) => Some(DnsIssueKind::Refused),
                Some(0 | 3) => transaction
                    .latency
                    .filter(|latency| *latency >= DEGRADED_P95)
                    .map(|_| DnsIssueKind::Slow),
                _ => Some(DnsIssueKind::OtherResponse),
            }
        };
        if let Some(kind) = issue {
            // Timeouts may be finalized together in arbitrary hash-map order.
            let issue = DnsIssue {
                resolver: transaction.resolver,
                kind,
                at: transaction.completed_at,
                query_name: transaction.query_name.clone(),
            };
            let index = self
                .recent_issues
                .partition_point(|previous| previous.at <= issue.at);
            self.recent_issues.insert(index, issue);
            if self.recent_issues.len() > MAX_DNS_ISSUES {
                self.recent_issues.pop_front();
            }
        }
        if self.completed.len() >= MAX_RETAINED_DNS_TRANSACTIONS
            && let Some(evicted) = self.completed.pop_front()
        {
            self.mark_truncated(evicted.completed_at);
        }
        self.completed.push_back(transaction);
    }

    fn mark_truncated(&mut self, at: SystemTime) {
        if self.truncated_at.is_none_or(|previous| at > previous) {
            self.truncated_at = Some(at);
        }
    }
}

fn normalize_query_name(name: Option<&str>) -> Option<String> {
    let name = name?.trim_end_matches('.');
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::Protocol;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn time(ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms)
    }

    fn connection() -> ConnectionKey {
        ConnectionKey::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        )
    }

    fn dns(
        name: &str,
        query_type: DnsQueryType,
        txid: u16,
        is_response: bool,
        rcode: Option<u8>,
    ) -> DnsInfo {
        DnsInfo {
            query_name: Some(name.to_string()),
            query_type: Some(query_type),
            response_ips: Vec::new(),
            is_response,
            txid,
            rcode,
            nodata: (is_response && rcode == Some(0)).then_some(false),
        }
    }

    fn complete(
        tracker: &mut DnsAnalyticsTracker,
        txid: u16,
        name: &str,
        rcode: u8,
        sent_ms: u64,
        latency_ms: u64,
    ) {
        let query = dns(name, DnsQueryType::A, txid, false, None);
        tracker.record_packet(connection(), &query, true, time(sent_ms));
        let response = dns(name, DnsQueryType::A, txid, true, Some(rcode));
        tracker.record_packet(connection(), &response, false, time(sent_ms + latency_ms));
    }

    #[test]
    fn repeated_socket_transactions_remain_distinct() {
        let mut tracker = DnsAnalyticsTracker::default();
        complete(&mut tracker, 1, "Example.COM.", 0, 0, 12);
        complete(&mut tracker, 2, "example.com", 3, 100, 25);

        let snapshot = tracker.snapshot(time(200));
        assert_eq!(snapshot.lookups, 2);
        assert_eq!(snapshot.answered, 2);
        assert_eq!(snapshot.noerror, 1);
        assert_eq!(snapshot.nxdomain, 1);
        assert_eq!(snapshot.latency_p50, Some(Duration::from_millis(12)));
        assert_eq!(snapshot.latency_p95, Some(Duration::from_millis(25)));
        assert_eq!(snapshot.questions.len(), 1);
        assert_eq!(snapshot.questions[0].name, "example.com");
        assert_eq!(snapshot.questions[0].lookups, 2);
        assert_eq!(snapshot.questions[0].nxdomain, 1);
        assert_eq!(snapshot.health, DnsHealth::Responsive);
    }

    #[test]
    fn retransmission_refreshes_one_logical_lookup() {
        let mut tracker = DnsAnalyticsTracker::default();
        let query = dns("example.com", DnsQueryType::AAAA, 7, false, None);
        tracker.record_packet(connection(), &query, true, time(0));
        tracker.record_packet(connection(), &query, true, time(1_000));
        let response = dns("example.com", DnsQueryType::AAAA, 7, true, Some(0));
        tracker.record_packet(connection(), &response, false, time(1_020));

        let snapshot = tracker.snapshot(time(1_100));
        assert_eq!(snapshot.lookups, 1);
        assert_eq!(snapshot.answered, 1);
        assert_eq!(snapshot.pending, 0);
    }

    #[test]
    fn three_expired_queries_report_no_replies() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 1..=3 {
            let query = dns(
                &format!("name{txid}.example"),
                DnsQueryType::A,
                txid,
                false,
                None,
            );
            tracker.record_packet(connection(), &query, true, time(0));
        }

        let snapshot = tracker.snapshot(time(10_001));
        assert_eq!(snapshot.timeouts, 3);
        assert_eq!(snapshot.health, DnsHealth::NoReplies);
    }

    #[test]
    fn operational_failures_degrade_but_nxdomain_does_not() {
        let mut degraded = DnsAnalyticsTracker::default();
        for txid in 1..=4 {
            complete(&mut degraded, txid, "ok.example", 0, u64::from(txid), 10);
        }
        complete(&mut degraded, 5, "bad.example", 2, 10, 10);
        assert_eq!(degraded.snapshot(time(100)).health, DnsHealth::Degraded);

        let mut negative = DnsAnalyticsTracker::default();
        for txid in 1..=5 {
            complete(
                &mut negative,
                txid,
                "missing.example",
                3,
                u64::from(txid),
                10,
            );
        }
        assert_eq!(negative.snapshot(time(100)).health, DnsHealth::Responsive);
    }

    #[test]
    fn completed_transactions_leave_the_rolling_window() {
        let mut tracker = DnsAnalyticsTracker::default();
        complete(&mut tracker, 1, "old.example", 0, 0, 10);
        assert_eq!(tracker.snapshot(time(1_000)).lookups, 1);
        assert_eq!(tracker.snapshot(time(60_011)).lookups, 0);
    }

    #[test]
    fn packets_expire_pending_queries_but_defer_history_cleanup_to_snapshots() {
        let mut tracker = DnsAnalyticsTracker::default();
        complete(&mut tracker, 1, "old.example", 2, 0, 10);
        tracker.record_packet(
            connection(),
            &dns("late.example", DnsQueryType::A, 2, false, None),
            true,
            time(3_600_000),
        );
        tracker.record_packet(
            connection(),
            &dns("late.example", DnsQueryType::A, 2, true, Some(0)),
            false,
            time(3_610_000),
        );

        // A late reply still times out immediately, without pruning old history.
        assert!(tracker.pending.is_empty());
        assert_eq!(tracker.completed.len(), 2);
        assert!(tracker.completed.back().unwrap().timed_out);
        assert_eq!(tracker.recent_issues.len(), 2);

        let hour = tracker.snapshot_for_window(time(3_610_000), TimeWindow::OneHour);
        assert_eq!(hour.lookups, 1);
        assert_eq!(hour.timeouts, 1);
        assert_eq!(hour.answered, 0);
        assert_eq!(hour.recent_issues.len(), 1);
        assert_eq!(tracker.completed.len(), 1);
        let session = tracker.snapshot_for_window(time(3_610_000), TimeWindow::SinceStartup);
        assert_eq!(session.lookups, 2);
        assert_eq!(session.servfail, 1);
        assert_eq!(session.timeouts, 1);
    }

    #[test]
    fn sampled_indicator_leaves_the_rolling_window() {
        let mut tracker = DnsAnalyticsTracker::default();
        tracker.mark_truncated(time(0));
        assert!(tracker.snapshot(time(1_000)).truncated);
        assert!(!tracker.snapshot(time(60_001)).truncated);
    }
    #[test]
    fn resolver_failure_is_visible_among_successful_resolvers() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 0..30 {
            complete(&mut tracker, txid, "ok.example", 0, u64::from(txid), 10);
        }
        let mut failing = connection();
        failing.remote_addr = "192.0.2.53:53".parse().unwrap();
        for txid in 0..3 {
            tracker.record_packet(
                failing,
                &dns("bad.example", DnsQueryType::A, txid, false, None),
                true,
                time(100),
            );
            tracker.record_packet(
                failing,
                &dns("bad.example", DnsQueryType::A, txid, true, Some(2)),
                false,
                time(120),
            );
        }
        let snapshot = tracker.snapshot(time(150));
        assert_eq!(snapshot.health, DnsHealth::Degraded);
        assert_eq!(snapshot.resolvers.len(), 2);
        assert_eq!(snapshot.resolvers[0].address, failing.remote_addr);
        assert_eq!(snapshot.resolvers[0].health, DnsHealth::Failing);
        assert_eq!(snapshot.resolvers[0].servfail, 3);
        assert_eq!(snapshot.resolvers[1].health, DnsHealth::Responsive);
        assert_eq!(snapshot.recent_issues.len(), 3);
    }

    #[test]
    fn retries_preserve_wait_age_and_total_lookup_latency() {
        let mut tracker = DnsAnalyticsTracker::default();
        let query = dns("slow.example", DnsQueryType::A, 1, false, None);
        for ms in [0, 5_000, 10_000] {
            tracker.record_packet(connection(), &query, true, time(ms));
        }
        let waiting = tracker.snapshot(time(15_000));
        assert_eq!(waiting.lookups, 1);
        assert_eq!(waiting.resolvers[0].retries, 2);
        assert_eq!(
            waiting.resolvers[0].oldest_pending,
            Some(Duration::from_secs(15))
        );
        tracker.record_packet(
            connection(),
            &dns("slow.example", DnsQueryType::A, 1, true, Some(0)),
            false,
            time(15_010),
        );
        let answered = tracker.snapshot(time(15_020));
        assert_eq!(answered.latency_p95, Some(Duration::from_millis(15_010)));
        assert_eq!(answered.resolvers[0].retries, 2);
        assert_eq!(answered.resolvers[0].oldest_pending, None);
        assert_eq!(answered.recent_issues[0].kind, DnsIssueKind::Slow);
    }

    #[test]
    fn retained_issues_survive_recovery_then_expire_and_clear() {
        let mut tracker = DnsAnalyticsTracker::default();
        complete(&mut tracker, 1, "bad.example", 2, 0, 10);
        complete(&mut tracker, 2, "ok.example", 0, 70_000, 10);
        let recovered = tracker.snapshot(time(70_100));
        assert_eq!(recovered.health, DnsHealth::Responsive);
        assert_eq!(recovered.servfail, 0);
        assert_eq!(recovered.recent_issues.len(), 1);
        assert_eq!(
            recovered.recent_issues[0].query_name.as_deref(),
            Some("bad.example")
        );
        assert!(tracker.snapshot(time(900_010)).recent_issues.is_empty());
        complete(&mut tracker, 3, "bad.example", 5, 901_000, 10);
        tracker.clear();
        assert_eq!(
            tracker.snapshot(time(902_000)),
            DnsAnalyticsSnapshot::default()
        );
    }

    #[test]
    fn recent_issue_history_is_bounded_and_negative_answers_are_not_failures() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 0..100 {
            complete(
                &mut tracker,
                txid,
                "bad.example",
                2,
                u64::from(txid) * 10,
                1,
            );
        }
        let snapshot = tracker.snapshot(time(1_000));
        assert_eq!(snapshot.recent_issues.len(), MAX_DNS_ISSUES);
        assert_eq!(snapshot.recent_issues[0].at, time(991));
        assert_eq!(snapshot.recent_issues.last().unwrap().at, time(361));
        tracker.clear();
        complete(&mut tracker, 1, "missing.example", 3, 2_000, 10);
        assert!(tracker.snapshot(time(2_020)).recent_issues.is_empty());
    }

    #[test]
    fn reused_id_and_mismatched_question_do_not_complete_another_lookup() {
        let mut tracker = DnsAnalyticsTracker::default();
        tracker.record_packet(
            connection(),
            &dns("old.example", DnsQueryType::A, 1, false, None),
            true,
            time(0),
        );
        tracker.record_packet(
            connection(),
            &dns("new.example", DnsQueryType::A, 1, false, None),
            true,
            time(1),
        );
        tracker.record_packet(
            connection(),
            &dns("old.example", DnsQueryType::A, 1, true, Some(2)),
            false,
            time(2),
        );
        let snapshot = tracker.snapshot(time(3));
        assert_eq!(snapshot.pending, 1);
        assert_eq!(snapshot.answered, 0);
        assert!(snapshot.truncated);
        tracker.record_packet(
            connection(),
            &dns("NEW.example.", DnsQueryType::A, 1, true, Some(0)),
            false,
            time(11),
        );
        assert_eq!(
            tracker.snapshot(time(12)).latency_p95,
            Some(Duration::from_millis(10))
        );
        assert!(
            tracker
                .snapshot_for_window(time(7_200_000), TimeWindow::SinceStartup)
                .truncated
        );
    }

    #[test]
    fn timeouts_are_retained_in_timestamp_order_after_idle_period() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 0..5 {
            tracker.record_packet(
                connection(),
                &dns("drop.example", DnsQueryType::A, txid, false, None),
                true,
                time(u64::from(txid) * 100),
            );
        }
        let snapshot = tracker.snapshot(time(90_000));
        assert_eq!(snapshot.health, DnsHealth::NotObserved);
        assert_eq!(snapshot.recent_issues.len(), 5);
        assert!(
            snapshot
                .recent_issues
                .windows(2)
                .all(|pair| pair[0].at >= pair[1].at)
        );
        assert_eq!(snapshot.recent_issues[0].at, time(10_400));
        assert!(
            snapshot
                .recent_issues
                .iter()
                .all(|issue| issue.kind == DnsIssueKind::Timeout)
        );
    }
    #[test]
    fn five_minute_evidence_survives_live_snapshots_and_expires_at_the_boundary() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 1..=3 {
            complete(&mut tracker, txid, "outage.example", 2, 0, 10);
        }
        for txid in 4..=6 {
            complete(&mut tracker, txid, "recovered.example", 0, 90_000, 20);
        }
        let live = tracker.snapshot(time(100_000));
        assert_eq!(live.health, DnsHealth::Responsive);
        assert_eq!(live.lookups, 3);
        assert_eq!(live.servfail, 0);
        assert_eq!(live.questions.len(), 1);
        assert_eq!(live.resolvers[0].servfail, 0);
        let history = tracker.snapshot_for_window(time(100_000), TimeWindow::FiveMinutes);
        assert_eq!(history.window, TimeWindow::FiveMinutes);
        assert_eq!(history.health, DnsHealth::Degraded);
        assert_eq!(history.lookups, 6);
        assert_eq!(history.servfail, 3);
        assert_eq!(history.questions.len(), 2);
        assert_eq!(history.resolvers[0].servfail, 3);
        assert_eq!(history.latency_samples, 6);
        assert_eq!(history.recent_issues, live.recent_issues);
        assert_eq!(tracker.snapshot(time(100_000)), live);
        assert_eq!(
            tracker
                .snapshot_for_window(time(300_009), TimeWindow::FiveMinutes)
                .lookups,
            6
        );
        let expired = tracker.snapshot_for_window(time(300_010), TimeWindow::FiveMinutes);
        assert_eq!(expired.lookups, 3);
        assert_eq!(expired.servfail, 0);
        assert_eq!(expired.health, DnsHealth::Responsive);
        assert_eq!(expired.recent_issues.len(), 3);
    }

    #[test]
    fn capacity_sampling_only_marks_windows_that_lost_evidence() {
        let mut tracker = DnsAnalyticsTracker::default();
        for _ in 0..MAX_RETAINED_DNS_TRANSACTIONS {
            tracker.push_completed(CompletedTransaction {
                completed_at: time(10),
                resolver: connection().remote_addr,
                retries: 0,
                query_name: None,
                query_type: None,
                rcode: Some(0),
                nodata: false,
                latency: None,
                timed_out: false,
            });
        }
        complete(&mut tracker, 1, "recent.example", 0, 90_000, 10);
        assert_eq!(tracker.completed.len(), MAX_RETAINED_DNS_TRANSACTIONS);
        let live = tracker.snapshot(time(100_000));
        assert_eq!(live.lookups, 1);
        assert!(!live.truncated);
        let history = tracker.snapshot_for_window(time(100_000), TimeWindow::FiveMinutes);
        assert_eq!(history.lookups, MAX_RETAINED_DNS_TRANSACTIONS);
        assert!(history.truncated);
        assert!(
            !tracker
                .snapshot_for_window(time(300_010), TimeWindow::FiveMinutes)
                .truncated
        );
        let hour = tracker.snapshot_for_window(time(300_010), TimeWindow::OneHour);
        assert!(hour.truncated);
        assert_eq!(hour.lookups, MAX_RETAINED_DNS_TRANSACTIONS);
        tracker.clear();
        let cleared = tracker.snapshot_for_window(time(300_011), TimeWindow::OneHour);
        assert_eq!(cleared.lookups, 0);
        assert!(cleared.resolvers.is_empty());
        assert!(cleared.recent_issues.is_empty());
    }
    #[test]
    fn one_hour_evidence_survives_short_windows_and_expires_at_the_boundary() {
        let mut tracker = DnsAnalyticsTracker::default();
        for txid in 1..=3 {
            complete(&mut tracker, txid, "earlier.example", 2, 0, 10);
        }
        let now = time(1_800_000);
        assert_eq!(tracker.snapshot(now).lookups, 0);
        assert_eq!(
            tracker
                .snapshot_for_window(now, TimeWindow::FiveMinutes)
                .lookups,
            0
        );
        let hour = tracker.snapshot_for_window(now, TimeWindow::OneHour);
        assert_eq!(hour.health, DnsHealth::Failing);
        assert_eq!(hour.lookups, 3);
        assert_eq!(hour.servfail, 3);
        assert_eq!(hour.resolvers[0].servfail, 3);
        assert_eq!(hour.questions[0].name, "earlier.example");
        assert_eq!(hour.latency_samples, 3);
        assert!(hour.recent_issues.is_empty());
        assert_eq!(
            tracker
                .snapshot_for_window(time(3_600_009), TimeWindow::OneHour)
                .lookups,
            3
        );
        let expired = tracker.snapshot_for_window(time(3_600_010), TimeWindow::OneHour);
        assert_eq!(expired.health, DnsHealth::NotObserved);
        assert_eq!(expired.lookups, 0);
        assert!(expired.resolvers.is_empty());
        assert!(expired.questions.is_empty());
        assert!(tracker.completed.is_empty());
    }
    #[test]
    fn session_totals_survive_raw_eviction_expiry_and_reset_on_clear() {
        let mut tracker = DnsAnalyticsTracker::default();
        let total = MAX_RETAINED_DNS_TRANSACTIONS + 100;
        for _ in 0..total {
            tracker.push_completed(CompletedTransaction {
                completed_at: time(10),
                resolver: connection().remote_addr,
                retries: 0,
                query_name: Some("session.example".into()),
                query_type: Some(DnsQueryType::A),
                rcode: Some(0),
                nodata: true,
                latency: Some(Duration::from_millis(10)),
                timed_out: false,
            });
        }
        assert!(tracker.snapshot(time(100)).truncated);
        let session = tracker.snapshot_for_window(time(100), TimeWindow::SinceStartup);
        assert_eq!(session.lookups, total);
        assert_eq!(session.answered, total);
        assert_eq!(session.nodata, total);
        assert_eq!(session.latency_samples, total);
        assert_eq!(session.latency_buckets, [0, total, 0, 0]);
        assert_eq!(session.questions[0].lookups, total);
        assert_eq!(session.resolvers[0].lookups, total);
        assert!(!session.truncated);
        assert!(session.approximate_latency);
        assert_eq!(session.window_label(), "since startup");
        assert_eq!(
            tracker
                .snapshot_for_window(time(7_200_000), TimeWindow::OneHour)
                .lookups,
            0
        );
        assert_eq!(
            tracker.snapshot_for_window(time(7_200_000), TimeWindow::SinceStartup),
            session
        );
        tracker.clear();
        let cleared = tracker.snapshot_for_window(time(7_200_001), TimeWindow::SinceStartup);
        assert_eq!(cleared.lookups, 0);
        assert_eq!(cleared.window_label(), "since clear");
        assert!(cleared.questions.is_empty());
        assert!(cleared.resolvers.is_empty());
        assert!(cleared.latency_p95.is_none());
    }

    #[test]
    fn session_pending_retries_and_timeouts_are_counted_once() {
        let mut tracker = DnsAnalyticsTracker::default();
        let query = dns("pending.example", DnsQueryType::A, 1, false, None);
        tracker.record_packet(connection(), &query, true, time(0));
        tracker.record_packet(connection(), &query, true, time(5_000));
        let pending = tracker.snapshot_for_window(time(6_000), TimeWindow::SinceStartup);
        assert_eq!(pending.lookups, 1);
        assert_eq!(pending.pending, 1);
        assert_eq!(pending.resolvers[0].retries, 1);
        assert_eq!(
            pending.resolvers[0].oldest_pending,
            Some(Duration::from_secs(6))
        );
        let expired = tracker.snapshot_for_window(time(16_000), TimeWindow::SinceStartup);
        assert_eq!(expired.lookups, 1);
        assert_eq!(expired.pending, 0);
        assert_eq!(expired.timeouts, 1);
        assert_eq!(expired.resolvers[0].retries, 1);
        assert_eq!(
            expired,
            tracker.snapshot_for_window(time(16_000), TimeWindow::SinceStartup)
        );
    }
}
