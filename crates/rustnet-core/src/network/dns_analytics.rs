//! Bounded passive DNS transaction analytics.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

use super::types::{ConnectionKey, DnsInfo, DnsQueryType};

const DNS_ANALYTICS_WINDOW: Duration = Duration::from_secs(60);
const DNS_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_DNS_TRANSACTIONS: usize = 4096;
const MAX_RETAINED_DNS_TRANSACTIONS: usize = 8192;
/// Operational-failure share of finalized lookups that degrades DNS health.
pub const DEGRADED_FAILURE_PERCENT: usize = 20;
const DEGRADED_P95: Duration = Duration::from_millis(500);

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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsAnalyticsSnapshot {
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
    /// True when capacity pressure within the rolling window caused at least
    /// one transaction sample to be omitted or evicted.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TransactionKey {
    connection: ConnectionKey,
    txid: u16,
}

#[derive(Debug)]
struct PendingTransaction {
    sent_at: SystemTime,
    query_name: Option<String>,
    query_type: Option<DnsQueryType>,
}

#[derive(Debug)]
struct CompletedTransaction {
    completed_at: SystemTime,
    query_name: Option<String>,
    query_type: Option<DnsQueryType>,
    rcode: Option<u8>,
    nodata: bool,
    latency: Option<Duration>,
    timed_out: bool,
}

impl CompletedTransaction {
    fn is_normal_response(&self) -> bool {
        !self.timed_out && matches!(self.rcode, Some(0 | 3))
    }

    fn is_failure(&self) -> bool {
        !self.is_normal_response()
    }
}

#[derive(Debug, Default)]
struct QuestionAggregate {
    lookups: usize,
    nxdomain: usize,
    failures: usize,
    latencies: Vec<Duration>,
}

#[derive(Debug, Default)]
pub(crate) struct DnsAnalyticsTracker {
    pending: HashMap<TransactionKey, PendingTransaction>,
    completed: VecDeque<CompletedTransaction>,
    truncated_at: Option<SystemTime>,
}

impl DnsAnalyticsTracker {
    pub(crate) fn record_packet(
        &mut self,
        connection: ConnectionKey,
        info: &DnsInfo,
        is_outgoing: bool,
        at: SystemTime,
        latency: Option<Duration>,
    ) {
        self.advance(at);
        let key = TransactionKey {
            connection,
            txid: info.txid,
        };

        if is_outgoing && !info.is_response {
            let pending = PendingTransaction {
                sent_at: at,
                query_name: normalize_query_name(info.query_name.as_deref()),
                query_type: info.query_type,
            };
            if self.pending.len() < MAX_PENDING_DNS_TRANSACTIONS || self.pending.contains_key(&key)
            {
                self.pending.insert(key, pending);
            } else {
                self.mark_truncated(at);
            }
            return;
        }

        if is_outgoing || !info.is_response {
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
            query_name: pending.query_name,
            query_type: pending.query_type,
            rcode: info.rcode,
            nodata: info.nodata == Some(true),
            latency,
            timed_out: false,
        });
    }

    pub(crate) fn snapshot(&mut self, now: SystemTime) -> DnsAnalyticsSnapshot {
        self.advance(now);

        let mut snapshot = DnsAnalyticsSnapshot {
            pending: self.pending.len(),
            truncated: self.truncated_at.is_some(),
            ..DnsAnalyticsSnapshot::default()
        };
        let mut latencies = Vec::new();
        let mut questions: HashMap<(String, Option<DnsQueryType>), QuestionAggregate> =
            HashMap::new();
        let mut normal_responses = 0usize;
        let mut failures = 0usize;

        for transaction in &self.completed {
            if transaction.timed_out {
                snapshot.timeouts += 1;
            } else {
                snapshot.answered += 1;
                match transaction.rcode {
                    Some(0) => snapshot.noerror += 1,
                    Some(2) => snapshot.servfail += 1,
                    Some(3) => snapshot.nxdomain += 1,
                    Some(5) => snapshot.refused += 1,
                    _ => snapshot.other_rcodes += 1,
                }
                if transaction.nodata {
                    snapshot.nodata += 1;
                }
            }

            if transaction.is_normal_response() {
                normal_responses += 1;
            } else {
                failures += 1;
            }

            if let Some(latency) = transaction.latency {
                latencies.push(latency);
                let bucket = if latency < Duration::from_millis(10) {
                    0
                } else if latency < Duration::from_millis(50) {
                    1
                } else if latency < Duration::from_millis(100) {
                    2
                } else {
                    3
                };
                snapshot.latency_buckets[bucket] += 1;
            }

            if let Some(name) = &transaction.query_name {
                let aggregate = questions
                    .entry((name.clone(), transaction.query_type))
                    .or_default();
                aggregate.lookups += 1;
                if transaction.rcode == Some(3) {
                    aggregate.nxdomain += 1;
                }
                if transaction.is_failure() {
                    aggregate.failures += 1;
                }
                if let Some(latency) = transaction.latency {
                    aggregate.latencies.push(latency);
                }
            }
        }

        snapshot.lookups = self.completed.len() + snapshot.pending;
        snapshot.failures = failures;
        latencies.sort_unstable();
        snapshot.latency_samples = latencies.len();
        snapshot.latency_p50 = percentile(&latencies, 50);
        snapshot.latency_p95 = percentile(&latencies, 95);
        snapshot.latency_max = latencies.last().copied();

        snapshot.questions = questions
            .into_iter()
            .map(|((name, query_type), mut aggregate)| {
                aggregate.latencies.sort_unstable();
                DnsQuestionStats {
                    name,
                    query_type,
                    lookups: aggregate.lookups,
                    nxdomain: aggregate.nxdomain,
                    failures: aggregate.failures,
                    latency_p95: percentile(&aggregate.latencies, 95),
                }
            })
            .collect();
        snapshot.questions.sort_unstable_by(|a, b| {
            b.lookups
                .cmp(&a.lookups)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| {
                    a.query_type
                        .map(|value| value.to_string())
                        .cmp(&b.query_type.map(|value| value.to_string()))
                })
        });

        snapshot.health = classify_health(HealthInputs {
            lookups: snapshot.lookups,
            pending: snapshot.pending,
            finalized: self.completed.len(),
            answered: snapshot.answered,
            timeouts: snapshot.timeouts,
            normal_responses,
            failures,
            latency_samples: snapshot.latency_samples,
            latency_p95: snapshot.latency_p95,
        });
        snapshot
    }

    pub(crate) fn clear(&mut self) {
        self.pending.clear();
        self.completed.clear();
        self.truncated_at = None;
    }

    fn advance(&mut self, now: SystemTime) {
        let pending_cutoff = now.checked_sub(DNS_TRANSACTION_TIMEOUT);
        let expired: Vec<TransactionKey> = pending_cutoff.map_or_else(Vec::new, |cutoff| {
            self.pending
                .iter()
                .filter_map(|(key, pending)| (pending.sent_at <= cutoff).then_some(*key))
                .collect()
        });
        for key in expired {
            if let Some(pending) = self.pending.remove(&key) {
                let completed_at = pending
                    .sent_at
                    .checked_add(DNS_TRANSACTION_TIMEOUT)
                    .unwrap_or(now);
                self.push_completed(CompletedTransaction {
                    completed_at,
                    query_name: pending.query_name,
                    query_type: pending.query_type,
                    rcode: None,
                    nodata: false,
                    latency: None,
                    timed_out: true,
                });
            }
        }

        let transaction_cutoff = now.checked_sub(DNS_ANALYTICS_WINDOW);
        if let Some(cutoff) = transaction_cutoff {
            self.completed
                .retain(|transaction| transaction.completed_at > cutoff);
            if self.truncated_at.is_some_and(|at| at <= cutoff) {
                self.truncated_at = None;
            }
        }
    }

    fn push_completed(&mut self, transaction: CompletedTransaction) {
        if self.completed.len() >= MAX_RETAINED_DNS_TRANSACTIONS {
            self.completed.pop_front();
            self.mark_truncated(transaction.completed_at);
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

fn percentile(sorted: &[Duration], percent: usize) -> Option<Duration> {
    if sorted.is_empty() {
        return None;
    }
    let rank = sorted
        .len()
        .saturating_mul(percent)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1);
    sorted.get(rank).copied()
}

struct HealthInputs {
    lookups: usize,
    pending: usize,
    finalized: usize,
    answered: usize,
    timeouts: usize,
    normal_responses: usize,
    failures: usize,
    latency_samples: usize,
    latency_p95: Option<Duration>,
}

fn classify_health(inputs: HealthInputs) -> DnsHealth {
    if inputs.lookups == 0 {
        return DnsHealth::NotObserved;
    }
    if inputs.answered == 0 && inputs.timeouts >= 3 {
        return DnsHealth::NoReplies;
    }
    if inputs.finalized >= 3 && inputs.normal_responses == 0 {
        return DnsHealth::Failing;
    }
    let failure_degraded = inputs.finalized >= 5
        && inputs.failures.saturating_mul(100)
            >= inputs.finalized.saturating_mul(DEGRADED_FAILURE_PERCENT);
    let latency_degraded =
        inputs.latency_samples >= 5 && inputs.latency_p95.is_some_and(|p95| p95 >= DEGRADED_P95);
    if inputs.normal_responses > 0 && (failure_degraded || latency_degraded) {
        return DnsHealth::Degraded;
    }
    if inputs.normal_responses > 0 {
        return DnsHealth::Responsive;
    }
    if inputs.pending > 0 || inputs.finalized < 3 {
        return DnsHealth::Checking;
    }
    DnsHealth::Failing
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
        tracker.record_packet(connection(), &query, true, time(sent_ms), None);
        let response = dns(name, DnsQueryType::A, txid, true, Some(rcode));
        tracker.record_packet(
            connection(),
            &response,
            false,
            time(sent_ms + latency_ms),
            Some(Duration::from_millis(latency_ms)),
        );
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
        tracker.record_packet(connection(), &query, true, time(0), None);
        tracker.record_packet(connection(), &query, true, time(1_000), None);
        let response = dns("example.com", DnsQueryType::AAAA, 7, true, Some(0));
        tracker.record_packet(
            connection(),
            &response,
            false,
            time(1_020),
            Some(Duration::from_millis(20)),
        );

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
            tracker.record_packet(connection(), &query, true, time(0), None);
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
    fn sampled_indicator_leaves_the_rolling_window() {
        let mut tracker = DnsAnalyticsTracker::default();
        tracker.mark_truncated(time(0));
        assert!(tracker.snapshot(time(1_000)).truncated);
        assert!(!tracker.snapshot(time(60_001)).truncated);
    }
}
