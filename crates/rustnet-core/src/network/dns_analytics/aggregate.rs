//! Shared DNS aggregation for bounded rolling samples and cumulative history.

use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use super::{
    CompletedTransaction, DEGRADED_FAILURE_PERCENT, DEGRADED_P95, DnsAnalyticsSnapshot, DnsHealth,
    DnsQueryType, DnsQuestionStats, DnsResolverStats, PendingTransaction, TimeWindow,
    TransactionKey,
};

const MAX_SESSION_QUESTIONS: usize = 1024;
const MAX_SESSION_RESOLVERS: usize = 128;
const LATENCY_BOUNDS: [u64; 128] = latency_bounds();

// Four buckets per power of two in microseconds, followed by an overflow bucket.
const fn latency_bounds() -> [u64; 128] {
    let mut bounds = [0; 128];
    let mut index = 0;
    while index < bounds.len() {
        bounds[index] = (1u64 << (index / 4)) * (5 + index as u64 % 4) / 4;
        index += 1;
    }
    bounds
}

#[derive(Debug)]
enum LatencyDistribution {
    Exact(Vec<Duration>),
    Histogram(Box<[usize; 129]>),
}

#[derive(Debug)]
struct LatencyStats {
    distribution: LatencyDistribution,
    samples: usize,
    slow: usize,
    buckets: [usize; 4],
    max: Option<Duration>,
}

impl Default for LatencyStats {
    fn default() -> Self {
        Self {
            distribution: LatencyDistribution::Exact(Vec::new()),
            samples: 0,
            slow: 0,
            buckets: [0; 4],
            max: None,
        }
    }
}

impl LatencyStats {
    fn new(window: TimeWindow) -> Self {
        Self {
            distribution: if window == TimeWindow::SinceStartup {
                LatencyDistribution::Histogram(Box::new([0; 129]))
            } else {
                LatencyDistribution::Exact(Vec::new())
            },
            ..Self::default()
        }
    }

    fn record(&mut self, latency: Duration) {
        match &mut self.distribution {
            LatencyDistribution::Exact(samples) => samples.push(latency),
            LatencyDistribution::Histogram(counts) => {
                let index =
                    LATENCY_BOUNDS.partition_point(|upper| Duration::from_micros(*upper) < latency);
                counts[index] = counts[index].saturating_add(1);
            }
        }
        self.samples = self.samples.saturating_add(1);
        if latency >= DEGRADED_P95 {
            self.slow = self.slow.saturating_add(1);
        }
        let bucket = if latency < Duration::from_millis(10) {
            0
        } else if latency < Duration::from_millis(50) {
            1
        } else if latency < Duration::from_millis(100) {
            2
        } else {
            3
        };
        self.buckets[bucket] = self.buckets[bucket].saturating_add(1);
        self.max = self.max.max(Some(latency));
    }

    fn prepare(&mut self) {
        if let LatencyDistribution::Exact(samples) = &mut self.distribution {
            samples.sort_unstable();
        }
    }

    fn rank(&self, percent: usize) -> usize {
        (self.samples / 100) * percent + ((self.samples % 100) * percent).div_ceil(100)
    }

    fn percentile(&self, percent: usize) -> Option<Duration> {
        if self.samples == 0 {
            return None;
        }
        let counts = match &self.distribution {
            LatencyDistribution::Exact(samples) => return percentile(samples, percent),
            LatencyDistribution::Histogram(counts) => counts,
        };
        let rank = self.rank(percent);
        let mut count = 0usize;
        for (index, bucket) in counts.iter().enumerate() {
            count = count.saturating_add(*bucket);
            if count >= rank {
                let maximum = self.max?;
                return Some(
                    LATENCY_BOUNDS
                        .get(index)
                        .map_or(maximum, |upper| Duration::from_micros(*upper).min(maximum)),
                );
            }
        }
        self.max
    }

    fn p95_is_slow(&self) -> bool {
        // Health uses exact threshold counts, never rounded histogram bounds.
        self.samples > 0 && self.samples.saturating_sub(self.slow) < self.rank(95)
    }
}

#[derive(Debug, Default)]
struct Aggregate {
    answered: usize,
    timeouts: usize,
    noerror: usize,
    nxdomain: usize,
    servfail: usize,
    refused: usize,
    other_rcodes: usize,
    nodata: usize,
    retries: usize,
    latency: LatencyStats,
}

impl Aggregate {
    fn new(window: TimeWindow) -> Self {
        Self {
            latency: LatencyStats::new(window),
            ..Self::default()
        }
    }

    fn record(&mut self, transaction: &CompletedTransaction) {
        self.retries = self.retries.saturating_add(transaction.retries);
        if transaction.timed_out {
            self.timeouts = self.timeouts.saturating_add(1);
        } else {
            self.answered = self.answered.saturating_add(1);
            let counter = match transaction.rcode {
                Some(0) => &mut self.noerror,
                Some(2) => &mut self.servfail,
                Some(3) => &mut self.nxdomain,
                Some(5) => &mut self.refused,
                _ => &mut self.other_rcodes,
            };
            *counter = counter.saturating_add(1);
            if transaction.nodata {
                self.nodata = self.nodata.saturating_add(1);
            }
        }
        if let Some(latency) = transaction.latency {
            self.latency.record(latency);
        }
    }

    fn finalized(&self) -> usize {
        self.answered.saturating_add(self.timeouts)
    }
    fn failures(&self) -> usize {
        self.timeouts
            .saturating_add(self.servfail)
            .saturating_add(self.refused)
            .saturating_add(self.other_rcodes)
    }
    fn health(&self, pending: usize) -> DnsHealth {
        let finalized = self.finalized();
        let normal_responses = self.noerror.saturating_add(self.nxdomain);
        if finalized == 0 && pending == 0 {
            return DnsHealth::NotObserved;
        }
        if self.answered == 0 && self.timeouts >= 3 {
            return DnsHealth::NoReplies;
        }
        if finalized >= 3 && normal_responses == 0 {
            return DnsHealth::Failing;
        }
        let failure_degraded = finalized >= 5
            && self.failures().saturating_mul(100)
                >= finalized.saturating_mul(DEGRADED_FAILURE_PERCENT);
        let latency_degraded = self.latency.samples >= 5 && self.latency.p95_is_slow();
        if normal_responses > 0 && (failure_degraded || latency_degraded) {
            return DnsHealth::Degraded;
        }
        if normal_responses > 0 {
            return DnsHealth::Responsive;
        }
        if pending > 0 || finalized < 3 {
            return DnsHealth::Checking;
        }
        DnsHealth::Failing
    }
    fn resolver(&self, address: SocketAddr) -> DnsResolverStats {
        DnsResolverStats {
            address,
            health: self.health(0),
            lookups: self.finalized(),
            answered: self.answered,
            pending: 0,
            timeouts: self.timeouts,
            servfail: self.servfail,
            refused: self.refused,
            other_rcodes: self.other_rcodes,
            retries: self.retries,
            oldest_pending: None,
            latency_p95: self.latency.percentile(95),
        }
    }
}

#[derive(Debug)]
pub(super) struct DnsAggregate {
    window: TimeWindow,
    totals: Aggregate,
    resolvers: HashMap<SocketAddr, Aggregate>,
    questions: HashMap<(String, Option<DnsQueryType>), Aggregate>,
    pub(super) truncated: bool,
    details_truncated: bool,
    since_clear: bool,
}

impl Default for DnsAggregate {
    fn default() -> Self {
        Self::new(TimeWindow::SinceStartup)
    }
}

impl DnsAggregate {
    pub(super) fn new(window: TimeWindow) -> Self {
        Self {
            window,
            totals: Aggregate::new(window),
            resolvers: HashMap::new(),
            questions: HashMap::new(),
            truncated: false,
            details_truncated: false,
            since_clear: false,
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self {
            since_clear: true,
            ..Self::default()
        };
    }

    pub(super) fn record(&mut self, transaction: &CompletedTransaction) {
        self.totals.record(transaction);
        if self.window != TimeWindow::SinceStartup
            || self.resolvers.len() < MAX_SESSION_RESOLVERS
            || self.resolvers.contains_key(&transaction.resolver)
        {
            self.resolvers
                .entry(transaction.resolver)
                .or_insert_with(|| Aggregate::new(self.window))
                .record(transaction);
        } else {
            self.details_truncated = true;
        }
        if let Some(name) = &transaction.query_name {
            let key = (name.clone(), transaction.query_type);
            if self.window != TimeWindow::SinceStartup
                || self.questions.len() < MAX_SESSION_QUESTIONS
                || self.questions.contains_key(&key)
            {
                self.questions
                    .entry(key)
                    .or_insert_with(|| Aggregate::new(self.window))
                    .record(transaction);
            } else {
                self.details_truncated = true;
            }
        }
    }

    pub(super) fn snapshot(
        &mut self,
        now: SystemTime,
        pending: &HashMap<TransactionKey, PendingTransaction>,
    ) -> DnsAnalyticsSnapshot {
        self.totals.latency.prepare();
        for aggregate in self
            .resolvers
            .values_mut()
            .chain(self.questions.values_mut())
        {
            aggregate.latency.prepare();
        }
        let totals = &self.totals;
        let mut snapshot = DnsAnalyticsSnapshot {
            window: self.window,
            since_clear: self.since_clear,
            approximate_latency: self.window == TimeWindow::SinceStartup,
            slow_responses: totals.latency.slow,
            health: totals.health(pending.len()),
            lookups: totals.finalized().saturating_add(pending.len()),
            answered: totals.answered,
            pending: pending.len(),
            timeouts: totals.timeouts,
            noerror: totals.noerror,
            nxdomain: totals.nxdomain,
            servfail: totals.servfail,
            refused: totals.refused,
            other_rcodes: totals.other_rcodes,
            nodata: totals.nodata,
            failures: totals.failures(),
            latency_samples: totals.latency.samples,
            latency_p50: totals.latency.percentile(50),
            latency_p95: totals.latency.percentile(95),
            latency_max: totals.latency.max,
            latency_buckets: totals.latency.buckets,
            truncated: self.truncated,
            details_truncated: self.details_truncated,
            ..DnsAnalyticsSnapshot::default()
        };
        let mut resolvers: HashMap<_, _> = self
            .resolvers
            .iter()
            .map(|(address, aggregate)| (*address, aggregate.resolver(*address)))
            .collect();
        for (key, query) in pending {
            let address = key.connection.remote_addr;
            // Pending-only endpoints can be shown without creating cumulative state.
            let stats = resolvers
                .entry(address)
                .or_insert_with(|| Aggregate::default().resolver(address));
            stats.pending = stats.pending.saturating_add(1);
            stats.lookups = stats.lookups.saturating_add(1);
            stats.retries = stats.retries.saturating_add(query.retries);
            stats.oldest_pending = stats
                .oldest_pending
                .max(now.duration_since(query.sent_at).ok());
            stats.health = self
                .resolvers
                .get(&address)
                .map_or(DnsHealth::Checking, |aggregate| {
                    aggregate.health(stats.pending)
                });
        }
        snapshot.resolvers = resolvers.into_values().collect();
        snapshot.resolvers.sort_unstable_by(|a, b| {
            resolver_priority(b)
                .cmp(&resolver_priority(a))
                .then_with(|| a.address.cmp(&b.address))
        });
        snapshot.questions = self
            .questions
            .iter()
            .map(|((name, query_type), aggregate)| DnsQuestionStats {
                name: name.clone(),
                query_type: *query_type,
                lookups: aggregate.finalized(),
                nxdomain: aggregate.nxdomain,
                failures: aggregate.failures(),
                latency_p95: aggregate.latency.percentile(95),
            })
            .collect();
        snapshot.questions.sort_unstable_by(|a, b| {
            b.lookups
                .cmp(&a.lookups)
                .then_with(|| a.name.cmp(&b.name))
                .then_with(|| {
                    a.query_type
                        .map(|kind| kind.to_string())
                        .cmp(&b.query_type.map(|kind| kind.to_string()))
                })
        });
        if snapshot.health == DnsHealth::Responsive
            && snapshot.resolvers.iter().any(|resolver| {
                matches!(
                    resolver.health,
                    DnsHealth::Degraded | DnsHealth::Failing | DnsHealth::NoReplies
                )
            })
        {
            snapshot.health = DnsHealth::Degraded;
        }
        snapshot
    }
}

fn resolver_priority(stats: &DnsResolverStats) -> (bool, usize, usize) {
    (
        matches!(
            stats.health,
            DnsHealth::NoReplies | DnsHealth::Failing | DnsHealth::Degraded
        ),
        stats
            .timeouts
            .saturating_add(stats.servfail)
            .saturating_add(stats.refused)
            .saturating_add(stats.other_rcodes),
        stats.retries.saturating_add(stats.pending),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction(index: usize, latency: Duration) -> CompletedTransaction {
        CompletedTransaction {
            completed_at: SystemTime::UNIX_EPOCH,
            resolver: format!("192.0.2.1:{}", index + 1).parse().unwrap(),
            retries: 0,
            query_name: Some(format!("q{index}.example")),
            query_type: Some(DnsQueryType::A),
            rcode: Some(0),
            nodata: false,
            latency: Some(latency),
            timed_out: false,
        }
    }

    #[test]
    fn rolling_detail_is_limited_by_retained_transactions_and_keeps_exact_percentiles() {
        let mut aggregate = DnsAggregate::new(TimeWindow::OneHour);
        for index in 0..=MAX_SESSION_QUESTIONS {
            aggregate.record(&transaction(index, Duration::from_micros(index as u64 + 1)));
        }
        let snapshot = aggregate.snapshot(SystemTime::UNIX_EPOCH, &HashMap::new());
        assert_eq!(snapshot.questions.len(), MAX_SESSION_QUESTIONS + 1);
        assert_eq!(snapshot.resolvers.len(), MAX_SESSION_QUESTIONS + 1);
        assert!(!snapshot.details_truncated);
        assert!(!snapshot.approximate_latency);
        assert_eq!(snapshot.latency_p50, Some(Duration::from_micros(513)));
        assert_eq!(snapshot.latency_p95, Some(Duration::from_micros(974)));
    }

    #[test]
    fn detail_caps_keep_totals_and_existing_entries_complete() {
        let mut session = DnsAggregate::default();
        for index in 0..=MAX_SESSION_QUESTIONS {
            session.record(&transaction(index, Duration::from_millis(1)));
        }
        session.record(&transaction(0, Duration::from_millis(2)));
        let snapshot = session.snapshot(SystemTime::UNIX_EPOCH, &HashMap::new());
        assert_eq!(snapshot.lookups, MAX_SESSION_QUESTIONS + 2);
        assert_eq!(snapshot.latency_samples, MAX_SESSION_QUESTIONS + 2);
        assert_eq!(snapshot.questions.len(), MAX_SESSION_QUESTIONS);
        assert_eq!(snapshot.resolvers.len(), MAX_SESSION_RESOLVERS);
        assert_eq!(snapshot.questions[0].name, "q0.example");
        assert_eq!(snapshot.questions[0].lookups, 2);
        assert!(snapshot.details_truncated);
        assert!(!snapshot.truncated);
        session.clear();
        assert!(
            !session
                .snapshot(SystemTime::UNIX_EPOCH, &HashMap::new())
                .details_truncated
        );
    }

    #[test]
    fn approximate_percentiles_do_not_create_false_slow_health() {
        let mut aggregate = Aggregate::new(TimeWindow::SinceStartup);
        for _ in 0..19 {
            aggregate.record(&transaction(0, Duration::from_millis(499)));
        }
        aggregate.record(&transaction(0, Duration::from_millis(800)));
        assert!(aggregate.latency.percentile(95).unwrap() >= DEGRADED_P95);
        assert_eq!(aggregate.health(0), DnsHealth::Responsive);
        aggregate.record(&transaction(0, Duration::from_millis(800)));
        assert_eq!(aggregate.health(0), DnsHealth::Degraded);
    }

    #[test]
    fn histogram_handles_zero_boundaries_and_overflow_without_growing() {
        assert!(LATENCY_BOUNDS.windows(2).all(|pair| pair[0] <= pair[1]));
        for latency in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_micros(1),
            Duration::from_millis(10),
            Duration::from_millis(499),
            Duration::from_millis(500),
            Duration::from_secs(7_200),
        ] {
            let mut histogram = LatencyStats::new(TimeWindow::SinceStartup);
            for _ in 0..5 {
                histogram.record(latency);
            }
            assert_eq!(histogram.samples, 5);
            let LatencyDistribution::Histogram(counts) = &histogram.distribution else {
                panic!("expected cumulative histogram")
            };
            assert_eq!(counts.iter().sum::<usize>(), 5);
            assert_eq!(histogram.percentile(50), Some(latency));
            assert_eq!(histogram.percentile(95), Some(latency));
            assert_eq!(histogram.p95_is_slow(), latency >= DEGRADED_P95);
            assert_eq!(histogram.max, Some(latency));
        }
    }
}
