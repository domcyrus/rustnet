//! Shared Host history windows and bounded counter buckets.

use std::collections::VecDeque;
use std::time::{Duration, SystemTime};

/// Selects historical evidence without changing Overview's live health window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeWindow {
    #[default]
    OneMinute,
    FiveMinutes,
    OneHour,
    SinceStartup,
}

impl TimeWindow {
    pub fn duration(self) -> Option<Duration> {
        match self {
            Self::OneMinute => Some(Duration::from_secs(60)),
            Self::FiveMinutes => Some(Duration::from_secs(5 * 60)),
            Self::OneHour => Some(Duration::from_secs(60 * 60)),
            Self::SinceStartup => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::OneMinute => "60s",
            Self::FiveMinutes => "5m",
            Self::OneHour => "1h",
            Self::SinceStartup => "since startup",
        }
    }

    pub fn next(self) -> Self {
        match self {
            Self::OneMinute => Self::FiveMinutes,
            Self::FiveMinutes => Self::OneHour,
            Self::OneHour => Self::SinceStartup,
            Self::SinceStartup => Self::OneMinute,
        }
    }

    pub fn label_since_clear(self, since_clear: bool) -> &'static str {
        if self == Self::SinceStartup && since_clear {
            "since clear"
        } else {
            self.label()
        }
    }
}

/// One-second buckets bound memory independently of packet rate. The bucket
/// containing the cutoff may remain visible for up to one extra second.
#[derive(Debug)]
pub(crate) struct CounterHistory<const N: usize> {
    buckets: VecDeque<(SystemTime, [u64; N])>,
    total: [u64; N],
    pub since_clear: bool,
}

impl<const N: usize> Default for CounterHistory<N> {
    fn default() -> Self {
        Self {
            buckets: VecDeque::new(),
            total: [0; N],
            since_clear: false,
        }
    }
}

impl<const N: usize> CounterHistory<N> {
    pub fn record(&mut self, now: SystemTime, delta: [u64; N]) {
        for (total, value) in self.total.iter_mut().zip(delta) {
            *total = total.saturating_add(value);
        }
        if delta.iter().all(|value| *value == 0) {
            return;
        }
        // Clamp clock regressions so a backwards clock cannot grow the queue.
        let now = self.buckets.back().map_or(now, |(last, _)| now.max(*last));
        while self.buckets.front().is_some_and(|(at, _)| {
            now.duration_since(*at).unwrap_or_default() >= Duration::from_secs(3601)
        }) {
            self.buckets.pop_front();
        }
        if let Some((at, counts)) = self.buckets.back_mut()
            && now.duration_since(*at).unwrap_or_default() < Duration::from_secs(1)
        {
            for (count, value) in counts.iter_mut().zip(delta) {
                *count = count.saturating_add(value);
            }
        } else {
            self.buckets.push_back((now, delta));
        }
    }

    pub fn counts(&self, now: SystemTime, window: TimeWindow) -> [u64; N] {
        let Some(duration) = window.duration() else {
            return self.total;
        };
        let mut counts = [0u64; N];
        for (at, values) in &self.buckets {
            // Keep the whole boundary bucket until its last possible event expires.
            if now.duration_since(*at).unwrap_or_default() < duration + Duration::from_secs(1) {
                for (count, value) in counts.iter_mut().zip(values) {
                    *count = count.saturating_add(*value);
                }
            }
        }
        counts
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
        self.total = [0; N];
        self.since_clear = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
    }

    #[test]
    fn windows_expire_without_losing_session_totals() {
        let mut history = CounterHistory::<2>::default();
        history.record(at(0), [2, 3]);
        history.record(at(100), [5, 7]);
        assert_eq!(history.counts(at(150), TimeWindow::OneMinute), [5, 7]);
        assert_eq!(history.counts(at(150), TimeWindow::FiveMinutes), [7, 10]);
        assert_eq!(history.counts(at(301), TimeWindow::FiveMinutes), [5, 7]);
        assert_eq!(history.counts(at(401), TimeWindow::FiveMinutes), [0, 0]);
        assert_eq!(history.counts(at(3601), TimeWindow::OneHour), [5, 7]);
        assert_eq!(history.counts(at(3701), TimeWindow::OneHour), [0, 0]);
        assert_eq!(history.counts(at(10000), TimeWindow::SinceStartup), [7, 10]);
        history.record(at(10000), [1, 1]);
        assert_eq!(history.counts(at(10000), TimeWindow::SinceStartup), [8, 11]);
        history.clear();
        assert!(history.since_clear);
        assert_eq!(history.counts(at(10000), TimeWindow::SinceStartup), [0, 0]);
    }

    #[test]
    fn buckets_preserve_boundary_events_and_stay_bounded() {
        let mut history = CounterHistory::<1>::default();
        history.record(at(0), [1]);
        history.record(at(0) + Duration::from_millis(999), [1]);
        assert_eq!(history.buckets.len(), 1);
        assert_eq!(history.counts(at(60), TimeWindow::OneMinute), [2]);
        assert_eq!(history.counts(at(61), TimeWindow::OneMinute), [0]);
        for second in 1..10000 {
            history.record(at(second), [1]);
        }
        assert_eq!(history.buckets.len(), 3601);
        for _ in 0..10000 {
            history.record(at(0), [1]);
        }
        assert_eq!(history.buckets.len(), 3601);
        assert_eq!(history.counts(at(10000), TimeWindow::SinceStartup), [20001]);
    }
}
