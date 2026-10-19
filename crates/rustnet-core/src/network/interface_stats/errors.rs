//! Observed interface error increments, independent of OS lifetime totals.

use std::collections::HashMap;
use std::time::SystemTime;

use super::InterfaceStats;
use crate::network::time_window::{CounterHistory, TimeWindow};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterfaceErrorCounts {
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
}

impl From<[u64; 5]> for InterfaceErrorCounts {
    fn from(values: [u64; 5]) -> Self {
        Self {
            rx_errors: values[0],
            tx_errors: values[1],
            rx_dropped: values[2],
            tx_dropped: values[3],
            collisions: values[4],
        }
    }
}

fn counters(stats: &InterfaceStats) -> [u64; 5] {
    [
        stats.rx_errors,
        stats.tx_errors,
        stats.rx_dropped,
        stats.tx_dropped,
        stats.collisions,
    ]
}

#[derive(Debug, Default)]
struct InterfaceHistory {
    previous: Option<[u64; 5]>,
    history: CounterHistory<5>,
}

#[derive(Debug, Default)]
pub struct InterfaceErrorTracker {
    interfaces: HashMap<String, InterfaceHistory>,
    cleared_at: Option<SystemTime>,
}

impl InterfaceErrorTracker {
    /// First observation establishes the baseline. Removed interfaces lose
    /// their history so a new device with the same name cannot inherit it.
    pub fn observe(&mut self, stats: &[InterfaceStats]) {
        self.interfaces
            .retain(|name, _| stats.iter().any(|stat| &stat.interface_name == name));
        for stat in stats {
            // A poll can finish collecting before clear and acquire this tracker
            // afterward. It must not restore a pre-clear baseline.
            if self.cleared_at.is_some_and(|at| stat.timestamp <= at) {
                continue;
            }
            let entry = self
                .interfaces
                .entry(stat.interface_name.clone())
                .or_default();
            let current = counters(stat);
            if let Some(previous) = entry.previous {
                let delta = std::array::from_fn(|index| {
                    // A decreasing OS counter starts a new counter epoch.
                    current[index]
                        .checked_sub(previous[index])
                        .unwrap_or(current[index])
                });
                entry.history.record(stat.timestamp, delta);
            }
            entry.previous = Some(current);
        }
    }

    pub fn snapshot(
        &self,
        now: SystemTime,
        window: TimeWindow,
    ) -> HashMap<String, InterfaceErrorCounts> {
        self.interfaces
            .iter()
            .map(|(name, entry)| (name.clone(), entry.history.counts(now, window).into()))
            .collect()
    }

    pub fn since_clear(&self) -> bool {
        self.cleared_at.is_some()
    }

    pub fn clear(&mut self) {
        self.clear_at(SystemTime::now());
    }

    fn clear_at(&mut self, now: SystemTime) {
        for entry in self.interfaces.values_mut() {
            entry.history.clear();
            // Establish a fresh baseline on the next poll; do not include
            // increments from the interval that straddles the clear action.
            entry.previous = None;
        }
        self.cleared_at = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn stat(seconds: u64, count: u64) -> InterfaceStats {
        InterfaceStats {
            interface_name: "test0".into(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            rx_errors: count,
            tx_errors: count * 2,
            rx_dropped: count * 3,
            tx_dropped: count * 4,
            collisions: count * 5,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        }
    }

    #[test]
    fn excludes_os_baseline_and_expires_observed_errors() {
        let mut tracker = InterfaceErrorTracker::default();
        tracker.observe(&[stat(0, 100)]);
        tracker.observe(&[stat(10, 102)]);
        tracker.observe(&[stat(100, 105)]);
        let now = stat(100, 0).timestamp;
        assert_eq!(
            tracker.snapshot(now, TimeWindow::OneMinute)["test0"],
            InterfaceErrorCounts::from([3, 6, 9, 12, 15])
        );
        assert_eq!(
            tracker.snapshot(now, TimeWindow::FiveMinutes)["test0"],
            InterfaceErrorCounts::from([5, 10, 15, 20, 25])
        );
        assert_eq!(
            tracker.snapshot(stat(4000, 0).timestamp, TimeWindow::OneHour)["test0"],
            InterfaceErrorCounts::default()
        );
        assert_eq!(
            tracker.snapshot(stat(4000, 0).timestamp, TimeWindow::SinceStartup)["test0"].rx_errors,
            5
        );
    }

    #[test]
    fn counter_reset_counts_new_epoch_and_clear_rebaselines() {
        let mut tracker = InterfaceErrorTracker::default();
        tracker.observe(&[stat(0, 100)]);
        tracker.observe(&[stat(10, 102)]);
        tracker.observe(&[stat(20, 3)]);
        assert_eq!(
            tracker.snapshot(stat(20, 0).timestamp, TimeWindow::SinceStartup)["test0"].rx_errors,
            5
        );
        tracker.clear_at(stat(20, 0).timestamp);
        assert!(tracker.since_clear());
        tracker.observe(&[stat(30, 10)]);
        tracker.observe(&[stat(40, 12)]);
        assert_eq!(
            tracker.snapshot(stat(40, 0).timestamp, TimeWindow::SinceStartup)["test0"].rx_errors,
            2
        );
    }

    #[test]
    fn clear_rejects_a_poll_collected_before_the_clear() {
        let mut tracker = InterfaceErrorTracker::default();
        tracker.observe(&[stat(0, 100)]);
        let stale = stat(5, 105);
        tracker.clear_at(stat(10, 0).timestamp);
        let fresh = stat(20, 110);
        tracker.observe(&[stale]);
        tracker.observe(std::slice::from_ref(&fresh));
        assert_eq!(
            tracker.snapshot(fresh.timestamp, TimeWindow::SinceStartup)["test0"].rx_errors,
            0
        );
    }

    #[test]
    fn reappearing_interface_establishes_new_baseline() {
        let mut tracker = InterfaceErrorTracker::default();
        tracker.observe(&[stat(0, 100)]);
        tracker.observe(&[stat(10, 105)]);
        tracker.observe(&[]);
        tracker.observe(&[stat(20, 1000)]);
        tracker.observe(&[stat(30, 1001)]);
        assert_eq!(
            tracker.snapshot(stat(30, 0).timestamp, TimeWindow::SinceStartup)["test0"].rx_errors,
            1
        );
    }
}
