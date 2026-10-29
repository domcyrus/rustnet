//! Bounded pending requests shared by RTT and DNS analytics.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, SystemTime};

pub(super) trait PendingStamp {
    fn stamp(&self) -> SystemTime;
}

impl PendingStamp for SystemTime {
    fn stamp(&self) -> SystemTime {
        *self
    }
}

/// New keys are dropped at capacity; existing requests can still be updated.
#[derive(Debug)]
pub(super) struct PendingTable<K, V = SystemTime> {
    pub(super) map: HashMap<K, V>,
    cap: usize,
    max_age: Duration,
}

impl<K: Eq + Hash, V: PendingStamp> PendingTable<K, V> {
    pub(super) fn new(cap: usize, max_age: Duration) -> Self {
        Self {
            map: HashMap::new(),
            cap,
            max_age,
        }
    }

    /// `None` means capacity rejected a new key; `Some(true)` means a retry.
    pub(super) fn start(&mut self, key: K, value: V) -> Option<bool> {
        let replaced = self.map.contains_key(&key);
        if self.map.len() >= self.cap && !replaced {
            return None;
        }
        self.map.insert(key, value);
        Some(replaced)
    }

    pub(super) fn complete(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    /// Expire at the timeout boundary, using capture time and moving metadata.
    pub(super) fn prune(&mut self, now: SystemTime) -> Vec<(K, V)> {
        let Some(cutoff) = now.checked_sub(self.max_age) else {
            return Vec::new();
        };
        self.map
            .extract_if(|_, value| value.stamp() <= cutoff)
            .collect()
    }

    pub(super) fn clear(&mut self) {
        self.map.clear();
    }
}
