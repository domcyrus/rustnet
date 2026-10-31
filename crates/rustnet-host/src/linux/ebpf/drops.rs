//! Bounded typed drop observations. All events remain at Host scope initially.
use crate::{DropObservation, DropReasonCount, DropSnapshot};
use anyhow::{Context, Result, ensure};
use libbpf_rs::{
    Btf, Link, MapCore, MapFlags, Object, ObjectBuilder, RingBuffer, RingBufferBuilder,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const DRAIN_LIMIT: usize = 4096;
const REASON_LIMIT: usize = 256;
const RECENT_LIMIT: usize = 32;

pub(in crate::linux) struct DropCollector {
    ring: RingBuffer<'static>,
    _link: Link,
    object: Object,
    snapshot: Arc<Mutex<DropSnapshot>>,
}

impl DropCollector {
    pub(in crate::linux) fn load() -> Result<Self> {
        let btf = Btf::from_vmlinux()?;
        let reasons = btf
            .type_by_name::<libbpf_rs::btf::types::Enum<'_>>("skb_drop_reason")
            .context("kernel drop reasons unavailable")?;
        let names: HashMap<_, _> = reasons
            .iter()
            .filter_map(|r| {
                Some((
                    u32::try_from(r.value).ok()?,
                    r.name?.to_string_lossy().into_owned(),
                ))
            })
            .collect();
        let mut clock = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // CLOCK_MONOTONIC is the clock used by bpf_ktime_get_ns.
        ensure!(
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } == 0,
            "read monotonic clock"
        );
        let boot = SystemTime::now()
            .checked_sub(Duration::new(clock.tv_sec as u64, clock.tv_nsec as u32))
            .context("invalid monotonic clock")?;
        let object = ObjectBuilder::default()
            .open_memory(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/socket_tracker_drops.bpf.o"
            )))?
            .load()
            .context("load typed drop collector")?;
        let snapshot = Arc::new(Mutex::new(DropSnapshot::default()));
        let events = object
            .maps()
            .find(|map| map.name() == "drop_events")
            .context("missing drop event map")?;
        let shared = Arc::clone(&snapshot);
        let mut builder = RingBufferBuilder::new();
        builder.add(&events, move |bytes| {
            let mut snapshot = shared.lock().expect("drop snapshot lock poisoned");
            record(&mut snapshot, bytes, boot, &names);
            0
        })?;
        let ring = builder.build()?;
        let link = object
            .progs_mut()
            .next()
            .context("missing drop program")?
            .attach_trace()
            .context("attach typed drop collector")?;
        Ok(Self {
            ring,
            _link: link,
            object,
            snapshot,
        })
    }

    pub(in crate::linux) fn sample(&self) -> Result<Arc<DropSnapshot>> {
        let consumed = self.ring.consume_raw_n(DRAIN_LIMIT);
        ensure!(consumed >= 0, "consume drop events: {consumed}");
        let loss = self
            .object
            .maps()
            .find(|map| map.name() == "delivery_loss")
            .context("missing delivery loss map")?
            .lookup(&0_u32.to_ne_bytes(), MapFlags::ANY)?
            .context("missing delivery loss counter")?;
        let mut snapshot = self.snapshot.lock().expect("drop snapshot lock poisoned");
        snapshot.delivery_lost = u64::from_ne_bytes(loss.as_slice().try_into()?);
        snapshot.sampled_at = Some(SystemTime::now());
        snapshot.backlog_possible = consumed as usize == DRAIN_LIMIT;
        Ok(Arc::new(snapshot.clone()))
    }
}

fn record(
    snapshot: &mut DropSnapshot,
    bytes: &[u8],
    boot: SystemTime,
    names: &HashMap<u32, String>,
) {
    let Ok(bytes) = <&[u8; 16]>::try_from(bytes) else {
        snapshot.malformed = snapshot.malformed.saturating_add(1);
        return;
    };
    let reason = u32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    if !snapshot.counts.contains_key(&reason) && snapshot.counts.len() >= REASON_LIMIT {
        snapshot.malformed = snapshot.malformed.saturating_add(1);
        return;
    }
    let count = snapshot
        .counts
        .entry(reason)
        .or_insert_with(|| DropReasonCount {
            reason: names
                .get(&reason)
                .cloned()
                .unwrap_or_else(|| format!("Unknown native reason {reason}")),
            events: 0,
        });
    count.events = count.events.saturating_add(1);
    let Some(observed_at) = boot.checked_add(Duration::from_nanos(u64::from_ne_bytes(
        bytes[..8].try_into().unwrap(),
    ))) else {
        return;
    };
    if snapshot.recent.len() == RECENT_LIMIT {
        snapshot.recent.pop_front();
    }
    snapshot.recent.push_back(DropObservation {
        observed_at,
        reason,
        ifindex: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_reasons_and_bounded_history_are_preserved() {
        let mut snapshot = DropSnapshot::default();
        let mut bytes = [0; 16];
        bytes[8..12].copy_from_slice(&42_u32.to_ne_bytes());
        for _ in 0..100 {
            record(
                &mut snapshot,
                &bytes,
                SystemTime::UNIX_EPOCH,
                &HashMap::new(),
            );
        }
        assert_eq!(snapshot.counts[&42].events, 100);
        assert_eq!(snapshot.counts[&42].reason, "Unknown native reason 42");
        assert_eq!(snapshot.recent.len(), RECENT_LIMIT);
        record(&mut snapshot, &[0], SystemTime::UNIX_EPOCH, &HashMap::new());
        assert_eq!(snapshot.malformed, 1);
    }
}
