//! Stateful encoding runs only on the output worker, after queue replacement.

use std::time::Instant;

use super::*;
use crate::headless::INCREMENTAL_SCHEMA_VERSION;
use crate::headless::output::serialize_record;

const FULL_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(30);
const FULL_SNAPSHOT_RECORDS: u64 = 60;

#[derive(Serialize)]
struct IncrementalRecord<C> {
    sequence: u64,
    base_sequence: Option<u64>,
    removed_connection_ids: Vec<String>,
    #[serde(flatten)]
    snapshot: SnapshotEnvelope<C>,
}

// Keep homogeneous projections contiguous. Selecting a metadata mode once per
// snapshot avoids a box and an enum dispatch for every connection.
enum PreviousConnections {
    Basic(Vec<CachedConnection<ConnectionSnapshot>>),
    Full(Vec<CachedConnection<FullConnectionSnapshot>>),
}

trait IncrementalProjection: CacheableConnection + Sized {
    fn previous(state: &Option<PreviousConnections>) -> Option<&[CachedConnection<Self>]>;
    fn retain(records: Vec<CachedConnection<Self>>) -> PreviousConnections;
}

impl IncrementalProjection for ConnectionSnapshot {
    fn previous(state: &Option<PreviousConnections>) -> Option<&[CachedConnection<Self>]> {
        match state {
            Some(PreviousConnections::Basic(records)) => Some(records),
            _ => None,
        }
    }

    fn retain(records: Vec<CachedConnection<Self>>) -> PreviousConnections {
        PreviousConnections::Basic(records)
    }
}

impl IncrementalProjection for FullConnectionSnapshot {
    fn previous(state: &Option<PreviousConnections>) -> Option<&[CachedConnection<Self>]> {
        match state {
            Some(PreviousConnections::Full(records)) => Some(records),
            _ => None,
        }
    }

    fn retain(records: Vec<CachedConnection<Self>>) -> PreviousConnections {
        PreviousConnections::Full(records)
    }
}

#[derive(Default)]
pub(in crate::headless) struct IncrementalEncoder {
    // None means no complete baseline is retained. An empty baseline is valid.
    previous: Option<PreviousConnections>,
    sequence: u64,
    last_full: Option<(u64, Instant)>,
}

impl IncrementalEncoder {
    pub(in crate::headless) fn serialize(
        &mut self,
        snapshot: SnapshotEnvelope,
    ) -> anyhow::Result<Vec<u8>> {
        self.serialize_at(
            snapshot,
            Instant::now(),
            MAX_CACHED_CONNECTIONS,
            MAX_CACHED_JSON_BYTES,
        )
    }

    fn serialize_at(
        &mut self,
        mut snapshot: SnapshotEnvelope,
        now: Instant,
        max_connections: usize,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let records = std::mem::replace(
            &mut snapshot.connections,
            ConnectionSnapshots::Basic(Vec::new()),
        );
        match records {
            ConnectionSnapshots::Basic(records) => self.serialize_connections(
                snapshot.with_connections(records),
                now,
                max_connections,
                max_bytes,
            ),
            ConnectionSnapshots::Full(records) => self.serialize_connections(
                snapshot.with_connections(records),
                now,
                max_connections,
                max_bytes,
            ),
        }
    }

    fn serialize_connections<T: IncrementalProjection>(
        &mut self,
        mut snapshot: SnapshotEnvelope<Vec<T>>,
        now: Instant,
        max_connections: usize,
        max_bytes: usize,
    ) -> anyhow::Result<Vec<u8>> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("headless output sequence exhausted"))?;
        snapshot.schema_version = INCREMENTAL_SCHEMA_VERSION;
        let full = T::previous(&self.previous).is_none()
            || snapshot.runtime.shutdown.is_some()
            || self.last_full.is_none_or(|(last_sequence, time)| {
                sequence - last_sequence >= FULL_SNAPSHOT_RECORDS
                    || now.duration_since(time) >= FULL_SNAPSHOT_INTERVAL
            });

        if snapshot.connections.len() > max_connections {
            return self.full_without_baseline(snapshot, sequence, now);
        }

        let mut previous = T::previous(&self.previous).into_iter().flatten().peekable();
        let mut encoded = Vec::with_capacity(snapshot.connections.len());
        let mut updates = Vec::new();
        let mut removed = Vec::new();
        let mut bytes = 0;
        for projected in &snapshot.connections {
            // Sorted opaque IDs make both change detection and removal a linear
            // merge. Compare every exported field, including late enrichment.
            while previous
                .peek()
                .is_some_and(|entry| entry.projected.id() < projected.id())
            {
                removed.push(previous.next().unwrap().projected.id().to_owned());
            }
            let matching = if previous
                .peek()
                .is_some_and(|entry| entry.projected.id() == projected.id())
            {
                previous.next()
            } else {
                None
            };
            let unchanged = matching.filter(|entry| entry.projected == *projected);
            let json: Arc<RawValue> = match unchanged {
                Some(entry) => Arc::clone(&entry.json),
                None => Arc::from(serde_json::value::to_raw_value(projected)?),
            };
            if json.get().len() > max_bytes - bytes {
                // A partial baseline cannot safely describe removals. Send the
                // entire snapshot and retry establishing a baseline next time.
                return self.full_without_baseline(snapshot, sequence, now);
            }
            bytes += json.get().len();
            if !full && unchanged.is_none() {
                updates.push(Arc::clone(&json));
            }
            encoded.push(json);
        }
        if !full {
            removed.extend(previous.map(|entry| entry.projected.id().to_owned()));
            snapshot.record_type = "delta";
        } else {
            removed.clear();
        }

        let projected = std::mem::take(&mut snapshot.connections);
        let record = IncrementalRecord {
            sequence,
            base_sequence: (!full).then_some(self.sequence),
            removed_connection_ids: removed,
            snapshot: snapshot.with_connections(if full { &encoded } else { &updates }),
        };
        let result = serialize_record(&record)?;
        self.previous = Some(T::retain(
            projected
                .into_iter()
                .zip(encoded)
                .map(|(projected, json)| CachedConnection { projected, json })
                .collect(),
        ));
        self.sequence = sequence;
        if full {
            self.last_full = Some((sequence, now));
        }
        Ok(result)
    }

    fn full_without_baseline<T: Serialize>(
        &mut self,
        snapshot: SnapshotEnvelope<Vec<T>>,
        sequence: u64,
        now: Instant,
    ) -> anyhow::Result<Vec<u8>> {
        let result = serialize_record(&IncrementalRecord {
            sequence,
            base_sequence: None,
            removed_connection_ids: Vec::new(),
            snapshot,
        })?;
        self.previous = None;
        self.sequence = sequence;
        self.last_full = Some((sequence, now));
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
