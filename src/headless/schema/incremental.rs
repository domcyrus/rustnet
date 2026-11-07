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

// Keep the complete basic or full projection in the baseline so late detail
// enrichment invalidates a record even when traffic counters do not change.
#[derive(PartialEq, Serialize)]
#[serde(untagged)]
enum IncrementalConnection {
    Basic(Box<ConnectionSnapshot>),
    Full(Box<FullConnectionSnapshot>),
}
impl IncrementalConnection {
    fn id(&self) -> &str {
        match self {
            Self::Basic(record) => record.id(),
            Self::Full(record) => record.id(),
        }
    }
}

#[derive(Default)]
pub(in crate::headless) struct IncrementalEncoder {
    // None means no complete baseline is retained. An empty baseline is valid.
    previous: Option<Vec<CachedConnection<IncrementalConnection>>>,
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
        let records = match std::mem::replace(
            &mut snapshot.connections,
            ConnectionSnapshots::Basic(Vec::new()),
        ) {
            ConnectionSnapshots::Basic(records) => records
                .into_iter()
                .map(|record| IncrementalConnection::Basic(Box::new(record)))
                .collect::<Vec<_>>(),
            ConnectionSnapshots::Full(records) => records
                .into_iter()
                .map(|record| IncrementalConnection::Full(Box::new(record)))
                .collect::<Vec<_>>(),
        };
        let mut snapshot = snapshot.with_connections(records);
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("headless output sequence exhausted"))?;
        snapshot.schema_version = INCREMENTAL_SCHEMA_VERSION;
        let full = self.previous.is_none()
            || snapshot.runtime.shutdown.is_some()
            || self.last_full.is_none_or(|(last_sequence, time)| {
                sequence - last_sequence >= FULL_SNAPSHOT_RECORDS
                    || now.duration_since(time) >= FULL_SNAPSHOT_INTERVAL
            });

        if snapshot.connections.len() > max_connections {
            return self.full_without_baseline(snapshot, sequence, now);
        }

        let mut previous = self.previous.iter().flatten().peekable();
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
        self.previous = Some(
            projected
                .into_iter()
                .zip(encoded)
                .map(|(projected, json)| CachedConnection { projected, json })
                .collect(),
        );
        self.sequence = sequence;
        if full {
            self.last_full = Some((sequence, now));
        }
        Ok(result)
    }

    fn full_without_baseline(
        &mut self,
        snapshot: SnapshotEnvelope<Vec<IncrementalConnection>>,
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
