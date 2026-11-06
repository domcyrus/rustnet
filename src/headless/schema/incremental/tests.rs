use std::collections::BTreeMap;

use super::*;
use crate::headless::tests::app_with_connections;
use serde_json::Value;

// Deliberately reconstruct from wire JSON, without using encoder internals.
#[derive(Default)]
struct Consumer {
    sequence: Option<u64>,
    connections: BTreeMap<String, Value>,
}

impl Consumer {
    fn apply(&mut self, record: &Value) -> Option<Value> {
        assert_eq!(record["schema_version"], INCREMENTAL_SCHEMA_VERSION);
        let sequence = record["sequence"].as_u64().unwrap();
        match record["type"].as_str().unwrap() {
            "snapshot" => {
                assert!(record["base_sequence"].is_null());
                assert!(
                    record["removed_connection_ids"]
                        .as_array()
                        .unwrap()
                        .is_empty()
                );
                self.connections.clear();
            }
            "delta" => {
                if self.sequence != record["base_sequence"].as_u64()
                    || self.sequence.and_then(|last| last.checked_add(1)) != Some(sequence)
                {
                    self.sequence = None;
                    return None;
                }
                for id in record["removed_connection_ids"].as_array().unwrap() {
                    assert!(self.connections.remove(id.as_str().unwrap()).is_some());
                }
            }
            kind => panic!("unexpected record type: {kind}"),
        }
        for connection in record["connections"].as_array().unwrap() {
            self.connections.insert(
                connection["id"].as_str().unwrap().into(),
                connection.clone(),
            );
        }
        assert_eq!(record["connection_count"], self.connections.len());
        self.sequence = Some(sequence);
        let mut snapshot = record.clone();
        let object = snapshot.as_object_mut().unwrap();
        for key in ["sequence", "base_sequence", "removed_connection_ids"] {
            object.remove(key);
        }
        snapshot["schema_version"] = SCHEMA_VERSION.into();
        snapshot["type"] = "snapshot".into();
        snapshot["connections"] = self.connections.values().cloned().collect();
        Some(snapshot)
    }
}

fn snapshot(app: &App) -> SnapshotEnvelope {
    SnapshotEnvelope::new(app, None, RuntimePhase::Running, None, None).1
}

fn assert_reconstructs(
    encoder: &mut IncrementalEncoder,
    consumer: &mut Consumer,
    snapshot: SnapshotEnvelope,
    now: Instant,
) -> Value {
    let expected = serde_json::to_value(&snapshot).unwrap();
    let bytes = encoder
        .serialize_at(snapshot, now, MAX_CACHED_CONNECTIONS, MAX_CACHED_JSON_BYTES)
        .unwrap();
    let record = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(consumer.apply(&record).unwrap(), expected);
    record
}

#[test]
fn reconstructs_updates_archival_late_metadata_eviction_and_tuple_reuse() {
    let app = app_with_connections();
    let now = Instant::now();
    let mut encoder = IncrementalEncoder::default();
    let mut consumer = Consumer::default();
    assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
    let original = Arc::clone(&encoder.previous.as_ref().unwrap()[0].json);
    let unchanged = assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
    assert_eq!(unchanged["type"], "delta");
    assert_eq!(unchanged["connections"], serde_json::json!([]));
    assert!(Arc::ptr_eq(
        &original,
        &encoder.previous.as_ref().unwrap()[0].json
    ));

    for iteration in 0..150 {
        let mut record = snapshot(&app);
        record.runtime.snapshot_generation += iteration * 3;
        record.stats.packets_captured += iteration;
        record.stats.bytes_captured += iteration * 100;
        if iteration > 5 {
            record.connections[0].historic = true;
            record.connections[0].closed_at = Some("2026-01-01T00:00:00Z".into());
            record.connections[0].traffic.bytes_received = 500;
        }
        if iteration > 10 {
            record.connections[0].hostname = Some("late.example".into());
            record.connections[0].process.as_mut().unwrap().name = Some("late process".into());
            record.connections[0].geoip = Some(GeoIpSnapshot {
                country_code: Some("CH".into()),
                country_name: None,
                asn: Some(64512),
                as_org: None,
                city: None,
                postal_code: None,
            });
        }
        record.connections[1].traffic.bytes_sent += iteration;
        record.connections[1].traffic.outgoing_bytes_per_second =
            finite(if iteration % 2 == 0 { 0.0 } else { -0.0 });
        if iteration > 20 {
            record.connections[1].id.push_str("-new-lifetime");
        }
        if iteration > 25 {
            record.connections.remove(0);
            record.filter = Some("process:resolver".into());
        }
        if iteration > 40 {
            record.connections.clear();
        }
        record.connection_count = record.connections.len();
        assert_reconstructs(&mut encoder, &mut consumer, record, now);
    }
}

#[test]
fn dropped_duplicate_or_out_of_order_records_require_a_full_resynchronization() {
    let app = app_with_connections();
    let now = Instant::now();
    let mut encoder = IncrementalEncoder::default();
    let mut consumer = Consumer::default();
    let initial = assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
    let encode = |encoder: &mut IncrementalEncoder, now| {
        serde_json::from_slice::<Value>(
            &encoder
                .serialize_at(snapshot(&app), now, 10, 100_000)
                .unwrap(),
        )
        .unwrap()
    };
    let missed = encode(&mut encoder, now);
    let after_gap = encode(&mut encoder, now);
    assert!(consumer.apply(&after_gap).is_none());
    assert!(consumer.apply(&missed).is_none());
    let full = encode(&mut encoder, now + FULL_SNAPSHOT_INTERVAL);
    assert_eq!(full["type"], "snapshot");
    assert!(consumer.apply(&full).is_some());

    let delta = encode(&mut encoder, now + FULL_SNAPSHOT_INTERVAL);
    assert!(consumer.apply(&delta).is_some());
    assert!(consumer.apply(&delta).is_none());
    // A new process/pipe starts a new stream, with its own initial snapshot.
    consumer = Consumer::default();
    assert!(consumer.apply(&delta).is_none());
    assert!(consumer.apply(&initial).is_some());
}

#[test]
fn full_snapshots_are_periodic_and_terminal_is_self_contained() {
    let app = app_with_connections();
    let now = Instant::now();
    let mut encoder = IncrementalEncoder::default();
    let mut consumer = Consumer::default();
    for sequence in 1..=FULL_SNAPSHOT_RECORDS + 1 {
        let record = assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
        assert_eq!(record["sequence"], sequence);
        assert_eq!(
            record["type"] == "snapshot",
            sequence == 1 || sequence == FULL_SNAPSHOT_RECORDS + 1
        );
    }
    let mut terminal = SnapshotEnvelope::new(
        &app,
        None,
        RuntimePhase::StoppedWithErrors,
        Some(TerminationReason::RuntimeFailed),
        Some(StopReport::default()),
    )
    .1;
    terminal.connections[0].traffic.bytes_received += 77;
    terminal.stats.bytes_captured += 77;
    let expected = serde_json::to_value(&terminal).unwrap();
    let record = assert_reconstructs(&mut encoder, &mut consumer, terminal, now);
    assert_eq!(record["type"], "snapshot");
    assert_eq!(Consumer::default().apply(&record).unwrap(), expected);
}

#[test]
fn limits_fall_back_to_complete_snapshots_and_resume_deltas_when_state_fits() {
    let app = app_with_connections();
    let now = Instant::now();
    for (max_connections, max_bytes) in [(0, usize::MAX), (1, usize::MAX), (10, 1), (10, 1_500)] {
        let mut encoder = IncrementalEncoder::default();
        let mut consumer = Consumer::default();
        assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
        for _ in 0..2 {
            let snapshot = snapshot(&app);
            let expected = serde_json::to_value(&snapshot).unwrap();
            let record: Value = serde_json::from_slice(
                &encoder
                    .serialize_at(snapshot, now, max_connections, max_bytes)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(record["type"], "snapshot");
            assert_eq!(consumer.apply(&record).unwrap(), expected);
            assert!(encoder.previous.is_none());
        }
        let full = assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
        assert_eq!(full["type"], "snapshot");
        let delta = assert_reconstructs(&mut encoder, &mut consumer, snapshot(&app), now);
        assert_eq!(delta["type"], "delta");
    }
}
