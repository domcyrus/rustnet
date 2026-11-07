use super::*;
use crate::headless::output::serialize_record;
use crate::headless::tests::app_with_connections;

fn snapshot(app: &App) -> SnapshotEnvelope {
    let mut record = SnapshotEnvelope::new(app, None, RuntimePhase::Running, None, None, true).1;
    for connection in record.connections.full_mut() {
        connection.connection.historic = true;
        connection.details.lifecycle = None;
    }
    record
}

fn assert_matches_uncached(cache: &mut ConnectionCache, record: SnapshotEnvelope) {
    let expected = serialize_record(&record).unwrap();
    assert_eq!(cache.serialize(record).unwrap(), expected);
}

#[test]
fn unchanged_connections_reuse_json_but_envelope_stays_fresh() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    assert_matches_uncached(&mut cache, snapshot(&app));
    let original = Arc::clone(&cache.full.entries[0].json);
    let mut record = snapshot(&app);
    record.runtime.snapshot_generation += 1;
    record.runtime.status = "stopped";
    record.runtime.termination_reason = Some("duration_elapsed");
    record.stats.bytes_captured += 100;
    assert_matches_uncached(&mut cache, record);
    assert!(Arc::ptr_eq(&original, &cache.full.entries[0].json));
}

#[test]
fn archived_connections_preserve_late_metadata_and_final_counters() {
    let app = app_with_connections();
    // Each update must invalidate independently, even when counters and
    // last_activity are unchanged.
    let updates: [fn(&mut ConnectionSnapshot<FullProcessSnapshot>); 6] = [
        |connection| connection.hostname = Some("late.example".into()),
        |connection| {
            connection.process.as_mut().unwrap().process.name = Some("late process".into())
        },
        |connection| {
            connection.geoip = Some(GeoIpSnapshot {
                country_code: Some("CH".into()),
                country_name: None,
                asn: Some(64512),
                as_org: None,
                city: None,
                postal_code: None,
            })
        },
        |connection| connection.traffic.bytes_received += 123,
        |connection| connection.rtt.current_ms = finite(12.5),
        |connection| connection.closed_at = Some("2026-01-01T00:00:00Z".into()),
    ];
    for update in updates {
        let mut cache = ConnectionCache::default();
        assert_matches_uncached(&mut cache, snapshot(&app));
        let original = Arc::clone(&cache.full.entries[0].json);
        let mut record = snapshot(&app);
        update(&mut record.connections.full_mut()[0].connection);
        assert_matches_uncached(&mut cache, record);
        assert!(!Arc::ptr_eq(&original, &cache.full.entries[0].json));
    }
}

#[test]
fn filtering_clearing_and_tuple_reuse_evict_old_records() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    assert_matches_uncached(&mut cache, snapshot(&app));
    let original_ids: Vec<_> = cache
        .full
        .entries
        .iter()
        .map(|entry| entry.projected.connection.id.clone())
        .collect();
    let mut filtered = SnapshotEnvelope::new(
        &app,
        Some("process:curl"),
        RuntimePhase::Running,
        None,
        None,
        true,
    )
    .1;
    for connection in filtered.connections.full_mut() {
        connection.connection.historic = true;
        connection.details.lifecycle = None;
    }
    assert_matches_uncached(&mut cache, filtered);
    assert_eq!(cache.full.entries.len(), 1);

    let mut connections = app.get_connections();
    for connection in &mut connections {
        connection.created_at += Duration::from_secs(1);
    }
    app.set_connections_snapshot_for_test(connections);
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert!(original_ids.iter().all(|id| {
        !cache
            .full
            .entries
            .iter()
            .any(|entry| &entry.projected.connection.id == id)
    }));
    app.set_connections_snapshot_for_test(vec![]);
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert!(cache.full.entries.is_empty());
}

#[test]
fn cache_limits_do_not_truncate_output() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    for (max_connections, max_bytes) in [(0, usize::MAX), (1, usize::MAX), (10, 1), (10, 1_500)] {
        for _ in 0..2 {
            let record = snapshot(&app);
            let expected = serialize_record(&record).unwrap();
            assert_eq!(
                cache
                    .serialize_with_limits(record, max_connections, max_bytes)
                    .unwrap(),
                expected
            );
            assert!(cache.full.entries.len() <= max_connections);
            assert!(
                cache
                    .full
                    .entries
                    .iter()
                    .map(|entry| entry.json.get().len())
                    .sum::<usize>()
                    <= max_bytes
            );
        }
    }
}

#[test]
fn active_connections_and_transitions_keep_full_output() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    assert_matches_uncached(&mut cache, snapshot(&app));
    let mut record = snapshot(&app);
    record.connections.full_mut()[0].connection.historic = false;
    assert_matches_uncached(&mut cache, record);
    assert_eq!(cache.full.entries.len(), 1);
    let record = SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None, true).1;
    assert_matches_uncached(&mut cache, record);
    assert!(cache.full.entries.is_empty());
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert_eq!(cache.full.entries.len(), 2);
}

#[test]
fn signed_zero_changes_preserve_the_original_encoding() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    for rate in [0.0, -0.0, 0.0] {
        let mut record = snapshot(&app);
        record.connections.full_mut()[0]
            .connection
            .traffic
            .outgoing_bytes_per_second = finite(rate);
        assert_matches_uncached(&mut cache, record);
    }
}

// Run explicitly in release mode. Includes periodic full resynchronization.
// Measures projection and encoding, not capture or whole-process CPU.
#[test]
#[ignore = "manual release-mode performance measurement"]
fn benchmark_history_encoding() {
    use super::incremental::IncrementalEncoder;
    use std::hint::black_box;
    use std::time::Instant;

    let app = app_with_connections();
    app.set_show_historic(true);
    let template = app
        .get_connections()
        .into_iter()
        .find(|c| c.pid.is_some())
        .unwrap();
    let full = std::env::var_os("RUSTNET_PROFILE_FULL_DETAILS").is_some();
    const ITERATIONS: usize = 120;
    for (active, historic, metadata_bytes) in [
        (100, 0, 0),
        (100, 1_000, 0),
        (100, 5_000, 0),
        (5_000, 0, 0),
        (100, 5_000, 1_024),
        (100, 10_000, 0),
    ] {
        let connections: Vec<_> = (0..active + historic)
            .map(|index| {
                let mut connection = template.clone();
                connection.local_addr.set_port(10_000 + index as u16);
                connection.is_historic = index >= active;
                connection.closed_at = connection.is_historic.then_some(connection.last_activity);
                connection.current_incoming_rate_bps = 0.0;
                connection.current_outgoing_rate_bps = 0.0;
                if metadata_bytes > 0 {
                    connection.executable =
                        Some(std::path::PathBuf::from("x".repeat(metadata_bytes)).into());
                }
                connection
            })
            .collect();
        app.set_connections_snapshot_for_test(connections);
        let mut cache = ConnectionCache::default();
        let mut incremental = IncrementalEncoder::default();
        let snapshot =
            || SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None, full).1;
        cache.serialize(snapshot()).unwrap();
        incremental.serialize(snapshot()).unwrap();
        let mut projection_time = [Duration::ZERO; 3];
        let mut encoding_time = [Duration::ZERO; 3];
        let mut payload = [0; 3];
        for iteration in 0..ITERATIONS {
            // Rotate execution order to reduce systematic warm-up bias.
            for offset in 0..3 {
                let mode = (iteration + offset) % 3;
                let started = Instant::now();
                let mut record = snapshot();
                let update = |historic: bool, traffic: &mut TrafficSnapshot| {
                    if !historic {
                        traffic.bytes_sent += iteration as u64 + 1;
                        traffic.outgoing_bytes_per_second = finite(iteration as f64 + 1.0);
                    }
                };
                match &mut record.connections {
                    ConnectionSnapshots::Basic(records) => records
                        .iter_mut()
                        .for_each(|record| update(record.historic, &mut record.traffic)),
                    ConnectionSnapshots::Full(records) => records.iter_mut().for_each(|record| {
                        update(record.connection.historic, &mut record.connection.traffic)
                    }),
                }
                projection_time[mode] += started.elapsed();
                let started = Instant::now();
                let bytes = match mode {
                    0 => serialize_record(&record).unwrap(),
                    1 => cache.serialize(record).unwrap(),
                    _ => incremental.serialize(record).unwrap(),
                };
                payload[mode] += black_box(bytes).len();
                encoding_time[mode] += started.elapsed();
            }
        }
        for (mode, name) in ["uncached", "cached", "incremental"]
            .into_iter()
            .enumerate()
        {
            eprintln!(
                "active={active} historic={historic} metadata_bytes={metadata_bytes} mode={name} avg_bytes={} projection={:.3}ms encoding={:.3}ms total={:.3}ms",
                payload[mode] / ITERATIONS,
                projection_time[mode].as_secs_f64() * 1_000.0 / ITERATIONS as f64,
                encoding_time[mode].as_secs_f64() * 1_000.0 / ITERATIONS as f64,
                (projection_time[mode] + encoding_time[mode]).as_secs_f64() * 1_000.0
                    / ITERATIONS as f64,
            );
        }
    }
}

impl ConnectionSnapshots {
    fn full_mut(&mut self) -> &mut Vec<FullConnectionSnapshot> {
        match self {
            Self::Full(records) => records,
            Self::Basic(_) => panic!("expected full projection"),
        }
    }
}

#[test]
fn full_details_invalidate_without_base_connection_changes() {
    let app = app_with_connections();
    let updates: [fn(&mut FullConnectionSnapshot); 5] = [
        |value| value.details.network_context.remote_hostname = Some("late.example".into()),
        |value| {
            value.details.network_context.remote_mac = Some(NeighborSnapshot {
                mac: "02:00:00:00:00:01".into(),
                vendor: Some("test".into()),
            })
        },
        |value| {
            value
                .details
                .protocol_details
                .push(crate::connection_details::DetailField {
                    label: "test",
                    value: Some("late".into()),
                    warning: false,
                })
        },
        |value| value.details.request_health.quic_retries += 1,
        |value| value.connection.process.as_mut().unwrap().user_group = Some("user:group".into()),
    ];
    for update in updates {
        let mut cache = ConnectionCache::default();
        assert_matches_uncached(&mut cache, snapshot(&app));
        let original = Arc::clone(&cache.full.entries[0].json);
        let mut record = snapshot(&app);
        update(&mut record.connections.full_mut()[0]);
        assert_matches_uncached(&mut cache, record);
        assert!(!Arc::ptr_eq(&original, &cache.full.entries[0].json));
    }
}

#[test]
fn basic_and_full_modes_preserve_their_wire_shapes() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    for full in [false, true, false] {
        let mut record =
            SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None, full).1;
        match &mut record.connections {
            ConnectionSnapshots::Full(records) => {
                for value in records {
                    value.connection.historic = true;
                    value.details.lifecycle = None;
                }
            }
            ConnectionSnapshots::Basic(records) => {
                for value in records {
                    value.historic = true;
                }
            }
        }
        assert_matches_uncached(&mut cache, record);
        assert_eq!(cache.basic.entries.len(), if full { 0 } else { 2 });
        assert_eq!(cache.full.entries.len(), if full { 2 } else { 0 });
    }
}
