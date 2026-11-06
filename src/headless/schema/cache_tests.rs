use super::*;
use crate::headless::output::serialize_record;
use crate::headless::tests::app_with_connections;

fn snapshot(app: &App) -> SnapshotEnvelope {
    let mut record = SnapshotEnvelope::new(app, None, RuntimePhase::Running, None, None).1;
    for connection in &mut record.connections {
        connection.historic = true;
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
    let original = Arc::clone(&cache.entries[0].json);
    let mut record = snapshot(&app);
    record.runtime.snapshot_generation += 1;
    record.runtime.status = "stopped";
    record.runtime.termination_reason = Some("duration_elapsed");
    record.stats.bytes_captured += 100;
    assert_matches_uncached(&mut cache, record);
    assert!(Arc::ptr_eq(&original, &cache.entries[0].json));
}

#[test]
fn archived_connections_preserve_late_metadata_and_final_counters() {
    let app = app_with_connections();
    // Each update must invalidate independently, even when counters and
    // last_activity are unchanged.
    let updates: [fn(&mut ConnectionSnapshot); 6] = [
        |connection| connection.hostname = Some("late.example".into()),
        |connection| connection.process.as_mut().unwrap().name = Some("late process".into()),
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
        let original = Arc::clone(&cache.entries[0].json);
        let mut record = snapshot(&app);
        update(&mut record.connections[0]);
        assert_matches_uncached(&mut cache, record);
        assert!(!Arc::ptr_eq(&original, &cache.entries[0].json));
    }
}

#[test]
fn filtering_clearing_and_tuple_reuse_evict_old_records() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    assert_matches_uncached(&mut cache, snapshot(&app));
    let original_ids: Vec<_> = cache
        .entries
        .iter()
        .map(|entry| entry.projected.id.clone())
        .collect();
    let mut filtered = SnapshotEnvelope::new(
        &app,
        Some("process:curl"),
        RuntimePhase::Running,
        None,
        None,
    )
    .1;
    for connection in &mut filtered.connections {
        connection.historic = true;
    }
    assert_matches_uncached(&mut cache, filtered);
    assert_eq!(cache.entries.len(), 1);

    let mut connections = app.get_connections();
    for connection in &mut connections {
        connection.created_at += Duration::from_secs(1);
    }
    app.set_connections_snapshot_for_test(connections);
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert!(
        original_ids
            .iter()
            .all(|id| !cache.entries.iter().any(|entry| &entry.projected.id == id))
    );
    app.set_connections_snapshot_for_test(vec![]);
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert!(cache.entries.is_empty());
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
            assert!(cache.entries.len() <= max_connections);
            assert!(
                cache
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
    record.connections[0].historic = false;
    assert_matches_uncached(&mut cache, record);
    assert_eq!(cache.entries.len(), 1);
    let record = SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None).1;
    assert_matches_uncached(&mut cache, record);
    assert!(cache.entries.is_empty());
    assert_matches_uncached(&mut cache, snapshot(&app));
    assert_eq!(cache.entries.len(), 2);
}

#[test]
fn signed_zero_changes_preserve_the_original_encoding() {
    let app = app_with_connections();
    let mut cache = ConnectionCache::default();
    for rate in [0.0, -0.0, 0.0] {
        let mut record = snapshot(&app);
        record.connections[0].traffic.outgoing_bytes_per_second = finite(rate);
        assert_matches_uncached(&mut cache, record);
    }
}

// Run explicitly in release mode. Measures projection plus encoding, not capture
// or whole-process CPU. Both paths use the same synthetic connection snapshots.
#[test]
#[ignore = "manual release-mode performance measurement"]
fn benchmark_history_encoding() {
    use std::hint::black_box;
    use std::time::Instant;

    let app = app_with_connections();
    app.set_show_historic(true);
    let template = app
        .get_connections()
        .into_iter()
        .find(|c| c.pid.is_some())
        .unwrap();
    const ITERATIONS: usize = 100;
    for (active, historic) in [(100, 0), (100, 1_000), (100, 5_000), (5_000, 0)] {
        let connections: Vec<_> = (0..active + historic)
            .map(|index| {
                let mut connection = template.clone();
                connection.local_addr.set_port(10_000 + index as u16);
                connection.is_historic = index >= active;
                connection.closed_at = connection.is_historic.then_some(connection.last_activity);
                connection.current_incoming_rate_bps = 0.0;
                connection.current_outgoing_rate_bps = 0.0;
                connection
            })
            .collect();
        app.set_connections_snapshot_for_test(connections);
        let mut cache = ConnectionCache::default();
        cache
            .serialize(SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None).1)
            .unwrap();
        let mut uncached_time = Duration::ZERO;
        let mut cached_time = Duration::ZERO;
        let mut payload = 0;
        for iteration in 0..ITERATIONS {
            // Alternate execution order to reduce systematic warm-up bias.
            for cached in if iteration % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let started = Instant::now();
                let mut record =
                    SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None).1;
                for connection in &mut record.connections {
                    if !connection.historic {
                        connection.traffic.bytes_sent += iteration as u64 + 1;
                        connection.traffic.outgoing_bytes_per_second =
                            finite(iteration as f64 + 1.0);
                    }
                }
                let bytes = if cached {
                    cache.serialize(record).unwrap()
                } else {
                    serialize_record(&record).unwrap()
                };
                payload = black_box(bytes).len();
                if cached {
                    cached_time += started.elapsed();
                } else {
                    uncached_time += started.elapsed();
                }
            }
        }
        eprintln!(
            "active={active} historic={historic} bytes={payload} projection+encoding uncached={:.3}ms cached={:.3}ms ratio={:.2}x",
            uncached_time.as_secs_f64() * 1_000.0 / ITERATIONS as f64,
            cached_time.as_secs_f64() * 1_000.0 / ITERATIONS as f64,
            uncached_time.as_secs_f64() / cached_time.as_secs_f64()
        );
    }
}
