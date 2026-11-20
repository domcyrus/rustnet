//! Synthetic snapshot measurements, including the public API's mutex.
use super::tracker::ConnectionTracker;
use super::tracker_benchmarks::{packet, report, samples};
use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime};

#[test]
#[ignore = "release benchmark, run explicitly"]
fn benchmark_tcp_snapshots() {
    for sample in 0..samples() {
        for destinations in [1, 64, 8192] {
            let tracker = ConnectionTracker::new();
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
            for i in 0..8192 {
                tracker.ingest_at(&packet(i, i % destinations, 2, 10, 0), now);
                tracker.ingest_at(&packet(i, i % destinations, 20, 20, 11), now);
            }
            assert_eq!(tracker.tcp_attempt_snapshot_at(now).total.completed, 8192);
            let start = Instant::now();
            for i in 0..256 {
                black_box(tracker.tcp_attempt_snapshot_at(now + Duration::from_nanos(i)));
            }
            report(
                &format!("quiet_snapshot_{destinations}_destinations"),
                sample,
                256,
                start.elapsed(),
            );
            // Force a fresh summary every time, at capacity, including eviction.
            let start = Instant::now();
            for i in 0..256 {
                tracker.ingest_at(&packet(i, i % destinations, 2, 100, 0), now);
                tracker.ingest_at(&packet(i, i % destinations, 20, 200, 101), now);
                black_box(tracker.tcp_attempt_snapshot_at(now));
            }
            report(
                &format!("updated_snapshot_{destinations}_destinations"),
                sample,
                256,
                start.elapsed(),
            );
        }
    }
}
