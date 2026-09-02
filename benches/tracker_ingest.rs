use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustnet_monitor::network::parser::ParsedPacket;
use rustnet_monitor::network::tracker::ConnectionTracker;
use std::time::SystemTime;

mod common;

/// Interleaved packet stream: `flows` connections sending `packets_per_flow`
/// packets round-robin, mimicking concurrent flows rather than one flow at a
/// time.
fn make_workload(flows: u16, packets_per_flow: u32) -> Vec<ParsedPacket> {
    let mut packets = Vec::with_capacity(flows as usize * packets_per_flow as usize);
    for round in 0..packets_per_flow {
        for flow in 0..flows {
            packets.push(common::make_packet(10000 + flow, round * 1460));
        }
    }
    packets
}

/// The canonical per-packet ingest cost: parse results folded into a fresh
/// tracker (mix of connection creation and in-place merge). This is the
/// before/after number for connection-key, timestamp, and limit-check work
/// on the packet path.
fn bench_tracker_ingest(c: &mut Criterion) {
    let now = SystemTime::now();

    let mut group = c.benchmark_group("tracker_ingest");
    for (flows, per_flow) in [(100u16, 100u32), (1000, 50)] {
        let packets = make_workload(flows, per_flow);
        group.throughput(Throughput::Elements(packets.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("fresh_tracker", format!("{flows}x{per_flow}")),
            &packets,
            |b, packets| {
                b.iter(|| {
                    let tracker = ConnectionTracker::new();
                    for p in packets {
                        tracker.ingest_at(p, now);
                    }
                    tracker
                });
            },
        );
    }
    group.finish();

    // Steady state: every packet updates an existing connection (no creation).
    let mut group = c.benchmark_group("tracker_ingest_steady");
    let packets = make_workload(1000, 1);
    let tracker = ConnectionTracker::new();
    for p in &packets {
        tracker.ingest_at(p, now);
    }
    group.throughput(Throughput::Elements(packets.len() as u64));
    group.bench_function("existing_connections_1000", |b| {
        b.iter(|| {
            for p in &packets {
                tracker.ingest_at(p, now);
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_tracker_ingest);
criterion_main!(benches);
