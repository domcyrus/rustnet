use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustnet_monitor::network::types::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Create a Connection with a RateTracker filled to `n_samples` entries.
fn make_connection_with_samples(n_samples: usize) -> Connection {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    let mut conn = Connection::new(
        Protocol::Tcp,
        local,
        remote,
        ProtocolState::Tcp(TcpState::Established),
    );

    for i in 0..n_samples {
        conn.bytes_sent += 100;
        conn.bytes_received += 200;
        conn.rate_tracker
            .update(conn.bytes_sent, conn.bytes_received);
        // Sprinkle in some pruning to keep the tracker realistic
        if i % 500 == 0 {
            conn.rate_tracker.prune();
        }
    }
    conn
}

/// Benchmark the per-packet `update()` call on RateTracker.
/// This is the hot path — called for every packet received.
/// The Arc<VecDeque> change adds an `Arc::make_mut` atomic check here.
fn bench_rate_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_tracker_update");

    for n_samples in [0, 100, 1000, 5000] {
        // Unique owner: simulates the normal packet-processing path where
        // no snapshot clone is holding a shared reference.
        group.bench_with_input(
            BenchmarkId::new("unique_owner", n_samples),
            &n_samples,
            |b, &n| {
                let mut conn = make_connection_with_samples(n);
                let mut bytes_sent = conn.bytes_sent;
                let mut bytes_recv = conn.bytes_received;
                b.iter(|| {
                    bytes_sent += 100;
                    bytes_recv += 200;
                    conn.rate_tracker.update(bytes_sent, bytes_recv);
                });
            },
        );

        // Shared owner: simulates the case right after a snapshot clone,
        // where two Arcs point to the same VecDeque. The first `update()`
        // after a clone triggers a full VecDeque copy via Arc::make_mut.
        group.bench_with_input(
            BenchmarkId::new("after_snapshot_clone", n_samples),
            &n_samples,
            |b, &n| {
                b.iter_batched(
                    || {
                        let conn = make_connection_with_samples(n);
                        let _snapshot = conn.clone(); // create shared Arc
                        conn
                    },
                    |mut conn| {
                        conn.bytes_sent += 100;
                        conn.bytes_received += 200;
                        conn.rate_tracker
                            .update(conn.bytes_sent, conn.bytes_received);
                    },
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmark `refresh_rates()` (prune + rate calculation + smoothing).
/// Called once per second per connection from the refresh loop.
fn bench_refresh_rates(c: &mut Criterion) {
    let mut group = c.benchmark_group("refresh_rates");

    for n_samples in [0, 100, 1000, 5000] {
        group.bench_with_input(
            BenchmarkId::new("unique_owner", n_samples),
            &n_samples,
            |b, &n| {
                let mut conn = make_connection_with_samples(n);
                b.iter(|| {
                    conn.refresh_rates();
                });
            },
        );
    }

    group.finish();
}

/// Benchmark Connection::clone() to measure the impact of Arc<VecDeque>
/// vs a plain VecDeque. With Arc, clone is O(1) for the samples field
/// (just a refcount bump). Without Arc, it's O(n_samples).
fn bench_connection_clone(c: &mut Criterion) {
    let mut group = c.benchmark_group("connection_clone");

    for n_samples in [0, 100, 1000, 5000, 10000] {
        let conn = make_connection_with_samples(n_samples);
        group.bench_with_input(
            BenchmarkId::new("clone", n_samples),
            &conn,
            |b, conn| {
                b.iter(|| conn.clone());
            },
        );
    }

    group.finish();
}

/// Benchmark the snapshot-then-mutate cycle that happens in practice:
/// 1. Clone N connections for a UI snapshot
/// 2. Then update each original connection with a new packet
///
/// This measures the real-world cost: cheap clone (Arc refcount) followed
/// by a CoW deep-copy on first mutation.
fn bench_snapshot_then_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot_then_update");

    for n_conns in [100, 1000, 5000] {
        let connections: Vec<Connection> = (0..n_conns)
            .map(|_| make_connection_with_samples(100))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("clone_all_then_update_all", n_conns),
            &connections,
            |b, connections| {
                b.iter_batched(
                    || connections.clone(),
                    |mut conns| {
                        // Step 1: snapshot clone (simulates UI snapshot)
                        let _snapshot: Vec<Connection> =
                            conns.iter().map(|c| c.clone()).collect();
                        // Step 2: mutate originals (simulates incoming packets)
                        for conn in &mut conns {
                            conn.bytes_sent += 100;
                            conn.bytes_received += 200;
                            conn.rate_tracker
                                .update(conn.bytes_sent, conn.bytes_received);
                        }
                    },
                    criterion::BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_rate_update,
    bench_refresh_rates,
    bench_connection_clone,
    bench_snapshot_then_update,
);
criterion_main!(benches);
