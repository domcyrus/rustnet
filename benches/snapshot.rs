use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use dashmap::DashMap;
use rustnet_monitor::network::types::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Populate a DashMap with `n` connections, each with a small number of rate samples.
fn populate_connections(n: usize) -> DashMap<String, Connection> {
    let map = DashMap::new();
    for i in 0..n {
        let port = (i % 65000) as u16 + 1;
        let octet3 = ((i / 256) % 256) as u8;
        let octet4 = (i % 256) as u8;
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, octet3, octet4)), 443);
        let key = format!("TCP:{}-TCP:{}", local, remote);
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        // Add a few rate samples to simulate a real connection
        conn.bytes_sent = 5000;
        conn.bytes_received = 15000;
        conn.packets_sent = 10;
        conn.packets_received = 30;
        conn.rate_tracker
            .update(conn.bytes_sent, conn.bytes_received);
        map.insert(key, conn);
    }
    map
}

fn bench_snapshot(c: &mut Criterion) {
    let mut group = c.benchmark_group("snapshot");

    for n_conns in [100, 1000, 5000, 10000, 50000] {
        let connections = populate_connections(n_conns);

        // Benchmark: iterate + clone + collect (mirrors start_snapshot_provider)
        group.bench_with_input(
            BenchmarkId::new("clone_and_collect", n_conns),
            &connections,
            |b, connections| {
                b.iter(|| {
                    let snapshot: Vec<Connection> = connections
                        .iter()
                        .map(|entry| entry.value().clone())
                        .collect();
                    snapshot
                });
            },
        );

        // Benchmark: clone + collect + sort by created_at
        group.bench_with_input(
            BenchmarkId::new("clone_collect_sort", n_conns),
            &connections,
            |b, connections| {
                b.iter(|| {
                    let mut snapshot: Vec<Connection> = connections
                        .iter()
                        .map(|entry| entry.value().clone())
                        .collect();
                    snapshot.sort_by(|a, b| a.created_at.cmp(&b.created_at));
                    snapshot
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_snapshot);
criterion_main!(benches);
