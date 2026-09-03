use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rustnet_core::network::merge::merge_packet_into_connection;
use rustnet_monitor::network::types::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

mod common;

/// Create a Connection with a RateTracker filled to `n_samples` entries.
fn make_connection_with_samples(n_samples: usize) -> Connection {
    common::make_connection_with_samples(n_samples, None)
}

/// Create a minimal ParsedPacket for merge benchmarking.
fn make_parsed_packet() -> rustnet_monitor::network::parser::ParsedPacket {
    common::make_packet(54321, 1000)
}

fn bench_merge(c: &mut Criterion) {
    let parsed = make_parsed_packet();
    let now = SystemTime::now();

    let mut group = c.benchmark_group("merge_packet");

    for n_samples in [0, 100, 1000, 5000, 10000] {
        group.bench_with_input(
            BenchmarkId::new("in_place_merge", n_samples),
            &n_samples,
            |b, &n| {
                let mut conn = make_connection_with_samples(n);
                b.iter(|| merge_packet_into_connection(&mut conn, &parsed, now));
            },
        );

        let conn = make_connection_with_samples(n_samples);
        group.bench_with_input(
            BenchmarkId::new("clone_only", n_samples),
            &conn,
            |b, conn| {
                b.iter(|| conn.clone());
            },
        );
    }

    group.finish();
}

/// String-key baseline vs the Copy `ConnectionKey` + FxHash the tracker uses.
fn bench_connection_key_format(c: &mut Criterion) {
    use std::hash::BuildHasher;

    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

    c.bench_function("connection_key_format_string", |b| {
        b.iter(|| format!("TCP:{}-TCP:{}", local, remote));
    });

    let parsed = make_parsed_packet();
    let hasher = rustc_hash::FxBuildHasher;
    c.bench_function("connection_key_struct_fxhash", |b| {
        b.iter(|| hasher.hash_one(parsed.connection_key()));
    });
}

criterion_group!(benches, bench_merge, bench_connection_key_format);
criterion_main!(benches);
