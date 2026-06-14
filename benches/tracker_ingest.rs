use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustnet_monitor::network::parser::{ParsedPacket, TcpFlags, TcpHeaderInfo};
use rustnet_monitor::network::tracker::ConnectionTracker;
use rustnet_monitor::network::types::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::SystemTime;

/// Build a synthetic TCP data packet for one of `n_connections` flows.
///
/// Flows are distinguished by client port so the workload exercises the
/// tracker's key hashing and DashMap sharding the same way live traffic does.
fn make_packet(flow: u16, seq: u32) -> ParsedPacket {
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 10000 + flow);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    ParsedPacket {
        protocol: Protocol::Tcp,
        local_addr,
        remote_addr,
        tcp_header: Some(TcpHeaderInfo {
            seq,
            ack: seq.wrapping_add(1),
            window: 65535,
            flags: TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
                psh: true,
                urg: false,
            },
            payload_len: 1400,
        }),
        protocol_state: ProtocolState::Tcp(TcpState::Established),
        is_outgoing: true,
        packet_len: 1400,
        dpi_result: None,
        process_name: None,
        process_id: None,
    }
}

/// Interleaved packet stream: `flows` connections sending `packets_per_flow`
/// packets round-robin, mimicking concurrent flows rather than one flow at a
/// time.
fn make_workload(flows: u16, packets_per_flow: u32) -> Vec<ParsedPacket> {
    let mut packets = Vec::with_capacity(flows as usize * packets_per_flow as usize);
    for round in 0..packets_per_flow {
        for flow in 0..flows {
            packets.push(make_packet(flow, round * 1460));
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
