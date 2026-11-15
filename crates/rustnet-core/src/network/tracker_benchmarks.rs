//! Synthetic, opt-in release benchmarks. No capture or network access.
use super::parser::{ParsedPacket, TcpFlags};
use super::protocol::tcp::TcpHeaderInfo;
use super::tracker::ConnectionTracker;
use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime};

pub(super) fn packet(index: u16, destination: u16, flags: u8, seq: u32, ack: u32) -> ParsedPacket {
    let mut packet = ParsedPacket::test_tcp(
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 1024 + index)),
        SocketAddr::from((
            Ipv4Addr::new(198, 51, 100, (destination % 254 + 1) as u8),
            443 + destination / 254,
        )),
        TcpHeaderInfo {
            seq,
            ack,
            window: 65535,
            flags: TcpFlags {
                syn: flags & 2 != 0,
                ack: flags & 16 != 0,
                rst: flags & 4 != 0,
                fin: false,
            },
            payload_len: 0,
            window_scale: None,
        },
    );
    packet.is_outgoing = flags == 2 || flags == 16;
    packet
}

fn require_release() {
    #[cfg(debug_assertions)]
    panic!("use cargo test --release");
}

pub(super) fn samples() -> usize {
    require_release();
    std::env::var("RUSTNET_BENCH_SAMPLES").map_or(7, |s| s.parse().unwrap())
}

pub(super) fn report(name: &str, sample: usize, operations: usize, elapsed: Duration) {
    println!("BENCH,{name},{sample},{operations},{}", elapsed.as_nanos());
}

#[test]
#[ignore = "release benchmark, run explicitly"]
fn benchmark_tcp_ingestion() {
    for sample in 0..samples() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        let tracker = ConnectionTracker::new();
        let mut data = Vec::new();
        for i in 0..256 {
            tracker.ingest_at(&packet(i, i % 64, 2, 10, 0), now);
            tracker.ingest_at(&packet(i, i % 64, 18, 20, 11), now);
            let ack = packet(i, i % 64, 16, 11, 21);
            tracker.ingest_at(&ack, now);
            data.push(ack);
        }
        let start = Instant::now();
        for i in 0..2_000_000 {
            let p = &mut data[i % 256];
            p.tcp_header.as_mut().unwrap().seq += 1;
            black_box(tracker.ingest_at(black_box(p), now));
        }
        report("established_packets", sample, 2_000_000, start.elapsed());

        let packets: Vec<_> = (0..8192)
            .flat_map(|i| {
                [
                    packet(i, i % 64, 2, 10, 0),
                    packet(i, i % 64, 18, 20, 11),
                    packet(i, i % 64, 16, 11, 21),
                ]
            })
            .collect();
        let mut elapsed = Duration::ZERO;
        for _ in 0..8 {
            let tracker = ConnectionTracker::new();
            let start = Instant::now();
            for p in &packets {
                black_box(tracker.ingest_at(black_box(p), now));
            }
            elapsed += start.elapsed();
        }
        report("handshake_packets", sample, packets.len() * 8, elapsed);

        let packets: Vec<_> = (0..16_384).map(|i| packet(i, i % 64, 2, 10, 0)).collect();
        let tracker = ConnectionTracker::new();
        let start = Instant::now();
        for (i, p) in packets.iter().enumerate() {
            black_box(tracker.ingest_at(black_box(p), now + Duration::from_millis(i as u64 * 4)));
        }
        report(
            "timeout_churn_packets",
            sample,
            packets.len(),
            start.elapsed(),
        );
    }
}
