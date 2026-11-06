//! Deterministic full-packet workloads for comparing DPI changes with their base.
//! Fixture construction and parser initialization are outside the timed region.
//! These synthetic workloads measure CPU cost, not live capture loss or UI cost.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustnet_monitor::network::parser::PacketParser;
use rustnet_monitor::network::tracker::ConnectionTracker;
use std::hint::black_box;
use std::time::SystemTime;

fn tcp(payload: &[u8], source: u16, destination: u16, sequence: u32) -> Vec<u8> {
    let mut frame = vec![0; 54];
    frame[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = 6;
    // Loopback is always in the local address snapshot, making orientation stable.
    frame[26..30].copy_from_slice(&[127, 0, 0, 1]);
    frame[30..34].copy_from_slice(&[192, 0, 2, 1]);
    frame[34..36].copy_from_slice(&source.to_be_bytes());
    frame[36..38].copy_from_slice(&destination.to_be_bytes());
    frame[38..42].copy_from_slice(&sequence.to_be_bytes());
    frame[46] = 0x50;
    frame[47] = 0x10;
    frame[48..50].copy_from_slice(&65535u16.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn client_hello() -> Vec<u8> {
    // RFC 9001 Appendix A.2, wrapped in a TLS record.
    let hex = concat!(
        "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868",
        "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578",
        "616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e",
        "0005000501000000000033002600",
        "24001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e9",
        "94ec74d748002b0003020304000d0010000e04030503060302030804080508",
        "06002d00020101001c00024001003900320408ffffffffffffffff0504800",
        "0ffff07048000ffff0801100104800075300901100f088394c8f03e5157080",
        "6048000ffff"
    );
    let mut payload = vec![0x16, 3, 1];
    payload.extend_from_slice(&((hex.len() / 2) as u16).to_be_bytes());
    for offset in (0..hex.len()).step_by(2) {
        payload.push(u8::from_str_radix(&hex[offset..offset + 2], 16).unwrap());
    }
    payload
}

fn mysql_greeting() -> Vec<u8> {
    let mut body = b"\x0a8.4.0\0".to_vec();
    body.extend_from_slice(&123u32.to_le_bytes());
    body.extend_from_slice(b"12345678\0");
    body.extend_from_slice(&0x8a00u16.to_le_bytes());
    body.push(45);
    body.extend_from_slice(&2u16.to_le_bytes());
    body.extend_from_slice(&8u16.to_le_bytes());
    body.push(21);
    body.extend_from_slice(&[0; 10]);
    body.extend_from_slice(b"abcdefghijkl\0caching_sha2_password\0");
    let mut payload = (body.len() as u32).to_le_bytes().to_vec();
    payload.extend_from_slice(&body);
    payload
}

fn postgres_startup() -> Vec<u8> {
    let parameters = b"user\0bench\0database\0example\0application_name\0psql\0\0";
    let mut payload = ((8 + parameters.len()) as u32).to_be_bytes().to_vec();
    payload.extend_from_slice(&0x0003_0000u32.to_be_bytes());
    payload.extend_from_slice(parameters);
    payload
}

fn resp(arguments: &[&[u8]]) -> Vec<u8> {
    let mut payload = format!("*{}\r\n", arguments.len()).into_bytes();
    for argument in arguments {
        payload.extend_from_slice(format!("${}\r\n", argument.len()).as_bytes());
        payload.extend_from_slice(argument);
        payload.extend_from_slice(b"\r\n");
    }
    payload
}

fn workloads() -> Vec<(&'static str, Vec<u8>)> {
    let mut encrypted = vec![0x17, 3, 3, 0x05, 0x73];
    encrypted.extend((0..1395).map(|i| (i * 37 + 11) as u8));
    let unknown: Vec<u8> = (0..1400).map(|i| (i * 31 + 73) as u8).collect();
    let redis = resp(&[b"GET", b"example"]);
    let maximum_args = resp(&[b"GET".as_slice(); 128]);
    vec![
        ("tcp_ack", tcp(&[], 40000, 443, 0)),
        (
            "http",
            tcp(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 40000, 80, 0),
        ),
        ("tls_client_hello", tcp(&client_hello(), 40000, 443, 0)),
        ("tls_data_1400", tcp(&encrypted, 40000, 443, 0)),
        ("unknown_1400", tcp(&unknown, 40000, 45000, 0)),
        ("ssh", tcp(b"SSH-2.0-OpenSSH_9.0\r\n", 22, 40000, 0)),
        ("mysql_greeting", tcp(&mysql_greeting(), 3306, 40000, 0)),
        ("postgres_startup", tcp(&postgres_startup(), 40000, 5432, 0)),
        ("redis_get", tcp(&redis, 40000, 6379, 0)),
        ("redis_max_args", tcp(&maximum_args, 40000, 6379, 0)),
        ("redis_reply", tcp(&redis, 6379, 40000, 0)),
    ]
}

fn bench_dpi_overhead(c: &mut Criterion) {
    let parser = PacketParser::new().with_linktype(1);
    let workloads = workloads();
    for (name, frame) in &workloads {
        assert!(
            parser.parse_packet(frame).is_some(),
            "invalid fixture: {name}"
        );
    }
    let mut group = c.benchmark_group("dpi_packet");
    group.throughput(Throughput::Elements(1));
    for (name, frame) in &workloads {
        group.bench_function(*name, |b| {
            b.iter(|| black_box(parser.parse_packet(black_box(frame)).unwrap()));
        });
    }
    group.finish();

    // 64 concurrent flows, 32 packets each: 1 handshake, 15 ACKs, 16 data
    // packets per flow. Sequence numbers advance between data packets.
    // HTTP and TLS each make up half the flows; this is a defined synthetic
    // mix, not an estimate of real-world traffic proportions.
    let mut frames = Vec::new();
    let mut sequences = [0u32; 64];
    for round in 0..32u32 {
        for flow in 0..64u16 {
            let index = if round == 0 {
                1 + usize::from(flow % 2)
            } else if round % 2 == 0 {
                0
            } else {
                4 - usize::from(flow % 2)
            };
            let mut frame = workloads[index].1.clone();
            frame[34..36].copy_from_slice(&(40000 + flow).to_be_bytes());
            frame[36..38].copy_from_slice(&(if flow % 2 == 0 { 80u16 } else { 443 }).to_be_bytes());
            let sequence = &mut sequences[usize::from(flow)];
            frame[38..42].copy_from_slice(&sequence.to_be_bytes());
            *sequence += (frame.len() - 54) as u32;
            frames.push(frame);
        }
    }
    let mut group = c.benchmark_group("dpi_mixed");
    group.throughput(Throughput::Elements(frames.len() as u64));
    group.bench_function("parse", |b| {
        b.iter(|| {
            for frame in black_box(&frames) {
                black_box(parser.parse_packet(frame).unwrap());
            }
        });
    });
    let now = SystemTime::now();
    group.bench_function("parse_and_track", |b| {
        b.iter(|| {
            let tracker = ConnectionTracker::new();
            for frame in black_box(&frames) {
                tracker.ingest_at(&parser.parse_packet(frame).unwrap(), now);
            }
            black_box(tracker);
        });
    });
    group.finish();

    // Redis commands can be inspected throughout a connection, unlike the
    // MySQL/PostgreSQL startup metadata. Measure that sustained cost too.
    let mut redis_frames = Vec::new();
    let redis_payload = resp(&[b"GET", b"example"]);
    for round in 0..32u32 {
        for flow in 0..64u16 {
            redis_frames.push(tcp(
                &redis_payload,
                40000 + flow,
                6379,
                round * redis_payload.len() as u32,
            ));
        }
    }
    let mut group = c.benchmark_group("dpi_database");
    group.throughput(Throughput::Elements(redis_frames.len() as u64));
    group.bench_function("redis_parse_and_track", |b| {
        b.iter(|| {
            let tracker = ConnectionTracker::new();
            for frame in black_box(&redis_frames) {
                tracker.ingest_at(&parser.parse_packet(frame).unwrap(), now);
            }
            black_box(tracker);
        });
    });
    group.finish();
}

fn bench_capture(c: &mut Criterion) {
    let Some(path) = std::env::var_os("RUSTNET_BENCH_PCAP") else {
        return;
    };
    let mut capture = pcap::Capture::from_file(path).expect("open benchmark capture");
    let parser = PacketParser::new().with_linktype(capture.get_datalink().0);
    let mut frames = Vec::new();
    loop {
        match capture.next_packet() {
            Ok(packet) => frames.push(packet.data.to_vec()),
            Err(pcap::Error::NoMorePackets) => break,
            Err(error) => panic!("read benchmark capture: {error}"),
        }
    }
    assert!(!frames.is_empty(), "empty benchmark capture");
    let parsed = frames.iter().filter_map(|p| parser.parse_packet(p)).count();
    assert_eq!(parsed, frames.len(), "capture contains unsupported packets");
    let now = SystemTime::now();
    let mut group = c.benchmark_group("dpi_capture");
    group.throughput(Throughput::Elements(frames.len() as u64));
    group.bench_function("parse_and_track", |b| {
        b.iter(|| {
            let tracker = ConnectionTracker::new();
            for frame in black_box(&frames) {
                tracker.ingest_at(&parser.parse_packet(frame).unwrap(), now);
            }
            black_box(tracker);
        });
    });
    group.finish();
}

criterion_group!(benches, bench_dpi_overhead, bench_capture);
criterion_main!(benches);
