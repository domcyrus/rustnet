use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rustnet_monitor::network::parser::PacketParser;

/// Load all raw packet bytes from the capture.pcap file.
fn load_packets_from_pcap(path: &str) -> Vec<Vec<u8>> {
    let mut cap = pcap::Capture::from_file(path).expect("failed to open pcap file");
    let mut packets = Vec::new();
    while let Ok(packet) = cap.next_packet() {
        packets.push(packet.data.to_vec());
    }
    packets
}

fn bench_parse_packet(c: &mut Criterion) {
    let packets = load_packets_from_pcap("capture.pcap");
    assert!(!packets.is_empty(), "capture.pcap must contain packets");

    // Configure parser with Linux SLL linktype (DLT 113) matching capture.pcap
    let parser = PacketParser::new().with_linktype(113);

    let mut group = c.benchmark_group("parse_packet");
    group.throughput(Throughput::Elements(packets.len() as u64));

    group.bench_function("all_packets", |b| {
        b.iter(|| {
            let mut parsed_count = 0u32;
            for pkt in &packets {
                if parser.parse_packet(pkt).is_some() {
                    parsed_count += 1;
                }
            }
            parsed_count
        });
    });

    group.finish();

    // Per-packet benchmark (average cost of a single parse)
    let mut single_group = c.benchmark_group("parse_single_packet");
    single_group.throughput(Throughput::Elements(1));

    // Pick a few representative packets (first TCP, first UDP if available)
    let mut tcp_packet = None;
    let mut udp_packet = None;
    for pkt in &packets {
        let result = parser.parse_packet(pkt);
        if let Some(ref parsed) = result {
            match parsed.protocol {
                rustnet_monitor::network::types::Protocol::Tcp if tcp_packet.is_none() => {
                    tcp_packet = Some(pkt.clone());
                }
                rustnet_monitor::network::types::Protocol::Udp if udp_packet.is_none() => {
                    udp_packet = Some(pkt.clone());
                }
                _ => {}
            }
        }
        if tcp_packet.is_some() && udp_packet.is_some() {
            break;
        }
    }

    if let Some(ref pkt) = tcp_packet {
        single_group.bench_with_input(BenchmarkId::new("tcp", pkt.len()), pkt, |b, pkt| {
            b.iter(|| parser.parse_packet(pkt));
        });
    }

    if let Some(ref pkt) = udp_packet {
        single_group.bench_with_input(BenchmarkId::new("udp", pkt.len()), pkt, |b, pkt| {
            b.iter(|| parser.parse_packet(pkt));
        });
    }

    single_group.finish();
}

criterion_group!(benches, bench_parse_packet);
criterion_main!(benches);
