//! Opt-in release measurements of the production snapshot path. See PROFILING.md.

use super::*;
use crate::app::Config;
use crate::headless::output::serialize_record;
use crate::network::parser::PacketParser;
use crate::network::tracker::{ConnectionTracker, HistoricKey};
use crate::network::types::{Protocol, ProtocolState, TcpState};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

struct Profiler {
    app: App,
    cache: ConnectionCache,
    output: BufWriter<File>,
}

fn require_release() {
    #[cfg(debug_assertions)]
    panic!("run with cargo test --release");
}

impl Profiler {
    fn new() -> Self {
        require_release();
        let path = std::env::var_os("RUSTNET_PROFILE_CSV").expect("set RUSTNET_PROFILE_CSV");
        let mut output = BufWriter::new(File::create_new(path).expect("create a new CSV file"));
        writeln!(output, "workload,sample,trace_ms,active,historic,payload_bytes,cached_connections,cached_bytes,build_ns,project_ns,serialize_ns,uncached_ns").unwrap();
        Self {
            app: App::new(Config {
                resolve_dns: false,
                disable_geoip: true,
                ..Config::default()
            })
            .unwrap(),
            cache: ConnectionCache::default(),
            output,
        }
    }

    fn sample(&mut self, tracker: &ConnectionTracker, workload: &str, sample: u64, at: Duration) {
        let started = Instant::now();
        self.app.publish_tracker_snapshot_for_test(tracker);
        let build = started.elapsed();
        let started = Instant::now();
        let (_, snapshot) =
            SnapshotEnvelope::new(&self.app, None, RuntimePhase::Running, None, None, false);
        let project = started.elapsed();
        let ConnectionSnapshots::Basic(connections) = &snapshot.connections else {
            unreachable!("profiling uses basic metadata");
        };
        let historic = connections.iter().filter(|c| c.historic).count();
        let active = connections.len() - historic;

        // Serialize the exact same projection without the cache as a reference.
        // This is always first, so these are diagnostic timings, not a paired
        // speedup benchmark. Equality checking and CSV I/O are outside timing.
        let started = Instant::now();
        let reference = serialize_record(&snapshot).unwrap();
        let uncached = started.elapsed();
        let started = Instant::now();
        let encoded = self.cache.serialize(snapshot).unwrap();
        let serialize = started.elapsed();
        assert_eq!(
            reference, encoded,
            "cached output differs from full snapshot"
        );
        let cached_bytes: usize = self
            .cache
            .basic
            .entries
            .iter()
            .map(|c| c.json.get().len())
            .sum();
        writeln!(
            self.output,
            "{workload},{sample},{},{active},{historic},{},{},{cached_bytes},{},{},{},{}",
            at.as_millis(),
            encoded.len(),
            self.cache.basic.entries.len(),
            build.as_nanos(),
            project.as_nanos(),
            serialize.as_nanos(),
            uncached.as_nanos(),
        )
        .unwrap();
    }

    fn finish(mut self) {
        self.output.flush().unwrap();
    }
}

fn fixture(active: usize, historic: usize, metadata_bytes: usize) -> ConnectionTracker {
    let tracker = ConnectionTracker::new();
    let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for index in 0..active + historic {
        let mut connection = Connection::new(
            Protocol::Tcp,
            format!("127.0.0.1:{}", 1024 + index).parse().unwrap(),
            "192.0.2.1:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );
        connection.created_at = epoch + Duration::from_micros(index as u64);
        connection.last_activity = connection.created_at;
        connection.bytes_sent = 1024;
        connection.bytes_received = 8192;
        connection.packets_sent = 10;
        connection.packets_received = 20;
        connection.process_name = Some("profile-client".into());
        connection.executable = Some(
            std::path::PathBuf::from(format!("/profile/{}/client", "x".repeat(metadata_bytes)))
                .into(),
        );
        let key = ConnectionKey::new(
            connection.protocol,
            connection.local_addr,
            connection.remote_addr,
        );
        if index < active {
            tracker.connections().insert(key, connection);
        } else {
            connection.is_historic = true;
            connection.closed_at = Some(epoch + Duration::from_secs(60));
            connection.protocol_state = ProtocolState::Tcp(TcpState::Closed);
            tracker
                .historic()
                .insert(HistoricKey::for_connection(key, &connection), connection);
        }
    }
    tracker
}

#[test]
#[ignore = "manual release profiling; writes RUSTNET_PROFILE_CSV"]
fn profile_headless_matrix() {
    let mut profiler = Profiler::new();
    for metadata in [0, 1024, 4096] {
        for (active, historic) in [
            (100, 0),
            (1000, 0),
            (5000, 0),
            (100, 1000),
            (100, 5000),
            (100, 10000),
            (100, 15000),
        ] {
            let tracker = fixture(active, historic, metadata);
            let name = format!("a{active}-h{historic}-m{metadata}");
            profiler.cache = ConnectionCache::default();
            profiler.app.set_connections_snapshot_for_test(Vec::new());
            for sample in 0..40 {
                // Active counters change, while retained history stays unchanged.
                for mut entry in tracker.connections().iter_mut() {
                    entry.bytes_sent += 64;
                    entry.packets_sent += 1;
                }
                // Include a late metadata update after the cache has warmed.
                if sample == 20 {
                    for mut entry in tracker.historic().iter_mut() {
                        entry.process_name = Some("resolved-client".into());
                    }
                }
                profiler.sample(&tracker, &name, sample, Duration::from_millis(sample * 500));
            }
        }
    }
    profiler.finish();
}

#[test]
#[ignore = "manual release PCAP replay; requires RUSTNET_PROFILE_PCAP and RUSTNET_PROFILE_CSV"]
fn profile_headless_pcap() {
    let path = std::env::var_os("RUSTNET_PROFILE_PCAP").expect("set RUSTNET_PROFILE_PCAP");
    // The portable reader returns microseconds, including for nanosecond files.
    // The explicit-precision API is unavailable with Windows' default pcap cfg.
    let mut capture = pcap::Capture::from_file(path).unwrap();
    let parser = PacketParser::new().with_linktype(capture.get_datalink().0);
    let tracker = ConnectionTracker::new();
    let mut profiler = Profiler::new();
    let interval = Duration::from_millis(500);
    let mut first = None;
    let mut previous = None;
    let mut next_sample = None;
    let mut next_cleanup = None;
    let mut samples = 0;
    let mut packets = 0;
    let mut parsed = 0;
    loop {
        let packet = match capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::NoMorePackets) => break,
            Err(error) => panic!("read capture: {error}"),
        };
        let seconds = u64::try_from(packet.header.ts.tv_sec).expect("negative capture timestamp");
        let micros = u32::try_from(packet.header.ts.tv_usec).unwrap();
        assert!(micros < 1_000_000, "invalid capture timestamp");
        let at = SystemTime::UNIX_EPOCH + Duration::new(seconds, micros * 1000);
        assert!(
            previous.is_none_or(|last| at >= last),
            "capture timestamps must be ordered"
        );
        previous = Some(at);
        let start = *first.get_or_insert(at);
        let sample_at = next_sample.get_or_insert(at);
        let cleanup_at = next_cleanup.get_or_insert(at);
        // Process idle intervals before the next packet, so future traffic
        // cannot appear in earlier snapshots. Cleanup mirrors the 5s worker.
        while *sample_at < at {
            if *cleanup_at <= *sample_at {
                tracker.cleanup(*sample_at);
                *cleanup_at = *sample_at + Duration::from_secs(5);
            }
            profiler.sample(
                &tracker,
                "pcap",
                samples,
                sample_at.duration_since(start).unwrap(),
            );
            samples += 1;
            *sample_at += interval;
        }
        packets += 1;
        if let Some(packet) = parser.parse_packet(packet.data) {
            tracker.ingest_at(&packet, at);
            parsed += 1;
        }
    }
    assert!(parsed > 0, "capture has no supported packets");
    let end = previous.unwrap();
    tracker.cleanup(end);
    profiler.sample(
        &tracker,
        "pcap-final",
        samples,
        end.duration_since(first.unwrap()).unwrap(),
    );
    profiler.finish();
    eprintln!(
        "replayed {packets} packets ({parsed} parsed), {} snapshots, {} seconds",
        samples + 1,
        end.duration_since(first.unwrap()).unwrap().as_secs_f64()
    );
}
