use super::*;
use crate::app::Config;
use crate::network::parser::ParsedPacket;
use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::io;
use std::sync::{Arc, Mutex, mpsc};

#[derive(Clone, Default)]
struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl SharedWriter {
    fn bytes(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn app_with_connections() -> App {
    let app = App::new(Config {
        resolve_dns: false,
        ..Config::default()
    })
    .unwrap();
    let mut udp = Connection::new(
        Protocol::Udp,
        "127.0.0.1:53000".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
        ProtocolState::Udp,
    );
    udp.process_name = Some("resolver".to_string());
    let mut tcp = Connection::new(
        Protocol::Tcp,
        "127.0.0.1:45000".parse().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        ProtocolState::Tcp(TcpState::Established),
    );
    tcp.pid = Some(42);
    tcp.process_name = Some("curl".to_string());
    tcp.connection_direction = Some(true);
    tcp.initial_rtt = Some(Duration::from_millis(11));
    tcp.tcp_analytics.as_mut().unwrap().smoothed_rtt = Some(Duration::from_millis(18));
    tcp.dns_response_time = Some(Duration::from_millis(12));
    tcp.llmnr_response_time = Some(Duration::from_millis(13));
    tcp.netbios_response_time = Some(Duration::from_millis(14));
    tcp.icmp_echo_rtt = Some(Duration::from_millis(15));
    tcp.stun_rtt = Some(Duration::from_millis(16));
    tcp.ntp_rtt = Some(Duration::from_millis(17));
    tcp.current_outgoing_rate_bps = f64::NAN;
    tcp.current_incoming_rate_bps = f64::INFINITY;
    app.set_connections_snapshot_for_test(vec![udp, tcp]);
    app.ingest_packet_for_test(&ParsedPacket::new(
        Protocol::Udp,
        "127.0.0.1:53000".parse().unwrap(),
        "1.1.1.1:53".parse().unwrap(),
        ProtocolState::Udp,
        true,
        64,
        Some("resolver".to_string()),
        None,
    ));
    app.ingest_packet_for_test(&ParsedPacket::new(
        Protocol::Tcp,
        "127.0.0.1:45000".parse().unwrap(),
        "93.184.216.34:443".parse().unwrap(),
        ProtocolState::Tcp(TcpState::Established),
        true,
        64,
        Some("curl".to_string()),
        Some(42),
    ));
    app
}

pub(super) fn object_keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn json_writes_one_final_versioned_snapshot() {
    let mut app = app_with_connections();
    let output = SharedWriter::default();
    let outcome = run(
        &mut app,
        output.clone(),
        &HeadlessOptions {
            format: HeadlessFormat::Json,
            duration: Some(Duration::ZERO),
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap();

    assert_eq!(outcome.exit, HeadlessExit::DurationElapsed);
    let output = output.bytes();
    assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(value["type"], "snapshot");
    assert_eq!(value["runtime"]["status"], "stopped");
    assert_eq!(value["runtime"]["termination_reason"], "duration_elapsed");
    assert!(value["runtime"]["shutdown"].is_object());
    assert_eq!(
        object_keys(&value["runtime"]["shutdown"]),
        [
            "joined_workers",
            "output_errors",
            "panicked_workers",
            "timed_out_workers",
        ]
    );
    assert_eq!(value["connection_count"], 2);
    assert!(value["stats"]["packets_processed"].is_u64());
    assert!(value["sandbox"]["status"].is_string());
}

#[test]
fn jsonl_emits_an_initial_snapshot_and_applies_filter() {
    let mut app = app_with_connections();
    let output = SharedWriter::default();
    let outcome = run(
        &mut app,
        output.clone(),
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: Some(Duration::ZERO),
            filter_query: Some("proto:tcp".to_string()),
        },
        &AtomicBool::new(false),
    )
    .unwrap();

    assert_eq!(outcome.exit, HeadlessExit::DurationElapsed);
    let output = output.bytes();
    let records: Vec<Value> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert!((1..=2).contains(&records.len()));

    let value = records.last().unwrap();
    assert_eq!(value["filter"], "proto:tcp");
    assert_eq!(value["connection_count"], 1);
    assert_eq!(value["connections"][0]["protocol"], "TCP");
    assert_eq!(value["connections"][0]["process"]["name"], "curl");

    assert_eq!(value["runtime"]["status"], "stopped");
    assert_eq!(value["runtime"]["termination_reason"], "duration_elapsed");
    assert!(value["runtime"]["shutdown"].is_object());
}

#[derive(Default)]
struct BrokenPipeWriter;

impl Write for BrokenPipeWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn broken_pipe_is_a_clean_exit() {
    let mut app = app_with_connections();
    let outcome = run(
        &mut app,
        BrokenPipeWriter,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap();

    assert_eq!(outcome.exit, HeadlessExit::BrokenPipe);
    assert_eq!(outcome.stop_report.timed_out_workers, 0);
}

struct FlushBrokenPipeWriter(Vec<u8>);

impl Write for FlushBrokenPipeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "reader closed"))
    }
}

#[test]
fn broken_pipe_while_flushing_is_a_clean_exit() {
    let mut app = app_with_connections();
    let outcome = run(
        &mut app,
        FlushBrokenPipeWriter(Vec::new()),
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap();

    assert_eq!(outcome.exit, HeadlessExit::BrokenPipe);
    assert_eq!(outcome.stop_report.timed_out_workers, 0);
}

#[derive(Default)]
struct FailedWriter;

impl Write for FailedWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected output failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn non_pipe_writer_failure_is_an_error() {
    let mut app = app_with_connections();
    let error = run(
        &mut app,
        FailedWriter,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();

    assert!(error.to_string().contains("headless output"));
}

struct PanicWriter;

impl Write for PanicWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        panic!("injected writer panic")
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_panic_is_joined_and_reported() {
    let mut app = app_with_connections();
    let error = run(
        &mut app,
        PanicWriter,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("headless output writer panicked")
    );
}

struct StallOnceWriter {
    output: SharedWriter,
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    finished: Option<mpsc::Sender<()>>,
}

impl Write for StallOnceWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
            let _ = self.release.recv();
        }
        self.output.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

impl Drop for StallOnceWriter {
    fn drop(&mut self) {
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
    }
}

struct StallFlushWriter {
    entered: Option<mpsc::Sender<()>>,
    release: mpsc::Receiver<()>,
    finished: Option<mpsc::Sender<()>>,
}

impl Write for StallFlushWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
            let _ = self.release.recv();
        }
        Ok(())
    }
}

impl Drop for StallFlushWriter {
    fn drop(&mut self) {
        if let Some(finished) = self.finished.take() {
            let _ = finished.send(());
        }
    }
}

fn stalled_writer() -> (
    StallOnceWriter,
    SharedWriter,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
    mpsc::Receiver<()>,
) {
    let output = SharedWriter::default();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    (
        StallOnceWriter {
            output: output.clone(),
            entered: Some(entered_tx),
            release: release_rx,
            finished: Some(finished_tx),
        },
        output,
        entered_rx,
        release_tx,
        finished_rx,
    )
}

#[test]
fn latest_snapshot_replaces_a_queued_snapshot() {
    let (writer, output, entered, release, finished) = stalled_writer();
    let mut sink = AsyncOutput::spawn(writer).unwrap();
    sink.offer_latest(OutputRecord {
        bytes: b"first\n".to_vec(),
        terminal: false,
    });
    entered.recv_timeout(Duration::from_secs(1)).unwrap();
    sink.offer_latest(OutputRecord {
        bytes: b"stale\n".to_vec(),
        terminal: false,
    });
    sink.offer_latest(OutputRecord {
        bytes: b"terminal\n".to_vec(),
        terminal: true,
    });

    release.send(()).unwrap();
    assert_eq!(
        sink.finish(Duration::from_secs(1)).unwrap(),
        WriterCompletion::Written
    );
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(output.bytes(), b"first\nterminal\n");
}

#[test]
fn stalled_writer_cannot_block_duration_shutdown() {
    let (writer, _output, entered, release, finished) = stalled_writer();
    let mut app = app_with_connections();
    let started = Instant::now();
    let error = run_with_writer_deadline(
        &mut app,
        writer,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: Some(Duration::from_millis(20)),
            filter_query: None,
        },
        &AtomicBool::new(false),
        Duration::from_millis(30),
    )
    .unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(error.to_string().contains("did not finish within 30ms"));
    entered.recv_timeout(Duration::from_secs(1)).unwrap();
    release.send(()).unwrap();
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
}

#[test]
fn stalled_flush_cannot_block_duration_shutdown() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let writer = StallFlushWriter {
        entered: Some(entered_tx),
        release: release_rx,
        finished: Some(finished_tx),
    };
    let mut app = app_with_connections();
    let started = Instant::now();
    let error = run_with_writer_deadline(
        &mut app,
        writer,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: Some(Duration::from_millis(20)),
            filter_query: None,
        },
        &AtomicBool::new(false),
        Duration::from_millis(30),
    )
    .unwrap_err();

    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(error.to_string().contains("did not finish within 30ms"));
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    release_tx.send(()).unwrap();
    finished_rx.recv_timeout(Duration::from_secs(1)).unwrap();
}

#[test]
fn stalled_writer_cannot_block_signal_shutdown() {
    let (writer, _output, entered, release, finished) = stalled_writer();
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&shutdown);
    let trigger = thread::spawn(move || {
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        signal.store(true, Ordering::Release);
    });
    let mut app = app_with_connections();
    let started = Instant::now();
    let error = run_with_writer_deadline(
        &mut app,
        writer,
        &HeadlessOptions {
            format: HeadlessFormat::JsonLines,
            duration: None,
            filter_query: None,
        },
        &shutdown,
        Duration::from_millis(30),
    )
    .unwrap_err();

    trigger.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(error.to_string().contains("did not finish within 30ms"));
    release.send(()).unwrap();
    finished.recv_timeout(Duration::from_secs(1)).unwrap();
}

struct FailingSerialize;

impl Serialize for FailingSerialize {
    fn serialize<S: Serializer>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("injected serialization failure"))
    }
}

#[test]
fn serialization_failure_is_an_error() {
    let error = serialize_record(&FailingSerialize).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to serialize headless output")
    );
}

#[test]
fn capture_failure_stops_an_indefinite_run() {
    let mut app = app_with_connections();
    app.set_capture_error_for_test(Some("injected device failure"));
    let generation_before_run = app.snapshot_generation();
    let output = SharedWriter::default();
    let error = run(
        &mut app,
        output.clone(),
        &HeadlessOptions {
            format: HeadlessFormat::Json,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("packet capture stopped: injected device failure")
    );
    assert!(app.snapshot_generation() > generation_before_run);
    let value: Value = serde_json::from_slice(&output.bytes()).unwrap();
    assert_eq!(value["runtime"]["status"], "stopped_with_errors");
    assert_eq!(value["runtime"]["termination_reason"], "capture_failed");
    assert_eq!(value["runtime"]["capture_error"], "injected device failure");
    assert!(value["runtime"]["shutdown"].is_object());
}

#[test]
fn capture_failure_wins_a_simultaneous_normal_exit() {
    for format in [HeadlessFormat::JsonLines, HeadlessFormat::Json] {
        let mut app = app_with_connections();
        app.set_capture_error_for_test(Some("injected device failure"));
        let output = SharedWriter::default();
        let error = run(
            &mut app,
            output.clone(),
            &HeadlessOptions {
                format,
                duration: Some(Duration::ZERO),
                filter_query: None,
            },
            &AtomicBool::new(true),
        )
        .unwrap_err();

        assert!(error.to_string().contains("packet capture stopped"));
        let records = output.bytes();
        let value: Value = serde_json::from_slice(
            records
                .split(|byte| *byte == b'\n')
                .find(|line| !line.is_empty())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(value["runtime"]["status"], "stopped_with_errors");
        assert_eq!(value["runtime"]["termination_reason"], "capture_failed");
    }
}

#[test]
fn unexpected_critical_worker_exit_stops_an_indefinite_run() {
    let mut app = app_with_connections();
    app.inject_worker_panic_for_test();
    let started = Instant::now();
    let output = SharedWriter::default();
    let error = run(
        &mut app,
        output.clone(),
        &HeadlessOptions {
            format: HeadlessFormat::Json,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(false),
    )
    .unwrap_err();

    assert!(error.to_string().contains("injected-critical-worker"));
    assert!(started.elapsed() < Duration::from_secs(1));
    let value: Value = serde_json::from_slice(&output.bytes()).unwrap();
    assert_eq!(value["runtime"]["status"], "stopped_with_errors");
    assert_eq!(value["runtime"]["termination_reason"], "runtime_failed");
}

#[test]
fn shared_shutdown_condition_ends_json_mode() {
    let mut app = app_with_connections();
    let output = SharedWriter::default();
    let outcome = run(
        &mut app,
        output.clone(),
        &HeadlessOptions {
            format: HeadlessFormat::Json,
            duration: None,
            filter_query: None,
        },
        &AtomicBool::new(true),
    )
    .unwrap();

    assert_eq!(outcome.exit, HeadlessExit::ShutdownRequested);
    let output = output.bytes();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["runtime"]["status"], "stopped");
}

#[test]
fn format_tokens_are_stable() {
    assert_eq!(HeadlessFormat::JsonLines.as_str(), "jsonl");
    assert_eq!(HeadlessFormat::Json.as_str(), "json");
    assert_eq!("jsonl".parse(), Ok(HeadlessFormat::JsonLines));
    assert_eq!("json".parse(), Ok(HeadlessFormat::Json));
    assert!("yaml".parse::<HeadlessFormat>().is_err());
}
