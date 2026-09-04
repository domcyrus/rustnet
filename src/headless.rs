//! Stable machine-readable output for non-interactive runs.
//!
//! The adapter deliberately projects application state into a versioned
//! schema instead of serializing internal structs. This keeps the wire format
//! independent of implementation details such as atomics and cache fields.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use crossbeam::channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded};
use serde::Serialize;

use crate::app::{App, AppStats, StopReport};
use crate::network::types::{AttributionSource, Connection, ConnectionKey};

/// Current headless output schema.
pub const SCHEMA_VERSION: u8 = 1;

const MAX_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const OUTPUT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Machine-readable output mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HeadlessFormat {
    /// Emit newline-delimited latest-value snapshots followed by a terminal
    /// snapshot after shutdown finishes. Slow consumers can observe generation
    /// gaps because stale queued snapshots are replaced under backpressure.
    #[default]
    JsonLines,
    /// Emit exactly one snapshot after the run has stopped.
    Json,
}

impl HeadlessFormat {
    /// Stable CLI token for this format.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonLines => "jsonl",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for HeadlessFormat {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for HeadlessFormat {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "jsonl" => Ok(Self::JsonLines),
            "json" => Ok(Self::Json),
            _ => Err("expected jsonl or json"),
        }
    }
}

/// Settings used by [`run`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeadlessOptions {
    pub format: HeadlessFormat,
    /// Stop after this much wall-clock time. `None` waits for a shutdown
    /// signal in JSON mode. JSONL can also stop when its consumer closes the
    /// output pipe.
    pub duration: Option<Duration>,
    /// Optional connection filter using the same syntax as the TUI.
    pub filter_query: Option<String>,
}

/// Why a headless run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadlessExit {
    ShutdownRequested,
    DurationElapsed,
    /// The downstream reader closed stdout. This is a successful termination,
    /// matching normal Unix pipeline behavior.
    BrokenPipe,
}

impl HeadlessExit {
    /// Stable machine-readable token for the termination reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShutdownRequested => "shutdown_requested",
            Self::DurationElapsed => "duration_elapsed",
            Self::BrokenPipe => "broken_pipe",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum TerminationReason {
    ShutdownRequested,
    DurationElapsed,
    BrokenPipe,
    CaptureFailed,
    RuntimeFailed,
    OutputFailed,
}

impl TerminationReason {
    const fn from_exit(exit: HeadlessExit) -> Self {
        match exit {
            HeadlessExit::ShutdownRequested => Self::ShutdownRequested,
            HeadlessExit::DurationElapsed => Self::DurationElapsed,
            HeadlessExit::BrokenPipe => Self::BrokenPipe,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::ShutdownRequested => "shutdown_requested",
            Self::DurationElapsed => "duration_elapsed",
            Self::BrokenPipe => "broken_pipe",
            Self::CaptureFailed => "capture_failed",
            Self::RuntimeFailed => "runtime_failed",
            Self::OutputFailed => "output_failed",
        }
    }
}

/// Completed run information. Callers should inspect the stop report before
/// choosing their process exit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "inspect the shutdown report before exiting"]
pub struct HeadlessRunOutcome {
    pub exit: HeadlessExit,
    pub stop_report: StopReport,
}

/// Run the headless output loop and always stop the application before
/// returning.
///
/// JSONL mode sends live snapshots through a one-record latest-value queue,
/// then attempts one terminal snapshot containing the shutdown report. JSON
/// mode waits for termination and sends only the terminal snapshot. The writer
/// is isolated on a worker so a blocked pipe cannot delay runtime shutdown.
pub fn run<W: Write + Send + 'static>(
    app: &mut App,
    writer: W,
    options: &HeadlessOptions,
    shutdown_requested: &AtomicBool,
) -> Result<HeadlessRunOutcome> {
    run_with_writer_deadline(
        app,
        writer,
        options,
        shutdown_requested,
        OUTPUT_SHUTDOWN_DEADLINE,
    )
}

fn run_with_writer_deadline<W: Write + Send + 'static>(
    app: &mut App,
    writer: W,
    options: &HeadlessOptions,
    shutdown_requested: &AtomicBool,
    writer_deadline: Duration,
) -> Result<HeadlessRunOutcome> {
    let mut output = match AsyncOutput::spawn(writer) {
        Ok(output) => output,
        Err(error) => {
            let _ = app.stop();
            return Err(error).context("failed to start headless output writer");
        }
    };
    let started = Instant::now();
    let poll_interval = app
        .snapshot_refresh_interval()
        .min(MAX_STOP_POLL_INTERVAL)
        .max(Duration::from_millis(1));

    let monitor_result = match options.format {
        HeadlessFormat::JsonLines => stream_json_lines(
            app,
            &mut output,
            options,
            shutdown_requested,
            started,
            poll_interval,
        ),
        HeadlessFormat::Json => wait_for_exit(
            app,
            &mut output,
            options.duration,
            shutdown_requested,
            started,
            poll_interval,
        ),
    };

    let stop_report = app.stop();
    let post_stop_failure = runtime_failure(app);
    let (successful_exit, mut failure) = match monitor_result {
        Ok(exit) => (Some(exit), None),
        Err(failure) => (None, Some(failure)),
    };
    if let Some(post_stop_failure) = post_stop_failure {
        failure = Some(post_stop_failure);
    }
    if failure.is_none() {
        failure = shutdown_failure(stop_report);
    }

    let termination_reason = failure
        .as_ref()
        .map(|failure| failure.kind.termination_reason())
        .or_else(|| successful_exit.map(TerminationReason::from_exit));
    let phase = RuntimePhase::after_stop(stop_report, failure.is_some());
    let (_, snapshot) = SnapshotEnvelope::new(
        app,
        options.filter_query.as_deref(),
        phase,
        termination_reason,
        Some(stop_report),
    );

    let terminal_result = serialize_record(&snapshot).and_then(|record| {
        output.offer_latest(OutputRecord {
            bytes: record,
            terminal: true,
        });
        output.finish(writer_deadline)
    });

    if let Some(failure) = failure {
        if let Err(output_error) = terminal_result {
            return Err(output_error.context(format!(
                "{}; terminal headless output also failed",
                failure.error
            )));
        }
        return Err(failure.error);
    }

    let exit = successful_exit.expect("successful monitor result has an exit reason");
    match terminal_result? {
        WriterCompletion::Written => Ok(HeadlessRunOutcome { exit, stop_report }),
        WriterCompletion::BrokenPipe => Ok(HeadlessRunOutcome {
            exit: HeadlessExit::BrokenPipe,
            stop_report,
        }),
    }
}

fn stream_json_lines(
    app: &App,
    output: &mut AsyncOutput,
    options: &HeadlessOptions,
    shutdown_requested: &AtomicBool,
    started: Instant,
    poll_interval: Duration,
) -> MonitorResult<HeadlessExit> {
    let mut last_generation = None;

    loop {
        fail_if_runtime_unhealthy(app)?;
        if let Some(exit) = output.poll().map_err(RunFailure::output)? {
            return Ok(exit);
        }

        let generation = app.snapshot_generation();
        if last_generation != Some(generation) {
            let phase = if app.is_loading() {
                RuntimePhase::Starting
            } else {
                RuntimePhase::Running
            };
            let (generation, snapshot) =
                SnapshotEnvelope::new(app, options.filter_query.as_deref(), phase, None, None);
            if last_generation != Some(generation) {
                let record = serialize_record(&snapshot).map_err(RunFailure::output)?;
                output.offer_latest(OutputRecord {
                    bytes: record,
                    terminal: false,
                });
                last_generation = Some(generation);
            }
        }

        fail_if_runtime_unhealthy(app)?;
        if let Some(exit) = output.poll().map_err(RunFailure::output)? {
            return Ok(exit);
        }
        if let Some(exit) = exit_reason(options.duration, shutdown_requested, started) {
            return Ok(exit);
        }

        thread::sleep(sleep_duration(options.duration, started, poll_interval));
    }
}

fn wait_for_exit(
    app: &App,
    output: &mut AsyncOutput,
    duration: Option<Duration>,
    shutdown_requested: &AtomicBool,
    started: Instant,
    poll_interval: Duration,
) -> MonitorResult<HeadlessExit> {
    loop {
        fail_if_runtime_unhealthy(app)?;
        if let Some(exit) = output.poll().map_err(RunFailure::output)? {
            return Ok(exit);
        }
        if let Some(exit) = exit_reason(duration, shutdown_requested, started) {
            return Ok(exit);
        }
        thread::sleep(sleep_duration(duration, started, poll_interval));
    }
}

type MonitorResult<T> = std::result::Result<T, RunFailure>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunFailureKind {
    Capture,
    Runtime,
    Output,
}

impl RunFailureKind {
    const fn termination_reason(self) -> TerminationReason {
        match self {
            Self::Capture => TerminationReason::CaptureFailed,
            Self::Runtime => TerminationReason::RuntimeFailed,
            Self::Output => TerminationReason::OutputFailed,
        }
    }
}

struct RunFailure {
    kind: RunFailureKind,
    error: anyhow::Error,
}

impl RunFailure {
    fn output(error: anyhow::Error) -> Self {
        Self {
            kind: RunFailureKind::Output,
            error,
        }
    }
}

fn fail_if_runtime_unhealthy(app: &App) -> MonitorResult<()> {
    if let Some(error) = app.capture_error() {
        return Err(RunFailure {
            kind: RunFailureKind::Capture,
            error: anyhow::anyhow!("packet capture stopped: {error}"),
        });
    }
    if let Some(error) = app.runtime_error() {
        return Err(RunFailure {
            kind: RunFailureKind::Runtime,
            error: anyhow::anyhow!(error),
        });
    }
    Ok(())
}

fn runtime_failure(app: &App) -> Option<RunFailure> {
    fail_if_runtime_unhealthy(app).err()
}

fn shutdown_failure(report: StopReport) -> Option<RunFailure> {
    if report.panicked_workers > 0 || report.timed_out_workers > 0 {
        return Some(RunFailure {
            kind: RunFailureKind::Runtime,
            error: anyhow::anyhow!(
                "runtime shutdown failed: {} worker(s) timed out and {} worker(s) panicked",
                report.timed_out_workers,
                report.panicked_workers
            ),
        });
    }
    (report.output_errors > 0).then(|| RunFailure {
        kind: RunFailureKind::Output,
        error: anyhow::anyhow!(
            "runtime shutdown failed: {} output operation(s) failed",
            report.output_errors
        ),
    })
}

fn exit_reason(
    duration: Option<Duration>,
    shutdown_requested: &AtomicBool,
    started: Instant,
) -> Option<HeadlessExit> {
    if shutdown_requested.load(Ordering::Acquire) {
        return Some(HeadlessExit::ShutdownRequested);
    }
    duration
        .is_some_and(|limit| started.elapsed() >= limit)
        .then_some(HeadlessExit::DurationElapsed)
}

fn sleep_duration(
    duration: Option<Duration>,
    started: Instant,
    poll_interval: Duration,
) -> Duration {
    duration
        .map(|limit| limit.saturating_sub(started.elapsed()))
        .unwrap_or(poll_interval)
        .min(poll_interval)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterCompletion {
    Written,
    BrokenPipe,
}

#[derive(Debug, Clone)]
enum WriterStatus {
    Finished,
    BrokenPipe,
    Failed(String),
}

struct OutputRecord {
    bytes: Vec<u8>,
    terminal: bool,
}

struct AsyncOutput {
    records_tx: Sender<OutputRecord>,
    pending_rx: Receiver<OutputRecord>,
    status_rx: Receiver<WriterStatus>,
    observed_status: Option<WriterStatus>,
    worker: Option<thread::JoinHandle<()>>,
}

impl AsyncOutput {
    fn spawn<W: Write + Send + 'static>(mut writer: W) -> io::Result<Self> {
        let (records_tx, records_rx) = bounded::<OutputRecord>(1);
        let pending_rx = records_rx.clone();
        let (status_tx, status_rx) = bounded(1);
        let worker = thread::Builder::new()
            .name("headless_output".to_string())
            .spawn(move || {
                let status = loop {
                    let record = match records_rx.recv() {
                        Ok(record) => record,
                        Err(_) => break WriterStatus::Finished,
                    };
                    if let Err(error) = writer
                        .write_all(&record.bytes)
                        .and_then(|()| writer.flush())
                    {
                        break if error.kind() == io::ErrorKind::BrokenPipe {
                            WriterStatus::BrokenPipe
                        } else {
                            WriterStatus::Failed(error.to_string())
                        };
                    }
                    if record.terminal {
                        break WriterStatus::Finished;
                    }
                };
                drop(writer);
                let _ = status_tx.try_send(status);
            })?;

        Ok(Self {
            records_tx,
            pending_rx,
            status_rx,
            observed_status: None,
            worker: Some(worker),
        })
    }

    /// Replace a queued live record with the newest record. The worker may
    /// also be writing one record, so memory remains bounded to two serialized
    /// snapshots plus the producer's current snapshot.
    fn offer_latest(&mut self, mut record: OutputRecord) {
        loop {
            match self.records_tx.try_send(record) {
                Ok(()) => return,
                Err(TrySendError::Full(returned)) => {
                    record = returned;
                    match self.pending_rx.try_recv() {
                        Ok(_) | Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => return,
                    }
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }

    fn poll(&mut self) -> Result<Option<HeadlessExit>> {
        if self.observed_status.is_none() {
            match self.status_rx.try_recv() {
                Ok(status) => self.observed_status = Some(status),
                Err(TryRecvError::Empty) => return Ok(None),
                Err(TryRecvError::Disconnected) => {
                    self.join_finished_worker()?;
                    anyhow::bail!("headless output writer stopped unexpectedly")
                }
            }
        }
        match self.observed_status.as_ref().expect("status was populated") {
            WriterStatus::BrokenPipe => Ok(Some(HeadlessExit::BrokenPipe)),
            WriterStatus::Failed(error) => anyhow::bail!("headless output failed: {error}"),
            WriterStatus::Finished => {
                anyhow::bail!("headless output writer stopped before the terminal record")
            }
        }
    }

    fn finish(mut self, deadline: Duration) -> Result<WriterCompletion> {
        let status = if let Some(status) = self.observed_status.take() {
            status
        } else {
            match self.status_rx.recv_timeout(deadline) {
                Ok(status) => status,
                Err(RecvTimeoutError::Timeout) => {
                    self.worker.take();
                    anyhow::bail!(
                        "headless output writer did not finish within {deadline:?}; detached blocked writer"
                    );
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.join_finished_worker()?;
                    anyhow::bail!("headless output writer stopped unexpectedly");
                }
            }
        };
        self.join_finished_worker()?;
        match status {
            WriterStatus::Finished => Ok(WriterCompletion::Written),
            WriterStatus::BrokenPipe => Ok(WriterCompletion::BrokenPipe),
            WriterStatus::Failed(error) => anyhow::bail!("headless output failed: {error}"),
        }
    }

    fn join_finished_worker(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            anyhow::bail!("headless output writer panicked");
        }
        Ok(())
    }
}

fn serialize_record<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut record = serde_json::to_vec(value).context("failed to serialize headless output")?;
    record.push(b'\n');
    Ok(record)
}

#[derive(Serialize)]
struct SnapshotEnvelope {
    schema_version: u8,
    #[serde(rename = "type")]
    record_type: &'static str,
    timestamp: String,
    runtime: RuntimeSnapshot,
    sandbox: SandboxSnapshot,
    stats: StatsSnapshot,
    filter: Option<String>,
    connection_count: usize,
    connections: Vec<ConnectionSnapshot>,
}

impl SnapshotEnvelope {
    fn new(
        app: &App,
        filter_query: Option<&str>,
        phase: RuntimePhase,
        termination_reason: Option<TerminationReason>,
        stop_report: Option<StopReport>,
    ) -> (u64, Self) {
        let filter = filter_query
            .map(str::trim)
            .filter(|query| !query.is_empty());
        let (generation, connections) =
            app.get_filtered_connections_with_generation(filter.unwrap_or_default());
        let mut connections: Vec<_> = connections
            .iter()
            .map(ConnectionSnapshot::from_connection)
            .collect();
        connections.sort_unstable_by(|left, right| left.id.cmp(&right.id));

        (
            generation,
            Self {
                schema_version: SCHEMA_VERSION,
                record_type: "snapshot",
                timestamp: timestamp(SystemTime::now()),
                runtime: RuntimeSnapshot::new(
                    app,
                    generation,
                    phase,
                    termination_reason,
                    stop_report,
                ),
                sandbox: SandboxSnapshot::from_app(app),
                stats: StatsSnapshot::from_stats(&app.get_stats()),
                filter: filter.map(str::to_string),
                connection_count: connections.len(),
                connections,
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum RuntimePhase {
    Starting,
    Running,
    Stopping,
    Stopped,
    StoppedWithErrors,
}

impl RuntimePhase {
    const fn after_stop(report: StopReport, failed: bool) -> Self {
        if report.timed_out_workers > 0 {
            Self::Stopping
        } else if failed || report.panicked_workers > 0 || report.output_errors > 0 {
            Self::StoppedWithErrors
        } else {
            Self::Stopped
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::StoppedWithErrors => "stopped_with_errors",
        }
    }
}

#[derive(Serialize)]
struct RuntimeSnapshot {
    status: &'static str,
    snapshot_generation: u64,
    interface: Option<String>,
    capture_status: &'static str,
    capture_error: Option<String>,
    process_detection: ProcessDetectionSnapshot,
    termination_reason: Option<&'static str>,
    shutdown: Option<ShutdownSnapshot>,
}

impl RuntimeSnapshot {
    fn new(
        app: &App,
        generation: u64,
        phase: RuntimePhase,
        termination_reason: Option<TerminationReason>,
        stop_report: Option<StopReport>,
    ) -> Self {
        let capture_error = app.capture_error();
        let process = app.get_process_detection_status();
        Self {
            status: phase.as_str(),
            snapshot_generation: generation,
            interface: app.get_current_interface(),
            capture_status: if capture_error.is_some() {
                "failed"
            } else {
                "healthy"
            },
            capture_error,
            process_detection: ProcessDetectionSnapshot {
                method: process.method,
                degraded: process.is_degraded,
                degradation_reason: process.degradation_reason,
                unavailable_feature: process.unavailable_feature,
            },
            termination_reason: termination_reason.map(TerminationReason::as_str),
            shutdown: stop_report.map(ShutdownSnapshot::from),
        }
    }
}

#[derive(Serialize)]
struct ProcessDetectionSnapshot {
    method: String,
    degraded: bool,
    degradation_reason: Option<String>,
    unavailable_feature: Option<String>,
}

#[derive(Serialize)]
struct ShutdownSnapshot {
    joined_workers: usize,
    panicked_workers: usize,
    timed_out_workers: usize,
    output_errors: u64,
}

impl From<StopReport> for ShutdownSnapshot {
    fn from(report: StopReport) -> Self {
        Self {
            joined_workers: report.joined_workers,
            panicked_workers: report.panicked_workers,
            timed_out_workers: report.timed_out_workers,
            output_errors: report.output_errors,
        }
    }
}

#[derive(Serialize)]
struct SandboxSnapshot {
    status: &'static str,
    message: String,
    filesystem_restricted: bool,
    network_restricted: bool,
    uid_dropped: bool,
}

impl SandboxSnapshot {
    fn from_app(app: &App) -> Self {
        use rustnet_sandbox::SandboxStatus;

        let report = app.sandbox_report();
        let status = match report.status {
            SandboxStatus::FullyEnforced => "fully_enforced",
            SandboxStatus::PartiallyEnforced => "partially_enforced",
            SandboxStatus::NotApplied => "not_applied",
            SandboxStatus::Error => "error",
        };
        Self {
            status,
            message: report.message,
            filesystem_restricted: report.fs_restricted,
            network_restricted: report.net_restricted,
            uid_dropped: report.uid_dropped,
        }
    }
}

#[derive(Serialize)]
struct StatsSnapshot {
    packets_processed: u64,
    packets_dropped: u64,
    capture_packets_dropped: u64,
    interface_packets_dropped: u64,
    pre_attribution_packets: u64,
    connections_tracked: u64,
    total_connections_created: u64,
    total_connections_archived: u64,
    tcp_retransmits: u64,
    tcp_out_of_order: u64,
    tcp_fast_retransmits: u64,
    pcap_records_written: u64,
    pcap_export_errors: u64,
    pcapng_records_queued: u64,
    pcapng_records_written: u64,
    pcapng_records_annotated: u64,
    pcapng_records_unannotated: u64,
    pcapng_records_dropped: u64,
    pcapng_export_errors: u64,
}

impl StatsSnapshot {
    fn from_stats(stats: &AppStats) -> Self {
        let load = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
        Self {
            packets_processed: load(&stats.packets_processed),
            packets_dropped: load(&stats.packets_dropped),
            capture_packets_dropped: load(&stats.capture_packets_dropped),
            interface_packets_dropped: load(&stats.interface_packets_dropped),
            pre_attribution_packets: load(&stats.pre_attribution_packets),
            connections_tracked: load(&stats.connections_tracked),
            total_connections_created: load(&stats.total_connections_created),
            total_connections_archived: load(&stats.total_connections_archived),
            tcp_retransmits: load(&stats.total_tcp_retransmits),
            tcp_out_of_order: load(&stats.total_tcp_out_of_order),
            tcp_fast_retransmits: load(&stats.total_tcp_fast_retransmits),
            pcap_records_written: load(&stats.pcap_records_written),
            pcap_export_errors: load(&stats.pcap_export_errors),
            pcapng_records_queued: load(&stats.pcapng_records_queued),
            pcapng_records_written: load(&stats.pcapng_records_written),
            pcapng_records_annotated: load(&stats.pcapng_records_annotated),
            pcapng_records_unannotated: load(&stats.pcapng_records_unannotated),
            pcapng_records_dropped: load(&stats.pcapng_records_dropped),
            pcapng_export_errors: load(&stats.pcapng_export_errors),
        }
    }
}

#[derive(Serialize)]
struct ConnectionSnapshot {
    id: String,
    protocol: &'static str,
    state: String,
    local: EndpointSnapshot,
    remote: EndpointSnapshot,
    remote_is_gateway: bool,
    direction: Option<&'static str>,
    process: Option<ProcessSnapshot>,
    service: Option<String>,
    application: Option<&'static str>,
    hostname: Option<String>,
    hostname_source: Option<&'static str>,
    traffic: TrafficSnapshot,
    rtt: RttSnapshot,
    geoip: Option<GeoIpSnapshot>,
    kubernetes: Option<KubernetesSnapshot>,
    created_at: String,
    last_activity: String,
    historic: bool,
    closed_at: Option<String>,
}

impl ConnectionSnapshot {
    fn from_connection(connection: &Connection) -> Self {
        let authoritative_hostname = connection.authoritative_hostname();
        let (hostname, hostname_source) = if let Some(hostname) = authoritative_hostname {
            (Some(hostname.to_string()), Some("application"))
        } else if let Some(attributed) = &connection.attributed_hostname {
            let source = match attributed.source {
                AttributionSource::CapturedDns => "captured_dns",
            };
            (Some(attributed.name.clone()), Some(source))
        } else {
            (None, None)
        };

        let process = if connection.pid.is_some()
            || connection.process_ppid.is_some()
            || connection.process_name.is_some()
            || connection.executable.is_some()
            || connection.process_uid.is_some()
            || connection.process_gid.is_some()
            || connection.attribution_quality.is_some()
            || connection.process_lineage.is_some()
        {
            Some(ProcessSnapshot {
                pid: connection.pid,
                ppid: connection.process_ppid,
                name: connection.process_name.clone(),
                executable: connection
                    .executable
                    .as_ref()
                    .map(|path| path.display().to_string()),
                uid: connection.process_uid,
                gid: connection.process_gid,
                attribution_match: connection
                    .attribution_quality
                    .map(|quality| quality.as_token()),
                lineage: connection.process_lineage.as_deref().map(|lineage| {
                    ProcessLineageSnapshot {
                        ancestors: lineage
                            .ancestors
                            .iter()
                            .map(|ancestor| ProcessAncestorSnapshot {
                                pid: ancestor.pid,
                                name: ancestor.name.clone(),
                                executable: ancestor
                                    .executable
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                                started_at_unix_ms: ancestor.started_at_unix_ms,
                            })
                            .collect(),
                        truncated: lineage.truncated,
                    }
                }),
            })
        } else {
            None
        };

        let geoip = connection.geoip_info.as_ref().and_then(|info| {
            info.has_data().then(|| GeoIpSnapshot {
                country_code: info.country_code.clone(),
                country_name: info.country_name.clone(),
                asn: info.asn,
                as_org: info.as_org.clone(),
                city: info.city.clone(),
                postal_code: info.postal_code.clone(),
            })
        });

        #[cfg(feature = "kubernetes")]
        let kubernetes = connection.k8s_info.as_ref().map(|info| KubernetesSnapshot {
            pod_uid: info.pod_uid.clone(),
            pod_name: info.pod_name.clone(),
            pod_namespace: info.pod_namespace.clone(),
            container_id: info.container_id.clone(),
            container_name: info.container_name.clone(),
            cgroup_path: info.cgroup_path.clone(),
        });
        #[cfg(not(feature = "kubernetes"))]
        let kubernetes = None;

        Self {
            id: connection_id(connection),
            protocol: connection.protocol.as_str(),
            state: connection.state().into_owned(),
            local: EndpointSnapshot {
                ip: connection.local_addr.ip().to_string(),
                port: connection.local_addr.port(),
                address_kind: connection.local_addr_kind.as_token(),
            },
            remote: EndpointSnapshot {
                ip: connection.remote_addr.ip().to_string(),
                port: connection.remote_addr.port(),
                address_kind: connection.remote_addr_kind.as_token(),
            },
            remote_is_gateway: connection.remote_is_gateway,
            direction: connection
                .connection_direction
                .map(|outgoing| if outgoing { "outbound" } else { "inbound" }),
            process,
            service: connection.service_name.clone(),
            application: connection
                .dpi_info
                .as_ref()
                .map(|dpi| dpi.application.sort_key()),
            hostname,
            hostname_source,
            traffic: TrafficSnapshot {
                bytes_sent: connection.bytes_sent,
                bytes_received: connection.bytes_received,
                packets_sent: connection.packets_sent,
                packets_received: connection.packets_received,
                outgoing_bytes_per_second: finite(connection.current_outgoing_rate_bps),
                incoming_bytes_per_second: finite(connection.current_incoming_rate_bps),
            },
            rtt: RttSnapshot {
                current_ms: duration_ms(connection.current_rtt()),
                initial_ms: duration_ms(connection.initial_rtt),
                tcp_smoothed_ms: duration_ms(
                    connection
                        .tcp_analytics
                        .as_ref()
                        .and_then(|analytics| analytics.smoothed_rtt),
                ),
                dns_response_ms: duration_ms(connection.dns_response_time),
                llmnr_response_ms: duration_ms(connection.llmnr_response_time),
                netbios_response_ms: duration_ms(connection.netbios_response_time),
                icmp_echo_ms: duration_ms(connection.icmp_echo_rtt),
                stun_ms: duration_ms(connection.stun_rtt),
                ntp_ms: duration_ms(connection.ntp_rtt),
            },
            geoip,
            kubernetes,
            created_at: timestamp(connection.created_at),
            last_activity: timestamp(connection.last_activity),
            historic: connection.is_historic,
            closed_at: connection.closed_at.map(timestamp),
        }
    }
}

#[derive(Serialize)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
    address_kind: &'static str,
}

#[derive(Serialize)]
struct ProcessSnapshot {
    pid: Option<u32>,
    ppid: Option<u32>,
    name: Option<String>,
    executable: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    attribution_match: Option<&'static str>,
    lineage: Option<ProcessLineageSnapshot>,
}

#[derive(Serialize)]
struct ProcessLineageSnapshot {
    ancestors: Vec<ProcessAncestorSnapshot>,
    truncated: bool,
}

#[derive(Serialize)]
struct ProcessAncestorSnapshot {
    pid: u32,
    name: String,
    executable: Option<String>,
    started_at_unix_ms: Option<u64>,
}

#[derive(Serialize)]
struct TrafficSnapshot {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    outgoing_bytes_per_second: Option<f64>,
    incoming_bytes_per_second: Option<f64>,
}

#[derive(Serialize)]
struct RttSnapshot {
    current_ms: Option<f64>,
    initial_ms: Option<f64>,
    tcp_smoothed_ms: Option<f64>,
    dns_response_ms: Option<f64>,
    llmnr_response_ms: Option<f64>,
    netbios_response_ms: Option<f64>,
    icmp_echo_ms: Option<f64>,
    stun_ms: Option<f64>,
    ntp_ms: Option<f64>,
}

#[derive(Serialize)]
struct GeoIpSnapshot {
    country_code: Option<String>,
    country_name: Option<String>,
    asn: Option<u32>,
    as_org: Option<String>,
    city: Option<String>,
    postal_code: Option<String>,
}

#[derive(Serialize)]
struct KubernetesSnapshot {
    pod_uid: Option<String>,
    pod_name: Option<String>,
    pod_namespace: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
    cgroup_path: Option<String>,
}

fn timestamp(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn connection_id(connection: &Connection) -> String {
    // Tracker keys distinguish active and archived entries, but a consumer
    // needs one identity throughout a flow's lifetime, including tuple reuse.
    let created = DateTime::<Utc>::from(connection.created_at);
    format!(
        "{}:{}.{:09}",
        ConnectionKey::from_connection(connection),
        created.timestamp(),
        created.timestamp_subsec_nanos(),
    )
}

fn finite(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn duration_ms(value: Option<Duration>) -> Option<f64> {
    value.and_then(|duration| finite(duration.as_secs_f64() * 1_000.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Config;
    use crate::network::parser::ParsedPacket;
    use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};
    use serde::Serializer;
    use serde_json::Value;
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

    fn app_with_connections() -> App {
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

    fn object_keys(value: &Value) -> Vec<&str> {
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
    fn version_one_schema_keys_and_protocol_timings_are_stable() {
        let app = app_with_connections();
        let (_, snapshot) = SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None);
        let value = serde_json::to_value(snapshot).unwrap();

        assert_eq!(
            object_keys(&value),
            [
                "connection_count",
                "connections",
                "filter",
                "runtime",
                "sandbox",
                "schema_version",
                "stats",
                "timestamp",
                "type",
            ]
        );
        assert_eq!(
            object_keys(&value["runtime"]),
            [
                "capture_error",
                "capture_status",
                "interface",
                "process_detection",
                "shutdown",
                "snapshot_generation",
                "status",
                "termination_reason",
            ]
        );
        assert_eq!(
            object_keys(&value["runtime"]["process_detection"]),
            [
                "degradation_reason",
                "degraded",
                "method",
                "unavailable_feature",
            ]
        );
        assert_eq!(
            object_keys(&value["sandbox"]),
            [
                "filesystem_restricted",
                "message",
                "network_restricted",
                "status",
                "uid_dropped",
            ]
        );
        assert_eq!(
            object_keys(&value["stats"]),
            [
                "capture_packets_dropped",
                "connections_tracked",
                "interface_packets_dropped",
                "packets_dropped",
                "packets_processed",
                "pcap_export_errors",
                "pcap_records_written",
                "pcapng_export_errors",
                "pcapng_records_annotated",
                "pcapng_records_dropped",
                "pcapng_records_queued",
                "pcapng_records_unannotated",
                "pcapng_records_written",
                "pre_attribution_packets",
                "tcp_fast_retransmits",
                "tcp_out_of_order",
                "tcp_retransmits",
                "total_connections_archived",
                "total_connections_created",
            ]
        );

        let connection = value["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|connection| connection["protocol"] == "TCP")
            .unwrap();
        assert_eq!(
            object_keys(connection),
            [
                "application",
                "closed_at",
                "created_at",
                "direction",
                "geoip",
                "historic",
                "hostname",
                "hostname_source",
                "id",
                "kubernetes",
                "last_activity",
                "local",
                "process",
                "protocol",
                "remote",
                "remote_is_gateway",
                "rtt",
                "service",
                "state",
                "traffic",
            ]
        );
        assert_eq!(
            object_keys(&connection["local"]),
            ["address_kind", "ip", "port"]
        );
        assert_eq!(
            object_keys(&connection["remote"]),
            ["address_kind", "ip", "port"]
        );
        assert_eq!(
            object_keys(&connection["process"]),
            [
                "attribution_match",
                "executable",
                "gid",
                "lineage",
                "name",
                "pid",
                "ppid",
                "uid",
            ]
        );
        assert_eq!(
            object_keys(&connection["traffic"]),
            [
                "bytes_received",
                "bytes_sent",
                "incoming_bytes_per_second",
                "outgoing_bytes_per_second",
                "packets_received",
                "packets_sent",
            ]
        );
        assert_eq!(
            object_keys(&connection["rtt"]),
            [
                "current_ms",
                "dns_response_ms",
                "icmp_echo_ms",
                "initial_ms",
                "llmnr_response_ms",
                "netbios_response_ms",
                "ntp_ms",
                "stun_ms",
                "tcp_smoothed_ms",
            ]
        );
        assert_eq!(connection["rtt"]["current_ms"], 18.0);
        assert_eq!(connection["rtt"]["initial_ms"], 11.0);
        assert_eq!(connection["rtt"]["tcp_smoothed_ms"], 18.0);
        assert_eq!(connection["rtt"]["dns_response_ms"], 12.0);
        assert_eq!(connection["rtt"]["llmnr_response_ms"], 13.0);
        assert_eq!(connection["rtt"]["netbios_response_ms"], 14.0);
        assert_eq!(connection["rtt"]["icmp_echo_ms"], 15.0);
        assert_eq!(connection["rtt"]["stun_ms"], 16.0);
        assert_eq!(connection["rtt"]["ntp_ms"], 17.0);
        assert!(connection["traffic"]["outgoing_bytes_per_second"].is_null());
        assert!(connection["traffic"]["incoming_bytes_per_second"].is_null());
        assert_eq!(
            value["connection_count"],
            value["connections"].as_array().unwrap().len()
        );
        assert!(value["filter"].is_null());
        DateTime::parse_from_rfc3339(value["timestamp"].as_str().unwrap()).unwrap();
        let ids: Vec<_> = value["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|connection| connection["id"].as_str().unwrap())
            .collect();
        assert!(ids.windows(2).all(|pair| pair[0] <= pair[1]));

        let lineage = serde_json::to_value(ProcessLineageSnapshot {
            ancestors: vec![ProcessAncestorSnapshot {
                pid: 1,
                name: "init".to_string(),
                executable: None,
                started_at_unix_ms: None,
            }],
            truncated: false,
        })
        .unwrap();
        assert_eq!(object_keys(&lineage), ["ancestors", "truncated"]);
        assert_eq!(
            object_keys(&lineage["ancestors"][0]),
            ["executable", "name", "pid", "started_at_unix_ms"]
        );

        let geoip = serde_json::to_value(GeoIpSnapshot {
            country_code: None,
            country_name: None,
            asn: None,
            as_org: None,
            city: None,
            postal_code: None,
        })
        .unwrap();
        assert_eq!(
            object_keys(&geoip),
            [
                "as_org",
                "asn",
                "city",
                "country_code",
                "country_name",
                "postal_code",
            ]
        );

        let kubernetes = serde_json::to_value(KubernetesSnapshot {
            pod_uid: None,
            pod_name: None,
            pod_namespace: None,
            container_id: None,
            container_name: None,
            cgroup_path: None,
        })
        .unwrap();
        assert_eq!(
            object_keys(&kubernetes),
            [
                "cgroup_path",
                "container_id",
                "container_name",
                "pod_name",
                "pod_namespace",
                "pod_uid",
            ]
        );
    }

    #[test]
    fn connection_identity_survives_archival_and_distinguishes_tuple_reuse() {
        let mut connection = Connection::new(
            Protocol::Tcp,
            "127.0.0.1:45000".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );
        connection.created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let live = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        connection.is_historic = true;
        connection.closed_at = Some(connection.created_at + Duration::from_secs(1));
        let archived =
            serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_eq!(live["id"], archived["id"]);

        connection.is_historic = false;
        connection.closed_at = None;
        connection.created_at += Duration::from_nanos(1);
        let reused =
            serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_ne!(live["id"], reused["id"]);
        assert_eq!(live["local"], reused["local"]);
        assert_eq!(live["remote"], reused["remote"]);
    }

    #[test]
    fn traffic_rates_serialize_explicit_byte_units() {
        let mut connection = Connection::new(
            Protocol::Udp,
            "127.0.0.1:45000".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        connection.current_outgoing_rate_bps = 125.0;
        connection.current_incoming_rate_bps = 250.0;
        let value = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_eq!(value["traffic"]["outgoing_bytes_per_second"], 125.0);
        assert_eq!(value["traffic"]["incoming_bytes_per_second"], 250.0);
        assert!(value["traffic"].get("outgoing_rate_bps").is_none());
        assert!(value["traffic"].get("incoming_rate_bps").is_none());
    }

    #[test]
    fn terminal_status_keeps_timed_out_workers_in_stopping_phase() {
        let app = app_with_connections();
        for report in [
            StopReport {
                timed_out_workers: 1,
                ..StopReport::default()
            },
            StopReport {
                timed_out_workers: 1,
                panicked_workers: 1,
                output_errors: 1,
                ..StopReport::default()
            },
        ] {
            let failure = shutdown_failure(report).unwrap();
            let (_, snapshot) = SnapshotEnvelope::new(
                &app,
                None,
                RuntimePhase::after_stop(report, true),
                Some(failure.kind.termination_reason()),
                Some(report),
            );
            let value = serde_json::to_value(snapshot).unwrap();
            assert_eq!(value["runtime"]["status"], "stopping");
            assert_eq!(value["runtime"]["termination_reason"], "runtime_failed");
            assert_eq!(value["runtime"]["shutdown"]["timed_out_workers"], 1);
        }
    }

    #[test]
    fn process_snapshot_keeps_metadata_without_a_pid_name_or_executable() {
        let mut connection = Connection::new(
            Protocol::Udp,
            "127.0.0.1:40000".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        connection.process_ppid = Some(7);

        let value = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();

        assert_eq!(value["process"]["ppid"], 7);
        assert!(value["process"]["pid"].is_null());
        assert!(value["process"]["name"].is_null());
        assert!(value["process"]["executable"].is_null());
    }

    #[test]
    fn whitespace_only_filter_serializes_as_null() {
        let app = app_with_connections();
        let (_, snapshot) =
            SnapshotEnvelope::new(&app, Some(" \t "), RuntimePhase::Running, None, None);
        let value = serde_json::to_value(snapshot).unwrap();

        assert!(value["filter"].is_null());
        assert_eq!(value["connection_count"], 2);
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
}
