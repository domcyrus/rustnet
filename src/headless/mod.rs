//! Stable machine-readable output for non-interactive runs.
//!
//! The adapter deliberately projects application state into a versioned
//! schema instead of serializing internal structs. This keeps the wire format
//! independent of implementation details such as atomics and cache fields.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::app::{App, StopReport};

mod output;
mod schema;

use output::{AsyncOutput, OutputRecord, WriterCompletion, serialize_record};
use schema::{RuntimePhase, SnapshotEnvelope};

#[cfg(test)]
mod tests;

/// Current headless output schema.
pub const SCHEMA_VERSION: u8 = 1;

const MAX_STOP_POLL_INTERVAL: Duration = Duration::from_millis(50);
const OUTPUT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Machine-readable output mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum HeadlessFormat {
    /// Emit newline-delimited latest-value snapshots followed by a terminal
    /// snapshot after the shutdown attempt. Slow consumers can observe generation
    /// gaps because stale queued snapshots are replaced under backpressure.
    #[default]
    JsonLines,
    /// Emit exactly one snapshot after the shutdown attempt.
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

/// Run the headless output loop and always attempt bounded application
/// shutdown before returning.
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
