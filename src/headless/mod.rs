//! Headless front-end: the full capture pipeline with no terminal, streaming
//! connection events as JSON lines to stdout. The serializable event shapes
//! and the line sinks (also used by `--json-log` and the PCAP sidecar) live
//! in the submodules.

pub mod events;
pub mod sink;

use anyhow::{Result, anyhow};
use clap::ArgMatches;
use log::{error, info};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::app::{App, sleep_unless_stopped};
use crate::bootstrap::{self, Frontend, shutdown_requested};
use crate::filter::ConnectionFilter;
use events::{SnapshotEvent, StartupEvent};
use sink::{EventSink, FilteredSink, StdoutSink, json_line};

/// Maximum queued event lines before the stdout stream drops events. A slow
/// or paused consumer must never stall the packet-processing threads.
const MAX_EVENT_QUEUE: usize = 10_000;

/// How often the run loop checks for a shutdown signal, a closed stdout,
/// or a dead capture thread.
const EXIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Run the pipeline until a shutdown signal arrives or stdout is closed
/// (both a normal exit), or the capture thread fails (an error).
pub fn run(matches: &ArgMatches) -> Result<()> {
    // The query is checked before the privilege check and capture open so
    // a typo costs nothing and the error lands on a plain stderr.
    let filter_query = matches.get_one::<String>("filter").map(String::as_str);
    if let Some(query) = filter_query {
        ConnectionFilter::validate(query)
            .map_err(|e| anyhow!("Invalid --filter query {query:?}: {e}"))?;
    }
    let snapshot_interval = matches
        .get_one::<u64>("snapshot-interval")
        .map(|secs| Duration::from_secs(*secs));

    let mut prepared = bootstrap::prepare(matches, Frontend::Headless)?;

    let stdout = Arc::new(StdoutSink::new());
    let live_sink: Arc<dyn EventSink> = match filter_query {
        Some(query) => Arc::new(FilteredSink::new(
            ConnectionFilter::parse(query),
            stdout.clone(),
        )),
        None => stdout.clone(),
    };
    prepared.add_event_sink(live_sink);

    let app = prepared.launch_with(|app| {
        if let Some(line) = json_line(&StartupEvent::from_app(
            app,
            filter_query,
            snapshot_interval,
        )) {
            stdout.write_line(&line);
        }
    })?;
    info!("Headless event stream started");

    let exit = run_until_exit(&app, &stdout, filter_query, snapshot_interval);
    app.stop();

    match exit {
        Exit::Signal => {
            info!("Termination signal received, shutting down");
            Ok(())
        }
        Exit::OutputClosed => {
            info!("Event output closed, shutting down");
            Ok(())
        }
        Exit::CaptureFailed(message) => {
            error!("Packet capture failed: {message}");
            Err(anyhow!("Packet capture failed: {message}"))
        }
    }
}

/// Block until the run should end, with the snapshot ticker (if any)
/// running alongside and stopped before returning: it writes into the
/// stdout sink, which `App::stop` drains and joins afterwards.
fn run_until_exit(
    app: &App,
    stdout: &StdoutSink,
    filter_query: Option<&str>,
    snapshot_interval: Option<Duration>,
) -> Exit {
    let stop_snapshots = AtomicBool::new(false);
    let stop_snapshots = &stop_snapshots;
    thread::scope(|scope| {
        let snapshot_thread = snapshot_interval.map(|interval| {
            thread::Builder::new()
                .name("headless-snapshot".to_string())
                .spawn_scoped(scope, move || {
                    emit_snapshots(
                        app,
                        stdout,
                        filter_query.unwrap_or_default(),
                        interval,
                        stop_snapshots,
                    )
                })
                .expect("Failed to spawn headless-snapshot thread")
        });

        let exit = wait_for_exit(app, stdout);

        stop_snapshots.store(true, Ordering::Relaxed);
        if let Some(handle) = snapshot_thread
            && handle.join().is_err()
        {
            error!("headless-snapshot thread panicked");
        }
        exit
    })
}

enum Exit {
    Signal,
    OutputClosed,
    CaptureFailed(String),
}

fn wait_for_exit(app: &App, stdout: &StdoutSink) -> Exit {
    loop {
        if shutdown_requested() {
            return Exit::Signal;
        }
        if stdout.output_failed() {
            return Exit::OutputClosed;
        }
        if let Some(message) = app.get_capture_error() {
            return Exit::CaptureFailed(message);
        }
        thread::sleep(EXIT_POLL_INTERVAL);
    }
}

/// Write the (filtered) connection table every `interval` until told to
/// stop. The first snapshot waits one full interval so it reflects real
/// traffic rather than an empty table.
fn emit_snapshots(
    app: &App,
    stdout: &StdoutSink,
    filter_query: &str,
    interval: Duration,
    stop: &AtomicBool,
) {
    let dns_resolver = app.get_dns_resolver();
    loop {
        sleep_unless_stopped(stop, interval);
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let connections = app.get_filtered_connections(filter_query);
        if let Some(line) = json_line(&SnapshotEvent::new(&connections, dns_resolver.as_deref())) {
            stdout.write_line(&line);
        }
    }
}
