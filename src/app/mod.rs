//! Application orchestration: spins up the packet-capture pipeline, the
//! DNS resolver, the GeoIP resolver, and the interface-stats collector,
//! and owns the shared `DashMap` connection table that the TUI renders.
//!
//! Threads communicate over `crossbeam` channels; counters use atomics.

mod capture;
mod enrichment;
mod logging;
mod output;
mod pcapng_export;
mod runtime;
mod sampling;
#[cfg(test)]
#[path = "../test_support/scratch_dir.rs"]
mod scratch_dir;
mod state;
mod types;
#[cfg(target_os = "windows")]
mod windows_output;

pub use output::{open_private_append_file, precreate_private_file, validate_output_paths};
pub use runtime::{InitStatus, StopReport, WorkerStartupPermit};
pub use state::App;
pub(crate) use types::ConnectionCounts;
pub use types::{AppOutputHandles, AppStats, Config};

use std::time::Duration;

/// Maximum queued packets before backpressure drops packets.
/// At the capture snap length, 10,000 packets is about 15 MB of packet data.
const MAX_PACKET_QUEUE: usize = 10_000;
/// Maximum packets grouped into one capture-to-processor channel item.
const PACKET_BATCH_SIZE: usize = 100;
/// The channel stores batches, so derive its capacity from the packet limit.
const PACKET_BATCH_QUEUE_CAPACITY: usize = MAX_PACKET_QUEUE / PACKET_BATCH_SIZE;
const _: () = assert!(MAX_PACKET_QUEUE.is_multiple_of(PACKET_BATCH_SIZE));
const MAX_PCAPNG_QUEUE: usize = 10_000;
const MAX_PCAPNG_RETRY_RECORDS: usize = 10_000;
const MAX_PCAPNG_RETRY_BYTES: usize = 64 * 1024 * 1024;
const PCAPNG_ATTRIBUTION_WAIT: Duration = Duration::from_secs(2);
const STARTUP_SPLASH_DURATION: Duration = Duration::from_millis(750);
const LIVE_RATE_INTERVAL: Duration = Duration::from_millis(500);
/// Shortest measurement window that may be converted into a per-second rate.
/// The traffic-history thread's first pass measures only the few milliseconds
/// since its baselines were initialized; dividing the startup burst of
/// connection creations by such a sliver window turns a handful of events
/// into a thousands-per-second outlier that pins the graph ceiling for the
/// whole 60s history window. Keep this at half of [`LIVE_RATE_INTERVAL`].
const MIN_RATE_SAMPLE_SECONDS: f64 = 0.25;
const TRAFFIC_HISTORY_SECONDS: usize = 60;
const TRAFFIC_HISTORY_CAPACITY: usize = TRAFFIC_HISTORY_SECONDS * 2;
