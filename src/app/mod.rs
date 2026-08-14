//! Application orchestration: spins up the packet-capture pipeline, the
//! DNS resolver, the GeoIP resolver, and the interface-stats collector,
//! and owns the shared `DashMap` connection table that the TUI renders.
//!
//! Threads communicate over `crossbeam` channels; counters use atomics.

mod capture;
mod enrichment;
mod logging;
mod pcapng_export;
mod sampling;
mod state;
mod types;

pub use state::App;
pub(crate) use types::ConnectionCounts;
pub use types::{
    AppOutputHandles, AppStats, Config, ConnRateHistory, ConnRateHistorySnapshot,
    ProcessDetectionStatus,
};

use std::time::Duration;

// Connection-table limits (max connections, historic retention, QUIC mappings)
// now live in `rustnet_core::network::tracker::TrackerConfig`, which the
// `ConnectionTracker` enforces. The defaults match the previous constants.

/// Maximum queued packets before backpressure drops packets.
/// At ~1500 bytes per packet, 10,000 packets ≈ 15 MB of buffer.
const MAX_PACKET_QUEUE: usize = 10_000;
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
