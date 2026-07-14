//! Process traffic accounting over active and retained historic connections.
//!
//! Connection rows are intentionally short lived, but security-relevant
//! traffic often needs to remain visible after a socket and its owning process
//! have exited. [`ProcessActivityTracker`] streams the connection tracker's
//! existing active and bounded historic rows into compact one-second and
//! rolling-window metrics for user interfaces and exporters.

use crate::network::types::{ApplicationProtocol, Connection, ConnectionKey};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

const UNKNOWN_NAME: &str = "Unknown";
const OTHER_NAME: &str = "Other";

/// Bounds for retained process accounting.
#[derive(Debug, Clone)]
pub struct ProcessActivityConfig {
    /// Maximum number of historic process buckets represented in one sample.
    /// Additional identities are folded into attributed/unattributed `Other`
    /// buckets. Active identities are always represented individually.
    pub max_completed_processes: usize,
    /// Maximum number of unique destinations reported per process. When this
    /// is exceeded, the visible count is rendered with a `+` suffix. Top peers
    /// are still selected from every destination in the transient sample.
    pub max_destinations_per_process: usize,
    /// Rolling traffic window used by the activity UI.
    pub window: Duration,
}

impl Default for ProcessActivityConfig {
    fn default() -> Self {
        Self {
            max_completed_processes: 4096,
            max_destinations_per_process: 256,
            window: Duration::from_secs(60),
        }
    }
}

/// Stable identity used to aggregate connections into process rows.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessIdentity {
    pub pid: Option<u32>,
    pub name: String,
    pub attributed: bool,
}

impl ProcessIdentity {
    fn from_connection(conn: &Connection) -> Self {
        let attributed = conn.pid.is_some() || conn.process_name.is_some();
        Self {
            pid: conn.pid,
            name: conn
                .process_name
                .clone()
                .unwrap_or_else(|| UNKNOWN_NAME.to_string()),
            attributed,
        }
    }

    fn overflow(attributed: bool) -> Self {
        Self {
            pid: None,
            name: if attributed {
                OTHER_NAME.to_string()
            } else {
                UNKNOWN_NAME.to_string()
            },
            attributed,
        }
    }

    pub fn display_name(&self) -> String {
        match self.pid {
            Some(pid) => format!("{} ({pid})", self.name),
            None => self.name.clone(),
        }
    }
}

/// Traffic attributed to one remote socket for a process.
#[derive(Debug, Clone)]
pub struct DestinationActivity {
    pub remote_addr: SocketAddr,
    pub label: Option<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub connections: u64,
}

impl DestinationActivity {
    pub fn display_name(&self) -> String {
        self.label
            .as_ref()
            .map(|label| format!("{label}:{}", self.remote_addr.port()))
            .unwrap_or_else(|| self.remote_addr.to_string())
    }
}

/// Aggregated retained and rolling metrics for one process identity.
#[derive(Debug, Clone)]
pub struct ProcessActivity {
    pub identity: ProcessIdentity,
    pub current_tx_bps: f64,
    pub current_rx_bps: f64,
    pub window_tx_bytes: u64,
    pub window_rx_bytes: u64,
    pub peak_tx_bps: f64,
    pub peak_rx_bps: f64,
    pub retained_tx_bytes: u64,
    pub retained_rx_bytes: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub unique_destinations: usize,
    pub destinations_truncated: bool,
    pub top_tx_destination: Option<DestinationActivity>,
    pub top_rx_destination: Option<DestinationActivity>,
    pub current_tx_share: f64,
    pub current_rx_share: f64,
    pub window_tx_share: f64,
    pub window_rx_share: f64,
    pub retained_tx_share: f64,
    pub retained_rx_share: f64,
    pub first_seen: SystemTime,
    pub last_seen: SystemTime,
}

/// Immutable point-in-time process activity view.
#[derive(Debug, Clone)]
pub struct ProcessActivitySnapshot {
    pub generated_at: SystemTime,
    pub processes: Vec<ProcessActivity>,
    pub current_tx_bps: f64,
    pub current_rx_bps: f64,
    pub window_tx_bytes: u64,
    pub window_rx_bytes: u64,
    pub retained_tx_bytes: u64,
    pub retained_rx_bytes: u64,
    pub attributed_tx_bytes: u64,
    pub attributed_rx_bytes: u64,
}

impl Default for ProcessActivitySnapshot {
    fn default() -> Self {
        Self {
            generated_at: SystemTime::UNIX_EPOCH,
            processes: Vec::new(),
            current_tx_bps: 0.0,
            current_rx_bps: 0.0,
            window_tx_bytes: 0,
            window_rx_bytes: 0,
            retained_tx_bytes: 0,
            retained_rx_bytes: 0,
            attributed_tx_bytes: 0,
            attributed_rx_bytes: 0,
        }
    }
}

impl ProcessActivitySnapshot {
    pub fn tx_attribution_pct(&self) -> f64 {
        percentage(
            self.attributed_tx_bytes as f64,
            self.retained_tx_bytes as f64,
        )
    }

    pub fn rx_attribution_pct(&self) -> f64 {
        percentage(
            self.attributed_rx_bytes as f64,
            self.retained_rx_bytes as f64,
        )
    }
}

#[derive(Debug, Clone)]
struct FlowActivity {
    identity: ProcessIdentity,
    bytes_sent: u64,
    bytes_received: u64,
    remote_addr: SocketAddr,
    remote_label: Option<String>,
    created_at: SystemTime,
    last_activity: SystemTime,
}

impl FlowActivity {
    fn from_connection(conn: &Connection) -> Self {
        Self {
            identity: ProcessIdentity::from_connection(conn),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            remote_addr: conn.remote_addr,
            remote_label: destination_label(conn),
            created_at: conn.created_at,
            last_activity: conn.last_activity,
        }
    }
}

/// Fixed-size identity used to detect byte growth without retaining a second
/// copy of each full connection. Creation time distinguishes historic flows
/// that reused the same protocol and socket tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowIdentity {
    key: ConnectionKey,
    created_nanos: u128,
}

impl FlowIdentity {
    fn from_connection(conn: &Connection) -> Self {
        Self {
            key: ConnectionKey::new(conn.protocol, conn.local_addr, conn.remote_addr),
            created_nanos: conn
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FlowCounters {
    tx_bytes: u64,
    rx_bytes: u64,
    observed_generation: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct TrafficDelta {
    tx_bytes: u64,
    rx_bytes: u64,
}

impl TrafficDelta {
    fn add(&mut self, other: Self) {
        self.tx_bytes = self.tx_bytes.saturating_add(other.tx_bytes);
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
    }
}

#[derive(Debug, Clone)]
struct ProcessAccumulator {
    tx_bytes: u64,
    rx_bytes: u64,
    active_connections: usize,
    completed_connections: u64,
    destinations: HashMap<SocketAddr, DestinationActivity>,
    first_seen: SystemTime,
    last_seen: SystemTime,
}

impl ProcessAccumulator {
    fn new(first_seen: SystemTime) -> Self {
        Self {
            tx_bytes: 0,
            rx_bytes: 0,
            active_connections: 0,
            completed_connections: 0,
            destinations: HashMap::new(),
            first_seen,
            last_seen: first_seen,
        }
    }

    fn add_flow(&mut self, flow: &FlowActivity, completed: bool) {
        self.tx_bytes = self.tx_bytes.saturating_add(flow.bytes_sent);
        self.rx_bytes = self.rx_bytes.saturating_add(flow.bytes_received);
        if completed {
            self.completed_connections = self.completed_connections.saturating_add(1);
        } else {
            self.active_connections = self.active_connections.saturating_add(1);
        }
        self.first_seen = self.first_seen.min(flow.created_at);
        self.last_seen = self.last_seen.max(flow.last_activity);
        self.add_destination(flow);
    }

    fn add_destination(&mut self, flow: &FlowActivity) {
        if let Some(destination) = self.destinations.get_mut(&flow.remote_addr) {
            destination.tx_bytes = destination.tx_bytes.saturating_add(flow.bytes_sent);
            destination.rx_bytes = destination.rx_bytes.saturating_add(flow.bytes_received);
            destination.connections = destination.connections.saturating_add(1);
            if destination.label.is_none() {
                destination.label.clone_from(&flow.remote_label);
            }
            return;
        }

        self.destinations.insert(
            flow.remote_addr,
            DestinationActivity {
                remote_addr: flow.remote_addr,
                label: flow.remote_label.clone(),
                tx_bytes: flow.bytes_sent,
                rx_bytes: flow.bytes_received,
                connections: 1,
            },
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct ProcessSample {
    timestamp: SystemTime,
    tx_bytes: u64,
    rx_bytes: u64,
}

#[derive(Debug, Default)]
struct ProcessHistory {
    samples: VecDeque<ProcessSample>,
    cumulative_tx_bytes: u64,
    cumulative_rx_bytes: u64,
    current_tx_bps: f64,
    current_rx_bps: f64,
    peak_tx_bps: f64,
    peak_rx_bps: f64,
}

impl ProcessHistory {
    fn sample(
        &mut self,
        now: SystemTime,
        tx_delta: u64,
        rx_delta: u64,
        window: Duration,
        active: bool,
    ) {
        if self.samples.is_empty() {
            // Monotonic counters begin at the first retained observation. A
            // zero baseline at the same instant includes the first observed
            // bytes in the rolling window without inventing a current rate.
            self.samples.push_back(ProcessSample {
                timestamp: now,
                tx_bytes: self.cumulative_tx_bytes,
                rx_bytes: self.cumulative_rx_bytes,
            });
        }

        self.cumulative_tx_bytes = self.cumulative_tx_bytes.saturating_add(tx_delta);
        self.cumulative_rx_bytes = self.cumulative_rx_bytes.saturating_add(rx_delta);
        let tx_bytes = self.cumulative_tx_bytes;
        let rx_bytes = self.cumulative_rx_bytes;

        let unchanged = self
            .samples
            .back()
            .is_some_and(|sample| sample.tx_bytes == tx_bytes && sample.rx_bytes == rx_bytes);
        if !active && unchanged {
            self.current_tx_bps = 0.0;
            self.current_rx_bps = 0.0;
            self.prune(now, window, false);
            return;
        }

        if let Some(previous) = self.samples.back().copied() {
            let elapsed = now
                .duration_since(previous.timestamp)
                .unwrap_or_default()
                .as_secs_f64();
            if elapsed > 0.0 {
                self.current_tx_bps = tx_bytes.saturating_sub(previous.tx_bytes) as f64 / elapsed;
                self.current_rx_bps = rx_bytes.saturating_sub(previous.rx_bytes) as f64 / elapsed;
                self.peak_tx_bps = self.peak_tx_bps.max(self.current_tx_bps);
                self.peak_rx_bps = self.peak_rx_bps.max(self.current_rx_bps);
            }
        }

        self.samples.push_back(ProcessSample {
            timestamp: now,
            tx_bytes,
            rx_bytes,
        });

        self.prune(now, window, active);
    }

    fn prune(&mut self, now: SystemTime, window: Duration, active: bool) {
        while self.samples.len() > 2
            && self.samples.get(1).is_some_and(|sample| {
                now.duration_since(sample.timestamp).unwrap_or_default() >= window
            })
        {
            self.samples.pop_front();
        }

        if !active
            && self.samples.back().is_some_and(|sample| {
                now.duration_since(sample.timestamp).unwrap_or_default() >= window
            })
            && let Some(last) = self.samples.back().copied()
        {
            self.samples.clear();
            self.samples.push_back(last);
        }
    }

    fn window_bytes(&self, now: SystemTime, window: Duration) -> (u64, u64) {
        if self.samples.back().is_some_and(|sample| {
            now.duration_since(sample.timestamp).unwrap_or_default() >= window
        }) {
            return (0, 0);
        }
        match (self.samples.front(), self.samples.back()) {
            (Some(first), Some(last)) => (
                last.tx_bytes.saturating_sub(first.tx_bytes),
                last.rx_bytes.saturating_sub(first.rx_bytes),
            ),
            _ => (0, 0),
        }
    }
}

fn observe_flow_delta(
    flow_counters: &mut HashMap<FlowIdentity, FlowCounters>,
    conn: &Connection,
    generation: u64,
) -> TrafficDelta {
    let identity = FlowIdentity::from_connection(conn);
    match flow_counters.entry(identity) {
        std::collections::hash_map::Entry::Occupied(mut entry) => {
            let counters = entry.get_mut();
            let delta = TrafficDelta {
                tx_bytes: conn.bytes_sent.saturating_sub(counters.tx_bytes),
                rx_bytes: conn.bytes_received.saturating_sub(counters.rx_bytes),
            };
            counters.tx_bytes = conn.bytes_sent;
            counters.rx_bytes = conn.bytes_received;
            counters.observed_generation = generation;
            delta
        }
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(FlowCounters {
                tx_bytes: conn.bytes_sent,
                rx_bytes: conn.bytes_received,
                observed_generation: generation,
            });
            TrafficDelta {
                tx_bytes: conn.bytes_sent,
                rx_bytes: conn.bytes_received,
            }
        }
    }
}

/// Process traffic view derived from active and retained historic connections.
pub struct ProcessActivityTracker {
    config: ProcessActivityConfig,
    sample: HashMap<ProcessIdentity, ProcessAccumulator>,
    flow_counters: HashMap<FlowIdentity, FlowCounters>,
    sample_generation: u64,
    histories: HashMap<ProcessIdentity, ProcessHistory>,
    snapshot: ProcessActivitySnapshot,
}

impl ProcessActivityTracker {
    pub fn new() -> Self {
        Self::with_config(ProcessActivityConfig::default())
    }

    pub fn with_config(config: ProcessActivityConfig) -> Self {
        Self {
            config,
            sample: HashMap::new(),
            flow_counters: HashMap::new(),
            sample_generation: 0,
            histories: HashMap::new(),
            snapshot: ProcessActivitySnapshot::default(),
        }
    }

    /// Aggregate one complete active-plus-historic connection view.
    /// Repeated observations are idempotent because compact per-flow counters
    /// contribute only newly observed bytes.
    pub fn observe_connections(&mut self, connections: &[Connection], now: SystemTime) {
        self.observe_sources(
            now,
            |observe| {
                for connection in connections.iter().filter(|conn| !conn.is_historic) {
                    observe(connection);
                }
            },
            |observe| {
                for connection in connections.iter().filter(|conn| conn.is_historic) {
                    observe(connection);
                }
            },
        );
    }

    /// Stream active and historic sources into one sample without cloning
    /// their full [`Connection`] values.
    ///
    /// The historic callback is replayed once to choose a deterministic,
    /// bounded set of completed process identities and once to aggregate it.
    /// Callers must therefore provide stable sources for the duration of this
    /// synchronous method.
    pub fn observe_sources<A, H>(
        &mut self,
        now: SystemTime,
        mut feed_active: A,
        mut feed_historic: H,
    ) where
        A: FnMut(&mut dyn FnMut(&Connection)),
        H: FnMut(&mut dyn FnMut(&Connection)),
    {
        self.sample.clear();
        self.sample_generation = self.sample_generation.wrapping_add(1);
        let generation = self.sample_generation;
        let max_processes = self.config.max_completed_processes;
        let mut traffic_deltas: HashMap<ProcessIdentity, TrafficDelta> = HashMap::new();

        {
            let sample = &mut self.sample;
            let flow_counters = &mut self.flow_counters;
            let mut observe = |conn: &Connection| {
                let flow = FlowActivity::from_connection(conn);
                let identity = flow.identity.clone();
                sample
                    .entry(identity.clone())
                    .or_insert_with(|| ProcessAccumulator::new(flow.created_at))
                    .add_flow(&flow, false);
                traffic_deltas
                    .entry(identity)
                    .or_default()
                    .add(observe_flow_delta(flow_counters, conn, generation));
            };
            feed_active(&mut observe);
        }

        let mut completed_identities = BTreeSet::new();
        {
            let active = &self.sample;
            let mut select = |conn: &Connection| {
                let identity = ProcessIdentity::from_connection(conn);
                if active.contains_key(&identity) {
                    return;
                }
                completed_identities.insert(identity);
                if completed_identities.len() > max_processes {
                    completed_identities.pop_last();
                }
            };
            feed_historic(&mut select);
        }

        {
            let sample = &mut self.sample;
            let flow_counters = &mut self.flow_counters;
            let mut observe = |conn: &Connection| {
                let flow = FlowActivity::from_connection(conn);
                let identity = if sample.contains_key(&flow.identity)
                    || completed_identities.contains(&flow.identity)
                {
                    flow.identity.clone()
                } else {
                    ProcessIdentity::overflow(flow.identity.attributed)
                };
                sample
                    .entry(identity.clone())
                    .or_insert_with(|| ProcessAccumulator::new(flow.created_at))
                    .add_flow(&flow, true);
                traffic_deltas
                    .entry(identity)
                    .or_default()
                    .add(observe_flow_delta(flow_counters, conn, generation));
            };
            feed_historic(&mut observe);
        }

        self.flow_counters
            .retain(|_, counters| counters.observed_generation == generation);
        self.rebuild_snapshot(now, &traffic_deltas);
        self.sample.clear();
    }

    pub fn snapshot(&self) -> ProcessActivitySnapshot {
        self.snapshot.clone()
    }

    pub fn clear(&mut self) {
        self.sample.clear();
        self.flow_counters.clear();
        self.sample_generation = 0;
        self.histories.clear();
        self.snapshot = ProcessActivitySnapshot::default();
    }

    fn rebuild_snapshot(
        &mut self,
        now: SystemTime,
        traffic_deltas: &HashMap<ProcessIdentity, TrafficDelta>,
    ) {
        self.histories
            .retain(|identity, _| self.sample.contains_key(identity));

        for (identity, aggregate) in &self.sample {
            let is_new = !self.histories.contains_key(identity);
            let delta = traffic_deltas.get(identity).copied().unwrap_or_default();
            let (tx_delta, rx_delta) = if is_new {
                (aggregate.tx_bytes, aggregate.rx_bytes)
            } else {
                (delta.tx_bytes, delta.rx_bytes)
            };
            self.histories.entry(identity.clone()).or_default().sample(
                now,
                tx_delta,
                rx_delta,
                self.config.window,
                aggregate.active_connections > 0,
            );
        }

        let mut processes = Vec::with_capacity(self.sample.len());
        for (identity, aggregate) in &self.sample {
            let history = self.histories.entry(identity.clone()).or_default();
            let (window_tx_bytes, window_rx_bytes) = history.window_bytes(now, self.config.window);
            let destination_count = aggregate.destinations.len();
            let top_tx_destination = aggregate
                .destinations
                .values()
                .max_by(|a, b| {
                    a.tx_bytes
                        .cmp(&b.tx_bytes)
                        .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                })
                .cloned();
            let top_rx_destination = aggregate
                .destinations
                .values()
                .max_by(|a, b| {
                    a.rx_bytes
                        .cmp(&b.rx_bytes)
                        .then_with(|| a.remote_addr.cmp(&b.remote_addr))
                })
                .cloned();
            processes.push(ProcessActivity {
                identity: identity.clone(),
                current_tx_bps: history.current_tx_bps,
                current_rx_bps: history.current_rx_bps,
                window_tx_bytes,
                window_rx_bytes,
                peak_tx_bps: history.peak_tx_bps,
                peak_rx_bps: history.peak_rx_bps,
                retained_tx_bytes: aggregate.tx_bytes,
                retained_rx_bytes: aggregate.rx_bytes,
                active_connections: aggregate.active_connections,
                total_connections: aggregate
                    .completed_connections
                    .saturating_add(aggregate.active_connections as u64),
                unique_destinations: destination_count
                    .min(self.config.max_destinations_per_process),
                destinations_truncated: destination_count
                    > self.config.max_destinations_per_process,
                top_tx_destination,
                top_rx_destination,
                current_tx_share: 0.0,
                current_rx_share: 0.0,
                window_tx_share: 0.0,
                window_rx_share: 0.0,
                retained_tx_share: 0.0,
                retained_rx_share: 0.0,
                first_seen: aggregate.first_seen,
                last_seen: aggregate.last_seen,
            });
        }

        let current_tx_bps = processes.iter().map(|p| p.current_tx_bps).sum();
        let current_rx_bps = processes.iter().map(|p| p.current_rx_bps).sum();
        let window_tx_bytes = processes.iter().map(|p| p.window_tx_bytes).sum();
        let window_rx_bytes = processes.iter().map(|p| p.window_rx_bytes).sum();
        let retained_tx_bytes = processes.iter().map(|p| p.retained_tx_bytes).sum();
        let retained_rx_bytes = processes.iter().map(|p| p.retained_rx_bytes).sum();
        let attributed_tx_bytes = processes
            .iter()
            .filter(|p| p.identity.attributed)
            .map(|p| p.retained_tx_bytes)
            .sum();
        let attributed_rx_bytes = processes
            .iter()
            .filter(|p| p.identity.attributed)
            .map(|p| p.retained_rx_bytes)
            .sum();

        for process in &mut processes {
            process.current_tx_share = percentage(process.current_tx_bps, current_tx_bps);
            process.current_rx_share = percentage(process.current_rx_bps, current_rx_bps);
            process.window_tx_share =
                percentage(process.window_tx_bytes as f64, window_tx_bytes as f64);
            process.window_rx_share =
                percentage(process.window_rx_bytes as f64, window_rx_bytes as f64);
            process.retained_tx_share =
                percentage(process.retained_tx_bytes as f64, retained_tx_bytes as f64);
            process.retained_rx_share =
                percentage(process.retained_rx_bytes as f64, retained_rx_bytes as f64);
        }
        processes.sort_by(|a, b| {
            b.retained_tx_bytes
                .cmp(&a.retained_tx_bytes)
                .then_with(|| a.identity.name.cmp(&b.identity.name))
                .then_with(|| a.identity.pid.cmp(&b.identity.pid))
        });

        self.snapshot = ProcessActivitySnapshot {
            generated_at: now,
            processes,
            current_tx_bps,
            current_rx_bps,
            window_tx_bytes,
            window_rx_bytes,
            retained_tx_bytes,
            retained_rx_bytes,
            attributed_tx_bytes,
            attributed_rx_bytes,
        };
    }
}

impl Default for ProcessActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn percentage(part: f64, total: f64) -> f64 {
    if total > 0.0 {
        (part / total * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    }
}

fn destination_label(conn: &Connection) -> Option<String> {
    let dpi = conn.dpi_info.as_ref()?;
    match &dpi.application {
        ApplicationProtocol::Https(info) => info
            .tls_info
            .as_ref()
            .and_then(|tls| tls.sni.as_ref())
            .cloned(),
        ApplicationProtocol::Quic(info) => info
            .tls_info
            .as_ref()
            .and_then(|tls| tls.sni.as_ref())
            .cloned(),
        ApplicationProtocol::Http(info) => info.host.clone(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use std::net::{IpAddr, Ipv4Addr};

    fn connection(pid: Option<u32>, name: Option<&str>, remote_port: u16) -> Connection {
        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40_000 + remote_port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), remote_port),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.pid = pid;
        conn.process_name = name.map(str::to_string);
        conn
    }

    #[test]
    fn aggregates_active_and_retained_historic_flows() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut a = connection(Some(7), Some("uploader"), 443);
        let mut b = connection(Some(7), Some("uploader"), 8443);
        a.created_at = start;
        b.created_at = start + Duration::from_millis(1);
        a.bytes_sent = 800;
        b.bytes_sent = 200;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[a.clone(), b.clone()], start + Duration::from_secs(1));
        a.is_historic = true;
        tracker.observe_connections(&[a, b], start + Duration::from_secs(2));

        let snapshot = tracker.snapshot();
        let process = &snapshot.processes[0];
        assert_eq!(process.retained_tx_bytes, 1000);
        assert_eq!(process.active_connections, 1);
        assert_eq!(process.total_connections, 2);
        assert_eq!(process.unique_destinations, 2);
    }

    #[test]
    fn late_attribution_moves_active_bytes_out_of_unknown() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
        let mut conn = connection(None, None, 443);
        conn.created_at = now;
        conn.bytes_sent = 4096;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[conn.clone()], now + Duration::from_secs(1));
        assert!(!tracker.snapshot().processes[0].identity.attributed);

        conn.pid = Some(42);
        conn.process_name = Some("agent-helper".to_string());
        tracker.observe_connections(&[conn], now + Duration::from_secs(2));
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.processes.len(), 1);
        assert_eq!(snapshot.processes[0].identity.pid, Some(42));
        assert_eq!(snapshot.attributed_tx_bytes, 4096);
    }

    #[test]
    fn repeated_historic_observations_are_idempotent() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(300);
        let mut conn = connection(Some(9), Some("once"), 443);
        conn.created_at = now;
        conn.bytes_sent = 1234;
        conn.is_historic = true;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[conn.clone()], now + Duration::from_secs(1));
        tracker.observe_connections(&[conn], now + Duration::from_secs(2));

        let process = &tracker.snapshot().processes[0];
        assert_eq!(process.retained_tx_bytes, 1234);
        assert_eq!(process.active_connections, 0);
        assert_eq!(process.total_connections, 1);
    }

    #[test]
    fn calculates_current_window_and_retained_shares() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(400);
        let mut first = connection(Some(1), Some("first"), 443);
        let mut second = connection(Some(2), Some("second"), 443);
        first.created_at = now;
        second.created_at = now + Duration::from_millis(1);

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(
            &[first.clone(), second.clone()],
            now + Duration::from_secs(1),
        );
        first.bytes_sent = 750;
        second.bytes_sent = 250;
        first.bytes_received = 250;
        second.bytes_received = 750;
        tracker.observe_connections(&[first, second], now + Duration::from_secs(2));

        let snapshot = tracker.snapshot();
        let first = snapshot
            .processes
            .iter()
            .find(|process| process.identity.name == "first")
            .unwrap();
        assert_eq!(snapshot.window_tx_bytes, 1000);
        assert_eq!(snapshot.window_rx_bytes, 1000);
        assert_eq!(first.current_tx_bps, 750.0);
        assert_eq!(first.current_rx_bps, 250.0);
        assert_eq!(first.peak_rx_bps, 250.0);
        assert_eq!(first.window_tx_share, 75.0);
        assert_eq!(first.window_rx_share, 25.0);
        assert_eq!(first.retained_tx_share, 75.0);
        assert_eq!(first.retained_rx_share, 25.0);
    }

    #[test]
    fn first_observation_is_visible_in_the_window_without_a_fake_rate() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(500);
        let mut conn = connection(Some(12), Some("quick-uploader"), 443);
        conn.created_at = now;
        conn.bytes_sent = 64 * 1024 * 1024;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[conn], now + Duration::from_secs(1));

        let process = &tracker.snapshot().processes[0];
        assert_eq!(process.window_tx_bytes, 64 * 1024 * 1024);
        assert_eq!(process.current_tx_bps, 0.0);
        assert_eq!(process.window_tx_share, 100.0);
    }

    #[test]
    fn historic_eviction_preserves_new_traffic_in_both_directions() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(600);
        let mut old = connection(Some(21), Some("worker"), 443);
        let mut live = connection(Some(21), Some("worker"), 8443);
        old.created_at = now;
        live.created_at = now + Duration::from_millis(1);
        old.bytes_sent = 10_000;
        old.bytes_received = 100;
        old.is_historic = true;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[old, live.clone()], now + Duration::from_secs(1));

        live.bytes_sent = 100;
        live.bytes_received = 300;
        tracker.observe_connections(&[live.clone()], now + Duration::from_secs(2));
        let after_eviction = &tracker.snapshot().processes[0];
        assert_eq!(after_eviction.retained_tx_bytes, 100);
        assert_eq!(after_eviction.retained_rx_bytes, 300);
        assert_eq!(after_eviction.current_tx_bps, 100.0);
        assert_eq!(after_eviction.current_rx_bps, 300.0);
        assert_eq!(after_eviction.window_tx_bytes, 10_100);
        assert_eq!(after_eviction.window_rx_bytes, 400);

        live.bytes_sent = 300;
        live.bytes_received = 500;
        tracker.observe_connections(&[live], now + Duration::from_secs(3));
        let resumed = &tracker.snapshot().processes[0];
        assert_eq!(resumed.current_tx_bps, 200.0);
        assert_eq!(resumed.current_rx_bps, 200.0);
        assert_eq!(resumed.window_tx_bytes, 10_300);
        assert_eq!(resumed.window_rx_bytes, 600);
    }

    #[test]
    fn historic_eviction_does_not_reduce_a_larger_new_delta() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(650);
        let mut old = connection(Some(22), Some("worker"), 443);
        let mut live = connection(Some(22), Some("worker"), 8443);
        old.created_at = now;
        live.created_at = now + Duration::from_millis(1);
        old.bytes_sent = 1_000;
        old.is_historic = true;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[old, live.clone()], now + Duration::from_secs(1));

        live.bytes_sent = 1_500;
        tracker.observe_connections(&[live], now + Duration::from_secs(2));
        let process = &tracker.snapshot().processes[0];
        assert_eq!(process.retained_tx_bytes, 1_500);
        assert_eq!(process.current_tx_bps, 1_500.0);
        assert_eq!(process.window_tx_bytes, 2_500);
    }

    #[test]
    fn full_connection_aggregation_is_transient() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(700);
        let conn = connection(Some(33), Some("short-lived"), 443);
        let mut tracker = ProcessActivityTracker::new();

        tracker.observe_connections(&[conn], now);

        assert!(tracker.sample.is_empty());
        assert_eq!(tracker.snapshot().processes.len(), 1);
        assert_eq!(tracker.histories.len(), 1);
    }

    #[test]
    fn active_to_historic_transition_does_not_create_a_rate_spike() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(800);
        let mut idle = connection(Some(44), Some("long-session"), 443);
        let mut live = connection(Some(44), Some("long-session"), 8443);
        idle.bytes_sent = 500 * 1024 * 1024;

        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[idle.clone(), live.clone()], now);

        live.bytes_sent = 1024;
        tracker.observe_connections(&[idle.clone(), live.clone()], now + Duration::from_secs(1));

        idle.is_historic = true;
        live.bytes_sent = 2048;
        tracker.observe_connections(&[idle, live], now + Duration::from_secs(2));

        let process = &tracker.snapshot().processes[0];
        assert_eq!(process.current_tx_bps, 1024.0);
        assert_eq!(process.peak_tx_bps, 1024.0);
        assert_eq!(process.window_tx_bytes, 500 * 1024 * 1024 + 2048);
    }

    #[test]
    fn completed_process_overflow_is_independent_of_source_order() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(900);
        let mut connections: Vec<_> = (1..=4)
            .map(|pid| {
                let mut conn = connection(Some(pid), Some(&format!("process-{pid}")), 443);
                conn.bytes_sent = u64::from(pid) * 100;
                conn.is_historic = true;
                conn
            })
            .collect();
        let config = ProcessActivityConfig {
            max_completed_processes: 2,
            ..ProcessActivityConfig::default()
        };
        let mut tracker = ProcessActivityTracker::with_config(config);

        tracker.observe_connections(&connections, now);
        let first: Vec<_> = tracker
            .snapshot()
            .processes
            .iter()
            .map(|process| (process.identity.display_name(), process.retained_tx_bytes))
            .collect();

        connections.reverse();
        tracker.observe_connections(&connections, now + Duration::from_secs(1));
        let second: Vec<_> = tracker
            .snapshot()
            .processes
            .iter()
            .map(|process| (process.identity.display_name(), process.retained_tx_bytes))
            .collect();

        assert_eq!(second, first);
        assert!(second.contains(&("process-1 (1)".to_string(), 100)));
        assert!(second.contains(&("process-2 (2)".to_string(), 200)));
        assert!(second.contains(&(OTHER_NAME.to_string(), 700)));
        assert!(
            tracker
                .snapshot()
                .processes
                .iter()
                .all(|process| process.current_tx_bps == 0.0)
        );
    }

    #[test]
    fn destination_cap_does_not_hide_the_highest_volume_peer() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut low = connection(Some(55), Some("scanner"), 80);
        let mut medium = connection(Some(55), Some("scanner"), 443);
        let mut highest = connection(Some(55), Some("scanner"), 8443);
        low.bytes_sent = 10;
        medium.bytes_sent = 20;
        highest.bytes_sent = 10_000;
        low.bytes_received = 30;
        medium.bytes_received = 40;
        highest.bytes_received = 20_000;

        let config = ProcessActivityConfig {
            max_destinations_per_process: 2,
            ..ProcessActivityConfig::default()
        };
        let mut tracker = ProcessActivityTracker::with_config(config);
        tracker.observe_connections(&[low, medium, highest], now);

        let process = &tracker.snapshot().processes[0];
        assert_eq!(process.unique_destinations, 2);
        assert!(process.destinations_truncated);
        assert_eq!(
            process
                .top_tx_destination
                .as_ref()
                .map(|destination| destination.remote_addr.port()),
            Some(8443)
        );
        assert_eq!(
            process
                .top_rx_destination
                .as_ref()
                .map(|destination| destination.remote_addr.port()),
            Some(8443)
        );
    }
}
