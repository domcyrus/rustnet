//! Process traffic accounting over active and retained historic connections.
//!
//! Connection rows are intentionally short lived, but security-relevant
//! traffic often needs to remain visible after a socket and its owning process
//! have exited. [`ProcessActivityTracker`] streams the connection tracker's
//! existing active and bounded historic rows into compact one-second and
//! rolling-window metrics for user interfaces and exporters.

use crate::network::tracker::HistoricKey;
use crate::network::types::{Connection, ConnectionKey, UNKNOWN_PROCESS_NAME};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

const OTHER_NAME: &str = "Other";

/// Group label used when a connection has no resolved process name.
pub const UNKNOWN_PROCESS_GROUP: &str = "<unknown>";

/// Return the stable process-group label for a connection.
///
/// Both a missing owner and the placeholder used when a PID's image cannot be
/// resolved belong to the same group.
pub fn process_group_label(conn: &Connection) -> &str {
    match conn.process_name.as_deref() {
        None | Some(UNKNOWN_PROCESS_NAME) => UNKNOWN_PROCESS_GROUP,
        Some(name) => name,
    }
}

/// Bounds for retained process accounting.
#[derive(Debug, Clone)]
pub(crate) struct ProcessActivityConfig {
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
                .unwrap_or_else(|| UNKNOWN_PROCESS_NAME.to_string()),
            attributed,
        }
    }

    fn overflow(attributed: bool) -> Self {
        Self {
            pid: None,
            name: if attributed {
                OTHER_NAME.to_string()
            } else {
                UNKNOWN_PROCESS_NAME.to_string()
            },
            attributed,
        }
    }

    /// Applications use the same name grouping as Overview, independent of PID.
    pub fn application_identity(&self) -> Self {
        let unknown = self.name == UNKNOWN_PROCESS_NAME;
        Self {
            pid: None,
            name: self.name.clone(),
            attributed: !unknown && self.attributed,
        }
    }

    /// An exact Overview query. Hex escapes survive its whitespace tokenizer and
    /// case-normalization, including names with spaces, uppercase, or regex syntax.
    pub fn connection_filter_query(&self) -> Option<String> {
        if self.name == OTHER_NAME && self.pid.is_none() {
            return None;
        }
        let name: String = self
            .name
            .chars()
            .map(|ch| {
                if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-') {
                    ch.to_string()
                } else {
                    format!("\\x{{{:x}}}", u32::from(ch))
                }
            })
            .collect();
        let mut query = format!("process:/^(?-i:{name})$/");
        if let Some(pid) = self.pid {
            query.push_str(&format!(" pid:{pid}"));
        }
        Some(query)
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
    pub window_tx_share: f64,
    pub window_rx_share: f64,
    pub retained_tx_share: f64,
    pub retained_rx_share: f64,
}

/// Immutable point-in-time process activity view.
#[derive(Debug, Clone)]
pub struct ProcessActivitySnapshot {
    pub processes: Vec<ProcessActivity>,
    /// Application-name totals with deduplicated peers and concurrent peaks.
    pub applications: Vec<ProcessActivity>,
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
            processes: Vec::new(),
            applications: Vec::new(),
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
}

impl FlowActivity {
    fn from_connection(conn: &Connection) -> Self {
        Self {
            identity: ProcessIdentity::from_connection(conn),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            remote_addr: conn.remote_addr,
            remote_label: destination_label(conn),
        }
    }
}

/// Fixed-size identity used to detect byte growth without retaining a second
/// copy of each full connection. Creation time distinguishes historic flows
/// that reused the same protocol and socket tuple, which is exactly what the
/// tracker's historic key encodes.
fn flow_identity(conn: &Connection) -> HistoricKey {
    HistoricKey::for_connection(ConnectionKey::from_connection(conn), conn)
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
}

impl ProcessAccumulator {
    fn new() -> Self {
        Self {
            tx_bytes: 0,
            rx_bytes: 0,
            active_connections: 0,
            completed_connections: 0,
            destinations: HashMap::new(),
        }
    }

    fn merge(&mut self, other: &Self) {
        self.tx_bytes = self.tx_bytes.saturating_add(other.tx_bytes);
        self.rx_bytes = self.rx_bytes.saturating_add(other.rx_bytes);
        self.active_connections = self
            .active_connections
            .saturating_add(other.active_connections);
        self.completed_connections = self
            .completed_connections
            .saturating_add(other.completed_connections);
        for (address, peer) in &other.destinations {
            let combined =
                self.destinations
                    .entry(*address)
                    .or_insert_with(|| DestinationActivity {
                        remote_addr: *address,
                        label: peer.label.clone(),
                        tx_bytes: 0,
                        rx_bytes: 0,
                        connections: 0,
                    });
            combined.tx_bytes = combined.tx_bytes.saturating_add(peer.tx_bytes);
            combined.rx_bytes = combined.rx_bytes.saturating_add(peer.rx_bytes);
            combined.connections = combined.connections.saturating_add(peer.connections);
            if combined.label.is_none() {
                combined.label.clone_from(&peer.label);
            }
        }
    }

    fn top_peer(&self, transmit: bool) -> Option<DestinationActivity> {
        self.destinations
            .values()
            .max_by(|a, b| {
                let bytes = |peer: &DestinationActivity| {
                    if transmit {
                        peer.tx_bytes
                    } else {
                        peer.rx_bytes
                    }
                };
                bytes(a)
                    .cmp(&bytes(b))
                    .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            })
            .cloned()
    }

    fn add_flow(&mut self, flow: &FlowActivity, completed: bool) {
        self.tx_bytes = self.tx_bytes.saturating_add(flow.bytes_sent);
        self.rx_bytes = self.rx_bytes.saturating_add(flow.bytes_received);
        if completed {
            self.completed_connections = self.completed_connections.saturating_add(1);
        } else {
            self.active_connections = self.active_connections.saturating_add(1);
        }
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
    flow_counters: &mut HashMap<HistoricKey, FlowCounters>,
    conn: &Connection,
    generation: u64,
) -> TrafficDelta {
    let identity = flow_identity(conn);
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
    flow_counters: HashMap<HistoricKey, FlowCounters>,
    sample_generation: u64,
    histories: HashMap<ProcessIdentity, ProcessHistory>,
    application_peaks: HashMap<ProcessIdentity, (f64, f64)>,
    snapshot: ProcessActivitySnapshot,
}

impl ProcessActivityTracker {
    pub fn new() -> Self {
        Self::with_config(ProcessActivityConfig::default())
    }

    pub(crate) fn with_config(config: ProcessActivityConfig) -> Self {
        Self {
            config,
            sample: HashMap::new(),
            flow_counters: HashMap::new(),
            sample_generation: 0,
            histories: HashMap::new(),
            application_peaks: HashMap::new(),
            snapshot: ProcessActivitySnapshot::default(),
        }
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
                    .or_insert_with(ProcessAccumulator::new)
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
                    .or_insert_with(ProcessAccumulator::new)
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
        self.application_peaks.clear();
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
            let top_tx_destination = aggregate.top_peer(true);
            let top_rx_destination = aggregate.top_peer(false);
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
                window_tx_share: 0.0,
                window_rx_share: 0.0,
                retained_tx_share: 0.0,
                retained_rx_share: 0.0,
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

        let applications = self.application_totals(&processes);

        self.snapshot = ProcessActivitySnapshot {
            processes,
            applications,
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

    fn application_totals(&mut self, processes: &[ProcessActivity]) -> Vec<ProcessActivity> {
        let mut groups: HashMap<ProcessIdentity, (ProcessActivity, ProcessAccumulator)> =
            HashMap::new();
        for process in processes {
            let identity = process.identity.application_identity();
            let aggregate = &self.sample[&process.identity];
            match groups.entry(identity.clone()) {
                std::collections::hash_map::Entry::Vacant(entry) => {
                    let mut summary = process.clone();
                    summary.identity = identity;
                    entry.insert((summary, aggregate.clone()));
                }
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let (summary, combined) = entry.get_mut();
                    summary.current_tx_bps += process.current_tx_bps;
                    summary.current_rx_bps += process.current_rx_bps;
                    summary.window_tx_bytes = summary
                        .window_tx_bytes
                        .saturating_add(process.window_tx_bytes);
                    summary.window_rx_bytes = summary
                        .window_rx_bytes
                        .saturating_add(process.window_rx_bytes);
                    summary.window_tx_share += process.window_tx_share;
                    summary.window_rx_share += process.window_rx_share;
                    summary.retained_tx_share += process.retained_tx_share;
                    summary.retained_rx_share += process.retained_rx_share;
                    combined.merge(aggregate);
                }
            }
        }
        self.application_peaks
            .retain(|identity, _| groups.contains_key(identity));
        let mut applications = Vec::with_capacity(groups.len());
        for (identity, (mut summary, aggregate)) in groups {
            let peak = self.application_peaks.entry(identity).or_default();
            peak.0 = peak.0.max(summary.current_tx_bps);
            peak.1 = peak.1.max(summary.current_rx_bps);
            summary.peak_tx_bps = peak.0;
            summary.peak_rx_bps = peak.1;
            summary.retained_tx_bytes = aggregate.tx_bytes;
            summary.retained_rx_bytes = aggregate.rx_bytes;
            summary.active_connections = aggregate.active_connections;
            summary.total_connections = aggregate
                .completed_connections
                .saturating_add(aggregate.active_connections as u64);
            summary.unique_destinations = aggregate
                .destinations
                .len()
                .min(self.config.max_destinations_per_process);
            summary.destinations_truncated =
                aggregate.destinations.len() > self.config.max_destinations_per_process;
            summary.top_tx_destination = aggregate.top_peer(true);
            summary.top_rx_destination = aggregate.top_peer(false);
            applications.push(summary);
        }
        applications.sort_by(|a, b| {
            b.retained_tx_bytes
                .cmp(&a.retained_tx_bytes)
                .then_with(|| a.identity.cmp(&b.identity))
        });
        applications
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
    dpi.application.hostname().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use std::net::{IpAddr, Ipv4Addr};

    impl ProcessActivityTracker {
        /// Test shorthand: feed one complete active-plus-historic connection
        /// slice through [`observe_sources`](Self::observe_sources).
        fn observe_connections(&mut self, connections: &[Connection], now: SystemTime) {
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
    }

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
    fn application_totals_merge_pids_and_deduplicate_peers_before_truncation() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut flows: Vec<_> = [(1, 443, 100), (1, 8443, 90), (2, 9443, 100), (2, 8443, 90)]
            .into_iter()
            .enumerate()
            .map(|(index, (pid, port, bytes))| {
                let mut flow = connection(Some(pid), Some("gh"), port);
                flow.local_addr.set_port(1000 + index as u16);
                flow.bytes_sent = bytes;
                flow.bytes_received = bytes * 2;
                flow
            })
            .collect();
        flows[0].is_historic = true;
        let mut tracker = ProcessActivityTracker::with_config(ProcessActivityConfig {
            max_destinations_per_process: 2,
            ..Default::default()
        });
        tracker.observe_connections(&flows, now);
        let snapshot = tracker.snapshot();
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.applications.len(), 1);
        let app = &snapshot.applications[0];
        assert_eq!(app.identity.name, "gh");
        assert_eq!(app.identity.pid, None);
        assert_eq!(app.retained_tx_bytes, 380);
        assert_eq!(app.retained_rx_bytes, 760);
        assert_eq!(app.active_connections, 3);
        assert_eq!(app.total_connections, 4);
        assert_eq!(app.unique_destinations, 2);
        assert!(app.destinations_truncated);
        assert_eq!(
            app.top_tx_destination.as_ref().unwrap().remote_addr.port(),
            8443
        );
        assert_eq!(app.top_tx_destination.as_ref().unwrap().tx_bytes, 180);
        assert_eq!(app.top_rx_destination.as_ref().unwrap().rx_bytes, 360);
        assert_eq!(app.window_tx_share, 100.0);
    }

    #[test]
    fn application_peak_tracks_simultaneous_rates_and_survives_pid_turnover() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut a = connection(Some(1), Some("gh"), 443);
        let mut b = connection(Some(2), Some("gh"), 8443);
        let mut tracker = ProcessActivityTracker::new();
        tracker.observe_connections(&[a.clone(), b.clone()], now);
        a.bytes_sent = 100;
        tracker.observe_connections(&[a.clone(), b.clone()], now + Duration::from_secs(1));
        b.bytes_sent = 100;
        tracker.observe_connections(&[a.clone(), b.clone()], now + Duration::from_secs(2));
        let snapshot = tracker.snapshot();
        assert_eq!(
            snapshot
                .processes
                .iter()
                .map(|p| p.peak_tx_bps)
                .sum::<f64>(),
            200.0
        );
        assert_eq!(snapshot.applications[0].peak_tx_bps, 100.0);
        a.bytes_sent += 100;
        b.bytes_sent += 100;
        tracker.observe_connections(&[a, b.clone()], now + Duration::from_secs(3));
        assert_eq!(tracker.snapshot().applications[0].peak_tx_bps, 200.0);
        tracker.observe_connections(&[b.clone()], now + Duration::from_secs(4));
        assert_eq!(tracker.snapshot().applications[0].peak_tx_bps, 200.0);
        tracker.clear();
        tracker.observe_connections(&[b], now + Duration::from_secs(5));
        assert_eq!(tracker.snapshot().applications[0].peak_tx_bps, 0.0);
    }

    #[test]
    fn application_query_matches_exact_names_and_optional_pids() {
        use crate::network::filter::ConnectionFilter;
        for name in ["gh", "GH", "Code (Service)", "a/b.*[x]", "工具 App"] {
            let identity = ProcessIdentity {
                name: name.into(),
                pid: None,
                attributed: true,
            };
            let query = identity.connection_filter_query().unwrap();
            let filter = ConnectionFilter::parse(&query);
            assert!(
                filter.matches(&connection(Some(1), Some(name), 443)),
                "{query}"
            );
            assert!(!filter.matches(&connection(Some(1), Some(&format!("{name}-extra")), 443)));
            if name.to_lowercase() != name {
                assert!(!filter.matches(&connection(Some(1), Some(&name.to_lowercase()), 443)));
            }
            let mut identity = identity;
            identity.pid = Some(1);
            let filter = ConnectionFilter::parse(&identity.connection_filter_query().unwrap());
            assert!(filter.matches(&connection(Some(1), Some(name), 443)));
            assert!(!filter.matches(&connection(Some(10), Some(name), 443)));
        }
        let unknown = ProcessIdentity {
            name: UNKNOWN_PROCESS_NAME.into(),
            pid: None,
            attributed: false,
        };
        let filter = ConnectionFilter::parse(&unknown.connection_filter_query().unwrap());
        assert!(filter.matches(&connection(None, None, 443)));
        assert!(filter.matches(&connection(Some(1), Some(UNKNOWN_PROCESS_NAME), 443)));
        assert!(!ConnectionFilter::parse("pid:invalid").matches(&connection(None, None, 443)));
    }

    #[test]
    fn process_group_label_folds_missing_and_placeholder_names() {
        let missing = connection(None, None, 80);
        let placeholder = connection(Some(7), Some(UNKNOWN_PROCESS_NAME), 443);
        let named = connection(Some(8), Some("curl"), 8443);

        assert_eq!(process_group_label(&missing), UNKNOWN_PROCESS_GROUP);
        assert_eq!(process_group_label(&placeholder), UNKNOWN_PROCESS_GROUP);
        assert_eq!(process_group_label(&named), "curl");
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
