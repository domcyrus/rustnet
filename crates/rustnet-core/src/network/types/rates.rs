use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

// ============================================================================
// Rate Tracking Types
// ============================================================================

#[derive(Debug, Clone)]
pub(super) struct RateSample {
    timestamp: Instant,
    // Delta values since last sample
    delta_sent: u64,
    delta_received: u64,
}

/// Drop the oldest sample while keeping the window totals equal to the sum of
/// the deltas still held in `samples`.
fn pop_oldest_sample(
    samples: &mut VecDeque<RateSample>,
    window_sent_total: &mut u64,
    window_received_total: &mut u64,
) {
    if let Some(old) = samples.pop_front() {
        *window_sent_total = window_sent_total.saturating_sub(old.delta_sent);
        *window_received_total = window_received_total.saturating_sub(old.delta_received);
    }
}

#[derive(Debug, Clone)]
pub struct RateTracker {
    pub(super) samples: Arc<VecDeque<RateSample>>,
    window_duration: Duration,
    last_update: Instant,
    max_samples: usize,
    // Keep track of last byte counts for delta calculation
    last_bytes_sent: u64,
    last_bytes_received: u64,
    // Running sums of the deltas currently held in `samples`, maintained on
    // every push/pop. Keeps rate calculation O(1) instead of summing the
    // whole window (up to `max_samples` entries) per refresh.
    window_sent_total: u64,
    window_received_total: u64,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::with_window_duration(Duration::from_secs(10))
    }

    pub fn with_window_duration(window_duration: Duration) -> Self {
        Self {
            samples: Arc::new(VecDeque::new()),
            window_duration,
            last_update: Instant::now(),
            // Increased to allow full time window even at high packet rates
            // 5000 pps × 10 sec = 50,000 samples, but we cap at 20,000 for memory
            max_samples: 20_000,
            last_bytes_sent: 0,
            last_bytes_received: 0,
            window_sent_total: 0,
            window_received_total: 0,
        }
    }

    /// Initialize the tracker with initial byte counts
    /// This should be called when creating a connection with existing bytes
    pub fn initialize_with_counts(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.last_bytes_sent = bytes_sent;
        self.last_bytes_received = bytes_received;
    }

    /// Update the rate tracker with new byte counts
    pub fn update(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.update_at(Instant::now(), bytes_sent, bytes_received);
    }

    /// Update the rate tracker with new byte counts at a specific timestamp.
    /// Full pruning is deferred to `prune()`, but a lightweight cap is enforced
    /// here to prevent unbounded growth between prune intervals.
    fn update_at(&mut self, now: Instant, bytes_sent: u64, bytes_received: u64) {
        // Calculate deltas since last update
        let delta_sent = bytes_sent.saturating_sub(self.last_bytes_sent);
        let delta_received = bytes_received.saturating_sub(self.last_bytes_received);

        // Add new sample with deltas
        let samples = Arc::make_mut(&mut self.samples);
        samples.push_back(RateSample {
            timestamp: now,
            delta_sent,
            delta_received,
        });
        self.window_sent_total += delta_sent;
        self.window_received_total += delta_received;

        // Lightweight overflow guard: drop oldest samples if we exceed the cap.
        // Full time-based pruning happens in prune() every ~1s.
        while samples.len() > self.max_samples {
            pop_oldest_sample(
                samples,
                &mut self.window_sent_total,
                &mut self.window_received_total,
            );
        }

        // Update last values for next delta calculation
        self.last_bytes_sent = bytes_sent;
        self.last_bytes_received = bytes_received;
        self.last_update = now;
    }

    /// Remove samples older than the window duration and enforce the sample cap.
    /// Called periodically (via `refresh_rates`) rather than per-packet.
    pub fn prune(&mut self) {
        let cutoff_time = self.last_update - self.window_duration;

        // Fast path: nothing to prune. Checked through `&self.samples` so a
        // no-op refresh never touches `Arc::make_mut` (which would deep-copy
        // a shared buffer) or the pop loop.
        let needs_prune = self.samples.len() > self.max_samples
            || self
                .samples
                .front()
                .is_some_and(|oldest| oldest.timestamp < cutoff_time);
        if !needs_prune {
            return;
        }

        let samples = Arc::make_mut(&mut self.samples);

        while samples
            .front()
            .is_some_and(|oldest| oldest.timestamp < cutoff_time)
        {
            pop_oldest_sample(
                samples,
                &mut self.window_sent_total,
                &mut self.window_received_total,
            );
        }

        // Limit total samples to prevent memory bloat
        while samples.len() > self.max_samples {
            pop_oldest_sample(
                samples,
                &mut self.window_sent_total,
                &mut self.window_received_total,
            );
        }
    }

    /// Get the current incoming rate in bytes per second
    pub fn get_incoming_rate_bps(&self) -> f64 {
        self.get_incoming_rate_bps_at(Instant::now())
    }

    /// Get the current outgoing rate in bytes per second
    pub fn get_outgoing_rate_bps(&self) -> f64 {
        self.get_outgoing_rate_bps_at(Instant::now())
    }

    /// Get the incoming rate in bytes per second at a specific timestamp
    fn get_incoming_rate_bps_at(&self, now: Instant) -> f64 {
        self.calculate_rate_from_deltas_at(now, self.window_received_total)
    }

    /// Get the outgoing rate in bytes per second at a specific timestamp
    fn get_outgoing_rate_bps_at(&self, now: Instant) -> f64 {
        self.calculate_rate_from_deltas_at(now, self.window_sent_total)
    }

    /// Calculate rate from the running window total — O(1), no walk over the
    /// sample buffer. `total_bytes` is the maintained sum of all deltas
    /// currently in `samples` (each represents bytes transferred).
    fn calculate_rate_from_deltas_at(&self, now: Instant, total_bytes: u64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }

        // If we only have one sample, we can't calculate a rate yet
        if self.samples.len() == 1 {
            return 0.0;
        }

        // Check if newest sample is too old (connection is idle)
        // We check against current time to handle idle connections where update() isn't being called
        let newest = self.samples.back().unwrap();
        let oldest = self.samples.front().unwrap();
        let age_of_newest = now.duration_since(newest.timestamp).as_secs_f64();

        // If the newest sample is older than our window, all samples are stale - return 0
        // Use a slightly larger threshold to avoid edge cases at window boundary
        if age_of_newest > self.window_duration.as_secs_f64() * 1.1 {
            return 0.0;
        }

        // Calculate the time span of our samples
        let time_span = newest
            .timestamp
            .duration_since(oldest.timestamp)
            .as_secs_f64();

        // Need at least 1 second of data for meaningful average
        // This matches iftop's approach of showing stable averages
        if time_span < 1.0 {
            return 0.0;
        }

        // Simple sliding window average: total bytes over time span
        // No decay - just pure average like iftop's 10-second column
        total_bytes as f64 / time_span
    }

    /// Clone carrying the rate metadata but an empty sample buffer.
    ///
    /// A regular `clone()` shares the sample buffer via `Arc`, which forces
    /// the next per-packet `update()` on the live tracker into an
    /// `Arc::make_mut` deep copy of the whole window (up to `max_samples`
    /// entries). Read-only consumers (UI snapshots, historic archives) never
    /// look at raw samples — they read the cached `current_*_rate_bps`
    /// fields on [`Connection`] — so they should use this instead and leave
    /// the live tracker as the buffer's unique owner.
    pub fn clone_without_samples(&self) -> Self {
        Self {
            samples: Arc::new(VecDeque::new()),
            window_duration: self.window_duration,
            last_update: self.last_update,
            max_samples: self.max_samples,
            last_bytes_sent: self.last_bytes_sent,
            last_bytes_received: self.last_bytes_received,
            // Zeroed alongside the empty buffer so the invariant
            // `window totals == sum(samples)` holds for the copy.
            window_sent_total: 0,
            window_received_total: 0,
        }
    }

    // Test-only methods for deterministic testing with controlled timestamps
    #[cfg(test)]
    pub fn update_at_time(&mut self, now: Instant, bytes_sent: u64, bytes_received: u64) {
        self.update_at(now, bytes_sent, bytes_received);
    }

    #[cfg(test)]
    pub fn get_outgoing_rate_at(&self, now: Instant) -> f64 {
        self.get_outgoing_rate_bps_at(now)
    }

    #[cfg(test)]
    pub fn get_incoming_rate_at(&self, now: Instant) -> f64 {
        self.get_incoming_rate_bps_at(now)
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// TCP analytics for tracking retransmissions and connection quality
#[derive(Debug, Clone)]
pub struct TcpAnalytics {
    // Highest sequence number seen in each direction, i.e. the next byte the
    // stream is expected to reach. Tracking the high-water mark rather than a
    // strict "next expected seq" keeps detection alive across gaps: a segment
    // missed by the capture advances the mark instead of desynchronising it.
    pub highest_seq_outbound: u32,
    pub highest_seq_inbound: u32,
    // 0 is a legal sequence/ack number, so it cannot double as "not yet seen".
    pub seen_outbound: bool,
    pub seen_inbound: bool,

    // ACK tracking for duplicate detection
    pub last_ack_received: u32,
    pub seen_ack: bool,
    /// Length of the duplicate-ACK run currently in progress. Live state,
    /// cleared by every ACK that advances; not a lifetime statistic.
    pub dup_ack_run: u32,

    // Statistics counters
    pub duplicate_ack_count: u64,
    pub retransmit_count: u64,
    pub out_of_order_count: u64,
    pub fast_retransmit_count: u64,

    // Window tracking
    pub last_window_size: u16,

    // Continuous RTT estimation. One outbound segment is timed at a time:
    // (sequence end of the timed bytes, capture time it left this host).
    // Karn's algorithm: a retransmission invalidates the pending probe, so
    // an ACK for a resent segment never produces an ambiguous sample.
    pub rtt_probe: Option<(u32, SystemTime)>,
    /// EWMA of data round trips (RFC 6298 style: 7/8 old + 1/8 sample).
    pub smoothed_rtt: Option<Duration>,
    /// Most recent raw sample, before smoothing.
    pub last_rtt: Option<Duration>,
    pub rtt_samples: u64,
}

impl TcpAnalytics {
    pub fn new() -> Self {
        Self {
            highest_seq_outbound: 0,
            highest_seq_inbound: 0,
            seen_outbound: false,
            seen_inbound: false,
            last_ack_received: 0,
            seen_ack: false,
            dup_ack_run: 0,
            duplicate_ack_count: 0,
            retransmit_count: 0,
            out_of_order_count: 0,
            fast_retransmit_count: 0,
            last_window_size: 0,
            rtt_probe: None,
            smoothed_rtt: None,
            last_rtt: None,
            rtt_samples: 0,
        }
    }
}

impl Default for TcpAnalytics {
    fn default() -> Self {
        Self::new()
    }
}

// Rate-smoothing constants — tune these to control how quickly displayed
// rates react to traffic changes.
/// Multiplier when traffic stops entirely: prev * DECAY_FAST each refresh.
/// ~3 refreshes (3 s) to reach zero.
const RATE_DECAY_STOPPED: f64 = 0.15;
/// Weight of the new sample when rate drops but traffic is still flowing.
const RATE_BLEND_NEW: f64 = 0.6;
/// Weight of the previous value (complement of RATE_BLEND_NEW).
const RATE_BLEND_PREV: f64 = 0.4;
/// Rates below this snap to zero to avoid perpetual sub-byte trickle.
const RATE_ZERO_THRESHOLD: f64 = 1.0;

/// Minimum time a terminal connection remains in the live table before it is
/// archived. This is long enough for the 10-second rate window and its display
/// smoothing to settle, while still removing completed flows promptly.
pub(super) const TERMINAL_ARCHIVE_GRACE: Duration = Duration::from_secs(15);

/// Smooth a rate value for display/sort stability.
/// - Rising: take the new value immediately (accurate throughput).
/// - Falling to zero: aggressive decay (~3 refreshes / 3s to clear).
/// - Falling but non-zero: gentle decay to absorb fluctuations.
pub(super) fn smooth_rate(raw: f64, prev: f64) -> f64 {
    let smoothed = if raw >= prev {
        raw
    } else if raw == 0.0 {
        prev * RATE_DECAY_STOPPED
    } else {
        RATE_BLEND_NEW * raw + RATE_BLEND_PREV * prev
    };
    if smoothed < RATE_ZERO_THRESHOLD {
        0.0
    } else {
        smoothed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_tracker_initialization() {
        let tracker = RateTracker::new();

        // Initial rates should be 0
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
    }

    #[test]
    fn test_sliding_window_simple_average() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Initialize with 0 bytes
        tracker.update_at_time(start, 0, 0);

        // Simulate steady traffic: 10,000 bytes/sec for 2 seconds
        // 1000 bytes every 100ms = 10KB/s out, 5KB/s in
        for i in 1..=20_u64 {
            let t = start + Duration::from_millis(i * 100);
            tracker.update_at_time(t, i * 1000, i * 500);
        }

        let final_time = start + Duration::from_millis(2000);
        let outgoing_rate = tracker.get_outgoing_rate_at(final_time);
        let incoming_rate = tracker.get_incoming_rate_at(final_time);

        // Should converge to actual sustained rate
        // 1000 bytes / 0.1s = 10,000 bytes/sec outgoing
        // 500 bytes / 0.1s = 5,000 bytes/sec incoming
        assert!(
            (outgoing_rate - 10000.0).abs() < 1.0,
            "Outgoing rate should be exactly 10KB/s, got: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 5000.0).abs() < 1.0,
            "Incoming rate should be exactly 5KB/s, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_sliding_window_with_burst() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        tracker.update_at_time(start, 0, 0);

        // Large burst: 1MB in one shot at 500ms
        tracker.update_at_time(start + Duration::from_millis(500), 1_000_000, 500_000);

        // Then slow traffic: 10KB every 100ms
        for i in 1..=10_u64 {
            let t = start + Duration::from_millis(500 + 100 + i * 100);
            tracker.update_at_time(t, 1_000_000 + i * 10_000, 500_000 + i * 5_000);
        }

        let final_time = start + Duration::from_millis(1600);
        let outgoing_rate = tracker.get_outgoing_rate_at(final_time);

        // Rate should be averaged over the whole window
        // Total bytes sent: 1MB burst + 100KB slow = 1.1MB over 1.6s = ~687.5 KB/s
        assert!(
            outgoing_rate > 600_000.0 && outgoing_rate < 800_000.0,
            "Rate should average burst and steady traffic, got: {}",
            outgoing_rate
        );
    }

    #[test]
    fn test_sliding_window_requires_minimum_timespan() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        tracker.update_at_time(start, 0, 0);
        tracker.update_at_time(start + Duration::from_millis(100), 10_000, 5_000);

        // With only 100ms of data (< 1 second minimum), should return 0
        let check_time = start + Duration::from_millis(100);
        assert_eq!(
            tracker.get_outgoing_rate_at(check_time),
            0.0,
            "Should return 0 when time_span < 1 second"
        );
        assert_eq!(
            tracker.get_incoming_rate_at(check_time),
            0.0,
            "Should return 0 when time_span < 1 second"
        );
    }

    #[test]
    fn test_sliding_window_high_packet_rate() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        tracker.update_at_time(start, 0, 0);

        // Simulate high packet rate: 100 packets/sec for 2 seconds = 200 packets
        // Each packet is 1500 bytes, 10ms intervals
        for i in 1..=200_u64 {
            let t = start + Duration::from_millis(i * 10);
            tracker.update_at_time(t, i * 1500, i * 750);
        }

        let final_time = start + Duration::from_millis(2000);
        let outgoing_rate = tracker.get_outgoing_rate_at(final_time);
        let incoming_rate = tracker.get_incoming_rate_at(final_time);

        // Expected: 1500 bytes / 0.01s = 150,000 bytes/sec = ~150 KB/s outgoing
        // 750 bytes / 0.01s = 75,000 bytes/sec = ~75 KB/s incoming
        assert!(
            (outgoing_rate - 150_000.0).abs() < 1.0,
            "High packet rate should give 150KB/s, got: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 75_000.0).abs() < 1.0,
            "High packet rate should give 75KB/s, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_sliding_window_no_skip_first_sample() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        tracker.update_at_time(start, 0, 0);

        // Add exactly one more sample after 1 second
        tracker.update_at_time(start + Duration::from_secs(1), 10_000, 5_000);

        // Now we have 2 samples spanning 1 second with 10,000 bytes transferred
        // This should give us 10,000 bytes/sec
        // If we were .skip(1), we'd get 0 because we'd skip the only data sample!
        let check_time = start + Duration::from_secs(1);
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);

        assert!(
            (outgoing_rate - 10_000.0).abs() < 1.0,
            "Should include all samples (not skip first), got: {}",
            outgoing_rate
        );
    }

    #[test]
    fn test_sliding_window_idle_connection() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Establish some traffic
        tracker.update_at_time(start, 0, 0);
        tracker.update_at_time(start + Duration::from_millis(500), 100_000, 50_000);

        // Check at a time beyond the 10-second window (samples become stale)
        let check_time = start + Duration::from_secs(12);

        // Should return 0 as all samples are outside the window
        assert_eq!(
            tracker.get_outgoing_rate_at(check_time),
            0.0,
            "Should return 0 when window has slid past all traffic"
        );
    }

    #[test]
    fn test_rate_tracker_single_update() {
        let mut tracker = RateTracker::new();

        // First update establishes baseline
        tracker.update(1000, 500);
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
        // Test single update - need at least 2 samples for rate
    }

    #[test]
    fn test_rate_tracker_clone_without_samples_detaches_buffer() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();
        for i in 0..10_u64 {
            tracker.update_at_time(start + Duration::from_millis(i * 100), i * 1000, i * 500);
        }

        let detached = tracker.clone_without_samples();

        // The detached copy has no samples but keeps the rate metadata.
        assert!(detached.samples.is_empty());
        assert_eq!(detached.last_bytes_sent, tracker.last_bytes_sent);
        assert_eq!(detached.last_bytes_received, tracker.last_bytes_received);
        assert_eq!(detached.window_duration, tracker.window_duration);

        // The live tracker stays unique owner of its buffer, so the next
        // per-packet update takes the in-place fast path (no CoW deep copy).
        assert_eq!(Arc::strong_count(&tracker.samples), 1);
    }

    #[test]
    fn test_rate_tracker_window_totals_match_brute_force_across_prunes() {
        let window = Duration::from_millis(500);
        let mut tracker = RateTracker::with_window_duration(window);
        let start = Instant::now();

        let mut bytes_sent = 0u64;
        let mut bytes_recv = 0u64;
        for i in 0..50u64 {
            bytes_sent += 100 + i;
            bytes_recv += 50 + i;
            tracker.update_at_time(
                start + Duration::from_millis(i * 40),
                bytes_sent,
                bytes_recv,
            );
            if i % 10 == 9 {
                tracker.prune();
            }
        }
        tracker.prune();

        let brute_sent: u64 = tracker.samples.iter().map(|s| s.delta_sent).sum();
        let brute_recv: u64 = tracker.samples.iter().map(|s| s.delta_received).sum();
        assert_eq!(tracker.window_sent_total, brute_sent);
        assert_eq!(tracker.window_received_total, brute_recv);
    }

    #[test]
    fn test_rate_tracker_cap_eviction_keeps_totals_in_sync() {
        let mut tracker = RateTracker::new();
        tracker.max_samples = 8;
        let start = Instant::now();

        let mut sent = 0u64;
        let mut recv = 0u64;
        for i in 0..20u64 {
            sent += 10 * (i + 1);
            recv += 5 * (i + 1);
            tracker.update_at_time(start + Duration::from_millis(i * 100), sent, recv);
        }

        assert!(tracker.samples.len() <= 8, "cap must be enforced");
        let brute_sent: u64 = tracker.samples.iter().map(|s| s.delta_sent).sum();
        let brute_recv: u64 = tracker.samples.iter().map(|s| s.delta_received).sum();
        assert_eq!(tracker.window_sent_total, brute_sent);
        assert_eq!(tracker.window_received_total, brute_recv);
    }

    #[test]
    fn test_rate_tracker_prune_noop_avoids_cow() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();
        tracker.update_at_time(start, 100, 50);
        tracker.update_at_time(start + Duration::from_millis(100), 200, 100);

        // Share the buffer (as a full clone would), then prune with nothing
        // prunable: the fast path must not deep-copy via Arc::make_mut.
        let shared = tracker.clone();
        tracker.prune();
        assert_eq!(
            Arc::strong_count(&tracker.samples),
            2,
            "no-op prune must not detach the shared buffer"
        );
        drop(shared);
    }

    #[test]
    fn test_rate_tracker_steady_traffic() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Add initial sample
        tracker.update_at_time(start, 0, 0);

        // Add second sample - 5000 bytes sent, 2500 received over 1 second
        tracker.update_at_time(start + Duration::from_secs(1), 5000, 2500);

        let check_time = start + Duration::from_secs(1);
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);
        let incoming_rate = tracker.get_incoming_rate_at(check_time);

        // Should be exactly 5000 bytes/sec outgoing, 2500 bytes/sec incoming
        assert!(
            (outgoing_rate - 5000.0).abs() < 1.0,
            "Outgoing rate: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 2500.0).abs() < 1.0,
            "Incoming rate: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_multiple_updates() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Simulate steady transfer over time
        tracker.update_at_time(start, 0, 0);

        // Add samples every 100ms for 1.5 seconds (15 samples)
        // 1000 bytes/100ms = 10KB/s, 500 bytes/100ms = 5KB/s
        for i in 1..=15_u64 {
            let t = start + Duration::from_millis(i * 100);
            tracker.update_at_time(t, i * 1000, i * 500);
        }

        let final_time = start + Duration::from_millis(1500);
        let outgoing_rate = tracker.get_outgoing_rate_at(final_time);
        let incoming_rate = tracker.get_incoming_rate_at(final_time);

        // Should be exactly 10000 bytes/sec outgoing, 5000 bytes/sec incoming
        assert!(
            (outgoing_rate - 10000.0).abs() < 1.0,
            "Outgoing rate: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 5000.0).abs() < 1.0,
            "Incoming rate: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_window_pruning() {
        let window_duration = Duration::from_millis(300);
        let mut tracker = RateTracker::with_window_duration(window_duration);
        let start = Instant::now();

        // Add samples that will be pruned
        tracker.update_at_time(start, 0, 0);
        tracker.update_at_time(start + Duration::from_millis(100), 1000, 500);

        // Add a sample after the window has slid past the first samples
        tracker.update_at_time(start + Duration::from_millis(500), 2000, 1000);

        // Check rate - the first samples should be pruned
        let check_time = start + Duration::from_millis(500);
        let rate = tracker.get_outgoing_rate_at(check_time);
        // After pruning, should have limited data - just verify it works
        assert!(rate >= 0.0);
    }

    #[test]
    fn test_rate_tracker_memory_limit() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Add more samples than we need, ensuring we span > 1 second
        tracker.update_at_time(start, 0, 0);
        for i in 1..=150_u64 {
            let t = start + Duration::from_millis(i * 10); // 10ms intervals = 1.5 seconds total
            tracker.update_at_time(t, i * 100, i * 50);
        }

        // Should have pruned to max_samples limit (20,000)
        assert!(tracker.samples.len() <= 20_000);

        // Should still calculate rates (we have > 1 second of data)
        let check_time = start + Duration::from_millis(1500);
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);
        let incoming_rate = tracker.get_incoming_rate_at(check_time);
        assert!(outgoing_rate >= 0.0);
        assert!(incoming_rate >= 0.0);
    }

    #[test]
    fn test_rate_tracker_bursty_traffic() {
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Initial state
        tracker.update_at_time(start, 0, 0);

        // Burst of traffic at 500ms
        tracker.update_at_time(start + Duration::from_millis(500), 10000, 5000);

        // No more traffic (same byte counts) - keep updating to span > 1 second
        tracker.update_at_time(start + Duration::from_millis(1000), 10000, 5000);
        tracker.update_at_time(start + Duration::from_millis(1500), 10000, 5000);

        // Rate should be averaged over the entire window (1.5 seconds)
        // 10,000 bytes over 1.5 seconds ≈ 6,666 bytes/sec
        let check_time = start + Duration::from_millis(1500);
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);
        let incoming_rate = tracker.get_incoming_rate_at(check_time);

        // Should be smoothed average: 10000 / 1.5 = 6666.67 bytes/sec
        assert!(
            (outgoing_rate - 6666.67).abs() < 1.0,
            "Rate should be ~6666.67 bytes/sec, got: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 3333.33).abs() < 1.0,
            "Rate should be ~3333.33 bytes/sec, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_zero_time_diff() {
        let mut tracker = RateTracker::new();

        // Add two samples with identical or very close timestamps
        tracker.update(0, 0);
        tracker.update(1000, 500); // Immediately after, should be < 100ms apart

        // Should return 0 to avoid division by very small numbers
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
    }

    #[test]
    fn test_rate_tracker_cumulative_fix() {
        // This test verifies the fix for the cumulative byte count issue
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Simulate a connection that has been running for a while with cumulative byte counts
        // Initialize tracker to simulate connection with existing traffic
        tracker.initialize_with_counts(1_000_000, 500_000);
        tracker.update_at_time(start, 1_000_000, 500_000); // No change yet (establishing baseline)

        tracker.update_at_time(start + Duration::from_millis(500), 1_500_000, 750_000); // 500KB more sent, 250KB more received
        tracker.update_at_time(start + Duration::from_millis(1000), 2_000_000, 1_000_000); // 500KB more sent, 250KB more received

        // The rate should be based on the deltas, not the cumulative values
        // We sent 1MB in deltas over 1 second = 1MB/s
        let check_time = start + Duration::from_millis(1000);
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);
        let incoming_rate = tracker.get_incoming_rate_at(check_time);

        // Should be exactly 1MB/s outgoing (1_000_000 bytes/sec)
        assert!(
            (outgoing_rate - 1_000_000.0).abs() < 1.0,
            "Outgoing rate should be 1MB/s, got: {}",
            outgoing_rate
        );

        // Should be exactly 500KB/s incoming (500_000 bytes/sec)
        assert!(
            (incoming_rate - 500_000.0).abs() < 1.0,
            "Incoming rate should be 500KB/s, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_window_sliding() {
        // Test that rates are calculated correctly as the window slides
        let window_duration = Duration::from_secs(2); // 2-second window
        let mut tracker = RateTracker::with_window_duration(window_duration);
        let start = Instant::now();

        // Add initial samples - 1MB/s for first second (100KB every 100ms = 11 samples total)
        tracker.update_at_time(start, 0, 0);
        for i in 1..=10_u64 {
            let t = start + Duration::from_millis(i * 100);
            tracker.update_at_time(t, i * 100_000, i * 50_000);
        }

        // After window slides past first samples (at 3 seconds), add new samples
        // Start from cumulative position of 10*100KB = 1MB, add 11 more at 100KB each
        // Need >= 1 second span, so 11 samples at 100ms intervals = 1.0s span
        for i in 0..=10_u64 {
            let t = start + Duration::from_millis(3000 + i * 100);
            tracker.update_at_time(t, 1_000_000 + i * 100_000, 500_000 + i * 50_000);
        }

        // Rate should be consistent: 10 deltas of 100KB over 1 second = 1MB/s
        let check_time = start + Duration::from_millis(4000);
        tracker.prune();
        let outgoing_rate = tracker.get_outgoing_rate_at(check_time);
        let incoming_rate = tracker.get_incoming_rate_at(check_time);

        // We're sending at 1MB/s and receiving at 500KB/s
        assert!(
            (outgoing_rate - 1_000_000.0).abs() < 1.0,
            "Outgoing rate after window slide: {}",
            outgoing_rate
        );
        assert!(
            (incoming_rate - 500_000.0).abs() < 1.0,
            "Incoming rate after window slide: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_decay_for_idle_connections() {
        // Test that rates decay to zero when connections become idle
        let mut tracker = RateTracker::new();
        let start = Instant::now();

        // Simulate active traffic
        tracker.update_at_time(start, 0, 0);
        tracker.update_at_time(start + Duration::from_secs(1), 100_000, 50_000); // 100KB sent, 50KB received over 1 second

        // Should have non-zero rate with >= 1 second of data
        let check_time_active = start + Duration::from_secs(1);
        let initial_out = tracker.get_outgoing_rate_at(check_time_active);
        let initial_in = tracker.get_incoming_rate_at(check_time_active);
        assert!(
            (initial_out - 100_000.0).abs() < 1.0,
            "Should have outgoing traffic: {}",
            initial_out
        );
        assert!(
            (initial_in - 50_000.0).abs() < 1.0,
            "Should have incoming traffic: {}",
            initial_in
        );

        // Check at a time after samples become stale
        // Newest sample is at start+1s, window is 10s, threshold is 1.1x
        // So need to check at > start + 1s + 11s = start + 12.1s
        let check_time_idle = start + Duration::from_millis(12200);

        let final_out = tracker.get_outgoing_rate_at(check_time_idle);
        let final_in = tracker.get_incoming_rate_at(check_time_idle);

        // After window slides past all samples, should be zero
        assert_eq!(
            final_out, 0.0,
            "Outgoing rate should be zero after 10+ seconds idle"
        );
        assert_eq!(
            final_in, 0.0,
            "Incoming rate should be zero after 10+ seconds idle"
        );
    }
}
