use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ============================================================================
// Traffic History Types (for graph visualization)
// ============================================================================

/// Chart data points as (time_offset, value) pairs
pub type ChartData = Vec<(f64, f64)>;

/// Connection counts and lifecycle rates captured with one traffic sample.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConnectionLifecycleSample {
    pub active: usize,
    pub retained: usize,
    pub opened_per_sec_tenths: u64,
    pub closed_per_sec_tenths: u64,
}

/// A single sample of aggregate traffic data for graphing.
#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub timestamp: Instant,
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    smoothed_rx_bytes_per_sec: u64,
    smoothed_tx_bytes_per_sec: u64,
    pub connection_count: usize,
    pub retained_connection_count: usize,
    opened_connections_per_sec_tenths: u64,
    closed_connections_per_sec_tenths: u64,
    smoothed_opened_connections_per_sec_tenths: u64,
    smoothed_closed_connections_per_sec_tenths: u64,
    // Network health metrics
    pub packets_per_sec: u64,
    pub packet_loss_pct: f32,
    pub avg_rtt_ms: Option<f64>,
}

const GRAPH_SCALE_UP_TRANSITION: Duration = Duration::from_millis(1200);
const GRAPH_SCALE_DOWN_TRANSITION: Duration = Duration::from_secs(6);

/// Stable graph ceiling derived from the visible history peak. Power-of-two
/// steps provide headroom, upward changes are eased, and downward changes are
/// deliberately slower so old spikes do not make the graph snap taller as
/// they leave the window.
#[derive(Debug, Clone)]
pub struct GraphScale {
    minimum: u64,
    transition_from: f64,
    target: u64,
    transition_started: Instant,
    transition_duration: Duration,
}

impl GraphScale {
    pub fn new(minimum: u64) -> Self {
        let minimum = minimum.max(1);
        Self {
            minimum,
            transition_from: minimum as f64,
            target: minimum,
            transition_started: Instant::now(),
            transition_duration: GRAPH_SCALE_UP_TRANSITION,
        }
    }

    fn target_for_peak(&self, peak: u64) -> u64 {
        peak.max(self.minimum)
            .checked_next_power_of_two()
            .unwrap_or(u64::MAX)
    }

    fn ceiling_at(&self, now: Instant) -> f64 {
        let progress = now
            .saturating_duration_since(self.transition_started)
            .as_secs_f64()
            / self.transition_duration.as_secs_f64();
        let progress = progress.clamp(0.0, 1.0);
        let eased = 1.0 - (1.0 - progress).powi(3);
        self.transition_from + (self.target as f64 - self.transition_from) * eased
    }

    fn update_peak_at(&mut self, peak: u64, now: Instant) {
        let target = self.target_for_peak(peak);
        if target == self.target {
            return;
        }
        let current = self.ceiling_at(now);
        self.transition_from = current;
        self.target = target;
        self.transition_started = now;
        self.transition_duration = if target as f64 >= current {
            GRAPH_SCALE_UP_TRANSITION
        } else {
            GRAPH_SCALE_DOWN_TRANSITION
        };
    }

    pub fn update_peak(&mut self, peak: u64) {
        self.update_peak_at(peak, Instant::now());
    }

    pub fn ceiling(&self) -> f64 {
        self.ceiling_at(Instant::now())
    }

    pub fn reset(&mut self) {
        *self = Self::new(self.minimum);
    }
}

impl Default for GraphScale {
    fn default() -> Self {
        Self::new(1024)
    }
}

/// Ring buffer for aggregate traffic history (used for graphs)
#[derive(Debug, Clone)]
pub struct TrafficHistory {
    samples: VecDeque<TrafficSample>,
    max_samples: usize,
    rx_scale: GraphScale,
    tx_scale: GraphScale,
    opened_scale: GraphScale,
    closed_scale: GraphScale,
}

const GRAPH_SCROLL_STEPS: f64 = 5.0;
const OPENED_RATE_SMOOTHING_SAMPLES: usize = 3;
const CLOSED_RATE_SMOOTHING_SAMPLES: usize = 10;

fn quantize_scroll_fraction(raw: f64) -> f64 {
    (raw.clamp(0.0, 1.0) * GRAPH_SCROLL_STEPS).floor() / GRAPH_SCROLL_STEPS
}

impl TrafficHistory {
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(max_samples),
            max_samples,
            rx_scale: GraphScale::default(),
            tx_scale: GraphScale::default(),
            opened_scale: GraphScale::new(10),
            closed_scale: GraphScale::new(10),
        }
    }

    /// Add a new sample
    pub fn add_sample(
        &mut self,
        rx_bytes_per_sec: u64,
        tx_bytes_per_sec: u64,
        connection_count: usize,
        packets_per_sec: u64,
        retransmits_per_sec: u64,
        avg_rtt_ms: Option<f64>,
    ) {
        self.add_sample_with_lifecycle(
            rx_bytes_per_sec,
            tx_bytes_per_sec,
            ConnectionLifecycleSample {
                active: connection_count,
                ..ConnectionLifecycleSample::default()
            },
            packets_per_sec,
            retransmits_per_sec,
            avg_rtt_ms,
        );
    }

    /// Add a traffic sample with connection lifecycle activity.
    pub fn add_sample_with_lifecycle(
        &mut self,
        rx_bytes_per_sec: u64,
        tx_bytes_per_sec: u64,
        lifecycle: ConnectionLifecycleSample,
        packets_per_sec: u64,
        retransmits_per_sec: u64,
        avg_rtt_ms: Option<f64>,
    ) {
        let packet_loss_pct = if packets_per_sec > 0 {
            (retransmits_per_sec as f32 / packets_per_sec as f32) * 100.0
        } else {
            0.0
        };

        // Trailing average over the newest samples; byte rates truncate while
        // lifecycle rates (stored in tenths) round to nearest.
        let smoothed =
            |current: u64, previous_count: usize, rate: fn(&TrafficSample) -> u64, round: bool| {
                let (sum, count) = self
                    .samples
                    .iter()
                    .rev()
                    .take(previous_count)
                    .fold((u128::from(current), 1u128), |(sum, count), sample| {
                        (sum + u128::from(rate(sample)), count + 1)
                    });
                let sum = if round { sum + count / 2 } else { sum };
                (sum / count) as u64
            };
        let smoothed_rx_bytes_per_sec =
            smoothed(rx_bytes_per_sec, 2, |sample| sample.rx_bytes_per_sec, false);
        let smoothed_tx_bytes_per_sec =
            smoothed(tx_bytes_per_sec, 2, |sample| sample.tx_bytes_per_sec, false);
        let smoothed_opened_connections_per_sec_tenths = smoothed(
            lifecycle.opened_per_sec_tenths,
            OPENED_RATE_SMOOTHING_SAMPLES - 1,
            |sample| sample.opened_connections_per_sec_tenths,
            true,
        );
        let smoothed_closed_connections_per_sec_tenths = smoothed(
            lifecycle.closed_per_sec_tenths,
            CLOSED_RATE_SMOOTHING_SAMPLES - 1,
            |sample| sample.closed_connections_per_sec_tenths,
            true,
        );

        let sample = TrafficSample {
            timestamp: Instant::now(),
            rx_bytes_per_sec,
            tx_bytes_per_sec,
            smoothed_rx_bytes_per_sec,
            smoothed_tx_bytes_per_sec,
            connection_count: lifecycle.active,
            retained_connection_count: lifecycle.retained,
            opened_connections_per_sec_tenths: lifecycle.opened_per_sec_tenths,
            closed_connections_per_sec_tenths: lifecycle.closed_per_sec_tenths,
            smoothed_opened_connections_per_sec_tenths,
            smoothed_closed_connections_per_sec_tenths,
            packets_per_sec,
            packet_loss_pct,
            avg_rtt_ms,
        };

        if self.samples.len() >= self.max_samples {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        let picks: [fn(&TrafficSample) -> u64; 4] = [
            |sample| sample.smoothed_rx_bytes_per_sec,
            |sample| sample.smoothed_tx_bytes_per_sec,
            |sample| sample.smoothed_opened_connections_per_sec_tenths,
            |sample| sample.smoothed_closed_connections_per_sec_tenths,
        ];
        let mut peaks = [0u64; 4];
        for sample in &self.samples {
            for (peak, pick) in peaks.iter_mut().zip(picks) {
                *peak = (*peak).max(pick(sample));
            }
        }
        let [rx_peak, tx_peak, opened_peak, closed_peak] = peaks;
        self.rx_scale.update_peak(rx_peak);
        self.tx_scale.update_peak(tx_peak);
        self.opened_scale.update_peak(opened_peak);
        self.closed_scale.update_peak(closed_peak);
    }

    /// Get the latest packets/sec value, or 0 if no samples
    pub fn get_latest_packets_per_sec(&self) -> u64 {
        self.samples.back().map(|s| s.packets_per_sec).unwrap_or(0)
    }

    /// Configured ring-buffer capacity (the graph's sample window).
    pub fn capacity(&self) -> usize {
        self.max_samples
    }

    pub fn rx_graph_ceiling(&self) -> f64 {
        self.rx_scale.ceiling()
    }

    pub fn tx_graph_ceiling(&self) -> f64 {
        self.tx_scale.ceiling()
    }

    pub fn opened_graph_ceiling(&self) -> f64 {
        self.opened_scale.ceiling()
    }

    pub fn closed_graph_ceiling(&self) -> f64 {
        self.closed_scale.ceiling()
    }

    /// How far we are into the current sampling interval, in [0, 1].
    /// Samples arrive on a ~500ms cadence while tabs containing waves redraw
    /// every 200ms. Graphs shift by this fraction as the next sample becomes
    /// due. Measured against the actual gap
    /// between the last two samples (the sampler thread drifts past
    /// its nominal 500ms period), so the fraction wraps to 0 exactly
    /// when a new sample lands and the wave never jumps backward.
    ///
    /// Quantized to five stable positions per interval. The 200ms redraw
    /// heartbeat may skip a position because it does not divide the 500ms
    /// sampling interval evenly, while still preventing full-sample jumps.
    pub fn scroll_fraction(&self) -> f64 {
        let len = self.samples.len();
        if len < 2 {
            return 0.0;
        }
        let newest = &self.samples[len - 1];
        let interval = newest
            .timestamp
            .duration_since(self.samples[len - 2].timestamp)
            .as_secs_f64();
        if interval <= 0.0 {
            return 0.0;
        }
        let raw = newest.timestamp.elapsed().as_secs_f64() / interval;
        quantize_scroll_fraction(raw)
    }

    /// Last `count` values of `pick`, oldest first (newest last).
    ///
    /// `samples` is filled push_back/pop_front, so `iter()` is already
    /// oldest→newest. Skip past everything but the last `count` instead of
    /// the rev→take→collect→rev→collect dance, which allocated twice.
    fn sparkline(&self, count: usize, pick: fn(&TrafficSample) -> u64) -> Vec<u64> {
        let skip = self.samples.len().saturating_sub(count);
        self.samples.iter().skip(skip).map(pick).collect()
    }

    /// Get RX bytes/sec values for sparkline (newest last). Each value is
    /// smoothed when sampled so trimming the ring cannot rewrite its left edge.
    pub fn get_rx_sparkline_data(&self, count: usize) -> Vec<u64> {
        self.sparkline(count, |s| s.smoothed_rx_bytes_per_sec)
    }

    /// Get TX bytes/sec values for sparkline (newest last). Each value is
    /// smoothed when sampled so trimming the ring cannot rewrite its left edge.
    pub fn get_tx_sparkline_data(&self, count: usize) -> Vec<u64> {
        self.sparkline(count, |s| s.smoothed_tx_bytes_per_sec)
    }

    /// Get active connection count values for sparkline (newest last)
    pub fn get_connection_sparkline_data(&self, count: usize) -> Vec<u64> {
        self.sparkline(count, |s| s.connection_count as u64)
    }

    pub fn get_opened_sparkline_data(&self, count: usize) -> Vec<u64> {
        self.sparkline(count, |s| s.smoothed_opened_connections_per_sec_tenths)
    }

    pub fn get_closed_sparkline_data(&self, count: usize) -> Vec<u64> {
        self.sparkline(count, |s| s.smoothed_closed_connections_per_sec_tenths)
    }

    pub fn latest_connection_counts(&self) -> (usize, usize) {
        self.samples
            .back()
            .map(|sample| (sample.connection_count, sample.retained_connection_count))
            .unwrap_or((0, 0))
    }

    /// Average age in seconds of the samples in a smoothing window.
    fn avg_age(now: Instant, window: &[&TrafficSample]) -> f64 {
        window
            .iter()
            .map(|s| now.duration_since(s.timestamp).as_secs_f64())
            .sum::<f64>()
            / window.len() as f64
    }

    /// Moving-average series of `value` as (negative age, value) pairs,
    /// falling back to raw points when there are fewer than `window` samples.
    fn windowed_series(
        &self,
        now: Instant,
        window: usize,
        value: fn(&TrafficSample) -> f64,
    ) -> ChartData {
        if self.samples.len() < window {
            // Not enough data for smoothing, return raw
            return self
                .samples
                .iter()
                .map(|s| {
                    let age = now.duration_since(s.timestamp).as_secs_f64();
                    (-age, value(s))
                })
                .collect();
        }

        let samples: Vec<_> = self.samples.iter().collect();
        samples
            .windows(window)
            .map(|w| {
                let avg: f64 = w.iter().map(|s| value(s)).sum::<f64>() / window as f64;
                (-Self::avg_age(now, w), avg)
            })
            .collect()
    }

    /// Get data for Chart widget: (time_offset, rate) pairs, smoothed with moving average
    /// Time offset is negative seconds from now
    pub fn get_chart_data(&self) -> (ChartData, ChartData) {
        let now = Instant::now();
        // Apply smoothing with window of 3
        let window = 3;
        let rx = self.windowed_series(now, window, |s| s.rx_bytes_per_sec as f64);
        let tx = self.windowed_series(now, window, |s| s.tx_bytes_per_sec as f64);
        (rx, tx)
    }

    /// Get network health chart data: (packet_loss_pct, rtt_ms) as ChartData pairs
    /// Time offset is negative seconds from now
    pub fn get_health_chart_data(&self) -> (ChartData, ChartData) {
        let now = Instant::now();
        // Apply smoothing with window of 3
        let window = 3;
        let loss = self.windowed_series(now, window, |s| s.packet_loss_pct as f64);

        // RTT samples are optional per interval, so the moving average runs
        // over the values present in each window rather than a fixed divisor.
        let rtt: ChartData = if self.samples.len() < window {
            self.samples
                .iter()
                .filter_map(|s| {
                    s.avg_rtt_ms.map(|rtt| {
                        let age = now.duration_since(s.timestamp).as_secs_f64();
                        (-age, rtt)
                    })
                })
                .collect()
        } else {
            let samples: Vec<_> = self.samples.iter().collect();
            samples
                .windows(window)
                .filter_map(|w| {
                    let rtts: Vec<f64> = w.iter().filter_map(|s| s.avg_rtt_ms).collect();
                    if rtts.is_empty() {
                        None
                    } else {
                        let avg_rtt: f64 = rtts.iter().sum::<f64>() / rtts.len() as f64;
                        Some((-Self::avg_age(now, w), avg_rtt))
                    }
                })
                .collect()
        };

        (loss, rtt)
    }

    /// Check if we have enough data to display
    pub fn has_enough_data(&self) -> bool {
        self.samples.len() >= 2
    }

    /// Clear all traffic history samples
    pub fn clear(&mut self) {
        self.samples.clear();
        self.rx_scale.reset();
        self.tx_scale.reset();
        self.opened_scale.reset();
        self.closed_scale.reset();
    }
}

impl Default for TrafficHistory {
    fn default() -> Self {
        Self::new(120) // 60 seconds of history at two samples per second
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparkline_getters_return_last_count_oldest_first() {
        // Distinct rx/tx/conn values per sample so ordering bugs are visible.
        let mut hist = TrafficHistory::new(100);
        for i in 1u64..=5 {
            hist.add_sample(i * 10, i * 100, i as usize, 0, 0, None);
        }

        // Fewer than available: keep the N newest stored samples in order.
        assert_eq!(hist.get_rx_sparkline_data(2), vec![30, 40]);
        assert_eq!(hist.get_tx_sparkline_data(2), vec![300, 400]);
        assert_eq!(hist.get_connection_sparkline_data(3), vec![3, 4, 5]);

        // count exceeds sample count: return everything, oldest→newest.
        assert_eq!(hist.get_connection_sparkline_data(99), vec![1, 2, 3, 4, 5]);

        // count == 0: empty.
        assert!(hist.get_connection_sparkline_data(0).is_empty());

        // Empty history: empty out, no panic.
        let empty = TrafficHistory::new(10);
        assert!(empty.get_connection_sparkline_data(5).is_empty());
    }

    #[test]
    fn sparkline_smoothing_preserves_the_full_history_window() {
        let mut history = TrafficHistory::new(5);
        for i in 1u64..=5 {
            history.add_sample(i * 10, i * 100, 1, 0, 0, None);
        }

        let rx = history.get_rx_sparkline_data(usize::MAX);
        let tx = history.get_tx_sparkline_data(usize::MAX);
        assert_eq!(rx, vec![10, 15, 20, 30, 40]);
        assert_eq!(tx, vec![100, 150, 200, 300, 400]);
        assert_eq!(rx.len(), history.capacity());
        assert_eq!(tx.len(), history.capacity());
    }

    #[test]
    fn lifecycle_history_tracks_counts_and_spreads_cleanup_bursts() {
        let mut history = TrafficHistory::new(12);
        for retained in 0..9 {
            history.add_sample_with_lifecycle(
                0,
                0,
                ConnectionLifecycleSample {
                    active: 4,
                    retained,
                    ..ConnectionLifecycleSample::default()
                },
                0,
                0,
                None,
            );
        }

        history.add_sample_with_lifecycle(
            0,
            0,
            ConnectionLifecycleSample {
                active: 3,
                retained: 10,
                opened_per_sec_tenths: 20,
                closed_per_sec_tenths: 20,
            },
            0,
            0,
            None,
        );

        assert_eq!(history.latest_connection_counts(), (3, 10));
        assert_eq!(history.get_opened_sparkline_data(1), [7]);
        assert_eq!(history.get_closed_sparkline_data(1), [2]);
        assert_eq!(history.opened_scale.target, 16);
        assert_eq!(history.closed_scale.target, 16);
    }

    #[test]
    fn trimming_history_does_not_resmooth_the_left_edge() {
        let mut history = TrafficHistory::new(3);
        for value in [100, 200, 300] {
            history.add_sample(value, value, 1, 0, 0, None);
        }
        assert_eq!(history.get_rx_sparkline_data(usize::MAX), [100, 150, 200]);

        history.add_sample(400, 400, 1, 0, 0, None);

        assert_eq!(history.get_rx_sparkline_data(usize::MAX), [150, 200, 300]);
    }

    #[test]
    fn default_traffic_history_retains_sixty_seconds_at_two_hertz() {
        assert_eq!(TrafficHistory::default().capacity(), 120);
    }

    #[test]
    fn graph_scroll_fraction_has_five_visual_steps() {
        assert_eq!(quantize_scroll_fraction(0.0), 0.0);
        assert_eq!(quantize_scroll_fraction(0.19), 0.0);
        assert_eq!(quantize_scroll_fraction(0.20), 0.2);
        assert_eq!(quantize_scroll_fraction(0.79), 0.6);
        assert_eq!(quantize_scroll_fraction(0.99), 0.8);
        assert_eq!(quantize_scroll_fraction(1.0), 1.0);
    }

    #[test]
    fn graph_scale_uses_nice_steps_and_recovers_slowly() {
        let start = Instant::now();
        let mut scale = GraphScale::new(1024);

        scale.update_peak_at(1500, start);
        assert_eq!(scale.target, 2048);
        assert_eq!(scale.ceiling_at(start), 1024.0);
        assert_eq!(scale.ceiling_at(start + GRAPH_SCALE_UP_TRANSITION), 2048.0);

        let down_started = start + GRAPH_SCALE_UP_TRANSITION;
        scale.update_peak_at(500, down_started);
        assert_eq!(scale.target, 1024);
        assert_eq!(scale.ceiling_at(down_started), 2048.0);
        assert_eq!(
            scale.ceiling_at(down_started + GRAPH_SCALE_DOWN_TRANSITION),
            1024.0
        );
    }

    #[test]
    fn traffic_scale_forgets_peaks_after_they_leave_the_window() {
        let mut history = TrafficHistory::new(3);
        history.add_sample(10_000, 10_000, 1, 0, 0, None);
        assert_eq!(history.rx_scale.target, 16_384);

        for _ in 0..5 {
            history.add_sample(1_000, 1_000, 1, 0, 0, None);
        }

        assert_eq!(history.get_rx_sparkline_data(usize::MAX), [1_000; 3]);
        assert_eq!(history.rx_scale.target, 1_024);
        assert_eq!(history.tx_scale.target, 1_024);
    }

    // ========================================================================
    // Traffic History Health Data Tests
    // ========================================================================

    #[test]
    fn test_traffic_sample_packet_loss_calculation() {
        let mut history = TrafficHistory::new(60);

        // Add sample with 100 packets and 5 retransmits (5% loss)
        history.add_sample(1000, 500, 10, 100, 5, Some(25.0));

        let (loss_data, rtt_data) = history.get_health_chart_data();

        // Should have at least one data point
        assert!(!loss_data.is_empty());
        // Loss percentage should be 5%
        assert!((loss_data[0].1 - 5.0).abs() < 0.01);

        // Should have RTT data
        assert!(!rtt_data.is_empty());
        // RTT should be around 25ms
        assert!((rtt_data[0].1 - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_traffic_sample_zero_packets() {
        let mut history = TrafficHistory::new(60);

        // Add sample with 0 packets (no loss calculation possible)
        history.add_sample(1000, 500, 10, 0, 0, None);

        let (loss_data, rtt_data) = history.get_health_chart_data();

        // Should have data with 0% loss
        assert!(!loss_data.is_empty());
        assert!((loss_data[0].1).abs() < 0.01);

        // No RTT data
        assert!(rtt_data.is_empty());
    }

    #[test]
    fn test_traffic_history_health_smoothing() {
        let mut history = TrafficHistory::new(60);

        // Add multiple samples
        for i in 0..5 {
            history.add_sample(1000, 500, 10, 100, i * 2, Some((i * 10) as f64));
            std::thread::sleep(Duration::from_millis(10));
        }

        let (loss_data, rtt_data) = history.get_health_chart_data();

        // Should have smoothed data points
        assert!(loss_data.len() >= 2);
        assert!(rtt_data.len() >= 2);
    }
}
