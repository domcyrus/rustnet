//! Per-connection throughput trend: the short history behind the
//! connection tables' Trend column, and the sparkline it renders as.
//!
//! The UI snapshot carries connections without their raw rate samples
//! (see `RateTracker::clone_without_samples`), and the cached
//! `current_*_rate_bps` fields are 10-second sliding averages that would
//! flatten every burst. So the history is kept here, UI-side: once per
//! [`SAMPLE_INTERVAL`] the cumulative byte counters of every live
//! connection are diffed against the previous sample, which yields true
//! per-interval rates at the cost of two `u64`s and a few floats per row.
//!
//! The sparkline is an eighth-block bar per sample, newest at the right
//! edge, scaled to the row's own peak (with a floor so a trickle draws
//! low bars instead of a full-height wall). Each bar takes the traffic
//! wave gradient of its dominant direction, brighter as it grows, so the
//! column reads like a miniature of the Graph tab. Silent seconds draw
//! the same faint dotted track the glow bars use. Under NO_COLOR the bar
//! heights carry the shape on their own.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::network::types::Connection;
use crate::ui::{process_group_label, theme};

/// Samples kept per connection: exactly the cells the Trend column draws.
pub(in crate::ui) const TREND_SAMPLES: usize = 8;
/// Spacing between samples; also the column's time resolution.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Series not seen in this long (closed, or filtered out) are dropped.
const EVICT_AFTER: Duration = Duration::from_secs(30);
/// Minimum scale ceiling. Rows peaking below it share this ceiling, so a
/// connection trickling a few bytes per second draws low bars rather
/// than being stretched to full height by per-row normalization.
const MIN_CEILING_BPS: f64 = 1024.0;
/// Bar glyphs from one eighth to a full cell.
const LEVELS: [&str; 8] = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];
/// Track glyph for a second with no traffic (matches the glow bars).
const IDLE: &str = "·";

/// One interval's average rates, in bytes per second.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(in crate::ui) struct TrendSample {
    pub rx_bps: f64,
    pub tx_bps: f64,
}

impl TrendSample {
    fn total(self) -> f64 {
        self.rx_bps + self.tx_bps
    }
}

#[derive(Debug)]
struct Series {
    samples: VecDeque<TrendSample>,
    bytes_received: u64,
    bytes_sent: u64,
    last_seen: Instant,
}

impl Series {
    /// A fresh series holds the counters as a baseline and no samples, so
    /// bytes moved before the connection was first seen never show up as
    /// a spike.
    fn new(bytes_received: u64, bytes_sent: u64, now: Instant) -> Self {
        Self {
            samples: VecDeque::with_capacity(TREND_SAMPLES),
            bytes_received,
            bytes_sent,
            last_seen: now,
        }
    }

    /// Append the average rate since this series was last sampled. Using
    /// the series' own clock (not the global one) keeps a connection that
    /// was briefly filtered out from reporting its whole gap as one burst.
    fn push(&mut self, bytes_received: u64, bytes_sent: u64, now: Instant) -> Option<TrendSample> {
        let secs = now.saturating_duration_since(self.last_seen).as_secs_f64();
        if secs <= 0.0 {
            return None;
        }
        let sample = TrendSample {
            rx_bps: bytes_received.saturating_sub(self.bytes_received) as f64 / secs,
            tx_bps: bytes_sent.saturating_sub(self.bytes_sent) as f64 / secs,
        };
        if self.samples.len() == TREND_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        self.bytes_received = bytes_received;
        self.bytes_sent = bytes_sent;
        self.last_seen = now;
        Some(sample)
    }
}

#[derive(Debug)]
struct GroupSeries {
    samples: VecDeque<TrendSample>,
    last_seen: Instant,
}

impl GroupSeries {
    fn push(&mut self, sample: TrendSample, now: Instant) {
        if self.samples.len() == TREND_SAMPLES {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
        self.last_seen = now;
    }
}

/// Rolling per-connection and per-process-group rate history.
#[derive(Debug, Default)]
pub struct TrendHistory {
    series: HashMap<String, Series>,
    groups: HashMap<String, GroupSeries>,
    last_sample: Option<Instant>,
}

impl TrendHistory {
    /// Sample the live connections in `connections`. Cheap to call on
    /// every data refresh: calls closer than [`SAMPLE_INTERVAL`] to the
    /// previous sample are ignored, so every row advances in lockstep and
    /// the sparklines scroll together.
    pub fn record(&mut self, connections: &[Connection], now: Instant) {
        if self
            .last_sample
            .is_some_and(|last| now.saturating_duration_since(last) < SAMPLE_INTERVAL)
        {
            return;
        }
        self.last_sample = Some(now);

        // Sum each member connection's per-interval delta into its process
        // group so a closing or newly opened connection never causes a
        // negative jump or pre-existing-bytes spike on the group header.
        let mut group_totals: HashMap<&str, TrendSample> = HashMap::new();
        for conn in connections.iter().filter(|conn| !conn.is_historic) {
            let (received, sent) = (conn.bytes_received, conn.bytes_sent);
            match self.series.entry(conn.key()) {
                Entry::Occupied(mut entry) => {
                    if let Some(sample) = entry.get_mut().push(received, sent, now) {
                        let agg = group_totals.entry(process_group_label(conn)).or_default();
                        agg.rx_bps += sample.rx_bps;
                        agg.tx_bps += sample.tx_bps;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(Series::new(received, sent, now));
                }
            }
        }
        for (group, sample) in group_totals {
            self.groups
                .entry(group.to_owned())
                .or_insert_with(|| GroupSeries {
                    samples: VecDeque::with_capacity(TREND_SAMPLES),
                    last_seen: now,
                })
                .push(sample, now);
        }
        self.series
            .retain(|_, series| now.saturating_duration_since(series.last_seen) < EVICT_AFTER);
        self.groups
            .retain(|_, group| now.saturating_duration_since(group.last_seen) < EVICT_AFTER);
    }

    /// Drop all recorded series (e.g. after clearing all connections).
    pub(in crate::ui) fn clear(&mut self) {
        self.series.clear();
        self.groups.clear();
        self.last_sample = None;
    }

    /// Samples for the connection with `key`, oldest first.
    pub(in crate::ui) fn samples(&self, key: &str) -> Option<&VecDeque<TrendSample>> {
        self.series.get(key).map(|series| &series.samples)
    }

    /// Aggregate samples for the process group `group_name`, oldest first.
    pub(in crate::ui) fn group_samples(&self, group_name: &str) -> Option<&VecDeque<TrendSample>> {
        self.groups.get(group_name).map(|group| &group.samples)
    }
}

/// Render a trend as exactly [`TREND_SAMPLES`] cells: the newest sample
/// at the right edge and older ones to its left. Seconds before the first
/// sample show the idle track too: a connection that did not exist yet
/// moved no traffic. `colored` false drops every style, for rows painted
/// whole by the historic pass; `on_selection_tint` lifts the idle track
/// from `faint` to `muted` so it stays readable on a tinted selection band.
pub(in crate::ui) fn trend_line(
    samples: Option<&VecDeque<TrendSample>>,
    colored: bool,
    on_selection_tint: bool,
) -> Line<'static> {
    let count = samples.map_or(0, VecDeque::len);
    let ceiling = samples
        .into_iter()
        .flatten()
        .map(|sample| sample.total())
        .fold(MIN_CEILING_BPS, f64::max);
    let idle = if !colored {
        Style::default()
    } else if on_selection_tint {
        theme::fg(theme::muted())
    } else {
        theme::fg(theme::faint())
    };

    let mut spans = Vec::with_capacity(TREND_SAMPLES);
    spans.extend((count..TREND_SAMPLES).map(|_| Span::styled(IDLE, idle)));
    spans.extend(
        samples
            .into_iter()
            .flatten()
            .map(|sample| sample_span(*sample, ceiling, colored, idle)),
    );
    Line::from(spans)
}

/// One bar: height from the sample's share of `ceiling` (any traffic at
/// all draws at least the lowest bar), color from the dominant direction's
/// wave gradient at that height.
fn sample_span(sample: TrendSample, ceiling: f64, colored: bool, idle: Style) -> Span<'static> {
    let total = sample.total();
    if !total.is_finite() || total <= 0.0 {
        return Span::styled(IDLE, idle);
    }
    let fraction = (total / ceiling).clamp(0.0, 1.0);
    let level = ((fraction * LEVELS.len() as f64).ceil() as usize).clamp(1, LEVELS.len()) - 1;
    let glyph = LEVELS[level];
    if !colored {
        return Span::raw(glyph);
    }
    let t = level as f64 / (LEVELS.len() - 1) as f64;
    let color = if sample.rx_bps >= sample.tx_bps {
        theme::rx_wave(t)
    } else {
        theme::tx_wave(t)
    };
    Span::styled(glyph, theme::fg(color))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::local_tcp;

    fn text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn series(totals: &[f64]) -> VecDeque<TrendSample> {
        totals
            .iter()
            .map(|&rx_bps| TrendSample {
                rx_bps,
                tx_bps: 0.0,
            })
            .collect()
    }

    #[test]
    fn rates_come_from_byte_deltas_over_the_interval() {
        let mut history = TrendHistory::default();
        let mut conn = local_tcp(40000, "curl");
        conn.bytes_received = 10_000;
        conn.bytes_sent = 5_000;
        let t0 = Instant::now();

        // First sight is a baseline only: earlier bytes are not a spike.
        history.record(std::slice::from_ref(&conn), t0);
        assert!(history.samples(&conn.key()).unwrap().is_empty());

        conn.bytes_received += 4_096;
        conn.bytes_sent += 1_024;
        // Too soon: ignored, so rows advance in lockstep.
        history.record(std::slice::from_ref(&conn), t0 + Duration::from_millis(500));
        assert!(history.samples(&conn.key()).unwrap().is_empty());

        history.record(std::slice::from_ref(&conn), t0 + Duration::from_secs(2));
        let samples = history.samples(&conn.key()).unwrap();
        assert_eq!(
            samples.iter().copied().collect::<Vec<_>>(),
            vec![TrendSample {
                rx_bps: 2_048.0,
                tx_bps: 512.0,
            }]
        );
    }

    #[test]
    fn history_is_capped_to_the_column_width() {
        let mut history = TrendHistory::default();
        let mut conn = local_tcp(40001, "wget");
        let t0 = Instant::now();
        for second in 0..(TREND_SAMPLES as u64 + 5) {
            conn.bytes_received += 100 * second;
            history.record(
                std::slice::from_ref(&conn),
                t0 + Duration::from_secs(second),
            );
        }
        let samples = history.samples(&conn.key()).unwrap();
        assert_eq!(samples.len(), TREND_SAMPLES);
        // The oldest samples rolled off; the newest is the last delta.
        let last = (TREND_SAMPLES as u64 + 4) * 100;
        assert_eq!(samples.back().unwrap().rx_bps, last as f64);
    }

    #[test]
    fn unseen_series_are_evicted_and_historic_rows_ignored() {
        let mut history = TrendHistory::default();
        let gone = local_tcp(40002, "gone");
        let mut historic = local_tcp(40003, "old");
        historic.is_historic = true;
        let t0 = Instant::now();

        history.record(&[gone.clone(), historic.clone()], t0);
        assert!(history.samples(&gone.key()).is_some());
        assert!(history.samples(&historic.key()).is_none());

        history.record(&[], t0 + EVICT_AFTER + Duration::from_secs(1));
        assert!(history.samples(&gone.key()).is_none());
    }

    #[test]
    fn empty_trend_is_a_full_idle_track() {
        let idle = "·".repeat(TREND_SAMPLES);
        let empty = VecDeque::new();
        assert_eq!(text(&trend_line(None, false, false)), idle);
        assert_eq!(text(&trend_line(Some(&empty), true, false)), idle);
    }

    #[test]
    fn bars_scale_to_the_row_peak_newest_on_the_right() {
        let samples = series(&[0.0, 512.0, 1_024.0, 4_096.0]);
        let line = trend_line(Some(&samples), false, false);
        assert_eq!(text(&line), "·····▁▂█");
        assert_eq!(line.width(), TREND_SAMPLES);
    }

    #[test]
    fn a_trickle_stays_low_under_the_ceiling_floor() {
        // 100 B/s is below MIN_CEILING_BPS: the lowest bar, not a wall.
        let samples = series(&[100.0, 100.0]);
        let line = trend_line(Some(&samples), false, false);
        assert_eq!(text(&line), "······▁▁");
    }

    #[test]
    fn colored_bars_follow_the_dominant_direction() {
        let samples: VecDeque<TrendSample> = [
            TrendSample {
                rx_bps: 2_048.0,
                tx_bps: 0.0,
            },
            TrendSample {
                rx_bps: 0.0,
                tx_bps: 2_048.0,
            },
        ]
        .into_iter()
        .collect();
        let line = trend_line(Some(&samples), true, false);
        let rx = &line.spans[TREND_SAMPLES - 2];
        let tx = &line.spans[TREND_SAMPLES - 1];
        assert_eq!(rx.style, theme::fg(theme::rx_wave(1.0)));
        assert_eq!(tx.style, theme::fg(theme::tx_wave(1.0)));
    }

    #[test]
    fn group_trends_sum_member_deltas_and_clear_resets_history() {
        let mut history = TrendHistory::default();
        let mut first = local_tcp(40010, "firefox");
        let mut second = local_tcp(40011, "firefox");
        first.bytes_received = 5_000;
        second.bytes_received = 9_000;
        let t0 = Instant::now();

        // Tick 0: baselines only, no group sample yet.
        history.record(&[first.clone(), second.clone()], t0);
        assert!(history.group_samples("firefox").is_none());

        // Tick 1: sum both live members' deltas into one group sample.
        first.bytes_received += 1_500;
        second.bytes_received += 500;
        second.bytes_sent += 250;
        history.record(
            &[first.clone(), second.clone()],
            t0 + Duration::from_secs(1),
        );
        let group = history.group_samples("firefox").unwrap();
        assert_eq!(
            group.iter().copied().collect::<Vec<_>>(),
            vec![TrendSample {
                rx_bps: 2_000.0,
                tx_bps: 250.0,
            }]
        );

        history.clear();
        assert!(history.samples(&first.key()).is_none());
        assert!(history.group_samples("firefox").is_none());
    }
}
