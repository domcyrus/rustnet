//! Per-connection throughput trend: the short history behind the
//! connection tables' Trend column, and the sparkline it renders as.
//!
//! The UI reads cumulative counters from live flows once per second.
//! Snapshot refreshes and input can run at different cadences. The
//! cached 10-second rate averages would flatten short exchanges.
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
use std::time::{Duration, Instant, SystemTime};

use ratatui::style::Style;
use ratatui::text::{Line, Span};

use crate::network::tracker::HistoricKey;
use crate::network::types::{Connection, ConnectionKey};
use crate::ui::{process_group_label, theme};

/// Samples kept per connection: exactly the cells the Trend column draws.
pub(in crate::ui) const TREND_SAMPLES: usize = 8;
/// Spacing between samples; also the column's time resolution.
const SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Slack before the previous sample's wall clock when classifying a newly
/// observed flow as born during the current interval. Capture batches stamp
/// `created_at` from kernel packet timestamps (up to ~100 ms plus parser
/// queuing), so a flow created just before tick N can first commit to the
/// tracker after tick N and be observed at tick N+1.
const BIRTH_BATCH_SLACK: Duration = Duration::from_millis(250);
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

fn push_sample(samples: &mut VecDeque<TrendSample>, sample: TrendSample) {
    if samples.len() == TREND_SAMPLES {
        samples.pop_front();
    }
    samples.push_back(sample);
}

#[derive(Debug)]
struct GroupSeries {
    samples: VecDeque<TrendSample>,
    total: TrendSample,
    last_seen: Instant,
}

fn flow_key(conn: &Connection) -> HistoricKey {
    HistoricKey::for_connection(ConnectionKey::from_connection(conn), conn)
}

/// Rolling per-connection and per-process-group rate history.
#[derive(Debug, Default)]
pub struct TrendHistory {
    series: HashMap<HistoricKey, Series>,
    groups: HashMap<String, GroupSeries>,
    /// Trimmed filter query backing the current `groups` aggregates.
    /// Changing it resets `groups` immediately so group sparklines never
    /// mix pre-filter and post-filter totals, while keeping per-connection
    /// `series` intact across filter edits.
    active_filter: String,
    // Use monotonic time for rates and wall time only to compare flow births.
    last_sample: Option<(Instant, SystemTime)>,
}

impl TrendHistory {
    pub(crate) fn time_until_sample(&self, now: Instant) -> Duration {
        self.last_sample.map_or(Duration::ZERO, |(last, _)| {
            SAMPLE_INTERVAL.saturating_sub(now.saturating_duration_since(last))
        })
    }

    /// Read the live source only when a sample is due. After a missed tick
    /// (e.g. system sleep), restart with a baseline instead of joining bars
    /// across a gap for which we have no per-second observations.
    ///
    /// Changing `filter_query` clears process-group aggregates immediately so
    /// group headers never mix pre-filter and post-filter totals, while
    /// preserving per-connection series across filter edits.
    pub(crate) fn record(
        &mut self,
        now: Instant,
        wall_now: SystemTime,
        filter_query: &str,
        visit_live: impl FnOnce(&mut dyn FnMut(&Connection, bool)),
    ) -> bool {
        let normalized_filter = filter_query.trim();
        if self.active_filter != normalized_filter {
            self.groups.clear();
            self.active_filter.clear();
            self.active_filter.push_str(normalized_filter);
        }
        if !self.time_until_sample(now).is_zero() {
            return false;
        }
        let mut previous = self.last_sample.replace((now, wall_now));
        if previous.is_some_and(|(last, _)| now.duration_since(last) >= SAMPLE_INTERVAL * 2) {
            self.series.clear();
            self.groups.clear();
            previous = None;
        }
        let seconds = previous.map(|(last, _)| now.duration_since(last).as_secs_f64());
        visit_live(&mut |conn, matches_filter| {
            if conn.is_historic {
                return;
            }
            let (series, baseline) = match self.series.entry(flow_key(conn)) {
                Entry::Occupied(entry) => {
                    let series = entry.into_mut();
                    let counters = (series.bytes_received, series.bytes_sent);
                    (series, Some(counters))
                }
                Entry::Vacant(entry) => {
                    let born_this_interval = previous.is_some_and(|(_, wall_last)| {
                        let cutoff = wall_last
                            .checked_sub(BIRTH_BATCH_SLACK)
                            .unwrap_or(SystemTime::UNIX_EPOCH);
                        conn.created_at > cutoff
                    });
                    let series = entry.insert(Series {
                        samples: VecDeque::with_capacity(TREND_SAMPLES),
                        bytes_received: 0,
                        bytes_sent: 0,
                        last_seen: now,
                    });
                    (series, born_this_interval.then_some((0, 0)))
                }
            };
            series.last_seen = now;
            series.bytes_received = conn.bytes_received;
            series.bytes_sent = conn.bytes_sent;
            let (Some((received, sent)), Some(seconds)) = (baseline, seconds) else {
                return;
            };
            let sample = TrendSample {
                rx_bps: conn.bytes_received.saturating_sub(received) as f64 / seconds,
                tx_bps: conn.bytes_sent.saturating_sub(sent) as f64 / seconds,
            };
            push_sample(&mut series.samples, sample);

            if !matches_filter {
                return;
            }
            let label = process_group_label(conn);
            let group = match self.groups.get_mut(label) {
                Some(group) => group,
                None => self
                    .groups
                    .entry(label.to_owned())
                    .or_insert_with(|| GroupSeries {
                        samples: VecDeque::with_capacity(TREND_SAMPLES),
                        total: TrendSample::default(),
                        last_seen: now,
                    }),
            };
            group.total.rx_bps += sample.rx_bps;
            group.total.tx_bps += sample.tx_bps;
            group.last_seen = now;
        });

        // Evict flows that left the active table and groups with no matching
        // live members on this tick.
        self.series.retain(|_, series| series.last_seen == now);
        self.groups.retain(|_, group| {
            if group.last_seen != now {
                return false;
            }
            push_sample(&mut group.samples, std::mem::take(&mut group.total));
            true
        });
        true
    }

    pub(in crate::ui) fn clear(&mut self) {
        self.series.clear();
        self.groups.clear();
        self.active_filter.clear();
        self.last_sample = None;
    }

    pub(in crate::ui) fn samples(&self, conn: &Connection) -> Option<&VecDeque<TrendSample>> {
        self.series
            .get(&flow_key(conn))
            .map(|series| &series.samples)
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

    struct Clock(Instant, SystemTime);

    impl Clock {
        fn new() -> Self {
            Self(Instant::now(), SystemTime::now())
        }

        fn record(&self, history: &mut TrendHistory, rows: &[Connection], millis: u64) {
            let offset = Duration::from_millis(millis);
            history.record(self.0 + offset, self.1 + offset, "", |visit| {
                rows.iter().for_each(|row| visit(row, true));
            });
        }
    }

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
        let clock = Clock::new();

        // First sight is a baseline only: earlier bytes are not a spike.
        clock.record(&mut history, std::slice::from_ref(&conn), 0);
        assert!(history.samples(&conn).unwrap().is_empty());

        conn.bytes_received += 2_560;
        conn.bytes_sent += 640;
        // Too soon: ignored, so rows advance in lockstep.
        clock.record(&mut history, std::slice::from_ref(&conn), 500);
        assert!(history.samples(&conn).unwrap().is_empty());

        clock.record(&mut history, std::slice::from_ref(&conn), 1250);
        let samples = history.samples(&conn).unwrap();
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
        let clock = Clock::new();
        for second in 0..(TREND_SAMPLES as u64 + 5) {
            conn.bytes_received += 100 * second;
            clock.record(&mut history, std::slice::from_ref(&conn), second * 1000);
        }
        let samples = history.samples(&conn).unwrap();
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
        let clock = Clock::new();

        clock.record(&mut history, &[gone.clone(), historic.clone()], 0);
        assert!(history.samples(&gone).is_some());
        assert!(history.samples(&historic).is_none());

        clock.record(&mut history, &[], 1000);
        assert!(history.samples(&gone).is_none());
    }

    #[test]
    fn reused_tuple_starts_a_new_generation_in_the_row_and_group() {
        let mut history = TrendHistory::default();
        let mut old = local_tcp(41000, "curl");
        let clock = Clock::new();
        clock.record(&mut history, std::slice::from_ref(&old), 0);
        old.bytes_received = 8192;
        clock.record(&mut history, std::slice::from_ref(&old), 1000);

        let mut new = old.clone();
        new.created_at = clock.1 + Duration::from_millis(1500);
        new.bytes_received = 128;
        // The table can render the replacement before the next sample.
        assert!(history.samples(&new).is_none());
        clock.record(&mut history, std::slice::from_ref(&new), 2000);
        assert_eq!(history.samples(&new), Some(&series(&[128.0])));
        assert!(history.samples(&old).is_none());
        assert_eq!(
            history.group_samples("curl"),
            Some(&series(&[8192.0, 128.0]))
        );
    }

    #[test]
    fn first_interval_counts_a_finished_exchange_but_baselines_older_flows() {
        use crate::network::types::{Protocol, ProtocolState};
        let mut history = TrendHistory::default();
        let clock = Clock::new();
        clock.record(&mut history, &[], 0);
        let mut dns = Connection::new(
            Protocol::Udp,
            "127.0.0.1:41001".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        dns.created_at = clock.1 + Duration::from_millis(250);
        dns.bytes_sent = 64;
        dns.bytes_received = 256;
        dns.process_name = Some("resolver".into());
        let mut older = local_tcp(41002, "resolver");
        older.created_at = clock.1 - Duration::from_secs(30);
        older.bytes_received = 1_000_000;
        let rows = [dns, older];
        clock.record(&mut history, &rows, 1000);
        clock.record(&mut history, &rows, 2000);
        let expected = VecDeque::from([
            TrendSample {
                rx_bps: 256.0,
                tx_bps: 64.0,
            },
            TrendSample::default(),
        ]);
        assert_eq!(history.samples(&rows[0]), Some(&expected));
        assert_eq!(history.group_samples("resolver"), Some(&expected));
        assert_eq!(history.samples(&rows[1]), Some(&series(&[0.0])));
    }

    #[test]
    fn slow_snapshot_refresh_and_extra_input_do_not_distort_the_eight_second_window() {
        use crate::app::{App, Config};
        use crate::network::parser::ParsedPacket;
        use crate::network::types::{Protocol, ProtocolState};
        let app = App::new(Config {
            refresh_interval: 5000,
            ..crate::test_support::test_config()
        })
        .unwrap();
        let packet = ParsedPacket::new(
            Protocol::Udp,
            "127.0.0.1:41003".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            ProtocolState::Udp,
            true,
            128,
            Some("resolver".into()),
            None,
        );
        let clock = Clock::new();
        let mut history = TrendHistory::default();
        let read_live = |visit: &mut dyn FnMut(&Connection, bool)| {
            app.visit_live_connections("service:domain", visit)
        };
        history.record(clock.0, clock.1, "service:domain", read_live);
        for second in 1..=8 {
            let offset = Duration::from_secs(second);
            let between = offset - Duration::from_millis(250);
            app.ingest_packet_at_for_test(&packet, clock.1 + between);
            // Input between ticks must not even read the source.
            assert!(!history.record(
                clock.0 + between,
                clock.1 + between,
                "service:domain",
                |_| panic!("early sample"),
            ));
            if second == 5 {
                app.visit_live_connections("", |c, _| {
                    app.set_connections_snapshot_for_test(vec![c.clone()])
                });
            }
            assert!(history.record(
                clock.0 + offset,
                clock.1 + offset,
                "service:domain",
                read_live,
            ));
        }
        let displayed = app.get_connections();
        assert_eq!(displayed[0].bytes_sent, 5 * 128);
        let expected = VecDeque::from(
            [TrendSample {
                rx_bps: 0.0,
                tx_bps: 128.0,
            }; 8],
        );
        assert_eq!(history.samples(&displayed[0]), Some(&expected));
        assert_eq!(history.group_samples("resolver"), Some(&expected));
        app.visit_live_connections("service:ssh", |_, matched| {
            assert!(!matched, "filtered connection matched")
        });
    }

    #[test]
    fn filter_change_resets_group_trends_without_wiping_connection_history() {
        let mut history = TrendHistory::default();
        let mut heavy = local_tcp(41010, "firefox");
        let mut quiet = local_tcp(41011, "firefox");
        let clock = Clock::new();

        let sample =
            |history: &mut TrendHistory, millis: u64, query: &str, rows: &[(&Connection, bool)]| {
                let offset = Duration::from_millis(millis);
                history.record(clock.0 + offset, clock.1 + offset, query, |visit| {
                    for &(conn, matched) in rows {
                        visit(conn, matched);
                    }
                })
            };

        // Tick 0: baseline both connections unfiltered.
        assert!(sample(
            &mut history,
            0,
            "",
            &[(&heavy, true), (&quiet, true)]
        ));
        // Ticks 1 & 2: heavy moves 10 KiB/s, quiet moves 1 KiB/s.
        for second in [1000, 2000] {
            heavy.bytes_received += 10_000;
            quiet.bytes_received += 1_000;
            assert!(sample(
                &mut history,
                second,
                "",
                &[(&heavy, true), (&quiet, true)],
            ));
        }
        assert_eq!(
            history.group_samples("firefox"),
            Some(&series(&[11_000.0, 11_000.0]))
        );

        // Changing the filter between ticks clears the stale unfiltered group
        // aggregate immediately without touching either connection's history.
        assert!(!sample(
            &mut history,
            2500,
            "port:80",
            &[(&heavy, false), (&quiet, true)],
        ));
        assert!(history.group_samples("firefox").is_none());
        assert_eq!(
            history.samples(&heavy),
            Some(&series(&[10_000.0, 10_000.0]))
        );
        assert_eq!(history.samples(&quiet), Some(&series(&[1_000.0, 1_000.0])));

        // Tick 3: group sums only the matching member while heavy keeps sampling.
        heavy.bytes_received += 10_000;
        quiet.bytes_received += 1_000;
        assert!(sample(
            &mut history,
            3000,
            "port:80",
            &[(&heavy, false), (&quiet, true)],
        ));
        assert_eq!(history.group_samples("firefox"), Some(&series(&[1_000.0])));
        assert_eq!(
            history.samples(&heavy),
            Some(&series(&[10_000.0, 10_000.0, 10_000.0]))
        );

        // Clearing the filter resets group history again and both connections
        // contribute immediately on the next tick without re-baselining heavy.
        assert!(!sample(
            &mut history,
            3500,
            "",
            &[(&heavy, true), (&quiet, true)],
        ));
        assert!(history.group_samples("firefox").is_none());
        heavy.bytes_received += 10_000;
        quiet.bytes_received += 1_000;
        assert!(sample(
            &mut history,
            4000,
            "",
            &[(&heavy, true), (&quiet, true)],
        ));
        assert_eq!(history.group_samples("firefox"), Some(&series(&[11_000.0])));
    }

    #[test]
    fn batch_delayed_or_skewed_new_flows_count_their_first_exchange() {
        let mut history = TrendHistory::default();
        let clock = Clock::new();
        clock.record(&mut history, &[], 0);

        // Captured 80 ms before tick 0, committed to tracker after tick 0.
        let mut delayed = local_tcp(41020, "resolver");
        delayed.created_at = clock.1 - Duration::from_millis(80);
        delayed.bytes_received = 512;

        // Slightly ahead of UI wall_now (e.g. minor clock skew).
        let mut skewed = local_tcp(41021, "resolver");
        skewed.created_at = clock.1 + Duration::from_millis(1005);
        skewed.bytes_sent = 256;

        // Long-lived connection outside the slack window must still baseline.
        let mut older = local_tcp(41022, "resolver");
        older.created_at = clock.1 - Duration::from_secs(30);
        older.bytes_received = 1_000_000;

        let rows = [delayed, skewed, older];
        clock.record(&mut history, &rows, 1000);

        assert_eq!(history.samples(&rows[0]), Some(&series(&[512.0])));
        assert_eq!(
            history.samples(&rows[1]),
            Some(&VecDeque::from([TrendSample {
                rx_bps: 0.0,
                tx_bps: 256.0,
            }]))
        );
        assert!(history.samples(&rows[2]).unwrap().is_empty());
        assert_eq!(
            history.group_samples("resolver"),
            Some(&VecDeque::from([TrendSample {
                rx_bps: 512.0,
                tx_bps: 256.0,
            }]))
        );
    }

    #[test]
    fn a_filter_gap_or_missed_tick_restarts_the_window() {
        let mut history = TrendHistory::default();
        let mut conn = local_tcp(41004, "wget");
        let clock = Clock::new();
        clock.record(&mut history, std::slice::from_ref(&conn), 0);
        conn.bytes_received = 1000;
        clock.record(&mut history, std::slice::from_ref(&conn), 1000);
        clock.record(&mut history, &[], 2000);
        conn.bytes_received += 1000;
        clock.record(&mut history, std::slice::from_ref(&conn), 3000);
        assert!(history.samples(&conn).unwrap().is_empty());
        assert!(history.group_samples("wget").is_none());
        conn.bytes_received += 100;
        clock.record(&mut history, std::slice::from_ref(&conn), 4000);
        assert_eq!(history.samples(&conn), Some(&series(&[100.0])));
        clock.record(&mut history, std::slice::from_ref(&conn), 14000);
        assert!(history.samples(&conn).unwrap().is_empty());
        assert!(history.group_samples("wget").is_none());
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
        let clock = Clock::new();

        // Tick 0: baselines only, no group sample yet.
        clock.record(&mut history, &[first.clone(), second.clone()], 0);
        assert!(history.group_samples("firefox").is_none());

        // Tick 1: sum both live members' deltas into one group sample.
        first.bytes_received += 1_500;
        second.bytes_received += 500;
        second.bytes_sent += 250;
        clock.record(&mut history, &[first.clone(), second.clone()], 1000);
        let group = history.group_samples("firefox").unwrap();
        assert_eq!(
            group.iter().copied().collect::<Vec<_>>(),
            vec![TrendSample {
                rx_bps: 2_000.0,
                tx_bps: 250.0,
            }]
        );

        history.clear();
        assert!(history.samples(&first).is_none());
        assert!(history.group_samples("firefox").is_none());
    }
}
