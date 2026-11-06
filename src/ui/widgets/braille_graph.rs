//! Braille area graph: renders a rate history as a filled wave on a
//! 2×4 dots-per-cell braille canvas with a vertical color gradient
//! (bright crest, saturated base). Visual style inspired by
//! <https://github.com/programmersd21/flow>, reimplemented for ratatui.
//!
//! The renderer is pure: samples in, styled `Line`s out. Callers pick
//! the gradient via a color callback so the widget stays theme-agnostic.

use ratatui::{
    Frame,
    layout::Rect,
    style::Color,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{format::format_rate, theme};

/// Width of rate values in wave-panel headers. This fits values through
/// `999.99 GiB/s` and keeps both the trend glyph and `peak` label anchored as
/// formatted values cross digit and unit boundaries.
const HEADER_RATE_WIDTH: usize = 11;

pub(in crate::ui) struct WavePanelOptions {
    summary: Option<Line<'static>>,
    frac: f64,
    window: usize,
    max_val: Option<f64>,
    header_color: Option<Color>,
    average: Option<f64>,
    time_window_seconds: Option<u64>,
    placeholder: Option<&'static str>,
}

impl WavePanelOptions {
    pub(in crate::ui) fn new(frac: f64, window: usize) -> Self {
        Self {
            summary: None,
            frac,
            window,
            max_val: None,
            header_color: None,
            average: None,
            time_window_seconds: None,
            placeholder: None,
        }
    }

    pub(in crate::ui) fn with_summary(mut self, summary: Line<'static>) -> Self {
        self.summary = Some(summary);
        self
    }

    pub(in crate::ui) fn with_header_color(mut self, color: Color) -> Self {
        self.header_color = Some(color);
        self
    }

    pub(in crate::ui) fn with_average(mut self, average: Option<f64>) -> Self {
        self.average = average;
        self
    }

    pub(in crate::ui) fn with_time_axis(mut self, seconds: u64) -> Self {
        self.time_window_seconds = Some(seconds);
        self
    }

    pub(in crate::ui) fn with_placeholder(mut self, message: Option<&'static str>) -> Self {
        self.placeholder = message;
        self
    }

    pub(in crate::ui) fn with_max_val(mut self, max_val: f64) -> Self {
        self.max_val = Some(max_val);
        self
    }
}

/// Unicode braille bit for a dot at (dx, dy) inside one cell.
/// dx: 0 = left column, 1 = right column; dy: 0 = top … 3 = bottom.
/// Dots 7/8 (the bottom row) live in the high bits; this is the
/// standard braille encoding, not a linear layout.
const fn dot_mask(dx: usize, dy: usize) -> u8 {
    match (dx, dy) {
        (0, 0) => 0x01,
        (0, 1) => 0x02,
        (0, 2) => 0x04,
        (0, 3) => 0x40,
        (1, 0) => 0x08,
        (1, 1) => 0x10,
        (1, 2) => 0x20,
        _ => 0x80,
    }
}

/// Soft peak shaping: lifts small ratios so idle traffic still draws
/// a visible curve instead of a flat line.
fn ease_out_quad(t: f64) -> f64 {
    t * (2.0 - t)
}

/// Interpolate in sample coordinates, before mapping to terminal columns.
/// Smoothstep rounds each interval without overshooting or changing its peaks.
/// Its shape is fixed as it scrolls, independent of the terminal dot grid.
fn sample_at(samples: &[u64], pos: f64) -> f64 {
    if pos < 0.0 {
        return 0.0;
    }
    let last = samples.len() - 1;
    let pos = pos.clamp(0.0, last as f64);
    let i = pos as usize;
    let f = pos - i as f64;
    let f = f * f * (3.0 - 2.0 * f);
    if i < last {
        samples[i] as f64 * (1.0 - f) + samples[i + 1] as f64 * f
    } else {
        samples[last] as f64
    }
}

/// Round the curve before rasterizing it. The kernel is measured in sample
/// coordinates, so its shape stays fixed while scrolling or resizing.
fn curve_at(samples: &[u64], pos: f64) -> f64 {
    if pos < 0.0 {
        return 0.0;
    }
    const TAPS: [(f64, f64); 5] = [(-1.0, 1.0), (-0.5, 2.0), (0.0, 3.0), (0.5, 2.0), (1.0, 1.0)];
    TAPS.into_iter()
        .map(|(offset, weight)| sample_at(samples, (pos + offset).max(0.0)) * weight)
        .sum::<f64>()
        / 9.0
}

/// Render `samples` (oldest→newest) as a filled braille wave of
/// `width`×`height` cells, normalized against `max_val`.
///
/// `window` is the number of samples the panel spans horizontally
/// (the history buffer's capacity, not the current sample count).
/// Anchoring the newest sample to the right edge at a fixed
/// samples-per-dot density keeps the scroll continuous: while the
/// buffer is still filling, the wave grows in from the right instead
/// of stretching (which made every new sample snap the wave back).
///
/// `frac` is the continuous phase relative to the newest sampling
/// interval (negative after an early arrival); it shifts the wave left each frame
/// so the graph scrolls smoothly instead of stepping once per sample. A
/// single sample stays fixed because there is no advancing series to scroll.
///
/// Each row is one solid-colored `Line`; `row_color` maps `intensity`
/// (1.0 at the crest row, →0 at the base) to a gradient color.
pub(in crate::ui) fn render(
    samples: &[u64],
    width: usize,
    height: usize,
    max_val: f64,
    frac: f64,
    window: usize,
    row_color: impl Fn(f64) -> ratatui::style::Color,
) -> Vec<Line<'static>> {
    render_wave(
        samples,
        width,
        height,
        WaveGeometry {
            max_val,
            frac,
            window,
            scale: WaveScale::Shaped,
        },
        row_color,
    )
}

#[derive(Clone, Copy, PartialEq)]
enum WaveScale {
    Shaped,
    Linear,
}

impl WaveScale {
    fn ratio(self, value: f64, ceiling: f64) -> f64 {
        if ceiling <= 0.0 {
            return 0.0;
        }
        let value = value.clamp(0.0, ceiling);
        match self {
            Self::Shaped => ease_out_quad(value / ceiling),
            Self::Linear => value / ceiling,
        }
    }
}

/// Retain crests of the chosen curve when multiple samples share a column.
/// The endpoints join continuously as each crest crosses a column boundary.
fn column_peak(samples: &[u64], pos: f64, per_dot: f64, sample: fn(&[u64], f64) -> f64) -> f64 {
    let start = (pos - per_dot / 2.0).ceil().max(0.0) as usize;
    let end = ((pos + per_dot / 2.0).floor() + 1.0).max(0.0) as usize;
    let peak = (start.min(samples.len())..end.min(samples.len()))
        .map(|i| sample(samples, i as f64))
        .fold(0.0, f64::max);
    peak.max(sample(samples, pos - per_dot / 2.0))
        .max(sample(samples, pos + per_dot / 2.0))
        .max(sample(samples, pos))
}

struct WaveGeometry {
    max_val: f64,
    frac: f64,
    window: usize,
    scale: WaveScale,
}

fn render_wave(
    samples: &[u64],
    width: usize,
    height: usize,
    geometry: WaveGeometry,
    row_color: impl Fn(f64) -> Color,
) -> Vec<Line<'static>> {
    let WaveGeometry {
        max_val,
        frac,
        window,
        scale,
    } = geometry;
    if width == 0 || height == 0 || samples.is_empty() {
        return Vec::new();
    }

    let dots_x = width * 2;
    let dots_y = height * 4;

    // Newest sample pinned to the right edge; `frac` advances every
    // lookup by a sub-sample amount so the wave flows left between
    // samples. Positions before the first sample render as zero.
    let per_dot = if dots_x > 1 {
        (window.max(2) - 1) as f64 / (dots_x - 1) as f64
    } else {
        0.0
    };
    let scroll = if samples.len() > 1 {
        frac.min(1.0)
    } else {
        0.0
    };
    let right = (samples.len() - 1) as f64 + scroll;
    let mut grid = vec![vec![0u8; width]; height];
    // Traffic interpolates raw samples without averaging away their peaks.
    // Compact activity and lifecycle waves retain their existing rounding.
    let sample = if scale == WaveScale::Shaped {
        curve_at
    } else {
        sample_at
    };
    for x in 0..dots_x {
        let pos = right - (dots_x - 1 - x) as f64 * per_dot;
        let value = column_peak(samples, pos, per_dot, sample);
        let filled = (scale.ratio(value, max_val) * dots_y as f64).ceil() as usize;
        // One contour owns the entire fill. A separate outline can leave
        // hollow pockets when its height differs from a smoothed area.
        for y in 0..filled.min(dots_y) {
            grid[height - 1 - y / 4][x / 2] |= dot_mask(x % 2, 3 - y % 4);
        }
    }

    grid.into_iter()
        .enumerate()
        .map(|(i, row)| {
            let text: String = row
                .into_iter()
                .map(|bits| char::from_u32(0x2800 + bits as u32).unwrap_or(' '))
                .collect();
            let intensity = 1.0 - i as f64 / height as f64;
            Line::from(Span::styled(text, theme::fg(row_color(intensity))))
        })
        .collect()
}

/// Header line for a wave panel: left spans, then the right span
/// pushed to the panel's right edge (all glyphs used here are
/// single-width, so char count == display width).
pub(in crate::ui) fn spread_line(
    mut left: Vec<Span<'static>>,
    right: Span<'static>,
    width: u16,
) -> Line<'static> {
    let used = left.iter().map(Span::width).sum::<usize>() + right.width();
    let gap = (width as usize).saturating_sub(used + 1);
    left.push(Span::raw(" ".repeat(gap)));
    left.push(right);
    Line::from(left)
}

fn format_header_rate(rate: f64) -> String {
    let rate = format_rate(rate);
    format!("{rate:<HEADER_RATE_WIDTH$}")
}

fn format_peak_rate(rate: f64) -> String {
    let rate = format_rate(rate);
    format!("peak {rate:>HEADER_RATE_WIDTH$}")
}

/// Keep plotted peaks visible while retaining the history scale's gradual decay.
/// Each direction has its own labeled linear scale.
pub(in crate::ui) fn rate_ceilings(rx: &[u64], tx: &[u64], scales: (f64, f64)) -> (f64, f64) {
    let rx = scales
        .0
        .max(rx.iter().copied().max().unwrap_or(0) as f64)
        .max(1024.0);
    let tx = scales
        .1
        .max(tx.iter().copied().max().unwrap_or(0) as f64)
        .max(1024.0);
    (rx, tx)
}

/// One rate direction as a complete panel: a header line (label, the
/// current rate, a trend arrow, and the window peak), an optional summary
/// line, then an area chart with a labeled bytes-per-second scale.
/// A single continuous fill follows the curve without a separate outline.
pub(in crate::ui) fn wave_panel(
    f: &mut Frame,
    area: Rect,
    samples: &[u64],
    label: &str,
    options: WavePanelOptions,
    wave: fn(f64) -> Color,
) {
    if area.height < 2 || samples.is_empty() {
        return;
    }

    let current = *samples.last().unwrap() as f64;
    let peak = samples.iter().copied().max().unwrap_or(0) as f64;
    let max_val = options.max_val.unwrap_or(peak).max(1024.0);
    let speed_ratio = (current / max_val).clamp(0.0, 1.0);

    let value_color = options
        .header_color
        .unwrap_or_else(|| wave(0.35 + 0.65 * speed_ratio));
    let mut left = vec![
        Span::styled(
            format!("{label} Now "),
            theme::bold_fg(options.header_color.unwrap_or_else(|| wave(0.4))),
        ),
        Span::styled(format_header_rate(current), theme::bold_fg(value_color)),
    ];
    if area.width >= 48 {
        left.push(Span::styled(
            format!(" {}", trend_glyph(samples)),
            theme::fg(theme::muted()),
        ));
    }
    let average_text = options
        .average
        .map(|avg| format!("2s avg {}", format_header_rate(avg)));
    let inline_average = area.width >= 72;
    if inline_average && let Some(average) = &average_text {
        left.push(Span::styled(
            format!("  {average}"),
            theme::fg(theme::muted()),
        ));
    }
    let right = Span::styled(format_peak_rate(peak), theme::fg(theme::muted()));
    f.render_widget(
        Paragraph::new(spread_line(left, right, area.width)),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let summary_height = u16::from(options.summary.is_some() && area.height >= 3);
    let combine_average = !inline_average
        && summary_height > 0
        && options.summary.as_ref().is_some_and(|summary| {
            average_text
                .as_ref()
                .is_some_and(|avg| summary.width() + avg.len() + 2 <= usize::from(area.width))
        });
    if let Some(summary) = options.summary.filter(|_| summary_height == 1) {
        let summary = if combine_average {
            spread_line(
                summary.spans,
                Span::styled(
                    average_text.clone().unwrap_or_default(),
                    theme::fg(theme::muted()),
                ),
                area.width,
            )
        } else {
            summary
        };
        f.render_widget(
            Paragraph::new(summary),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
    }
    let average_height = u16::from(
        !inline_average && !combine_average && average_text.is_some() && area.height >= 5,
    );
    if average_height > 0 {
        f.render_widget(
            Paragraph::new(Line::styled(
                average_text.unwrap_or_default(),
                theme::fg(theme::muted()),
            )),
            Rect::new(area.x, area.y + 1 + summary_height, area.width, 1),
        );
    }

    let graph_area = Rect::new(
        area.x,
        area.y + 1 + summary_height + average_height,
        area.width,
        area.height
            .saturating_sub(1 + summary_height + average_height),
    );
    if let Some(message) = options.placeholder {
        f.render_widget(
            Paragraph::new(Line::styled(message, theme::fg(theme::muted()))),
            graph_area,
        );
        return;
    }
    // Plot the same sampled rates used by the current and peak readouts.
    let time_axis_height = u16::from(
        options.time_window_seconds.is_some() && graph_area.height >= 3 && graph_area.width >= 22,
    );
    let axis_width = 6.min(graph_area.width.saturating_sub(1));
    let plot = Rect::new(
        graph_area.x + axis_width,
        graph_area.y,
        graph_area.width.saturating_sub(axis_width),
        graph_area.height.saturating_sub(time_axis_height),
    );
    let lines = render_wave(
        samples,
        usize::from(plot.width),
        usize::from(plot.height),
        WaveGeometry {
            max_val,
            frac: options.frac,
            window: options.window,
            scale: WaveScale::Linear,
        },
        wave,
    );
    f.render_widget(Paragraph::new(lines), plot);
    if axis_width > 0 && plot.height > 0 {
        let label_width = usize::from(axis_width - 1);
        let ceiling = crate::ui::format::format_rate_compact(max_val, "0B");
        let ceiling = crate::ui::format::truncate_with_ellipsis(&ceiling, label_width);
        let midpoint_row = plot.height / 2;
        let midpoint_ratio =
            1.0 - f64::from(midpoint_row) / f64::from(plot.height.saturating_sub(1).max(1));
        let midpoint_value = max_val * midpoint_ratio;
        let midpoint = crate::ui::format::format_rate_compact(midpoint_value, "0B");
        let midpoint = crate::ui::format::truncate_with_ellipsis(&midpoint, label_width);
        let labels: Vec<_> = (0..plot.height)
            .map(|row| {
                let label = if row == 0 {
                    ceiling.as_str()
                } else if row + 1 == plot.height {
                    "0"
                } else if plot.height >= 5 && row == midpoint_row {
                    midpoint.as_str()
                } else {
                    ""
                };
                Line::styled(format!("{label:>label_width$}│"), theme::fg(theme::muted()))
            })
            .collect();
        f.render_widget(
            Paragraph::new(labels),
            Rect::new(graph_area.x, graph_area.y, axis_width, plot.height),
        );
    }
    if time_axis_height > 0 {
        let seconds = options.time_window_seconds.unwrap_or_default();
        let width = usize::from(plot.width);
        let mut labels = vec![b' '; width];
        let left = format!("-{seconds}s");
        let middle = format!("-{}s", seconds / 2);
        for (offset, label) in [(0, left.as_str()), (width.saturating_sub(3), "Now")] {
            for (cell, ch) in labels.iter_mut().skip(offset).zip(label.bytes()) {
                *cell = ch;
            }
        }
        if width >= left.len() + middle.len() + 7 {
            let offset = (width - middle.len()) / 2;
            labels[offset..offset + middle.len()].copy_from_slice(middle.as_bytes());
        }
        f.render_widget(
            Paragraph::new(labels.into_iter().map(char::from).collect::<String>())
                .style(theme::fg(theme::muted())),
            Rect::new(plot.x, plot.bottom(), plot.width, 1),
        );
    }
}

/// Least-squares slope over the last `n` samples; feeds the ↗/→/↘
/// trend glyph next to the current rate.
fn slope(samples: &[u64], n: usize) -> f64 {
    let tail = &samples[samples.len().saturating_sub(n)..];
    let len = tail.len();
    if len < 2 {
        return 0.0;
    }
    let mean_x = (len - 1) as f64 / 2.0;
    let mean_y = tail.iter().map(|&v| v as f64).sum::<f64>() / len as f64;
    let (mut num, mut den) = (0.0, 0.0);
    for (i, &v) in tail.iter().enumerate() {
        let dx = i as f64 - mean_x;
        num += dx * (v as f64 - mean_y);
        den += dx * dx;
    }
    if den == 0.0 { 0.0 } else { num / den }
}

/// Trend arrow for the recent samples: rising, falling, or steady
/// (relative to 5% of the current value, so noise reads as steady).
pub(in crate::ui) fn trend_glyph(samples: &[u64]) -> &'static str {
    let current = samples.last().copied().unwrap_or(0) as f64;
    let s = slope(samples, 6);
    let threshold = current * 0.05;
    if s > threshold {
        "↗"
    } else if s < -threshold {
        "↘"
    } else {
        "→"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_plot_keeps_peak_and_fixed_totals_row() {
        use crate::ui::test_support::render;
        let raw = [0, 0, 9000, 0, 0, 0];
        let text = render(68, 10, |f| {
            wave_panel(
                f,
                f.area(),
                &raw,
                "RX",
                WavePanelOptions::new(0.0, 6)
                    .with_time_axis(60)
                    .with_max_val(9000.0)
                    .with_average(Some(1500.0))
                    .with_summary(Line::raw("Total 100 KiB · 42 packets")),
                theme::rx_wave,
            )
        });
        let rows: Vec<_> = text.lines().collect();
        assert!(rows[0].contains("peak") && rows[0].contains("8.79 KiB/s"));
        assert!(rows[1].contains("Total") && rows[1].contains("2s avg"));
        assert!(
            rows[2..]
                .iter()
                .filter(|row| row.chars().any(|c| ('⠁'..='⣿').contains(&c)))
                .count()
                >= 5
        );
        assert!(!text.contains('▲'));
        assert!(rows.last().unwrap().contains("-60s"));
        assert!(rows.last().unwrap().contains("-30s"));
        assert!(rows.last().unwrap().trim_end().ends_with("Now"));
    }

    #[test]
    fn filled_contour_has_no_holes_at_any_scroll_phase() {
        let samples: Vec<u64> = (0..120)
            .map(|i| match i % 13 {
                0 => 65536,
                1 => 128,
                3 => 4096,
                7 => 0,
                _ => 256,
            })
            .collect();
        for scale in [WaveScale::Linear, WaveScale::Shaped] {
            for width in [8, 30, 97] {
                for step in -5..=20 {
                    let lines = render_wave(
                        &samples,
                        width,
                        12,
                        WaveGeometry {
                            max_val: 65536.0,
                            frac: f64::from(step) / 20.0,
                            window: 120,
                            scale,
                        },
                        |_| Color::Green,
                    );
                    let rows: Vec<Vec<u32>> = lines
                        .iter()
                        .map(|line| {
                            line.spans
                                .iter()
                                .flat_map(|s| s.content.chars())
                                .map(|c| u32::from(c) - 0x2800)
                                .collect()
                        })
                        .collect();
                    for x in 0..width * 2 {
                        let mut above_fill = false;
                        for y in 0..48 {
                            let filled = rows[11 - y / 4][x / 2]
                                & u32::from(dot_mask(x % 2, 3 - y % 4))
                                != 0;
                            assert!(
                                !(filled && above_fill),
                                "hole at column {x}, phase {step}, width {width}"
                            );
                            above_fill |= !filled;
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn peak_crosses_column_boundaries_without_a_height_jump() {
        let samples = [0, 0, 10000, 0, 0];
        for footprint in [0.25, 0.8, 1.7, 3.0] {
            for boundary in [2.0 - footprint / 2.0, 2.0 + footprint / 2.0] {
                let before = column_peak(&samples, boundary - 1e-6, footprint, sample_at);
                let after = column_peak(&samples, boundary + 1e-6, footprint, sample_at);
                assert!((after - before).abs() < 1e-5);
            }
        }
    }

    #[test]
    fn scrolling_translates_the_curve_without_reshaping_it() {
        let samples: Vec<u64> = (0..120).map(|i| (i * 137) % 4096).collect();
        let width = 100;
        let per_dot = 119.0 / 199.0;
        for scale in [WaveScale::Linear, WaveScale::Shaped] {
            let draw = |frac| {
                render_wave(
                    &samples,
                    width,
                    12,
                    WaveGeometry {
                        max_val: 4096.0,
                        frac,
                        window: 120,
                        scale,
                    },
                    |_| Color::Green,
                )
            };
            let before = draw(-0.4);
            let after = draw(-0.4 + 2.0 * per_dot);
            for (before, after) in before.iter().zip(&after) {
                let before: String = before
                    .spans
                    .iter()
                    .flat_map(|s| s.content.chars())
                    .skip(1)
                    .take(width - 3)
                    .collect();
                let after: String = after
                    .spans
                    .iter()
                    .flat_map(|s| s.content.chars())
                    .take(width - 3)
                    .collect();
                assert_eq!(before, after);
            }
        }
    }

    #[test]
    fn narrow_downsampling_preserves_the_full_burst_height() {
        let mut samples = vec![0; 120];
        samples[37] = 8192;
        for width in [1, 8, 30, 120] {
            let lines = render_wave(
                &samples,
                width,
                8,
                WaveGeometry {
                    max_val: 8192.0,
                    frac: 0.3,
                    window: 120,
                    scale: WaveScale::Linear,
                },
                |_| Color::Green,
            );
            assert!(
                lines[0]
                    .spans
                    .iter()
                    .any(|span| span.content.chars().any(|c| ('⠁'..='⣿').contains(&c))),
                "width {width}"
            );
        }
    }

    #[test]
    fn surge_chart_keeps_readouts_visible_at_multiple_sizes() {
        use crate::ui::test_support::render;
        for (width, height) in [(38, 12), (48, 12), (80, 16), (140, 24)] {
            let text = render(width, height, |f| {
                wave_panel(
                    f,
                    f.area(),
                    &[256, 8192, 512],
                    "RX",
                    WavePanelOptions::new(0.0, 3)
                        .with_max_val(8192.0)
                        .with_average(Some(1024.0)),
                    theme::rx_wave,
                )
            });
            assert!(
                text.contains("Now") && text.contains("2s avg") && text.contains("peak"),
                "{text}"
            );
            assert!(!text.contains('▲'));
            let header = text.lines().next().unwrap();
            assert!(header.contains("512 B/s"), "{header}");
            assert!(header.contains("peak  8.00 KiB/s"), "{header}");
        }
    }

    #[test]
    fn area_chart_uses_linear_heights_and_labels_its_scale() {
        use crate::ui::test_support::render;
        let draw = |value| {
            render(60, 14, |f| {
                wave_panel(
                    f,
                    f.area(),
                    &[value, value],
                    "RX",
                    WavePanelOptions::new(0.0, 2).with_max_val(1024.0),
                    |_| Color::Green,
                );
            })
        };
        let quarter = draw(256);
        let half = draw(512);
        let filled_rows = |text: &str| {
            text.lines()
                .filter(|line| line.chars().any(|c| ('⠁'..='⣿').contains(&c)))
                .count()
        };
        let low = filled_rows(&quarter);
        let high = filled_rows(&half);
        assert!(low > 0 && high > low, "{quarter}\n{half}");
        assert!(high.abs_diff(low * 2) <= 1, "quarter={low}, half={high}");
        assert!(quarter.contains("1K"));
        assert!(half.contains("1K"));
        insta::assert_snapshot!("linear_traffic_scale", half);
    }

    #[test]
    fn automatic_scales_preserve_peaks_and_decay_independently() {
        assert_eq!(
            rate_ceilings(&[0, 8192], &[0, 2048], (4096.0, 1024.0)),
            (8192.0, 2048.0)
        );
        assert_eq!(
            rate_ceilings(&[0], &[0], (4096.0, 2048.0)),
            (4096.0, 2048.0)
        );
    }

    #[test]
    fn wave_has_a_gradient_and_keeps_raw_readouts() {
        use crate::ui::test_support::{buffer_to_string, render_buffer};
        let buffer = render_buffer(80, 12, |f| {
            wave_panel(
                f,
                f.area(),
                &[256, 1024, 256],
                "RX",
                WavePanelOptions::new(0.0, 3).with_max_val(1024.0),
                |t| Color::Rgb(20, (80.0 + t * 175.0) as u8, 80),
            )
        });
        let output = buffer_to_string(&buffer);
        assert!(output.contains("256 B/s"));
        assert!(output.contains("peak") && output.contains("1.00 KiB/s"));
        let colors: std::collections::HashSet<_> = buffer
            .content
            .iter()
            .filter(|cell| cell.symbol().chars().any(|ch| ('⠁'..='⣿').contains(&ch)))
            .map(|cell| cell.fg)
            .collect();
        assert!(colors.len() > 3);
    }

    #[test]
    fn linear_chart_scrolls_left_without_jumping_at_the_next_sample() {
        use crate::ui::test_support::render_buffer;
        let mut samples = vec![0; 32];
        samples[20] = 768;
        let draw = |values: &[u64], frac| {
            render_buffer(200, 8, |f| {
                wave_panel(
                    f,
                    f.area(),
                    values,
                    "RX",
                    WavePanelOptions::new(frac, 32).with_max_val(1024.0),
                    theme::rx_wave,
                );
            })
        };
        let mut positions = Vec::new();
        for frame in 0..=10 {
            let buffer = draw(&samples, f64::from(frame) / 10.0);
            let rightmost = (0..200)
                .rev()
                .find(|&x| {
                    (2..6).any(|y| {
                        buffer[(x, y)]
                            .symbol()
                            .chars()
                            .any(|ch| ('⠁'..='⣿').contains(&ch))
                    })
                })
                .expect("visible spike");
            positions.push(rightmost);
        }
        assert!(positions.windows(2).all(|pair| pair[1] <= pair[0]));
        positions.dedup();
        assert!(positions.len() > 5, "{positions:?}");
        let before = draw(&samples, 1.0);
        samples.remove(0);
        samples.push(0);
        let after = draw(&samples, 0.0);
        for y in 2..6 {
            for x in 0..190 {
                assert_eq!(before[(x, y)], after[(x, y)], "at {x},{y}");
            }
        }
    }

    #[test]
    fn dot_mask_covers_all_braille_bits() {
        let mut all = 0u8;
        for dx in 0..2 {
            for dy in 0..4 {
                all |= dot_mask(dx, dy);
            }
        }
        assert_eq!(all, 0xFF);
    }

    #[test]
    fn render_fills_bottom_row_under_load() {
        let samples = vec![100u64; 30];
        let lines = render(&samples, 10, 3, 100.0, 0.0, 30, |_| {
            ratatui::style::Color::Reset
        });
        assert_eq!(lines.len(), 3);
        // Constant max-value input must fully fill the bottom row.
        let bottom: String = lines[2].spans.iter().map(|s| s.content.clone()).collect();
        assert!(bottom.chars().all(|c| c == '⣿'), "got {bottom:?}");
    }

    #[test]
    fn render_empty_when_no_samples() {
        assert!(render(&[], 10, 3, 1.0, 0.0, 60, |_| ratatui::style::Color::Reset).is_empty());
    }

    #[test]
    fn partial_buffer_grows_from_right() {
        // 5 samples in a 60-sample window: the wave hugs the right
        // edge and the left stays blank (no stretch during warmup).
        let samples = vec![100u64; 5];
        let lines = render(&samples, 30, 2, 100.0, 0.0, 60, |_| {
            ratatui::style::Color::Reset
        });
        let bottom: String = lines[1].spans.iter().map(|s| s.content.clone()).collect();
        let cells: Vec<char> = bottom.chars().collect();
        assert_eq!(cells[0], '\u{2800}', "left edge should be blank");
        assert_eq!(*cells.last().unwrap(), '⣿', "right edge should be full");
    }

    #[test]
    fn single_sample_does_not_oscillate_with_scroll_fraction() {
        let render_at = |frac| {
            render(&[100], 30, 2, 100.0, frac, 60, |_| {
                ratatui::style::Color::Reset
            })
        };

        assert_eq!(render_at(0.0), render_at(0.5));
        assert_eq!(render_at(0.0), render_at(1.0));
    }

    #[test]
    fn scroll_is_continuous_across_sample_rollover() {
        // frame N at frac=1.0 must equal frame N+1 (data shifted by
        // one sample) at frac=0.0 everywhere except the right edge,
        // where the new sample is revealed.
        let old: Vec<u64> = (0..60).map(|i| (i * 13) % 100).collect();
        let mut new = old[1..].to_vec();
        new.push(77);

        let render_plain = |s: &[u64], frac: f64| -> Vec<String> {
            render(s, 30, 2, 100.0, frac, 60, |_| ratatui::style::Color::Reset)
                .into_iter()
                .map(|l| l.spans.iter().map(|sp| sp.content.clone()).collect())
                .collect()
        };
        let before = render_plain(&old, 1.0);
        let after = render_plain(&new, 0.0);
        for (b, a) in before.iter().zip(after.iter()) {
            // Ignore the last 3 cells where the newly revealed sample
            // changes the right edge of the visible curve.
            let cut = b.chars().count() - 3;
            let b_body: String = b.chars().take(cut).collect();
            let a_body: String = a.chars().take(cut).collect();
            assert_eq!(b_body, a_body);
        }
    }

    #[test]
    fn trend_glyph_directions() {
        assert_eq!(trend_glyph(&[0, 100, 200, 300, 400, 500]), "↗");
        assert_eq!(trend_glyph(&[500, 400, 300, 200, 100, 0]), "↘");
        assert_eq!(trend_glyph(&[300, 300, 300, 300, 300, 300]), "→");
    }

    #[test]
    fn wave_header_rate_slots_keep_a_constant_width() {
        let rates = [0.0, 730.0, 1_020.0, 12_345.0, 2_500_000.0];
        for rate in rates {
            assert_eq!(format_header_rate(rate).chars().count(), HEADER_RATE_WIDTH);
            assert_eq!(
                format_peak_rate(rate).chars().count(),
                "peak ".len() + HEADER_RATE_WIDTH
            );
        }
    }
}
