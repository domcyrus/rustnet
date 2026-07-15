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
/// `999.99 GB/s` and keeps both the trend glyph and `peak` label anchored as
/// formatted values cross digit and unit boundaries.
const HEADER_RATE_WIDTH: usize = 11;

pub(in crate::ui) struct WavePanelOptions {
    summary: Option<Line<'static>>,
    frac: f64,
    window: usize,
}

impl WavePanelOptions {
    pub(in crate::ui) fn new(frac: f64, window: usize) -> Self {
        Self {
            summary: None,
            frac,
            window,
        }
    }

    pub(in crate::ui) fn with_summary(mut self, summary: Line<'static>) -> Self {
        self.summary = Some(summary);
        self
    }
}

/// Unicode braille bit for a dot at (dx, dy) inside one cell.
/// dx: 0 = left column, 1 = right column; dy: 0 = top … 3 = bottom.
/// Dots 7/8 (the bottom row) live in the high bits — this is the
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

/// Value at fractional position `pos` (in sample units), linearly
/// interpolated between neighbors.
fn sample_at(samples: &[u64], pos: f64) -> f64 {
    let last = samples.len() - 1;
    let pos = pos.clamp(0.0, last as f64);
    let i = pos as usize;
    let f = pos - i as f64;
    if i < last {
        samples[i] as f64 * (1.0 - f) + samples[i + 1] as f64 * f
    } else {
        samples[last] as f64
    }
}

/// 5-tap weighted moving average (1-2-3-2-1) over dot columns, for a
/// water-like curve instead of hard per-sample steps.
fn smooth_columns(cols: &[f64]) -> Vec<f64> {
    const W: [f64; 5] = [1.0, 2.0, 3.0, 2.0, 1.0];
    let n = cols.len();
    (0..n)
        .map(|i| {
            let mut sum = 0.0;
            let mut total = 0.0;
            for (k, w) in W.iter().enumerate() {
                if let Some(j) = (i + k).checked_sub(2)
                    && j < n
                {
                    sum += cols[j] * w;
                    total += w;
                }
            }
            sum / total
        })
        .collect()
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
/// `frac` ∈ [0, 1] is how far we are into the current sampling
/// interval; it shifts the wave left by a sub-cell amount each frame
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
        frac.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let right = (samples.len() - 1) as f64 + scroll;
    let cols: Vec<f64> = (0..dots_x)
        .map(|x| {
            let pos = right - (dots_x - 1 - x) as f64 * per_dot;
            if pos < 0.0 {
                0.0
            } else {
                sample_at(samples, pos)
            }
        })
        .collect();
    let cols = smooth_columns(&cols);

    // Fill each dot column bottom-up to its eased height.
    let mut grid = vec![vec![0u8; width]; height];
    for (x, col) in cols.iter().enumerate() {
        let ratio = if max_val > 0.0 {
            ease_out_quad((col / max_val).clamp(0.0, 1.0))
        } else {
            0.0
        };
        let h_dots = ratio * dots_y as f64;
        for y_dot in 0..dots_y {
            if (y_dot as f64) < h_dots {
                let row = height - 1 - y_dot / 4;
                grid[row][x / 2] |= dot_mask(x % 2, 3 - y_dot % 4);
            }
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
    let used: usize = left
        .iter()
        .map(|s| s.content.chars().count())
        .sum::<usize>()
        + right.content.chars().count();
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

/// One rate direction as a complete panel: a header line (label, the
/// current rate, a trend arrow, and the window peak), an optional summary
/// line, then a gradient braille wave. The wave is normalized to the window
/// peak; row brightness also scales with how close the current rate is to
/// that peak, so the panel glows under load and dims when idle.
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
    let max_val = peak.max(1024.0); // minimum 1 KB/s scale
    let speed_ratio = (current / max_val).clamp(0.0, 1.0);

    let value_color = wave(0.35 + 0.65 * speed_ratio);
    let left = vec![
        Span::styled(format!("{label} "), theme::bold_fg(wave(0.4))),
        Span::styled(format_header_rate(current), theme::bold_fg(value_color)),
        Span::styled(
            format!(" {}", trend_glyph(samples)),
            theme::fg(theme::muted()),
        ),
    ];
    let right = Span::styled(format_peak_rate(peak), theme::fg(theme::muted()));
    f.render_widget(
        Paragraph::new(spread_line(left, right, area.width)),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let summary_height = u16::from(options.summary.is_some() && area.height >= 3);
    if let Some(summary) = options.summary.filter(|_| summary_height == 1) {
        f.render_widget(
            Paragraph::new(summary),
            Rect::new(area.x, area.y + 1, area.width, 1),
        );
    }

    let graph_area = Rect::new(
        area.x,
        area.y + 1 + summary_height,
        area.width,
        area.height.saturating_sub(1 + summary_height),
    );
    let lines = render(
        samples,
        graph_area.width as usize,
        graph_area.height as usize,
        max_val,
        options.frac,
        options.window,
        |intensity| wave((0.6 + 0.4 * speed_ratio) * intensity),
    );
    f.render_widget(Paragraph::new(lines), graph_area);
}

/// Least-squares slope over the last `n` samples — feeds the ↗/→/↘
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
            // Ignore the last 3 cells: the column smoother's 2-dot
            // reach plus the revealed sample touch only those.
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
