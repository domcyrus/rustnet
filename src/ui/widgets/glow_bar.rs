//! Truecolor horizontal bars using the same dark-to-bright ramps as the
//! braille traffic graphs.

use ratatui::{style::Color, text::Span};

use crate::ui::theme;

pub(in crate::ui) fn spans(
    fraction: f64,
    width: usize,
    ramp: fn(f64) -> Color,
) -> Vec<Span<'static>> {
    let filled = (fraction.clamp(0.0, 1.0) * width as f64).round() as usize;
    from_filled(filled, width, ramp)
}

pub(in crate::ui) fn from_filled(
    filled: usize,
    width: usize,
    ramp: fn(f64) -> Color,
) -> Vec<Span<'static>> {
    let filled = filled.min(width);
    let mut spans: Vec<Span> = (0..filled)
        .map(|i| {
            let t = if filled > 1 {
                i as f64 / (filled - 1) as f64
            } else {
                1.0
            };
            Span::styled("█", theme::fg(ramp(0.15 + 0.85 * t)))
        })
        .collect();
    if width > filled {
        spans.push(Span::styled(
            "░".repeat(width - filled),
            theme::fg(theme::muted()),
        ));
    }
    spans
}
