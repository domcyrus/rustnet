//! Truecolor horizontal bars using the same dark-to-bright ramps as the
//! braille traffic graphs. Bars have sub-cell precision: the tip renders
//! the fractional cell with an eighth-block glyph, and the unfilled
//! remainder is a quiet dotted track. Under NO_COLOR the block-vs-dot
//! glyph contrast keeps the bar legible on its own.

use ratatui::{style::Color, text::Span};

use crate::ui::theme;

/// Partial-cell tip glyphs; index i renders (i + 1)/8 of a cell.
const EIGHTHS: [&str; 7] = [
    "\u{258F}", "\u{258E}", "\u{258D}", "\u{258C}", "\u{258B}", "\u{258A}", "\u{2589}",
];

/// Quiet track glyph (middle dot) for the unfilled remainder.
const TRACK: &str = "\u{00B7}";

pub(in crate::ui) fn spans(
    fraction: f64,
    width: usize,
    ramp: fn(f64) -> Color,
) -> Vec<Span<'static>> {
    let cells = fraction.clamp(0.0, 1.0) * width as f64;
    let mut whole = cells.floor() as usize;
    let mut tip_eighths = ((cells - whole as f64) * 8.0).round() as usize;
    if tip_eighths == 8 {
        whole += 1;
        tip_eighths = 0;
    }
    if whole >= width {
        whole = width;
        tip_eighths = 0;
    }
    render(whole, tip_eighths, width, ramp)
}

pub(in crate::ui) fn from_filled(
    filled: usize,
    width: usize,
    ramp: fn(f64) -> Color,
) -> Vec<Span<'static>> {
    render(filled.min(width), 0, width, ramp)
}

/// `whole` full cells, then an optional eighth-block tip (`tip_eighths` in
/// 1..=7), then the track. The gradient walks every lit cell including the
/// tip, so the crest always sits at the bar's leading edge.
fn render(
    whole: usize,
    tip_eighths: usize,
    width: usize,
    ramp: fn(f64) -> Color,
) -> Vec<Span<'static>> {
    let lit = whole + usize::from(tip_eighths > 0);
    let color_at = |i: usize| {
        let t = if lit > 1 {
            i as f64 / (lit - 1) as f64
        } else {
            1.0
        };
        ramp(0.15 + 0.85 * t)
    };
    let mut spans: Vec<Span> = Vec::with_capacity(lit + 1);
    for i in 0..whole {
        spans.push(Span::styled("█", theme::fg(color_at(i))));
    }
    if tip_eighths > 0 {
        spans.push(Span::styled(
            EIGHTHS[tip_eighths - 1],
            theme::fg(color_at(whole)),
        ));
    }
    if width > lit {
        // faint(): a neutral dim tier on every preset. border() would leak
        // chrome colors into data bars (Vivid's border is Magenta).
        spans.push(Span::styled(
            TRACK.repeat(width - lit),
            theme::fg(theme::faint()),
        ));
    }
    spans
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::style::Color;

    fn flat_ramp(_t: f64) -> Color {
        Color::Green
    }

    fn rendered_width(spans: &[Span<'_>]) -> usize {
        spans.iter().map(|s| s.content.chars().count()).sum()
    }

    fn text(spans: &[Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn empty_bar_is_all_track() {
        let s = spans(0.0, 4, flat_ramp);
        assert_eq!(text(&s), "····");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn full_bar_has_no_track() {
        let s = spans(1.0, 4, flat_ramp);
        assert_eq!(text(&s), "████");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn fractional_tip_uses_eighth_blocks() {
        // 2.5 cells over width 4: two full blocks, a half-block tip, one track cell.
        let s = spans(0.625, 4, flat_ramp);
        assert_eq!(text(&s), "██▌·");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn tip_rounds_up_to_full_cell() {
        // 1.99 cells rounds to 2 full blocks, never a stray tip glyph.
        let s = spans(0.995, 2, flat_ramp);
        assert_eq!(text(&s), "██");
    }

    #[test]
    fn tiny_fraction_shows_one_eighth() {
        let s = spans(0.01, 10, flat_ramp);
        assert_eq!(text(&s), "▏·········");
    }

    #[test]
    fn from_filled_stays_whole_cell() {
        let s = from_filled(2, 5, flat_ramp);
        assert_eq!(text(&s), "██···");
        let overshoot = from_filled(9, 5, flat_ramp);
        assert_eq!(text(&overshoot), "█████");
    }

    #[test]
    fn width_is_preserved_across_fractions() {
        for i in 0..=100 {
            let s = spans(i as f64 / 100.0, 7, flat_ramp);
            assert_eq!(rendered_width(&s), 7, "fraction {i}%");
        }
    }
}
