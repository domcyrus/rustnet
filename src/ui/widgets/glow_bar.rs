//! Horizontal bars with theme-derived shading and an ANSI texture fallback.
//! Bars have sub-cell precision: the tip renders
//! the fractional cell with an eighth-block glyph, and the unfilled
//! remainder is a quiet dotted track. Under NO_COLOR the block-vs-dot
//! glyph contrast keeps the bar legible on its own.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    time::{Duration, Instant},
};

use ratatui::{style::Color, text::Span};

use crate::ui::theme;

const TRANSITION: Duration = Duration::from_millis(250);

/// Per-view bar transitions keyed by metric identity, never by row position.
/// New or resized bars show their actual value immediately. Only subsequent
/// changes animate; entries disappear as soon as their bars leave the view.
#[derive(Debug)]
pub(crate) struct BarAnimations {
    entries: RefCell<HashMap<String, BarTransition>>,
    now: Cell<Instant>,
    active: Cell<bool>,
}

#[derive(Debug)]
struct BarTransition {
    from: f64,
    target: f64,
    started: Instant,
    width: usize,
    seen: bool,
}

impl BarTransition {
    fn value(&self, now: Instant) -> f64 {
        let t = (now.saturating_duration_since(self.started).as_secs_f64()
            / TRANSITION.as_secs_f64())
        .clamp(0.0, 1.0);
        let eased = t * t * (3.0 - 2.0 * t);
        self.from + (self.target - self.from) * eased
    }
}

impl Default for BarAnimations {
    fn default() -> Self {
        Self {
            entries: RefCell::default(),
            now: Cell::new(Instant::now()),
            active: Cell::new(false),
        }
    }
}

impl BarAnimations {
    pub(crate) fn begin_frame(&self, now: Instant) {
        self.now.set(now);
        self.active.set(false);
        for entry in self.entries.borrow_mut().values_mut() {
            entry.seen = false;
        }
    }

    pub(crate) fn finish_frame(&self) {
        self.entries.borrow_mut().retain(|_, entry| entry.seen);
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.get()
    }

    fn fraction(&self, key: String, target: f64, width: usize) -> f64 {
        let target = if target.is_finite() {
            target.clamp(0.0, 1.0)
        } else {
            0.0
        };
        if width == 0 {
            return target;
        }
        let now = self.now.get();
        let mut entries = self.entries.borrow_mut();
        let entry = entries.entry(key).or_insert(BarTransition {
            from: target,
            target,
            started: now,
            width,
            seen: true,
        });
        entry.seen = true;
        if entry.width != width {
            *entry = BarTransition {
                from: target,
                target,
                started: now,
                width,
                seen: true,
            };
        } else if entry.target != target {
            entry.from = entry.value(now);
            entry.target = target;
            entry.started = now;
        }
        let value = entry.value(now);
        if (value - target).abs() * width as f64 >= 0.0625 {
            self.active.set(true);
            value
        } else {
            // Snap the last half-eighth-cell so completed bars stop redrawing.
            entry.from = target;
            target
        }
    }

    pub(crate) fn spans(
        &self,
        key: impl Into<String>,
        fraction: f64,
        width: usize,
        color: Color,
    ) -> Vec<Span<'static>> {
        themed_spans(self.fraction(key.into(), fraction, width), width, color)
    }
}

/// Partial-cell tip glyphs; index i renders (i + 1)/8 of a cell.
const EIGHTHS: [&str; 7] = [
    "\u{258F}", "\u{258E}", "\u{258D}", "\u{258C}", "\u{258B}", "\u{258A}", "\u{2589}",
];

/// Quiet track glyph (middle dot) for the unfilled remainder.
const TRACK: &str = "\u{00B7}";

/// Theme-derived gradient, with a textured ANSI fallback. Geometry and
/// fractional tips are shared with the other bars.
pub(in crate::ui) fn themed_spans(fraction: f64, width: usize, color: Color) -> Vec<Span<'static>> {
    fractional_spans(
        fraction,
        width,
        |t| theme::bar_tint(color, t),
        !matches!(color, Color::Rgb(..)),
    )
}

fn fractional_spans(
    fraction: f64,
    width: usize,
    ramp: impl Fn(f64) -> Color,
    textured: bool,
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
    render(whole, tip_eighths, width, ramp, textured)
}

/// `whole` full cells, then an optional eighth-block tip (`tip_eighths` in
/// 1..=7), then the track. The gradient walks every lit cell including the
/// tip, where it reaches the semantic colour token.
fn render(
    whole: usize,
    tip_eighths: usize,
    width: usize,
    ramp: impl Fn(f64) -> Color,
    textured: bool,
) -> Vec<Span<'static>> {
    let lit = whole + usize::from(tip_eighths > 0);
    let color_at = |i: usize| {
        let t = if lit > 1 {
            i as f64 / (lit - 1) as f64
        } else {
            1.0
        };
        ramp(t)
    };
    let mut spans: Vec<Span> = Vec::with_capacity(lit + 1);
    for i in 0..whole {
        let glyph = if textured && lit >= 4 {
            match i * 4 / lit {
                0 => "░",
                1 => "▒",
                2 => "▓",
                _ => "█",
            }
        } else {
            "█"
        };
        spans.push(Span::styled(glyph, theme::fg(color_at(i))));
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
    use crate::ui::test_support::spans_text;
    use ratatui::style::Color;

    #[test]
    fn transitions_retarget_from_the_displayed_value_and_settle() {
        let animation = BarAnimations::default();
        let start = Instant::now();
        animation.begin_frame(start);
        assert_eq!(animation.fraction("rx".into(), 0.2, 100), 0.2);
        assert!(!animation.is_active());
        assert_eq!(animation.fraction("rx".into(), 0.8, 100), 0.2);
        assert!(animation.is_active());
        animation.finish_frame();
        animation.begin_frame(start + TRANSITION / 2);
        let middle = animation.fraction("rx".into(), 0.8, 100);
        assert!((middle - 0.5).abs() < 1e-9);
        assert_eq!(animation.fraction("rx".into(), 0.0, 100), middle);
        animation.finish_frame();
        animation.begin_frame(start + TRANSITION);
        let falling = animation.fraction("rx".into(), 0.0, 100);
        assert!(falling > 0.0 && falling < middle);
        animation.finish_frame();
        animation.begin_frame(start + TRANSITION * 2);
        assert_eq!(animation.fraction("rx".into(), 0.0, 100), 0.0);
        assert!(!animation.is_active());
    }

    #[test]
    fn identities_survive_reordering_and_hidden_entries_are_removed() {
        let animation = BarAnimations::default();
        let start = Instant::now();
        animation.begin_frame(start);
        animation.fraction("firefox/tx".into(), 0.2, 20);
        animation.fraction("ssh/tx".into(), 0.8, 20);
        animation.finish_frame();
        animation.begin_frame(start + TRANSITION);
        assert_eq!(animation.fraction("ssh/tx".into(), 0.1, 20), 0.8);
        assert_eq!(animation.fraction("firefox/tx".into(), 0.9, 20), 0.2);
        // Switching direction creates an independent metric immediately.
        assert_eq!(animation.fraction("firefox/rx".into(), 0.6, 20), 0.6);
        animation.finish_frame();
        animation.begin_frame(start + TRANSITION * 2);
        animation.fraction("firefox/rx".into(), 0.6, 20);
        animation.finish_frame();
        assert_eq!(animation.entries.borrow().len(), 1);
        assert!(!animation.is_active());
        animation.begin_frame(start + TRANSITION * 3);
        animation.finish_frame();
        assert!(animation.entries.borrow().is_empty());
    }

    #[test]
    fn resizing_and_subpixel_changes_do_not_keep_the_ui_animating() {
        let animation = BarAnimations::default();
        let now = Instant::now();
        animation.begin_frame(now);
        animation.fraction("rx".into(), 0.2, 20);
        assert_eq!(animation.fraction("rx".into(), 0.201, 20), 0.201);
        assert!(!animation.is_active());
        animation.finish_frame();
        animation.begin_frame(now);
        assert_eq!(animation.fraction("rx".into(), 0.8, 40), 0.8);
        assert!(!animation.is_active());
        animation.finish_frame();
        animation.begin_frame(now);
        animation.fraction("invisible".into(), 1.0, 0);
        animation.finish_frame();
        assert!(animation.entries.borrow().is_empty());
    }

    fn rendered_width(spans: &[Span<'_>]) -> usize {
        spans.iter().map(|s| s.content.chars().count()).sum()
    }

    #[test]
    fn themed_bars_shade_rgb_and_preserve_ansi_palette() {
        let token = Color::Rgb(90, 140, 190);
        let rgb = themed_spans(0.75, 8, token);
        assert_ne!(rgb[0].style.fg, rgb[5].style.fg);
        assert_eq!(rgb[5].style, theme::fg(token));
        assert_eq!(rendered_width(&rgb), 8);
        let ansi = themed_spans(1.0, 8, Color::Blue);
        assert_eq!(spans_text(&ansi), "░░▒▒▓▓██");
        assert!(ansi.iter().all(|span| span.style == theme::fg(Color::Blue)));
    }

    #[test]
    fn empty_bar_is_all_track() {
        let s = themed_spans(0.0, 4, Color::Rgb(0, 180, 90));
        assert_eq!(spans_text(&s), "····");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn full_bar_has_no_track() {
        let s = themed_spans(1.0, 4, Color::Rgb(0, 180, 90));
        assert_eq!(spans_text(&s), "████");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn fractional_tip_uses_eighth_blocks() {
        // 2.5 cells over width 4: two full blocks, a half-block tip, one track cell.
        let s = themed_spans(0.625, 4, Color::Rgb(0, 180, 90));
        assert_eq!(spans_text(&s), "██▌·");
        assert_eq!(rendered_width(&s), 4);
    }

    #[test]
    fn tip_rounds_up_to_full_cell() {
        // 1.99 cells rounds to 2 full blocks, never a stray tip glyph.
        let s = themed_spans(0.995, 2, Color::Rgb(0, 180, 90));
        assert_eq!(spans_text(&s), "██");
    }

    #[test]
    fn tiny_fraction_shows_one_eighth() {
        let s = themed_spans(0.01, 10, Color::Rgb(0, 180, 90));
        assert_eq!(spans_text(&s), "▏·········");
    }

    #[test]
    fn width_is_preserved_across_fractions() {
        for i in 0..=100 {
            let s = themed_spans(i as f64 / 100.0, 7, Color::Rgb(0, 180, 90));
            assert_eq!(rendered_width(&s), 7, "fraction {i}%");
        }
    }
}
