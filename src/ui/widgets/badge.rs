//! Inline badge primitives: a solid `pill` for state-like values and a
//! quieter `chip` for metadata. Both return spans, so callers splice them
//! into a `Line` they are already building.
//!
//! A painted band needs a fg/bg pair that is readable on the terminal at
//! hand. Truecolor gives us that (the foreground is picked by luminance,
//! see `theme::on_color`); ANSI-16 palettes do not, since the terminal
//! remaps them freely. Both helpers therefore degrade to a bracketed
//! `[text]` form whenever no tint is available, which occupies exactly
//! the same width as the padded ` text ` band so layouts do not shift.
//! Under NO_COLOR the brackets carry the badge on their own.

use ratatui::{
    style::{Color, Modifier, Style},
    text::Span,
};

use crate::ui::{NO_COLOR, Ordering, theme};

/// Solid badge: ` text ` painted on `bg`, bold, with the readable
/// foreground [`theme::on_color`] picks for that background. `bg` is
/// meant to be a theme color (a connection state color, for instance).
///
/// Non-RGB backgrounds (every color on an ANSI-16 terminal) render as
/// `[text]` in `bg`'s own color with no band; NO_COLOR renders `[text]`
/// unstyled.
pub(in crate::ui) fn pill(text: &str, bg: Color) -> Vec<Span<'static>> {
    pill_spans(text, bg, NO_COLOR.load(Ordering::Relaxed))
}

/// Quiet badge: ` text ` on the theme's selection band, the one fg/bg
/// pair every preset already guarantees (and the contrast guard checks).
///
/// Themes without a truecolor selection tint, and NO_COLOR, render
/// `[text]` in the muted tier instead.
pub(in crate::ui) fn chip(text: &str) -> Vec<Span<'static>> {
    chip_spans(text, theme::selection_has_bg())
}

/// [`pill`] with the NO_COLOR flag passed in, so tests can exercise both
/// paths without touching the process-wide flag.
fn pill_spans(text: &str, bg: Color, no_color: bool) -> Vec<Span<'static>> {
    if no_color {
        return vec![Span::raw(bracketed(text))];
    }
    match bg {
        Color::Rgb(..) => vec![Span::styled(
            padded(text),
            Style::default()
                .fg(theme::on_color(bg))
                .bg(bg)
                .add_modifier(Modifier::BOLD),
        )],
        _ => vec![Span::styled(bracketed(text), theme::fg(bg))],
    }
}

/// [`chip`] with the selection-tint decision passed in, so tests can
/// exercise both paths whatever theme is active.
fn chip_spans(text: &str, banded: bool) -> Vec<Span<'static>> {
    if banded {
        // selection_row() is the band itself: tint, plus the theme's
        // selection foreground when it sets one.
        vec![Span::styled(padded(text), theme::selection_row())]
    } else {
        // Muted under a color theme, plain under NO_COLOR (theme::fg
        // strips the color there).
        vec![Span::styled(bracketed(text), theme::fg(theme::muted()))]
    }
}

/// Band form: one padding cell on each side.
fn padded(text: &str) -> String {
    format!(" {text} ")
}

/// Bracket fallback, the same width as [`padded`].
fn bracketed(text: &str) -> String {
    format!("[{text}]")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_of(spans: &[Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn pill_paints_a_band_on_rgb_backgrounds() {
        let bg = Color::Rgb(20, 120, 60);
        let spans = pill_spans("ESTABLISHED", bg, false);
        assert_eq!(text_of(&spans), " ESTABLISHED ");
        let style = spans[0].style;
        assert_eq!(style.bg, Some(bg));
        assert_eq!(style.fg, Some(theme::on_color(bg)));
        assert!(style.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn pill_brackets_non_rgb_backgrounds() {
        let spans = pill_spans("CLOSED", Color::Red, false);
        assert_eq!(text_of(&spans), "[CLOSED]");
        assert_eq!(spans[0].style.bg, None);
        assert_eq!(spans[0].style.fg, Some(Color::Red));
    }

    #[test]
    fn pill_is_plain_under_no_color() {
        let spans = pill_spans("ESTABLISHED", Color::Rgb(20, 120, 60), true);
        assert_eq!(text_of(&spans), "[ESTABLISHED]");
        assert_eq!(spans[0].style, Style::default());
    }

    #[test]
    fn chip_paints_the_selection_band_when_tinted() {
        let spans = chip_spans("rtt 34 ms", true);
        assert_eq!(text_of(&spans), " rtt 34 ms ");
        assert_eq!(spans[0].style, theme::selection_row());
    }

    #[test]
    fn chip_brackets_without_a_selection_tint() {
        let spans = chip_spans("rtt 34 ms", false);
        assert_eq!(text_of(&spans), "[rtt 34 ms]");
        assert_eq!(spans[0].style.bg, None);
    }

    #[test]
    fn both_forms_have_the_same_width() {
        assert_eq!(padded("port:443").chars().count(), 10);
        assert_eq!(bracketed("port:443").chars().count(), 10);
    }
}
