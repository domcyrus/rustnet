//! Startup splash shown while packet capture initializes: a breathing
//! accent glow, a spinning braille spinner, a shimmer running through
//! the headline, and an animated wave in the same gradient family as
//! the traffic graphs.

use std::time::Duration;

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{panel_block, theme, widgets::braille_graph};

/// Braille spinner frames, advanced every [`FRAME_MS`] of splash time.
const SPINNER: [char; 8] = ['⣾', '⣽', '⣻', '⢿', '⡿', '⣟', '⣯', '⣷'];

/// Splash animation frame length in milliseconds. Callers quantize
/// `elapsed` to this bucket so repeated draws within one frame are
/// byte-identical (and the first frame is deterministic for tests).
pub(in crate::ui) const FRAME_MS: u64 = 120;

/// Headline shimmer: cycles per second of the travelling highlight.
const SHIMMER_SPEED: f64 = 0.7;
/// Phase offset between neighboring characters, in cycles. Small enough
/// that the crest reads as one band sliding along the text.
const SHIMMER_STEP: f64 = 0.045;

pub(in crate::ui) fn draw_loading_screen(f: &mut Frame, elapsed: Duration) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Length(9),
            Constraint::Percentage(40),
        ])
        .split(f.area());
    let panel = chunks[1];

    let secs = elapsed.as_secs_f64();
    // Breathing glow: brightness swings through the accent gradient on
    // a ~2s cycle (same trick as flow's pulsing logo dot).
    let breath = 0.5 + 0.5 * (secs * std::f64::consts::TAU / 2.0).sin();
    let glow = theme::accent_wave(0.35 + 0.55 * breath);
    let spinner = SPINNER[(elapsed.as_millis() as u64 / FRAME_MS) as usize % SPINNER.len()];

    let mut headline = vec![Span::styled(format!("{spinner} "), theme::bold_fg(glow))];
    headline.extend(shimmer_spans("Loading network connections...", secs));

    let loading_text = vec![
        Line::from(""),
        Line::from(headline),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Preparing capture and process attribution",
            theme::fg(theme::muted()),
        )]),
    ];

    let loading_paragraph = Paragraph::new(loading_text)
        .alignment(ratatui::layout::Alignment::Center)
        .block(panel_block("RustNet Monitor"));

    f.render_widget(loading_paragraph, panel);

    // Animated swell centered under the text, scrolling left, rendered
    // with the same braille gradient engine as the traffic graphs.
    // Purely decorative: a synthetic sine under a raised-sine envelope,
    // so a few gentle crests rise in the middle and fade out toward
    // the edges instead of a wall of waves spanning the panel.
    if panel.width > 8 && panel.height >= 9 {
        let wave_width = (panel.width - 4).min(40);
        let wave_area = Rect::new(
            panel.x + (panel.width - wave_width) / 2,
            panel.y + panel.height - 3,
            wave_width,
            2,
        );
        let phase = secs * 6.0;
        let dots = wave_area.width as usize * 2;
        let samples: Vec<u64> = (0..dots)
            .map(|i| {
                let envelope = (std::f64::consts::PI * i as f64 / (dots - 1) as f64).sin();
                (55.0 * envelope * (1.0 + (i as f64 * 0.22 + phase).sin())) as u64
            })
            .collect();
        let lines = braille_graph::render(
            &samples,
            wave_area.width as usize,
            2,
            130.0,
            0.0,
            dots,
            |intensity| theme::accent_wave((0.35 + 0.45 * breath) * intensity),
        );
        f.render_widget(Paragraph::new(lines), wave_area);
    }
}

/// One span per character of `text`, each sampling the accent shimmer at
/// its own phase so a highlight travels along the line. `secs` is the
/// splash clock; the caller quantizes it, so a redraw inside one
/// animation frame repeats byte for byte.
///
/// On themes and terminals without truecolor `shimmer_wave` returns the
/// plain accent for every phase, which makes the headline a static
/// accent line; under NO_COLOR `theme::fg` strips it back to plain text.
fn shimmer_spans(text: &str, secs: f64) -> Vec<Span<'static>> {
    text.chars()
        .enumerate()
        .map(|(i, ch)| {
            let phase = secs * SHIMMER_SPEED - i as f64 * SHIMMER_STEP;
            let t = 0.5 + 0.5 * (phase * std::f64::consts::TAU).sin();
            Span::styled(ch.to_string(), theme::fg(theme::shimmer_wave(t)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shimmer_preserves_the_text() {
        let spans = shimmer_spans("Loading network connections...", 0.0);
        assert_eq!(
            spans.len(),
            "Loading network connections...".chars().count()
        );
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "Loading network connections...");
    }

    #[test]
    fn shimmer_is_char_safe() {
        let spans = shimmer_spans("héllo…", 1.5);
        assert_eq!(spans.len(), 6);
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "héllo…");
    }

    #[test]
    fn shimmer_is_static_without_truecolor() {
        // The default (muted) theme is ANSI, so every phase resolves to
        // the same accent color and the splash simply stops animating.
        let spans = shimmer_spans("abc", 0.0);
        let later = shimmer_spans("abc", 3.0);
        for (a, b) in spans.iter().zip(later.iter()) {
            assert_eq!(a.style, b.style);
            assert_eq!(a.style, theme::fg(theme::accent()));
        }
    }
}
