//! Centralized color palette for cross-terminal consistency.
//!
//! Every color the UI emits routes through this module. A [`ThemeSpec`]
//! (per-token definitions, see `definitions`) resolves into a [`Theme`]
//! (final `Color` per role plus precomputed gradient ramps, see `derive`)
//! which is stored once at startup in the `ACTIVE` static. Helper fns read
//! the active theme, so call sites stay theme-agnostic, and every style
//! builder respects the `ui::NO_COLOR` flag.

use std::sync::OnceLock;

use ratatui::style::{Color, Modifier, Style};

mod definitions;
mod derive;

pub use definitions::{ThemePreset, ThemeSpec, TokenColor, detect_truecolor};
pub use derive::Theme;

use derive::{ON_COLOR_DARK, ON_COLOR_LIGHT, five_stop, three_stop};

/// The resolved theme in effect. Set once at startup; reads are lock-free
/// after first use and default to the muted preset (snapshot tests never
/// set a theme, so they keep rendering the muted default).
static ACTIVE: OnceLock<Theme> = OnceLock::new();

fn active() -> &'static Theme {
    ACTIVE.get_or_init(|| Theme::resolve(&ThemeSpec::builtin(ThemePreset::Muted), false))
}

/// Install the resolved theme. Called once at startup; a repeat call is
/// ignored with a warning.
pub fn set_theme(theme: Theme) {
    if ACTIVE.set(theme).is_err() {
        log::warn!("set_theme called more than once; keeping the active theme");
    }
}

/// Whether the Classic (full-color) preset mapping is active.
pub(super) fn is_classic() -> bool {
    active().classic
}

// --- Base color accessors ---
pub(super) fn ok() -> Color {
    active().ok
}
pub(super) fn warn() -> Color {
    active().warn
}
pub(super) fn err() -> Color {
    active().err
}
pub(super) fn accent() -> Color {
    active().accent
}
pub(super) fn muted() -> Color {
    active().muted
}
pub(super) fn info() -> Color {
    active().info
}
/// Dimmest tier: historic rows, disabled chrome.
pub(super) fn faint() -> Color {
    active().faint
}
/// Default body text (the terminal's own foreground on every built-in).
pub(super) fn text() -> Color {
    active().text
}

// --- UI element aliases ---
//
// Three-tier hierarchy so the showcase can pick out a clear winner:
//   * primary()  - what the user is acting on right now (active tab,
//     selected row's focus column, sorted column header)
//   * heading()  - structural anchors (table column headers, section titles)
//   * label()    - supporting context (field labels, units, separators)
//
// `primary()` returns a full Style because it always pairs with BOLD;
// the others return raw Colors so callers can compose with `fg()` /
// `bold_fg()` as needed.
pub(super) fn primary() -> Style {
    bold_fg(accent())
}
pub(super) fn label() -> Color {
    active().label
}
pub(super) fn heading() -> Color {
    active().heading
}

// --- Network aliases ---
pub(super) fn rx() -> Color {
    active().rx
}
pub(super) fn tx() -> Color {
    active().tx
}

// --- Traffic wave gradients (Graph tab) ---
//
// Truecolor 5-stop ramps for the braille traffic waves, derived from the
// theme's token seeds at resolve time: saturated color at the base and a
// white-hot crest for the glow ramps, a dark-to-bright walk for the signal
// ramps. Callers must wrap the result in `fg()` so NO_COLOR still strips
// these.

const EXPIRY_WARNING_START: f32 = 0.75;
const EXPIRY_CRITICAL_START: f32 = 0.90;

/// RX wave gradient color at intensity `t` (0 = dim base, 1 = crest).
pub(super) fn rx_wave(t: f64) -> Color {
    five_stop(&active().rx_ramp, t)
}
/// TX wave gradient color at intensity `t` (0 = dim base, 1 = crest).
pub(super) fn tx_wave(t: f64) -> Color {
    five_stop(&active().tx_ramp, t)
}
/// Accent wave gradient for non-directional graphs like the connection
/// count, at intensity `t` (0 = dim base, 1 = crest).
pub(super) fn accent_wave(t: f64) -> Color {
    five_stop(&active().accent_ramp, t)
}
/// Green gradient for healthy/success bars (derived from the ok token).
pub(super) fn ok_wave(t: f64) -> Color {
    five_stop(&active().ok_ramp, t)
}
/// Amber gradient for caution bars.
pub(super) fn warn_wave(t: f64) -> Color {
    five_stop(&active().warn_ramp, t)
}
/// Red gradient for critical bars.
pub(super) fn err_wave(t: f64) -> Color {
    five_stop(&active().err_ramp, t)
}
/// Fuchsia gradient for special/distinct bars (DNS).
pub(super) fn special_wave(t: f64) -> Color {
    five_stop(&active().special_ramp, t)
}
/// Gray gradient for secondary/inactive bars.
pub(super) fn muted_wave(t: f64) -> Color {
    five_stop(&active().muted_ramp, t)
}
/// Warn-to-err glow for connections nearing their removal timeout.
pub(super) fn expiry_glow(t: f64) -> Color {
    five_stop(&active().expiry_ramp, t)
}

/// Accent shimmer at phase `t` (0 = the accent itself, 1 = its lightest
/// step): a 3-stop lightness walk for animated text. Themes and terminals
/// without truecolor get the plain accent color, so the animation
/// gracefully becomes a static one.
pub(super) fn shimmer_wave(t: f64) -> Color {
    match &active().shimmer_ramp {
        Some(ramp) => three_stop(ramp, t),
        None => accent(),
    }
}

/// Map connection staleness to the expiry glow. The row turns yellow at 75%
/// of its timeout, stays yellow through the warning window, then intensifies
/// toward red during the final 10% before removal.
pub(super) fn expiry_glow_intensity(staleness: f32) -> Option<f64> {
    (staleness >= EXPIRY_WARNING_START).then(|| {
        f64::from(
            ((staleness - EXPIRY_CRITICAL_START) / (1.0 - EXPIRY_CRITICAL_START)).clamp(0.0, 1.0),
        )
    })
}

// --- Protocol aliases ---
pub(super) fn proto_https() -> Color {
    active().proto_https
}
pub(super) fn proto_quic() -> Color {
    active().proto_quic
}
pub(super) fn proto_http() -> Color {
    active().proto_http
}
pub(super) fn proto_dns() -> Color {
    active().proto_dns
}
pub(super) fn proto_ssh() -> Color {
    active().proto_ssh
}
pub(super) fn proto_other() -> Color {
    active().proto_other
}

// --- TCP state aliases ---
// Non-classic themes: ESTABLISHED is the common case and reads as plain
// text; only transitional states (a genuine signal) keep an attention color.
pub(super) fn tcp_established() -> Color {
    active().tcp_established
}
pub(super) fn tcp_opening() -> Color {
    active().tcp_opening
}
pub(super) fn tcp_closing() -> Color {
    active().tcp_closing
}
pub(super) fn tcp_waiting() -> Color {
    active().tcp_waiting
}
pub(super) fn tcp_closed() -> Color {
    active().tcp_closed
}

// --- Field-level aliases (same color used everywhere a field appears) ---
// Non-classic themes: addresses keep a calm color (they're the data being
// monitored), the other identifying fields render as body text, supporting
// context fades to the muted tier. Same address roles in every theme.
pub(super) fn field_local_addr() -> Color {
    active().field_local_addr
}
pub(super) fn field_remote_addr() -> Color {
    active().field_remote_addr
}
pub(super) fn field_state() -> Color {
    active().field_state
}
pub(super) fn field_service() -> Color {
    active().field_service
}
pub(super) fn field_location() -> Color {
    active().field_location
}
pub(super) fn field_process() -> Color {
    active().field_process
}
pub(super) fn field_application() -> Color {
    active().field_application
}
/// Color for hostnames inferred from a recently observed DNS resolution
/// (shown with a `~` prefix). Dimmer than `field_remote_addr` so the
/// inference is visually distinct from authoritative SNI / Host data.
pub(super) fn field_attributed_hostname() -> Color {
    active().field_attributed_hostname
}

// --- Historic (closed) connection rows ---
// Whole-row override; per-cell colors are dropped so the uniform faint
// tier carries the signal. DIM is deliberately NOT used when colors are
// available: terminals disagree wildly on it (invisible on light themes,
// barely-there in WezTerm dark). Under NO_COLOR it returns as the only
// row-level cue, alongside the "closed" state text.
pub(super) fn historic_row() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default().fg(faint())
    }
}

// --- Panel border ---
pub(super) fn border() -> Color {
    active().border
}

// --- Status bar styles ---
// Built on status_bar_base(): a REVERSED band (fg(Black).bg(Color) breaks
// on dark terminals) unless the theme provides a truecolor bg tint.

/// Subtle background band for the status bar: the theme's status_bg tint
/// when available, otherwise the REVERSED fallback.
pub(super) fn status_bar_base() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    match active().status_bg {
        Some(bg) => Style::default().bg(bg),
        None => Style::default().add_modifier(Modifier::REVERSED),
    }
}

pub(super) fn status_bar_confirm() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return status_bar_base();
    }
    status_bar_base().fg(warn()).add_modifier(Modifier::BOLD)
}
pub(super) fn status_bar_success() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return status_bar_base();
    }
    status_bar_base().fg(ok()).add_modifier(Modifier::BOLD)
}
pub(super) fn status_bar_error() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return status_bar_base().add_modifier(Modifier::BOLD);
    }
    status_bar_base().fg(err()).add_modifier(Modifier::BOLD)
}
pub(super) fn status_bar_default() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) || !is_classic() {
        return status_bar_base();
    }
    status_bar_base().fg(info())
}

// --- Selection and key hint styles ---

/// Accent-tinted selection band for table rows. Falls back to
/// BOLD | REVERSED (with no fg override, so when REVERSED swaps fg and bg
/// a red staleness row gets a red selection bar and the signal survives)
/// whenever the theme has no truecolor selection tint. Built-ins leave
/// `selection_fg` unset for the same reason: the row's own fg, including
/// the expiry glow, survives selection.
pub(super) fn selection_row() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
    }
    match active().selection_bg {
        Some(bg) => {
            let mut style = Style::default().bg(bg).add_modifier(Modifier::BOLD);
            if let Some(fg) = active().selection_fg {
                style = style.fg(fg);
            }
            style
        }
        None => Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
    }
}

/// The table highlight routes through `selection_row()` so a theme's
/// selection tint reaches every existing call site.
pub(super) fn row_highlight() -> Style {
    selection_row()
}

/// Whether the selection band is a real background tint (rather than the
/// BOLD | REVERSED fallback). Rows whose fg would be unreadable on the
/// tint (the faint historic tier) use this to restyle themselves when
/// selected.
pub(super) fn selection_has_bg() -> bool {
    !super::NO_COLOR.load(super::Ordering::Relaxed) && active().selection_bg.is_some()
}

/// Keycap style for status bar and help key hints.
pub(super) fn key_hint() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    Style::default()
        .fg(active().key)
        .add_modifier(Modifier::BOLD)
}

/// Label text following a keycap.
pub(super) fn key_hint_label() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default();
    }
    Style::default().fg(active().label)
}

// --- Style builders (NO_COLOR-aware) ---

/// Apply a foreground color, respecting NO_COLOR.
pub(super) fn fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

/// Apply a foreground color with BOLD, respecting NO_COLOR.
pub(super) fn bold_fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    }
}

/// Readable foreground for text drawn on `bg`, picking the near-black or
/// near-white candidate with the better contrast. Non-RGB (ANSI)
/// backgrounds return `Color::Black`: callers that cannot guarantee a
/// readable pair on an ANSI terminal render their bracket fallback instead
/// (see the badge widget). NO_COLOR returns `Color::Reset`.
pub(super) fn on_color(bg: Color) -> Color {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Color::Reset;
    }
    match bg {
        Color::Rgb(r, g, b) => {
            let bg = (r, g, b);
            let (r, g, b) = if derive::contrast_ratio(bg, ON_COLOR_DARK)
                >= derive::contrast_ratio(bg, ON_COLOR_LIGHT)
            {
                ON_COLOR_DARK
            } else {
                ON_COLOR_LIGHT
            };
            Color::Rgb(r, g, b)
        }
        _ => Color::Black,
    }
}

/// Stable per-identity tint for a name (a process or application), so the
/// same name keeps the same hue everywhere it appears. `None` means "no
/// tint available": NO_COLOR, a terminal without truecolor, or the classic
/// preset, whose palette stays as it always was. Callers keep their own
/// style in that case.
pub(super) fn identity_color(name: &str) -> Option<Color> {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return None;
    }
    let hues = active().identity_hues?;
    let (r, g, b) = derive::identity_rgb(hues, name);
    Some(Color::Rgb(r, g, b))
}

/// Fade a style toward the faint tier, marking a scroll boundary where
/// content continues past the visible edge. Truecolor foregrounds blend
/// halfway to the faint token; anything else (including a style with no
/// foreground) is substituted with it outright. NO_COLOR returns the style
/// untouched, since the fade is a color-only cue.
pub(super) fn edge_fade(style: Style) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return style;
    }
    match (style.fg, faint()) {
        (Some(Color::Rgb(r, g, b)), Color::Rgb(fr, fg, fb)) => {
            let (r, g, b) = derive::blend_half((r, g, b), (fr, fg, fb));
            style.fg(Color::Rgb(r, g, b))
        }
        _ => style.fg(faint()),
    }
}

/// Apply a foreground color with BOLD + UNDERLINED, respecting NO_COLOR.
pub(super) fn bold_underline_fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests read the module-level default (muted) theme; none of
    // them may call set_theme, since ACTIVE is process-wide.

    #[test]
    fn primary_wave_ramps_match_flow_direction_colors() {
        let white = Color::Rgb(0xFF, 0xFF, 0xFF);

        assert_eq!(rx_wave(0.0), Color::Rgb(0x3B, 0x82, 0xF6));
        assert_eq!(tx_wave(0.0), Color::Rgb(0x10, 0xB9, 0x81));
        assert_eq!(rx_wave(1.0), white);
        assert_eq!(tx_wave(1.0), white);
        assert_eq!(accent_wave(1.0), white);
        assert_eq!(ok_wave(1.0), white);
    }

    #[test]
    fn heading_outranks_label_in_default_theme() {
        // The hierarchy fix: heading (Reset, terminal default fg) must not
        // collapse into the label tier (Gray).
        assert_ne!(heading(), label());
        assert_eq!(heading(), Color::Reset);
        assert_eq!(label(), Color::Gray);
    }

    #[test]
    fn default_theme_uses_reversed_fallbacks_for_bg_styles() {
        let reversed_bold = Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED);
        assert_eq!(selection_row(), reversed_bold);
        assert_eq!(row_highlight(), reversed_bold);
        assert_eq!(
            status_bar_base(),
            Style::default().add_modifier(Modifier::REVERSED)
        );
    }

    #[test]
    fn key_hints_use_key_and_label_tokens() {
        assert_eq!(
            key_hint(),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        );
        assert_eq!(key_hint_label(), Style::default().fg(Color::Gray));
    }

    #[test]
    fn on_color_picks_the_readable_foreground() {
        // Dark badge background: near-white text; light one: near-black.
        assert_eq!(
            on_color(Color::Rgb(0x33, 0x46, 0x7C)),
            Color::Rgb(240, 240, 240)
        );
        assert_eq!(
            on_color(Color::Rgb(0x00, 0x00, 0x00)),
            Color::Rgb(240, 240, 240)
        );
        assert_eq!(
            on_color(Color::Rgb(0xF9, 0xE2, 0xAF)),
            Color::Rgb(26, 26, 26)
        );
        assert_eq!(
            on_color(Color::Rgb(0xFF, 0xFF, 0xFF)),
            Color::Rgb(26, 26, 26)
        );
        // ANSI backgrounds cannot be measured; callers render their
        // bracket fallback instead of a filled badge.
        assert_eq!(on_color(Color::Green), Color::Black);
        assert_eq!(on_color(Color::Reset), Color::Black);
    }

    #[test]
    fn shimmer_wave_is_static_accent_without_truecolor() {
        // The default (muted, ANSI) theme has no shimmer ramp.
        for t in [0.0, 0.25, 0.5, 1.0] {
            assert_eq!(shimmer_wave(t), accent());
        }
    }

    #[test]
    fn identity_color_is_absent_without_truecolor() {
        // The default theme resolves against a non-truecolor terminal.
        assert_eq!(identity_color("firefox"), None);
    }

    #[test]
    fn edge_fade_substitutes_faint_for_ansi_foregrounds() {
        let style = Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD);
        let faded = edge_fade(style);
        assert_eq!(faded.fg, Some(faint()));
        assert_eq!(faded.add_modifier, Modifier::BOLD);
        // A style with no foreground still picks up the faint tier.
        assert_eq!(edge_fade(Style::default()).fg, Some(faint()));
        // Backgrounds are untouched: only the text fades.
        let banded = edge_fade(Style::default().bg(Color::Blue));
        assert_eq!(banded.bg, Some(Color::Blue));
    }

    #[test]
    fn default_theme_matches_historical_muted_palette() {
        assert_eq!(accent(), Color::Cyan);
        assert_eq!(ok(), Color::Green);
        assert_eq!(warn(), Color::Yellow);
        assert_eq!(err(), Color::Red);
        assert_eq!(info(), Color::Blue);
        // The special token has no accessor of its own; DNS is its role.
        assert_eq!(proto_dns(), Color::Magenta);
        assert_eq!(muted(), Color::Gray);
        assert_eq!(faint(), Color::DarkGray);
        assert_eq!(text(), Color::Reset);
        assert_eq!(border(), Color::DarkGray);
        assert_eq!(rx(), Color::Green);
        assert_eq!(tx(), Color::Blue);
        assert!(!is_classic());
    }
}
