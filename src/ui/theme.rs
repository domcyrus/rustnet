//! Centralized color palette for cross-terminal consistency.
//! All semantic colors derive from these 7 base constants.
//!
//! Two presets share this module: the default `Muted` preset keeps one
//! accent color (cyan) and reserves the rest of the palette for semantic
//! signals (state health, staleness, traffic activity), while `Classic`
//! restores the original per-field rainbow. Every alias below branches on
//! the active preset so call sites stay preset-agnostic.

use std::sync::atomic::{AtomicBool, Ordering};

use ratatui::style::{Color, Modifier, Style};

// --- 7-slot base palette ---
const OK: Color = Color::Green; // Healthy/success
const WARN: Color = Color::Yellow; // Caution/attention
const ERR: Color = Color::Red; // Error/critical
const ACCENT: Color = Color::Cyan; // Informational highlight
const MUTED: Color = Color::Gray; // Secondary/inactive
const INFO: Color = Color::Blue; // Neutral info
const SPECIAL: Color = Color::Magenta; // Distinct/special

// --- Theme presets ---

/// Selectable palette presets (`--theme` CLI flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemePreset {
    /// Restrained default: one cyan accent, color only for semantic signals.
    Muted,
    /// The original full-color palette with per-field colors.
    Classic,
}

/// Stored as a bool ("is classic") so reads stay a single relaxed atomic
/// load, mirroring the NO_COLOR flag in `ui::mod`.
static CLASSIC: AtomicBool = AtomicBool::new(false);

/// Select the active palette preset. Called once at startup.
pub fn set_preset(preset: ThemePreset) {
    CLASSIC.store(preset == ThemePreset::Classic, Ordering::Relaxed);
}

/// Whether the Classic (full-color) preset is active.
pub fn is_classic() -> bool {
    CLASSIC.load(Ordering::Relaxed)
}

// --- Base color accessors ---
pub fn ok() -> Color {
    OK
}
pub fn warn() -> Color {
    WARN
}
pub fn err() -> Color {
    ERR
}
pub fn accent() -> Color {
    ACCENT
}
pub fn muted() -> Color {
    MUTED
}
pub fn info() -> Color {
    INFO
}
pub fn special() -> Color {
    SPECIAL
}

// --- UI element aliases ---
//
// Three-tier hierarchy so the showcase can pick out a clear winner:
//   * primary()  — what the user is acting on right now (active tab,
//     selected row's focus column, sorted column header)
//   * heading()  — structural anchors (table column headers, section titles)
//   * label()    — supporting context (field labels, units, separators)
//
// `primary()` returns a full Style because it always pairs with BOLD;
// the others return raw Colors so callers can compose with `fg()` /
// `bold_fg()` as needed.
pub fn primary() -> Style {
    bold_fg(accent())
}
pub fn label() -> Color {
    muted()
}
pub fn heading() -> Color {
    if is_classic() { warn() } else { muted() }
}
pub fn key() -> Color {
    if is_classic() { warn() } else { accent() }
}

// --- Network aliases ---
pub fn rx() -> Color {
    ok()
}
pub fn tx() -> Color {
    info()
}

// --- Traffic wave gradients (Graph tab) ---
//
// Truecolor 5-stop ramps for the braille traffic waves: deep hue at
// the base of the wave, brighter at the crest (style borrowed from
// github.com/programmersd21/flow). Each ramp stays inside a single
// hue — RX is unmistakably green, TX unmistakably blue — and the
// bright end stops well short of white so crests stay visible on
// light backgrounds. Callers must wrap the result in `fg()` so
// NO_COLOR still strips these.
const RX_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x16, 0x65, 0x34), // deep green
    (0x15, 0x80, 0x3D),
    (0x16, 0xA3, 0x4A),
    (0x22, 0xC5, 0x5E),
    (0x4A, 0xDE, 0x80), // bright green crest
];
const TX_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x1E, 0x40, 0xAF), // deep blue
    (0x1D, 0x4E, 0xD8),
    (0x25, 0x63, 0xEB),
    (0x3B, 0x82, 0xF6),
    (0x60, 0xA5, 0xFA), // bright blue crest
];
const ACCENT_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x15, 0x5E, 0x75), // deep cyan
    (0x0E, 0x74, 0x90),
    (0x08, 0x91, 0xB2),
    (0x06, 0xB6, 0xD4),
    (0x22, 0xD3, 0xEE), // bright cyan crest
];
const WARN_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x92, 0x40, 0x0E), // deep amber
    (0xB4, 0x53, 0x09),
    (0xD9, 0x77, 0x06),
    (0xF5, 0x9E, 0x0B),
    (0xFB, 0xBF, 0x24), // bright amber
];
const ERR_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x99, 0x1B, 0x1B), // deep red
    (0xB9, 0x1C, 0x1C),
    (0xDC, 0x26, 0x26),
    (0xEF, 0x44, 0x44),
    (0xF8, 0x71, 0x71), // bright red
];
const SPECIAL_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x86, 0x19, 0x8F), // deep fuchsia
    (0xA2, 0x1C, 0xAF),
    (0xC0, 0x26, 0xD3),
    (0xD9, 0x46, 0xEF),
    (0xE8, 0x79, 0xF9), // bright fuchsia
];
const MUTED_WAVE_STOPS: [(u8, u8, u8); 5] = [
    (0x37, 0x41, 0x51), // deep gray
    (0x4B, 0x55, 0x63),
    (0x6B, 0x72, 0x80),
    (0x84, 0x8D, 0x9C),
    (0x9C, 0xA3, 0xAF), // light gray
];

fn lerp_channel(a: u8, b: u8, t: f64) -> u8 {
    (a as f64 + (b as f64 - a as f64) * t).round() as u8
}

/// Walk a 5-stop color ramp at `t` ∈ [0, 1] (4 linear segments).
fn five_stop(stops: &[(u8, u8, u8); 5], t: f64) -> Color {
    let seg = t.clamp(0.0, 1.0) * 4.0;
    let i = (seg as usize).min(3);
    let local = seg - i as f64;
    let (a, b) = (stops[i], stops[i + 1]);
    Color::Rgb(
        lerp_channel(a.0, b.0, local),
        lerp_channel(a.1, b.1, local),
        lerp_channel(a.2, b.2, local),
    )
}

/// RX wave gradient color at intensity `t` (0 = dim base, 1 = crest).
pub fn rx_wave(t: f64) -> Color {
    five_stop(&RX_WAVE_STOPS, t)
}
/// TX wave gradient color at intensity `t` (0 = dim base, 1 = crest).
pub fn tx_wave(t: f64) -> Color {
    five_stop(&TX_WAVE_STOPS, t)
}
/// Accent (cyan) wave gradient for non-directional graphs like the
/// connection count, at intensity `t` (0 = dim base, 1 = crest).
pub fn accent_wave(t: f64) -> Color {
    five_stop(&ACCENT_WAVE_STOPS, t)
}
/// Green gradient for healthy/success bars (same ramp as RX).
pub fn ok_wave(t: f64) -> Color {
    five_stop(&RX_WAVE_STOPS, t)
}
/// Amber gradient for caution bars.
pub fn warn_wave(t: f64) -> Color {
    five_stop(&WARN_WAVE_STOPS, t)
}
/// Red gradient for critical bars.
pub fn err_wave(t: f64) -> Color {
    five_stop(&ERR_WAVE_STOPS, t)
}
/// Fuchsia gradient for special/distinct bars (DNS).
pub fn special_wave(t: f64) -> Color {
    five_stop(&SPECIAL_WAVE_STOPS, t)
}
/// Gray gradient for secondary/inactive bars.
pub fn muted_wave(t: f64) -> Color {
    five_stop(&MUTED_WAVE_STOPS, t)
}

// --- Protocol aliases ---
pub fn proto_https() -> Color {
    ok()
}
pub fn proto_quic() -> Color {
    accent()
}
pub fn proto_http() -> Color {
    warn()
}
pub fn proto_dns() -> Color {
    special()
}
pub fn proto_ssh() -> Color {
    info()
}
pub fn proto_other() -> Color {
    muted()
}

// --- TCP state aliases ---
// Muted preset: ESTABLISHED is the common case and reads as plain text;
// only transitional states (a genuine signal) keep an attention color.
pub fn tcp_established() -> Color {
    if is_classic() { ok() } else { Color::Reset }
}
pub fn tcp_opening() -> Color {
    warn()
}
pub fn tcp_closing() -> Color {
    if is_classic() { accent() } else { muted() }
}
pub fn tcp_waiting() -> Color {
    if is_classic() { special() } else { muted() }
}
pub fn tcp_closed() -> Color {
    muted()
}

// --- Field-level aliases (same color used everywhere a field appears) ---
// Muted preset: addresses keep a calm color (they're the data being
// monitored), the other identifying fields render in the terminal's
// default foreground (`Color::Reset`), supporting context fades to
// gray. Same address colors in both presets.
pub fn field_local_addr() -> Color {
    accent()
}
pub fn field_remote_addr() -> Color {
    info()
}
pub fn field_state() -> Color {
    if is_classic() { ok() } else { Color::Reset }
}
pub fn field_service() -> Color {
    if is_classic() { warn() } else { muted() }
}
pub fn field_location() -> Color {
    if is_classic() { special() } else { muted() }
}
pub fn field_process() -> Color {
    if is_classic() { ok() } else { Color::Reset }
}
pub fn field_application() -> Color {
    if is_classic() { warn() } else { muted() }
}

// --- Historic (closed) connection rows ---
// Whole-row override; per-cell colors are dropped so the uniform gray
// carries the signal. DarkGray reads as muted-but-present on both
// light and dark backgrounds. DIM is deliberately NOT used when colors
// are available: terminals disagree wildly on it (invisible on light
// themes, barely-there in WezTerm dark). Under NO_COLOR it returns as
// the only row-level cue, alongside the "closed" state text.
pub fn historic_row() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default().fg(Color::DarkGray)
    }
}

// --- Panel border ---
pub fn border() -> Color {
    if is_classic() {
        special()
    } else {
        Color::DarkGray
    }
}

// --- Status bar styles ---
// Uses REVERSED modifier instead of fg(Black).bg(Color) which breaks on dark terminals
pub fn status_bar_confirm() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    Style::default()
        .fg(warn())
        .add_modifier(Modifier::BOLD | Modifier::REVERSED)
}
pub fn status_bar_success() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    Style::default()
        .fg(ok())
        .add_modifier(Modifier::BOLD | Modifier::REVERSED)
}
pub fn status_bar_default() -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) || !is_classic() {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    Style::default().fg(info()).add_modifier(Modifier::REVERSED)
}

pub fn row_highlight() -> Style {
    // No fg override: the highlight inherits the row's existing fg, so
    // when REVERSED swaps fg ↔ bg, a red staleness row gets a red
    // selection bar, a yellow row gets a yellow bar, and a default row
    // gets a default-fg bar. The staleness signal survives the
    // selection highlight.
    Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED)
}

// --- Style builders (NO_COLOR-aware) ---

/// Apply a foreground color, respecting NO_COLOR.
pub fn fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default()
    } else {
        Style::default().fg(color)
    }
}

/// Apply a foreground color with BOLD, respecting NO_COLOR.
pub fn bold_fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(color).add_modifier(Modifier::BOLD)
    }
}

/// Apply a foreground color with BOLD + UNDERLINED, respecting NO_COLOR.
pub fn bold_underline_fg(color: Color) -> Style {
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
        Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }
}
