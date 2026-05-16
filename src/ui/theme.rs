//! Centralized color palette for cross-terminal consistency.
//! All semantic colors derive from these 7 base constants.

use ratatui::style::{Color, Modifier, Style};

// --- 7-slot base palette ---
const OK: Color = Color::Green; // Healthy/success
const WARN: Color = Color::Yellow; // Caution/attention
const ERR: Color = Color::Red; // Error/critical
const ACCENT: Color = Color::Cyan; // Informational highlight
const MUTED: Color = Color::Gray; // Secondary/inactive
const INFO: Color = Color::Blue; // Neutral info
const SPECIAL: Color = Color::Magenta; // Distinct/special

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
    warn()
}
pub fn key() -> Color {
    warn()
}

// --- Network aliases ---
pub fn rx() -> Color {
    ok()
}
pub fn tx() -> Color {
    info()
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
pub fn tcp_established() -> Color {
    ok()
}
pub fn tcp_opening() -> Color {
    warn()
}
pub fn tcp_closing() -> Color {
    accent()
}
pub fn tcp_waiting() -> Color {
    special()
}
pub fn tcp_closed() -> Color {
    muted()
}

// --- Field-level aliases (same color used everywhere a field appears) ---
pub fn field_local_addr() -> Color {
    accent()
}
pub fn field_remote_addr() -> Color {
    info()
}
pub fn field_state() -> Color {
    ok()
}
pub fn field_service() -> Color {
    warn()
}
pub fn field_location() -> Color {
    special()
}
pub fn field_process() -> Color {
    ok()
}
pub fn field_application() -> Color {
    warn()
}

// --- Panel border ---
pub fn border() -> Color {
    special()
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
    if super::NO_COLOR.load(super::Ordering::Relaxed) {
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
