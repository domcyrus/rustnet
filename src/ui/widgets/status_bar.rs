//! Bottom status line: shows tab-specific keycap hints by default, or
//! transient confirmation prompts ("press q again to quit"),
//! filtered-count messages, clipboard feedback, and capture failures
//! (which claim a second row when they do not fit on one).
//!
//! Hints follow a keycap grammar: the key on a raised chip
//! (`theme::key_cap()`), its label in `theme::key_hint_label()`, two
//! spaces between hints. When the bar is too narrow, trailing hints are
//! dropped whole; nothing wraps mid-hint.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{UIState, theme};

/// One keycap hint: the key as typed and the action it triggers.
type Hint = (&'static str, &'static str);

/// Hints shared by every tab, always listed first.
const COMMON_HINTS: [Hint; 3] = [("h", "help"), ("1-5", "tabs"), ("tab", "cycle")];

/// Keycap hints per tab. Only Overview exposes connection-list shortcuts
/// (select, filter, group, history, copy); other tabs show just what
/// actually works there. Every tab ends on q quit.
fn tab_hints(ui_state: &UIState) -> Vec<Hint> {
    let mut hints = COMMON_HINTS.to_vec();
    match ui_state.selected_tab {
        // Overview
        0 => hints.extend([
            ("j/k", "select"),
            ("/", "filter"),
            ("a", "group"),
            ("t", "history"),
            ("i", "info"),
            ("c", "copy"),
        ]),
        // Details
        1 => {
            hints.push(("j/k", "prev/next"));
            // Ctrl+D/U only moves when the record outgrows its pane, so on a
            // tall terminal the hint would advertise a no-op.
            if ui_state.details_scroll.can_scroll() {
                hints.push(("ctrl-d/u", "scroll"));
            }
            hints.extend([("c", "copy remote addr"), ("esc", "back")]);
        }
        // Activity, interface list
        2 if ui_state.activity_show_interfaces => hints.extend([
            ("j/k", "scroll"),
            ("i", "process activity"),
            ("esc", "back"),
        ]),
        // Activity
        2 => hints.extend([
            ("d", "tx/rx"),
            ("s", "sort"),
            ("S", "order"),
            ("i", "interfaces"),
            ("esc", "back"),
        ]),
        // Help
        4 => hints.extend([("j/k", "scroll"), ("esc", "back")]),
        // Graph
        _ => hints.push(("esc", "back")),
    }
    hints.push(("q", "quit"));
    hints
}

/// Lay hints out as spans: leading space, then keycap + label pairs with
/// two-space gaps, then an optional trailing message. Anything that does
/// not fit `width` is dropped whole from the end.
fn hint_line(hints: &[Hint], trailing: Option<String>, width: u16) -> Line<'static> {
    let width = width as usize;
    let mut spans: Vec<Span<'static>> = vec![Span::raw(" ")];
    let mut used = 1usize;
    for (i, (key, label)) in hints.iter().enumerate() {
        let gap = if i == 0 { 0 } else { 2 };
        // Keycap chip (" key ") plus the single space before its label.
        let needed = gap + key.chars().count() + 3 + label.chars().count();
        if used + needed > width {
            return Line::from(spans);
        }
        if gap > 0 {
            spans.push(Span::raw("  "));
        }
        spans.push(Span::styled(format!(" {key} "), theme::key_cap()));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(*label, theme::key_hint_label()));
        used += needed;
    }
    if let Some(message) = trailing
        && used + 2 + message.chars().count() <= width
    {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(message, theme::key_hint_label()));
    }
    Line::from(spans)
}

/// Actionable half of a capture-failure line.
const CAPTURE_RECOVERY_HINT: &str = "Restart rustnet to resume. Press 'q' to quit.";

fn capture_error_one_line(cause: &str) -> String {
    format!(" {cause} {CAPTURE_RECOVERY_HINT} ")
}

/// Rows the status bar needs. Real libpcap errors are far longer than one
/// terminal row and the bar does not wrap, so a failure that does not fit gets
/// a second row instead of losing its recovery hint off the right edge.
pub(in crate::ui) fn status_bar_height(capture_error: Option<&str>, width: u16) -> u16 {
    match capture_error {
        Some(cause) if capture_error_one_line(cause).chars().count() > width as usize => 2,
        _ => 1,
    }
}

fn elide(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{}…", kept.trim_end())
}

/// Lay a capture failure out over the rows `status_bar_height` reserved: cause
/// first, recovery hint below it. When only one row is available the cause is
/// elided instead of the hint, which is the half the user can act on.
fn capture_error_text(cause: &str, width: u16, height: u16) -> String {
    let single = capture_error_one_line(cause);
    if single.chars().count() <= width as usize {
        return single;
    }
    if height >= 2 {
        return format!(
            "{}\n{}",
            elide(&format!(" {cause} "), width as usize),
            elide(&format!(" {CAPTURE_RECOVERY_HINT} "), width as usize),
        );
    }

    // " " + cause + "… " + hint + " "
    let room = (width as usize).saturating_sub(CAPTURE_RECOVERY_HINT.chars().count() + 4);
    if room < 16 {
        // Too narrow for both; show as much of the cause as fits.
        return single;
    }
    let cause: String = cause.chars().take(room).collect();
    format!(" {}… {CAPTURE_RECOVERY_HINT} ", cause.trim_end())
}

pub(in crate::ui) fn draw_status_bar(
    f: &mut Frame,
    ui_state: &UIState,
    connection_count: usize,
    capture_error: Option<&str>,
    area: Rect,
) {
    let clipboard_message = ui_state
        .clipboard_message
        .as_ref()
        .filter(|(_, time)| time.elapsed().as_secs() < 3)
        .map(|(message, _)| message);

    let status_bar = if ui_state.quit_confirmation {
        Paragraph::new(" Press 'q' again to quit or any other key to cancel ")
            .style(theme::status_bar_confirm())
    } else if ui_state.clear_confirmation {
        Paragraph::new(" Press 'x' again to clear all connections or any other key to cancel ")
            .style(theme::status_bar_confirm())
    } else if let Some(message) = clipboard_message {
        Paragraph::new(format!(" {message} ")).style(theme::status_bar_success())
    } else if let Some(error) = capture_error {
        Paragraph::new(capture_error_text(error, area.width, area.height))
            .style(theme::status_bar_error())
    } else if ui_state.has_active_filter() {
        let mut hints = COMMON_HINTS.to_vec();
        hints.push(("esc", "clear filter"));
        let message = format!("showing {connection_count} filtered connections");
        Paragraph::new(hint_line(&hints, Some(message), area.width))
            .style(theme::status_bar_default())
    } else {
        Paragraph::new(hint_line(&tab_hints(ui_state), None, area.width))
            .style(theme::status_bar_default())
    };

    f.render_widget(status_bar.alignment(ratatui::layout::Alignment::Left), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertises(hints: &[Hint], key: &str) -> bool {
        hints.iter().any(|(hint_key, _)| *hint_key == key)
    }

    fn rendered(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn details_advertises_pane_scrolling_only_once_the_pane_scrolls() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        assert!(!advertises(&tab_hints(&ui_state), "ctrl-d/u"));

        // A render that reports headroom turns the hint on.
        ui_state.details_scroll.clamp_for_render(12);
        assert!(advertises(&tab_hints(&ui_state), "ctrl-d/u"));
    }

    #[test]
    fn overview_and_details_advertise_the_same_navigation_keys() {
        let overview = tab_hints(&UIState::default());
        let details = tab_hints(&UIState {
            selected_tab: 1,
            ..Default::default()
        });
        assert!(advertises(&overview, "j/k"));
        assert!(advertises(&details, "j/k"));
    }

    #[test]
    fn keycaps_pad_the_key_and_keep_one_space_before_the_label() {
        let line = hint_line(&[("h", "help"), ("q", "quit")], None, 80);
        assert_eq!(rendered(&line), "  h  help   q  quit");
    }

    #[test]
    fn a_hint_that_does_not_fit_is_dropped_whole() {
        let line = hint_line(&[("h", "help"), ("q", "quit")], None, 10);
        assert_eq!(rendered(&line), "  h  help");
    }
}
