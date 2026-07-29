//! Bottom status line: shows tab-specific keybinds by default, or
//! transient confirmation prompts ("press q again to quit"),
//! filtered-count messages, clipboard feedback, and capture failures
//! (which claim a second row when they do not fit on one).

use ratatui::{Frame, layout::Rect, widgets::Paragraph};

use crate::ui::{UIState, theme};

/// Status bar text per tab. Only Overview exposes connection-list shortcuts
/// (/, a, t, c); other tabs show just what actually works there.
fn default_status_line(ui_state: &UIState) -> &'static str {
    match ui_state.selected_tab {
        // Overview
        0 => {
            " 'h' help | 1-5 jump | Tab/[/] cycle | '/' filter | 'a' group | 't' history | 'i' info | 'c' copy"
        }
        // Details
        1 => {
            " 'h' help | 1-5 jump | Tab/[/] cycle | j/k prev/next | Ctrl-d/u scroll | 'c' copy remote addr | Esc back"
        }
        // Activity
        2 if ui_state.activity_show_interfaces => {
            " 'h' help | 1-5 jump | Tab/[/] cycle | j/k scroll | 'i' process activity | Esc back"
        }
        2 => {
            " 'h' help | 1-5 jump | Tab/[/] cycle | 'd' TX/RX | 's' sort | 'S' order | 'i' interfaces | Esc back"
        }
        // Help
        4 => " 'h' help | 1-5 jump | Tab/[/] cycle | j/k scroll | Esc back to Overview",
        // Graph
        _ => " 'h' help | 1-5 jump | Tab/[/] cycle | Esc back to Overview",
    }
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

    let status = if ui_state.quit_confirmation {
        " Press 'q' again to quit or any other key to cancel ".to_string()
    } else if ui_state.clear_confirmation {
        " Press 'x' again to clear all connections or any other key to cancel ".to_string()
    } else if let Some(message) = clipboard_message {
        format!(" {message} ")
    } else if let Some(error) = capture_error {
        capture_error_text(error, area.width, area.height)
    } else if ui_state.has_active_filter() {
        format!(
            " 'h' help | 1-5 jump | Tab/[/] cycle | Showing {} filtered connections (Esc to clear) ",
            connection_count
        )
    } else {
        default_status_line(ui_state).to_string()
    };

    let style = if ui_state.quit_confirmation || ui_state.clear_confirmation {
        theme::status_bar_confirm()
    } else if clipboard_message.is_some() {
        theme::status_bar_success()
    } else if capture_error.is_some() {
        theme::status_bar_error()
    } else {
        theme::status_bar_default()
    };

    let status_bar = Paragraph::new(status)
        .style(style)
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(status_bar, area);
}
