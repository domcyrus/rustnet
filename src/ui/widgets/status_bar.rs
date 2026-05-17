//! Bottom status line: shows tab-specific keybinds by default, or
//! transient confirmation prompts ("press q again to quit"),
//! filtered-count messages, and clipboard feedback when relevant.

use ratatui::{Frame, layout::Rect, widgets::Paragraph};

use crate::ui::{UIState, theme};

/// Status bar text per tab. Only Overview exposes connection-list shortcuts
/// (/, a, t, c); other tabs show just what actually works there.
fn default_status_line(selected_tab: usize) -> &'static str {
    match selected_tab {
        // Overview
        0 => {
            " 'h' help | Tab/Shift+Tab switch tabs | '/' filter | 'a' group | 't' history | 'c' copy"
        }
        // Details
        1 => " 'h' help | Tab/Shift+Tab switch tabs | 'c' copy remote addr | Esc back to Overview",
        // Interfaces / Graph / Help
        _ => " 'h' help | Tab/Shift+Tab switch tabs | Esc back to Overview",
    }
}

pub(in crate::ui) fn draw_status_bar(
    f: &mut Frame,
    ui_state: &UIState,
    connection_count: usize,
    area: Rect,
) {
    let status = if ui_state.quit_confirmation {
        " Press 'q' again to quit or any other key to cancel ".to_string()
    } else if ui_state.clear_confirmation {
        " Press 'x' again to clear all connections or any other key to cancel ".to_string()
    } else if let Some((ref msg, ref time)) = ui_state.clipboard_message {
        // Show clipboard message for 3 seconds
        if time.elapsed().as_secs() < 3 {
            format!(" {} ", msg)
        } else {
            default_status_line(ui_state.selected_tab).to_string()
        }
    } else if !ui_state.filter_query.is_empty() {
        format!(
            " 'h' help | Tab/Shift+Tab switch tabs | Showing {} filtered connections (Esc to clear) ",
            connection_count
        )
    } else {
        default_status_line(ui_state.selected_tab).to_string()
    };

    let style = if ui_state.quit_confirmation || ui_state.clear_confirmation {
        theme::status_bar_confirm()
    } else if ui_state.clipboard_message.is_some()
        && ui_state
            .clipboard_message
            .as_ref()
            .unwrap()
            .1
            .elapsed()
            .as_secs()
            < 3
    {
        theme::status_bar_success()
    } else {
        theme::status_bar_default()
    };

    let status_bar = Paragraph::new(status)
        .style(style)
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(status_bar, area);
}
