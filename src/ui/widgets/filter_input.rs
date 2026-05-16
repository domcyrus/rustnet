//! Filter input line shown above the status bar whenever the user
//! has either entered filter mode or has a persistent filter active.

use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Paragraph, Wrap},
};

use crate::ui::{UIState, panel_block, theme};

pub(in crate::ui) fn draw_filter_input(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let title = if ui_state.filter_mode {
        "Filter (↑↓/jk to navigate, Enter to confirm, Esc to cancel)"
    } else {
        "Active Filter (Press Esc to clear)"
    };

    let input_text = if ui_state.filter_mode {
        // Show cursor when in filter mode
        let mut display_query = ui_state.filter_query.clone();
        if ui_state.filter_cursor_position <= display_query.len() {
            display_query.insert(ui_state.filter_cursor_position, '|');
        }
        display_query
    } else {
        ui_state.filter_query.clone()
    };

    let style = if ui_state.filter_mode {
        theme::fg(theme::warn())
    } else {
        theme::fg(theme::ok())
    };

    let filter_input = Paragraph::new(input_text)
        .block(panel_block(title))
        .style(style)
        .wrap(Wrap { trim: false });

    f.render_widget(filter_input, area);
}
