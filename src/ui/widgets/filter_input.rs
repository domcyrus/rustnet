//! Filter input line shown above the status bar whenever the user
//! has either entered filter mode or has a persistent filter active.
//! A single borderless row: accent " / " prompt, the query, and a
//! muted right-side hint with the relevant keys.

use std::borrow::Cow;

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{UIState, theme};

/// Height of the filter line in rows.
pub(crate) const FILTER_INPUT_HEIGHT: u16 = 1;

pub(in crate::ui) fn draw_filter_input(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let query: Cow<str> = if ui_state.filter_mode {
        // Show cursor when in filter mode
        let mut display_query = ui_state.filter_query.clone();
        if ui_state.filter_cursor_position <= display_query.len() {
            display_query.insert(ui_state.filter_cursor_position, '|');
        }
        Cow::Owned(display_query)
    } else {
        Cow::Borrowed(&ui_state.filter_query)
    };

    let hint = if ui_state.filter_mode {
        "↑↓ navigate · Enter confirm · Esc cancel "
    } else {
        "filter active · Esc clears "
    };

    let line = Line::from(vec![
        Span::styled(" / ", theme::bold_fg(theme::accent())),
        Span::raw(query),
    ]);
    let hint_line = Line::from(Span::styled(hint, theme::fg(theme::muted()))).right_aligned();

    // Hint first, query second: when the terminal is too narrow for both,
    // the query (rendered later) wins the overlap.
    f.render_widget(Paragraph::new(hint_line), area);
    f.render_widget(Paragraph::new(line), area);
}
