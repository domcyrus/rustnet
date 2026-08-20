//! Filter input line shown above the status bar while the user is typing
//! a filter. A single borderless row: accent " / " prompt, the query with
//! its cursor, and a muted right-side hint.
//!
//! It is an editing surface, not a status readout: once a query is
//! confirmed the row is gone, and the Connections title chip plus the tab
//! bar's activity dot carry the filter state instead.

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
    let mut query = ui_state.filter_query.clone();
    if ui_state.filter_cursor_position <= query.len() {
        query.insert(ui_state.filter_cursor_position, '|');
    }
    let hint = "↑↓ navigate · Enter confirm · Esc cancel ";

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
