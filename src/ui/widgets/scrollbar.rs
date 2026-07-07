//! Shared vertical scrollbar for panes whose content can overflow:
//! the Overview connection table, the Details info panes, the Help
//! text, and the Interfaces table.

use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::ui::theme;

/// Render a vertical scrollbar on the right edge of `area` when the
/// content overflows the viewport. `position` is the scroll offset of
/// the topmost visible row; `viewport` is the number of rows currently
/// visible. No-op when everything fits. Styled to match the section
/// rules (and NO_COLOR-aware via `theme::fg`).
pub(in crate::ui) fn draw_scrollbar(
    f: &mut Frame,
    area: Rect,
    total_rows: usize,
    position: usize,
    viewport: usize,
) {
    if total_rows <= viewport {
        return;
    }
    // ratatui sizes the thumb against `(content_length - 1) + viewport`, so the
    // thumb only reaches the track bottom when `position == content_length - 1`
    // (last row scrolled to the *top* of the viewport). Our `position` is a
    // scroll offset clamped to `total_rows - viewport` (last row at the *bottom*
    // of the viewport), so reporting `total_rows` as the content length leaves
    // the thumb short by `viewport - 1` rows. Reporting the number of distinct
    // scroll positions instead makes the thumb track the visible window
    // `[position, position + viewport)` over `[0, total_rows)` and sit flush at
    // the bottom when fully scrolled.
    let scroll_positions = total_rows - viewport + 1;
    let mut scrollbar_state = ScrollbarState::new(scroll_positions)
        .position(position)
        .viewport_content_length(viewport);
    // Thumb in the default foreground so it matches the table content;
    // only the track recedes into the chrome gray.
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_style(theme::fg(theme::border()))
        .thumb_style(Style::default());
    f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}

#[cfg(test)]
mod tests {
    /// Render `draw_scrollbar` into a test buffer and report whether
    /// any non-space glyph landed in the rightmost column (the scrollbar
    /// track/thumb sits on the right border).
    fn scrollbar_renders(total_rows: usize, position: usize, viewport: usize) -> bool {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        use ratatui::layout::Rect;

        let backend = TestBackend::new(20, 12);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|f| {
                super::draw_scrollbar(f, Rect::new(0, 0, 20, 12), total_rows, position, viewport)
            })
            .expect("draw scrollbar");
        let buffer = terminal.backend().buffer();
        let right_x = 19;
        (0..12).any(|y| buffer[(right_x, y)].symbol() != " ")
    }

    #[test]
    fn scrollbar_hidden_when_content_fits() {
        // 5 rows, 10-row viewport: nothing to scroll, no bar drawn.
        assert!(!scrollbar_renders(5, 0, 10));
        // Exactly fits is also a no-op.
        assert!(!scrollbar_renders(10, 0, 10));
    }

    #[test]
    fn scrollbar_shown_when_content_overflows() {
        // 100 rows, 10-row viewport: bar must render on the right edge.
        assert!(scrollbar_renders(100, 0, 10));
        // Still drawn when scrolled into the middle of the list.
        assert!(scrollbar_renders(100, 45, 10));
    }
}
