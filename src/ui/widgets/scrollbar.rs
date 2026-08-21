//! Shared vertical scrollbar for panes whose content can overflow:
//! the Overview connection table, the Details info panes, the Help
//! overlay, and the Interfaces table.

use ratatui::{
    Frame,
    layout::Rect,
    widgets::{Scrollbar, ScrollbarOrientation, ScrollbarState},
};

use crate::ui::theme;

/// Scrollbar thumb: a right half block, so the bar reads as a thin rule on
/// the outer edge of its column instead of a full-width slab.
const THUMB: &str = "\u{2590}";

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
    // A half-block thumb in the accent color, riding an unpainted track.
    // The thumb alone carries both position and proportion, so the track
    // rule only adds a second vertical line beside the pane chrome that
    // already has one. The half block hugs the outer edge of its column,
    // keeping the bar clear of the right-aligned data beside it.
    //
    // The thumb fg must be set explicitly, not left empty: ratatui styles
    // are patches, and an empty patch lets the thumb inherit whatever color
    // the underlying cells already have (on the Help overlay the scrollbar
    // rides the panel border, which is gray, and the thumb would vanish
    // into it). Under NO_COLOR the glyph keeps it legible on its own.
    let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
        .begin_symbol(None)
        .end_symbol(None)
        .track_symbol(None)
        .thumb_symbol(THUMB)
        .thumb_style(theme::fg(theme::accent()));
    f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
}

#[cfg(test)]
mod tests {
    /// Glyphs `draw_scrollbar` paints down the rightmost column (the
    /// scrollbar track/thumb sits on the right border).
    fn scrollbar_glyphs(total_rows: usize, position: usize, viewport: usize) -> Vec<String> {
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
        (0..12)
            .map(|y| buffer[(right_x, y)].symbol().to_string())
            .collect()
    }

    /// Whether the scrollbar painted anything at all.
    fn scrollbar_renders(total_rows: usize, position: usize, viewport: usize) -> bool {
        scrollbar_glyphs(total_rows, position, viewport)
            .iter()
            .any(|glyph| glyph != " ")
    }

    #[test]
    fn thumb_is_a_thin_bar_rather_than_a_full_block() {
        let glyphs = scrollbar_glyphs(100, 0, 10);
        assert!(
            glyphs.iter().any(|glyph| glyph == super::THUMB),
            "no thumb painted: {glyphs:?}"
        );
        assert!(
            !glyphs
                .iter()
                .any(|glyph| glyph == ratatui::symbols::block::FULL),
            "thumb still renders as a full block: {glyphs:?}"
        );
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
