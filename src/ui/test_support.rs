//! UI rendering, text extraction, and handler-context fixtures.

use ratatui::{
    Frame, Terminal,
    backend::TestBackend,
    buffer::Buffer,
    text::{Line, Span},
};

use crate::app::App;
use crate::ui::{ClickableRegions, HandlerContext, UiState};

/// Render a closure into a `width × height` test buffer and return the
/// buffer for cell-level inspection.
pub(crate) fn render_buffer<F>(width: u16, height: u16, draw: F) -> Buffer
where
    F: FnOnce(&mut Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal.draw(draw).expect("draw frame");
    terminal.backend().buffer().clone()
}

/// Render a closure into a `width × height` test buffer and return a
/// plain-text dump (one line per row, no trailing whitespace trim).
pub(crate) fn render<F>(width: u16, height: u16, draw: F) -> String
where
    F: FnOnce(&mut Frame),
{
    buffer_to_string(&render_buffer(width, height, draw))
}

/// Plain-text dump of a buffer: cell symbols only, one line per row.
pub(crate) fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::with_capacity((area.width as usize + 1) * area.height as usize);
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// The concatenated text of a span run, styles dropped.
pub(crate) fn spans_text(spans: &[Span<'_>]) -> String {
    spans.iter().map(|span| span.content.as_ref()).collect()
}

/// The concatenated text of a line, styles dropped.
pub(crate) fn line_text(line: &Line<'_>) -> String {
    spans_text(&line.spans)
}

/// A handler context over an empty, ungrouped connection list.
pub(crate) fn empty_ctx<'a>(
    app: &'a App,
    ui_state: &'a mut UiState,
    click_regions: &'a ClickableRegions,
) -> HandlerContext<'a> {
    HandlerContext {
        app,
        ui_state,
        connections: &[],
        grouped_rows: None,
        click_regions,
    }
}
