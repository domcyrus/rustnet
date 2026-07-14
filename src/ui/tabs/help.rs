//! Help/legend tab — a scrollable paragraph of keybinds, mouse
//! controls, colors, and filter examples. Scroll position lives in
//! `UIState::help_scroll`.

use anyhow::Result;
use crossterm::event::{KeyEvent, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Padding, Paragraph, Wrap},
};

use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, UIState, panel_block,
    theme, try_handle_pane_scroll, widgets::scrollbar::draw_scrollbar,
};

/// Help tab. Zero-sized — the scroll offset it responds to lives in
/// `UIState`, not here.
pub(in crate::ui) struct HelpTab;

impl Component for HelpTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_help(f, ctx.ui_state, area)
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        try_handle_pane_scroll(
            key,
            ctx.ui_state.visible_rows,
            &mut ctx.ui_state.help_scroll,
        )
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        // Three lines per wheel tick: the Help text is a long static
        // page, so the single-line step shared by the data panes feels
        // sluggish here.
        const WHEEL_STEP: u16 = 3;
        let scroll = &mut ctx.ui_state.help_scroll;
        match mouse.kind {
            MouseEventKind::ScrollUp => scroll.scroll_up(WHEEL_STEP),
            MouseEventKind::ScrollDown => scroll.scroll_down(WHEEL_STEP),
            _ => return None,
        }
        Some(Vec::new())
    }
}

pub(in crate::ui) fn draw_help(f: &mut Frame, ui_state: &UIState, area: Rect) -> Result<()> {
    let help_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("RustNet Monitor ", theme::bold_fg(theme::ok())),
            Span::raw("- Network Connection Monitor"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("q ", theme::fg(theme::key())),
            Span::raw("Quit application (press twice to confirm)"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+C ", theme::fg(theme::key())),
            Span::raw("Quit immediately"),
        ]),
        Line::from(vec![
            Span::styled("x ", theme::fg(theme::key())),
            Span::raw("Clear all connections (press twice to confirm)"),
        ]),
        Line::from(vec![
            Span::styled("Tab, ] ", theme::fg(theme::key())),
            Span::raw("Next tab"),
        ]),
        Line::from(vec![
            Span::styled("Shift+Tab, [ ", theme::fg(theme::key())),
            Span::raw("Previous tab"),
        ]),
        Line::from(vec![
            Span::styled("1-5 ", theme::fg(theme::key())),
            Span::raw(
                "Jump directly to a tab (1=Overview, 2=Details, 3=Activity, 4=Graph, 5=Help)",
            ),
        ]),
        Line::from(vec![
            Span::styled("↑/k, ↓/j ", theme::fg(theme::key())),
            Span::raw("Navigate connections (wraps around)"),
        ]),
        Line::from(vec![
            Span::styled("g, G ", theme::fg(theme::key())),
            Span::raw("Jump to first/last connection (vim-style)"),
        ]),
        Line::from(vec![
            Span::styled("Page Up/Down, Ctrl+B/F ", theme::fg(theme::key())),
            Span::raw("Navigate connections by page"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+D/U ", theme::fg(theme::key())),
            Span::raw("Scroll the Details info panes"),
        ]),
        Line::from(vec![
            Span::styled("c ", theme::fg(theme::key())),
            Span::raw("Copy remote address to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("p ", theme::fg(theme::key())),
            Span::raw("Toggle between service names and port numbers"),
        ]),
        Line::from(vec![
            Span::styled("d ", theme::fg(theme::key())),
            Span::raw("Toggle hostnames/IPs on Overview or Egress (TX)/Ingress (RX) on Activity"),
        ]),
        Line::from(vec![
            Span::styled("s ", theme::fg(theme::key())),
            Span::raw("Cycle through sort columns (Bandwidth, Process, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("S ", theme::fg(theme::key())),
            Span::raw("Toggle sort direction (ascending/descending)"),
        ]),
        Line::from(vec![
            Span::styled("a ", theme::fg(theme::key())),
            Span::raw("Toggle process grouping (aggregate by process)"),
        ]),
        Line::from(vec![
            Span::styled("Space ", theme::fg(theme::key())),
            Span::raw("Expand/collapse group (when grouping enabled)"),
        ]),
        Line::from(vec![
            Span::styled("←/→ or h/l ", theme::fg(theme::key())),
            Span::raw("Collapse/expand group"),
        ]),
        Line::from(vec![
            Span::styled("t ", theme::fg(theme::key())),
            Span::raw("Toggle display of historic (closed) connections"),
        ]),
        Line::from(vec![
            Span::styled("i ", theme::fg(theme::key())),
            Span::raw("Toggle System info on Overview or interface details on Activity"),
        ]),
        Line::from(vec![
            Span::styled("r ", theme::fg(theme::key())),
            Span::raw("Reset view (grouping, sort, filter)"),
        ]),
        Line::from(vec![
            Span::styled("Enter ", theme::fg(theme::key())),
            Span::raw("View connection details"),
        ]),
        Line::from(vec![
            Span::styled("Esc ", theme::fg(theme::key())),
            Span::raw("Return to overview"),
        ]),
        Line::from(vec![
            Span::styled("h ", theme::fg(theme::key())),
            Span::raw("Toggle this help screen"),
        ]),
        Line::from(vec![
            Span::styled("/ ", theme::fg(theme::key())),
            Span::raw(
                "Enter filter mode on Overview (use \u{2191}/\u{2193} to navigate while typing)",
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Tabs:", theme::bold_fg(theme::accent()))]),
        Line::from(vec![
            Span::styled("  Overview ", theme::fg(theme::ok())),
            Span::raw("Connection list with mini traffic graph"),
        ]),
        Line::from(vec![
            Span::styled("  Details ", theme::fg(theme::ok())),
            Span::raw("Full details for selected connection"),
        ]),
        Line::from(vec![
            Span::styled("  Activity ", theme::fg(theme::ok())),
            Span::raw("Process egress/ingress, bandwidth shares, connections, and interface pulse"),
        ]),
        Line::from(vec![
            Span::styled("  Graph ", theme::fg(theme::ok())),
            Span::raw("Traffic charts and protocol distribution"),
        ]),
        Line::from(vec![
            Span::styled("  Help ", theme::fg(theme::ok())),
            Span::raw("This help screen"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Activity concepts:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  Egress (TX) / Ingress (RX) ", theme::fg(theme::key())),
            Span::raw("Traffic sent from or received by the local process"),
        ]),
        Line::from(vec![
            Span::styled("  60s coverage ", theme::fg(theme::key())),
            Span::raw("Captured connection traffic divided by interface traffic"),
        ]),
        Line::from(vec![
            Span::styled("  Retained ", theme::fg(theme::key())),
            Span::raw("Active traffic plus up to 5,000 recently closed connections"),
        ]),
        Line::from(vec![
            Span::styled("  Process attribution ", theme::fg(theme::key())),
            Span::raw("Traffic mapped to a PID or process name; unresolved bytes are Unknown"),
        ]),
        Line::from(vec![
            Span::styled("  Top remote peer ", theme::fg(theme::key())),
            Span::raw("Highest-volume remote endpoint for the selected direction"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Mouse Controls:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  Click tab ", theme::fg(theme::key())),
            Span::raw("Switch between tabs"),
        ]),
        Line::from(vec![
            Span::styled("  Click row ", theme::fg(theme::key())),
            Span::raw("Select connection"),
        ]),
        Line::from(vec![
            Span::styled("  Scroll wheel ", theme::fg(theme::key())),
            Span::raw("Navigate connection list / scroll Details, Activity interfaces, Help"),
        ]),
        Line::from(vec![
            Span::styled("  Double-click row ", theme::fg(theme::key())),
            Span::raw("Open connection details"),
        ]),
        Line::from(vec![
            Span::styled("  Double-click group ", theme::fg(theme::key())),
            Span::raw("Expand/collapse process group"),
        ]),
        Line::from(vec![
            Span::styled("  Click field (Details) ", theme::fg(theme::key())),
            Span::raw("Copy field value to clipboard"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Connection Colors:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  White ", Style::default()),
            Span::raw("Active connection (< 75% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Yellow ", theme::fg(theme::key())),
            Span::raw("Stale connection (75-90% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Red ", theme::fg(theme::err())),
            Span::raw("Critical - will be removed soon (> 90% of timeout)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Filter Examples:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  /google ", theme::fg(theme::ok())),
            Span::raw("Search for 'google' in all fields"),
        ]),
        Line::from(vec![
            Span::styled("  /port:22 ", theme::fg(theme::ok())),
            Span::raw("Exact port match (only port 22, not 2223 or 5522)"),
        ]),
        Line::from(vec![
            Span::styled("  /port:/22/ ", theme::fg(theme::ok())),
            Span::raw("Regex port match (22, 220, 5522, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("  /src:192.168 ", theme::fg(theme::ok())),
            Span::raw("Filter by source IP prefix"),
        ]),
        Line::from(vec![
            Span::styled("  /dst:github.com ", theme::fg(theme::ok())),
            Span::raw("Filter by destination"),
        ]),
        Line::from(vec![
            Span::styled("  /sni:/.*github.*/ ", theme::fg(theme::ok())),
            Span::raw("Regex SNI match (wrap value in /…/ for regex)"),
        ]),
        Line::from(vec![
            Span::styled("  /process:firefox ", theme::fg(theme::ok())),
            Span::raw("Filter by process name"),
        ]),
        Line::from(""),
    ];

    // Scroll against the unwrapped line count. A handful of lines can
    // wrap on very narrow terminals, making the true maximum slightly
    // larger, but staying off the unstable rendered-line-info APIs is
    // worth the last row or two of scroll range.
    let total_lines = help_text.len();
    let inner_height = area.height.saturating_sub(2); // panel borders
    let max_scroll = (total_lines as u16).saturating_sub(inner_height);
    let scroll = ui_state.help_scroll.clamp_for_render(max_scroll);

    let title = if max_scroll > 0 {
        "Help · ↑/↓ scroll"
    } else {
        "Help"
    };
    // Right padding keeps the text clear of the two rightmost inner
    // columns: a blank gap and the scrollbar, same arrangement as the
    // Overview table.
    let help = Paragraph::new(help_text)
        .block(panel_block(title).padding(Padding::right(2)))
        .style(Style::default())
        .wrap(Wrap { trim: true })
        .scroll((scroll, 0))
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    // Scrollbar one column inside the panel border so the border line
    // stays intact, inset one row top and bottom to clear the title
    // row and rounded corners.
    let track = Rect::new(
        area.x,
        area.y + 1,
        area.width.saturating_sub(1),
        area.height.saturating_sub(2),
    );
    draw_scrollbar(
        f,
        track,
        total_lines,
        scroll as usize,
        inner_height as usize,
    );

    Ok(())
}
