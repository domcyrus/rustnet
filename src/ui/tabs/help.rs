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

/// Key/description rows for the keybind list. The key half keeps its
/// trailing space so the description starts one cell after it.
const KEY_BINDINGS: &[(&str, &str)] = &[
    ("q ", "Quit application (press twice to confirm)"),
    ("Ctrl+C ", "Quit immediately"),
    ("x ", "Clear all connections (press twice to confirm)"),
    ("Tab, ] ", "Next tab"),
    ("Shift+Tab, [ ", "Previous tab"),
    (
        "1-5 ",
        "Jump directly to a tab (1=Overview, 2=Details, 3=Activity, 4=Graph, 5=Help)",
    ),
    ("↑/k, ↓/j ", "Navigate connections (wraps around)"),
    ("g, G ", "Jump to first/last connection (vim-style)"),
    ("Page Up/Down, Ctrl+B/F ", "Navigate connections by page"),
    ("Ctrl+D/U ", "Scroll the Details info panes"),
    ("c ", "Copy remote address to clipboard"),
    ("p ", "Toggle between service names and port numbers"),
    (
        "d ",
        "Toggle hostnames/IPs on Overview or Egress (TX)/Ingress (RX) on Activity",
    ),
    (
        "s ",
        "Cycle through sort columns (Bandwidth, Process, etc.)",
    ),
    ("S ", "Toggle sort direction (ascending/descending)"),
    ("a ", "Toggle process grouping (aggregate by process)"),
    ("Space ", "Expand/collapse group (when grouping enabled)"),
    ("←/→ or h/l ", "Collapse/expand group"),
    ("t ", "Toggle display of historic (closed) connections"),
    (
        "i ",
        "Toggle System info on Overview or interface details on Activity",
    ),
    ("r ", "Reset view (grouping, sort, filter)"),
    ("Enter ", "View connection details"),
    ("Esc ", "Return to overview"),
    ("h ", "Toggle this help screen"),
    (
        "/ ",
        "Enter filter mode on Overview (use \u{2191}/\u{2193} to navigate while typing)",
    ),
];

const TAB_SUMMARIES: &[(&str, &str)] = &[
    ("  Overview ", "Connection list with mini traffic graph"),
    ("  Details ", "Full details for selected connection"),
    (
        "  Activity ",
        "Process egress/ingress, bandwidth shares, connections, and interface pulse",
    ),
    ("  Graph ", "Traffic charts and protocol distribution"),
    ("  Help ", "This help screen"),
];

const ACTIVITY_CONCEPTS: &[(&str, &str)] = &[
    (
        "  Egress (TX) / Ingress (RX) ",
        "Traffic sent from or received by the local process",
    ),
    (
        "  60s coverage ",
        "Captured connection traffic divided by interface traffic",
    ),
    (
        "  Retained ",
        "Active traffic plus up to 5,000 recently closed connections",
    ),
    (
        "  Process attribution ",
        "Traffic mapped to a PID or process name; unresolved bytes are Unknown",
    ),
    (
        "  Top remote peer ",
        "Highest-volume remote endpoint for the selected direction",
    ),
];

const MOUSE_CONTROLS: &[(&str, &str)] = &[
    ("  Click tab ", "Switch between tabs"),
    ("  Click row ", "Select connection"),
    (
        "  Scroll wheel ",
        "Navigate connection list / scroll Details, Activity interfaces, Help",
    ),
    ("  Double-click row ", "Open connection details"),
    ("  Double-click group ", "Expand/collapse process group"),
    ("  Click field (Details) ", "Copy field value to clipboard"),
];

const FILTER_EXAMPLES: &[(&str, &str)] = &[
    ("  /google ", "Search for 'google' in all fields"),
    (
        "  /port:22 ",
        "Exact port match (only port 22, not 2223 or 5522)",
    ),
    ("  /port:/22/ ", "Regex port match (22, 220, 5522, etc.)"),
    ("  /src:192.168 ", "Filter by source IP prefix"),
    ("  /dst:github.com ", "Filter by destination"),
    (
        "  /sni:/.*github.*/ ",
        "Regex SNI match (wrap value in /…/ for regex)",
    ),
    ("  /process:firefox ", "Filter by process name"),
];

/// A key/description help row: the key span styled, the description raw.
fn kv_line(key: &'static str, description: &'static str, key_style: Style) -> Line<'static> {
    Line::from(vec![Span::styled(key, key_style), Span::raw(description)])
}

/// A bold accent section title ("Tabs:", "Mouse Controls:", ...).
fn section_title(title: &'static str) -> Line<'static> {
    Line::from(vec![Span::styled(title, theme::bold_fg(theme::accent()))])
}

pub(in crate::ui) fn draw_help(f: &mut Frame, ui_state: &UIState, area: Rect) -> Result<()> {
    let key_style = theme::fg(theme::key());
    let example_style = theme::fg(theme::ok());

    let mut help_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("RustNet Monitor ", theme::bold_fg(theme::ok())),
            Span::raw("- Network Connection Monitor"),
        ]),
        Line::from(""),
    ];
    help_text.extend(
        KEY_BINDINGS
            .iter()
            .map(|&(key, desc)| kv_line(key, desc, key_style)),
    );

    help_text.push(Line::from(""));
    help_text.push(section_title("Tabs:"));
    help_text.extend(
        TAB_SUMMARIES
            .iter()
            .map(|&(key, desc)| kv_line(key, desc, example_style)),
    );

    help_text.push(Line::from(""));
    help_text.push(section_title("Activity concepts:"));
    help_text.extend(
        ACTIVITY_CONCEPTS
            .iter()
            .map(|&(key, desc)| kv_line(key, desc, key_style)),
    );

    help_text.push(Line::from(""));
    help_text.push(section_title("Mouse Controls:"));
    help_text.extend(
        MOUSE_CONTROLS
            .iter()
            .map(|&(key, desc)| kv_line(key, desc, key_style)),
    );

    help_text.push(Line::from(""));
    help_text.push(section_title("Connection Colors:"));
    help_text.push(kv_line(
        "  White ",
        "Active connection (< 75% of timeout)",
        Style::default(),
    ));
    // The expiry gradient names three ramp stops, so it stays a literal.
    help_text.push(Line::from(vec![
        Span::styled("  Yellow", theme::fg(theme::expiry_glow(0.0))),
        Span::styled(" → ", theme::fg(theme::muted())),
        Span::styled("Orange", theme::fg(theme::expiry_glow(0.5))),
        Span::styled(" → ", theme::fg(theme::muted())),
        Span::styled("Red ", theme::fg(theme::expiry_glow(1.0))),
        Span::raw("Connection nearing timeout (75-100%; holds yellow to 90%, then intensifies)"),
    ]));
    help_text.push(kv_line(
        "  Gray ",
        "Historic (closed) connection",
        theme::historic_row(),
    ));

    help_text.push(Line::from(""));
    help_text.push(section_title("Hostname Display:"));
    help_text.push(Line::from(
        "  Names in the Remote column come from a recently observed DNS",
    ));
    help_text.push(Line::from(
        "  resolution (shown as ~name, dimmed) or reverse DNS; SNI and",
    ));
    help_text.push(Line::from("  HTTP Host appear in the App column."));
    help_text.push(Line::from(vec![
        Span::styled("  ~name ", theme::fg(theme::field_attributed_hostname())),
        Span::raw("Hostname inferred from a DNS response, not extracted"),
    ]));
    help_text.push(Line::from("  from the connection itself"));

    help_text.push(Line::from(""));
    help_text.push(section_title("Filter Examples:"));
    help_text.extend(
        FILTER_EXAMPLES
            .iter()
            .map(|&(key, desc)| kv_line(key, desc, example_style)),
    );
    help_text.push(Line::from(""));

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
