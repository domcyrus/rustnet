//! Help/legend tab: a scrollable document of keybinds, mouse
//! controls, colors, and filter examples, laid out as tick-marked
//! sections of aligned key/description columns. Scroll position lives
//! in `UIState::help_scroll`.

use anyhow::Result;
use crossterm::event::{KeyEvent, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Padding, Paragraph, Wrap},
};

use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, UIState, theme,
    try_handle_pane_scroll, widgets::scrollbar::draw_scrollbar,
};

/// Help tab. Zero-sized: the scroll offset it responds to lives in
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

/// Key/description rows for the keybind list. Keys carry no padding;
/// each section pads its key column to the widest key at render time.
const KEY_BINDINGS: &[(&str, &str)] = &[
    ("q", "Quit application (press twice to confirm)"),
    ("Ctrl+C", "Quit immediately"),
    ("x", "Clear all connections (press twice to confirm)"),
    ("Tab, ]", "Next tab"),
    ("Shift+Tab, [", "Previous tab"),
    (
        "1-5",
        "Jump directly to a tab (1=Overview, 2=Details, 3=Activity, 4=Graph, 5=Help)",
    ),
    ("↑/k, ↓/j", "Navigate connections (wraps around)"),
    ("g, G", "Jump to first/last connection (vim-style)"),
    ("Page Up/Down, Ctrl+B/F", "Navigate connections by page"),
    ("Ctrl+D/U", "Scroll the Details info panes"),
    ("c", "Copy remote address to clipboard"),
    ("p", "Toggle between service names and port numbers"),
    (
        "d",
        "Toggle hostnames/IPs on Overview or Egress (TX)/Ingress (RX) on Activity",
    ),
    ("s", "Cycle through sort columns (Bandwidth, Process, etc.)"),
    ("S", "Toggle sort direction (ascending/descending)"),
    ("a", "Toggle process grouping (aggregate by process)"),
    ("Space", "Expand/collapse group (when grouping enabled)"),
    ("←/→ or h/l", "Collapse/expand group"),
    ("t", "Toggle display of historic (closed) connections"),
    (
        "i",
        "Toggle System info on Overview or interface details on Activity",
    ),
    ("r", "Reset view (grouping, sort, filter)"),
    ("Enter", "View connection details"),
    ("Esc", "Return to overview"),
    ("h", "Toggle this help screen"),
    (
        "/",
        "Enter filter mode on Overview (use \u{2191}/\u{2193} to navigate while typing)",
    ),
];

const TAB_SUMMARIES: &[(&str, &str)] = &[
    ("Overview", "Connection list with mini traffic graph"),
    ("Details", "Full details for selected connection"),
    (
        "Activity",
        "Process egress/ingress, bandwidth shares, connections, and interface pulse",
    ),
    ("Graph", "Traffic charts and protocol distribution"),
    ("Help", "This help screen"),
];

const ACTIVITY_CONCEPTS: &[(&str, &str)] = &[
    (
        "Egress (TX) / Ingress (RX)",
        "Traffic sent from or received by the local process",
    ),
    (
        "60s coverage",
        "Captured connection traffic divided by interface traffic",
    ),
    (
        "Retained",
        "Active traffic plus up to 5,000 recently closed connections",
    ),
    (
        "Process attribution",
        "Traffic mapped to a PID or process name; unresolved bytes are Unknown",
    ),
    (
        "Top remote peer",
        "Highest-volume remote endpoint for the selected direction",
    ),
];

const MOUSE_CONTROLS: &[(&str, &str)] = &[
    ("Click tab", "Switch between tabs"),
    ("Click row", "Select connection"),
    (
        "Scroll wheel",
        "Navigate connection list / scroll Details, Activity interfaces, Help",
    ),
    ("Double-click row", "Open connection details"),
    ("Double-click group", "Expand/collapse process group"),
    ("Click field (Details)", "Copy field value to clipboard"),
];

const FILTER_EXAMPLES: &[(&str, &str)] = &[
    ("/google", "Search for 'google' in all fields"),
    (
        "/port:22",
        "Exact port match (only port 22, not 2223 or 5522)",
    ),
    ("/port:/22/", "Regex port match (22, 220, 5522, etc.)"),
    ("/src:192.168", "Filter by source IP prefix"),
    ("/dst:github.com", "Filter by destination"),
    (
        "/sni:/.*github.*/",
        "Regex SNI match (wrap value in /…/ for regex)",
    ),
    ("/process:firefox", "Filter by process name"),
];

/// Left indent for rows under a section tick line.
const ROW_INDENT: &str = "  ";
/// Gap between the padded key column and the description column.
const COLUMN_GAP: &str = "  ";

/// Widest key of a section in character cells (every glyph used in the
/// help keys is single width, so `chars().count()` is the cell width).
fn key_column_width(rows: &[(&str, &str)]) -> usize {
    rows.iter()
        .map(|(key, _)| key.chars().count())
        .max()
        .unwrap_or(0)
}

/// Section title line matching the `section_header` chrome used by the
/// other tabs: accent `▎` tick plus a bold title. Built as a paragraph
/// line instead of calling `section_header` because the whole Help page
/// scrolls as one paragraph, so the headers must scroll with it.
fn tick_line(title: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled("▎", theme::fg(theme::accent())),
        Span::styled(
            format!(" {title}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])
}

/// One aligned two-column row: the key padded to the section's key
/// column width in the given style, the description in the hint label
/// style.
fn column_row(
    key: &str,
    key_style: Style,
    description: &'static str,
    width: usize,
) -> Line<'static> {
    Line::from(vec![
        Span::raw(ROW_INDENT),
        Span::styled(format!("{key:<width$}"), key_style),
        Span::raw(COLUMN_GAP),
        Span::styled(description, theme::key_hint_label()),
    ])
}

/// A whole key/description section: blank separator, tick title, then
/// one aligned row per entry with the keys in the keycap style.
fn push_section(
    out: &mut Vec<Line<'static>>,
    title: &'static str,
    rows: &'static [(&'static str, &'static str)],
) {
    out.push(Line::from(""));
    out.push(tick_line(title));
    let width = key_column_width(rows);
    out.extend(
        rows.iter()
            .map(|&(key, desc)| column_row(key, theme::key_hint(), desc, width)),
    );
}

pub(in crate::ui) fn draw_help(f: &mut Frame, ui_state: &UIState, area: Rect) -> Result<()> {
    let mut help_text: Vec<Line> = vec![Line::from(vec![
        Span::styled("RustNet Monitor ", theme::bold_fg(theme::ok())),
        Span::raw("- Network Connection Monitor"),
    ])];

    push_section(&mut help_text, "Key Bindings", KEY_BINDINGS);
    push_section(&mut help_text, "Tabs", TAB_SUMMARIES);
    push_section(&mut help_text, "Activity Concepts", ACTIVITY_CONCEPTS);
    push_section(&mut help_text, "Mouse Controls", MOUSE_CONTROLS);

    // Connection colors: the keys are color swatches, so each keeps its
    // demo style instead of the keycap style, aligned to the same
    // two-column grid as every other section.
    help_text.push(Line::from(""));
    help_text.push(tick_line("Connection Colors"));
    let gradient_key = "Yellow → Orange → Red";
    let color_width = ["White", gradient_key, "Gray"]
        .iter()
        .map(|key| key.chars().count())
        .max()
        .unwrap_or(0);
    help_text.push(column_row(
        "White",
        Style::default(),
        "Active connection (< 75% of timeout)",
        color_width,
    ));
    // The expiry gradient names three ramp stops, so its key column is
    // assembled span by span and padded by hand.
    let gradient_pad = color_width.saturating_sub(gradient_key.chars().count());
    help_text.push(Line::from(vec![
        Span::raw(ROW_INDENT),
        Span::styled("Yellow", theme::fg(theme::expiry_glow(0.0))),
        Span::styled(" → ", theme::fg(theme::muted())),
        Span::styled("Orange", theme::fg(theme::expiry_glow(0.5))),
        Span::styled(" → ", theme::fg(theme::muted())),
        Span::styled("Red", theme::fg(theme::expiry_glow(1.0))),
        Span::raw(format!("{}{}", " ".repeat(gradient_pad), COLUMN_GAP)),
        Span::styled(
            "Connection nearing timeout (75-100%; holds yellow to 90%, then intensifies)",
            theme::key_hint_label(),
        ),
    ]));
    help_text.push(column_row(
        "Gray",
        theme::historic_row(),
        "Historic (closed) connection",
        color_width,
    ));

    help_text.push(Line::from(""));
    help_text.push(tick_line("Hostname Display"));
    help_text.push(Line::from(Span::styled(
        "  Names in the Remote column come from a recently observed DNS",
        theme::key_hint_label(),
    )));
    help_text.push(Line::from(Span::styled(
        "  resolution (shown as ~name, dimmed) or reverse DNS; SNI and",
        theme::key_hint_label(),
    )));
    help_text.push(Line::from(Span::styled(
        "  HTTP Host appear in the App column.",
        theme::key_hint_label(),
    )));
    help_text.push(column_row(
        "~name",
        theme::fg(theme::field_attributed_hostname()),
        "Hostname inferred from a DNS response, not extracted from the connection itself",
        "~name".chars().count(),
    ));

    push_section(&mut help_text, "Filter Examples", FILTER_EXAMPLES);
    help_text.push(Line::from(""));

    // Scroll against the unwrapped line count. A handful of lines can
    // wrap on very narrow terminals, making the true maximum slightly
    // larger, but staying off the unstable rendered-line-info APIs is
    // worth the last row or two of scroll range.
    let total_lines = help_text.len();
    let inner_height = area.height;
    let max_scroll = (total_lines as u16).saturating_sub(inner_height);
    let scroll = ui_state.help_scroll.clamp_for_render(max_scroll);

    // The old panel border carried the scroll hint in its title; with
    // the border gone it rides the intro line instead.
    if max_scroll > 0 {
        help_text[0]
            .spans
            .push(Span::styled(" · ↑/↓ scroll", theme::fg(theme::muted())));
    }

    // Right padding keeps the text clear of the two rightmost columns:
    // a blank gap and the scrollbar, same arrangement as the Overview
    // table. `trim: false` preserves the row indent and the padded key
    // columns that align the descriptions.
    let help = Paragraph::new(help_text)
        .block(Block::default().padding(Padding::right(2)))
        .style(Style::default())
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0))
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    draw_scrollbar(f, area, total_lines, scroll as usize, inner_height as usize);

    Ok(())
}
