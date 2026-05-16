//! Static help/legend tab — a paragraph of keybinds, mouse
//! controls, colors, and filter examples. No state, no inputs.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crate::ui::{panel_block, theme};

pub(in crate::ui) fn draw_help(f: &mut Frame, area: Rect) -> Result<()> {
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
            Span::styled("Tab ", theme::fg(theme::key())),
            Span::raw("Switch between tabs"),
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
            Span::styled("c ", theme::fg(theme::key())),
            Span::raw("Copy remote address to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("p ", theme::fg(theme::key())),
            Span::raw("Toggle between service names and port numbers"),
        ]),
        Line::from(vec![
            Span::styled("d ", theme::fg(theme::key())),
            Span::raw("Toggle between hostnames and IP addresses (when --resolve-dns)"),
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
            Span::styled("i ", theme::fg(theme::key())),
            Span::raw("Toggle interface statistics view"),
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
            Span::styled("  Interfaces ", theme::fg(theme::ok())),
            Span::raw("Network interface statistics"),
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
            Span::raw("Navigate connection list"),
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

    let help = Paragraph::new(help_text)
        .block(panel_block("Help"))
        .style(Style::default())
        .wrap(Wrap { trim: true })
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    Ok(())
}
