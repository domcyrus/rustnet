//! Contextual help overlay for the active tab.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Clear, Padding, Paragraph, Wrap},
};

use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, UIState, fade_line,
    panel_block, theme, try_handle_pane_scroll, widgets::scrollbar::draw_scrollbar,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelpContext {
    Overview,
    Details,
    Activity,
    Interfaces,
    Graph,
}

impl HelpContext {
    fn from_state(ui_state: &UIState) -> Self {
        match ui_state.selected_tab {
            0 => Self::Overview,
            1 => Self::Details,
            2 if ui_state.activity_show_interfaces => Self::Interfaces,
            2 => Self::Activity,
            _ => Self::Graph,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Details => "Details",
            Self::Activity => "Activity",
            Self::Interfaces => "Activity · Interfaces",
            Self::Graph => "Graph",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Self::Overview => "Inspect, filter, group, and sort captured connections.",
            Self::Details => "Inspect the currently selected connection.",
            Self::Activity => "Compare retained traffic by process.",
            Self::Interfaces => "Inspect traffic and counters for each interface.",
            Self::Graph => "Review live traffic, protocol, and connection charts.",
        }
    }
}

/// Help overlay. Its state lives in `UIState` so opening it does not replace
/// the active tab or lose the user's position in that tab.
pub(in crate::ui) struct HelpOverlay;

impl Component for HelpOverlay {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_help_overlay(f, ctx.ui_state, area)
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('h'), _) | (KeyCode::Esc, _) => {
                ctx.ui_state.show_help = false;
                ctx.ui_state.help_scroll.reset();
                Some(Vec::new())
            }
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => None,
            _ => try_handle_pane_scroll(
                key,
                ctx.ui_state.visible_rows,
                &mut ctx.ui_state.help_scroll,
            )
            .or_else(|| Some(Vec::new())),
        }
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        const WHEEL_STEP: u16 = 3;
        match mouse.kind {
            MouseEventKind::ScrollUp => ctx.ui_state.help_scroll.scroll_up(WHEEL_STEP),
            MouseEventKind::ScrollDown => ctx.ui_state.help_scroll.scroll_down(WHEEL_STEP),
            _ => {}
        }
        // The overlay is modal. Claim all mouse input so controls in the
        // obscured view cannot be activated accidentally.
        Some(Vec::new())
    }
}

type HelpRow = (&'static str, &'static str);

const GLOBAL_KEYS: &[HelpRow] = &[
    ("Tab, ]", "Next tab"),
    ("Shift+Tab, [", "Previous tab"),
    ("1-4", "Jump to Overview, Details, Activity, or Graph"),
    ("h, Esc", "Close this help overlay"),
    ("q", "Quit application (press twice to confirm)"),
    ("Ctrl+C", "Quit immediately"),
];

const CONNECTION_NAV_KEYS: &[HelpRow] = &[
    ("↑/k, ↓/j", "Select previous or next connection"),
    ("g, G", "Jump to first or last connection"),
    ("Page Up/Down", "Move by one page"),
    ("Ctrl+B/F", "Move by one page"),
];

const OVERVIEW_KEYS: &[HelpRow] = &[
    ("Enter", "Open the selected connection in Details"),
    ("/", "Enter filter mode"),
    ("Esc", "Clear the active filter"),
    ("c", "Copy the selected remote address"),
    ("p", "Toggle service names and port numbers"),
    ("d", "Toggle hostnames and IP addresses"),
    ("s, S", "Change sort column or direction"),
    ("a", "Toggle process grouping"),
    ("Space", "Expand or collapse the selected group"),
    ("←/→, l", "Collapse or expand the selected group"),
    ("t", "Toggle historic connections"),
    ("i", "Toggle the System info panel"),
    ("r", "Reset grouping, sorting, filter, and history"),
    ("x", "Clear all connections (press twice)"),
];

const FILTER_EXAMPLES: &[HelpRow] = &[
    ("/google", "Search all connection fields"),
    ("/port:22", "Match port 22 exactly"),
    ("/src:192.168", "Match a source address prefix"),
    ("/dst:github.com", "Match a destination"),
    ("/process:firefox", "Match a process name"),
    ("/state:established", "Match connection state"),
    ("/sni:/.*github.*/", "Use a regular expression for SNI"),
];

const OVERVIEW_MOUSE: &[HelpRow] = &[
    ("Click row", "Select a connection"),
    ("Double-click row", "Open connection details"),
    ("Double-click group", "Expand or collapse a process group"),
    ("Scroll wheel", "Navigate the connection list"),
];

const OVERVIEW_DISPLAY: &[HelpRow] = &[
    ("White", "Active connection"),
    ("Yellow to red", "Connection approaching its timeout"),
    ("Gray", "Historic closed connection"),
    ("~name", "Hostname inferred from an observed DNS response"),
    ("App column", "Application protocol, SNI, or HTTP Host"),
];

const DETAILS_KEYS: &[HelpRow] = &[
    ("↑/k, ↓/j", "Show the previous or next connection"),
    ("g, G", "Show the first or last connection"),
    ("Page Up/Down", "Move through connections by one page"),
    ("Ctrl+B/F", "Move through connections by one page"),
    ("Ctrl+D/U", "Scroll the connection information panes"),
    ("c", "Copy the remote address"),
    ("Esc", "Return to Overview"),
];

const DETAILS_MOUSE: &[HelpRow] = &[
    ("Click field", "Copy that field's value"),
    (
        "Click connection",
        "Select a connection in the continuity strip",
    ),
    ("Scroll wheel", "Scroll the connection information panes"),
];

const ACTIVITY_KEYS: &[HelpRow] = &[
    ("d", "Toggle Egress (TX) and Ingress (RX)"),
    ("s", "Cycle the process sort column"),
    ("S", "Reverse the sort direction"),
    ("i", "Open interface details"),
    ("Esc", "Return to Overview"),
];

const ACTIVITY_CONCEPTS: &[HelpRow] = &[
    (
        "60s coverage",
        "Captured connection traffic divided by interface traffic",
    ),
    (
        "Retained",
        "Active traffic plus recently closed connections",
    ),
    (
        "Unknown",
        "Traffic that could not be attributed to a process",
    ),
    (
        "Top remote peer",
        "Highest-volume peer for the selected direction",
    ),
];

const INTERFACE_KEYS: &[HelpRow] = &[
    ("↑/k, ↓/j", "Scroll one line"),
    ("Page Up/Down", "Scroll one page"),
    ("g, G", "Jump to the top or bottom"),
    ("i", "Return to process activity"),
    ("Esc", "Return to Overview"),
    ("Scroll wheel", "Scroll interface details"),
];

const GRAPH_KEYS: &[HelpRow] = &[
    ("Esc", "Return to Overview"),
    (
        "Live view",
        "Charts update automatically; no graph controls are required",
    ),
];

const ROW_INDENT: &str = "  ";
const COLUMN_GAP: &str = "  ";

fn key_column_width(rows: &[HelpRow]) -> usize {
    rows.iter()
        .map(|(key, _)| key.chars().count())
        .max()
        .unwrap_or(0)
}

fn tick_line(title: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled("▎", theme::fg(theme::accent())),
        Span::styled(
            format!(" {title}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ])
}

fn column_row(key: &str, description: &'static str, width: usize) -> Line<'static> {
    Line::from(vec![
        Span::raw(ROW_INDENT),
        Span::styled(format!("{key:<width$}"), theme::key_hint()),
        Span::raw(COLUMN_GAP),
        Span::styled(description, theme::key_hint_label()),
    ])
}

fn push_section(out: &mut Vec<Line<'static>>, title: &'static str, rows: &'static [HelpRow]) {
    out.push(Line::from(""));
    out.push(tick_line(title));
    let width = key_column_width(rows);
    out.extend(
        rows.iter()
            .map(|&(key, description)| column_row(key, description, width)),
    );
}

fn help_lines(ui_state: &UIState) -> Vec<Line<'static>> {
    let context = HelpContext::from_state(ui_state);
    let mut lines = vec![Line::from(Span::styled(
        context.summary(),
        theme::key_hint_label(),
    ))];

    match context {
        HelpContext::Overview => {
            push_section(&mut lines, "Connection Navigation", CONNECTION_NAV_KEYS);
            push_section(&mut lines, "Overview Actions", OVERVIEW_KEYS);
            push_section(&mut lines, "Connection Display", OVERVIEW_DISPLAY);
            push_section(&mut lines, "Filter Examples", FILTER_EXAMPLES);
            push_section(&mut lines, "Mouse", OVERVIEW_MOUSE);
        }
        HelpContext::Details => {
            push_section(&mut lines, "Details Actions", DETAILS_KEYS);
            push_section(&mut lines, "Mouse", DETAILS_MOUSE);
        }
        HelpContext::Activity => {
            push_section(&mut lines, "Activity Actions", ACTIVITY_KEYS);
            push_section(&mut lines, "Activity Concepts", ACTIVITY_CONCEPTS);
        }
        HelpContext::Interfaces => {
            push_section(&mut lines, "Interface Actions", INTERFACE_KEYS);
        }
        HelpContext::Graph => {
            push_section(&mut lines, "Graph", GRAPH_KEYS);
        }
    }
    push_section(&mut lines, "Global", GLOBAL_KEYS);
    lines.push(Line::from(""));
    lines
}

fn overlay_area(area: Rect, content_lines: usize) -> Rect {
    if area.width == 0 || area.height == 0 {
        return area;
    }
    let available_width = area.width.saturating_sub(4).max(1).min(area.width);
    let available_height = area.height.saturating_sub(2).max(1).min(area.height);
    let width = available_width.min(92);
    let height = available_height.min((content_lines as u16).saturating_add(2).min(32));
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

fn fade_targets(scroll: u16, height: u16, max_scroll: u16) -> [Option<usize>; 2] {
    let top = (scroll > 0).then_some(scroll as usize);
    let bottom = (scroll < max_scroll && height > 0).then(|| scroll as usize + height as usize - 1);
    [top, bottom]
}

pub(in crate::ui) fn draw_help_overlay(
    f: &mut Frame,
    ui_state: &UIState,
    area: Rect,
) -> Result<()> {
    let mut lines = help_lines(ui_state);
    let total_lines = lines.len();
    let popup = overlay_area(area, total_lines);
    if popup.width == 0 || popup.height == 0 {
        return Ok(());
    }

    let context = HelpContext::from_state(ui_state);
    let base_block =
        panel_block(format!(" Help · {} ", context.title())).padding(Padding::horizontal(1));
    let inner = base_block.inner(popup);
    let max_scroll = (total_lines as u16).saturating_sub(inner.height);
    let scroll = ui_state.help_scroll.clamp_for_render(max_scroll);

    for index in fade_targets(scroll, inner.height, max_scroll)
        .into_iter()
        .flatten()
    {
        if let Some(line) = lines.get_mut(index) {
            fade_line(line);
        }
    }

    f.render_widget(Clear, popup);
    f.render_widget(base_block, popup);
    let help = Paragraph::new(lines)
        .block(Block::default().padding(Padding::right(2)))
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(help, inner);
    draw_scrollbar(
        f,
        inner,
        total_lines,
        scroll as usize,
        inner.height as usize,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, Config};

    fn plain_text(ui_state: &UIState) -> String {
        help_lines(ui_state)
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn overview_help_contains_filtering() {
        let text = plain_text(&UIState::default());
        assert!(text.contains("Filter Examples"));
        assert!(text.contains("/port:22"));
    }

    #[test]
    fn details_help_excludes_overview_actions() {
        let state = UIState {
            selected_tab: 1,
            ..UIState::default()
        };
        let text = plain_text(&state);
        assert!(text.contains("Details Actions"));
        assert!(!text.contains("Filter Examples"));
        assert!(!text.contains("Connection Display"));
        assert!(!text.contains("process grouping"));
    }

    #[test]
    fn activity_subviews_have_distinct_help() {
        let activity = UIState {
            selected_tab: 2,
            ..UIState::default()
        };
        assert!(plain_text(&activity).contains("Activity Concepts"));

        let interfaces = UIState {
            selected_tab: 2,
            activity_show_interfaces: true,
            ..UIState::default()
        };
        let text = plain_text(&interfaces);
        assert!(text.contains("Interface Actions"));
        assert!(!text.contains("Activity Concepts"));
    }

    #[test]
    fn overlay_stays_inside_small_areas() {
        let parent = Rect::new(3, 4, 8, 3);
        let popup = overlay_area(parent, 50);
        assert!(popup.x >= parent.x && popup.y >= parent.y);
        assert!(popup.right() <= parent.right());
        assert!(popup.bottom() <= parent.bottom());
    }

    #[test]
    fn overlay_renders_on_a_minimal_terminal() {
        use ratatui::{Terminal, backend::TestBackend};

        let backend = TestBackend::new(8, 3);
        let mut terminal = Terminal::new(backend).expect("create terminal");
        let ui_state = UIState {
            show_help: true,
            ..UIState::default()
        };
        terminal
            .draw(|frame| {
                draw_help_overlay(frame, &ui_state, frame.area()).expect("draw help overlay")
            })
            .expect("draw frame");
    }

    #[test]
    fn scrolling_fades_hidden_edges() {
        assert_eq!(fade_targets(0, 10, 5), [None, Some(9)]);
        assert_eq!(fade_targets(3, 10, 5), [Some(3), Some(12)]);
        assert_eq!(fade_targets(5, 10, 5), [Some(5), None]);
    }

    #[test]
    fn closing_help_preserves_the_underlying_view() {
        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .expect("create app");
        let mut ui_state = UIState {
            selected_tab: 1,
            show_help: true,
            filter_query: "port:443".to_string(),
            ..UIState::default()
        };
        let click_regions = ClickableRegions::default();
        let mut ctx = HandlerContext {
            app: &app,
            ui_state: &mut ui_state,
            connections: &[],
            grouped_rows: None,
            click_regions: &click_regions,
        };

        let effects =
            HelpOverlay.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), &mut ctx);

        assert!(matches!(effects, Some(effects) if effects.is_empty()));
        assert!(!ctx.ui_state.show_help);
        assert_eq!(ctx.ui_state.selected_tab, 1);
        assert_eq!(ctx.ui_state.filter_query, "port:443");
    }

    #[test]
    fn overlay_consumes_view_actions_but_keeps_quit_global() {
        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .expect("create app");
        let mut ui_state = UIState {
            show_help: true,
            ..UIState::default()
        };
        let click_regions = ClickableRegions::default();
        let mut ctx = HandlerContext {
            app: &app,
            ui_state: &mut ui_state,
            connections: &[],
            grouped_rows: None,
            click_regions: &click_regions,
        };

        assert!(
            HelpOverlay
                .handle_key(
                    KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE),
                    &mut ctx,
                )
                .is_some()
        );
        assert!(!ctx.ui_state.filter_mode);
        assert!(
            HelpOverlay
                .handle_key(
                    KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
                    &mut ctx,
                )
                .is_none()
        );
        assert!(ctx.ui_state.show_help);
    }
}
