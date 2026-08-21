//! Contextual help overlay for the active tab.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Padding, Paragraph, Wrap},
};

use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, TAB_COUNT, UIState,
    fade_line, panel_block, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::scrollbar::draw_scrollbar, widgets::tabs_bar::TAB_TITLES,
};

// Compile-time tripwire: adding a tab must also add a `HelpContext`
// variant, `from_state` arm, and key tables, or the new tab would
// silently render another view's help.
const _: () = assert!(TAB_COUNT == 4, "update HelpContext for the new tab");

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
            3 => Self::Graph,
            // `selected_tab` is always < TAB_COUNT (jump_to_tab / next_tab
            // enforce it); the tripwire above keeps this match exhaustive.
            _ => Self::Overview,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::Overview => TAB_TITLES[0],
            Self::Details => TAB_TITLES[1],
            Self::Activity => TAB_TITLES[2],
            Self::Interfaces => "Activity · Interfaces",
            Self::Graph => TAB_TITLES[3],
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
            // Every key GLOBAL_KEYS advertises must stay live while the
            // overlay is open: quit, clear, and tab navigation fall through
            // to the global fallback in main.rs. Tab switches leave the
            // overlay up and it re-renders for the newly active view.
            (KeyCode::Char('q'), _)
            | (KeyCode::Char('c'), KeyModifiers::CONTROL)
            | (KeyCode::Char('x'), _)
            | (KeyCode::Tab, _)
            | (KeyCode::BackTab, _)
            | (KeyCode::Char('[' | ']'), KeyModifiers::NONE)
            | (KeyCode::Char('1'..='4'), KeyModifiers::NONE) => None,
            _ => {
                let page = ctx.ui_state.help_scroll.viewport_rows() as usize;
                try_handle_pane_scroll(key, page, &mut ctx.ui_state.help_scroll)
                    .or_else(|| Some(Vec::new()))
            }
        }
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        if let MouseEventKind::Down(_) = mouse.kind {
            // A click anywhere dismisses the overlay (the mouse equivalent
            // of Esc); claiming the event also keeps the click from
            // activating controls in the obscured view. Mirror the
            // click preamble in main.rs that this claim short-circuits:
            // a click cancels pending confirmations everywhere else too.
            ctx.ui_state.show_help = false;
            ctx.ui_state.help_scroll.reset();
            ctx.ui_state.quit_confirmation = false;
            ctx.ui_state.clear_confirmation = false;
            return Some(Vec::new());
        }
        // Wheel scrolling via the shared pane helper; Moved/Drag/Up stay
        // unclaimed so pointer motion does not force redraws.
        try_handle_pane_wheel(mouse, &mut ctx.ui_state.help_scroll)
    }
}

type HelpRow = (&'static str, &'static str);

// Only list keys here that the overlay's `handle_key` lets fall through
// to the global fallback in main.rs, so everything this section
// advertises works while the overlay is open.
const GLOBAL_KEYS: &[HelpRow] = &[
    ("Tab, ]", "Next tab"),
    ("Shift+Tab, [", "Previous tab"),
    ("1-4", "Jump to Overview, Details, Activity, or Graph"),
    ("x", "Clear all connections (press twice)"),
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
];

const FILTER_EXAMPLES: &[HelpRow] = &[
    ("/google", "Search all connection fields"),
    ("/port:22", "Match port 22 exactly"),
    ("/src:192.168", "Match a source address prefix"),
    ("/dst:github.com", "Match a destination"),
    ("/process:firefox", "Match a process name"),
    ("/state:established", "Match connection state"),
    ("/port:/22/", "Regex port match (22, 220, 5522, ...)"),
    (
        "/sni:/.*github.*/",
        "Regex SNI match; /.../ works on any field",
    ),
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

fn help_lines(context: HelpContext) -> Vec<Line<'static>> {
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

/// Popup width: near-full width on small terminals, capped for readability.
fn overlay_width(area: Rect) -> u16 {
    area.width.saturating_sub(4).max(1).min(area.width).min(92)
}

fn overlay_area(area: Rect, width: u16, content_rows: usize) -> Rect {
    if area.width == 0 || area.height == 0 {
        return area;
    }
    let available_height = area.height.saturating_sub(2).max(1).min(area.height);
    let content_rows = u16::try_from(content_rows).unwrap_or(u16::MAX);
    let height = available_height.min(content_rows.saturating_add(2).min(32));
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
    if area.width == 0 || area.height == 0 {
        return Ok(());
    }
    let context = HelpContext::from_state(ui_state);
    let mut lines = help_lines(context);
    let total_lines = lines.len();

    let width = overlay_width(area);
    // Room the text really gets: borders (2) + horizontal padding (2) +
    // the gutter (2) that keeps text clear of the scrollbar thumb.
    let text_width = width.saturating_sub(6);
    // Wrap-aware extent: on narrow popups lines wrap, so the popup height
    // and the scroll range must count rendered rows, not source lines,
    // or the tail of the help would be unreachable.
    let content_rows = if text_width == 0 {
        total_lines
    } else {
        Paragraph::new(lines.clone())
            .wrap(Wrap { trim: false })
            .line_count(text_width)
    };
    let popup = overlay_area(area, width, content_rows);
    if popup.width == 0 || popup.height == 0 {
        return Ok(());
    }

    let base_block =
        panel_block(format!(" Help · {} ", context.title())).padding(Padding::horizontal(1));
    let inner = base_block.inner(popup);
    let max_scroll = u16::try_from(content_rows)
        .unwrap_or(u16::MAX)
        .saturating_sub(inner.height);
    let scroll = ui_state.help_scroll.clamp_for_render(max_scroll);
    ui_state.help_scroll.record_viewport(inner.height);

    // The edge fade indexes into the source lines, which only lines up
    // with rendered rows while nothing wraps; skip the cosmetic fade
    // otherwise.
    if content_rows == total_lines {
        for index in fade_targets(scroll, inner.height, max_scroll)
            .into_iter()
            .flatten()
        {
            if let Some(line) = lines.get_mut(index) {
                fade_line(line);
            }
        }
    }

    f.render_widget(Clear, popup);
    f.render_widget(base_block, popup);
    let text_area = Rect {
        width: inner.width.saturating_sub(2),
        ..inner
    };
    let help = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
    f.render_widget(help, text_area);
    draw_scrollbar(
        f,
        inner,
        content_rows,
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
        help_lines(HelpContext::from_state(ui_state))
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
        let popup = overlay_area(parent, overlay_width(parent), 50);
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
        // Every key the overlay's Global section advertises must fall
        // through (None) so main.rs's global fallback can act on it.
        for key in [
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
            KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
            KeyEvent::new(KeyCode::Char('['), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char(']'), KeyModifiers::NONE),
            KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE),
        ] {
            assert!(
                HelpOverlay.handle_key(key, &mut ctx).is_none(),
                "{key:?} should fall through to the global fallback"
            );
        }
        assert!(ctx.ui_state.show_help);
    }

    #[test]
    fn click_dismisses_overlay_and_motion_stays_unclaimed() {
        use crossterm::event::MouseButton;

        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .expect("create app");
        let mut ui_state = UIState {
            show_help: true,
            quit_confirmation: true,
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

        let motion = MouseEvent {
            kind: MouseEventKind::Moved,
            column: 10,
            row: 10,
            modifiers: KeyModifiers::NONE,
        };
        // Pointer motion must stay unclaimed or every move forces a redraw.
        assert!(HelpOverlay.handle_mouse(motion, &mut ctx).is_none());
        assert!(ctx.ui_state.show_help);

        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            ..motion
        };
        assert!(HelpOverlay.handle_mouse(click, &mut ctx).is_some());
        assert!(!ctx.ui_state.show_help);
        assert!(!ctx.ui_state.quit_confirmation);
    }

    #[test]
    fn narrow_overlay_can_scroll_to_the_last_line() {
        use ratatui::{Terminal, backend::TestBackend};

        fn render_overlay(ui_state: &UIState) -> String {
            let backend = TestBackend::new(46, 20);
            let mut terminal = Terminal::new(backend).expect("create terminal");
            terminal
                .draw(|frame| {
                    draw_help_overlay(frame, ui_state, frame.area()).expect("draw help overlay")
                })
                .expect("draw frame");
            let buffer = terminal.backend().buffer().clone();
            let mut out = String::new();
            for y in 0..buffer.area.height {
                for x in 0..buffer.area.width {
                    out.push_str(buffer[(x, y)].symbol());
                }
                out.push('\n');
            }
            out
        }

        // At this width several help rows wrap onto two rendered rows, so
        // the scroll range must be computed from wrapped rows or the tail
        // of the Global section becomes unreachable.
        let mut ui_state = UIState {
            show_help: true,
            ..UIState::default()
        };
        let first = render_overlay(&ui_state);
        assert!(!first.contains("Quit immediately"));
        ui_state.help_scroll.scroll_to_bottom();
        let bottom = render_overlay(&ui_state);
        assert!(bottom.contains("Quit immediately"));
    }
}
