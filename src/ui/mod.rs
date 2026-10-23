//! Terminal user interface built on `ratatui` + `crossterm`: tabbed
//! layout (overview, details, process activity, graphs, host data), sortable tables
//! with adjustable columns, sparkline/chart bandwidth widgets, and
//! keyboard-driven filter and navigation.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::Color,
    symbols,
    text::Line,
    widgets::{Block, Borders},
};

use crate::app::{App, AppStats};
use crate::network::types::{Connection, ProtocolState, TcpState};

mod terminal;
pub use terminal::{Terminal, restore_terminal, setup_terminal};

mod widgets;
use widgets::{
    filter_input::draw_filter_input,
    loading::draw_loading_screen,
    status_bar::draw_status_bar,
    tabs_bar::{CaptureCluster, draw_tabs},
};

mod tabs;
use tabs::{
    activity::ActivityTab, details::DetailsTab, graph::GraphTab, help::HelpOverlay, host::HostTab,
    overview::OverviewTab,
};

/// Route a key event to the active tab's Component. Returns
/// `Some(effects)` if the tab claimed the key, `None` otherwise so
/// the caller can fall through to its own (global / fallback)
/// handling.
///
/// Filter mode is Overview-owned (it owns the query state and the
/// filter input widget), so when `filter_mode` is on the dispatch
/// routes to `OverviewTab` regardless of the visible tab. This
/// keeps filter typing working when the user has switched to
/// Details / Activity / Graph / Host while a filter is being
/// edited.
pub fn dispatch_key(
    tab: usize,
    key: crossterm::event::KeyEvent,
    ctx: &mut HandlerContext<'_>,
) -> Option<Vec<Effect>> {
    if ctx.ui_state.show_help {
        return HelpOverlay.handle_key(key, ctx);
    }
    if ctx.ui_state.filter_mode {
        return OverviewTab.handle_key(key, ctx);
    }
    if let Some(effects) = sections::handle_key(key, ctx.ui_state) {
        return Some(effects);
    }
    match tab {
        0 => OverviewTab.handle_key(key, ctx),
        1 => DetailsTab.handle_key(key, ctx),
        2 => ActivityTab.handle_key(key, ctx),
        3 => GraphTab.handle_key(key, ctx),
        4 => HostTab.handle_key(key, ctx),
        _ => None,
    }
}

/// Same as `dispatch_key` but for mouse events (currently the
/// scroll wheel; clicks go through the global `ClickableRegions`
/// hit-test in main.rs).
pub fn dispatch_mouse(
    tab: usize,
    mouse: crossterm::event::MouseEvent,
    ctx: &mut HandlerContext<'_>,
) -> Option<Vec<Effect>> {
    if ctx.ui_state.show_help {
        return HelpOverlay.handle_mouse(mouse, ctx);
    }
    match tab {
        0 => OverviewTab.handle_mouse(mouse, ctx),
        1 => DetailsTab.handle_mouse(mouse, ctx),
        2 => ActivityTab.handle_mouse(mouse, ctx),
        3 => GraphTab.handle_mouse(mouse, ctx),
        4 => HostTab.handle_mouse(mouse, ctx),
        _ => None,
    }
}

/// Placeholder string displayed when a value is unavailable.
const NONE_PLACEHOLDER: &str = "-";

/// Global flag for NO_COLOR support (<https://no-color.org>)
static NO_COLOR: AtomicBool = AtomicBool::new(false);

static POPUP_SHADOW: AtomicBool = AtomicBool::new(false);

/// Enable the optional static Help shadow. NO_COLOR always suppresses it.
pub fn set_popup_shadow(enabled: bool) {
    POPUP_SHADOW.store(enabled, Ordering::Relaxed);
}

/// Enable NO_COLOR mode (strips all colors from the UI)
pub fn set_no_color(enabled: bool) {
    NO_COLOR.store(enabled, Ordering::Relaxed);
}

mod state;
pub(crate) use crate::network::process_activity::process_group_label;
pub use state::{
    ActivityDirection, ActivitySection, ActivitySort, ActivityView, ClickAction, ClickableRegions,
    DetailsSection, DnsSort, GraphSection, GroupedRow, HostView, OverviewSection, PaneScroll,
    SortColumn, UiState, compute_grouped_rows, compute_scroll_offset,
};
pub(crate) use widgets::tabs_bar::TAB_COUNT;

mod connection_table;

mod sorting;
pub use sorting::sort_connections;

mod clipboard;
pub use clipboard::{clipboard_available, copy_to_clipboard};

mod sections;

mod actions;
pub use actions::clear_all_with_confirmation;
pub(crate) use actions::{
    try_handle_connection_nav, try_handle_pane_scroll, try_handle_pane_wheel,
};

mod component;
pub use component::{
    Component, DrawContext as ComponentContext, Effect, HandlerContext, SelectionMove,
};

mod effects;
pub use effects::apply_effects;

mod theme;
pub use theme::{
    Theme, ThemePreset, ThemeSpec, TokenColor, detect_light_background, detect_truecolor, set_theme,
};

/// Standard panel chrome: rounded border + title. Used by the few
/// views that frame themselves (Help overlay, loading splash);
/// everything else uses [`section_header`].
pub(crate) fn panel_block<'a, T: Into<Line<'a>>>(title: T) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_set(symbols::border::ROUNDED)
        .border_style(theme::fg(theme::border()))
        .title(title)
}

/// Borderless section chrome: renders an accent `▎` tick plus the given
/// title on the top row of `area` and returns the remaining rows.
/// Sections are borderless by design; the ▎ glyph still marks the
/// section start under NO_COLOR.
/// Callers style their own title spans (bold base + muted metadata).
pub(crate) fn section_header<'a, T: Into<Line<'a>>>(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    title: T,
) -> ratatui::layout::Rect {
    use ratatui::layout::Rect;
    use ratatui::text::Span;
    use ratatui::widgets::Paragraph;

    if area.height == 0 {
        return area;
    }
    let mut line: Line = title.into();
    // Callers may supply a leading space; normalize it once for every section.
    for span in &mut line.spans {
        let content = span.content.trim_start();
        let empty = content.is_empty();
        span.content = content.to_string().into();
        if !empty {
            break;
        }
    }
    let budget = usize::from(area.width.saturating_sub(2));
    if line.width() > budget {
        let mut used = 0;
        line.spans.retain_mut(|span| {
            if used >= budget {
                return false;
            }
            let room = budget - used;
            if span.width() >= room {
                span.content =
                    format::truncate_with_ellipsis(&format!("{}…", span.content), room).into();
                used = budget;
            } else {
                used += span.width();
            }
            true
        });
    }
    line.spans
        .insert(0, Span::styled("▎ ", theme::fg(theme::accent())));
    // A quiet rule links each title to its panel without boxing in the data.
    let remaining = usize::from(area.width).saturating_sub(line.width() + 1);
    if remaining > 0 {
        line.spans.push(Span::styled(
            format!(" {}", "─".repeat(remaining)),
            theme::fg(theme::faint()),
        ));
    }
    f.render_widget(
        Paragraph::new(line),
        Rect::new(area.x, area.y, area.width, 1),
    );
    section_body(area)
}

fn section_body(area: ratatui::layout::Rect) -> ratatui::layout::Rect {
    ratatui::layout::Rect::new(
        area.x,
        area.y + area.height.min(1),
        area.width,
        area.height.saturating_sub(1),
    )
}

/// Theme-aware bold heading span for [`section_header`].
pub(crate) fn section_title(text: impl Into<String>) -> ratatui::text::Span<'static> {
    ratatui::text::Span::styled(text.into(), theme::bold_fg(theme::heading()))
}

/// Muted empty-state text filling a section that has nothing to show yet.
pub(crate) fn draw_placeholder(f: &mut Frame, area: ratatui::layout::Rect, text: &str) {
    f.render_widget(
        ratatui::widgets::Paragraph::new(text).style(theme::fg(theme::muted())),
        area,
    );
}

/// Fade one line toward the faint tier: the scroll-boundary cue shared
/// by every scrolling pane. Spans carry their own styles, so the fade is
/// applied span by span, with the line style following for the cells a
/// short line leaves empty. A no-op under NO_COLOR, where
/// [`theme::edge_fade`] returns the style untouched.
pub(crate) fn fade_line(line: &mut Line<'_>) {
    line.style = theme::edge_fade(line.style);
    for span in &mut line.spans {
        span.style = theme::edge_fade(span.style);
    }
}

/// Dim the boundary rows of a scrolled pane: the first visible row when
/// content continues above it, the last when content continues below.
/// Nothing is inserted or removed, so the panes' fixed row positions and
/// the click-to-copy registry stay in step with the rendered lines.
pub(crate) fn fade_scroll_edges(lines: &mut [Line<'_>], scroll: u16, height: u16) {
    if height == 0 {
        return;
    }
    let (top, height) = (scroll as usize, height as usize);
    let bottom = top + height - 1;
    if top > 0 {
        fade_at(lines, top);
    }
    if bottom + 1 < lines.len() {
        fade_at(lines, bottom);
    }
}

/// Apply the shared edge fade to the line at `index`, if it exists.
fn fade_at(lines: &mut [Line<'_>], index: usize) {
    if let Some(line) = lines.get_mut(index) {
        fade_line(line);
    }
}

/// Foreground style for a counter that is fine at zero and alarming
/// otherwise: `ok` while nothing is wrong, `alert` once `alerting`.
pub(crate) fn alert_style(alerting: bool, alert: Color) -> ratatui::style::Style {
    theme::fg(if alerting { alert } else { theme::ok() })
}

/// Resolve the cell color for a connection's State column.
/// Maps TCP states to the existing `tcp_*` aliases; falls back to
/// `field_state()` for non-TCP protocols.
pub(crate) fn state_color(conn: &Connection) -> Color {
    match &conn.protocol_state {
        ProtocolState::Tcp(state) => match state {
            TcpState::Established => theme::tcp_established(),
            TcpState::SynSent | TcpState::SynReceived => theme::tcp_opening(),
            TcpState::FinWait1 | TcpState::FinWait2 | TcpState::Closing => theme::tcp_closing(),
            TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait => theme::tcp_waiting(),
            TcpState::Closed | TcpState::Unknown => theme::tcp_closed(),
        },
        _ => theme::field_state(),
    }
}

/// Resolve the cell color for a DPI Application protocol.
/// Vivid preset mirrors the palette used in `draw_app_distribution`;
/// the muted preset renders detected applications as plain content so
/// the `proto_*` palette stays a chart-only encoding.
pub(crate) fn dpi_color(app: &crate::network::types::ApplicationProtocol) -> Color {
    use crate::network::types::ApplicationProtocol as AP;
    if !theme::is_vivid() {
        return Color::Reset;
    }
    match app {
        AP::Https(_) => theme::proto_https(),
        AP::Quic(_) => theme::proto_quic(),
        AP::Http(_) => theme::proto_http(),
        AP::Dns(_) | AP::Mdns(_) | AP::Llmnr(_) => theme::proto_dns(),
        AP::Ssh(_) => theme::proto_ssh(),
        _ => theme::field_application(),
    }
}

/// Color for the Details Application heading of the non-DPI protocol classes
/// (ARP, ICMP, IGMP), which have no `ApplicationProtocol` value to feed
/// [`dpi_color`]. Mirrors its theme fallback: the vivid preset colors the
/// heading like any other detected application, the muted preset renders it
/// as plain content.
pub(crate) fn non_dpi_app_color() -> Color {
    if theme::is_vivid() {
        theme::field_application()
    } else {
        Color::Reset
    }
}

pub fn draw(
    f: &mut Frame,
    app: &App,
    ui_state: &mut UiState,
    connections: &[Connection],
    grouped_rows: Option<&[GroupedRow]>,
    stats: &AppStats,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    click_regions.clear();
    ui_state.graph_animation_visible.set(false);
    ui_state
        .bar_animations
        .begin_frame(std::time::Instant::now());

    // If still loading, show loading screen. The splash clock starts on
    // the first frame and is quantized to whole animation frames, so
    // draws within one frame are byte-identical (cheap for the
    // terminal) and the first frame is deterministic for tests.
    if app.is_loading() {
        use std::sync::OnceLock;
        use widgets::loading::FRAME_MS;
        static SPLASH_START: OnceLock<std::time::Instant> = OnceLock::new();
        let elapsed = SPLASH_START.get_or_init(std::time::Instant::now).elapsed();
        let frame =
            std::time::Duration::from_millis(elapsed.as_millis() as u64 / FRAME_MS * FRAME_MS);
        ui_state.bar_animations.finish_frame();
        draw_loading_screen(f, frame);
        return Ok(());
    }

    use widgets::filter_input::FILTER_INPUT_HEIGHT;
    use widgets::status_bar::status_bar_height;
    use widgets::tabs_bar::TABS_BAR_HEIGHT;

    // A capture failure can need a second row, so the status bar is measured
    // before the layout is split.
    let capture_error = app.capture_error();
    let status_height = status_bar_height(capture_error.as_deref(), f.area().width);

    let chunks = if ui_state.filter_row_visible() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(TABS_BAR_HEIGHT),     // Tabs
                Constraint::Min(0),                      // Content
                Constraint::Length(FILTER_INPUT_HEIGHT), // Filter input area
                Constraint::Length(status_height),       // Status bar
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(TABS_BAR_HEIGHT), // Tabs
                Constraint::Min(0),                  // Content
                Constraint::Length(status_height),   // Status bar
            ])
            .split(f.area())
    };

    // Capture cluster: same sources the status bar and the Overview
    // sidebar read. `get_link_layer_info` reports "Unknown" until the
    // capture thread has a linktype, which is not worth a suffix.
    let capture_interface = app.get_current_interface();
    let (link_type, _is_tunnel) = app.get_link_layer_info();
    let capture = CaptureCluster {
        interface: capture_interface.as_deref(),
        link_type: Some(link_type.as_str()).filter(|link| *link != "Unknown"),
        failed: capture_error.is_some(),
    };

    draw_tabs(f, ui_state, &capture, chunks[0], click_regions);

    if ui_state.selected_tab == 1 {
        // Repair selection before measuring optional identity cards.
        ui_state.prepare_connection_viewport(
            tabs::overview::visible_connection_rows(chunks[1]),
            connections,
            grouped_rows,
        );
        let conn = ui_state
            .get_selected_index(connections)
            .and_then(|index| connections.get(index));
        let sectioned = tabs::details::sectioned_layout(chunks[1], conn);
        if ui_state.details_compact.replace(sectioned) != sectioned {
            ui_state.details_page.set(0);
            ui_state.details_page_count.set(1);
        }
    }
    ui_state.section_navigation = match ui_state.selected_tab {
        0 => tabs::overview::compact_layout(chunks[1]),
        1 => ui_state.details_compact.get(),
        2 => tabs::activity::compact_layout(chunks[1]),
        3 => tabs::graph::compact_layout(chunks[1]),
        4 => true,
        _ => false,
    };
    let content_area = sections::draw_selector(f, chunks[1], ui_state, click_regions);
    let (filter_area, status_area) = if ui_state.filter_row_visible() {
        (Some(chunks[2]), chunks[3])
    } else {
        (None, chunks[2])
    };

    // Use this frame's actual content bounds, including an expanded error
    // banner, before repairing selection and building the virtual row window.
    ui_state.prepare_connection_viewport(
        tabs::overview::visible_connection_rows(content_area),
        connections,
        grouped_rows,
    );

    let comp_ctx = ComponentContext {
        app,
        connections,
        ui_state,
        grouped_rows,
        stats,
    };
    match ui_state.selected_tab {
        0 => OverviewTab.draw(f, content_area, &comp_ctx, click_regions)?,
        1 => DetailsTab.draw(f, content_area, &comp_ctx, click_regions)?,
        2 => ActivityTab.draw(f, content_area, &comp_ctx, click_regions)?,
        3 => GraphTab.draw(f, content_area, &comp_ctx, click_regions)?,
        4 => HostTab.draw(f, content_area, &comp_ctx, click_regions)?,
        _ => {}
    }

    ui_state.bar_animations.finish_frame();

    if let Some(filter_area) = filter_area {
        draw_filter_input(f, ui_state, filter_area);
    }

    if ui_state.show_help {
        tabs::help::draw_help_overlay(f, ui_state, content_area)?;
    }

    draw_status_bar(
        f,
        ui_state,
        clipboard_available(app),
        capture_error.as_deref(),
        status_area,
    );

    Ok(())
}

mod format;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_toggle_default_state() {
        let ui_state = UiState::default();
        assert!(
            !ui_state.show_port_numbers,
            "Port numbers should be hidden by default"
        );
    }

    #[test]
    fn test_sort_column_cycle_without_location() {
        use SortColumn::*;

        // Test the complete cycle without GeoIP (follows left-to-right visual order)
        assert_eq!(CreatedAt.next(false), Process);
        assert_eq!(Process.next(false), RemoteAddress);
        assert_eq!(RemoteAddress.next(false), LocalAddress);
        assert_eq!(LocalAddress.next(false), Service); // Skips Location
        assert_eq!(Service.next(false), Application);
        assert_eq!(Application.next(false), State);
        assert_eq!(State.next(false), Rtt);
        assert_eq!(Rtt.next(false), Health);
        assert_eq!(Health.next(false), BandwidthTotal);
        assert_eq!(BandwidthTotal.next(false), CreatedAt); // Cycles back
    }

    #[test]
    fn test_sort_column_cycle_with_location() {
        use SortColumn::*;

        // With GeoIP, Location appears between LocalAddress and Service
        assert_eq!(LocalAddress.next(true), Location);
        assert_eq!(Location.next(true), Service);
        // Other transitions unchanged
        assert_eq!(CreatedAt.next(true), Process);
        assert_eq!(Service.next(true), Application);
    }

    #[test]
    fn test_sort_column_default_directions() {
        use SortColumn::*;

        // Bandwidth, RTT, and Health should default to descending (false)
        assert!(!BandwidthTotal.default_direction());
        assert!(!Rtt.default_direction());
        assert!(!Health.default_direction());

        // Everything else should default to ascending (true)
        assert!(Process.default_direction());
        assert!(LocalAddress.default_direction());
        assert!(RemoteAddress.default_direction());
        assert!(Location.default_direction());
        assert!(Application.default_direction());
        assert!(Service.default_direction());
        assert!(State.default_direction());
        assert!(CreatedAt.default_direction());
    }

    #[test]
    fn test_ui_state_cycle_sort_column() {
        use SortColumn::*;
        let mut ui_state = UiState::default();
        assert_eq!(ui_state.sort_column, CreatedAt);
        assert!(ui_state.sort_ascending);

        for (column, ascending) in [
            (Process, true),
            (RemoteAddress, true),
            (LocalAddress, true),
            (Service, true),
            (Application, true),
            (State, true),
            (Rtt, false),
            (Health, false),
            (BandwidthTotal, false),
            (CreatedAt, true),
        ] {
            // A column change must restore its default direction.
            ui_state.sort_ascending = !ascending;
            ui_state.cycle_sort_column();
            assert_eq!(ui_state.sort_column, column);
            assert_eq!(ui_state.sort_ascending, ascending, "{column:?}");
        }
    }

    #[test]
    fn test_ui_state_toggle_sort_direction() {
        let mut ui_state = UiState {
            sort_column: SortColumn::BandwidthTotal,
            sort_ascending: false,
            ..Default::default()
        };

        // Toggle direction
        ui_state.toggle_sort_direction();
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(ui_state.sort_ascending);

        // Toggle back
        ui_state.toggle_sort_direction();
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(!ui_state.sort_ascending);
    }

    #[test]
    fn test_sort_column_display_names() {
        use SortColumn::*;

        assert_eq!(CreatedAt.display_name(), "Time");
        assert_eq!(BandwidthTotal.display_name(), "Bandwidth Total");
        assert_eq!(Process.display_name(), "Process");
        assert_eq!(LocalAddress.display_name(), "Local Addr");
        assert_eq!(RemoteAddress.display_name(), "Remote Addr");
        assert_eq!(Location.display_name(), "Location");
        assert_eq!(Application.display_name(), "Application");
        assert_eq!(Service.display_name(), "Service");
        assert_eq!(State.display_name(), "State");
        assert_eq!(Rtt.display_name(), "RTT");
        assert_eq!(Health.display_name(), "Health");
    }

    #[test]
    fn only_the_cut_rows_of_a_scrolled_pane_fade() {
        use ratatui::text::Span;

        let plain = theme::fg(theme::text());
        let mut lines: Vec<Line<'static>> = (0..6)
            .map(|i| Line::from(Span::styled(format!("row {i}"), plain)))
            .collect();
        // Rows 1..=3 visible: content continues above and below.
        fade_scroll_edges(&mut lines, 1, 3);
        let faded = theme::edge_fade(plain);
        assert_eq!(lines[1].spans[0].style, faded, "top boundary must fade");
        assert_eq!(lines[3].spans[0].style, faded, "bottom boundary must fade");
        for index in [0, 2, 4, 5] {
            assert_eq!(
                lines[index].spans[0].style, plain,
                "row {index} is not a boundary and must keep its style"
            );
        }
    }

    #[test]
    fn a_pane_that_does_not_scroll_keeps_every_row() {
        use ratatui::text::Span;

        let plain = theme::fg(theme::text());
        let mut lines: Vec<Line<'static>> = (0..3)
            .map(|i| Line::from(Span::styled(format!("row {i}"), plain)))
            .collect();
        fade_scroll_edges(&mut lines, 0, 3);
        assert!(lines.iter().all(|line| line.spans[0].style == plain));
        // A zero-height pane has no boundary rows to fade.
        fade_scroll_edges(&mut lines, 0, 0);
        assert!(lines.iter().all(|line| line.spans[0].style == plain));
    }

    #[test]
    fn test_navigation_consistency_with_sorted_list() {
        use crate::test_support::local_tcp;

        // Create test connections with different process names for sorting
        // (alphabetically: alpha, beta, charlie)
        let mut connections = vec![
            local_tcp(8080, "charlie"),
            local_tcp(8081, "alpha"),
            local_tcp(8082, "beta"),
        ];

        let mut ui_state = UiState::default();

        // Initial state: select first connection (charlie)
        ui_state.set_selected_by_index(&connections, 0);
        assert_eq!(ui_state.selected_connection_key, Some(connections[0].key()));

        // Sort by process name (ascending): alpha, beta, charlie
        connections.sort_by(|a, b| {
            a.process_name
                .as_deref()
                .unwrap_or("")
                .cmp(b.process_name.as_deref().unwrap_or(""))
        });

        // After sorting, "charlie" is now at index 2
        // Selection should still point to "charlie" by key
        let current_index = ui_state.get_selected_index(&connections);
        assert_eq!(
            current_index,
            Some(2),
            "Selected connection should now be at index 2 after sorting"
        );

        // Navigate down: should move from charlie (2) to wrap to alpha (0)
        ui_state.move_selection_down(&connections);
        assert_eq!(
            ui_state.get_selected_index(&connections),
            Some(0),
            "Should wrap to index 0"
        );
        assert_eq!(ui_state.selected_connection_key, Some(connections[0].key()));

        // Navigate down: should move from alpha (0) to beta (1)
        ui_state.move_selection_down(&connections);
        assert_eq!(
            ui_state.get_selected_index(&connections),
            Some(1),
            "Should move to index 1"
        );
        assert_eq!(ui_state.selected_connection_key, Some(connections[1].key()));

        // Navigate up: should move from beta (1) to alpha (0)
        ui_state.move_selection_up(&connections);
        assert_eq!(
            ui_state.get_selected_index(&connections),
            Some(0),
            "Should move to index 0"
        );
        assert_eq!(ui_state.selected_connection_key, Some(connections[0].key()));
    }
}

#[cfg(test)]
mod snapshot_tests;
