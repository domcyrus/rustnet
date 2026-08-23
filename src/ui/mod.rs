//! Terminal user interface built on `ratatui` + `crossterm`: tabbed
//! layout (overview, details, process activity, graphs), sortable tables
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
    activity::ActivityTab, details::DetailsTab, graph::GraphTab, help::HelpOverlay,
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
/// Details / Activity / Graph while a filter is being
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
    match tab {
        0 => OverviewTab.handle_key(key, ctx),
        1 => DetailsTab.handle_key(key, ctx),
        2 => ActivityTab.handle_key(key, ctx),
        3 => GraphTab.handle_key(key, ctx),
        _ => None,
    }
}

/// Same as `dispatch_key` but for mouse events (currently the
/// scroll wheel — clicks go through the global `ClickableRegions`
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
        _ => None,
    }
}

/// Placeholder string displayed when a value is unavailable.
const NONE_PLACEHOLDER: &str = "-";

/// Global flag for NO_COLOR support (<https://no-color.org>)
static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Enable NO_COLOR mode (strips all colors from the UI)
pub fn set_no_color(enabled: bool) {
    NO_COLOR.store(enabled, Ordering::Relaxed);
}

mod state;
pub(crate) use state::process_group_label;
pub use state::{
    ActivityDirection, ActivitySort, ClickAction, ClickableRegions, GroupedRow, PaneScroll,
    SortColumn, UIState, compute_grouped_rows, compute_scroll_offset,
};
pub(crate) use widgets::tabs_bar::TAB_COUNT;

mod connection_table;

mod sorting;
pub use sorting::sort_connections;

mod clipboard;
pub use clipboard::{clipboard_available, copy_to_clipboard};

mod actions;
pub use actions::clear_all_with_confirmation;
pub(crate) use actions::{
    try_handle_connection_nav, try_handle_pane_scroll, try_handle_pane_wheel,
};

mod component;
pub use component::{Component, DrawContext as ComponentContext, Effect, HandlerContext};

mod effects;
pub use effects::apply_effects;

mod theme;
pub use theme::{
    Theme, ThemePreset, ThemeSpec, TokenColor, detect_light_background, detect_truecolor, set_theme,
};

/// Standard panel chrome: rounded border + title. Kept for the few
/// views that still frame themselves (Help overlay, loading
/// splash); everything else uses [`section_header`].
pub(crate) fn panel_block<'a, T: Into<Line<'a>>>(title: T) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_set(symbols::border::ROUNDED)
        .border_style(theme::fg(theme::border()))
        .title(title)
}

/// Borderless section chrome: renders an accent `▎` tick plus the given
/// title on the top row of `area` and returns the remaining rows. This
/// is rustnet's replacement for the old box-around-everything look; the
/// ▎ glyph itself still marks the section start under NO_COLOR.
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
    line.spans
        .insert(0, Span::styled("▎", theme::fg(theme::accent())));
    f.render_widget(
        Paragraph::new(line),
        Rect::new(area.x, area.y, area.width, 1),
    );
    Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    )
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

/// Draw the UI
pub fn draw(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    connections: &[Connection],
    grouped_rows: Option<&[GroupedRow]>,
    stats: &AppStats,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    click_regions.clear();

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
        draw_loading_screen(f, frame);
        return Ok(());
    }

    use widgets::filter_input::FILTER_INPUT_HEIGHT;
    use widgets::status_bar::status_bar_height;
    use widgets::tabs_bar::TABS_BAR_HEIGHT;

    // A capture failure can need a second row, so the status bar is measured
    // before the layout is split.
    let capture_error = app.get_capture_error();
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

    let content_area = chunks[1];
    let (filter_area, status_area) = if ui_state.filter_row_visible() {
        (Some(chunks[2]), chunks[3])
    } else {
        (None, chunks[2])
    };

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
        _ => {}
    }

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
mod tests {
    use super::*;

    #[test]
    fn test_port_toggle_default_state() {
        let ui_state = UIState::default();
        assert!(
            !ui_state.show_port_numbers,
            "Port numbers should be hidden by default"
        );
    }

    #[test]
    fn test_port_toggle_state_change() {
        let mut ui_state = UIState::default();
        assert!(!ui_state.show_port_numbers);

        // Toggle to show port numbers
        ui_state.show_port_numbers = !ui_state.show_port_numbers;
        assert!(
            ui_state.show_port_numbers,
            "Port numbers should be visible after toggle"
        );

        // Toggle back to show service names
        ui_state.show_port_numbers = !ui_state.show_port_numbers;
        assert!(
            !ui_state.show_port_numbers,
            "Service names should be visible after second toggle"
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
        assert_eq!(Rtt.next(false), BandwidthTotal);
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

        // Bandwidth and RTT should default to descending (false)
        assert!(!BandwidthTotal.default_direction());
        assert!(!Rtt.default_direction());

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
        let mut ui_state = UIState::default();

        // Default state
        assert_eq!(ui_state.sort_column, SortColumn::CreatedAt);
        assert!(ui_state.sort_ascending);

        // Cycle to Process - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::Process);
        assert!(ui_state.sort_ascending); // Process defaults to ascending

        // Cycle to RemoteAddress - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::RemoteAddress);
        assert!(ui_state.sort_ascending);

        // Cycle to LocalAddress - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::LocalAddress);
        assert!(ui_state.sort_ascending);

        // Skip ahead to Application
        ui_state.cycle_sort_column(); // Service
        ui_state.cycle_sort_column(); // Application
        assert_eq!(ui_state.sort_column, SortColumn::Application);
        assert!(ui_state.sort_ascending);

        // Cycle to State, then Rtt, then BandwidthTotal
        ui_state.cycle_sort_column(); // State
        ui_state.cycle_sort_column(); // Rtt
        assert_eq!(ui_state.sort_column, SortColumn::Rtt);
        assert!(!ui_state.sort_ascending); // RTT defaults to descending (slowest first)
        ui_state.cycle_sort_column(); // BandwidthTotal
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(!ui_state.sort_ascending); // Bandwidth defaults to descending
    }

    #[test]
    fn test_ui_state_toggle_sort_direction() {
        let mut ui_state = UIState {
            sort_column: SortColumn::BandwidthTotal,
            sort_ascending: false,
            ..Default::default()
        };

        // Toggle direction
        ui_state.toggle_sort_direction();
        assert!(ui_state.sort_ascending);

        // Toggle back
        ui_state.toggle_sort_direction();
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
    }

    #[test]
    fn test_bandwidth_sort_states() {
        let mut ui_state = UIState::default();

        // Start from default
        assert_eq!(ui_state.sort_column, SortColumn::CreatedAt);
        assert!(ui_state.sort_ascending);

        // Cycle through columns to reach BandwidthTotal
        // CreatedAt -> Process -> RemoteAddress -> LocalAddress -> Service ->
        // Application -> State -> Rtt -> BandwidthTotal
        for _ in 0..8 {
            ui_state.cycle_sort_column();
        }

        // Should be at BandwidthTotal with default descending (false)
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(
            !ui_state.sort_ascending,
            "BandwidthTotal should default to descending"
        );

        // Toggle direction with Shift+S
        ui_state.toggle_sort_direction();
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(
            ui_state.sort_ascending,
            "After toggle, BandwidthTotal should be ascending"
        );

        // Toggle back
        ui_state.toggle_sort_direction();
        assert_eq!(ui_state.sort_column, SortColumn::BandwidthTotal);
        assert!(
            !ui_state.sort_ascending,
            "After second toggle, BandwidthTotal should be descending again"
        );

        // Cycle past BandwidthTotal wraps back to the CreatedAt default
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::CreatedAt);
        assert!(
            ui_state.sort_ascending,
            "CreatedAt should default to ascending"
        );
    }

    #[test]
    fn test_navigation_consistency_with_sorted_list() {
        use crate::network::types::{Protocol, ProtocolState};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        // Create test connections with different process names for sorting
        let mut connections = vec![
            Connection::new(
                Protocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443),
                ProtocolState::Tcp(crate::network::types::TcpState::Established),
            ),
            Connection::new(
                Protocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 443),
                ProtocolState::Tcp(crate::network::types::TcpState::Established),
            ),
            Connection::new(
                Protocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8082),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)), 443),
                ProtocolState::Tcp(crate::network::types::TcpState::Established),
            ),
        ];

        // Set different process names for sorting (alphabetically: alpha, beta, charlie)
        connections[0].process_name = Some("charlie".to_string());
        connections[1].process_name = Some("alpha".to_string());
        connections[2].process_name = Some("beta".to_string());

        // Create UI state
        let mut ui_state = UIState::default();

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
mod snapshot_tests {
    //! Snapshot tests covering chrome (tabs, filter, status bar, loading,
    //! help) and full-page renders that need no live `App` plumbing.
    //!
    //! Rendering is captured as plain-text (cell symbols only) — colors
    //! and modifiers are dropped because they're hard to diff usefully and
    //! the theme is exercised separately. Layout regressions are what
    //! these tests catch.
    //!
    //! Snapshots live in `src/snapshots/` (insta's default for unit
    //! tests). Run `cargo insta review` after intentional UI changes.
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;
    use std::collections::HashSet;

    /// Render a closure into a `width × height` test buffer and return a
    /// plain-text dump (one line per row, no trailing whitespace trim).
    fn render<F>(width: u16, height: u16, draw: F) -> String
    where
        F: FnOnce(&mut Frame),
    {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("create test terminal");
        terminal.draw(draw).expect("draw frame");
        buffer_to_string(terminal.backend().buffer())
    }

    fn buffer_to_string(buffer: &Buffer) -> String {
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

    // --- Chrome: loading, help, tabs, filter input, status bar ---

    #[test]
    fn loading_screen() {
        let output = render(80, 20, |f| {
            draw_loading_screen(f, std::time::Duration::ZERO);
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn help_overlay_overview() {
        use crate::ui::tabs::help::draw_help_overlay;
        let ui_state = UIState {
            show_help: true,
            ..UIState::default()
        };
        let output = render(100, 40, |f| {
            draw_help_overlay(f, &ui_state, f.area()).expect("draw help overlay");
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn help_overlay_details() {
        use crate::ui::tabs::help::draw_help_overlay;
        let ui_state = UIState {
            selected_tab: 1,
            show_help: true,
            ..UIState::default()
        };
        let output = render(100, 30, |f| {
            draw_help_overlay(f, &ui_state, f.area()).expect("draw help overlay");
        });
        assert!(!output.contains("Filter"));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_overview_active() {
        let ui_state = UIState {
            selected_tab: 0,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 2, |f| {
            draw_tabs(
                f,
                &ui_state,
                &CaptureCluster::default(),
                f.area(),
                &mut regions,
            )
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_details_active() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 2, |f| {
            draw_tabs(
                f,
                &ui_state,
                &CaptureCluster::default(),
                f.area(),
                &mut regions,
            )
        });
        insta::assert_snapshot!(output);
    }

    /// The capture cluster is right-aligned on the title row and
    /// carries the interface plus its link layer.
    #[test]
    fn tabs_bar_capture_cluster_is_right_aligned() {
        let ui_state = UIState::default();
        let mut regions = ClickableRegions::default();
        let capture = CaptureCluster {
            interface: Some("eth0"),
            link_type: Some("Ethernet"),
            failed: false,
        };
        let output = render(100, 2, |f| {
            draw_tabs(f, &ui_state, &capture, f.area(), &mut regions)
        });

        let title_row = output.lines().next().expect("title row");
        assert!(
            title_row.trim_end().ends_with("● eth0 · Ethernet"),
            "cluster should sit at the right edge, got:\n{output}"
        );
    }

    /// The cluster degrades in two steps: link layer first, then the
    /// whole cluster once the tab titles would collide with it.
    #[test]
    fn tabs_bar_capture_cluster_drops_on_narrow_terminals() {
        let ui_state = UIState::default();
        let capture = CaptureCluster {
            interface: Some("eth0"),
            link_type: Some("Ethernet"),
            failed: false,
        };

        let mut regions = ClickableRegions::default();
        let medium = render(70, 2, |f| {
            draw_tabs(f, &ui_state, &capture, f.area(), &mut regions)
        });
        assert!(
            medium.contains("● eth0") && !medium.contains("Ethernet"),
            "link layer should be dropped first, got:\n{medium}"
        );

        let mut regions = ClickableRegions::default();
        let narrow = render(64, 2, |f| {
            draw_tabs(f, &ui_state, &capture, f.area(), &mut regions)
        });
        assert!(
            !narrow.contains("●"),
            "cluster should disappear rather than collide, got:\n{narrow}"
        );
    }

    /// An active filter marks the Overview title, and the underline
    /// grows with the wider label so the rule keeps tracking it.
    #[test]
    fn tabs_bar_marks_an_active_filter_on_overview() {
        let ui_state = UIState {
            selected_tab: 0,
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let capture = CaptureCluster::default();
        let output = render(80, 2, |f| {
            draw_tabs(f, &ui_state, &capture, f.area(), &mut regions)
        });

        let mut rows = output.lines();
        let title_row = rows.next().expect("title row");
        let underline_row = rows.next().expect("underline row");
        assert!(
            title_row.contains("1 Overview •"),
            "filtered Overview should carry the activity dot, got:\n{output}"
        );
        let dot_column = title_row
            .chars()
            .position(|c| c == '•')
            .expect("dot column");
        assert_eq!(
            underline_row.chars().nth(dot_column),
            Some('━'),
            "the active underline must extend under the dot, got:\n{output}"
        );

        // No filter, no dot.
        let mut regions = ClickableRegions::default();
        let plain = render(80, 2, |f| {
            draw_tabs(f, &UIState::default(), &capture, f.area(), &mut regions)
        });
        assert!(!plain.contains('•'), "unfiltered Overview stays plain");
    }

    #[test]
    fn filter_input_mode_active_empty() {
        let ui_state = UIState {
            filter_mode: true,
            filter_query: String::new(),
            filter_cursor_position: 0,
            ..Default::default()
        };
        let output = render(80, 1, |f| draw_filter_input(f, &ui_state, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn filter_input_mode_active_with_text() {
        let ui_state = UIState {
            filter_mode: true,
            filter_query: "port:443".to_string(),
            filter_cursor_position: 8,
            ..Default::default()
        };
        let output = render(80, 1, |f| draw_filter_input(f, &ui_state, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_overview_default() {
        let ui_state = UIState::default();
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_overview_grouped_collapsed() {
        let ui_state = UIState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_overview_grouped_expanded_with_history() {
        let ui_state = UIState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            expanded_groups: HashSet::from(["firefox".to_string()]),
            show_historic: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_details_tab() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_activity_tab() {
        let ui_state = UIState {
            selected_tab: 2,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_help_overlay() {
        let ui_state = UIState {
            selected_tab: 1,
            show_help: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_filtered() {
        let ui_state = UIState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_quit_confirmation() {
        let ui_state = UIState {
            quit_confirmation: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_clear_confirmation() {
        let ui_state = UIState {
            clear_confirmation: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, true, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_capture_error() {
        let ui_state = UIState::default();
        let output = render(120, 1, |f| {
            draw_status_bar(
                f,
                &ui_state,
                true,
                Some("Capture stopped: The interface disappeared."),
                f.area(),
            )
        });
        insta::assert_snapshot!(output);
    }

    /// A realistic libpcap error is longer than the status row, which does not
    /// wrap: the cause is elided so the recovery hint stays on screen.
    #[test]
    fn status_bar_capture_error_keeps_hint_on_narrow_terminal() {
        let ui_state = UIState::default();
        let output = render(80, 1, |f| {
            draw_status_bar(
                f,
                &ui_state,
                true,
                Some(
                    "Capture failed to start: eth0: You don't have permission to capture on that device (socket: Operation not permitted).",
                ),
                f.area(),
            )
        });

        assert!(
            output.contains("Restart rustnet to resume. Press 'q' to quit."),
            "recovery hint must survive truncation, got: {output}"
        );
        assert!(
            output.contains("Capture failed to start:"),
            "the cause must still be introduced, got: {output}"
        );
        assert!(output.contains('…'), "elision marker expected: {output}");
    }

    // --- Full-page renders backed by a seeded App ---
    //
    // A real `App` is built with `App::new(test_config())` (no threads, no
    // DNS, no GeoIP). Connection lists, interface stats, and the loading
    // flag are injected through `#[cfg(test)]` setters on `App`. Time-
    // sensitive strings (Status "Active (last seen Xs ago)", "Started Xs
    // ago", etc.) are scrubbed with `insta::with_settings!` filters so
    // snapshots stay stable across runs.

    use crate::app::{App, Config};
    use crate::network::geoip::GeoIpInfo;
    use crate::network::interface_stats::{InterfaceRates, InterfaceStats, InterfaceTrafficWindow};
    use crate::network::types::{Connection, Protocol, ProtocolState, TcpState, TrafficHistory};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, SystemTime};

    fn test_config() -> Config {
        Config {
            interface: Some("eth0".to_string()),
            filter_localhost: false,
            refresh_interval: 1000,
            enable_dpi: false,
            bpf_filter: None,
            json_log_file: None,
            pcap_export_file: None,
            pcapng_export_file: None,
            resolve_dns: false,
            show_ptr_lookups: false,
            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: true,
            #[cfg(feature = "kubernetes")]
            kubernetes_mode: crate::network::kubernetes::KubernetesMode::default(),
        }
    }

    fn test_app() -> App {
        let app = App::new(test_config()).expect("App::new in test_config");
        app.set_loading_for_test(false);
        app.set_current_interface_for_test(Some("eth0".to_string()));
        app
    }

    /// Full-page render of `app` through `draw`, owning the stats /
    /// click-regions boilerplate every such test repeats. Returns the text
    /// dump plus the click regions the frame registered.
    fn render_app_frame(
        app: &App,
        ui_state: &UIState,
        connections: &[Connection],
        grouped: Option<&[GroupedRow]>,
        width: u16,
        height: u16,
    ) -> (String, ClickableRegions) {
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();
        let output = render(width, height, |f| {
            draw(
                f,
                app,
                ui_state,
                connections,
                grouped,
                &stats,
                &mut click_regions,
            )
            .expect("draw full page");
        });
        (output, click_regions)
    }

    /// [`render_app_frame`] for the tests that only need the text dump.
    fn render_app(
        app: &App,
        ui_state: &UIState,
        connections: &[Connection],
        grouped: Option<&[GroupedRow]>,
        width: u16,
        height: u16,
    ) -> String {
        render_app_frame(app, ui_state, connections, grouped, width, height).0
    }

    #[test]
    fn full_page_shows_capture_error() {
        let app = test_app();
        app.set_capture_error_for_test(Some("Capture stopped: The interface disappeared."));
        let ui_state = UIState {
            show_system_panel: false,
            ..Default::default()
        };
        let output = render_app(&app, &ui_state, &[], None, 100, 16);

        assert!(
            output
                .contains("Capture stopped: The interface disappeared. Restart rustnet to resume. Press 'q' to quit."),
            "capture failure should remain visible in the global status bar"
        );
    }

    /// A real libpcap error does not fit one row; the status bar claims a
    /// second one so both the cause and the recovery hint stay readable.
    #[test]
    fn full_page_capture_error_grows_the_status_bar_to_two_rows() {
        let app = test_app();
        app.set_capture_error_for_test(Some(
            "Capture failed to start: eth0: You don't have permission to capture on that device (socket: Operation not permitted).",
        ));
        let ui_state = UIState {
            show_system_panel: false,
            ..Default::default()
        };
        let output = render_app(&app, &ui_state, &[], None, 80, 16);

        let rows: Vec<&str> = output.lines().collect();
        let hint_row = rows
            .iter()
            .rposition(|row| row.contains("Restart rustnet to resume. Press 'q' to quit."))
            .expect("recovery hint must stay on screen");
        assert_eq!(
            hint_row,
            rows.len() - 1,
            "the hint belongs on the last row, got:\n{output}"
        );
        assert!(
            rows[hint_row - 1].contains("Capture failed to start: eth0: You don't have permission"),
            "the row above the hint should carry the cause, got:\n{output}"
        );
    }

    /// Test-fixture spec for one connection. Folded into a struct so
    /// `sample_connections()` can build a vec literally instead of
    /// passing nine positional args per entry.
    struct ConnSpec {
        protocol: Protocol,
        local: (Ipv4Addr, u16),
        remote: (Ipv4Addr, u16),
        state: ProtocolState,
        service: &'static str,
        process: &'static str,
        pid: u32,
        bytes_sent: u64,
        bytes_received: u64,
    }

    fn build_conn(spec: ConnSpec) -> Connection {
        let local_sa = SocketAddr::new(IpAddr::V4(spec.local.0), spec.local.1);
        let remote_sa = SocketAddr::new(IpAddr::V4(spec.remote.0), spec.remote.1);
        let now = SystemTime::now();
        let mut conn = Connection::new(spec.protocol, local_sa, remote_sa, spec.state);
        conn.service_name = Some(spec.service.to_string());
        conn.process_name = Some(spec.process.to_string());
        conn.pid = Some(spec.pid);
        conn.bytes_sent = spec.bytes_sent;
        conn.bytes_received = spec.bytes_received;
        conn.packets_sent = spec.bytes_sent / 1024;
        conn.packets_received = spec.bytes_received / 1024;
        conn.created_at = now;
        conn.last_activity = now;
        conn
    }

    fn sample_connections() -> Vec<Connection> {
        [
            ConnSpec {
                protocol: Protocol::Tcp,
                local: (Ipv4Addr::new(192, 168, 1, 10), 51234),
                remote: (Ipv4Addr::new(140, 82, 121, 4), 443),
                state: ProtocolState::Tcp(TcpState::Established),
                service: "https",
                process: "firefox",
                pid: 2001,
                bytes_sent: 12_500,
                bytes_received: 240_000,
            },
            ConnSpec {
                protocol: Protocol::Udp,
                local: (Ipv4Addr::new(192, 168, 1, 10), 53),
                remote: (Ipv4Addr::new(1, 1, 1, 1), 53),
                state: ProtocolState::Udp,
                service: "dns",
                process: "systemd-resolved",
                pid: 820,
                bytes_sent: 1_200,
                bytes_received: 3_400,
            },
            ConnSpec {
                protocol: Protocol::Tcp,
                local: (Ipv4Addr::new(192, 168, 1, 10), 22),
                remote: (Ipv4Addr::new(10, 0, 0, 5), 51022),
                state: ProtocolState::Tcp(TcpState::Established),
                service: "ssh",
                process: "sshd",
                pid: 1500,
                bytes_sent: 88_000,
                bytes_received: 42_000,
            },
            ConnSpec {
                protocol: Protocol::Tcp,
                local: (Ipv4Addr::new(192, 168, 1, 10), 60123),
                remote: (Ipv4Addr::new(151, 101, 1, 195), 443),
                state: ProtocolState::Tcp(TcpState::TimeWait),
                service: "https",
                process: "curl",
                pid: 9876,
                bytes_sent: 0,
                bytes_received: 1_536,
            },
        ]
        .into_iter()
        .map(build_conn)
        .collect()
    }

    /// Insta filters that scrub volatile values from the rendered output.
    /// The order matters — more specific patterns first.
    fn time_filters() -> Vec<(&'static str, &'static str)> {
        vec![
            (r"last seen \d+[smhd] ago", "last seen <T> ago"),
            (r"Started \d+[smhd] ago", "Started <T> ago"),
            (r"Closed \(\d+[smhd] ago\)", "Closed (<T> ago)"),
            (r"\(idle \d+[smhd]\)", "(idle <T>)"),
        ]
    }

    // Full Overview snapshots omit the System sidebar because its Security
    // text follows platform-specific code paths and includes the running
    // user's UID. The connection canvas remains portable and is covered in
    // both flat and process-aggregate modes below.

    fn overview_connections() -> Vec<Connection> {
        let mut connections = sample_connections();
        connections[0].current_incoming_rate_bps = 3_200_000.0;
        connections[0].current_outgoing_rate_bps = 950_000.0;
        connections[1].current_incoming_rate_bps = 48_000.0;
        connections[1].current_outgoing_rate_bps = 84_000.0;
        connections[2].current_incoming_rate_bps = 420_000.0;
        connections[2].current_outgoing_rate_bps = 1_800_000.0;
        // RTT column coverage: a measured live RTT, a handshake-only RTT,
        // and connections with nothing measured (placeholder).
        if let Some(analytics) = connections[0].tcp_analytics.as_mut() {
            analytics.smoothed_rtt = Some(Duration::from_micros(23_400));
        }
        connections[2].initial_rtt = Some(Duration::from_millis(184));
        connections
    }

    fn render_overview(grouped: bool) -> String {
        let app = test_app();
        let connections = overview_connections();
        app.set_connections_snapshot_for_test(connections.clone());
        let mut ui_state = UIState {
            grouping_enabled: grouped,
            show_system_panel: false,
            visible_rows: 18,
            ..Default::default()
        };
        let grouped_rows =
            grouped.then(|| compute_grouped_rows(&connections, &ui_state.expanded_groups));
        // The app repairs the grouped selection before every draw (see the
        // main loop), so the canonical snapshot must render it repaired too:
        // otherwise the footer would omit the space hint no real user of the
        // grouped view ever loses, and its fit would go untested.
        if let Some(rows) = grouped_rows.as_deref() {
            ui_state.ensure_valid_grouped_selection(rows);
        }
        render_app(
            &app,
            &ui_state,
            &connections,
            grouped_rows.as_deref(),
            140,
            26,
        )
    }

    #[test]
    fn overview_live_connections() {
        insta::assert_snapshot!(render_overview(false));
    }

    #[test]
    fn overview_process_aggregate() {
        insta::assert_snapshot!(render_overview(true));
    }

    #[test]
    fn overview_statistics_count_distinct_active_processes() {
        let app = test_app();
        let mut connections = overview_connections();
        connections[3].process_name = Some("firefox".to_string());
        app.set_connections_snapshot_for_test(connections.clone());
        let ui_state = UIState::default();
        let output = render_app(&app, &ui_state, &connections, None, 140, 40);

        assert!(output.contains("Processes: 3"));
    }

    #[test]
    fn overview_filter_count_does_not_change_statistics_totals() {
        let app = test_app();
        let connections = overview_connections();
        app.set_connections_snapshot_for_test(connections.clone());
        let filtered = vec![connections[0].clone()];
        let ui_state = UIState {
            filter_query: "process:firefox".to_string(),
            ..Default::default()
        };
        let output = render_app(&app, &ui_state, &filtered, None, 140, 40);

        assert!(output.contains("Live Connections · 1 shown"));
        assert!(output.contains("Processes: 4"));
        assert!(output.contains("Total Connections: 4"));
    }

    #[test]
    fn overview_system_panel_places_traffic_before_security() {
        let app = test_app();
        let connections = overview_connections();
        let output = render_app(&app, &UIState::default(), &connections, None, 140, 40);

        let traffic = output.find("Traffic").expect("Traffic section");
        let security = output.find("Security").expect("Security section");
        assert!(
            traffic < security,
            "Traffic should precede Security:\n{output}"
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    #[test]
    fn overview_system_panel_compacts_security_on_short_terminals() {
        let app = test_app();
        let connections = overview_connections();
        let output = render_app(&app, &UIState::default(), &connections, None, 140, 32);

        assert!(output.contains("Traffic"));
        assert!(output.contains("Security (compact)"));
        assert!(!output.contains("No restrictions active"));
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    #[test]
    fn overview_system_panel_expands_security_when_space_returns() {
        let app = test_app();
        let connections = overview_connections();
        let output = render_app(&app, &UIState::default(), &connections, None, 140, 35);

        assert!(!output.contains("Security (compact)"));
        assert!(output.contains("No restrictions active"));
    }

    /// One observed ARP reply between the gateway and this host. Seeds the
    /// tracker's neighbor cache so Details can label on-link addresses with
    /// MAC + vendor. The fixture's remote (140.82.121.4) is public and never
    /// ARPs, so its "Remote MAC" row renders the placeholder.
    fn gateway_arp_reply() -> crate::network::parser::ParsedPacket {
        use crate::network::types::{ArpInfo, ArpOperation};

        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        crate::network::parser::ParsedPacket::new(
            Protocol::Arp,
            SocketAddr::new(host, 0),
            SocketAddr::new(gateway, 0),
            ProtocolState::Arp(ArpInfo {
                operation: ArpOperation::Reply,
                sender_mac: "04:d9:f5:c5:ed:e8".to_string(),
                sender_ip: gateway,
                target_mac: "68:5e:dd:09:15:5e".to_string(),
                target_ip: host,
                sender_vendor: Some("ASUSTek COMPUTER INC.".to_string()),
                target_vendor: Some("Apple, Inc.".to_string()),
            }),
            false,
            42,
            None,
            None,
        )
    }

    /// An ARP reply from the sshd fixture's on-link peer (10.0.0.5). Seeds
    /// the neighbor cache so a Details render of that connection resolves
    /// its "Remote MAC" row to an actual address.
    fn sshd_peer_arp_reply() -> crate::network::parser::ParsedPacket {
        use crate::network::types::{ArpInfo, ArpOperation};

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        crate::network::parser::ParsedPacket::new(
            Protocol::Arp,
            SocketAddr::new(host, 0),
            SocketAddr::new(peer, 0),
            ProtocolState::Arp(ArpInfo {
                operation: ArpOperation::Reply,
                sender_mac: "b8:27:eb:12:34:56".to_string(),
                sender_ip: peer,
                target_mac: "68:5e:dd:09:15:5e".to_string(),
                target_ip: host,
                sender_vendor: Some("Raspberry Pi Foundation".to_string()),
                target_vendor: Some("Apple, Inc.".to_string()),
            }),
            false,
            42,
            None,
            None,
        )
    }

    /// Details render of `connections[selected]` through the full-page
    /// `draw`, returning the text dump plus the click regions the frame
    /// registered. `height` varies per test (40 covers the dashboard;
    /// the attribution tests need 52 for the lineage rows).
    fn render_details_frame(
        app: &App,
        connections: &[Connection],
        selected: usize,
        height: u16,
    ) -> (String, ClickableRegions) {
        let ui_state = UIState {
            selected_tab: 1, // Details
            selected_connection_key: Some(connections[selected].key()),
            ..Default::default()
        };
        render_app_frame(app, &ui_state, connections, None, 140, height)
    }

    /// Standard Details render at the 140x40 reference size.
    fn render_details(app: &App, connections: &[Connection], selected: usize) -> String {
        render_details_frame(app, connections, selected, 40).0
    }

    /// Row index of the first rendered line containing `heading`.
    fn heading_row(render: &str, heading: &str) -> usize {
        render
            .lines()
            .position(|line| line.contains(heading))
            .unwrap_or_else(|| panic!("missing {heading}"))
    }

    #[test]
    fn details_tab_tcp_https() {
        let app = test_app();
        app.ingest_packet_for_test(&gateway_arp_reply());
        let connections = sample_connections();
        app.set_connections_snapshot_for_test(connections.clone());

        let output = render_details(&app, &connections, 0);

        insta::with_settings!({
            filters => time_filters(),
        }, {
            insta::assert_snapshot!(output);
        });
    }

    /// QUIC rides on UDP, so the Details tab used to label its Transport
    /// Health card with TCP loss counters that can never be filled in, because packet
    /// numbers and ACK frames sit behind QUIC's header protection. The card
    /// must show what is actually observable instead, without changing height.
    #[test]
    fn details_tab_quic_shows_transport_health_without_tcp_counters() {
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, QuicCloseInfo, QuicConnectionState, QuicInfo,
            QuicPacketType,
        };

        let app = test_app();
        let mut connections = sample_connections();
        let mut quic = QuicInfo::new(1);
        quic.packet_type = QuicPacketType::OneRtt;
        quic.connection_state = QuicConnectionState::Connected;
        quic.idle_timeout = Some(Duration::from_secs(30));
        quic.connection_close = Some(QuicCloseInfo {
            frame_type: 0x1d,
            error_code: 0x100,
        });

        let quic_conn = &mut connections[1];
        quic_conn.remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(142, 250, 74, 138)), 443);
        quic_conn.service_name = Some("https".to_string());
        quic_conn.process_name = Some("firefox".to_string());
        quic_conn.initial_rtt = Some(Duration::from_micros(23_400));
        quic_conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic)),
        });

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 1);

        for tcp_only in [
            "TCP Retransmits",
            "Out-of-Order Packets",
            "Duplicate ACKs",
            "Fast Retransmits",
            "Window Size",
        ] {
            assert!(
                !output.contains(tcp_only),
                "{tcp_only} is a TCP counter and cannot be measured on a QUIC flow"
            );
        }
        assert!(
            output.contains("23.4ms"),
            "QUIC handshake RTT should fill the Initial RTT row"
        );
        assert!(output.contains("Idle Timeout") && output.contains("30s"));
        assert!(output.contains("Connection Close") && output.contains("application 0x100"));
        assert!(
            output.contains("Loss counters are encrypted in QUIC"),
            "the card should say why the loss counters are absent"
        );

        // The card must not resize between protocols: Traffic Statistics is
        // anchored below Transport Health, so a shorter QUIC card would pull
        // the whole lower half of the dashboard upward.
        let tcp_output = render_details(&app, &connections, 0);
        assert_eq!(
            heading_row(&output, "Traffic Statistics"),
            heading_row(&tcp_output, "Traffic Statistics"),
            "Traffic Statistics moved between the QUIC and TCP records"
        );
    }

    /// A unicast DNS flow has no handshake, but query/response pairs are
    /// timeable by transaction ID, so its Transport Health card shows the
    /// response time and last response code instead of the "no metrics" note.
    #[test]
    fn details_tab_dns_shows_response_time_in_transport_health() {
        use crate::network::types::{ApplicationProtocol, DnsInfo, DnsQueryType, DpiInfo};

        let app = test_app();
        let mut connections = sample_connections();

        let dns_conn = &mut connections[1];
        dns_conn.dns_response_time = Some(Duration::from_micros(12_300));
        dns_conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(DnsInfo {
                query_name: Some("example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_ips: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                is_response: true,
                txid: 0x1234,
                rcode: Some(0),
                nodata: Some(false),
            }),
        });

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 1);

        assert!(
            output.contains("DNS Response Time") && output.contains("12.3ms"),
            "the paired query/response time should fill the card"
        );
        assert!(output.contains("Last Response Code") && output.contains("NOERROR"));
        assert!(
            output.contains("DNS Query") && output.contains("example.com"),
            "the queried name should show alongside the response details"
        );
        assert!(
            output.contains("Timed by pairing query and response IDs"),
            "the card should say where the timing comes from"
        );
        assert!(
            !output.contains("No transport metrics for this protocol"),
            "DNS flows now have a transport metric"
        );
        for non_dns in ["Initial RTT", "TCP Retransmits", "Window Size"] {
            assert!(
                !output.contains(non_dns),
                "{non_dns} cannot be measured on a UDP DNS flow"
            );
        }

        // Same geometry invariant as the QUIC card: Traffic Statistics must
        // not move when flipping between a DNS and a TCP connection.
        let tcp_output = render_details(&app, &connections, 0);
        assert_eq!(
            heading_row(&output, "Traffic Statistics"),
            heading_row(&tcp_output, "Traffic Statistics"),
            "Traffic Statistics moved between the DNS and TCP records"
        );
    }

    /// LLMNR lookup latency is measured to the first unicast response, and is
    /// shown on the multicast query row that a user naturally inspects.
    #[test]
    fn details_tab_llmnr_shows_response_time_in_transport_health() {
        use crate::network::types::{
            ApplicationProtocol, DnsQueryType, DpiInfo, LlmnrInfo, ProtocolState,
        };

        let app = test_app();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 40_000);
        let multicast = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 252)), 5355);
        let mut llmnr = Connection::new(Protocol::Udp, local, multicast, ProtocolState::Udp);
        llmnr.llmnr_response_time = Some(Duration::from_micros(14_800));
        llmnr.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Llmnr(LlmnrInfo {
                query_name: Some("fileserver".to_string()),
                query_type: Some(DnsQueryType::A),
                is_response: false,
                response_ips: Vec::new(),
                txid: 0x1234,
            }),
        });
        let connections = vec![llmnr];

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);

        assert!(output.contains("LLMNR Response Time") && output.contains("14.8ms"));
        assert!(output.contains("First response paired by transaction ID"));
        assert!(output.contains("Query Name") && output.contains("fileserver"));
        assert!(!output.contains("No transport metrics for this protocol"));
    }

    #[test]
    fn details_tab_netbios_shows_response_time_in_transport_health() {
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, NetBiosInfo, NetBiosOpcode, NetBiosResponseStatus,
            NetBiosService,
        };

        let app = test_app();
        let mut connections = sample_connections();
        let netbios_conn = &mut connections[1];
        netbios_conn.netbios_response_time = Some(Duration::from_micros(18_700));
        netbios_conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::NetBios(NetBiosInfo {
                service: NetBiosService::NameService,
                opcode: NetBiosOpcode::Response,
                name: Some("FILESERVER".to_string()),
                transaction_id: 0x1234,
                is_response: true,
                response_status: Some(NetBiosResponseStatus::NameService(3)),
            }),
        });

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 1);

        assert!(output.contains("NetBIOS Response Time") && output.contains("18.7ms"));
        assert!(output.contains("Last Response Status") && output.contains("NAM_ERR"));
        assert!(output.contains("Timed by pairing request and response IDs"));
        assert!(!output.contains("No transport metrics for this protocol"));
    }

    /// ICMP echo has an explicit identifier and sequence pair, so it can show
    /// a real RTT even when requests are sent more often than the UI refreshes.
    #[test]
    fn details_tab_ping_shows_echo_rtt_and_sequence() {
        let app = test_app();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        let mut ping = Connection::new(
            Protocol::Icmp,
            local,
            remote,
            ProtocolState::Icmp {
                icmp_type: 0,
                icmp_id: Some(0x1234),
                icmp_sequence: Some(42),
                ndp_neighbor: None,
            },
        );
        ping.process_name = Some("ping".to_string());
        ping.icmp_echo_rtt = Some(Duration::from_micros(8_700));
        let connections = vec![ping];

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);

        assert!(output.contains("Ping RTT") && output.contains("8.7ms"));
        assert!(output.contains("Last Sequence") && output.contains("42"));
        assert!(output.contains("Paired by echo ID and sequence"));
        assert!(!output.contains("No transport metrics for this protocol"));
    }

    /// Inbound pings are answered here but timed by the remote sender: the
    /// Ping RTT row keeps its place with a placeholder (the row set depends
    /// on the class, not on direction, which resolves asynchronously) and
    /// the footnote explains who measures it.
    #[test]
    fn details_tab_inbound_ping_keeps_rtt_placeholder_row() {
        let app = test_app();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 0);
        let mut ping = Connection::new(
            Protocol::Icmp,
            local,
            remote,
            ProtocolState::Icmp {
                icmp_type: 8,
                icmp_id: Some(0x0042),
                icmp_sequence: Some(4242),
                ndp_neighbor: None,
            },
        );
        ping.connection_direction = Some(false);
        let connections = vec![ping];

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);

        let rtt_row = output
            .lines()
            .find(|line| line.contains("Ping RTT"))
            .expect("inbound echo must keep the Ping RTT row");
        let rtt_value = rtt_row
            .split_once("Ping RTT")
            .and_then(|(_, rest)| rest.split_whitespace().next());
        assert!(
            rtt_value == Some(NONE_PLACEHOLDER),
            "an unmeasured inbound Ping RTT must render the placeholder, got: {rtt_row}"
        );
        assert!(output.contains("Last Sequence") && output.contains("4242"));
        assert!(output.contains("RTT is timed by the remote sender"));
    }

    /// A STUN flow has no handshake, but request/response pairs share a
    /// transaction ID, so its Transport Health card shows a real RTT.
    #[test]
    fn details_tab_stun_shows_rtt_in_transport_health() {
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, StunInfo, StunMessageClass, StunMethod,
        };

        let app = test_app();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 54_000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 3478);
        let mut stun = Connection::new(Protocol::Udp, local, remote, ProtocolState::Udp);
        stun.stun_rtt = Some(Duration::from_micros(23_400));
        stun.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Stun(StunInfo {
                message_class: StunMessageClass::SuccessResponse,
                method: StunMethod::Binding,
                transaction_id: [7u8; 12],
                software: None,
            }),
        });
        let connections = vec![stun];

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);

        assert!(output.contains("STUN RTT") && output.contains("23.4ms"));
        assert!(output.contains("Paired by 96-bit transaction ID"));
        assert!(!output.contains("No transport metrics for this protocol"));
        // Method and class moved to the Application card; Transport Health
        // must not repeat them as a Last Message row.
        assert!(output.contains("Binding") && output.contains("Success"));
        assert!(!output.contains("Last Message"));
    }

    /// An NTP poll is timeable through the originate timestamp echo, so its
    /// Transport Health card shows a real RTT plus the server stratum.
    #[test]
    fn details_tab_ntp_shows_rtt_in_transport_health() {
        use crate::network::types::{ApplicationProtocol, DpiInfo, NtpInfo, NtpMode};

        let app = test_app();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 47_000);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 123);
        let mut ntp = Connection::new(Protocol::Udp, local, remote, ProtocolState::Udp);
        ntp.ntp_rtt = Some(Duration::from_micros(6_500));
        ntp.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Ntp(NtpInfo {
                version: 4,
                mode: NtpMode::Server,
                stratum: 2,
                origin_timestamp: 0xAABB,
                transmit_timestamp: 0xCCDD,
            }),
        });
        let connections = vec![ntp];

        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);

        assert!(output.contains("NTP RTT") && output.contains("6.5ms"));
        assert!(output.contains("Paired by originate timestamp echo"));
        assert!(!output.contains("No transport metrics for this protocol"));
        // Stratum's only home is the Application card now; the old Transport
        // Health duplicate is gone.
        assert_eq!(
            output.matches("Stratum").count(),
            1,
            "Stratum must render exactly once:\n{output}"
        );
    }

    /// The Attribution section repeats PID beside the richer process fields so
    /// the identity remains visible as one self-contained block.
    #[test]
    fn details_tab_shows_complete_process_attribution() {
        use crate::network::types::{MatchQuality, ProcessAncestor, ProcessLineage};
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        let app = test_app();
        let mut connections = sample_connections();
        app.set_connections_snapshot_for_test(connections.clone());

        // 52 rows so the lineage rows fit below the dashboard.
        let render_connections =
            |connections: &[Connection]| render_details_frame(&app, connections, 0, 52).0;

        connections[0].pid = None;
        let unattributed = render_connections(&connections);
        assert!(
            unattributed.contains("Attribution"),
            "the Attribution card renders placeholders even when nothing resolved"
        );

        connections[0].pid = Some(2001);
        connections[0].process_ppid = Some(1900);
        connections[0].executable = Some(Arc::from(Path::new("/usr/lib/firefox/firefox")));
        connections[0].process_uid = Some(1000);
        connections[0].process_gid = Some(1000);
        connections[0].attribution_quality = Some(MatchQuality::ExactTuple);
        connections[0].process_lineage = Some(Arc::new(ProcessLineage {
            ancestors: vec![
                ProcessAncestor {
                    pid: 1,
                    name: "systemd".to_string(),
                    executable: Some(PathBuf::from("/usr/lib/systemd/systemd")),
                    started_at_unix_ms: Some(1_700_000_000_000),
                },
                ProcessAncestor {
                    pid: 1900,
                    name: "bash".to_string(),
                    executable: Some(PathBuf::from("/usr/bin/bash")),
                    started_at_unix_ms: Some(1_700_000_010_000),
                },
            ],
            truncated: false,
        }));
        app.set_connections_snapshot_for_test(connections.clone());

        let attributed = render_connections(&connections);
        assert!(attributed.contains("Attribution"));
        assert!(attributed.contains("1900"));
        assert!(attributed.contains("/usr/lib/firefox/firefox"));
        assert!(attributed.contains("systemd > bash > firefox"));
        assert!(attributed.contains(&tabs::details::format_user_group(1000, Some(1000))));
        assert!(attributed.contains("exact tuple"));
    }

    /// Partial attribution is the common case off Linux: resolved fields carry
    /// values while unresolved ones keep their rows with a placeholder, so the
    /// card never changes height. Placeholder rows must not register a
    /// click-to-copy target.
    #[test]
    fn details_tab_renders_partial_attribution() {
        use crate::network::types::MatchQuality;

        let app = test_app();
        let mut connections = sample_connections();
        connections[0].attribution_quality = Some(MatchQuality::ListenerSocket);
        app.set_connections_snapshot_for_test(connections.clone());

        // 52 rows so the Attribution card rows sit above the fold.
        let (output, click_regions) = render_details_frame(&app, &connections, 0, 52);

        assert!(output.contains("Attribution"));
        assert!(output.contains("listener socket"));
        for label in ["Executable", "User"] {
            let row = output
                .lines()
                .find(|line| line.trim_start().starts_with(label))
                .unwrap_or_else(|| panic!("missing {label} row"));
            assert!(
                row.split_whitespace().nth(1) == Some(NONE_PLACEHOLDER),
                "an unresolved {label} must keep its row with a placeholder, got: {row}"
            );
        }
        let copyable_labels: Vec<String> = (0..52u16)
            .flat_map(|row| (0..140u16).map(move |col| (col, row)))
            .filter_map(|(col, row)| click_regions.hit_test(col, row).cloned())
            .filter_map(|action| match action {
                ClickAction::CopyField { label, .. } => Some(label),
                _ => None,
            })
            .collect();
        for placeholder_label in ["Executable", "User"] {
            assert!(
                !copyable_labels.iter().any(|l| l == placeholder_label),
                "placeholder {placeholder_label} row must not be clickable"
            );
        }
    }

    /// Long executable paths shorten from the middle so the location prefix
    /// and the basename stay visible instead of clipping at the pane edge;
    /// click-to-copy must still yield the full path.
    #[test]
    fn details_tab_shortens_long_executable_paths() {
        use crate::network::types::MatchQuality;
        use std::path::Path;
        use std::sync::Arc;

        let app = test_app();
        let mut connections = sample_connections();
        let full =
            "/nix/store/8xkzp1qdcnhmzy4v7c9r2c8dyl4qv8bq-firefox-141.0/lib/firefox/firefox-bin";
        connections[0].executable = Some(Arc::from(Path::new(full)));
        connections[0].attribution_quality = Some(MatchQuality::ExactTuple);
        app.set_connections_snapshot_for_test(connections.clone());

        // 52 rows so the Attribution card rows sit above the fold.
        let (output, click_regions) = render_details_frame(&app, &connections, 0, 52);

        assert!(
            output.contains("/nix/store/"),
            "the location prefix must survive"
        );
        assert!(output.contains("firefox-bin"), "the basename must survive");
        assert!(
            !output.contains("8xkzp1qdcnhmzy4v7c9r2c8dyl4qv8bq"),
            "middle components must be elided, not clipped at the pane edge"
        );
        assert!(output.contains("…"), "the elision must be visible");

        // The shortening is display-only: hit-test every cell and confirm the
        // Executable copy region still carries the unshortened path.
        let copied = (0..52u16)
            .flat_map(|row| (0..140u16).map(move |col| (col, row)))
            .filter_map(|(col, row)| click_regions.hit_test(col, row).cloned())
            .find_map(|action| match action {
                ClickAction::CopyField { label, value } if label == "Executable" => Some(value),
                _ => None,
            });
        assert_eq!(copied.as_deref(), Some(full));
    }

    #[test]
    fn details_tab_keeps_section_anchors_across_metadata_shapes() {
        let app = test_app();
        let mut connections = sample_connections();
        connections[0].geoip_info = Some(GeoIpInfo {
            country_code: Some("DE".to_string()),
            country_name: Some("Germany".to_string()),
            city: Some("Falkenstein".to_string()),
            postal_code: None,
            asn: Some(24_940),
            as_org: Some("Hetzner Online GmbH".to_string()),
        });
        app.set_connections_snapshot_for_test(connections.clone());

        let render_selected = |selected: usize| render_details(&app, &connections, selected);

        let enriched_tcp = render_selected(0);
        let plain_udp = render_selected(1);
        assert!(
            enriched_tcp
                .lines()
                .any(|line| line.contains("Network Context") && line.contains("Transport Health")),
            "second-row card headings should share one visual anchor"
        );
        let card_header = enriched_tcp
            .lines()
            .find(|line| line.contains("Connection") && line.contains("Application"))
            .expect("missing dashboard card header");
        let traffic_header = enriched_tcp
            .lines()
            .find(|line| line.contains("↓ RX") && line.contains("↑ TX"))
            .expect("missing traffic card header");
        let cell_position = |line: &str, needle: &str| {
            let byte_index = line.find(needle).unwrap();
            line[..byte_index].chars().count()
        };
        let left_card_x = cell_position(card_header, "Connection");
        let right_card_x = cell_position(card_header, "Application");
        let rx_x = cell_position(traffic_header, "↓ RX");
        let tx_x = cell_position(traffic_header, "↑ TX");
        assert_eq!(
            rx_x, left_card_x,
            "RX must align with the left dashboard card"
        );
        assert_eq!(
            tx_x, right_card_x,
            "TX must align with the right dashboard card"
        );
        let peak_positions: Vec<usize> = traffic_header
            .match_indices("peak")
            .map(|(byte_index, _)| traffic_header[..byte_index].chars().count())
            .collect();
        assert_eq!(peak_positions.len(), 2);
        assert_eq!(
            peak_positions[0] - rx_x,
            peak_positions[1] - tx_x,
            "peak labels must use the same offset within both traffic cards"
        );
        for heading in [
            "Connection",
            "Network Context",
            "Application",
            "Transport Health",
            "Traffic Statistics",
        ] {
            let enriched_row = enriched_tcp
                .lines()
                .position(|line| line.contains(heading))
                .unwrap_or_else(|| panic!("missing {heading} in enriched render"));
            let plain_row = plain_udp
                .lines()
                .position(|line| line.contains(heading))
                .unwrap_or_else(|| panic!("missing {heading} in plain render"));
            assert_eq!(
                enriched_row, plain_row,
                "{heading} moved between enriched TCP and plain UDP records"
            );
        }
    }

    /// The Details row set depends only on the connection class, never on
    /// data availability: a fully enriched record and a bare one must render
    /// the same labels at the same vertical positions, so a hovered
    /// click-to-copy row never turns into a different field while navigating.
    #[test]
    fn details_tab_row_positions_do_not_depend_on_data_availability() {
        use crate::network::types::{
            AttributedHostname, AttributionSource, MatchQuality, ProcessAncestor, ProcessLineage,
        };
        use std::path::{Path, PathBuf};
        use std::sync::Arc;

        // Enriched: neighbor cache seeded, DNS attribution, full process
        // attribution. Bare: the same TCP connection with none of it.
        let rich_app = test_app();
        rich_app.ingest_packet_for_test(&gateway_arp_reply());
        let mut rich_connections = sample_connections();
        rich_connections[0].attributed_hostname = Some(AttributedHostname {
            name: "lb-140-82-121-4.github.com".to_string(),
            source: AttributionSource::CapturedDns,
            observed_at: SystemTime::now(),
        });
        rich_connections[0].process_ppid = Some(1900);
        rich_connections[0].executable = Some(Arc::from(Path::new("/usr/lib/firefox/firefox")));
        rich_connections[0].process_uid = Some(1000);
        rich_connections[0].process_gid = Some(1000);
        rich_connections[0].attribution_quality = Some(MatchQuality::ExactTuple);
        rich_connections[0].process_lineage = Some(Arc::new(ProcessLineage {
            ancestors: vec![ProcessAncestor {
                pid: 1900,
                name: "bash".to_string(),
                executable: Some(PathBuf::from("/usr/bin/bash")),
                started_at_unix_ms: Some(1_700_000_010_000),
            }],
            truncated: false,
        }));
        rich_app.set_connections_snapshot_for_test(rich_connections.clone());
        let rich = render_details_frame(&rich_app, &rich_connections, 0, 52).0;

        let bare_app = test_app();
        let mut bare_connections = sample_connections();
        bare_connections[0].pid = None;
        bare_app.set_connections_snapshot_for_test(bare_connections.clone());
        let bare = render_details_frame(&bare_app, &bare_connections, 0, 52).0;

        // Every card heading and every conditional-looking label must sit on
        // the same row in both renders.
        for needle in [
            "Network Context",
            "Local MAC",
            "Attributed Name",
            "Attributed Via",
            "Remote MAC",
            "Attribution",
            "PPID",
            "Process Tree",
            "Executable",
            "User",
            "Match",
            "Transport Health",
            "Traffic Statistics",
        ] {
            assert_eq!(
                heading_row(&rich, needle),
                heading_row(&bare, needle),
                "{needle} moved between the enriched and the bare record"
            );
        }

        // Stronger form: the whole label column of the details body is
        // identical, only values differ. The body starts at the dashboard
        // card header; the continuity strip above legitimately differs
        // (the bare record has no PID to show there).
        let label_column = |render: &str| -> Vec<String> {
            let body_start = heading_row(render, "Protocol");
            render
                .lines()
                .skip(body_start)
                .map(|line| {
                    line.chars()
                        .take(tabs::details::DETAIL_LABEL_WIDTH)
                        .collect::<String>()
                        .trim_end()
                        .to_string()
                })
                .collect()
        };
        assert_eq!(
            label_column(&rich),
            label_column(&bare),
            "the label column must not depend on data availability"
        );

        // The resolved direction of the Remote MAC row: the sshd remote
        // (10.0.0.5) is on-link and seeded in the neighbor cache, so its row
        // must carry the actual MAC while sitting exactly where the
        // placeholder sits for the off-link remote above. This is the
        // scroll-between-on-link-and-off-link case the fixed row set exists
        // for.
        rich_app.ingest_packet_for_test(&sshd_peer_arp_reply());
        let on_link = render_details_frame(&rich_app, &rich_connections, 2, 52).0;
        let remote_mac_row = heading_row(&on_link, "Remote MAC");
        assert_eq!(
            remote_mac_row,
            heading_row(&rich, "Remote MAC"),
            "Remote MAC must sit on the same row for on-link and off-link remotes"
        );
        assert!(
            on_link
                .lines()
                .nth(remote_mac_row)
                .expect("Remote MAC row")
                .contains("b8:27:eb:12:34:56"),
            "an on-link remote must render its resolved MAC on the Remote MAC row"
        );
    }

    /// ARP is not exempt from the fixed row layout: it renders the same
    /// Network Context rows and the same Attribution card (all placeholders,
    /// there is no owning process), so the cards below sit on the same rows
    /// as for any other connection while the selection moves through a mixed
    /// list of ARP and non-ARP entries.
    #[test]
    fn details_tab_arp_uses_the_same_row_layout() {
        use crate::network::types::{ArpInfo, ArpOperation};

        let app = test_app();
        app.ingest_packet_for_test(&gateway_arp_reply());
        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let arp = Connection::new(
            Protocol::Arp,
            SocketAddr::new(host, 0),
            SocketAddr::new(gateway, 0),
            ProtocolState::Arp(ArpInfo {
                operation: ArpOperation::Reply,
                sender_mac: "04:d9:f5:c5:ed:e8".to_string(),
                sender_ip: gateway,
                target_mac: "68:5e:dd:09:15:5e".to_string(),
                target_ip: host,
                sender_vendor: Some("ASUSTek COMPUTER INC.".to_string()),
                target_vendor: Some("Apple, Inc.".to_string()),
            }),
        );
        let mut connections = sample_connections();
        connections.push(arp);
        let arp_index = connections.len() - 1;
        app.set_connections_snapshot_for_test(connections.clone());

        let arp_render = render_details_frame(&app, &connections, arp_index, 52).0;
        let tcp_render = render_details_frame(&app, &connections, 0, 52).0;

        assert!(arp_render.contains("Application: ARP"));
        assert!(arp_render.contains("Sender MAC") && arp_render.contains("Target MAC"));

        // Every shared card heading and left-column label sits on the same
        // row for the ARP record as for the TCP record; only the Application
        // card content is allowed to differ between classes.
        for needle in [
            "Network Context",
            "Local MAC",
            "Attributed Name",
            "Attributed Via",
            "Remote MAC",
            "Attribution",
            "PPID",
            "Process Tree",
            "Executable",
            "User ",
            "Match ",
            "Transport Health",
            "Traffic Statistics",
        ] {
            assert_eq!(
                heading_row(&arp_render, needle),
                heading_row(&tcp_render, needle),
                "{needle} moved between the ARP and the TCP record"
            );
        }

        // The ingested reply seeds both endpoints in the neighbor cache, so
        // the ARP record's MAC rows resolve like any other on-link
        // connection instead of pinning dead placeholders.
        for (label, mac) in [
            ("Remote MAC", "04:d9:f5:c5:ed:e8"),
            ("Local MAC", "68:5e:dd:09:15:5e"),
        ] {
            let row = heading_row(&arp_render, label);
            assert!(
                arp_render.lines().nth(row).expect("MAC row").contains(mac),
                "ARP must resolve its on-link {label}:\n{arp_render}"
            );
        }
    }

    #[test]
    fn activity_interface_details() {
        let app = test_app();
        app.set_connections_snapshot_for_test(sample_connections());
        app.set_interface_stats_for_test(
            "eth0",
            InterfaceStats {
                interface_name: "eth0".to_string(),
                rx_bytes: 1_500_000_000,
                tx_bytes: 250_000_000,
                rx_packets: 1_200_000,
                tx_packets: 800_000,
                rx_errors: 0,
                tx_errors: 0,
                rx_dropped: 12,
                tx_dropped: 0,
                collisions: 0,
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            },
        );
        app.set_interface_rates_for_test(
            "eth0",
            InterfaceRates {
                rx_bytes_per_sec: 524_288,
                tx_bytes_per_sec: 131_072,
            },
        );

        let ui_state = UIState {
            selected_tab: 2, // Activity
            activity_show_interfaces: true,
            ..Default::default()
        };
        let connections = app.get_connections();
        let output = render_app(&app, &ui_state, &connections, None, 140, 30);

        insta::with_settings!({
            filters => time_filters(),
        }, {
            insta::assert_snapshot!(output);
        });
    }

    fn seeded_activity_app() -> App {
        let app = test_app();
        let mut connections = sample_connections();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        app.observe_process_activity_for_test(&connections, now);
        connections[0].bytes_sent += 5_000_000;
        connections[0].bytes_received += 3_000_000;
        connections[1].bytes_sent += 32_000;
        connections[1].bytes_received += 64_000;
        connections[2].bytes_sent += 1_000_000;
        connections[2].bytes_received += 500_000;
        app.observe_process_activity_for_test(&connections, now + Duration::from_secs(2));
        app.set_connections_snapshot_for_test(connections);
        app.set_interface_rates_for_test(
            "eth0",
            InterfaceRates {
                rx_bytes_per_sec: 2_097_152,
                tx_bytes_per_sec: 4_194_304,
            },
        );
        app.set_interface_traffic_window_for_test(
            "eth0",
            InterfaceTrafficWindow {
                rx_bytes: 4_194_304,
                tx_bytes: 8_388_608,
            },
        );
        app
    }

    fn render_activity(app: &App, direction: ActivityDirection) -> String {
        let ui_state = UIState {
            selected_tab: 2,
            activity_direction: direction,
            ..Default::default()
        };
        let connections = app.get_connections();
        render_app(app, &ui_state, &connections, None, 150, 40)
    }

    #[test]
    fn activity_tab_process_egress() {
        let app = seeded_activity_app();
        insta::assert_snapshot!(render_activity(&app, ActivityDirection::Egress));
    }

    #[test]
    fn activity_tab_process_ingress() {
        let app = seeded_activity_app();
        insta::assert_snapshot!(render_activity(&app, ActivityDirection::Ingress));
    }

    #[test]
    fn graph_tab_empty_history() {
        let app = test_app();
        app.set_connections_snapshot_for_test(sample_connections());
        app.set_traffic_history_for_test(TrafficHistory::new(60));

        let ui_state = UIState {
            selected_tab: 3, // Graph
            ..Default::default()
        };
        let connections = app.get_connections();
        let output = render_app(&app, &ui_state, &connections, None, 140, 40);

        insta::with_settings!({
            filters => time_filters(),
        }, {
            insta::assert_snapshot!(output);
        });
    }

    #[test]
    fn loading_screen_via_app() {
        let app = App::new(test_config()).expect("App::new");
        // Leave is_loading=true so draw() takes the loading branch.
        let ui_state = UIState::default();
        let output = render_app(&app, &ui_state, &[], None, 80, 20);

        insta::assert_snapshot!(output);
    }

    // --- Application card: fixed per-protocol row sets ---

    /// One fully populated instance per `ApplicationProtocol` variant. The
    /// match at the bottom is deliberately exhaustive so a new variant fails
    /// compilation here until the fixture (and the fixed row-set spec in
    /// details.rs) covers it.
    fn dpi_variants_full() -> Vec<crate::network::types::ApplicationProtocol> {
        use crate::network::types::{
            ApplicationProtocol, BitTorrentInfo, BitTorrentType, DhcpInfo, DhcpMessageType,
            DnsInfo, DnsQueryType, FtpInfo, FtpMessageType, HttpInfo, HttpVersion, HttpsInfo,
            LlmnrInfo, MdnsInfo, MqttInfo, MqttPacketType, MqttVersion, NetBiosInfo, NetBiosOpcode,
            NetBiosResponseStatus, NetBiosService, NtpInfo, NtpMode, QuicConnectionState, QuicInfo,
            QuicPacketType, SnmpInfo, SnmpPduType, SnmpVersion, SsdpInfo, SsdpMethod,
            SshConnectionState, SshInfo, SshVersion, StunInfo, StunMessageClass, StunMethod,
            TlsInfo, TlsVersion,
        };

        let tls_info = TlsInfo {
            version: Some(TlsVersion::Tls13),
            sni: Some("github.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cipher_suite: Some(0x1301),
        };
        let mut quic = QuicInfo::new(0x0000_0001);
        quic.packet_type = QuicPacketType::OneRtt;
        quic.connection_state = QuicConnectionState::Connected;
        quic.connection_id_hex = Some("deadbeefcafe".to_string());
        quic.tls_info = Some(tls_info.clone());

        let variants = vec![
            ApplicationProtocol::Http(HttpInfo {
                version: HttpVersion::Http11,
                method: Some("GET".to_string()),
                host: Some("example.com".to_string()),
                path: Some("/index.html".to_string()),
                status_code: Some(200),
                user_agent: Some("curl/8.9.0".to_string()),
            }),
            ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(tls_info),
            }),
            ApplicationProtocol::Dns(DnsInfo {
                query_name: Some("example.com".to_string()),
                query_type: Some(DnsQueryType::A),
                response_ips: vec![
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
                ],
                is_response: true,
                txid: 0x1234,
                rcode: Some(0),
                nodata: Some(false),
            }),
            ApplicationProtocol::Ssh(SshInfo {
                version: Some(SshVersion::V2),
                client_software: Some("OpenSSH_9.8".to_string()),
                server_software: Some("OpenSSH_9.6p1".to_string()),
                connection_state: SshConnectionState::Established,
                algorithms: vec!["curve25519-sha256".to_string(), "ssh-ed25519".to_string()],
                auth_method: Some("publickey".to_string()),
            }),
            ApplicationProtocol::Quic(Box::new(quic)),
            ApplicationProtocol::Ntp(NtpInfo {
                version: 4,
                mode: NtpMode::Server,
                stratum: 2,
                origin_timestamp: 0xAABB,
                transmit_timestamp: 0xCCDD,
            }),
            ApplicationProtocol::Mdns(MdnsInfo {
                query_name: Some("printer.local".to_string()),
                query_type: Some(DnsQueryType::A),
                is_response: true,
                response_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42))],
            }),
            ApplicationProtocol::Llmnr(LlmnrInfo {
                query_name: Some("fileserver".to_string()),
                query_type: Some(DnsQueryType::A),
                is_response: true,
                response_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 43))],
                txid: 0x77,
            }),
            ApplicationProtocol::Dhcp(DhcpInfo {
                message_type: DhcpMessageType::Ack,
                hostname: Some("laptop".to_string()),
                client_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            }),
            ApplicationProtocol::Snmp(SnmpInfo {
                version: SnmpVersion::V2c,
                community: Some("public".to_string()),
                pdu_type: SnmpPduType::GetRequest,
            }),
            ApplicationProtocol::Ssdp(SsdpInfo {
                method: SsdpMethod::MSearch,
                service_type: Some("upnp:rootdevice".to_string()),
            }),
            ApplicationProtocol::NetBios(NetBiosInfo {
                service: NetBiosService::NameService,
                opcode: NetBiosOpcode::Response,
                name: Some("FILESERVER".to_string()),
                transaction_id: 0x1234,
                is_response: true,
                response_status: Some(NetBiosResponseStatus::NameService(0)),
            }),
            ApplicationProtocol::BitTorrent(BitTorrentInfo {
                protocol_type: BitTorrentType::Peer,
                info_hash: Some("aabbccddeeff00112233445566778899aabbccdd".to_string()),
                client: Some("qBittorrent 4.6".to_string()),
                dht_method: Some("get_peers".to_string()),
                supports_dht: true,
                supports_extension: true,
                supports_fast: true,
            }),
            ApplicationProtocol::Stun(StunInfo {
                message_class: StunMessageClass::SuccessResponse,
                method: StunMethod::Binding,
                transaction_id: [7u8; 12],
                software: Some("coturn".to_string()),
            }),
            ApplicationProtocol::Mqtt(MqttInfo {
                version: Some(MqttVersion::V311),
                packet_type: MqttPacketType::Publish,
                client_id: Some("sensor-1".to_string()),
                topic: Some("home/temp".to_string()),
                qos: Some(1),
            }),
            ApplicationProtocol::Ftp(FtpInfo {
                message_type: FtpMessageType::Response,
                command: Some("USER".to_string()),
                args: Some("marco".to_string()),
                response_code: Some(230),
                response_message: Some("Login successful".to_string()),
                username: Some("marco".to_string()),
                server_software: Some("vsftpd 3.0.5".to_string()),
                system_type: Some("UNIX".to_string()),
            }),
        ];

        let mut seen = std::collections::HashSet::new();
        for variant in &variants {
            assert!(
                seen.insert(std::mem::discriminant(variant)),
                "duplicate fixture for {}",
                variant.sort_key()
            );
            // Exhaustive on purpose: extend the fixture list above (and the
            // Details row-set table) when this match stops compiling.
            match variant {
                ApplicationProtocol::Http(_) => {}
                ApplicationProtocol::Https(_) => {}
                ApplicationProtocol::Dns(_) => {}
                ApplicationProtocol::Ssh(_) => {}
                ApplicationProtocol::Quic(_) => {}
                ApplicationProtocol::Ntp(_) => {}
                ApplicationProtocol::Mdns(_) => {}
                ApplicationProtocol::Llmnr(_) => {}
                ApplicationProtocol::Dhcp(_) => {}
                ApplicationProtocol::Snmp(_) => {}
                ApplicationProtocol::Ssdp(_) => {}
                ApplicationProtocol::NetBios(_) => {}
                ApplicationProtocol::BitTorrent(_) => {}
                ApplicationProtocol::Stun(_) => {}
                ApplicationProtocol::Mqtt(_) => {}
                ApplicationProtocol::Ftp(_) => {}
            }
        }
        assert_eq!(
            seen.len(),
            16,
            "fixture list out of sync with ApplicationProtocol: update the \
             variants vec (and this count) alongside the match above"
        );
        variants
    }

    /// A Details-ready connection carrying `app` as its DPI classification,
    /// on the transport that protocol actually rides on.
    fn dpi_details_connection(app: crate::network::types::ApplicationProtocol) -> Connection {
        use crate::network::types::{ApplicationProtocol, DpiInfo};

        let tcp_based = matches!(
            app,
            ApplicationProtocol::Http(_)
                | ApplicationProtocol::Https(_)
                | ApplicationProtocol::Ssh(_)
                | ApplicationProtocol::BitTorrent(_)
                | ApplicationProtocol::Mqtt(_)
                | ApplicationProtocol::Ftp(_)
        );
        let (protocol, state) = if tcp_based {
            (Protocol::Tcp, ProtocolState::Tcp(TcpState::Established))
        } else {
            (Protocol::Udp, ProtocolState::Udp)
        };
        let mut conn = Connection::new(
            protocol,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 50_000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4433),
            state,
        );
        conn.process_name = Some("proc".to_string());
        conn.pid = Some(4242);
        conn.dpi_info = Some(DpiInfo { application: app });
        conn
    }

    fn arp_details_connection(with_vendors: bool) -> Connection {
        use crate::network::types::{ArpInfo, ArpOperation};

        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        Connection::new(
            Protocol::Arp,
            SocketAddr::new(host, 0),
            SocketAddr::new(gateway, 0),
            ProtocolState::Arp(ArpInfo {
                operation: ArpOperation::Request,
                sender_mac: "68:5e:dd:09:15:5e".to_string(),
                sender_ip: host,
                target_mac: "00:00:00:00:00:00".to_string(),
                target_ip: gateway,
                sender_vendor: with_vendors.then(|| "Apple, Inc.".to_string()),
                target_vendor: with_vendors.then(|| "ASUSTek COMPUTER INC.".to_string()),
            }),
        )
    }

    fn icmp_echo_details_connection() -> Connection {
        let mut conn = Connection::new(
            Protocol::Icmp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0),
            ProtocolState::Icmp {
                icmp_type: 8,
                icmp_id: Some(0x1234),
                icmp_sequence: Some(42),
                ndp_neighbor: None,
            },
        );
        conn.process_name = Some("ping".to_string());
        conn.icmp_echo_rtt = Some(Duration::from_micros(8_700));
        conn
    }

    fn icmpv6_ndp_details_connection() -> Connection {
        use crate::network::types::NdpNeighbor;
        use std::net::Ipv6Addr;

        let local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let remote = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        Connection::new(
            Protocol::Icmp,
            SocketAddr::new(local, 0),
            SocketAddr::new(remote, 0),
            ProtocolState::Icmp {
                icmp_type: 136,
                icmp_id: None,
                icmp_sequence: None,
                ndp_neighbor: Some(NdpNeighbor {
                    ip: remote,
                    mac: "b8:27:eb:12:34:56".to_string(),
                    vendor: Some("Raspberry Pi Foundation".to_string()),
                }),
            },
        )
    }

    fn igmp_details_connection() -> Connection {
        Connection::new(
            Protocol::Igmp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 0),
            ProtocolState::Igmp {
                igmp_type: 0x16,
                group_addr: Some(Ipv4Addr::new(224, 0, 0, 251)),
            },
        )
    }

    /// Rows between the Application heading and the Transport Health heading
    /// in a Details render: the release-mode guard for the Application card's
    /// row budget.
    fn application_card_height(app: &App, conn: Connection) -> usize {
        let connections = vec![conn];
        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(app, &connections, 0);
        heading_row(&output, "Transport Health") - heading_row(&output, "Application")
    }

    /// The Application heading and the Transport Health heading must sit the
    /// same distance apart for every protocol class, so the dashboard cards
    /// never move while flipping through a mixed connection list. The
    /// baseline is measured from an unclassified TCP record, not hardcoded.
    #[test]
    fn application_card_geometry_is_fixed_for_all_protocols() {
        let app = test_app();
        let baseline = {
            let mut sample = sample_connections();
            application_card_height(&app, sample.remove(0))
        };
        assert!(baseline > 0, "baseline render must show both headings");

        for variant in dpi_variants_full() {
            let name = variant.sort_key();
            assert_eq!(
                application_card_height(&app, dpi_details_connection(variant)),
                baseline,
                "Application card height for {name} deviates from the TCP baseline"
            );
        }
        for (name, conn) in [
            ("ARP", arp_details_connection(true)),
            ("ICMP echo", icmp_echo_details_connection()),
            ("ICMPv6 NDP", icmpv6_ndp_details_connection()),
            ("IGMP", igmp_details_connection()),
        ] {
            assert_eq!(
                application_card_height(&app, conn),
                baseline,
                "Application card height for {name} deviates from the TCP baseline"
            );
        }
    }

    /// Label column of the Application card (heading row through the row
    /// before Transport Health), sliced at the card's own x offset since the
    /// card lives in the right pane of the split layout.
    fn application_card_labels(render: &str) -> Vec<String> {
        let header_row = heading_row(render, "Application");
        let header_line = render.lines().nth(header_row).expect("header line");
        let byte_index = header_line.find("Application").expect("Application x");
        let x = header_line[..byte_index].chars().count();
        let end_row = heading_row(render, "Transport Health");
        render
            .lines()
            .skip(header_row)
            .take(end_row - header_row)
            .map(|line| {
                line.chars()
                    .skip(x)
                    .take(tabs::details::DETAIL_LABEL_WIDTH)
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    /// The card's label column is a function of the protocol class alone:
    /// a fully populated record and an empty one of the same class must
    /// render identical labels, with `-` filling the gaps.
    #[test]
    fn application_card_rows_do_not_depend_on_data() {
        use crate::network::types::{
            ApplicationProtocol, DnsInfo, DnsQueryType, FtpInfo, FtpMessageType, HttpsInfo,
            QuicInfo, SshConnectionState, SshInfo,
        };

        let app = test_app();
        let full = |matcher: fn(&ApplicationProtocol) -> bool| {
            dpi_variants_full()
                .into_iter()
                .find(matcher)
                .expect("fixture variant")
        };

        let pairs: Vec<(&str, Connection, Connection)> = vec![
            (
                "HTTPS",
                dpi_details_connection(full(|v| matches!(v, ApplicationProtocol::Https(_)))),
                dpi_details_connection(ApplicationProtocol::Https(HttpsInfo { tls_info: None })),
            ),
            (
                "QUIC",
                dpi_details_connection(full(|v| matches!(v, ApplicationProtocol::Quic(_)))),
                dpi_details_connection(ApplicationProtocol::Quic(Box::new(QuicInfo::new(
                    0xdead_beef,
                )))),
            ),
            (
                "SSH",
                dpi_details_connection(full(|v| matches!(v, ApplicationProtocol::Ssh(_)))),
                dpi_details_connection(ApplicationProtocol::Ssh(SshInfo {
                    version: None,
                    client_software: None,
                    server_software: None,
                    connection_state: SshConnectionState::Banner,
                    algorithms: Vec::new(),
                    auth_method: None,
                })),
            ),
            (
                "FTP",
                dpi_details_connection(full(|v| matches!(v, ApplicationProtocol::Ftp(_)))),
                dpi_details_connection(ApplicationProtocol::Ftp(FtpInfo {
                    message_type: FtpMessageType::Request,
                    command: None,
                    args: None,
                    response_code: None,
                    response_message: None,
                    username: None,
                    server_software: None,
                    system_type: None,
                })),
            ),
            (
                "DNS",
                dpi_details_connection(full(|v| matches!(v, ApplicationProtocol::Dns(_)))),
                dpi_details_connection(ApplicationProtocol::Dns(DnsInfo {
                    query_name: Some("example.com".to_string()),
                    query_type: Some(DnsQueryType::A),
                    response_ips: Vec::new(),
                    is_response: false,
                    txid: 0x0001,
                    rcode: None,
                    nodata: None,
                })),
            ),
            (
                "ARP",
                arp_details_connection(true),
                arp_details_connection(false),
            ),
        ];

        for (name, full_conn, empty_conn) in pairs {
            let render_one = |conn: Connection| {
                let connections = vec![conn];
                app.set_connections_snapshot_for_test(connections.clone());
                render_details(&app, &connections, 0)
            };
            let full_labels = application_card_labels(&render_one(full_conn));
            let empty_labels = application_card_labels(&render_one(empty_conn));
            assert!(
                full_labels.len() > 1,
                "{name}: the card must render labeled rows"
            );
            assert_eq!(
                full_labels, empty_labels,
                "{name}: the Application card labels must not depend on data availability"
            );
        }
    }

    /// Snapshot of one Details render per reworked Application card, so the
    /// exact row sets (placeholders included) are pinned and reviewable.
    /// The name is explicit because the assertion runs inside this shared
    /// helper, where insta cannot derive a per-test name.
    fn assert_details_snapshot(name: &str, conn: Connection) {
        let app = test_app();
        let connections = vec![conn];
        app.set_connections_snapshot_for_test(connections.clone());
        let output = render_details(&app, &connections, 0);
        insta::with_settings!({
            filters => time_filters(),
        }, {
            insta::assert_snapshot!(name, output);
        });
    }

    #[test]
    fn details_tab_http_application_card() {
        use crate::network::types::ApplicationProtocol;
        let http = dpi_variants_full()
            .into_iter()
            .find(|v| matches!(v, ApplicationProtocol::Http(_)))
            .expect("HTTP fixture");
        assert_details_snapshot(
            "details_tab_http_application_card",
            dpi_details_connection(http),
        );
    }

    #[test]
    fn details_tab_https_without_tls_info() {
        use crate::network::types::{ApplicationProtocol, HttpsInfo};
        assert_details_snapshot(
            "details_tab_https_without_tls_info",
            dpi_details_connection(ApplicationProtocol::Https(HttpsInfo { tls_info: None })),
        );
    }

    #[test]
    fn details_tab_ssh_application_card() {
        use crate::network::types::ApplicationProtocol;
        let ssh = dpi_variants_full()
            .into_iter()
            .find(|v| matches!(v, ApplicationProtocol::Ssh(_)))
            .expect("SSH fixture");
        assert_details_snapshot(
            "details_tab_ssh_application_card",
            dpi_details_connection(ssh),
        );
    }

    #[test]
    fn details_tab_dns_response_application_card() {
        use crate::network::types::ApplicationProtocol;
        let dns = dpi_variants_full()
            .into_iter()
            .find(|v| matches!(v, ApplicationProtocol::Dns(_)))
            .expect("DNS fixture");
        assert_details_snapshot(
            "details_tab_dns_response_application_card",
            dpi_details_connection(dns),
        );
    }

    #[test]
    fn details_tab_ntp_application_card() {
        use crate::network::types::ApplicationProtocol;
        let ntp = dpi_variants_full()
            .into_iter()
            .find(|v| matches!(v, ApplicationProtocol::Ntp(_)))
            .expect("NTP fixture");
        assert_details_snapshot(
            "details_tab_ntp_application_card",
            dpi_details_connection(ntp),
        );
    }

    #[test]
    fn details_tab_icmp_echo_application_card() {
        assert_details_snapshot(
            "details_tab_icmp_echo_application_card",
            icmp_echo_details_connection(),
        );
    }

    #[test]
    fn details_tab_icmpv6_ndp_application_card() {
        assert_details_snapshot(
            "details_tab_icmpv6_ndp_application_card",
            icmpv6_ndp_details_connection(),
        );
    }

    #[test]
    fn details_tab_igmp_application_card() {
        assert_details_snapshot(
            "details_tab_igmp_application_card",
            igmp_details_connection(),
        );
    }

    #[test]
    fn details_tab_arp_application_card() {
        assert_details_snapshot(
            "details_tab_arp_application_card",
            arp_details_connection(true),
        );
    }
}
