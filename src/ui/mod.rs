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
    filter_input::draw_filter_input, loading::draw_loading_screen, status_bar::draw_status_bar,
    tabs_bar::draw_tabs,
};

mod tabs;
use tabs::{
    activity::ActivityTab, details::DetailsTab, graph::GraphTab, help::HelpTab,
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
/// Details / Activity / Graph / Help while a filter is being
/// edited.
pub fn dispatch_key(
    tab: usize,
    key: crossterm::event::KeyEvent,
    ctx: &mut HandlerContext<'_>,
) -> Option<Vec<Effect>> {
    if ctx.ui_state.filter_mode {
        return OverviewTab.handle_key(key, ctx);
    }
    match tab {
        0 => OverviewTab.handle_key(key, ctx),
        1 => DetailsTab.handle_key(key, ctx),
        2 => ActivityTab.handle_key(key, ctx),
        3 => GraphTab.handle_key(key, ctx),
        4 => HelpTab.handle_key(key, ctx),
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
    match tab {
        0 => OverviewTab.handle_mouse(mouse, ctx),
        1 => DetailsTab.handle_mouse(mouse, ctx),
        2 => ActivityTab.handle_mouse(mouse, ctx),
        3 => GraphTab.handle_mouse(mouse, ctx),
        4 => HelpTab.handle_mouse(mouse, ctx),
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
pub use state::{
    ActivityDirection, ActivitySort, ClickAction, ClickableRegions, GroupedRow, PaneScroll,
    SortColumn, UIState, compute_grouped_rows, compute_scroll_offset, process_group_label,
};
pub(crate) use widgets::tabs_bar::{HELP_TAB_INDEX, TAB_COUNT};

mod connection_table;

mod sorting;
pub use sorting::sort_connections;

mod clipboard;
pub use clipboard::copy_to_clipboard;

mod actions;
pub use actions::{
    clear_all_with_confirmation, try_handle_connection_nav, try_handle_pane_scroll,
    try_handle_pane_wheel,
};

mod component;
pub use component::{Component, DrawContext as ComponentContext, Effect, HandlerContext};

mod effects;
pub use effects::apply_effects;

mod theme;
pub use theme::{ThemePreset, set_preset as set_theme_preset};

/// Standard panel chrome: rounded border + title. Kept for the few
/// views that still frame themselves (Help reference card, loading
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
/// Classic preset mirrors the palette used in `draw_app_distribution`;
/// the muted preset renders detected applications as plain content so
/// the `proto_*` palette stays a chart-only encoding.
pub(crate) fn dpi_color(app: &crate::network::types::ApplicationProtocol) -> Color {
    use crate::network::types::ApplicationProtocol as AP;
    if !theme::is_classic() {
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

    let chunks = if ui_state.filter_mode || ui_state.has_active_filter() {
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

    draw_tabs(f, ui_state, chunks[0], click_regions);

    let content_area = chunks[1];
    let (filter_area, status_area) = if ui_state.filter_mode || ui_state.has_active_filter() {
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
        4 => HelpTab.draw(f, content_area, &comp_ctx, click_regions)?,
        _ => {}
    }

    if let Some(filter_area) = filter_area {
        draw_filter_input(f, ui_state, filter_area);
    }

    draw_status_bar(
        f,
        ui_state,
        connections.len(),
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
    fn help_tab() {
        use crate::ui::tabs::help::draw_help;
        let ui_state = UIState::default();
        let output = render(100, 50, |f| {
            draw_help(f, &ui_state, f.area()).expect("draw_help");
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_overview_active() {
        let ui_state = UIState {
            selected_tab: 0,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 2, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_details_active() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 2, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_help_active() {
        let ui_state = UIState {
            selected_tab: 4,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 2, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
        insta::assert_snapshot!(output);
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
    fn filter_input_persisted() {
        let ui_state = UIState {
            filter_mode: false,
            filter_query: "tcp port:443".to_string(),
            filter_cursor_position: 0,
            ..Default::default()
        };
        let output = render(80, 1, |f| draw_filter_input(f, &ui_state, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_overview_default() {
        let ui_state = UIState::default();
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, 42, None, f.area())
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
            draw_status_bar(f, &ui_state, 42, None, f.area())
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
            draw_status_bar(f, &ui_state, 42, None, f.area())
        });
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_help_tab() {
        let ui_state = UIState {
            selected_tab: 4,
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 0, None, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_filtered() {
        let ui_state = UIState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 7, None, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_quit_confirmation() {
        let ui_state = UIState {
            quit_confirmation: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| {
            draw_status_bar(f, &ui_state, 42, None, f.area())
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
            draw_status_bar(f, &ui_state, 42, None, f.area())
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
                0,
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
                0,
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

    #[test]
    fn full_page_shows_capture_error() {
        let app = test_app();
        app.set_capture_error_for_test(Some("Capture stopped: The interface disappeared."));
        let ui_state = UIState {
            show_system_panel: false,
            ..Default::default()
        };
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(100, 16, |f| {
            draw(f, &app, &ui_state, &[], None, &stats, &mut click_regions)
                .expect("draw Overview with capture error");
        });

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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(80, 16, |f| {
            draw(f, &app, &ui_state, &[], None, &stats, &mut click_regions)
                .expect("draw Overview with a long capture error");
        });

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
        let ui_state = UIState {
            grouping_enabled: grouped,
            show_system_panel: false,
            visible_rows: 18,
            ..Default::default()
        };
        let grouped_rows =
            grouped.then(|| compute_grouped_rows(&connections, &ui_state.expanded_groups));
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        render(140, 26, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                grouped_rows.as_deref(),
                &stats,
                &mut click_regions,
            )
            .expect("draw overview");
        })
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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw overview statistics");
        });

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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &filtered,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw filtered overview statistics");
        });

        assert!(output.contains("Live Connections · 1 shown"));
        assert!(output.contains("Processes: 4"));
        assert!(output.contains("Total Connections: 4"));
    }

    /// One observed ARP reply between the gateway and this host. Seeds the
    /// tracker's neighbor cache so Details can label on-link addresses with
    /// MAC + vendor. The fixture's remote (140.82.121.4) is public and never
    /// ARPs, so no "Remote MAC" row is rendered for it.
    fn gateway_arp_reply() -> crate::network::parser::ParsedPacket {
        use crate::network::types::{AddrKind, ArpInfo, ArpOperation};

        let gateway = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        crate::network::parser::ParsedPacket {
            protocol: Protocol::Arp,
            local_addr: SocketAddr::new(host, 0),
            remote_addr: SocketAddr::new(gateway, 0),
            local_addr_kind: AddrKind::Unicast,
            remote_addr_kind: AddrKind::Unicast,
            remote_is_gateway: false,
            tcp_header: None,
            protocol_state: ProtocolState::Arp(ArpInfo {
                operation: ArpOperation::Reply,
                sender_mac: "04:d9:f5:c5:ed:e8".to_string(),
                sender_ip: gateway,
                target_mac: "68:5e:dd:09:15:5e".to_string(),
                target_ip: host,
                sender_vendor: Some("ASUSTek COMPUTER INC.".to_string()),
                target_vendor: Some("Apple, Inc.".to_string()),
            }),
            is_outgoing: false,
            packet_len: 42,
            dpi_result: None,
            process_name: None,
            process_id: None,
        }
    }

    #[test]
    fn details_tab_tcp_https() {
        let app = test_app();
        app.ingest_packet_for_test(&gateway_arp_reply());
        let connections = sample_connections();
        app.set_connections_snapshot_for_test(connections.clone());

        let ui_state = UIState {
            selected_tab: 1, // Details
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });

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
            last_update_time: std::time::Instant::now(),
        });

        app.set_connections_snapshot_for_test(connections.clone());
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1, // Details
            selected_connection_key: Some(connections[1].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });

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
        let tcp_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let tcp_output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &tcp_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });
        let heading_row = |render: &str, heading: &str| {
            render
                .lines()
                .position(|line| line.contains(heading))
                .unwrap_or_else(|| panic!("missing {heading}"))
        };
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
            last_update_time: std::time::Instant::now(),
        });

        app.set_connections_snapshot_for_test(connections.clone());
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1, // Details
            selected_connection_key: Some(connections[1].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });

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
        let tcp_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let tcp_output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &tcp_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });
        let heading_row = |render: &str, heading: &str| {
            render
                .lines()
                .position(|line| line.contains(heading))
                .unwrap_or_else(|| panic!("missing {heading}"))
        };
        assert_eq!(
            heading_row(&output, "Traffic Statistics"),
            heading_row(&tcp_output, "Traffic Statistics"),
            "Traffic Statistics moved between the DNS and TCP records"
        );
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
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw ping details");
        });

        assert!(output.contains("Ping RTT") && output.contains("8.7ms"));
        assert!(output.contains("Last Sequence") && output.contains("42"));
        assert!(output.contains("Paired by echo ID and sequence"));
        assert!(!output.contains("No transport metrics for this protocol"));
    }

    /// Inbound pings are answered here but timed by the remote sender, so the
    /// responder view drops the Ping RTT row instead of showing a permanent
    /// placeholder.
    #[test]
    fn details_tab_inbound_ping_hides_rtt_row() {
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
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw inbound ping details");
        });

        assert!(!output.contains("Ping RTT"));
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
            last_update_time: std::time::Instant::now(),
        });
        let connections = vec![stun];

        app.set_connections_snapshot_for_test(connections.clone());
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw stun details");
        });

        assert!(output.contains("STUN RTT") && output.contains("23.4ms"));
        assert!(output.contains("Last Message") && output.contains("Binding Success"));
        assert!(output.contains("Paired by 96-bit transaction ID"));
        assert!(!output.contains("No transport metrics for this protocol"));
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
            last_update_time: std::time::Instant::now(),
        });
        let connections = vec![ntp];

        app.set_connections_snapshot_for_test(connections.clone());
        let stats = app.get_stats();
        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw ntp details");
        });

        assert!(output.contains("NTP RTT") && output.contains("6.5ms"));
        assert!(output.contains("Stratum"));
        assert!(output.contains("Paired by originate timestamp echo"));
        assert!(!output.contains("No transport metrics for this protocol"));
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
        let stats = app.get_stats();

        let render_connections = |connections: &[Connection]| {
            let ui_state = UIState {
                selected_tab: 1,
                selected_connection_key: Some(connections[0].key()),
                ..Default::default()
            };
            let mut click_regions = ClickableRegions::default();
            render(140, 52, |f| {
                draw(
                    f,
                    &app,
                    &ui_state,
                    connections,
                    None,
                    &stats,
                    &mut click_regions,
                )
                .expect("draw details");
            })
        };

        connections[0].pid = None;
        let unattributed = render_connections(&connections);
        assert!(
            !unattributed.contains("Attribution"),
            "an unattributed connection must not render an empty Attribution card"
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

    /// Partial attribution is the common case off Linux: render the fields that
    /// resolved and leave the rest out entirely.
    #[test]
    fn details_tab_renders_partial_attribution() {
        use crate::network::types::MatchQuality;

        let app = test_app();
        let mut connections = sample_connections();
        connections[0].attribution_quality = Some(MatchQuality::ListenerSocket);
        app.set_connections_snapshot_for_test(connections.clone());
        let stats = app.get_stats();

        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        // 40 rows: the Attribution card must stay visible on a 40-row
        // terminal — unresolved MAC rows are omitted, not rendered as
        // placeholders, precisely so the dashboard column does not grow.
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });

        assert!(output.contains("Attribution"));
        assert!(output.contains("listener socket"));
        assert!(
            !output.contains("Executable"),
            "an unresolved executable must not leave a labelled blank row"
        );
        assert!(!output.contains("User "));
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
        let stats = app.get_stats();

        let ui_state = UIState {
            selected_tab: 1,
            selected_connection_key: Some(connections[0].key()),
            ..Default::default()
        };
        let mut click_regions = ClickableRegions::default();
        // 40 rows for the same reason as the partial-attribution test above.
        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw details");
        });

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
        let copied = (0..40u16)
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
        let stats = app.get_stats();

        let render_selected = |selected: usize| {
            let ui_state = UIState {
                selected_tab: 1,
                selected_connection_key: Some(connections[selected].key()),
                ..Default::default()
            };
            let mut click_regions = ClickableRegions::default();
            render(140, 40, |f| {
                draw(
                    f,
                    &app,
                    &ui_state,
                    &connections,
                    None,
                    &stats,
                    &mut click_regions,
                )
                .expect("draw details");
            })
        };

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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(140, 30, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw Activity interface details");
        });

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
                sampled_for: Duration::from_secs(2),
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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        render(150, 40, |f| {
            draw(
                f,
                app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw process Activity");
        })
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
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(140, 40, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw graph");
        });

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
        let connections: Vec<Connection> = Vec::new();
        let ui_state = UIState::default();
        let stats = app.get_stats();
        let mut click_regions = ClickableRegions::default();

        let output = render(80, 20, |f| {
            draw(
                f,
                &app,
                &ui_state,
                &connections,
                None,
                &stats,
                &mut click_regions,
            )
            .expect("draw loading");
        });

        insta::assert_snapshot!(output);
    }
}
