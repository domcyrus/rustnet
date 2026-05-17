//! Terminal user interface built on `ratatui` + `crossterm`: tabbed
//! layout (overview, connections, interfaces, details), sortable tables
//! with adjustable columns, sparkline/chart bandwidth widgets, and
//! keyboard-driven filter and navigation.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::Color,
    symbols,
    text::{Line, Span},
    widgets::{Block, Borders, Cell},
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
    details::DetailsTab, graph::GraphTab, help::HelpTab, interfaces::InterfacesTab,
    overview::OverviewTab,
};

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
    ClickAction, ClickableRegions, GroupedRow, SortColumn, UIState, compute_grouped_rows,
    compute_scroll_offset,
};

mod sorting;
pub use sorting::sort_connections;

mod clipboard;
pub use clipboard::copy_to_clipboard;

mod component;
pub use component::{Component, DrawContext as ComponentContext};

mod theme;

/// Standard panel chrome: rounded magenta border + title.
/// Single source of truth for every framed pane in the UI.
pub(crate) fn panel_block<'a, T: Into<Line<'a>>>(title: T) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_set(symbols::border::ROUNDED)
        .border_style(theme::fg(theme::border()))
        .title(title)
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
/// Mirrors the palette used in `draw_app_distribution`.
pub(crate) fn dpi_color(app: &crate::network::types::ApplicationProtocol) -> Color {
    use crate::network::types::ApplicationProtocol as AP;
    match app {
        AP::Https(_) => theme::proto_https(),
        AP::Quic(_) => theme::proto_quic(),
        AP::Http(_) => theme::proto_http(),
        AP::Dns(_) | AP::Mdns(_) | AP::Llmnr(_) => theme::proto_dns(),
        AP::Ssh(_) => theme::proto_ssh(),
        _ => theme::field_application(),
    }
}

/// Build a right-aligned bandwidth `Line` with rx/tx colored independently:
/// "{rx}↓/{tx}↑" where the rx half is green (rx) and the tx half is blue (tx).
pub(crate) fn bandwidth_line<'a>(rx_text: String, tx_text: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(rx_text, theme::fg(theme::rx())),
        Span::raw("↓/"),
        Span::styled(tx_text, theme::fg(theme::tx())),
        Span::raw("↑"),
    ])
    .right_aligned()
}

/// Status indicator cell: filled dot for active connections (green/yellow/red
/// by staleness), hollow dot for historic. Dual-encodes status via shape so
/// the cue still works in NO_COLOR mode and for colorblind users.
pub(crate) fn status_indicator_cell(conn: &Connection) -> Cell<'static> {
    let (glyph, color) = if conn.is_historic {
        ("○", theme::muted())
    } else {
        let staleness = conn.staleness_ratio();
        if staleness >= 0.90 {
            ("●", theme::err())
        } else if staleness >= 0.75 {
            ("●", theme::warn())
        } else {
            ("●", theme::ok())
        }
    };
    Cell::from(glyph).style(theme::fg(color))
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

    // If still loading, show loading screen
    if app.is_loading() {
        draw_loading_screen(f);
        return Ok(());
    }

    let chunks = if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tabs
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Filter input area
                Constraint::Length(1), // Status bar
            ])
            .split(f.area())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Tabs
                Constraint::Min(0),    // Content
                Constraint::Length(1), // Status bar
            ])
            .split(f.area())
    };

    draw_tabs(f, ui_state, chunks[0], click_regions);

    let content_area = chunks[1];
    let (filter_area, status_area) = if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
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
        2 => InterfacesTab.draw(f, content_area, &comp_ctx, click_regions)?,
        3 => GraphTab.draw(f, content_area, &comp_ctx, click_regions)?,
        4 => HelpTab.draw(f, content_area, &comp_ctx, click_regions)?,
        _ => {}
    }

    if let Some(filter_area) = filter_area {
        draw_filter_input(f, ui_state, filter_area);
    }

    draw_status_bar(f, ui_state, connections.len(), status_area);

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
        assert_eq!(CreatedAt.next(false), Protocol);
        assert_eq!(Protocol.next(false), LocalAddress);
        assert_eq!(LocalAddress.next(false), RemoteAddress);
        assert_eq!(RemoteAddress.next(false), State); // Skips Location
        assert_eq!(State.next(false), Service);
        assert_eq!(Service.next(false), Application);
        assert_eq!(Application.next(false), BandwidthTotal);
        assert_eq!(BandwidthTotal.next(false), Process);
        assert_eq!(Process.next(false), CreatedAt); // Cycles back
    }

    #[test]
    fn test_sort_column_cycle_with_location() {
        use SortColumn::*;

        // With GeoIP, Location appears between RemoteAddress and State
        assert_eq!(RemoteAddress.next(true), Location);
        assert_eq!(Location.next(true), State);
        // Other transitions unchanged
        assert_eq!(CreatedAt.next(true), Protocol);
        assert_eq!(State.next(true), Service);
    }

    #[test]
    fn test_sort_column_default_directions() {
        use SortColumn::*;

        // Bandwidth should default to descending (false)
        assert!(!BandwidthTotal.default_direction());

        // Everything else should default to ascending (true)
        assert!(Process.default_direction());
        assert!(LocalAddress.default_direction());
        assert!(RemoteAddress.default_direction());
        assert!(Location.default_direction());
        assert!(Application.default_direction());
        assert!(Service.default_direction());
        assert!(State.default_direction());
        assert!(Protocol.default_direction());
        assert!(CreatedAt.default_direction());
    }

    #[test]
    fn test_ui_state_cycle_sort_column() {
        let mut ui_state = UIState::default();

        // Default state
        assert_eq!(ui_state.sort_column, SortColumn::CreatedAt);
        assert!(ui_state.sort_ascending);

        // Cycle to Protocol - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::Protocol);
        assert!(ui_state.sort_ascending); // Protocol defaults to ascending

        // Cycle to LocalAddress - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::LocalAddress);
        assert!(ui_state.sort_ascending);

        // Cycle to RemoteAddress - should reset to ascending
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::RemoteAddress);
        assert!(ui_state.sort_ascending);

        // Skip ahead to Application
        ui_state.cycle_sort_column(); // State
        ui_state.cycle_sort_column(); // Service
        ui_state.cycle_sort_column(); // Application
        assert_eq!(ui_state.sort_column, SortColumn::Application);
        assert!(ui_state.sort_ascending);

        // Cycle to BandwidthTotal - should reset to descending
        ui_state.cycle_sort_column();
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
        assert_eq!(Protocol.display_name(), "Protocol");
    }

    #[test]
    fn test_bandwidth_sort_states() {
        let mut ui_state = UIState::default();

        // Start from default
        assert_eq!(ui_state.sort_column, SortColumn::CreatedAt);
        assert!(ui_state.sort_ascending);

        // Cycle through columns to reach BandwidthTotal
        // CreatedAt -> Protocol -> LocalAddress -> RemoteAddress -> State -> Service -> Application -> BandwidthTotal
        for _ in 0..7 {
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

        // Cycle to Process (next after BandwidthTotal)
        ui_state.cycle_sort_column();
        assert_eq!(ui_state.sort_column, SortColumn::Process);
        assert!(
            ui_state.sort_ascending,
            "Process should default to ascending"
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
        let output = render(80, 20, draw_loading_screen);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn help_tab() {
        use crate::ui::tabs::help::draw_help;
        let output = render(100, 50, |f| {
            draw_help(f, f.area()).expect("draw_help");
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
        let output = render(80, 3, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_details_active() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 3, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn tabs_bar_help_active() {
        let ui_state = UIState {
            selected_tab: 4,
            ..Default::default()
        };
        let mut regions = ClickableRegions::default();
        let output = render(80, 3, |f| draw_tabs(f, &ui_state, f.area(), &mut regions));
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
        let output = render(80, 3, |f| draw_filter_input(f, &ui_state, f.area()));
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
        let output = render(80, 3, |f| draw_filter_input(f, &ui_state, f.area()));
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
        let output = render(80, 3, |f| draw_filter_input(f, &ui_state, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_overview_default() {
        let ui_state = UIState::default();
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 42, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_details_tab() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 42, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_help_tab() {
        let ui_state = UIState {
            selected_tab: 4,
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 0, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_filtered() {
        let ui_state = UIState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 7, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_quit_confirmation() {
        let ui_state = UIState {
            quit_confirmation: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 42, f.area()));
        insta::assert_snapshot!(output);
    }

    #[test]
    fn status_bar_clear_confirmation() {
        let ui_state = UIState {
            clear_confirmation: true,
            ..Default::default()
        };
        let output = render(120, 1, |f| draw_status_bar(f, &ui_state, 42, f.area()));
        insta::assert_snapshot!(output);
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
    use crate::network::interface_stats::{InterfaceRates, InterfaceStats};
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
            resolve_dns: false,
            show_ptr_lookups: false,
            geoip_country_path: None,
            geoip_asn_path: None,
            geoip_city_path: None,
            disable_geoip: true,
        }
    }

    fn test_app() -> App {
        let app = App::new(test_config()).expect("App::new in test_config");
        app.set_loading_for_test(false);
        app.set_current_interface_for_test(Some("eth0".to_string()));
        app
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

    // Overview snapshots are intentionally omitted from Phase 1: the
    // stats sidebar renders a Security panel whose text comes from
    // platform-specific code paths (Seatbelt on macOS, Landlock on
    // Linux, Restricted Token on Windows) plus the running user's UID,
    // making byte-stable snapshots non-portable. Once Phase 2 splits
    // the Security panel into its own function we can snapshot it with
    // a stub `SandboxInfo`, then add overview snapshots back.

    #[test]
    fn details_tab_tcp_https() {
        let app = test_app();
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

    #[test]
    fn interfaces_tab() {
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
            selected_tab: 2, // Interfaces
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
            .expect("draw interfaces");
        });

        insta::with_settings!({
            filters => time_filters(),
        }, {
            insta::assert_snapshot!(output);
        });
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
