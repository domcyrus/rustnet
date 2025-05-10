use anyhow::Result;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
    Frame, Terminal as RatatuiTerminal,
};
// Removed unused import: use std::collections::HashMap;
use std::net::SocketAddr; // Import SocketAddr

use crate::app::{App, DetailFocusField, ViewMode}; // Added DetailFocusField
use crate::network::Protocol;

pub type Terminal<B> = RatatuiTerminal<B>;

/// Set up the terminal for the TUI application
pub fn setup_terminal<B: ratatui::backend::Backend>(backend: B) -> Result<Terminal<B>> {
    let mut terminal = RatatuiTerminal::new(backend)?;
    terminal.clear()?;
    terminal.hide_cursor()?;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    Ok(terminal)
}

/// Restore the terminal to its original state
pub fn restore_terminal<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()> {
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Draw the UI
pub fn draw(f: &mut Frame, app: &mut App) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Status bar
        ])
        .split(f.size()); // Changed from f.area() to f.size()

    draw_tabs(f, app, chunks[0]);

    match app.mode {
        ViewMode::Overview => draw_overview(f, app, chunks[1])?,
        ViewMode::ConnectionDetails => draw_connection_details(f, app, chunks[1])?,
        ViewMode::Help => draw_help(f, app, chunks[1])?,
    }

    draw_status_bar(f, app, chunks[2]);

    Ok(())
}

/// Draw mode tabs
fn draw_tabs(f: &mut Frame, app: &App, area: Rect) {
    let titles = vec![
        Span::styled(app.i18n.get("overview"), Style::default().fg(Color::Green)),
        Span::styled(
            app.i18n.get("connections"),
            Style::default().fg(Color::Green),
        ),
        Span::styled(app.i18n.get("help"), Style::default().fg(Color::Green)),
    ];

    let tabs = Tabs::new(titles.into_iter().map(Line::from).collect::<Vec<_>>())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("rustnet")),
        )
        .select(match app.mode {
            ViewMode::Overview => 0,
            ViewMode::ConnectionDetails => 1,
            ViewMode::Help => 2,
        })
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        );

    f.render_widget(tabs, area);
}

/// Draw the overview mode
fn draw_overview(f: &mut Frame, app: &mut App, area: Rect) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    draw_connections_list(f, app, chunks[0]);
    draw_side_panel(f, app, chunks[1])?;

    Ok(())
}

/// Draw connections list
fn draw_connections_list(f: &mut Frame, app: &mut App, area: Rect) {
    let widths = [
        Constraint::Length(6),  // Protocol
        Constraint::Length(28), // Local Address
        Constraint::Length(28), // Remote Address
        Constraint::Length(12), // State
        Constraint::Length(10), // Service
        Constraint::Length(22), // Bandwidth (Down/Up) - Increased Width
        Constraint::Min(10),    // Process
    ];

    let header_cells = [
        "Proto",
        "Local Address",
        "Remote Address",
        "State",
        "Service",
        "Down / Up", // Updated Header
        "Process",
    ]
    .iter()
    .map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let mut rows = Vec::new();
    // Collect addresses to format to avoid borrowing issues with app.format_socket_addr
    let addresses_to_format: Vec<(SocketAddr, SocketAddr)> = app
        .connections
        .iter()
        .map(|conn| (conn.local_addr, conn.remote_addr))
        .collect();

    let mut formatted_addresses = Vec::new();
    for (local_addr, remote_addr) in addresses_to_format {
        let local_display = app.format_socket_addr(local_addr);
        let remote_display = app.format_socket_addr(remote_addr);
        formatted_addresses.push((local_display, remote_display));
    }

    for (idx, conn) in app.connections.iter().enumerate() {
        let pid_str = conn
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());

        let process_str = conn.process_name.clone().unwrap_or_else(|| "-".to_string());
        let process_display = format!("{} ({})", process_str, pid_str);

        let (local_display, remote_display) = formatted_addresses[idx].clone();
        let service_display = conn.service_name.clone().unwrap_or_else(|| "-".to_string());

        let incoming_rate_str = format_rate_from_bps(conn.current_incoming_rate_bps);
        let outgoing_rate_str = format_rate_from_bps(conn.current_outgoing_rate_bps);
        let bandwidth_display = format!("{} / {}", incoming_rate_str, outgoing_rate_str);

        let cells = [
            Cell::from(conn.protocol.to_string()),
            Cell::from(local_display),
            Cell::from(remote_display),
            Cell::from(conn.state.to_string()),
            Cell::from(service_display),
            Cell::from(bandwidth_display), // Updated Cell
            Cell::from(process_display),
        ];
        rows.push(Row::new(cells));
    }

    // Create table state with current selection
    let mut state = ratatui::widgets::TableState::default();
    if !app.connections.is_empty() {
        state.select(Some(app.selected_connection_idx));
    }

    let connections = Table::new(rows, &widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("connections")),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    f.render_stateful_widget(connections, area, &mut state);
}

/// Draw side panel with stats
fn draw_side_panel(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Interface
            Constraint::Min(0),    // Summary stats (takes remaining space)
        ])
        .split(area);

    let interface_text = format!(
        "{}: {}",
        app.i18n.get("interface"),
        app.config
            .interface
            .clone()
            .unwrap_or_else(|| app.i18n.get("default").to_string())
    );
    let interface_para = Paragraph::new(interface_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("network")),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(interface_para, chunks[0]);

    let tcp_count = app
        .connections
        .iter()
        .filter(|c| c.protocol == Protocol::TCP)
        .count();
    let udp_count = app
        .connections
        .iter()
        .filter(|c| c.protocol == Protocol::UDP)
        .count();
    let process_count = app.processes.len();

    let stats_text: Vec<Line> = vec![
        Line::from(format!(
            "{}: {}",
            app.i18n.get("tcp_connections"),
            tcp_count
        )),
        Line::from(format!(
            "{}: {}",
            app.i18n.get("udp_connections"),
            udp_count
        )),
        Line::from(format!(
            "{}: {}",
            app.i18n.get("total_connections"),
            app.connections.len()
        )),
        Line::from(format!("{}: {}", app.i18n.get("processes"), process_count)),
        Line::from(""), // Spacer
        Line::from(format!(
            "{}: {}",
            app.i18n.get("total_incoming"),
            format_rate_from_bps(
                app.connections
                    .iter()
                    .map(|c| c.current_incoming_rate_bps)
                    .sum()
            )
        )),
        Line::from(format!(
            "{}: {}",
            app.i18n.get("total_outgoing"),
            format_rate_from_bps(
                app.connections
                    .iter()
                    .map(|c| c.current_outgoing_rate_bps)
                    .sum()
            )
        )),
    ];

    let stats_para = Paragraph::new(stats_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("statistics")),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(stats_para, chunks[1]); // Render stats into the second chunk which now takes remaining space

    Ok(())
}

/// Draw connection details view
fn draw_connection_details(f: &mut Frame, app: &mut App, area: Rect) -> Result<()> {
    if app.connections.is_empty() {
        let text = Paragraph::new(app.i18n.get("no_connections"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(app.i18n.get("connection_details")),
            )
            .style(Style::default().fg(Color::Red))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, area);
        return Ok(());
    }

    let conn_idx = app.selected_connection_idx;
    let local_addr_to_format = app.connections[conn_idx].local_addr;
    let remote_addr_to_format = app.connections[conn_idx].remote_addr;

    // Format addresses before further immutable borrows of app.connections
    let local_display = app.format_socket_addr(local_addr_to_format);
    let remote_display = app.format_socket_addr(remote_addr_to_format);

    let conn = &app.connections[conn_idx]; // Now we can immutably borrow again

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mut details_text: Vec<Line> = Vec::new();

    // Styles for focused IP
    let local_ip_style = if app.detail_focus == DetailFocusField::LocalIp {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let remote_ip_style = if app.detail_focus == DetailFocusField::RemoteIp {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("protocol")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.protocol.to_string()),
    ]));

    // Use pre-formatted addresses
    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("local_address")),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(local_display, local_ip_style), // Apply style
    ]));

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("remote_address")),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(remote_display, remote_ip_style), // Apply style
    ]));

    if app.show_locations && !conn.remote_addr.ip().is_unspecified() {
        // Commented out private field access
    }

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("state")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.state.to_string()),
    ]));

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("process")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.process_name.clone().unwrap_or_else(|| "-".to_string())),
    ]));

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("pid")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(
            conn.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
    ]));

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("age")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!("{:?}", conn.age())),
    ]));

    details_text.push(Line::from("")); // Spacer
    details_text.push(Line::from(Span::styled(
        "Use Up/Down to select IP, 'c' to copy.", // Hint text
        Style::default().fg(Color::DarkGray),
    )));

    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("connection_details")),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });

    f.render_widget(details, chunks[0]);

    let mut traffic_text: Vec<Line> = Vec::new();
    traffic_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("bytes_sent")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format_bytes(conn.bytes_sent)),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("bytes_received")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format_bytes(conn.bytes_received)),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("packets_sent")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.packets_sent.to_string()),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("packets_received")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.packets_received.to_string()),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("last_activity")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!("{:?}", conn.idle_time())),
    ]));

    let traffic = Paragraph::new(traffic_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("traffic")),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });

    f.render_widget(traffic, chunks[1]);

    Ok(())
}

/// Draw help screen
fn draw_help(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
    let help_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "RustNet ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(app.i18n.get("help_intro")),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("q, Ctrl+C ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_quit")),
        ]),
        Line::from(vec![
            Span::styled("r ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_refresh")),
        ]),
        Line::from(vec![
            Span::styled("↑/k, ↓/j ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_navigate")),
        ]),
        Line::from(vec![
            Span::styled("Enter ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_select")),
        ]),
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_back")),
        ]),
        Line::from(vec![
            Span::styled("l ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_toggle_location")),
        ]),
        Line::from(vec![
            Span::styled("d ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_toggle_dns")),
        ]),
        Line::from(vec![
            Span::styled("h ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_toggle_help")),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+D ", Style::default().fg(Color::Yellow)),
            Span::raw(app.i18n.get("help_dump_connections")),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("help")),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true })
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    Ok(())
}

/// Draw status bar
fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let status = format!(
        "{} | {} | {}",
        app.i18n.get("press_h_for_help"),
        format!("{}: {}", app.i18n.get("language"), app.config.language),
        format!("{}: {}", app.i18n.get("connections"), app.connections.len())
    );

    let status_bar = Paragraph::new(status)
        .style(Style::default().fg(Color::White).bg(Color::Blue))
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(status_bar, area);
}

// format_rate function removed as it's no longer used.
// format_rate_from_bps is now the primary function for formatting rates.

/// Format rate (given as f64 bits_per_second) to human readable form (Kbps, Mbps, etc.)
fn format_rate_from_bps(bits_per_second: f64) -> String {
    const KBPS: f64 = 1000.0; // Kilobits per second
    const MBPS: f64 = KBPS * 1000.0; // Megabits per second
    const GBPS: f64 = MBPS * 1000.0; // Gigabits per second

    if bits_per_second.is_nan() || bits_per_second.is_infinite() {
        return "-".to_string();
    }

    if bits_per_second >= GBPS {
        format!("{:.2} Gbps", bits_per_second / GBPS)
    } else if bits_per_second >= MBPS {
        format!("{:.2} Mbps", bits_per_second / MBPS)
    } else if bits_per_second >= KBPS {
        format!("{:.2} Kbps", bits_per_second / KBPS)
    } else if bits_per_second >= 0.0 { // Show bps for small rates or zero
        format!("{:.0} bps", bits_per_second)
    } else {
        // Should not happen if input is always >= 0, but as a fallback
        "-".to_string()
    }
}

/// Format bytes to human readable form (KB, MB, etc.)
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
