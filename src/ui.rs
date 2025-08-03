use anyhow::Result;
use ratatui::{
    Frame, Terminal as RatatuiTerminal,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs, Wrap},
};

use crate::app::{App, AppStats};
use crate::network::types::{Connection, Protocol};

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

/// UI state for managing the interface
pub struct UIState {
    pub selected_tab: usize,
    pub selected_connection_key: Option<String>,
    pub show_help: bool,
    pub quit_confirmation: bool,
    pub clipboard_message: Option<(String, std::time::Instant)>,
}

impl UIState {
    /// Get the current selected connection index, if any
    pub fn get_selected_index(&self, connections: &[Connection]) -> Option<usize> {
        if let Some(ref selected_key) = self.selected_connection_key {
            connections
                .iter()
                .position(|conn| conn.key() == *selected_key)
        } else if !connections.is_empty() {
            Some(0) // Default to first connection
        } else {
            None
        }
    }

    /// Set the selected connection to the one at the given index
    pub fn set_selected_by_index(&mut self, connections: &[Connection], index: usize) {
        if let Some(conn) = connections.get(index) {
            self.selected_connection_key = Some(conn.key());
        }
    }

    /// Move selection up by one position
    pub fn move_selection_up(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        if current_index > 0 {
            self.set_selected_by_index(connections, current_index - 1);
        } else {
            // Wrap around to the bottom
            self.set_selected_by_index(connections, connections.len() - 1);
        }
    }

    /// Move selection down by one position
    pub fn move_selection_down(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        if current_index < connections.len().saturating_sub(1) {
            self.set_selected_by_index(connections, current_index + 1);
        } else {
            // Wrap around to the top
            self.set_selected_by_index(connections, 0);
        }
    }

    /// Move selection up by one page
    pub fn move_selection_page_up(&mut self, connections: &[Connection], page_size: usize) {
        if connections.is_empty() {
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        if current_index >= page_size {
            self.set_selected_by_index(connections, current_index - page_size);
        } else {
            self.set_selected_by_index(connections, 0);
        }
    }

    /// Move selection down by one page
    pub fn move_selection_page_down(&mut self, connections: &[Connection], page_size: usize) {
        if connections.is_empty() {
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        let new_index = current_index + page_size;
        if new_index < connections.len() {
            self.set_selected_by_index(connections, new_index);
        } else {
            self.set_selected_by_index(connections, connections.len() - 1);
        }
    }

    /// Ensure we have a valid selection when connections list changes
    pub fn ensure_valid_selection(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            self.selected_connection_key = None;
            return;
        }

        // If no selection or selection is no longer valid, select first connection
        if self.selected_connection_key.is_none() || self.get_selected_index(connections).is_none()
        {
            self.set_selected_by_index(connections, 0);
        }
    }
}

impl Default for UIState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            show_help: false,
            quit_confirmation: false,
            clipboard_message: None,
        }
    }
}

/// Draw the UI
pub fn draw(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    connections: &[Connection],
    stats: &AppStats,
) -> Result<()> {
    // If still loading, show loading screen
    if app.is_loading() {
        draw_loading_screen(f);
        return Ok(());
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Content
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    draw_tabs(f, ui_state, chunks[0]);

    match ui_state.selected_tab {
        0 => draw_overview(f, ui_state, connections, stats, app, chunks[1])?,
        1 => draw_connection_details(f, ui_state, connections, chunks[1])?,
        2 => draw_help(f, chunks[1])?,
        _ => {}
    }

    draw_status_bar(f, ui_state, connections.len(), chunks[2]);

    Ok(())
}

/// Draw mode tabs
fn draw_tabs(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let titles = vec![
        Span::styled("Overview", Style::default().fg(Color::Green)),
        Span::styled("Details", Style::default().fg(Color::Green)),
        Span::styled("Help", Style::default().fg(Color::Green)),
    ];

    let tabs = Tabs::new(titles.into_iter().map(Line::from).collect::<Vec<_>>())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RustNet Monitor"),
        )
        .select(ui_state.selected_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Yellow),
        );

    f.render_widget(tabs, area);
}

/// Draw the overview mode
fn draw_overview(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    stats: &AppStats,
    app: &App,
    area: Rect,
) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    draw_connections_list(f, ui_state, connections, chunks[0]);
    draw_stats_panel(f, connections, stats, app, chunks[1])?;

    Ok(())
}

/// Draw connections list
fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
) {
    let widths = [
        Constraint::Length(4),  // Protocol (TCP/UDP fits in 4)
        Constraint::Length(18), // Local Address (slightly reduced)
        Constraint::Length(22), // Remote Address (slightly reduced)
        Constraint::Length(8),  // State (EST/LIS/etc fit in 8)
        Constraint::Length(8),  // Service (port names fit in 8)
        Constraint::Length(25), // DPI/Application (slightly reduced)
        Constraint::Length(12), // Bandwidth (slightly reduced)
        Constraint::Min(20),    // Process (much more space!)
    ];

    let header_cells = [
        "Pro", // Shortened
        "Local Address",
        "Remote Address",
        "State",
        "Service",
        "Application / Host", // More descriptive for DPI
        "Down/Up",            // Compressed
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

    let rows: Vec<Row> = connections
        .iter()
        .map(|conn| {
            let pid_str = conn
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());

            let process_str = conn.process_name.clone().unwrap_or_else(|| "-".to_string());
            let process_display = if conn.pid.is_some() {
                let full_display = format!("{} ({})", process_str, pid_str);
                // Truncate process display to fit in column (roughly 20+ chars available)
                if full_display.len() > 25 {
                    format!("{}...", &full_display[..22])
                } else {
                    full_display
                }
            } else {
                // Truncate process name if no PID
                if process_str.len() > 25 {
                    format!("{}...", &process_str[..22])
                } else {
                    process_str
                }
            };

            // Truncate service name to fit in 8 chars
            let service_display = conn.service_name.clone().unwrap_or_else(|| "-".to_string());
            let service_display = if service_display.len() > 8 {
                format!("{:.5}...", service_display)
            } else {
                service_display
            };

            // DPI/Application protocol display (enhanced for hostnames)
            let dpi_display = match &conn.dpi_info {
                Some(dpi) => {
                    match &dpi.application {
                        crate::network::types::ApplicationProtocol::Http(info) => {
                            if let Some(host) = &info.host {
                                // Limit hostname to 28 chars to fit in 30-char column
                                if host.len() > 28 {
                                    format!("HTTP {:.25}...", host)
                                } else {
                                    format!("HTTP {}", host)
                                }
                            } else {
                                "HTTP".to_string()
                            }
                        }
                        crate::network::types::ApplicationProtocol::Https(info) => {
                            if let Some(sni) = &info.sni {
                                // Limit SNI to 26 chars to fit "HTTPS " prefix
                                if sni.len() > 24 {
                                    format!("HTTPS {:.21}...", sni)
                                } else {
                                    format!("HTTPS {}", sni)
                                }
                            } else {
                                "HTTPS".to_string()
                            }
                        }
                        crate::network::types::ApplicationProtocol::Dns(info) => {
                            if let Some(query) = &info.query_name {
                                // Limit query to 26 chars to fit "DNS " prefix
                                if query.len() > 26 {
                                    format!("DNS {:.23}...", query)
                                } else {
                                    format!("DNS {}", query)
                                }
                            } else {
                                "DNS".to_string()
                            }
                        }
                        crate::network::types::ApplicationProtocol::Ssh => "SSH".to_string(),
                        crate::network::types::ApplicationProtocol::Quic => "QUIC".to_string(),
                    }
                }
                None => "-".to_string(),
            };

            // Compact bandwidth display to fit in 14 chars
            let incoming_rate = format_rate_compact(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate_compact(conn.current_outgoing_rate_bps);
            let bandwidth_display = format!("{}↓/{}↑", incoming_rate, outgoing_rate);

            let cells = [
                Cell::from(conn.protocol.to_string()),
                Cell::from(conn.local_addr.to_string()),
                Cell::from(conn.remote_addr.to_string()),
                Cell::from(conn.state()),
                Cell::from(service_display),
                Cell::from(dpi_display),
                Cell::from(bandwidth_display),
                Cell::from(process_display),
            ];
            Row::new(cells)
        })
        .collect();

    // Create table state with current selection
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_index(connections) {
        state.select(Some(selected_index));
    }

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Active Connections"),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");

    f.render_stateful_widget(connections_table, area, &mut state);
}

/// Draw stats panel
fn draw_stats_panel(
    f: &mut Frame,
    connections: &[Connection],
    stats: &AppStats,
    app: &App,
    area: Rect,
) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(10), // Connection stats (increased for interface line)
            Constraint::Min(0),     // Traffic stats
        ])
        .split(area);

    // Connection statistics
    let tcp_count = connections
        .iter()
        .filter(|c| c.protocol == Protocol::TCP)
        .count();
    let udp_count = connections
        .iter()
        .filter(|c| c.protocol == Protocol::UDP)
        .count();

    let interface_name = app
        .get_current_interface()
        .unwrap_or_else(|| "Unknown".to_string());

    let conn_stats_text: Vec<Line> = vec![
        Line::from(format!("Interface: {}", interface_name)),
        Line::from(""),
        Line::from(format!("TCP Connections: {}", tcp_count)),
        Line::from(format!("UDP Connections: {}", udp_count)),
        Line::from(format!("Total Connections: {}", connections.len())),
        Line::from(""),
        Line::from(format!(
            "Packets Processed: {}",
            stats
                .packets_processed
                .load(std::sync::atomic::Ordering::Relaxed)
        )),
        Line::from(format!(
            "Packets Dropped: {}",
            stats
                .packets_dropped
                .load(std::sync::atomic::Ordering::Relaxed)
        )),
    ];

    let conn_stats = Paragraph::new(conn_stats_text)
        .block(Block::default().borders(Borders::ALL).title("Statistics"))
        .style(Style::default().fg(Color::White));
    f.render_widget(conn_stats, chunks[0]);

    // Traffic statistics
    let total_incoming: f64 = connections
        .iter()
        .map(|c| c.current_incoming_rate_bps)
        .sum();
    let total_outgoing: f64 = connections
        .iter()
        .map(|c| c.current_outgoing_rate_bps)
        .sum();

    let traffic_stats_text: Vec<Line> = vec![
        Line::from(format!("Total Incoming: {}", format_rate(total_incoming))),
        Line::from(format!("Total Outgoing: {}", format_rate(total_outgoing))),
        Line::from(""),
        Line::from(format!(
            "Last Update: {:?} ago",
            stats.last_update.read().unwrap().elapsed()
        )),
    ];

    let traffic_stats = Paragraph::new(traffic_stats_text)
        .block(Block::default().borders(Borders::ALL).title("Traffic"))
        .style(Style::default().fg(Color::White));
    f.render_widget(traffic_stats, chunks[1]);

    Ok(())
}

/// Draw connection details view
fn draw_connection_details(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
) -> Result<()> {
    if connections.is_empty() {
        let text = Paragraph::new("No connections available")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Connection Details"),
            )
            .style(Style::default().fg(Color::Red))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, area);
        return Ok(());
    }

    let conn_idx = ui_state.get_selected_index(connections).unwrap_or(0);
    let conn = &connections[conn_idx];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Connection details
    let mut details_text: Vec<Line> = Vec::new();

    details_text.push(Line::from(vec![
        Span::styled("Protocol: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.protocol.to_string()),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("Local Address: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.local_addr.to_string()),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("Remote Address: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.remote_addr.to_string()),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("State: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.state()),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("Process: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.process_name.clone().unwrap_or_else(|| "-".to_string())),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("PID: ", Style::default().fg(Color::Yellow)),
        Span::raw(
            conn.pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
    ]));

    details_text.push(Line::from(vec![
        Span::styled("Service: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.service_name.clone().unwrap_or_else(|| "-".to_string())),
    ]));

    // Add DPI information
    match &conn.dpi_info {
        Some(dpi) => {
            details_text.push(Line::from(vec![
                Span::styled("Application: ", Style::default().fg(Color::Yellow)),
                Span::raw(dpi.application.to_string()),
            ]));

            // Add protocol-specific details
            match &dpi.application {
                crate::network::types::ApplicationProtocol::Http(info) => {
                    if let Some(method) = &info.method {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Method: ", Style::default().fg(Color::Cyan)),
                            Span::raw(method.clone()),
                        ]));
                    }
                    if let Some(path) = &info.path {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Path: ", Style::default().fg(Color::Cyan)),
                            Span::raw(path.clone()),
                        ]));
                    }
                    if let Some(status) = info.status_code {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Status: ", Style::default().fg(Color::Cyan)),
                            Span::raw(status.to_string()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Https(info) => {
                    if let Some(version) = &info.version {
                        details_text.push(Line::from(vec![
                            Span::styled("  TLS Version: ", Style::default().fg(Color::Cyan)),
                            Span::raw(format!("{:?}", version)),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Dns(info) => {
                    if let Some(query_type) = &info.query_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  DNS Type: ", Style::default().fg(Color::Cyan)),
                            Span::raw(format!("{:?}", query_type)),
                        ]));
                    }
                }
                _ => {}
            }
        }
        None => {
            details_text.push(Line::from(vec![
                Span::styled("Application: ", Style::default().fg(Color::Yellow)),
                Span::raw("-".to_string()),
            ]));
        }
    }

    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Connection Information"),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });

    f.render_widget(details, chunks[0]);

    // Traffic details
    let mut traffic_text: Vec<Line> = Vec::new();

    traffic_text.push(Line::from(vec![
        Span::styled("Bytes Sent: ", Style::default().fg(Color::Yellow)),
        Span::raw(format_bytes(conn.bytes_sent)),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled("Bytes Received: ", Style::default().fg(Color::Yellow)),
        Span::raw(format_bytes(conn.bytes_received)),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled("Packets Sent: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.packets_sent.to_string()),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled("Packets Received: ", Style::default().fg(Color::Yellow)),
        Span::raw(conn.packets_received.to_string()),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled("Current Rate (In): ", Style::default().fg(Color::Yellow)),
        Span::raw(format_rate(conn.current_incoming_rate_bps)),
    ]));

    traffic_text.push(Line::from(vec![
        Span::styled("Current Rate (Out): ", Style::default().fg(Color::Yellow)),
        Span::raw(format_rate(conn.current_outgoing_rate_bps)),
    ]));

    let traffic = Paragraph::new(traffic_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Traffic Statistics"),
        )
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true });

    f.render_widget(traffic, chunks[1]);

    Ok(())
}

/// Draw help screen
fn draw_help(f: &mut Frame, area: Rect) -> Result<()> {
    let help_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "RustNet Monitor ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("- Network Connection Monitor"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("q ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit application (press twice to confirm)"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+C ", Style::default().fg(Color::Yellow)),
            Span::raw("Quit immediately"),
        ]),
        Line::from(vec![
            Span::styled("Tab ", Style::default().fg(Color::Yellow)),
            Span::raw("Switch between tabs"),
        ]),
        Line::from(vec![
            Span::styled("↑/k, ↓/j ", Style::default().fg(Color::Yellow)),
            Span::raw("Navigate connections (wraps around)"),
        ]),
        Line::from(vec![
            Span::styled("Page Up/Down ", Style::default().fg(Color::Yellow)),
            Span::raw("Navigate connections by page"),
        ]),
        Line::from(vec![
            Span::styled("c ", Style::default().fg(Color::Yellow)),
            Span::raw("Copy remote address to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("Enter ", Style::default().fg(Color::Yellow)),
            Span::raw("View connection details"),
        ]),
        Line::from(vec![
            Span::styled("Esc ", Style::default().fg(Color::Yellow)),
            Span::raw("Return to overview"),
        ]),
        Line::from(vec![
            Span::styled("h ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle this help screen"),
        ]),
        Line::from(""),
    ];

    let help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .style(Style::default().fg(Color::White))
        .wrap(Wrap { trim: true })
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    Ok(())
}

/// Draw status bar
fn draw_status_bar(f: &mut Frame, ui_state: &UIState, connection_count: usize, area: Rect) {
    let status = if ui_state.quit_confirmation {
        " Press 'q' again to quit or any other key to cancel ".to_string()
    } else if let Some((ref msg, ref time)) = ui_state.clipboard_message {
        // Show clipboard message for 3 seconds
        if time.elapsed().as_secs() < 3 {
            format!(" {} ", msg)
        } else {
            format!(
                " Press 'h' for help | 'c' to copy address | Connections: {} ",
                connection_count
            )
        }
    } else {
        format!(
            " Press 'h' for help | 'c' to copy address | Connections: {} ",
            connection_count
        )
    };

    let style = if ui_state.quit_confirmation {
        Style::default().fg(Color::Black).bg(Color::Yellow)
    } else if ui_state.clipboard_message.is_some()
        && ui_state
            .clipboard_message
            .as_ref()
            .unwrap()
            .1
            .elapsed()
            .as_secs()
            < 3
    {
        Style::default().fg(Color::Black).bg(Color::Green)
    } else {
        Style::default().fg(Color::White).bg(Color::Blue)
    };

    let status_bar = Paragraph::new(status)
        .style(style)
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(status_bar, area);
}

/// Draw loading screen
fn draw_loading_screen(f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Length(5),
            Constraint::Percentage(40),
        ])
        .split(f.area());

    let loading_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("⣾ ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Loading network connections...",
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "This may take a few seconds",
            Style::default().fg(Color::DarkGray),
        )]),
    ];

    let loading_paragraph = Paragraph::new(loading_text)
        .alignment(ratatui::layout::Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RustNet Monitor"),
        );

    f.render_widget(loading_paragraph, chunks[1]);
}

/// Format rate to human readable form
fn format_rate(bytes_per_second: f64) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.2} GB/s", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.2} MB/s", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.2} KB/s", bytes_per_second / KB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0} B/s", bytes_per_second)
    } else {
        "-".to_string()
    }
}

/// Format rate to compact form for tight spaces
fn format_rate_compact(bytes_per_second: f64) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.1}G", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.1}M", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.0}K", bytes_per_second / KB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0}B", bytes_per_second)
    } else {
        "-".to_string()
    }
}

/// Format bytes to human readable form
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
