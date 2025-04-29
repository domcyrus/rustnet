use anyhow::Result;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs, Wrap},
    Frame, Terminal as RatatuiTerminal,
};
use std::collections::HashMap;

use crate::app::{App, ViewMode};
use crate::network::{Connection, Protocol};

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
        ViewMode::ProcessDetails => draw_process_details(f, app, chunks[1])?,
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
        Span::styled(app.i18n.get("processes"), Style::default().fg(Color::Green)),
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
            ViewMode::ProcessDetails => 2,
            ViewMode::Help => 3,
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
fn draw_connections_list(f: &mut Frame, app: &App, area: Rect) {
    let widths = [
        Constraint::Length(6),  // Protocol
        Constraint::Length(22), // Local
        Constraint::Length(22), // Remote
        Constraint::Length(12), // State
        Constraint::Min(10),    // Process
    ];

    let header_cells = [
        "Proto",
        "Local Address",
        "Remote Address",
        "State",
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
    for conn in &app.connections {
        let pid_str = conn
            .pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());

        let process_str = conn.process_name.clone().unwrap_or_else(|| "-".to_string());
        let process_display = format!("{} ({})", process_str, pid_str);

        // Format addresses with hostnames if enabled - no mutable borrowing
        let local_display = app.format_socket_addr(conn.local_addr);
        let remote_display = app.format_socket_addr(conn.remote_addr);

        let cells = [
            Cell::from(conn.protocol.to_string()),
            Cell::from(local_display),
            Cell::from(remote_display),
            Cell::from(conn.state.to_string()),
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
            Constraint::Length(8), // Summary stats
            Constraint::Min(0),    // Process list
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
    ];

    let stats_para = Paragraph::new(stats_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("statistics")),
        )
        .style(Style::default().fg(Color::White));
    f.render_widget(stats_para, chunks[1]);

    let mut process_counts: HashMap<u32, usize> = HashMap::new();
    for conn in &app.connections {
        if let Some(pid) = conn.pid {
            *process_counts.entry(pid).or_insert(0) += 1;
        }
    }

    let mut process_list: Vec<(u32, usize)> = process_counts.into_iter().collect();
    process_list.sort_by(|a, b| b.1.cmp(&a.1));

    let mut items = Vec::new();
    for (pid, count) in process_list.iter().take(10) {
        if let Some(process) = app.processes.get(pid) {
            let item = ListItem::new(Line::from(vec![
                Span::raw(format!("{}: ", process.name)),
                Span::styled(
                    format!("{} {}", count, app.i18n.get("connections")),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
            items.push(item);
        }
    }

    let processes = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(app.i18n.get("top_processes")),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");

    f.render_widget(processes, chunks[2]);

    Ok(())
}

/// Draw connection details view
fn draw_connection_details(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
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

    let conn = &app.connections[app.selected_connection_idx];

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let mut details_text: Vec<Line> = Vec::new();
    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("protocol")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(conn.protocol.to_string()),
    ]));

    // Format addresses with hostnames if enabled
    let local_display = app.format_socket_addr(conn.local_addr);
    let remote_display = app.format_socket_addr(conn.remote_addr);

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("local_address")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(local_display),
    ]));

    details_text.push(Line::from(vec![
        Span::styled(
            format!("{}: ", app.i18n.get("remote_address")),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(remote_display),
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

    details_text.push(Line::from(""));
    details_text.push(Line::from(vec![Span::styled(
        format!("{} (p)", app.i18n.get("press_for_process_details")),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::ITALIC),
    )]));

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

/// Draw process details view
fn draw_process_details(f: &mut Frame, app: &mut App, area: Rect) -> Result<()> {
    if app.connections.is_empty() {
        let text = Paragraph::new(app.i18n.get("no_processes"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(app.i18n.get("process_details")),
            )
            .style(Style::default().fg(Color::Red))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, area);
        return Ok(());
    }

    // Look up process info on demand for the selected connection
    // This now returns an owned Process, not a reference
    if let Some(process) = app.get_process_for_selected_connection() {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(10), // Process details
                Constraint::Min(0),     // Process connections
            ])
            .split(area);

        let mut details_text: Vec<Line> = Vec::new();
        details_text.push(Line::from(vec![
            Span::styled(
                format!("{}: ", app.i18n.get("process_name")),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(&process.name),
        ]));

        details_text.push(Line::from(vec![
            Span::styled(
                format!("{}: ", app.i18n.get("pid")),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(process.pid.to_string()),
        ]));

        if let Some(ref cmd) = process.command_line {
            details_text.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", app.i18n.get("command_line")),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(cmd),
            ]));
        }

        if let Some(ref user) = process.user {
            details_text.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", app.i18n.get("user")),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(user),
            ]));
        }

        if let Some(cpu) = process.cpu_usage {
            details_text.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", app.i18n.get("cpu_usage")),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(format!("{:.1}%", cpu)),
            ]));
        }

        if let Some(mem) = process.memory_usage {
            details_text.push(Line::from(vec![
                Span::styled(
                    format!("{}: ", app.i18n.get("memory_usage")),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(format_bytes(mem)),
            ]));
        }

        let details = Paragraph::new(details_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(app.i18n.get("process_details")),
            )
            .style(Style::default().fg(Color::White))
            .wrap(Wrap { trim: true });

        f.render_widget(details, chunks[0]);

        // Find all connections for this process
        let pid = process.pid;
        let connections: Vec<&Connection> = app
            .connections
            .iter()
            .filter(|c| c.pid == Some(pid))
            .collect();

        let connections_count = connections.len();

        let mut items = Vec::new();
        for conn in &connections {
            // Format addresses with hostnames if enabled
            let local_display = app.format_socket_addr(conn.local_addr);
            let remote_display = app.format_socket_addr(conn.remote_addr);

            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{}: ", conn.protocol),
                    Style::default().fg(Color::Green),
                ),
                Span::raw(format!(
                    "{} -> {} ({})",
                    local_display, remote_display, conn.state
                )),
            ])));
        }

        let connections_list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "{} ({})",
                app.i18n.get("process_connections"),
                connections_count
            )))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");

        f.render_widget(connections_list, chunks[1]);
    } else {
        let text = Paragraph::new(app.i18n.get("process_not_found"))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(app.i18n.get("process_details")),
            )
            .style(Style::default().fg(Color::Red))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(text, area);
    }

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

// Extension trait to provide table state for connections
impl App {
    fn table_state(&self, selected: usize) -> ratatui::widgets::TableState {
        let mut state = ratatui::widgets::TableState::default();
        if !self.connections.is_empty() {
            state.select(Some(selected));
        }
        state
    }
}
