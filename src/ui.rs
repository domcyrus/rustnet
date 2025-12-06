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

/// Sort column options for the connections table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    #[default]
    CreatedAt, // Default: creation time (oldest first)
    BandwidthTotal, // Combined up + down bandwidth
    Process,
    LocalAddress,
    RemoteAddress,
    Application,
    Service,
    State,
    Protocol,
}

impl SortColumn {
    /// Get the next sort column in the cycle (follows left-to-right visual order)
    pub fn next(self) -> Self {
        match self {
            Self::CreatedAt => Self::Protocol,         // Column 1: Pro
            Self::Protocol => Self::LocalAddress,      // Column 2: Local Address
            Self::LocalAddress => Self::RemoteAddress, // Column 3: Remote Address
            Self::RemoteAddress => Self::State,        // Column 4: State
            Self::State => Self::Service,              // Column 5: Service
            Self::Service => Self::Application,        // Column 6: Application / Host
            Self::Application => Self::BandwidthTotal, // Column 7: Down/Up (combined total)
            Self::BandwidthTotal => Self::Process,     // Column 8: Process
            Self::Process => Self::CreatedAt,          // Back to default
        }
    }

    /// Get the default sort direction for this column (true = ascending, false = descending)
    pub fn default_direction(self) -> bool {
        match self {
            // Descending by default - show biggest/most active first
            Self::BandwidthTotal => false,

            // Ascending by default - alphabetical or chronological
            Self::Process => true,
            Self::LocalAddress => true,
            Self::RemoteAddress => true,
            Self::Application => true,
            Self::Service => true,
            Self::State => true,
            Self::Protocol => true,
            Self::CreatedAt => true, // Oldest first (current default behavior)
        }
    }

    /// Get the display name for the sort column
    pub fn display_name(self) -> &'static str {
        match self {
            Self::CreatedAt => "Time",
            Self::BandwidthTotal => "Bandwidth Total",
            Self::Process => "Process",
            Self::LocalAddress => "Local Addr",
            Self::RemoteAddress => "Remote Addr",
            Self::Application => "Application",
            Self::Service => "Service",
            Self::State => "State",
            Self::Protocol => "Protocol",
        }
    }
}

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
    pub filter_mode: bool,
    pub filter_query: String,
    pub filter_cursor_position: usize,
    pub show_port_numbers: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
}

impl Default for UIState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            show_help: false,
            quit_confirmation: false,
            clipboard_message: None,
            filter_mode: false,
            filter_query: String::new(),
            filter_cursor_position: 0,
            show_port_numbers: false,
            sort_column: SortColumn::default(),
            sort_ascending: true, // Default to ascending
        }
    }
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
            log::debug!("move_selection_up: connections list is empty");
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        let old_key = self.selected_connection_key.clone();
        log::debug!(
            "move_selection_up: current_index={}, total_connections={}, current_key={:?}",
            current_index,
            connections.len(),
            old_key
        );

        if current_index > 0 {
            self.set_selected_by_index(connections, current_index - 1);
            log::debug!(
                "move_selection_up: moved from index {} to {} (key: {:?} -> {:?})",
                current_index,
                current_index - 1,
                old_key,
                self.selected_connection_key
            );
        } else {
            // Wrap around to the bottom
            self.set_selected_by_index(connections, connections.len() - 1);
            log::debug!(
                "move_selection_up: wrapped from index {} to bottom index {} (key: {:?} -> {:?})",
                current_index,
                connections.len() - 1,
                old_key,
                self.selected_connection_key
            );
        }
    }

    /// Move selection down by one position
    pub fn move_selection_down(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            log::debug!("move_selection_down: connections list is empty");
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        let old_key = self.selected_connection_key.clone();
        log::debug!(
            "move_selection_down: current_index={}, total_connections={}, current_key={:?}",
            current_index,
            connections.len(),
            old_key
        );

        if current_index < connections.len().saturating_sub(1) {
            self.set_selected_by_index(connections, current_index + 1);
            log::debug!(
                "move_selection_down: moved from index {} to {} (key: {:?} -> {:?})",
                current_index,
                current_index + 1,
                old_key,
                self.selected_connection_key
            );
        } else {
            // Wrap around to the top
            self.set_selected_by_index(connections, 0);
            log::debug!(
                "move_selection_down: wrapped from index {} to top index 0 (key: {:?} -> {:?})",
                current_index,
                old_key,
                self.selected_connection_key
            );
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

    /// Move selection to the first connection (vim-style 'g')
    pub fn move_selection_to_first(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            return;
        }
        self.set_selected_by_index(connections, 0);
    }

    /// Move selection to the last connection (vim-style 'G')
    pub fn move_selection_to_last(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            return;
        }
        self.set_selected_by_index(connections, connections.len() - 1);
    }

    /// Ensure we have a valid selection when connections list changes
    pub fn ensure_valid_selection(&mut self, connections: &[Connection]) {
        if connections.is_empty() {
            log::debug!("ensure_valid_selection: connections list is empty, clearing selection");
            self.selected_connection_key = None;
            return;
        }

        let current_index = self.get_selected_index(connections);
        log::debug!(
            "ensure_valid_selection: current_index={:?}, total_connections={}",
            current_index,
            connections.len()
        );

        // If no selection or selection is no longer valid, select first connection
        if self.selected_connection_key.is_none() || current_index.is_none() {
            log::debug!("ensure_valid_selection: selecting first connection (index 0)");
            self.set_selected_by_index(connections, 0);
        }
    }

    /// Enter filter mode
    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        self.filter_cursor_position = self.filter_query.len();
    }

    /// Exit filter mode
    pub fn exit_filter_mode(&mut self) {
        self.filter_mode = false;
        self.filter_cursor_position = 0;
    }

    /// Clear filter and exit filter mode
    pub fn clear_filter(&mut self) {
        self.filter_query.clear();
        self.exit_filter_mode();
    }

    /// Add character to filter query at cursor position
    pub fn filter_add_char(&mut self, c: char) {
        self.filter_query.insert(self.filter_cursor_position, c);
        self.filter_cursor_position += 1;
    }

    /// Remove character before cursor position in filter query
    pub fn filter_backspace(&mut self) {
        if self.filter_cursor_position > 0 {
            self.filter_cursor_position -= 1;
            self.filter_query.remove(self.filter_cursor_position);
        }
    }

    /// Move cursor left in filter query
    pub fn filter_cursor_left(&mut self) {
        if self.filter_cursor_position > 0 {
            self.filter_cursor_position -= 1;
        }
    }

    /// Move cursor right in filter query
    pub fn filter_cursor_right(&mut self) {
        if self.filter_cursor_position < self.filter_query.len() {
            self.filter_cursor_position += 1;
        }
    }

    /// Cycle to the next sort column
    pub fn cycle_sort_column(&mut self) {
        self.sort_column = self.sort_column.next();
        // Reset to the default direction for the new column
        self.sort_ascending = self.sort_column.default_direction();
    }

    /// Toggle the sort direction for the current column
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
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

    draw_tabs(f, ui_state, chunks[0]);

    let content_area = chunks[1];
    let (filter_area, status_area) = if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
        (Some(chunks[2]), chunks[3])
    } else {
        (None, chunks[2])
    };

    match ui_state.selected_tab {
        0 => draw_overview(f, ui_state, connections, stats, app, content_area)?,
        1 => draw_connection_details(f, ui_state, connections, content_area)?,
        2 => draw_interface_stats(f, app, content_area)?,
        3 => draw_help(f, content_area)?,
        _ => {}
    }

    if let Some(filter_area) = filter_area {
        draw_filter_input(f, ui_state, filter_area);
    }

    draw_status_bar(f, ui_state, connections.len(), status_area);

    Ok(())
}

/// Draw mode tabs
fn draw_tabs(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let titles = vec![
        Span::styled("Overview", Style::default().fg(Color::Green)),
        Span::styled("Details", Style::default().fg(Color::Green)),
        Span::styled("Interfaces", Style::default().fg(Color::Green)),
        Span::styled("Help", Style::default().fg(Color::Green)),
    ];

    let tabs = Tabs::new(titles.into_iter().map(Line::from).collect::<Vec<_>>())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RustNet Monitor"),
        )
        .select(ui_state.selected_tab)
        .style(Style::default())
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
        Constraint::Length(6), // Protocol (TCP/UDP + arrow = "Pro ↑" = 5 chars, give 6 for padding)
        Constraint::Length(17), // Local Address (13 + arrow = 15, fits in 17)
        Constraint::Length(21), // Remote Address (14 + arrow = 16, fits in 21)
        Constraint::Length(16), // State (5 + arrow = 7, fits in 16)
        Constraint::Length(10), // Service (7 + arrow = 9, need at least 10 for padding)
        Constraint::Length(24), // DPI/Application (18 + arrow = 20, fits in 24)
        Constraint::Length(12), // Bandwidth (7 + arrow = 9, fits in 12)
        Constraint::Min(20),   // Process (flexible remaining space)
    ];

    // Helper function to add sort indicator to column headers
    let add_sort_indicator = |label: &str, columns: &[SortColumn]| -> String {
        if columns.contains(&ui_state.sort_column) && ui_state.sort_column != SortColumn::CreatedAt
        {
            let arrow = if ui_state.sort_ascending {
                "↑"
            } else {
                "↓"
            };
            format!("{} {}", label, arrow)
        } else {
            label.to_string()
        }
    };

    // Special handler for bandwidth column - shows combined total when sorting by bandwidth
    let bandwidth_label = match ui_state.sort_column {
        SortColumn::BandwidthTotal => {
            let arrow = if ui_state.sort_ascending {
                "↑"
            } else {
                "↓"
            };
            format!("Down/Up {}", arrow) // "Down/Up ↓" or "Down/Up ↑"
        }
        _ => "Down/Up".to_string(), // No bandwidth sort active
    };

    let header_labels = [
        add_sort_indicator("Pro", &[SortColumn::Protocol]),
        add_sort_indicator("Local Address", &[SortColumn::LocalAddress]),
        add_sort_indicator("Remote Address", &[SortColumn::RemoteAddress]),
        add_sort_indicator("State", &[SortColumn::State]),
        add_sort_indicator("Service", &[SortColumn::Service]),
        add_sort_indicator("Application / Host", &[SortColumn::Application]),
        bandwidth_label, // Use custom bandwidth label instead of generic indicator
        add_sort_indicator("Process", &[SortColumn::Process]),
    ];

    let header_cells = header_labels.iter().enumerate().map(|(idx, h)| {
        // Determine if this is the active sort column
        let is_active = match idx {
            0 => ui_state.sort_column == SortColumn::Protocol,
            1 => ui_state.sort_column == SortColumn::LocalAddress,
            2 => ui_state.sort_column == SortColumn::RemoteAddress,
            3 => ui_state.sort_column == SortColumn::State,
            4 => ui_state.sort_column == SortColumn::Service,
            5 => ui_state.sort_column == SortColumn::Application,
            6 => ui_state.sort_column == SortColumn::BandwidthTotal,
            7 => ui_state.sort_column == SortColumn::Process,
            _ => false,
        } && ui_state.sort_column != SortColumn::CreatedAt;

        let style = if is_active {
            // Active sort column: Cyan + Bold + Underlined
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            // Inactive columns: Yellow + Bold (normal)
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        };

        Cell::from(h.as_str()).style(style)
    });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = connections
        .iter()
        .map(|conn| {
            let pid_str = conn
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string());

            // Debug: Log the raw process data to understand what's changing
            if let Some(ref raw_process_name) = conn.process_name
                && raw_process_name.contains("firefox")
            {
                log::debug!(
                    "🔍 Raw process name for {}: '{:?}' (len:{}, bytes: {:?})",
                    conn.key(),
                    raw_process_name,
                    raw_process_name.len(),
                    raw_process_name.as_bytes()
                );
                log::debug!("🔍 PID: {:?}", conn.pid);

                // Check for non-standard whitespace characters
                let has_non_ascii_space = raw_process_name
                    .chars()
                    .any(|c| c.is_whitespace() && c != ' ' && c != '\t' && c != '\n');
                if has_non_ascii_space {
                    log::warn!(
                        "🚨 Process name contains non-standard whitespace: {:?}",
                        raw_process_name.chars().collect::<Vec<char>>()
                    );
                }
            }

            // Process names are now pre-normalized at the source (PKTAP/lsof), so we can use them directly
            let process_str = conn.process_name.clone().unwrap_or_else(|| "-".to_string());

            let process_display = if conn.pid.is_some() {
                // Ensure exactly one space between process name and PID: "PROCESS_NAME (PID)"
                let full_display = format!("{} ({})", process_str, pid_str);

                // Debug: Log the final formatted display
                if process_str.contains("firefox") {
                    log::debug!("🎨 Final display for {}: '{}'", conn.key(), full_display);
                }
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

            // Display port number or service name based on toggle
            let service_display = if ui_state.show_port_numbers {
                conn.remote_addr.port().to_string()
            } else {
                let service_name = conn.service_name.clone().unwrap_or_else(|| "-".to_string());
                // Truncate service name to fit in 8 chars
                if service_name.len() > 8 {
                    format!("{:.5}...", service_name)
                } else {
                    service_name
                }
            };

            // DPI/Application protocol display (enhanced for hostnames)
            let dpi_display = match &conn.dpi_info {
                Some(dpi) => dpi.application.to_string(),
                None => "-".to_string(),
            };

            // Compact bandwidth display to fit in 14 chars
            let incoming_rate = format_rate_compact(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate_compact(conn.current_outgoing_rate_bps);
            let bandwidth_display = format!("{}↓/{}↑", incoming_rate, outgoing_rate);

            // Determine row color based on staleness
            // - Normal (white/default): fresh connections (< 75% of timeout)
            // - Yellow: approaching timeout (75-90% of timeout)
            // - Red: very close to timeout (> 90% of timeout)
            let staleness = conn.staleness_ratio();
            let row_style = if staleness >= 0.90 {
                // Critical: > 90% of timeout - will be cleaned up very soon
                Style::default().fg(Color::Red)
            } else if staleness >= 0.75 {
                // Warning: 75-90% of timeout - approaching cleanup
                Style::default().fg(Color::Yellow)
            } else {
                // Normal: < 75% of timeout
                Style::default()
            };

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
            Row::new(cells).style(row_style)
        })
        .collect();

    // Create table state with current selection
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_index(connections) {
        state.select(Some(selected_index));
    }

    // Build dynamic title with sort information
    let table_title = if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        };
        format!(
            "Active Connections (Sort: {} {})",
            ui_state.sort_column.display_name(),
            direction
        )
    } else {
        "Active Connections".to_string()
    };

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(table_title))
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
            Constraint::Length(5),  // Traffic stats
            Constraint::Length(7),  // Network stats (TCP analytics + header)
            Constraint::Min(0),     // Interface stats
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

    let process_detection_method = app.get_process_detection_method();
    let (link_layer_type, is_tunnel) = app.get_link_layer_info();

    let conn_stats_text: Vec<Line> = vec![
        Line::from(format!("Interface: {}", interface_name)),
        Line::from(format!(
            "Link Layer: {}{}",
            link_layer_type,
            if is_tunnel { " (Tunnel)" } else { "" }
        )),
        Line::from(format!("Process Detection: {}", process_detection_method)),
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
        .style(Style::default());
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
        .style(Style::default());
    f.render_widget(traffic_stats, chunks[1]);

    // Network statistics (TCP analytics)
    let mut tcp_retransmits: u64 = 0;
    let mut tcp_out_of_order: u64 = 0;
    let mut tcp_fast_retransmits: u64 = 0;
    let mut tcp_connections_with_analytics = 0;

    for conn in connections {
        if let Some(analytics) = &conn.tcp_analytics {
            tcp_retransmits += analytics.retransmit_count;
            tcp_out_of_order += analytics.out_of_order_count;
            tcp_fast_retransmits += analytics.fast_retransmit_count;
            tcp_connections_with_analytics += 1;
        }
    }

    let total_retransmits = stats
        .total_tcp_retransmits
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_out_of_order = stats
        .total_tcp_out_of_order
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_fast_retransmits = stats
        .total_tcp_fast_retransmits
        .load(std::sync::atomic::Ordering::Relaxed);

    let network_stats_text: Vec<Line> = vec![
        Line::from(vec![Span::styled(
            "(Active / Total)",
            Style::default().fg(Color::Gray),
        )]),
        Line::from(format!(
            "TCP Retransmits: {} / {}",
            tcp_retransmits, total_retransmits
        )),
        Line::from(format!(
            "Out-of-Order: {} / {}",
            tcp_out_of_order, total_out_of_order
        )),
        Line::from(format!(
            "Fast Retransmits: {} / {}",
            tcp_fast_retransmits, total_fast_retransmits
        )),
        Line::from(format!(
            "Active TCP Flows: {}",
            tcp_connections_with_analytics
        )),
    ];

    let network_stats = Paragraph::new(network_stats_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Network Stats"),
        )
        .style(Style::default());
    f.render_widget(network_stats, chunks[2]);

    // Interface statistics
    let all_interface_stats = app.get_interface_stats();
    let interface_rates = app.get_interface_rates();

    // Filter to show only the captured interface (or active interfaces if "any" or "pktap")
    let captured_interface = app.get_current_interface();
    let filtered_interface_stats: Vec<_> = if let Some(ref iface) = captured_interface {
        // Windows uses NPF device paths like \Device\NPF_{GUID} which don't match friendly names
        // For these, show all active interfaces instead of trying exact match
        let is_npf_device = iface.starts_with("\\Device\\NPF_");

        if iface == "any" || iface == "pktap" || is_npf_device {
            // Show interfaces with some data
            // pktap is a macOS virtual interface that captures from all interfaces,
            // so we show all active interfaces rather than trying to show stats for pktap itself
            // On Windows, NPF device names don't match friendly names, so show active interfaces
            all_interface_stats
                .into_iter()
                .filter(|s| {
                    s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0
                })
                .collect()
        } else {
            // Show only the captured interface
            all_interface_stats
                .into_iter()
                .filter(|s| s.interface_name == *iface)
                .collect()
        }
    } else {
        // No interface specified yet - show active interfaces
        all_interface_stats
            .into_iter()
            .filter(|s| s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0)
            .collect()
    };

    // Calculate how many interfaces can fit in the available space
    // Each interface takes 2 lines, and we need 2 lines for borders
    // Reserve 1 line for the "... N more" message if needed
    let available_height = chunks[3].height as usize;
    let lines_for_borders = 2;
    let lines_per_interface = 2;
    let lines_for_more_message = 1;

    let max_interfaces = if available_height > lines_for_borders + lines_for_more_message {
        (available_height - lines_for_borders - lines_for_more_message) / lines_per_interface
    } else {
        0
    };

    let interface_stats_text: Vec<Line> = if filtered_interface_stats.is_empty() {
        vec![Line::from(Span::styled(
            "No interface stats available",
            Style::default().fg(Color::Gray),
        ))]
    } else {
        let mut lines = Vec::new();
        let num_to_show = max_interfaces.min(filtered_interface_stats.len());

        for stat in filtered_interface_stats.iter().take(num_to_show) {
            let total_errors = stat.rx_errors + stat.tx_errors;
            let total_drops = stat.rx_dropped + stat.tx_dropped;

            let error_style = if total_errors > 0 {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Green)
            };

            let drop_style = if total_drops > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            };

            // Get rates for this interface (if available)
            let rate_display = if let Some(rates) = interface_rates.get(&stat.interface_name) {
                format!(
                    "{}/s ↓ / {}/s ↑",
                    format_bytes(rates.rx_bytes_per_sec),
                    format_bytes(rates.tx_bytes_per_sec)
                )
            } else {
                "Calculating...".to_string()
            };

            // Interface name and rate on first line
            lines.push(Line::from(vec![
                Span::raw(format!("{}: ", stat.interface_name)),
                Span::raw(rate_display),
            ]));

            // Errors and drops on second line (indented) - these are cumulative totals
            lines.push(Line::from(vec![
                Span::raw("  Errors (Total): "),
                Span::styled(format!("{}", total_errors), error_style),
                Span::raw("  Drops (Total): "),
                Span::styled(format!("{}", total_drops), drop_style),
            ]));
        }

        // Only show "more" message if there are actually more interfaces that don't fit
        if filtered_interface_stats.len() > num_to_show {
            lines.push(Line::from(Span::styled(
                format!(
                    "... and {} more (press 'i' for details)",
                    filtered_interface_stats.len() - num_to_show
                ),
                Style::default().fg(Color::Gray),
            )));
        }
        lines
    };

    let interface_stats_widget = Paragraph::new(interface_stats_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Interface Stats (press 'i')"),
        )
        .style(Style::default());
    f.render_widget(interface_stats_widget, chunks[3]);

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
    let mut details_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Protocol: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.protocol.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Local Address: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.local_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Remote Address: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.remote_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("State: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.state()),
        ]),
        Line::from(vec![
            Span::styled("Process: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.process_name.clone().unwrap_or_else(|| "-".to_string())),
        ]),
        Line::from(vec![
            Span::styled("PID: ", Style::default().fg(Color::Yellow)),
            Span::raw(
                conn.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Service: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.service_name.clone().unwrap_or_else(|| "-".to_string())),
        ]),
    ];

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
                    if let Some(tls_info) = &info.tls_info {
                        if let Some(sni) = &tls_info.sni {
                            details_text.push(Line::from(vec![
                                Span::styled("  SNI: ", Style::default().fg(Color::Cyan)),
                                Span::raw(sni.clone()),
                            ]));
                        }
                        if !tls_info.alpn.is_empty() {
                            details_text.push(Line::from(vec![
                                Span::styled("  ALPN: ", Style::default().fg(Color::Cyan)),
                                Span::raw(tls_info.alpn.join(", ")),
                            ]));
                        }
                        if let Some(version) = &tls_info.version {
                            details_text.push(Line::from(vec![
                                Span::styled("  TLS Version: ", Style::default().fg(Color::Cyan)),
                                Span::raw(version.to_string()),
                            ]));
                        }
                        if let Some(formatted_cipher) = tls_info.format_cipher_suite() {
                            let cipher_color = if tls_info.is_cipher_suite_secure().unwrap_or(false)
                            {
                                Color::Green
                            } else {
                                Color::Yellow
                            };
                            details_text.push(Line::from(vec![
                                Span::styled("  Cipher Suite: ", Style::default().fg(Color::Cyan)),
                                Span::styled(formatted_cipher, Style::default().fg(cipher_color)),
                            ]));
                        }
                    }
                }
                crate::network::types::ApplicationProtocol::Dns(info) => {
                    if let Some(query_type) = &info.query_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  DNS Type: ", Style::default().fg(Color::Cyan)),
                            Span::raw(format!("{:?}", query_type)),
                        ]));
                    }
                    if !info.response_ips.is_empty() {
                        details_text.push(Line::from(vec![
                            Span::styled("  DNS Response IPs: ", Style::default().fg(Color::Cyan)),
                            Span::raw(format!("{:?}", info.response_ips)),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Quic(info) => {
                    if let Some(tls_info) = &info.tls_info {
                        let sni = tls_info.sni.clone().unwrap_or_else(|| "-".to_string());
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC SNI: ", Style::default().fg(Color::Cyan)),
                            Span::raw(sni),
                        ]));
                        let alpn = tls_info.alpn.join(", ");
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC ALPN: ", Style::default().fg(Color::Cyan)),
                            Span::raw(alpn),
                        ]));
                    }
                    if let Some(version) = info.version_string.as_ref() {
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC Version: ", Style::default().fg(Color::Cyan)),
                            Span::raw(version.clone()),
                        ]));
                    }
                    if let Some(connection_id) = &info.connection_id_hex {
                        details_text.push(Line::from(vec![
                            Span::styled("  Connection ID: ", Style::default().fg(Color::Cyan)),
                            Span::raw(connection_id.clone()),
                        ]));
                    }

                    let packet_type = info.packet_type.to_string();
                    details_text.push(Line::from(vec![
                        Span::styled("  Packet Type: ", Style::default().fg(Color::Cyan)),
                        Span::raw(packet_type),
                    ]));
                    let connection_state = info.connection_state.to_string();
                    details_text.push(Line::from(vec![
                        Span::styled("  Connection State: ", Style::default().fg(Color::Cyan)),
                        Span::raw(connection_state),
                    ]));
                }
                crate::network::types::ApplicationProtocol::Ssh(info) => {
                    if let Some(version) = &info.version {
                        details_text.push(Line::from(vec![
                            Span::styled("  SSH Version: ", Style::default().fg(Color::Cyan)),
                            Span::raw(format!("{:?}", version)),
                        ]));
                    }
                    if let Some(server_software) = &info.server_software {
                        details_text.push(Line::from(vec![
                            Span::styled("  Server Software: ", Style::default().fg(Color::Cyan)),
                            Span::raw(server_software.clone()),
                        ]));
                    }
                    if let Some(client_software) = &info.client_software {
                        details_text.push(Line::from(vec![
                            Span::styled("  Client Software: ", Style::default().fg(Color::Cyan)),
                            Span::raw(client_software.clone()),
                        ]));
                    }
                    details_text.push(Line::from(vec![
                        Span::styled("  Connection State: ", Style::default().fg(Color::Cyan)),
                        Span::raw(format!("{:?}", info.connection_state)),
                    ]));
                    if !info.algorithms.is_empty() {
                        details_text.push(Line::from(vec![
                            Span::styled("  Algorithms: ", Style::default().fg(Color::Cyan)),
                            Span::raw(info.algorithms.join(", ")),
                        ]));
                    }
                    if let Some(auth_method) = &info.auth_method {
                        details_text.push(Line::from(vec![
                            Span::styled("  Auth Method: ", Style::default().fg(Color::Cyan)),
                            Span::raw(auth_method.clone()),
                        ]));
                    }
                }
            }
        }
        None => {
            details_text.push(Line::from(vec![
                Span::styled("Application: ", Style::default().fg(Color::Yellow)),
                Span::raw("-".to_string()),
            ]));
        }
    }

    // Add TCP analytics if available
    if let Some(analytics) = &conn.tcp_analytics {
        details_text.push(Line::from(""));
        details_text.push(Line::from(vec![
            Span::styled("TCP Retransmits: ", Style::default().fg(Color::Yellow)),
            Span::raw(analytics.retransmit_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Out-of-Order Packets: ", Style::default().fg(Color::Yellow)),
            Span::raw(analytics.out_of_order_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Duplicate ACKs: ", Style::default().fg(Color::Yellow)),
            Span::raw(analytics.duplicate_ack_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Fast Retransmits: ", Style::default().fg(Color::Yellow)),
            Span::raw(analytics.fast_retransmit_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Window Size: ", Style::default().fg(Color::Yellow)),
            Span::raw(analytics.last_window_size.to_string()),
        ]));
    }

    let details = Paragraph::new(details_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Connection Information"),
        )
        .style(Style::default())
        .wrap(Wrap { trim: true });

    f.render_widget(details, chunks[0]);

    // Traffic details
    let traffic_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Bytes Sent: ", Style::default().fg(Color::Yellow)),
            Span::raw(format_bytes(conn.bytes_sent)),
        ]),
        Line::from(vec![
            Span::styled("Bytes Received: ", Style::default().fg(Color::Yellow)),
            Span::raw(format_bytes(conn.bytes_received)),
        ]),
        Line::from(vec![
            Span::styled("Packets Sent: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.packets_sent.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Packets Received: ", Style::default().fg(Color::Yellow)),
            Span::raw(conn.packets_received.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Current Rate (In): ", Style::default().fg(Color::Yellow)),
            Span::raw(format_rate(conn.current_incoming_rate_bps)),
        ]),
        Line::from(vec![
            Span::styled("Current Rate (Out): ", Style::default().fg(Color::Yellow)),
            Span::raw(format_rate(conn.current_outgoing_rate_bps)),
        ]),
    ];

    let traffic = Paragraph::new(traffic_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Traffic Statistics"),
        )
        .style(Style::default())
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
            Span::styled("g, G ", Style::default().fg(Color::Yellow)),
            Span::raw("Jump to first/last connection (vim-style)"),
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
            Span::styled("p ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle between service names and port numbers"),
        ]),
        Line::from(vec![
            Span::styled("s ", Style::default().fg(Color::Yellow)),
            Span::raw("Cycle through sort columns (Bandwidth, Process, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("S ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle sort direction (ascending/descending)"),
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
        Line::from(vec![
            Span::styled("i ", Style::default().fg(Color::Yellow)),
            Span::raw("Toggle interface statistics view"),
        ]),
        Line::from(vec![
            Span::styled("/ ", Style::default().fg(Color::Yellow)),
            Span::raw("Enter filter mode (navigate while typing!)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Connection Colors:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  White ", Style::default()),
            Span::raw("Active connection (< 75% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Yellow ", Style::default().fg(Color::Yellow)),
            Span::raw("Stale connection (75-90% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Red ", Style::default().fg(Color::Red)),
            Span::raw("Critical - will be removed soon (> 90% of timeout)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Filter Examples:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  /google ", Style::default().fg(Color::Green)),
            Span::raw("Search for 'google' in all fields"),
        ]),
        Line::from(vec![
            Span::styled("  /port:44 ", Style::default().fg(Color::Green)),
            Span::raw("Filter ports containing '44' (443, 8080, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("  /src:192.168 ", Style::default().fg(Color::Green)),
            Span::raw("Filter by source IP prefix"),
        ]),
        Line::from(vec![
            Span::styled("  /dst:github.com ", Style::default().fg(Color::Green)),
            Span::raw("Filter by destination"),
        ]),
        Line::from(vec![
            Span::styled("  /sni:example.com ", Style::default().fg(Color::Green)),
            Span::raw("Filter by SNI hostname"),
        ]),
        Line::from(vec![
            Span::styled("  /process:firefox ", Style::default().fg(Color::Green)),
            Span::raw("Filter by process name"),
        ]),
        Line::from(""),
    ];

    let help = Paragraph::new(help_text)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .style(Style::default())
        .wrap(Wrap { trim: true })
        .alignment(ratatui::layout::Alignment::Left);

    f.render_widget(help, area);

    Ok(())
}

/// Draw interface statistics table
fn draw_interface_stats(f: &mut Frame, app: &crate::app::App, area: Rect) -> Result<()> {
    let mut stats = app.get_interface_stats();
    let rates = app.get_interface_rates();

    // Sort interfaces to show the captured interface first
    let captured_interface = app.get_current_interface();
    if let Some(ref captured) = captured_interface {
        stats.sort_by(|a, b| {
            let a_is_captured = &a.interface_name == captured;
            let b_is_captured = &b.interface_name == captured;
            match (a_is_captured, b_is_captured) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.interface_name.cmp(&b.interface_name),
            }
        });
    }

    if stats.is_empty() {
        let empty_msg = Paragraph::new("No interface statistics available yet...")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Interface Statistics "),
            )
            .style(Style::default().fg(Color::Gray))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(empty_msg, area);
        return Ok(());
    }

    // Create table rows
    let mut rows = Vec::new();

    for stat in &stats {
        // Determine error style
        let error_style = if stat.rx_errors > 0 || stat.tx_errors > 0 {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Green)
        };

        // Determine drop style
        let drop_style = if stat.rx_dropped > 0 || stat.tx_dropped > 0 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Green)
        };

        // Get rate for this interface
        let rx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.rx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let tx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.tx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        rows.push(Row::new(vec![
            Cell::from(stat.interface_name.clone()),
            Cell::from(rx_rate_str),
            Cell::from(tx_rate_str),
            Cell::from(format!("{}", stat.rx_packets)),
            Cell::from(format!("{}", stat.tx_packets)),
            Cell::from(format!("{}", stat.rx_errors)).style(error_style),
            Cell::from(format!("{}", stat.tx_errors)).style(error_style),
            Cell::from(format!("{}", stat.rx_dropped)).style(drop_style),
            Cell::from(format!("{}", stat.tx_dropped)).style(drop_style),
            Cell::from(format!("{}", stat.collisions)),
        ]));
    }

    // Create table
    let table = Table::new(
        rows,
        [
            Constraint::Length(14), // Interface
            Constraint::Length(12), // RX Bytes
            Constraint::Length(12), // TX Bytes
            Constraint::Length(10), // RX Packets
            Constraint::Length(10), // TX Packets
            Constraint::Length(9),  // RX Err
            Constraint::Length(9),  // TX Err
            Constraint::Length(10), // RX Drop
            Constraint::Length(10), // TX Drop
            Constraint::Length(10), // Collis
        ],
    )
    .header(
        Row::new(vec![
            "Interface",
            "RX Rate",
            "TX Rate",
            "RX Packets",
            "TX Packets",
            "RX Err",
            "TX Err",
            "RX Drop",
            "TX Drop",
            "Collisions",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Interface Statistics (Press 'i' to toggle) "),
    )
    .style(Style::default());

    f.render_widget(table, area);

    Ok(())
}

/// Draw filter input area
fn draw_filter_input(f: &mut Frame, ui_state: &UIState, area: Rect) {
    let title = if ui_state.filter_mode {
        "Filter (↑↓/jk to navigate, Enter to confirm, Esc to cancel)"
    } else {
        "Active Filter (Press Esc to clear)"
    };

    let input_text = if ui_state.filter_mode {
        // Show cursor when in filter mode
        let mut display_query = ui_state.filter_query.clone();
        if ui_state.filter_cursor_position <= display_query.len() {
            display_query.insert(ui_state.filter_cursor_position, '|');
        }
        display_query
    } else {
        ui_state.filter_query.clone()
    };

    let style = if ui_state.filter_mode {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Green)
    };

    let filter_input = Paragraph::new(input_text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(style)
        .wrap(Wrap { trim: false });

    f.render_widget(filter_input, area);
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
    } else if !ui_state.filter_query.is_empty() {
        format!(
            " Press 'h' for help | '/' to filter | Showing {} filtered connections (Esc to clear filter) ",
            connection_count
        )
    } else {
        format!(
            " Press 'h' for help | '/' to filter & navigate | 'c' to copy address | Connections: {} ",
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
            Span::styled("Loading network connections...", Style::default()),
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
    fn test_sort_column_cycle() {
        use SortColumn::*;

        // Test the complete cycle (follows left-to-right visual order)
        assert_eq!(CreatedAt.next(), Protocol);
        assert_eq!(Protocol.next(), LocalAddress);
        assert_eq!(LocalAddress.next(), RemoteAddress);
        assert_eq!(RemoteAddress.next(), State);
        assert_eq!(State.next(), Service);
        assert_eq!(Service.next(), Application);
        assert_eq!(Application.next(), BandwidthTotal);
        assert_eq!(BandwidthTotal.next(), Process);
        assert_eq!(Process.next(), CreatedAt); // Cycles back
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
                Protocol::TCP,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443),
                ProtocolState::Tcp(crate::network::types::TcpState::Established),
            ),
            Connection::new(
                Protocol::TCP,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 443),
                ProtocolState::Tcp(crate::network::types::TcpState::Established),
            ),
            Connection::new(
                Protocol::TCP,
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
