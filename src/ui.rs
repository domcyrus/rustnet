use anyhow::Result;
use ratatui::{
    Frame, Terminal as RatatuiTerminal,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Cell, Chart, Dataset, GraphType, Paragraph, Row, Sparkline, Table,
        Tabs, Wrap,
    },
};

use crate::app::{App, AppStats};
use crate::network::types::{
    AppProtocolDistribution, Connection, Protocol, ProtocolState, TcpState, TrafficHistory,
};

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
        3 => draw_graph_tab(f, app, connections, content_area)?,
        4 => draw_help(f, content_area)?,
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
        Span::styled("Graph", Style::default().fg(Color::Green)),
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
            Constraint::Length(7),  // Network stats (TCP analytics + header)
            Constraint::Length(4),  // Security stats (sandbox)
            Constraint::Min(0),     // Interface stats (with traffic graph)
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
    f.render_widget(network_stats, chunks[1]);

    // Security statistics (sandbox) - Linux only shows Landlock info
    #[cfg(target_os = "linux")]
    let security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();
        let status_style = match sandbox_info.status.as_str() {
            "Fully enforced" => Style::default().fg(Color::Green),
            "Partially enforced" => Style::default().fg(Color::Yellow),
            "Not applied" | "Error" => Style::default().fg(Color::Red),
            _ => Style::default(),
        };

        let mut features = Vec::new();
        if sandbox_info.cap_dropped {
            features.push("CAP_NET_RAW dropped");
        }
        if sandbox_info.fs_restricted {
            features.push("FS restricted");
        }
        if sandbox_info.net_restricted {
            features.push("Net blocked");
        }

        let available_indicator = if sandbox_info.landlock_available {
            Span::styled(" [kernel supported]", Style::default().fg(Color::DarkGray))
        } else {
            Span::styled(
                " [kernel unsupported]",
                Style::default().fg(Color::DarkGray),
            )
        };

        vec![
            Line::from(vec![
                Span::raw("Landlock: "),
                Span::styled(sandbox_info.status.clone(), status_style),
                available_indicator,
            ]),
            Line::from(Span::styled(
                if features.is_empty() {
                    "No restrictions active".to_string()
                } else {
                    features.join(", ")
                },
                Style::default().fg(Color::Gray),
            )),
        ]
    };

    // Non-Linux platforms: show privilege info without mentioning Landlock
    #[cfg(all(unix, not(target_os = "linux")))]
    let security_text: Vec<Line> = {
        let uid = unsafe { libc::geteuid() };
        let is_root = uid == 0;
        if is_root {
            vec![Line::from(Span::styled(
                "Running as root (UID 0)",
                Style::default().fg(Color::Yellow),
            ))]
        } else {
            vec![Line::from(Span::styled(
                format!("Running as UID {}", uid),
                Style::default().fg(Color::Green),
            ))]
        }
    };

    #[cfg(target_os = "windows")]
    let security_text: Vec<Line> = {
        let is_elevated = crate::is_admin();
        if is_elevated {
            vec![Line::from(Span::styled(
                "Running as Administrator",
                Style::default().fg(Color::Yellow),
            ))]
        } else {
            vec![Line::from(Span::styled(
                "Running as standard user",
                Style::default().fg(Color::Green),
            ))]
        }
    };

    let security_stats = Paragraph::new(security_text)
        .block(Block::default().borders(Borders::ALL).title("Security"))
        .style(Style::default());
    f.render_widget(security_stats, chunks[2]);

    // Interface statistics with traffic graph
    draw_interface_stats_with_graph(f, app, chunks[3])?;

    Ok(())
}

/// Draw interface stats section with embedded traffic sparklines
fn draw_interface_stats_with_graph(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Interface Stats (press 'i')");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Split into: sparklines (3 lines) + interface details (remaining)
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Traffic sparklines
            Constraint::Min(0),    // Interface details
        ])
        .split(inner);

    // Draw traffic sparklines
    let traffic_history = app.get_traffic_history();
    let sparkline_width = sections[0].width.saturating_sub(8) as usize; // Leave room for labels

    // Split sparkline area into rows
    let sparkline_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // RX sparkline
            Constraint::Length(1), // TX sparkline
            Constraint::Length(1), // Current rates
        ])
        .split(sections[0]);

    // RX row: label + sparkline
    let rx_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(sparkline_rows[0]);

    let rx_label = Paragraph::new("RX").style(Style::default().fg(Color::Green));
    f.render_widget(rx_label, rx_cols[0]);

    let rx_data = traffic_history.get_rx_sparkline_data(sparkline_width);
    let rx_sparkline = Sparkline::default()
        .data(&rx_data)
        .style(Style::default().fg(Color::Green));
    f.render_widget(rx_sparkline, rx_cols[1]);

    // TX row: label + sparkline
    let tx_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(sparkline_rows[1]);

    let tx_label = Paragraph::new("TX").style(Style::default().fg(Color::Blue));
    f.render_widget(tx_label, tx_cols[0]);

    let tx_data = traffic_history.get_tx_sparkline_data(sparkline_width);
    let tx_sparkline = Sparkline::default()
        .data(&tx_data)
        .style(Style::default().fg(Color::Blue));
    f.render_widget(tx_sparkline, tx_cols[1]);

    // Current rates row
    let (current_rx, current_tx) = rx_data
        .last()
        .zip(tx_data.last())
        .map(|(rx, tx)| (*rx, *tx))
        .unwrap_or((0, 0));

    let rates_text = Line::from(vec![
        Span::styled(
            format!("↓{}/s", format_bytes(current_rx)),
            Style::default().fg(Color::Green),
        ),
        Span::raw(" "),
        Span::styled(
            format!("↑{}/s", format_bytes(current_tx)),
            Style::default().fg(Color::Blue),
        ),
    ]);
    let rates_para = Paragraph::new(rates_text);
    f.render_widget(rates_para, sparkline_rows[2]);

    // Interface details section (errors/drops only, rates shown in sparklines above)
    let all_interface_stats = app.get_interface_stats();

    // Filter to show only the captured interface (or active interfaces if "any" or "pktap")
    let captured_interface = app.get_current_interface();
    let filtered_interface_stats: Vec<_> = if let Some(ref iface) = captured_interface {
        let is_npf_device = iface.starts_with("\\Device\\NPF_");

        if iface == "any" || iface == "pktap" || is_npf_device {
            all_interface_stats
                .into_iter()
                .filter(|s| {
                    s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0
                })
                .collect()
        } else {
            all_interface_stats
                .into_iter()
                .filter(|s| s.interface_name == *iface)
                .collect()
        }
    } else {
        all_interface_stats
            .into_iter()
            .filter(|s| s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0)
            .collect()
    };

    // Calculate how many interfaces can fit (1 line per interface now)
    let available_height = sections[1].height as usize;
    let max_interfaces = available_height.saturating_sub(1); // Reserve 1 for "more" message

    let interface_text: Vec<Line> = if filtered_interface_stats.is_empty() {
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

            // Show interface name with errors/drops on single line
            lines.push(Line::from(vec![
                Span::raw(format!("{}: ", stat.interface_name)),
                Span::raw("Err: "),
                Span::styled(format!("{}", total_errors), error_style),
                Span::raw("  Drop: "),
                Span::styled(format!("{}", total_drops), drop_style),
            ]));
        }

        if filtered_interface_stats.len() > num_to_show {
            lines.push(Line::from(Span::styled(
                format!(
                    "... {} more (press 'i')",
                    filtered_interface_stats.len() - num_to_show
                ),
                Style::default().fg(Color::Gray),
            )));
        }
        lines
    };

    let interface_para = Paragraph::new(interface_text);
    f.render_widget(interface_para, sections[1]);

    Ok(())
}

/// Draw the Graph tab with traffic visualization
fn draw_graph_tab(f: &mut Frame, app: &App, connections: &[Connection], area: Rect) -> Result<()> {
    let traffic_history = app.get_traffic_history();

    // Main layout: traffic chart, health chart, legend, bottom row
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35), // Traffic chart
            Constraint::Percentage(20), // Network health + TCP states
            Constraint::Length(1),      // Legend row
            Constraint::Min(0),         // App distribution + top processes
        ])
        .split(area);

    // Top row: traffic chart (70%) + connections sparkline (30%)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    // Health row: health gauges (35%) + TCP counters (35%) + TCP states (30%)
    let health_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    // Bottom row: app distribution (50%) + top processes (50%)
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[3]);

    // Draw components
    draw_traffic_chart(f, &traffic_history, top_chunks[0]);
    draw_connections_sparkline(f, &traffic_history, top_chunks[1]);
    draw_health_chart(f, &traffic_history, health_chunks[0]);
    draw_tcp_counters(f, app, health_chunks[1]);
    draw_tcp_states(f, connections, health_chunks[2]);
    draw_traffic_legend(f, main_chunks[2]);
    draw_app_distribution(f, connections, bottom_chunks[0]);
    draw_top_processes(f, connections, bottom_chunks[1]);

    Ok(())
}

/// Draw the full traffic chart with RX/TX lines
fn draw_traffic_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Traffic Over Time (60s)");

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting data...")
            .block(block)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(placeholder, area);
        return;
    }

    let (rx_data, tx_data) = history.get_chart_data();

    // Find max value for Y axis scaling
    let max_rate = rx_data
        .iter()
        .chain(tx_data.iter())
        .map(|(_, y)| *y)
        .fold(0.0f64, |a, b| a.max(b))
        .max(1024.0); // Minimum 1 KB/s scale

    let datasets = vec![
        Dataset::default()
            .name("RX ↓")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Green))
            .data(&rx_data),
        Dataset::default()
            .name("TX ↑")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Blue))
            .data(&tx_data),
    ];

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .title("Time")
                .style(Style::default().fg(Color::Gray))
                .bounds([-60.0, 0.0])
                .labels(vec![
                    Line::from("-60s"),
                    Line::from("-30s"),
                    Line::from("now"),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("Rate")
                .style(Style::default().fg(Color::Gray))
                .bounds([0.0, max_rate])
                .labels(vec![
                    Line::from("0"),
                    Line::from(format_rate_compact(max_rate / 2.0)),
                    Line::from(format_rate_compact(max_rate)),
                ]),
        );

    f.render_widget(chart, area);
}

/// Draw connections count sparkline
fn draw_connections_sparkline(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = Block::default().borders(Borders::ALL).title("Connections");

    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder =
            Paragraph::new("Collecting...").style(Style::default().fg(Color::DarkGray));
        f.render_widget(placeholder, inner);
        return;
    }

    // Layout: sparkline + current count label
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let width = inner.width as usize;
    let conn_data = history.get_connection_sparkline_data(width);

    let sparkline = Sparkline::default()
        .data(&conn_data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(sparkline, chunks[0]);

    // Current connection count label
    let current_count = conn_data.last().copied().unwrap_or(0);
    let label = Paragraph::new(format!("{} connections", current_count))
        .style(Style::default().fg(Color::White));
    f.render_widget(label, chunks[1]);
}

/// Draw application protocol distribution
fn draw_app_distribution(f: &mut Frame, connections: &[Connection], area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Application Distribution");

    let inner = block.inner(area);
    f.render_widget(block, area);

    let dist = AppProtocolDistribution::from_connections(connections);
    let percentages = dist.as_percentages();

    // Filter out zero-count protocols and create bars
    let mut lines: Vec<Line> = Vec::new();

    for (label, count, pct) in percentages {
        if count == 0 {
            continue;
        }

        // Create a bar visualization
        let bar_width = (inner.width as f64 * 0.6) as usize; // 60% for bar
        let filled = ((pct / 100.0) * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width.saturating_sub(filled));

        let color = match label {
            "HTTPS" => Color::Green,
            "QUIC" => Color::Cyan,
            "HTTP" => Color::Yellow,
            "DNS" => Color::Magenta,
            "SSH" => Color::Blue,
            _ => Color::Gray,
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{:6}", label), Style::default().fg(color)),
            Span::raw(" "),
            Span::styled(bar, Style::default().fg(color)),
            Span::raw(format!(" {:5.1}%", pct)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No connections",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

/// Draw top processes by bandwidth
fn draw_top_processes(f: &mut Frame, connections: &[Connection], area: Rect) {
    use std::collections::HashMap;

    let block = Block::default()
        .borders(Borders::ALL)
        .title("Top Processes");

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Aggregate traffic by process
    let mut process_traffic: HashMap<String, f64> = HashMap::new();
    for conn in connections {
        let name = conn
            .process_name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let traffic = conn.current_incoming_rate_bps + conn.current_outgoing_rate_bps;
        *process_traffic.entry(name).or_insert(0.0) += traffic;
    }

    // Sort by traffic descending, filter out processes with no traffic
    let mut sorted: Vec<_> = process_traffic
        .into_iter()
        .filter(|(_, rate)| *rate > 0.0)
        .collect();
    sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Create rows for top 5 processes
    let rows: Vec<Row> = sorted
        .into_iter()
        .take(5)
        .map(|(name, rate)| {
            let display_name = if name.len() > 20 {
                format!("{}...", &name[..17])
            } else {
                name
            };
            Row::new(vec![
                Cell::from(display_name),
                Cell::from(format_rate(rate)).style(Style::default().fg(Color::Cyan)),
            ])
        })
        .collect();

    if rows.is_empty() {
        let placeholder =
            Paragraph::new("No active processes").style(Style::default().fg(Color::DarkGray));
        f.render_widget(placeholder, inner);
        return;
    }

    let table = Table::new(
        rows,
        [Constraint::Percentage(60), Constraint::Percentage(40)],
    )
    .header(
        Row::new(vec!["Process", "Rate"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    );

    f.render_widget(table, inner);
}

/// Draw chart legend
fn draw_traffic_legend(f: &mut Frame, area: Rect) {
    let legend = Paragraph::new(Line::from(vec![
        Span::styled("▬", Style::default().fg(Color::Green)),
        Span::raw(" RX (incoming)  "),
        Span::styled("▬", Style::default().fg(Color::Blue)),
        Span::raw(" TX (outgoing)"),
    ]))
    .style(Style::default().fg(Color::DarkGray));

    f.render_widget(legend, area);
}

/// Draw the network health gauges with RTT and packet loss bars
fn draw_health_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Network Health");

    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder =
            Paragraph::new("Collecting data...").style(Style::default().fg(Color::DarkGray));
        f.render_widget(placeholder, inner);
        return;
    }

    // Get current values from history
    let (loss_data, rtt_data) = history.get_health_chart_data();

    // Get most recent values (last data point)
    let current_loss = loss_data.last().map(|(_, v)| *v).unwrap_or(0.0);
    let current_rtt = rtt_data.last().map(|(_, v)| *v);

    // Calculate averages
    let avg_loss = if !loss_data.is_empty() {
        loss_data.iter().map(|(_, v)| v).sum::<f64>() / loss_data.len() as f64
    } else {
        0.0
    };
    let avg_rtt = if !rtt_data.is_empty() {
        Some(rtt_data.iter().map(|(_, v)| v).sum::<f64>() / rtt_data.len() as f64)
    } else {
        None
    };

    // Thresholds for gauges
    const RTT_MAX: f64 = 200.0; // 200ms max scale
    const LOSS_MAX: f64 = 10.0; // 10% max scale

    let bar_width = inner.width.saturating_sub(18) as usize; // Leave room for label + value

    // Build RTT gauge
    let rtt_line = if let Some(rtt) = current_rtt {
        let rtt_pct = (rtt / RTT_MAX).min(1.0);
        let filled = (rtt_pct * bar_width as f64) as usize;
        let empty = bar_width.saturating_sub(filled);

        let color = if rtt < 50.0 {
            Color::Green
        } else if rtt < 150.0 {
            Color::Yellow
        } else {
            Color::Red
        };

        Line::from(vec![
            Span::styled("  RTT  ", Style::default().fg(Color::White)),
            Span::styled("█".repeat(filled), Style::default().fg(color)),
            Span::styled("░".repeat(empty), Style::default().fg(Color::DarkGray)),
            Span::styled(format!(" {:>6.1}ms", rtt), Style::default().fg(color)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  RTT  ", Style::default().fg(Color::White)),
            Span::styled("░".repeat(bar_width), Style::default().fg(Color::DarkGray)),
            Span::styled("    --  ", Style::default().fg(Color::DarkGray)),
        ])
    };

    // Build Loss gauge
    let loss_pct = (current_loss / LOSS_MAX).min(1.0);
    let filled = (loss_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);

    let loss_color = if current_loss < 1.0 {
        Color::Green
    } else if current_loss < 5.0 {
        Color::Yellow
    } else {
        Color::Red
    };

    let loss_line = Line::from(vec![
        Span::styled("  Loss ", Style::default().fg(Color::White)),
        Span::styled(
            "█".repeat(filled.max(if current_loss > 0.0 { 1 } else { 0 })),
            Style::default().fg(loss_color),
        ),
        Span::styled(
            "░".repeat(empty.min(bar_width)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!(" {:>6.2}%", current_loss),
            Style::default().fg(loss_color),
        ),
    ]);

    // Build averages line
    let avg_line = Line::from(vec![
        Span::styled("  avg: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            avg_rtt
                .map(|r| format!("{:.0}ms", r))
                .unwrap_or_else(|| "--".to_string()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(" / ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("{:.2}%", avg_loss),
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    let paragraph = Paragraph::new(vec![rtt_line, loss_line, avg_line]);
    f.render_widget(paragraph, inner);
}

/// Draw TCP counters (retransmits, out of order, fast retransmits)
fn draw_tcp_counters(f: &mut Frame, app: &App, area: Rect) {
    use std::sync::atomic::Ordering;

    let stats = app.get_stats();
    let retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
    let out_of_order = stats.total_tcp_out_of_order.load(Ordering::Relaxed);
    let fast_retransmits = stats.total_tcp_fast_retransmits.load(Ordering::Relaxed);

    let block = Block::default().borders(Borders::ALL).title("TCP Counters");

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Color based on counts (higher = more concerning)
    let retrans_color = if retransmits == 0 {
        Color::Green
    } else if retransmits < 100 {
        Color::Yellow
    } else {
        Color::Red
    };

    let ooo_color = if out_of_order == 0 {
        Color::Green
    } else if out_of_order < 50 {
        Color::Yellow
    } else {
        Color::Red
    };

    let fast_color = if fast_retransmits == 0 {
        Color::Green
    } else if fast_retransmits < 50 {
        Color::Yellow
    } else {
        Color::Red
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Retransmits  ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:>8}", retransmits),
                Style::default().fg(retrans_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Out of Order ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:>8}", out_of_order),
                Style::default().fg(ooo_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Fast Retrans ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:>8}", fast_retransmits),
                Style::default().fg(fast_color),
            ),
        ]),
    ];

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

/// Draw TCP connection states breakdown
fn draw_tcp_states(f: &mut Frame, connections: &[Connection], area: Rect) {
    use std::collections::HashMap;

    // Count TCP states
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    for conn in connections {
        if conn.protocol == Protocol::TCP
            && let ProtocolState::Tcp(tcp_state) = &conn.protocol_state
        {
            let state_name = match tcp_state {
                TcpState::Established => "ESTAB",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RECV",
                TcpState::FinWait1 => "FIN_WAIT1",
                TcpState::FinWait2 => "FIN_WAIT2",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::LastAck => "LAST_ACK",
                TcpState::Closing => "CLOSING",
                TcpState::Closed => "CLOSED",
                TcpState::Listen => "LISTEN",
                TcpState::Unknown => "UNKNOWN",
            };
            *state_counts.entry(state_name).or_insert(0) += 1;
        }
    }

    // Fixed order based on connection lifecycle (most important first)
    const STATE_ORDER: &[&str] = &[
        "ESTAB",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "CLOSING",
        "CLOSED",
        "LISTEN",
        "UNKNOWN",
    ];

    // Build ordered list with only non-zero counts
    let states: Vec<_> = STATE_ORDER
        .iter()
        .filter_map(|&name| state_counts.get(name).map(|&count| (name, count)))
        .collect();

    let block = Block::default().borders(Borders::ALL).title("TCP States");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if states.is_empty() {
        let text = Paragraph::new("No TCP connections").style(Style::default().fg(Color::DarkGray));
        f.render_widget(text, inner);
        return;
    }

    // Find max count for bar scaling
    let max_count = states.iter().map(|(_, c)| *c).max().unwrap_or(1);
    let bar_width = inner.width.saturating_sub(15) as usize; // Leave room for label + count

    // Build lines for each state (limit to available height)
    let max_rows = inner.height as usize;
    let lines: Vec<Line> = states
        .iter()
        .take(max_rows)
        .map(|(name, count)| {
            let bar_len = if max_count > 0 {
                (*count * bar_width) / max_count
            } else {
                0
            };
            let bar = "█".repeat(bar_len.max(1));

            // Color based on state health
            let color = match *name {
                "ESTAB" => Color::Green,
                "SYN_SENT" | "SYN_RECV" => Color::Yellow,
                "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => Color::Cyan,
                "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => Color::Magenta,
                "CLOSED" => Color::DarkGray,
                _ => Color::White,
            };

            Line::from(vec![
                Span::styled(format!("{:>10} ", name), Style::default().fg(color)),
                Span::styled(bar, Style::default().fg(color)),
                Span::raw(format!(" {}", count)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
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

    // Add initial RTT measurement if available
    if let Some(rtt) = conn.initial_rtt {
        let rtt_ms = rtt.as_secs_f64() * 1000.0;
        let rtt_color = if rtt_ms < 50.0 {
            Color::Green
        } else if rtt_ms < 150.0 {
            Color::Yellow
        } else {
            Color::Red
        };
        details_text.push(Line::from(vec![
            Span::styled("Initial RTT: ", Style::default().fg(Color::Yellow)),
            Span::styled(format!("{:.1}ms", rtt_ms), Style::default().fg(rtt_color)),
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
            "Tabs:",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![
            Span::styled("  Overview ", Style::default().fg(Color::Green)),
            Span::raw("Connection list with mini traffic graph"),
        ]),
        Line::from(vec![
            Span::styled("  Details ", Style::default().fg(Color::Green)),
            Span::raw("Full details for selected connection"),
        ]),
        Line::from(vec![
            Span::styled("  Interfaces ", Style::default().fg(Color::Green)),
            Span::raw("Network interface statistics"),
        ]),
        Line::from(vec![
            Span::styled("  Graph ", Style::default().fg(Color::Green)),
            Span::raw("Traffic charts and protocol distribution"),
        ]),
        Line::from(vec![
            Span::styled("  Help ", Style::default().fg(Color::Green)),
            Span::raw("This help screen"),
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
            " 'h' help | Tab/Shift+Tab switch tabs | Showing {} filtered connections (Esc to clear) ",
            connection_count
        )
    } else {
        format!(
            " 'h' help | Tab/Shift+Tab switch tabs | '/' filter | 'c' copy | Connections: {} ",
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
