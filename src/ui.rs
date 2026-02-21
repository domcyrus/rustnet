use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

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
use crate::network::dns::DnsResolver;
use crate::network::types::{
    AppProtocolDistribution, Connection, Protocol, ProtocolState, TcpState, TrafficHistory,
};

pub type Terminal<B> = RatatuiTerminal<B>;

/// Placeholder string displayed when a value is unavailable.
const NONE_PLACEHOLDER: &str = "-";

/// Global flag for NO_COLOR support (https://no-color.org)
static NO_COLOR: AtomicBool = AtomicBool::new(false);

/// Enable NO_COLOR mode (strips all colors from the UI)
pub fn set_no_color(enabled: bool) {
    NO_COLOR.store(enabled, Ordering::Relaxed);
}

/// Centralized color palette for cross-terminal consistency.
/// All semantic colors derive from these 7 base constants.
mod theme {
    use ratatui::style::{Color, Modifier, Style};

    // --- 7-slot base palette ---
    const OK: Color = Color::Green; // Healthy/success
    const WARN: Color = Color::Yellow; // Caution/attention
    const ERR: Color = Color::Red; // Error/critical
    const ACCENT: Color = Color::Cyan; // Informational highlight
    const MUTED: Color = Color::Gray; // Secondary/inactive
    const INFO: Color = Color::Blue; // Neutral info
    const SPECIAL: Color = Color::Magenta; // Distinct/special

    // --- Base color accessors ---
    pub fn ok() -> Color {
        OK
    }
    pub fn warn() -> Color {
        WARN
    }
    pub fn err() -> Color {
        ERR
    }
    pub fn accent() -> Color {
        ACCENT
    }
    pub fn muted() -> Color {
        MUTED
    }
    pub fn info() -> Color {
        INFO
    }
    pub fn special() -> Color {
        SPECIAL
    }

    // --- UI element aliases ---
    pub fn label() -> Color {
        accent()
    }
    pub fn heading() -> Color {
        warn()
    }
    pub fn key() -> Color {
        warn()
    }

    // --- Network aliases ---
    pub fn rx() -> Color {
        ok()
    }
    pub fn tx() -> Color {
        info()
    }

    // --- Protocol aliases ---
    pub fn proto_https() -> Color {
        ok()
    }
    pub fn proto_quic() -> Color {
        accent()
    }
    pub fn proto_http() -> Color {
        warn()
    }
    pub fn proto_dns() -> Color {
        special()
    }
    pub fn proto_ssh() -> Color {
        info()
    }
    pub fn proto_other() -> Color {
        muted()
    }

    // --- TCP state aliases ---
    pub fn tcp_established() -> Color {
        ok()
    }
    pub fn tcp_opening() -> Color {
        warn()
    }
    pub fn tcp_closing() -> Color {
        accent()
    }
    pub fn tcp_waiting() -> Color {
        special()
    }
    pub fn tcp_closed() -> Color {
        muted()
    }

    // --- Status bar styles ---
    // Uses REVERSED modifier instead of fg(Black).bg(Color) which breaks on dark terminals
    pub fn status_bar_confirm() -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            return Style::default().add_modifier(Modifier::REVERSED);
        }
        Style::default()
            .fg(warn())
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    }
    pub fn status_bar_success() -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            return Style::default().add_modifier(Modifier::REVERSED);
        }
        Style::default()
            .fg(ok())
            .add_modifier(Modifier::BOLD | Modifier::REVERSED)
    }
    pub fn status_bar_default() -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            return Style::default().add_modifier(Modifier::REVERSED);
        }
        Style::default().fg(info()).add_modifier(Modifier::REVERSED)
    }

    // --- Style builders (NO_COLOR-aware) ---

    /// Apply a foreground color, respecting NO_COLOR.
    pub fn fg(color: Color) -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            Style::default()
        } else {
            Style::default().fg(color)
        }
    }

    /// Apply a foreground color with BOLD, respecting NO_COLOR.
    pub fn bold_fg(color: Color) -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        }
    }

    /// Apply a foreground color with BOLD + UNDERLINED, respecting NO_COLOR.
    pub fn bold_underline_fg(color: Color) -> Style {
        if super::NO_COLOR.load(super::Ordering::Relaxed) {
            Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        } else {
            Style::default()
                .fg(color)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
        }
    }
}

/// Sort column options for the connections table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortColumn {
    #[default]
    CreatedAt, // Default: creation time (oldest first)
    BandwidthTotal, // Combined up + down bandwidth
    Process,
    LocalAddress,
    RemoteAddress,
    Location, // GeoIP country code (only in cycle when GeoIP is active)
    Application,
    Service,
    State,
    Protocol,
}

impl SortColumn {
    /// Get the next sort column in the cycle (follows left-to-right visual order).
    /// When `has_location` is true, Location is included between Remote Address and State.
    pub fn next(self, has_location: bool) -> Self {
        match self {
            Self::CreatedAt => Self::Protocol,         // Column 1: Pro
            Self::Protocol => Self::LocalAddress,      // Column 2: Local Address
            Self::LocalAddress => Self::RemoteAddress, // Column 3: Remote Address
            Self::RemoteAddress => {
                if has_location {
                    Self::Location // Column 4: Loc (GeoIP)
                } else {
                    Self::State
                }
            }
            Self::Location => Self::State,      // Column 5: State
            Self::State => Self::Service,       // Column 6: Service
            Self::Service => Self::Application, // Column 7: Application / Host
            Self::Application => Self::BandwidthTotal, // Column 8: Down/Up (combined total)
            Self::BandwidthTotal => Self::Process, // Column 9: Process
            Self::Process => Self::CreatedAt,   // Back to default
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
            Self::Location => true,
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
            Self::Location => "Location",
            Self::Application => "Application",
            Self::Service => "Service",
            Self::State => "State",
            Self::Protocol => "Protocol",
        }
    }
}

/// Aggregated stats for a process group
#[derive(Debug, Clone, Default)]
pub struct ProcessGroupStats {
    pub connection_count: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub total_incoming_rate_bps: f64,
    pub total_outgoing_rate_bps: f64,
}

/// A row in the grouped display (either a group header or a connection)
#[derive(Debug, Clone)]
pub enum GroupedRow {
    /// A collapsed or expanded group header
    Group {
        process_name: String,
        stats: ProcessGroupStats,
        expanded: bool,
    },
    /// An individual connection within an expanded group
    Connection {
        process_name: String,
        connection: Box<Connection>,
        is_last_in_group: bool,
    },
}

/// Set up the terminal for the TUI application
pub fn setup_terminal<B: ratatui::backend::Backend>(backend: B) -> Result<Terminal<B>>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
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
pub fn restore_terminal<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
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
    pub clear_confirmation: bool,
    pub clipboard_message: Option<(String, std::time::Instant)>,
    pub filter_mode: bool,
    pub filter_query: String,
    pub filter_cursor_position: usize,
    pub show_port_numbers: bool,
    pub sort_column: SortColumn,
    pub sort_ascending: bool,
    /// Show hostnames instead of IP addresses (when DNS resolution is enabled)
    pub show_hostnames: bool,
    /// Whether grouping by process is enabled
    pub grouping_enabled: bool,
    /// Set of expanded process group names
    pub expanded_groups: HashSet<String>,
    /// Selected group name when in grouped view (for group-level selection)
    pub selected_group: Option<String>,
    /// Whether GeoIP country database is available (enables Location sort column)
    pub has_geoip: bool,
}

impl Default for UIState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            show_help: false,
            quit_confirmation: false,
            clear_confirmation: false,
            clipboard_message: None,
            filter_mode: false,
            filter_query: String::new(),
            filter_cursor_position: 0,
            show_port_numbers: false,
            sort_column: SortColumn::default(),
            sort_ascending: true, // Default to ascending
            show_hostnames: true, // Show hostnames by default when DNS resolution is enabled
            grouping_enabled: false,
            expanded_groups: HashSet::new(),
            selected_group: None,
            has_geoip: false,
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
        self.sort_column = self.sort_column.next(self.has_geoip);
        // Reset to the default direction for the new column
        self.sort_ascending = self.sort_column.default_direction();
    }

    /// Toggle the sort direction for the current column
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
    }

    /// Reset all view settings to defaults (grouping, sort, filter)
    pub fn reset_view(&mut self) {
        self.grouping_enabled = false;
        self.expanded_groups.clear();
        self.selected_group = None;
        self.sort_column = SortColumn::default();
        self.sort_ascending = self.sort_column.default_direction();
        self.filter_query.clear();
        self.filter_mode = false;
        self.filter_cursor_position = 0;
    }

    /// Toggle grouping mode
    pub fn toggle_grouping(&mut self) {
        self.grouping_enabled = !self.grouping_enabled;
        // When toggling grouping on, clear group selection to start fresh
        if self.grouping_enabled {
            self.selected_group = None;
        }
    }

    /// Toggle expansion of the currently selected group
    pub fn toggle_group_expansion(&mut self) {
        if let Some(ref group_name) = self.selected_group {
            if self.expanded_groups.contains(group_name) {
                self.expanded_groups.remove(group_name);
            } else {
                self.expanded_groups.insert(group_name.clone());
            }
        }
    }

    /// Expand the currently selected group
    pub fn expand_selected_group(&mut self) {
        if let Some(ref group_name) = self.selected_group {
            self.expanded_groups.insert(group_name.clone());
        }
    }

    /// Collapse the currently selected group
    pub fn collapse_selected_group(&mut self) {
        if let Some(ref group_name) = self.selected_group {
            self.expanded_groups.remove(group_name);
        }
    }

    /// Get the current selected index in the grouped rows
    pub fn get_selected_grouped_index(&self, grouped_rows: &[GroupedRow]) -> Option<usize> {
        if grouped_rows.is_empty() {
            return None;
        }

        // First check if we have a selected connection that's visible
        if let Some(ref selected_key) = self.selected_connection_key {
            for (idx, row) in grouped_rows.iter().enumerate() {
                if let GroupedRow::Connection { connection, .. } = row
                    && connection.key() == *selected_key
                {
                    return Some(idx);
                }
            }
        }

        // Then check if we have a selected group
        if let Some(ref selected_group) = self.selected_group {
            for (idx, row) in grouped_rows.iter().enumerate() {
                if let GroupedRow::Group { process_name, .. } = row
                    && process_name == selected_group
                {
                    return Some(idx);
                }
            }
        }

        // Default to first row
        Some(0)
    }

    /// Set the selection based on a grouped row index
    pub fn set_selected_grouped_by_index(&mut self, grouped_rows: &[GroupedRow], index: usize) {
        if let Some(row) = grouped_rows.get(index) {
            match row {
                GroupedRow::Group { process_name, .. } => {
                    self.selected_group = Some(process_name.clone());
                    self.selected_connection_key = None;
                }
                GroupedRow::Connection {
                    process_name,
                    connection,
                    ..
                } => {
                    self.selected_connection_key = Some(connection.key());
                    self.selected_group = Some(process_name.clone());
                }
            }
        }
    }

    /// Move selection up in grouped view
    pub fn move_selection_up_grouped(&mut self, grouped_rows: &[GroupedRow]) {
        if grouped_rows.is_empty() {
            return;
        }

        let current_index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        let new_index = if current_index > 0 {
            current_index - 1
        } else {
            grouped_rows.len() - 1 // Wrap to bottom
        };
        self.set_selected_grouped_by_index(grouped_rows, new_index);
    }

    /// Move selection down in grouped view
    pub fn move_selection_down_grouped(&mut self, grouped_rows: &[GroupedRow]) {
        if grouped_rows.is_empty() {
            return;
        }

        let current_index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        let new_index = if current_index < grouped_rows.len() - 1 {
            current_index + 1
        } else {
            0 // Wrap to top
        };
        self.set_selected_grouped_by_index(grouped_rows, new_index);
    }

    /// Ensure valid selection in grouped view
    pub fn ensure_valid_grouped_selection(&mut self, grouped_rows: &[GroupedRow]) {
        if grouped_rows.is_empty() {
            self.selected_group = None;
            self.selected_connection_key = None;
            return;
        }

        // If no group is selected, or current selection is not visible, reset to first row
        // This handles the case when grouping is first enabled
        let needs_init = self.selected_group.is_none()
            || self.get_selected_grouped_index(grouped_rows).is_none();

        if needs_init {
            self.set_selected_grouped_by_index(grouped_rows, 0);
        }
    }

    /// Check if the current selection is on a group header
    pub fn is_group_selected(&self) -> bool {
        self.selected_group.is_some() && self.selected_connection_key.is_none()
    }
}

/// Compute grouped rows from a list of connections
pub fn compute_grouped_rows(
    connections: &[Connection],
    expanded_groups: &HashSet<String>,
) -> Vec<GroupedRow> {
    use std::collections::HashMap;

    // Group connections by process name
    let mut groups: HashMap<String, Vec<&Connection>> = HashMap::new();
    for conn in connections {
        let key = conn
            .process_name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string());
        groups.entry(key).or_default().push(conn);
    }

    // Build stats for each group and sort by total bandwidth (descending)
    let mut group_stats: Vec<(String, ProcessGroupStats, Vec<&Connection>)> = groups
        .into_iter()
        .map(|(name, conns)| {
            let stats = ProcessGroupStats {
                connection_count: conns.len(),
                tcp_count: conns.iter().filter(|c| c.protocol == Protocol::TCP).count(),
                udp_count: conns.iter().filter(|c| c.protocol == Protocol::UDP).count(),
                total_incoming_rate_bps: conns.iter().map(|c| c.current_incoming_rate_bps).sum(),
                total_outgoing_rate_bps: conns.iter().map(|c| c.current_outgoing_rate_bps).sum(),
            };
            (name, stats, conns)
        })
        .collect();

    // Sort groups alphabetically by process name for stable ordering
    // (sorting by bandwidth causes constant reordering as rates fluctuate)
    group_stats.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

    // Build the flattened row list
    let mut rows = Vec::new();
    for (name, stats, conns) in group_stats {
        let expanded = expanded_groups.contains(&name);
        rows.push(GroupedRow::Group {
            process_name: name.clone(),
            stats,
            expanded,
        });

        if expanded {
            let conn_count = conns.len();
            for (idx, conn) in conns.into_iter().enumerate() {
                rows.push(GroupedRow::Connection {
                    process_name: name.clone(),
                    connection: Box::new(conn.clone()),
                    is_last_in_group: idx == conn_count - 1,
                });
            }
        }
    }

    rows
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

    // Compute grouped rows if grouping is enabled
    let grouped_rows = if ui_state.grouping_enabled {
        Some(compute_grouped_rows(connections, &ui_state.expanded_groups))
    } else {
        None
    };

    match ui_state.selected_tab {
        0 => draw_overview(
            f,
            ui_state,
            connections,
            stats,
            app,
            content_area,
            grouped_rows.as_deref(),
        )?,
        1 => {
            let dns_resolver = app.get_dns_resolver();
            draw_connection_details(
                f,
                ui_state,
                connections,
                content_area,
                dns_resolver.as_deref(),
            )?
        }
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
        Span::styled("Overview", theme::fg(theme::ok())),
        Span::styled("Details", theme::fg(theme::ok())),
        Span::styled("Interfaces", theme::fg(theme::ok())),
        Span::styled("Graph", theme::fg(theme::ok())),
        Span::styled("Help", theme::fg(theme::ok())),
    ];

    let tabs = Tabs::new(titles.into_iter().map(Line::from).collect::<Vec<_>>())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("RustNet Monitor"),
        )
        .select(ui_state.selected_tab)
        .style(Style::default())
        .highlight_style(theme::bold_fg(theme::heading()));

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
    grouped_rows: Option<&[GroupedRow]>,
) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    // Get DNS resolver from app if enabled
    let dns_resolver = app.get_dns_resolver();

    // Get GeoIP status - only show Loc column if country DB is loaded
    let (has_country_db, _has_asn_db, _has_city_db) = app.get_geoip_status();

    // Use grouped view if grouping is enabled
    if ui_state.grouping_enabled {
        if let Some(rows) = grouped_rows {
            draw_grouped_connections_list(
                f,
                ui_state,
                rows,
                chunks[0],
                dns_resolver.as_deref(),
                has_country_db,
            );
        }
    } else {
        draw_connections_list(
            f,
            ui_state,
            connections,
            chunks[0],
            dns_resolver.as_deref(),
            has_country_db,
        );
    }

    draw_stats_panel(f, connections, stats, app, chunks[1])?;

    Ok(())
}

/// Draw connections list
fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
) {
    // When DNS resolution is enabled, we need more space for hostnames
    let remote_addr_width = if dns_resolver.is_some() && ui_state.show_hostnames {
        30
    } else {
        21
    };

    // Build column widths dynamically based on whether location is shown
    let mut widths = vec![
        Constraint::Length(6),                 // Protocol
        Constraint::Length(17),                // Local Address
        Constraint::Length(remote_addr_width), // Remote Address
    ];
    if show_location {
        widths.push(Constraint::Length(4)); // Location (2-char country code)
    }
    widths.extend([
        Constraint::Length(16), // State
        Constraint::Length(10), // Service
        Constraint::Length(24), // DPI/Application
        Constraint::Length(12), // Bandwidth
        Constraint::Min(20),    // Process
    ]);

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
            format!("Down/Up {}", arrow)
        }
        _ => "Down/Up".to_string(),
    };

    // Build header labels dynamically
    let mut header_labels = vec![
        add_sort_indicator("Pro", &[SortColumn::Protocol]),
        add_sort_indicator("Local Address", &[SortColumn::LocalAddress]),
        add_sort_indicator("Remote Address", &[SortColumn::RemoteAddress]),
    ];
    if show_location {
        header_labels.push(add_sort_indicator("Loc", &[SortColumn::Location]));
    }
    header_labels.extend([
        add_sort_indicator("State", &[SortColumn::State]),
        add_sort_indicator("Service", &[SortColumn::Service]),
        add_sort_indicator("Application / Host", &[SortColumn::Application]),
        bandwidth_label,
        add_sort_indicator("Process", &[SortColumn::Process]),
    ]);

    // Compute column index offsets based on whether location is shown
    // Columns: Pro(0), Local(1), Remote(2), [Loc(3)], State(3/4), Service(4/5), App(5/6), BW(6/7), Process(7/8)
    let state_idx = if show_location { 4 } else { 3 };
    let service_idx = if show_location { 5 } else { 4 };
    let app_idx = if show_location { 6 } else { 5 };
    let bw_idx = if show_location { 7 } else { 6 };
    let process_idx = if show_location { 8 } else { 7 };

    let header_cells = header_labels.iter().enumerate().map(|(idx, h)| {
        let is_active = (match idx {
            0 => ui_state.sort_column == SortColumn::Protocol,
            1 => ui_state.sort_column == SortColumn::LocalAddress,
            2 => ui_state.sort_column == SortColumn::RemoteAddress,
            i if show_location && i == 3 => ui_state.sort_column == SortColumn::Location,
            i if i == state_idx => ui_state.sort_column == SortColumn::State,
            i if i == service_idx => ui_state.sort_column == SortColumn::Service,
            i if i == app_idx => ui_state.sort_column == SortColumn::Application,
            i if i == bw_idx => ui_state.sort_column == SortColumn::BandwidthTotal,
            i if i == process_idx => ui_state.sort_column == SortColumn::Process,
            _ => false,
        }) && ui_state.sort_column != SortColumn::CreatedAt;

        let style = if is_active {
            // Active sort column: Cyan + Bold + Underlined
            theme::bold_underline_fg(theme::accent())
        } else {
            // Inactive columns: Yellow + Bold (normal)
            theme::bold_fg(theme::heading())
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
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());

            // Process names are now pre-normalized at the source (PKTAP/lsof), so we can use them directly
            let process_str = conn
                .process_name
                .clone()
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());

            let process_display = if conn.pid.is_some() {
                // Ensure exactly one space between process name and PID: "PROCESS_NAME (PID)"
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

            // Display port number or service name based on toggle
            let service_display = if ui_state.show_port_numbers {
                conn.remote_addr.port().to_string()
            } else {
                let service_name = conn
                    .service_name
                    .clone()
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
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
                None => NONE_PLACEHOLDER.to_string(),
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
                theme::fg(theme::err())
            } else if staleness >= 0.75 {
                // Warning: 75-90% of timeout - approaching cleanup
                theme::fg(theme::warn())
            } else {
                // Normal: < 75% of timeout
                Style::default()
            };

            // Format addresses - use hostnames when DNS resolution is enabled and show_hostnames is true
            let local_addr_display = conn.local_addr.to_string();
            let remote_addr_display = if ui_state.show_hostnames {
                if let Some(resolver) = dns_resolver {
                    if let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip()) {
                        // Truncate hostname if too long, but always show port
                        let port = conn.remote_addr.port();
                        let max_hostname_len = (remote_addr_width as usize).saturating_sub(7); // Leave room for :port
                        if hostname.len() > max_hostname_len {
                            format!(
                                "{}...:{}",
                                &hostname[..max_hostname_len.saturating_sub(3)],
                                port
                            )
                        } else {
                            format!("{}:{}", hostname, port)
                        }
                    } else {
                        conn.remote_addr.to_string()
                    }
                } else {
                    conn.remote_addr.to_string()
                }
            } else {
                conn.remote_addr.to_string()
            };

            // Build cells dynamically based on whether location is shown
            let mut cells = vec![
                Cell::from(conn.protocol.to_string()),
                Cell::from(local_addr_display),
                Cell::from(remote_addr_display),
            ];
            if show_location {
                let location_display = conn
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or("-");
                cells.push(Cell::from(location_display));
            }
            cells.extend([
                Cell::from(conn.state()),
                Cell::from(service_display),
                Cell::from(dpi_display),
                Cell::from(bandwidth_display),
                Cell::from(process_display),
            ]);
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

/// Draw grouped connections list (grouped by process)
fn draw_grouped_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    grouped_rows: &[GroupedRow],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
) {
    // Column layout for grouped view:
    // - First column shows expand/collapse indicator + process name or tree prefix + protocol
    // - Remaining columns similar to flat view but with adjusted widths
    let remote_addr_width = if dns_resolver.is_some() && ui_state.show_hostnames {
        26
    } else {
        18
    };

    // Build widths dynamically - Loc column only when GeoIP country DB available
    let mut widths = vec![
        Constraint::Min(28),    // Process/Protocol (wider for tree structure)
        Constraint::Length(17), // Local Address
        Constraint::Length(remote_addr_width), // Remote Address
    ];
    if show_location {
        widths.push(Constraint::Length(4)); // Location (2-char country code)
    }
    widths.extend([
        Constraint::Length(12), // State
        Constraint::Length(8),  // Service
        Constraint::Length(20), // Application/Host
        Constraint::Length(14), // Bandwidth
    ]);

    let header_style = theme::bold_fg(theme::heading());

    // Build header cells dynamically
    let mut header_cells = vec![
        Cell::from("Process / Protocol").style(header_style),
        Cell::from("Local Address").style(header_style),
        Cell::from("Remote Address").style(header_style),
    ];
    if show_location {
        header_cells.push(Cell::from("Loc").style(header_style));
    }
    header_cells.extend([
        Cell::from("State").style(header_style),
        Cell::from("Service").style(header_style),
        Cell::from("Application").style(header_style),
        Cell::from("Down/Up").style(header_style),
    ]);
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = grouped_rows
        .iter()
        .map(|row| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => {
                let expand_indicator = if *expanded { "[-]" } else { "[+]" };
                let process_cell = format!(
                    "{} {} ({})",
                    expand_indicator, process_name, stats.connection_count
                );

                // Protocol breakdown
                let proto_breakdown = format!("TCP:{} UDP:{}", stats.tcp_count, stats.udp_count);

                // Bandwidth display
                let incoming_rate = format_rate_compact(stats.total_incoming_rate_bps);
                let outgoing_rate = format_rate_compact(stats.total_outgoing_rate_bps);
                let bandwidth = format!("{}↓/{}↑", incoming_rate, outgoing_rate);

                // Build cells dynamically
                let mut cells = vec![
                    Cell::from(process_cell).style(theme::bold_fg(theme::accent())),
                    Cell::from(""),
                    Cell::from(""),
                ];
                if show_location {
                    cells.push(Cell::from("")); // Loc (empty for group header)
                }
                cells.extend([
                    Cell::from(proto_breakdown),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(bandwidth),
                ]);
                Row::new(cells)
            }
            GroupedRow::Connection {
                connection,
                is_last_in_group,
                ..
            } => {
                let prefix = if *is_last_in_group {
                    "  └── "
                } else {
                    "  ├── "
                };

                let protocol_cell = format!("{}{}", prefix, connection.protocol);

                // Format addresses
                let local_addr_display = connection.local_addr.to_string();
                let remote_addr_display = if ui_state.show_hostnames {
                    if let Some(resolver) = dns_resolver {
                        if let Some(hostname) = resolver.get_hostname(&connection.remote_addr.ip())
                        {
                            let port = connection.remote_addr.port();
                            let max_len = (remote_addr_width as usize).saturating_sub(7);
                            if hostname.len() > max_len {
                                format!("{}..:{}", &hostname[..max_len.saturating_sub(2)], port)
                            } else {
                                format!("{}:{}", hostname, port)
                            }
                        } else {
                            connection.remote_addr.to_string()
                        }
                    } else {
                        connection.remote_addr.to_string()
                    }
                } else {
                    connection.remote_addr.to_string()
                };

                // State display
                let state = connection.state();

                // Service display
                let service_display = if ui_state.show_port_numbers {
                    connection.remote_addr.port().to_string()
                } else {
                    connection
                        .service_name
                        .clone()
                        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string())
                };

                // DPI display
                let dpi_display = match &connection.dpi_info {
                    Some(dpi) => dpi.application.to_string(),
                    None => NONE_PLACEHOLDER.to_string(),
                };

                // GeoIP location display (2-char country code)
                let location_display = connection
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or("-");

                // Bandwidth display
                let incoming_rate = format_rate_compact(connection.current_incoming_rate_bps);
                let outgoing_rate = format_rate_compact(connection.current_outgoing_rate_bps);
                let bandwidth = format!("{}↓/{}↑", incoming_rate, outgoing_rate);

                // Row color based on staleness
                let staleness = connection.staleness_ratio();
                let row_style = if staleness >= 0.90 {
                    theme::fg(theme::err())
                } else if staleness >= 0.75 {
                    theme::fg(theme::warn())
                } else {
                    Style::default()
                };

                // Build cells dynamically
                let mut cells = vec![
                    Cell::from(protocol_cell),
                    Cell::from(local_addr_display),
                    Cell::from(remote_addr_display),
                ];
                if show_location {
                    cells.push(Cell::from(location_display));
                }
                cells.extend([
                    Cell::from(state),
                    Cell::from(service_display),
                    Cell::from(dpi_display),
                    Cell::from(bandwidth),
                ]);
                Row::new(cells).style(row_style)
            }
        })
        .collect();

    // Create table state with current selection
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_grouped_index(grouped_rows) {
        state.select(Some(selected_index));
    }

    // Build title showing both group sort (A-Z) and connection sort within groups
    let table_title = if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        };
        format!(
            "Grouped by Process (A-Z) │ Connections: {} {}",
            ui_state.sort_column.display_name(),
            direction
        )
    } else {
        "Grouped by Process (A-Z) │ Connections: Time ↑".to_string()
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

    let detection_status = app.get_process_detection_status();
    let (link_layer_type, is_tunnel) = app.get_link_layer_info();

    // Build process detection line(s) with color based on status
    let process_detection_color = if detection_status.is_degraded {
        theme::warn()
    } else {
        theme::ok()
    };

    let mut conn_stats_text: Vec<Line> = vec![
        Line::from(format!("Interface: {}", interface_name)),
        Line::from(format!(
            "Link Layer: {}{}",
            link_layer_type,
            if is_tunnel { " (Tunnel)" } else { "" }
        )),
        Line::from(vec![
            Span::raw("Process Detection: "),
            Span::styled(
                detection_status.method.clone(),
                theme::fg(process_detection_color),
            ),
        ]),
    ];

    // Add degradation warning on second line if degraded
    if detection_status.is_degraded {
        let warning_text = format!(
            "  {} unavailable - {}",
            detection_status
                .unavailable_feature
                .as_deref()
                .unwrap_or("Enhanced"),
            detection_status
                .degradation_reason
                .as_deref()
                .unwrap_or("insufficient permissions")
        );
        conn_stats_text.push(Line::from(Span::styled(
            warning_text,
            theme::fg(theme::muted()),
        )));
    }

    // Add remaining stats
    conn_stats_text.extend([
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
    ]);

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
            theme::fg(theme::muted()),
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
            "Fully enforced" => theme::fg(theme::ok()),
            "Partially enforced" => theme::fg(theme::warn()),
            "Not applied" | "Error" => theme::fg(theme::err()),
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
            Span::styled(" [kernel supported]", theme::fg(theme::muted()))
        } else {
            Span::styled(" [kernel unsupported]", theme::fg(theme::muted()))
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
                theme::fg(theme::muted()),
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
                theme::fg(theme::warn()),
            ))]
        } else {
            vec![Line::from(Span::styled(
                format!("Running as UID {}", uid),
                theme::fg(theme::ok()),
            ))]
        }
    };

    #[cfg(target_os = "windows")]
    let security_text: Vec<Line> = {
        let is_elevated = crate::is_admin();
        if is_elevated {
            vec![Line::from(Span::styled(
                "Running as Administrator",
                theme::fg(theme::warn()),
            ))]
        } else {
            vec![Line::from(Span::styled(
                "Running as standard user",
                theme::fg(theme::ok()),
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

    let rx_label = Paragraph::new("RX").style(theme::fg(theme::rx()));
    f.render_widget(rx_label, rx_cols[0]);

    let rx_data = traffic_history.get_rx_sparkline_data(sparkline_width);
    let rx_sparkline = Sparkline::default()
        .data(&rx_data)
        .style(theme::fg(theme::rx()));
    f.render_widget(rx_sparkline, rx_cols[1]);

    // TX row: label + sparkline
    let tx_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(sparkline_rows[1]);

    let tx_label = Paragraph::new("TX").style(theme::fg(theme::tx()));
    f.render_widget(tx_label, tx_cols[0]);

    let tx_data = traffic_history.get_tx_sparkline_data(sparkline_width);
    let tx_sparkline = Sparkline::default()
        .data(&tx_data)
        .style(theme::fg(theme::tx()));
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
            theme::fg(theme::rx()),
        ),
        Span::raw(" "),
        Span::styled(
            format!("↑{}/s", format_bytes(current_tx)),
            theme::fg(theme::tx()),
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
            theme::fg(theme::muted()),
        ))]
    } else {
        let mut lines = Vec::new();
        let num_to_show = max_interfaces.min(filtered_interface_stats.len());

        for stat in filtered_interface_stats.iter().take(num_to_show) {
            let total_errors = stat.rx_errors + stat.tx_errors;
            let total_drops = stat.rx_dropped + stat.tx_dropped;

            let error_style = if total_errors > 0 {
                theme::fg(theme::err())
            } else {
                theme::fg(theme::ok())
            };

            let drop_style = if total_drops > 0 {
                theme::fg(theme::warn())
            } else {
                theme::fg(theme::ok())
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
                theme::fg(theme::muted()),
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
            .style(theme::fg(theme::muted()));
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
            .style(theme::fg(theme::rx()))
            .data(&rx_data),
        Dataset::default()
            .name("TX ↑")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(theme::fg(theme::tx()))
            .data(&tx_data),
    ];

    let chart = Chart::new(datasets)
        .block(block)
        .x_axis(
            Axis::default()
                .title("Time")
                .style(theme::fg(theme::muted()))
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
                .style(theme::fg(theme::muted()))
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
        let placeholder = Paragraph::new("Collecting...").style(theme::fg(theme::muted()));
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
        .style(theme::fg(theme::accent()));
    f.render_widget(sparkline, chunks[0]);

    // Current connection count label
    let current_count = conn_data.last().copied().unwrap_or(0);
    let label = Paragraph::new(format!("{} connections", current_count));
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
            "HTTPS" => theme::proto_https(),
            "QUIC" => theme::proto_quic(),
            "HTTP" => theme::proto_http(),
            "DNS" => theme::proto_dns(),
            "SSH" => theme::proto_ssh(),
            _ => theme::proto_other(),
        };

        lines.push(Line::from(vec![
            Span::styled(format!("{:6}", label), theme::fg(color)),
            Span::raw(" "),
            Span::styled(bar, theme::fg(color)),
            Span::raw(format!(" {:5.1}%", pct)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No connections",
            theme::fg(theme::muted()),
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
                Cell::from(format_rate(rate)).style(theme::fg(theme::accent())),
            ])
        })
        .collect();

    if rows.is_empty() {
        let placeholder = Paragraph::new("No active processes").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    let table = Table::new(
        rows,
        [Constraint::Percentage(60), Constraint::Percentage(40)],
    )
    .header(Row::new(vec!["Process", "Rate"]).style(theme::bold_fg(theme::heading())));

    f.render_widget(table, inner);
}

/// Draw chart legend
fn draw_traffic_legend(f: &mut Frame, area: Rect) {
    let legend = Paragraph::new(Line::from(vec![
        Span::styled("▬", theme::fg(theme::rx())),
        Span::raw(" RX (incoming)  "),
        Span::styled("▬", theme::fg(theme::tx())),
        Span::raw(" TX (outgoing)"),
    ]))
    .style(theme::fg(theme::muted()));

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
        let placeholder = Paragraph::new("Collecting data...").style(theme::fg(theme::muted()));
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
            theme::ok()
        } else if rtt < 150.0 {
            theme::warn()
        } else {
            theme::err()
        };

        Line::from(vec![
            Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("█".repeat(filled), theme::fg(color)),
            Span::styled("░".repeat(empty), theme::fg(theme::muted())),
            Span::styled(format!(" {:>6.1}ms", rtt), theme::fg(color)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("░".repeat(bar_width), theme::fg(theme::muted())),
            Span::styled("    --  ", theme::fg(theme::muted())),
        ])
    };

    // Build Loss gauge
    let loss_pct = (current_loss / LOSS_MAX).min(1.0);
    let filled = (loss_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);

    let loss_color = if current_loss < 1.0 {
        theme::ok()
    } else if current_loss < 5.0 {
        theme::warn()
    } else {
        theme::err()
    };

    let loss_line = Line::from(vec![
        Span::styled("  Loss ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            "█".repeat(filled.max(if current_loss > 0.0 { 1 } else { 0 })),
            theme::fg(loss_color),
        ),
        Span::styled("░".repeat(empty.min(bar_width)), theme::fg(theme::muted())),
        Span::styled(format!(" {:>6.2}%", current_loss), theme::fg(loss_color)),
    ]);

    // Build averages line
    let avg_line = Line::from(vec![
        Span::styled("  avg: ", theme::fg(theme::muted())),
        Span::styled(
            avg_rtt
                .map(|r| format!("{:.0}ms", r))
                .unwrap_or_else(|| "--".to_string()),
            theme::fg(theme::muted()),
        ),
        Span::styled(" / ", theme::fg(theme::muted())),
        Span::styled(format!("{:.2}%", avg_loss), theme::fg(theme::muted())),
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
        theme::ok()
    } else if retransmits < 100 {
        theme::warn()
    } else {
        theme::err()
    };

    let ooo_color = if out_of_order == 0 {
        theme::ok()
    } else if out_of_order < 50 {
        theme::warn()
    } else {
        theme::err()
    };

    let fast_color = if fast_retransmits == 0 {
        theme::ok()
    } else if fast_retransmits < 50 {
        theme::warn()
    } else {
        theme::err()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "  Retransmits  ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", retransmits), theme::fg(retrans_color)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Out of Order ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", out_of_order), theme::fg(ooo_color)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Fast Retrans ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", fast_retransmits), theme::fg(fast_color)),
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
        let text = Paragraph::new("No TCP connections").style(theme::fg(theme::muted()));
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
                "ESTAB" => theme::tcp_established(),
                "SYN_SENT" | "SYN_RECV" => theme::tcp_opening(),
                "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => theme::tcp_closing(),
                "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => theme::tcp_waiting(),
                "CLOSED" => theme::tcp_closed(),
                _ => Color::Reset,
            };

            Line::from(vec![
                Span::styled(format!("{:>10} ", name), theme::fg(color)),
                Span::styled(bar, theme::fg(color)),
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
    dns_resolver: Option<&DnsResolver>,
) -> Result<()> {
    if connections.is_empty() {
        let text = Paragraph::new("No connections available")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Connection Details"),
            )
            .style(theme::fg(theme::err()))
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
            Span::styled("Protocol: ", theme::fg(theme::label())),
            Span::raw(conn.protocol.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Local Address: ", theme::fg(theme::label())),
            Span::raw(conn.local_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Remote Address: ", theme::fg(theme::label())),
            Span::raw(conn.remote_addr.to_string()),
        ]),
        Line::from(vec![
            Span::styled("State: ", theme::fg(theme::label())),
            Span::raw(conn.state()),
        ]),
        Line::from(vec![
            Span::styled("Process: ", theme::fg(theme::label())),
            Span::raw(
                conn.process_name
                    .clone()
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("PID: ", theme::fg(theme::label())),
            Span::raw(
                conn.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            ),
        ]),
        Line::from(vec![
            Span::styled("Service: ", theme::fg(theme::label())),
            Span::raw(
                conn.service_name
                    .clone()
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            ),
        ]),
    ];

    // Add reverse DNS hostnames if available
    if let Some(resolver) = dns_resolver {
        let local_hostname = resolver.get_hostname(&conn.local_addr.ip());
        let remote_hostname = resolver.get_hostname(&conn.remote_addr.ip());

        if local_hostname.is_some() || remote_hostname.is_some() {
            details_text.push(Line::from("")); // Empty line separator
            details_text.push(Line::from(vec![
                Span::styled("Local Hostname: ", theme::fg(theme::label())),
                Span::raw(local_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string())),
            ]));
            details_text.push(Line::from(vec![
                Span::styled("Remote Hostname: ", theme::fg(theme::label())),
                Span::raw(remote_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string())),
            ]));
        }
    }

    // Add GeoIP information if available
    if let Some(ref geoip) = conn.geoip_info
        && (geoip.country_code.is_some() || geoip.asn.is_some() || geoip.city.is_some())
    {
        details_text.push(Line::from("")); // Empty line separator
        if let Some(ref country_name) = geoip.country_name {
            let country_display = if let Some(ref cc) = geoip.country_code {
                format!("{} ({})", country_name, cc)
            } else {
                country_name.clone()
            };
            details_text.push(Line::from(vec![
                Span::styled("Country: ", Style::default().fg(Color::Yellow)),
                Span::raw(country_display),
            ]));
        } else if let Some(ref cc) = geoip.country_code {
            details_text.push(Line::from(vec![
                Span::styled("Country: ", Style::default().fg(Color::Yellow)),
                Span::raw(cc.clone()),
            ]));
        }
        if let Some(ref city) = geoip.city {
            details_text.push(Line::from(vec![
                Span::styled("City: ", Style::default().fg(Color::Yellow)),
                Span::raw(city.clone()),
            ]));
        }
        if let Some(asn) = geoip.asn {
            let asn_display = if let Some(ref org) = geoip.as_org {
                format!("AS{} ({})", asn, org)
            } else {
                format!("AS{}", asn)
            };
            details_text.push(Line::from(vec![
                Span::styled("ASN: ", Style::default().fg(Color::Yellow)),
                Span::raw(asn_display),
            ]));
        }
    }

    // Add DPI information
    match &conn.dpi_info {
        Some(dpi) => {
            details_text.push(Line::from(vec![
                Span::styled("Application: ", theme::fg(theme::label())),
                Span::raw(dpi.application.to_string()),
            ]));

            // Add protocol-specific details
            match &dpi.application {
                crate::network::types::ApplicationProtocol::Http(info) => {
                    if let Some(method) = &info.method {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Method: ", theme::fg(theme::label())),
                            Span::raw(method.clone()),
                        ]));
                    }
                    if let Some(path) = &info.path {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Path: ", theme::fg(theme::label())),
                            Span::raw(path.clone()),
                        ]));
                    }
                    if let Some(status) = info.status_code {
                        details_text.push(Line::from(vec![
                            Span::styled("  HTTP Status: ", theme::fg(theme::label())),
                            Span::raw(status.to_string()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Https(info) => {
                    if let Some(tls_info) = &info.tls_info {
                        if let Some(sni) = &tls_info.sni {
                            details_text.push(Line::from(vec![
                                Span::styled("  SNI: ", theme::fg(theme::label())),
                                Span::raw(sni.clone()),
                            ]));
                        }
                        if !tls_info.alpn.is_empty() {
                            details_text.push(Line::from(vec![
                                Span::styled("  ALPN: ", theme::fg(theme::label())),
                                Span::raw(tls_info.alpn.join(", ")),
                            ]));
                        }
                        if let Some(version) = &tls_info.version {
                            details_text.push(Line::from(vec![
                                Span::styled("  TLS Version: ", theme::fg(theme::label())),
                                Span::raw(version.to_string()),
                            ]));
                        }
                        if let Some(formatted_cipher) = tls_info.format_cipher_suite() {
                            let cipher_color = if tls_info.is_cipher_suite_secure().unwrap_or(false)
                            {
                                theme::ok()
                            } else {
                                theme::warn()
                            };
                            details_text.push(Line::from(vec![
                                Span::styled("  Cipher Suite: ", theme::fg(theme::label())),
                                Span::styled(formatted_cipher, theme::fg(cipher_color)),
                            ]));
                        }
                    }
                }
                crate::network::types::ApplicationProtocol::Dns(info) => {
                    if let Some(query_type) = &info.query_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  DNS Type: ", theme::fg(theme::label())),
                            Span::raw(format!("{:?}", query_type)),
                        ]));
                    }
                    if !info.response_ips.is_empty() {
                        details_text.push(Line::from(vec![
                            Span::styled("  DNS Response IPs: ", theme::fg(theme::label())),
                            Span::raw(format!("{:?}", info.response_ips)),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Quic(info) => {
                    if let Some(tls_info) = &info.tls_info {
                        let sni = tls_info
                            .sni
                            .clone()
                            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC SNI: ", theme::fg(theme::label())),
                            Span::raw(sni),
                        ]));
                        let alpn = tls_info.alpn.join(", ");
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC ALPN: ", theme::fg(theme::label())),
                            Span::raw(alpn),
                        ]));
                    }
                    if let Some(version) = info.version_string.as_ref() {
                        details_text.push(Line::from(vec![
                            Span::styled("  QUIC Version: ", theme::fg(theme::label())),
                            Span::raw(version.clone()),
                        ]));
                    }
                    if let Some(connection_id) = &info.connection_id_hex {
                        details_text.push(Line::from(vec![
                            Span::styled("  Connection ID: ", theme::fg(theme::label())),
                            Span::raw(connection_id.clone()),
                        ]));
                    }

                    let packet_type = info.packet_type.to_string();
                    details_text.push(Line::from(vec![
                        Span::styled("  Packet Type: ", theme::fg(theme::label())),
                        Span::raw(packet_type),
                    ]));
                    let connection_state = info.connection_state.to_string();
                    details_text.push(Line::from(vec![
                        Span::styled("  Connection State: ", theme::fg(theme::label())),
                        Span::raw(connection_state),
                    ]));
                }
                crate::network::types::ApplicationProtocol::Ssh(info) => {
                    if let Some(version) = &info.version {
                        details_text.push(Line::from(vec![
                            Span::styled("  SSH Version: ", theme::fg(theme::label())),
                            Span::raw(format!("{:?}", version)),
                        ]));
                    }
                    if let Some(server_software) = &info.server_software {
                        details_text.push(Line::from(vec![
                            Span::styled("  Server Software: ", theme::fg(theme::label())),
                            Span::raw(server_software.clone()),
                        ]));
                    }
                    if let Some(client_software) = &info.client_software {
                        details_text.push(Line::from(vec![
                            Span::styled("  Client Software: ", theme::fg(theme::label())),
                            Span::raw(client_software.clone()),
                        ]));
                    }
                    details_text.push(Line::from(vec![
                        Span::styled("  Connection State: ", theme::fg(theme::label())),
                        Span::raw(format!("{:?}", info.connection_state)),
                    ]));
                    if !info.algorithms.is_empty() {
                        details_text.push(Line::from(vec![
                            Span::styled("  Algorithms: ", theme::fg(theme::label())),
                            Span::raw(info.algorithms.join(", ")),
                        ]));
                    }
                    if let Some(auth_method) = &info.auth_method {
                        details_text.push(Line::from(vec![
                            Span::styled("  Auth Method: ", theme::fg(theme::label())),
                            Span::raw(auth_method.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Ntp(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  NTP Version: ", theme::fg(theme::label())),
                        Span::raw(format!("{}", info.version)),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  NTP Mode: ", theme::fg(theme::label())),
                        Span::raw(info.mode.to_string()),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  Stratum: ", theme::fg(theme::label())),
                        Span::raw(format!("{}", info.stratum)),
                    ]));
                }
                crate::network::types::ApplicationProtocol::Mdns(info) => {
                    if let Some(query_name) = &info.query_name {
                        details_text.push(Line::from(vec![
                            Span::styled("  Query Name: ", theme::fg(theme::label())),
                            Span::raw(query_name.clone()),
                        ]));
                    }
                    if let Some(query_type) = &info.query_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  Query Type: ", theme::fg(theme::label())),
                            Span::raw(format!("{:?}", query_type)),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Llmnr(info) => {
                    if let Some(query_name) = &info.query_name {
                        details_text.push(Line::from(vec![
                            Span::styled("  Query Name: ", theme::fg(theme::label())),
                            Span::raw(query_name.clone()),
                        ]));
                    }
                    if let Some(query_type) = &info.query_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  Query Type: ", theme::fg(theme::label())),
                            Span::raw(format!("{:?}", query_type)),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Dhcp(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Message Type: ", theme::fg(theme::label())),
                        Span::raw(info.message_type.to_string()),
                    ]));
                    if let Some(hostname) = &info.hostname {
                        details_text.push(Line::from(vec![
                            Span::styled("  Hostname: ", theme::fg(theme::label())),
                            Span::raw(hostname.clone()),
                        ]));
                    }
                    if let Some(client_mac) = &info.client_mac {
                        details_text.push(Line::from(vec![
                            Span::styled("  Client MAC: ", theme::fg(theme::label())),
                            Span::raw(client_mac.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Snmp(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  SNMP Version: ", theme::fg(theme::label())),
                        Span::raw(info.version.to_string()),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  PDU Type: ", theme::fg(theme::label())),
                        Span::raw(info.pdu_type.to_string()),
                    ]));
                    if let Some(community) = &info.community {
                        details_text.push(Line::from(vec![
                            Span::styled("  Community: ", theme::fg(theme::label())),
                            Span::raw(community.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Ssdp(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Method: ", theme::fg(theme::label())),
                        Span::raw(info.method.to_string()),
                    ]));
                    if let Some(service_type) = &info.service_type {
                        details_text.push(Line::from(vec![
                            Span::styled("  Service Type: ", theme::fg(theme::label())),
                            Span::raw(service_type.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::NetBios(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Service: ", theme::fg(theme::label())),
                        Span::raw(info.service.to_string()),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  Opcode: ", theme::fg(theme::label())),
                        Span::raw(info.opcode.to_string()),
                    ]));
                    if let Some(name) = &info.name {
                        details_text.push(Line::from(vec![
                            Span::styled("  Name: ", theme::fg(theme::label())),
                            Span::raw(name.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::BitTorrent(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Type: ", theme::fg(theme::label())),
                        Span::raw(info.protocol_type.to_string()),
                    ]));
                    if let Some(client) = &info.client {
                        details_text.push(Line::from(vec![
                            Span::styled("  Client: ", theme::fg(theme::label())),
                            Span::raw(client.clone()),
                        ]));
                    }
                    if let Some(info_hash) = &info.info_hash {
                        details_text.push(Line::from(vec![
                            Span::styled("  Info Hash: ", theme::fg(theme::label())),
                            Span::raw(info_hash.clone()),
                        ]));
                    }
                    if let Some(method) = &info.dht_method {
                        details_text.push(Line::from(vec![
                            Span::styled("  DHT Method: ", theme::fg(theme::label())),
                            Span::raw(method.clone()),
                        ]));
                    }
                    let mut extensions = Vec::new();
                    if info.supports_dht {
                        extensions.push("DHT");
                    }
                    if info.supports_extension {
                        extensions.push("Extension Protocol");
                    }
                    if info.supports_fast {
                        extensions.push("Fast");
                    }
                    if !extensions.is_empty() {
                        details_text.push(Line::from(vec![
                            Span::styled("  Extensions: ", theme::fg(theme::label())),
                            Span::raw(extensions.join(", ")),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Stun(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Method: ", theme::fg(theme::label())),
                        Span::raw(info.method.to_string()),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  Class: ", theme::fg(theme::label())),
                        Span::raw(info.message_class.to_string()),
                    ]));
                    details_text.push(Line::from(vec![
                        Span::styled("  Transaction ID: ", theme::fg(theme::label())),
                        Span::raw(
                            info.transaction_id
                                .iter()
                                .map(|b| format!("{:02x}", b))
                                .collect::<String>(),
                        ),
                    ]));
                    if let Some(software) = &info.software {
                        details_text.push(Line::from(vec![
                            Span::styled("  Software: ", theme::fg(theme::label())),
                            Span::raw(software.clone()),
                        ]));
                    }
                }
                crate::network::types::ApplicationProtocol::Mqtt(info) => {
                    details_text.push(Line::from(vec![
                        Span::styled("  Packet Type: ", theme::fg(theme::label())),
                        Span::raw(info.packet_type.to_string()),
                    ]));
                    if let Some(version) = &info.version {
                        details_text.push(Line::from(vec![
                            Span::styled("  Version: ", theme::fg(theme::label())),
                            Span::raw(version.to_string()),
                        ]));
                    }
                    if let Some(client_id) = &info.client_id {
                        details_text.push(Line::from(vec![
                            Span::styled("  Client ID: ", theme::fg(theme::label())),
                            Span::raw(client_id.clone()),
                        ]));
                    }
                    if let Some(topic) = &info.topic {
                        details_text.push(Line::from(vec![
                            Span::styled("  Topic: ", theme::fg(theme::label())),
                            Span::raw(topic.clone()),
                        ]));
                    }
                    if let Some(qos) = info.qos {
                        details_text.push(Line::from(vec![
                            Span::styled("  QoS: ", theme::fg(theme::label())),
                            Span::raw(qos.to_string()),
                        ]));
                    }
                }
            }
        }
        None => {
            details_text.push(Line::from(vec![
                Span::styled("Application: ", theme::fg(theme::label())),
                Span::raw(NONE_PLACEHOLDER.to_string()),
            ]));
        }
    }

    // Add ARP details if this is an ARP connection
    if let ProtocolState::Arp(arp_info) = &conn.protocol_state {
        details_text.push(Line::from(""));
        details_text.push(Line::from(vec![
            Span::styled("Sender MAC: ", theme::fg(theme::label())),
            Span::raw(arp_info.sender_mac.clone()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Sender IP: ", theme::fg(theme::label())),
            Span::raw(arp_info.sender_ip.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Target MAC: ", theme::fg(theme::label())),
            Span::raw(arp_info.target_mac.clone()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Target IP: ", theme::fg(theme::label())),
            Span::raw(arp_info.target_ip.to_string()),
        ]));
    }

    // Add TCP analytics if available
    if let Some(analytics) = &conn.tcp_analytics {
        details_text.push(Line::from(""));
        details_text.push(Line::from(vec![
            Span::styled("TCP Retransmits: ", theme::fg(theme::label())),
            Span::raw(analytics.retransmit_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Out-of-Order Packets: ", theme::fg(theme::label())),
            Span::raw(analytics.out_of_order_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Duplicate ACKs: ", theme::fg(theme::label())),
            Span::raw(analytics.duplicate_ack_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Fast Retransmits: ", theme::fg(theme::label())),
            Span::raw(analytics.fast_retransmit_count.to_string()),
        ]));
        details_text.push(Line::from(vec![
            Span::styled("Window Size: ", theme::fg(theme::label())),
            Span::raw(analytics.last_window_size.to_string()),
        ]));
    }

    // Add initial RTT measurement if available
    if let Some(rtt) = conn.initial_rtt {
        let rtt_ms = rtt.as_secs_f64() * 1000.0;
        let rtt_color = if rtt_ms < 50.0 {
            theme::ok()
        } else if rtt_ms < 150.0 {
            theme::warn()
        } else {
            theme::err()
        };
        details_text.push(Line::from(vec![
            Span::styled("Initial RTT: ", theme::fg(theme::label())),
            Span::styled(format!("{:.1}ms", rtt_ms), theme::fg(rtt_color)),
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
            Span::styled("Bytes Sent: ", theme::fg(theme::label())),
            Span::raw(format_bytes(conn.bytes_sent)),
        ]),
        Line::from(vec![
            Span::styled("Bytes Received: ", theme::fg(theme::label())),
            Span::raw(format_bytes(conn.bytes_received)),
        ]),
        Line::from(vec![
            Span::styled("Packets Sent: ", theme::fg(theme::label())),
            Span::raw(conn.packets_sent.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Packets Received: ", theme::fg(theme::label())),
            Span::raw(conn.packets_received.to_string()),
        ]),
        Line::from(vec![
            Span::styled("Current Rate (In): ", theme::fg(theme::label())),
            Span::raw(format_rate(conn.current_incoming_rate_bps)),
        ]),
        Line::from(vec![
            Span::styled("Current Rate (Out): ", theme::fg(theme::label())),
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
            Span::styled("RustNet Monitor ", theme::bold_fg(theme::ok())),
            Span::raw("- Network Connection Monitor"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("q ", theme::fg(theme::key())),
            Span::raw("Quit application (press twice to confirm)"),
        ]),
        Line::from(vec![
            Span::styled("Ctrl+C ", theme::fg(theme::key())),
            Span::raw("Quit immediately"),
        ]),
        Line::from(vec![
            Span::styled("x ", theme::fg(theme::key())),
            Span::raw("Clear all connections (press twice to confirm)"),
        ]),
        Line::from(vec![
            Span::styled("Tab ", theme::fg(theme::key())),
            Span::raw("Switch between tabs"),
        ]),
        Line::from(vec![
            Span::styled("↑/k, ↓/j ", theme::fg(theme::key())),
            Span::raw("Navigate connections (wraps around)"),
        ]),
        Line::from(vec![
            Span::styled("g, G ", theme::fg(theme::key())),
            Span::raw("Jump to first/last connection (vim-style)"),
        ]),
        Line::from(vec![
            Span::styled("Page Up/Down ", theme::fg(theme::key())),
            Span::raw("Navigate connections by page"),
        ]),
        Line::from(vec![
            Span::styled("c ", theme::fg(theme::key())),
            Span::raw("Copy remote address to clipboard"),
        ]),
        Line::from(vec![
            Span::styled("p ", theme::fg(theme::key())),
            Span::raw("Toggle between service names and port numbers"),
        ]),
        Line::from(vec![
            Span::styled("d ", theme::fg(theme::key())),
            Span::raw("Toggle between hostnames and IP addresses (when --resolve-dns)"),
        ]),
        Line::from(vec![
            Span::styled("s ", theme::fg(theme::key())),
            Span::raw("Cycle through sort columns (Bandwidth, Process, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("S ", theme::fg(theme::key())),
            Span::raw("Toggle sort direction (ascending/descending)"),
        ]),
        Line::from(vec![
            Span::styled("a ", theme::fg(theme::key())),
            Span::raw("Toggle process grouping (aggregate by process)"),
        ]),
        Line::from(vec![
            Span::styled("Space ", theme::fg(theme::key())),
            Span::raw("Expand/collapse group (when grouping enabled)"),
        ]),
        Line::from(vec![
            Span::styled("←/→ ", theme::fg(theme::key())),
            Span::raw("Collapse/expand group"),
        ]),
        Line::from(vec![
            Span::styled("r ", theme::fg(theme::key())),
            Span::raw("Reset view (grouping, sort, filter)"),
        ]),
        Line::from(vec![
            Span::styled("Enter ", theme::fg(theme::key())),
            Span::raw("View connection details"),
        ]),
        Line::from(vec![
            Span::styled("Esc ", theme::fg(theme::key())),
            Span::raw("Return to overview"),
        ]),
        Line::from(vec![
            Span::styled("h ", theme::fg(theme::key())),
            Span::raw("Toggle this help screen"),
        ]),
        Line::from(vec![
            Span::styled("i ", theme::fg(theme::key())),
            Span::raw("Toggle interface statistics view"),
        ]),
        Line::from(vec![
            Span::styled("/ ", theme::fg(theme::key())),
            Span::raw("Enter filter mode (navigate while typing!)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Tabs:", theme::bold_fg(theme::accent()))]),
        Line::from(vec![
            Span::styled("  Overview ", theme::fg(theme::ok())),
            Span::raw("Connection list with mini traffic graph"),
        ]),
        Line::from(vec![
            Span::styled("  Details ", theme::fg(theme::ok())),
            Span::raw("Full details for selected connection"),
        ]),
        Line::from(vec![
            Span::styled("  Interfaces ", theme::fg(theme::ok())),
            Span::raw("Network interface statistics"),
        ]),
        Line::from(vec![
            Span::styled("  Graph ", theme::fg(theme::ok())),
            Span::raw("Traffic charts and protocol distribution"),
        ]),
        Line::from(vec![
            Span::styled("  Help ", theme::fg(theme::ok())),
            Span::raw("This help screen"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Connection Colors:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  White ", Style::default()),
            Span::raw("Active connection (< 75% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Yellow ", theme::fg(theme::key())),
            Span::raw("Stale connection (75-90% of timeout)"),
        ]),
        Line::from(vec![
            Span::styled("  Red ", theme::fg(theme::err())),
            Span::raw("Critical - will be removed soon (> 90% of timeout)"),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Filter Examples:",
            theme::bold_fg(theme::accent()),
        )]),
        Line::from(vec![
            Span::styled("  /google ", theme::fg(theme::ok())),
            Span::raw("Search for 'google' in all fields"),
        ]),
        Line::from(vec![
            Span::styled("  /port:44 ", theme::fg(theme::ok())),
            Span::raw("Filter ports containing '44' (443, 8080, etc.)"),
        ]),
        Line::from(vec![
            Span::styled("  /src:192.168 ", theme::fg(theme::ok())),
            Span::raw("Filter by source IP prefix"),
        ]),
        Line::from(vec![
            Span::styled("  /dst:github.com ", theme::fg(theme::ok())),
            Span::raw("Filter by destination"),
        ]),
        Line::from(vec![
            Span::styled("  /sni:example.com ", theme::fg(theme::ok())),
            Span::raw("Filter by SNI hostname"),
        ]),
        Line::from(vec![
            Span::styled("  /process:firefox ", theme::fg(theme::ok())),
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
            .style(theme::fg(theme::muted()))
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(empty_msg, area);
        return Ok(());
    }

    // Create table rows
    let mut rows = Vec::new();

    for stat in &stats {
        // Determine error style
        let error_style = if stat.rx_errors > 0 || stat.tx_errors > 0 {
            theme::fg(theme::err())
        } else {
            theme::fg(theme::ok())
        };

        // Determine drop style
        let drop_style = if stat.rx_dropped > 0 || stat.tx_dropped > 0 {
            theme::fg(theme::warn())
        } else {
            theme::fg(theme::ok())
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
        .style(theme::bold_fg(theme::heading())),
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
        theme::fg(theme::warn())
    } else {
        theme::fg(theme::ok())
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
    } else if ui_state.clear_confirmation {
        " Press 'x' again to clear all connections or any other key to cancel ".to_string()
    } else if let Some((ref msg, ref time)) = ui_state.clipboard_message {
        // Show clipboard message for 3 seconds
        if time.elapsed().as_secs() < 3 {
            format!(" {} ", msg)
        } else {
            " 'h' help | Tab/Shift+Tab switch tabs | '/' filter | 'a' group | 'c' copy ".to_string()
        }
    } else if !ui_state.filter_query.is_empty() {
        format!(
            " 'h' help | Tab/Shift+Tab switch tabs | Showing {} filtered connections (Esc to clear) ",
            connection_count
        )
    } else {
        " 'h' help | Tab/Shift+Tab switch tabs | '/' filter | 'a' group | 'c' copy ".to_string()
    };

    let style = if ui_state.quit_confirmation || ui_state.clear_confirmation {
        theme::status_bar_confirm()
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
        theme::status_bar_success()
    } else {
        theme::status_bar_default()
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
            Span::styled("⣾ ", theme::fg(theme::heading())),
            Span::styled("Loading network connections...", Style::default()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "This may take a few seconds",
            theme::fg(theme::muted()),
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
        NONE_PLACEHOLDER.to_string()
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
        NONE_PLACEHOLDER.to_string()
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
