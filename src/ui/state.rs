//! UIState, ClickableRegions, ClickAction, SortColumn, GroupedRow, and
//! the selection/scroll helpers — everything tracking what the user is
//! looking at and acting on. No rendering happens here; tabs and widgets
//! read these to know what to draw.

use std::collections::HashSet;

use ratatui::layout::Rect;

use crate::network::types::{Connection, Protocol};

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
    pub historic_count: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
    pub total_incoming_rate_bps: f64,
    pub total_outgoing_rate_bps: f64,
}

/// A row in the grouped display (either a group header or a connection)
#[derive(Debug, Clone)]
pub enum GroupedRow<'a> {
    /// A collapsed or expanded group header
    Group {
        process_name: String,
        stats: ProcessGroupStats,
        expanded: bool,
    },
    /// An individual connection within an expanded group
    Connection {
        process_name: String,
        connection: &'a Connection,
        is_last_in_group: bool,
    },
}

/// Represents an action that can be triggered by clicking a screen region.
#[derive(Debug, Clone)]
pub enum ClickAction {
    /// Switch to a specific tab (index 0-4)
    SwitchTab(usize),
    /// Select a connection by index in the current sorted/filtered list
    SelectConnection(usize),
    /// Copy a field value to clipboard (label for feedback, value for clipboard)
    CopyField { label: String, value: String },
}

/// Registry of clickable screen regions, rebuilt every frame during render.
/// The event handler reads from this to determine what a mouse click means.
#[derive(Debug, Default)]
pub struct ClickableRegions {
    regions: Vec<(Rect, ClickAction)>,
    /// The area of the connections table, used for scroll event targeting
    pub scroll_area: Option<Rect>,
}

impl ClickableRegions {
    pub fn clear(&mut self) {
        self.regions.clear();
        self.scroll_area = None;
    }

    pub fn register(&mut self, area: Rect, action: ClickAction) {
        self.regions.push((area, action));
    }

    /// Find the action for a click at (column, row).
    /// Returns the last registered matching region (later registrations take priority).
    pub fn hit_test(&self, column: u16, row: u16) -> Option<&ClickAction> {
        self.regions
            .iter()
            .rev()
            .find(|(rect, _)| {
                column >= rect.x
                    && column < rect.x + rect.width
                    && row >= rect.y
                    && row < rect.y + rect.height
            })
            .map(|(_, action)| action)
    }
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
    /// Last mouse click position and time, for double-click detection
    pub last_click: Option<(u16, u16, std::time::Instant)>,
    /// Whether to show historic (closed) connections
    pub show_historic: bool,
    /// Number of visible rows in the connections table (updated after rendering)
    pub visible_rows: usize,
    /// Scroll offset for flat connection list (persisted for stable scrolling)
    pub scroll_offset: usize,
    /// Scroll offset for grouped connection list (persisted for stable scrolling)
    pub grouped_scroll_offset: usize,
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
            last_click: None,
            show_historic: false,
            visible_rows: 10,
            scroll_offset: 0,
            grouped_scroll_offset: 0,
        }
    }
}

/// Compute a stable scroll offset that only adjusts when selection goes out of bounds.
pub fn compute_scroll_offset(
    selected_index: usize,
    current_offset: usize,
    visible_rows: usize,
    total_rows: usize,
) -> usize {
    if total_rows == 0 || visible_rows == 0 {
        return 0;
    }
    let max_offset = total_rows.saturating_sub(visible_rows);
    let mut offset = current_offset.min(max_offset);

    // Scroll up if selection is above viewport
    if selected_index < offset {
        offset = selected_index;
    }
    // Scroll down if selection is below viewport
    if selected_index >= offset + visible_rows {
        offset = selected_index - visible_rows + 1;
    }

    offset.min(max_offset)
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
    /// Jump directly to a tab by index (0 = Overview … 4 = Help).
    ///
    /// Keeps `show_help` in sync with `selected_tab` so the Help tab toggle
    /// (`h`) and the direct-jump shortcut (`5`) agree on which screen is
    /// visible. Out-of-range indices are ignored.
    pub fn jump_to_tab(&mut self, target: usize) {
        use crate::ui::{HELP_TAB_INDEX, TAB_COUNT};
        if target >= TAB_COUNT {
            return;
        }
        self.selected_tab = target;
        self.show_help = target == HELP_TAB_INDEX;
    }

    /// Cycle to the next tab, wrapping back to Overview after Help.
    pub fn next_tab(&mut self) {
        use crate::ui::TAB_COUNT;
        self.selected_tab = (self.selected_tab + 1) % TAB_COUNT;
    }

    /// Cycle to the previous tab, wrapping from Overview back to Help.
    pub fn prev_tab(&mut self) {
        use crate::ui::TAB_COUNT;
        self.selected_tab = if self.selected_tab == 0 {
            TAB_COUNT - 1
        } else {
            self.selected_tab - 1
        };
    }

    pub fn cycle_sort_column(&mut self) {
        self.sort_column = self.sort_column.next(self.has_geoip);
        // Reset to the default direction for the new column
        self.sort_ascending = self.sort_column.default_direction();
    }

    /// Toggle the sort direction for the current column
    pub fn toggle_sort_direction(&mut self) {
        self.sort_ascending = !self.sort_ascending;
    }

    /// Reset all view settings to defaults (grouping, sort, filter, historic)
    pub fn reset_view(&mut self) {
        self.grouping_enabled = false;
        self.expanded_groups.clear();
        self.selected_group = None;
        self.sort_column = SortColumn::default();
        self.sort_ascending = self.sort_column.default_direction();
        self.filter_query.clear();
        self.filter_mode = false;
        self.filter_cursor_position = 0;
        self.show_historic = false;
        self.scroll_offset = 0;
        self.grouped_scroll_offset = 0;
    }

    /// Toggle grouping mode
    pub fn toggle_grouping(&mut self) {
        self.grouping_enabled = !self.grouping_enabled;
        // When toggling grouping on, clear group selection to start fresh
        if self.grouping_enabled {
            self.selected_group = None;
            self.grouped_scroll_offset = 0;
        } else {
            self.scroll_offset = 0;
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

    /// Move selection up by one page in grouped view
    pub fn move_selection_page_up_grouped(
        &mut self,
        grouped_rows: &[GroupedRow],
        page_size: usize,
    ) {
        if grouped_rows.is_empty() {
            return;
        }

        let current_index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        let new_index = current_index.saturating_sub(page_size);
        self.set_selected_grouped_by_index(grouped_rows, new_index);
    }

    /// Move selection down by one page in grouped view
    pub fn move_selection_page_down_grouped(
        &mut self,
        grouped_rows: &[GroupedRow],
        page_size: usize,
    ) {
        if grouped_rows.is_empty() {
            return;
        }

        let current_index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        let new_index = (current_index + page_size).min(grouped_rows.len() - 1);
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
pub fn compute_grouped_rows<'a>(
    connections: &'a [Connection],
    expanded_groups: &HashSet<String>,
) -> Vec<GroupedRow<'a>> {
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

    // Build stats for each group in a single pass over each group's connections
    let mut group_stats: Vec<(String, ProcessGroupStats, Vec<&Connection>)> = groups
        .into_iter()
        .map(|(name, conns)| {
            let mut connection_count = 0usize;
            let mut historic_count = 0usize;
            let mut tcp_count = 0usize;
            let mut udp_count = 0usize;
            let mut total_incoming_rate_bps = 0.0f64;
            let mut total_outgoing_rate_bps = 0.0f64;

            for c in &conns {
                if c.is_historic {
                    historic_count += 1;
                } else {
                    connection_count += 1;
                    if c.protocol == Protocol::Tcp {
                        tcp_count += 1;
                    } else if c.protocol == Protocol::Udp {
                        udp_count += 1;
                    }
                    total_incoming_rate_bps += c.current_incoming_rate_bps;
                    total_outgoing_rate_bps += c.current_outgoing_rate_bps;
                }
            }

            let stats = ProcessGroupStats {
                connection_count,
                historic_count,
                tcp_count,
                udp_count,
                total_incoming_rate_bps,
                total_outgoing_rate_bps,
            };
            (name, stats, conns)
        })
        .collect();

    // Sort groups alphabetically by process name for stable ordering
    // (sorting by bandwidth causes constant reordering as rates fluctuate)
    group_stats.sort_by_key(|a| a.0.to_lowercase());

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
                    connection: conn,
                    is_last_in_group: idx == conn_count - 1,
                });
            }
        }
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{HELP_TAB_INDEX, TAB_COUNT};

    #[test]
    fn jump_to_tab_sets_selected_and_help_flag() {
        // Each in-range index switches to the matching tab; `show_help` must
        // agree with `selected_tab == HELP_TAB_INDEX` so the `h` toggle and
        // the direct-jump shortcut (`5`) stay coherent.
        for idx in 0..TAB_COUNT {
            // Start in the opposite `show_help` state so the assertion below
            // proves `jump_to_tab` rewrote the flag, not just left it alone.
            let mut ui = UIState {
                show_help: idx != HELP_TAB_INDEX,
                ..UIState::default()
            };
            ui.jump_to_tab(idx);
            assert_eq!(ui.selected_tab, idx, "selected_tab after jump_to_tab({idx})");
            assert_eq!(
                ui.show_help,
                idx == HELP_TAB_INDEX,
                "show_help after jump_to_tab({idx})"
            );
        }
    }

    #[test]
    fn jump_to_tab_ignores_out_of_range() {
        // Lock the invariant that the public API does not silently corrupt
        // `selected_tab` to a value outside `0..TAB_COUNT` — `tabs_bar.rs`
        // indexes into `TAB_TITLES` by that value when drawing.
        let mut ui = UIState {
            selected_tab: 2,
            show_help: false,
            ..UIState::default()
        };
        ui.jump_to_tab(TAB_COUNT);
        assert_eq!(ui.selected_tab, 2);
        assert!(!ui.show_help);
        ui.jump_to_tab(99);
        assert_eq!(ui.selected_tab, 2);
        assert!(!ui.show_help);
    }

    #[test]
    fn next_tab_cycles_and_wraps() {
        let mut ui = UIState::default();
        assert_eq!(ui.selected_tab, 0);
        for expected in 1..TAB_COUNT {
            ui.next_tab();
            assert_eq!(ui.selected_tab, expected);
        }
        // Past the last tab wraps to the first.
        ui.next_tab();
        assert_eq!(ui.selected_tab, 0);
    }

    #[test]
    fn prev_tab_wraps_from_first_to_last() {
        let mut ui = UIState::default();
        ui.prev_tab();
        assert_eq!(ui.selected_tab, TAB_COUNT - 1);
        ui.prev_tab();
        assert_eq!(ui.selected_tab, TAB_COUNT - 2);
    }
}
