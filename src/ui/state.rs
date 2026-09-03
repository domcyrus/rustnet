//! UiState, ClickableRegions, ClickAction, SortColumn, GroupedRow, and
//! the selection/scroll helpers: everything tracking what the user is
//! looking at and acting on. No rendering happens here; tabs and widgets
//! read these to know what to draw.

use std::cell::Cell;
use std::collections::HashSet;

use ratatui::layout::Rect;

use crate::network::types::{Connection, Protocol, UNKNOWN_PROCESS_NAME};

/// Traffic direction emphasized by the process activity view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivityDirection {
    #[default]
    Egress,
    Ingress,
}

impl ActivityDirection {
    pub fn toggle(self) -> Self {
        match self {
            Self::Egress => Self::Ingress,
            Self::Ingress => Self::Egress,
        }
    }

    pub fn display_name_with_rate(self) -> &'static str {
        match self {
            Self::Egress => "Egress (TX)",
            Self::Ingress => "Ingress (RX)",
        }
    }

    pub fn rate_label(self) -> &'static str {
        match self {
            Self::Egress => "TX",
            Self::Ingress => "RX",
        }
    }

    /// Select the transmit or receive value for this direction.
    pub fn pick<T>(self, tx: T, rx: T) -> T {
        match self {
            Self::Egress => tx,
            Self::Ingress => rx,
        }
    }
}

/// A selection movement shared by the flat and grouped connection lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum Motion {
    /// One row up, wrapping to the bottom from the first row.
    Up,
    /// One row down, wrapping to the top from the last row.
    Down,
    /// A page up, clamped at the first row.
    PageUp(usize),
    /// A page down, clamped at the last row.
    PageDown(usize),
    First,
    Last,
}

/// Compute the index a motion lands on in a list of `len` rows.
///
/// `len` must be non-zero; callers guard against empty lists.
fn step_index(current: usize, len: usize, motion: Motion) -> usize {
    let last = len.saturating_sub(1);
    match motion {
        Motion::Up => {
            if current > 0 {
                current - 1
            } else {
                last
            }
        }
        Motion::Down => {
            if current < last {
                current + 1
            } else {
                0
            }
        }
        Motion::PageUp(page) => current.saturating_sub(page),
        Motion::PageDown(page) => (current + page).min(last),
        Motion::First => 0,
        Motion::Last => last,
    }
}

/// Subview shown on the Host tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostView {
    #[default]
    Sockets,
    Interfaces,
}

/// Sort modes for the process activity view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActivitySort {
    #[default]
    RetainedTx,
    WindowTx,
    CurrentTx,
    PeakTx,
    Connections,
    Destinations,
    Process,
}

impl ActivitySort {
    pub fn next(self) -> Self {
        match self {
            Self::RetainedTx => Self::WindowTx,
            Self::WindowTx => Self::CurrentTx,
            Self::CurrentTx => Self::PeakTx,
            Self::PeakTx => Self::Connections,
            Self::Connections => Self::Destinations,
            Self::Destinations => Self::Process,
            Self::Process => Self::RetainedTx,
        }
    }

    pub fn display_name(self, direction: ActivityDirection) -> &'static str {
        match self {
            Self::RetainedTx => match direction {
                ActivityDirection::Egress => "Retained TX",
                ActivityDirection::Ingress => "Retained RX",
            },
            Self::WindowTx => match direction {
                ActivityDirection::Egress => "60s TX",
                ActivityDirection::Ingress => "60s RX",
            },
            Self::CurrentTx => match direction {
                ActivityDirection::Egress => "TX Rate",
                ActivityDirection::Ingress => "RX Rate",
            },
            Self::PeakTx => match direction {
                ActivityDirection::Egress => "Peak TX",
                ActivityDirection::Ingress => "Peak RX",
            },
            Self::Connections => "Connections",
            Self::Destinations => "Destinations",
            Self::Process => "Process",
        }
    }
}

/// Scroll state for a pane that only learns its content and viewport
/// size at render time (Details info panes, Help overlay, Host tables).
/// Event handlers mutate `offset`; the draw path reports the
/// real maximum through [`Self::clamp_for_render`] (a `Cell`, because
/// drawing only holds `&UiState`), so the next scroll input clamps
/// against what is actually on screen.
#[derive(Debug, Default)]
pub struct PaneScroll {
    offset: u16,
    max: Cell<u16>,
    viewport: Cell<u16>,
}

impl PaneScroll {
    pub fn scroll_up(&mut self, lines: u16) {
        self.offset = self.offset.saturating_sub(lines);
    }

    pub fn scroll_down(&mut self, lines: u16) {
        self.offset = self.offset.saturating_add(lines).min(self.max.get());
    }

    pub fn scroll_to_top(&mut self) {
        self.offset = 0;
    }

    pub fn scroll_to_bottom(&mut self) {
        self.offset = self.max.get();
    }

    pub fn reset(&mut self) {
        self.offset = 0;
        // Forget the last render's extent too, so the hint gating does not
        // keep advertising scroll for content that is gone; the next render
        // reports the real extent again.
        self.max.set(0);
    }

    /// Whether the last render had content beyond the viewport. Drives
    /// hints that would otherwise advertise a key that does nothing.
    pub fn can_scroll(&self) -> bool {
        self.max.get() > 0
    }

    /// Record this render's maximum scroll offset and return the
    /// (clamped) offset to draw with.
    pub fn clamp_for_render(&self, max: u16) -> u16 {
        self.max.set(max);
        self.offset.min(max)
    }

    /// Record this render's viewport height so page-wise scrolling can
    /// step by what is actually on screen. Survives [`Self::reset`]: a
    /// stale height from the previous render beats stepping by one line.
    pub fn record_viewport(&self, rows: u16) {
        self.viewport.set(rows);
    }

    /// Viewport height reported by the last render (0 before the first).
    pub fn viewport_rows(&self) -> u16 {
        self.viewport.get()
    }
}

/// Sort column options for the connections table.
/// Protocol is merged into Application, whose comparator tie-breaks on it.
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
    Rtt,    // Best available TCP, QUIC handshake, or ICMP echo RTT
    Health, // Protocol-aware observable health signals
}

impl SortColumn {
    /// Get the next sort column in the cycle (follows left-to-right visual
    /// order: identifying columns first, status columns last). When
    /// `has_location` is true, Location is included after Local Address.
    ///
    /// Columns hidden at narrow widths stay in the cycle: the active sort
    /// is always named in the table's section title, so sorting by an
    /// off-screen column is still discoverable.
    pub fn next(self, has_location: bool) -> Self {
        match self {
            Self::CreatedAt => Self::Process,          // Column 1: Process
            Self::Process => Self::RemoteAddress,      // Column 2: Remote
            Self::RemoteAddress => Self::LocalAddress, // Column 3: Local
            Self::LocalAddress => {
                if has_location {
                    Self::Location // Column 4: Loc (GeoIP)
                } else {
                    Self::Service
                }
            }
            Self::Location => Self::Service,    // Column 5: Service
            Self::Service => Self::Application, // Column 6: App (proto·application)
            Self::Application => Self::State,   // Column 7: State
            Self::State => Self::Rtt,           // Column 8: RTT
            Self::Rtt => Self::Health,          // Column 9: Health
            Self::Health => Self::BandwidthTotal, // Column 10: ↓Rx/Tx↑ (combined total)
            Self::BandwidthTotal => Self::CreatedAt, // Back to default
        }
    }

    /// Get the default sort direction for this column (true = ascending, false = descending)
    pub fn default_direction(self) -> bool {
        match self {
            // Descending by default - show biggest/most active first
            Self::BandwidthTotal => false,
            // Slowest connections first - latency problems surface on top
            Self::Rtt => false,
            // Most severe observable health signals first
            Self::Health => false,

            // Ascending by default - alphabetical or chronological
            Self::Process => true,
            Self::LocalAddress => true,
            Self::RemoteAddress => true,
            Self::Location => true,
            Self::Application => true,
            Self::Service => true,
            Self::State => true,
            Self::CreatedAt => true, // Oldest first (current default behavior)
        }
    }

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
            Self::Rtt => "RTT",
            Self::Health => "Health",
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
    /// Switch to a specific tab (index 0-4).
    SwitchTab(usize),
    /// Select a connection by index in the current sorted/filtered list
    SelectConnection(usize),
    /// Select a connection by its stable key. Used where an index would
    /// be ambiguous (the Details strip shows flat-list neighbors even
    /// while grouping is enabled, where indices mean grouped rows).
    SelectConnectionKey(String),
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
pub struct UiState {
    pub selected_tab: usize,
    pub selected_connection_key: Option<String>,
    /// Cached positions for the selected key. Each lookup validates the hint
    /// against the current row before using it, so sorting and filtering keep
    /// key-based selection semantics without repeatedly scanning the full list.
    #[doc(hidden)]
    pub selected_connection_index_hint: Cell<Option<usize>>,
    #[doc(hidden)]
    pub selected_grouped_index_hint: Cell<Option<usize>>,
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
    /// Whether the System stats sidebar is visible on the Overview tab.
    /// A layout preference, so deliberately not reset by `reset_view()`.
    pub show_system_panel: bool,
    /// Number of visible rows in the connections table (updated after rendering)
    pub visible_rows: usize,
    /// Scroll offset for flat connection list (persisted for stable scrolling)
    pub scroll_offset: usize,
    /// Scroll offset for grouped connection list (persisted for stable scrolling)
    pub grouped_scroll_offset: usize,
    /// Scroll state for the Details info panes (reset when the selection changes)
    pub details_scroll: PaneScroll,
    /// Scroll state for the contextual help overlay.
    pub help_scroll: PaneScroll,
    /// Scroll state for the Host tab's interface table.
    pub interfaces_scroll: PaneScroll,
    /// Scroll state for the Host tab's socket table.
    pub host_sockets_scroll: PaneScroll,
    /// Active Host tab subview.
    pub host_view: HostView,
    /// Process traffic direction emphasized by Activity.
    pub activity_direction: ActivityDirection,
    /// Active process-activity sort mode.
    pub activity_sort: ActivitySort,
    /// Sort direction for the process-activity table.
    pub activity_sort_ascending: bool,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            selected_tab: 0,
            selected_connection_key: None,
            selected_connection_index_hint: Cell::new(None),
            selected_grouped_index_hint: Cell::new(None),
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
            show_system_panel: true,
            visible_rows: 10,
            scroll_offset: 0,
            grouped_scroll_offset: 0,
            details_scroll: PaneScroll::default(),
            help_scroll: PaneScroll::default(),
            interfaces_scroll: PaneScroll::default(),
            host_sockets_scroll: PaneScroll::default(),
            host_view: HostView::default(),
            activity_direction: ActivityDirection::default(),
            activity_sort: ActivitySort::default(),
            activity_sort_ascending: false,
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

    if selected_index < offset {
        offset = selected_index;
    }
    if selected_index >= offset + visible_rows {
        offset = selected_index - visible_rows + 1;
    }

    offset.min(max_offset)
}

impl UiState {
    /// Whether the query changes the displayed connection set.
    pub fn has_active_filter(&self) -> bool {
        !self.filter_query.trim().is_empty()
    }

    /// Whether the connection list is being narrowed right now: a
    /// persisted query, or one currently being typed. Drives the
    /// Overview tab's activity dot in the tab bar.
    pub fn is_filtering(&self) -> bool {
        self.filter_mode || self.has_active_filter()
    }

    /// Whether the filter input row is on screen, claiming a terminal row.
    /// The row is an editing surface only: once a query is confirmed it is
    /// gone and the title chip carries the state. The layout in `ui::draw`
    /// and the page-navigation math in `main` both read this, so the two
    /// cannot disagree about how many rows the chrome occupies.
    pub fn filter_row_visible(&self) -> bool {
        self.filter_mode
    }

    /// Set the selected connection key, resetting the Details pane
    /// scroll when the selection actually changes so a newly selected
    /// record always starts at the top.
    pub fn set_connection_key(&mut self, key: Option<String>) {
        if self.selected_connection_key != key {
            self.details_scroll.reset();
            self.selected_connection_index_hint.set(None);
            self.selected_grouped_index_hint.set(None);
        }
        self.selected_connection_key = key;
    }

    pub fn get_selected_index(&self, connections: &[Connection]) -> Option<usize> {
        if let Some(ref selected_key) = self.selected_connection_key {
            if let Some(index) = self.selected_connection_index_hint.get()
                && connections
                    .get(index)
                    .is_some_and(|conn| conn.key() == *selected_key)
            {
                return Some(index);
            }

            let index = connections
                .iter()
                .position(|conn| conn.key() == *selected_key);
            self.selected_connection_index_hint.set(index);
            index
        } else if !connections.is_empty() {
            Some(0) // Default to first connection
        } else {
            None
        }
    }

    pub fn set_selected_by_index(&mut self, connections: &[Connection], index: usize) {
        if let Some(conn) = connections.get(index) {
            self.set_connection_key(Some(conn.key()));
            self.selected_connection_index_hint.set(Some(index));
        }
    }

    /// Apply a motion to the flat connection list selection.
    pub(in crate::ui) fn move_selection(&mut self, connections: &[Connection], motion: Motion) {
        if connections.is_empty() {
            log::debug!("move_selection({motion:?}): connections list is empty");
            return;
        }

        let current_index = self.get_selected_index(connections).unwrap_or(0);
        let old_key = self.selected_connection_key.clone();
        let new_index = step_index(current_index, connections.len(), motion);
        self.set_selected_by_index(connections, new_index);
        log::debug!(
            "move_selection({motion:?}): moved from index {current_index} to {new_index} of {} (key: {old_key:?} -> {:?})",
            connections.len(),
            self.selected_connection_key
        );
    }

    pub fn move_selection_up(&mut self, connections: &[Connection]) {
        self.move_selection(connections, Motion::Up);
    }

    pub fn move_selection_down(&mut self, connections: &[Connection]) {
        self.move_selection(connections, Motion::Down);
    }

    /// Ensure we have a valid selection when connections list changes
    pub fn ensure_valid_selection(&mut self, connections: &[Connection]) -> Option<usize> {
        if connections.is_empty() {
            log::debug!("ensure_valid_selection: connections list is empty, clearing selection");
            self.set_connection_key(None);
            return None;
        }

        let current_index = self.get_selected_index(connections);
        log::debug!(
            "ensure_valid_selection: current_index={:?}, total_connections={}",
            current_index,
            connections.len()
        );

        if self.selected_connection_key.is_none() || current_index.is_none() {
            log::debug!("ensure_valid_selection: selecting first connection (index 0)");
            self.set_selected_by_index(connections, 0);
            Some(0)
        } else {
            current_index
        }
    }

    pub fn enter_filter_mode(&mut self) {
        self.filter_mode = true;
        self.filter_cursor_position = self.filter_query.len();
    }

    pub fn exit_filter_mode(&mut self) {
        if !self.has_active_filter() {
            self.filter_query.clear();
        }
        self.filter_mode = false;
        self.filter_cursor_position = 0;
    }

    pub fn clear_filter(&mut self) {
        self.filter_query.clear();
        self.exit_filter_mode();
    }

    pub fn filter_add_char(&mut self, c: char) {
        self.filter_query.insert(self.filter_cursor_position, c);
        self.filter_cursor_position += 1;
    }

    pub fn filter_backspace(&mut self) {
        if self.filter_cursor_position > 0 {
            self.filter_cursor_position -= 1;
            self.filter_query.remove(self.filter_cursor_position);
        }
    }

    pub fn filter_cursor_left(&mut self) {
        if self.filter_cursor_position > 0 {
            self.filter_cursor_position -= 1;
        }
    }

    pub fn filter_cursor_right(&mut self) {
        if self.filter_cursor_position < self.filter_query.len() {
            self.filter_cursor_position += 1;
        }
    }

    /// Jump directly to a tab by index (0 = Overview, 4 = Host).
    /// Out-of-range indices are ignored.
    pub fn jump_to_tab(&mut self, target: usize) {
        use crate::ui::TAB_COUNT;
        if target >= TAB_COUNT {
            return;
        }
        self.selected_tab = target;
        self.rewind_help_for_new_view();
    }

    /// Cycle to the next tab, wrapping back to Overview after Host.
    pub fn next_tab(&mut self) {
        use crate::ui::TAB_COUNT;
        self.selected_tab = (self.selected_tab + 1) % TAB_COUNT;
        self.rewind_help_for_new_view();
    }

    /// Cycle to the previous tab, wrapping from Overview back to Host.
    pub fn prev_tab(&mut self) {
        use crate::ui::TAB_COUNT;
        self.selected_tab = if self.selected_tab == 0 {
            TAB_COUNT - 1
        } else {
            self.selected_tab - 1
        };
        self.rewind_help_for_new_view();
    }

    /// Help content is per-view, so an open overlay restarts from its top
    /// when tab navigation changes the view underneath it.
    fn rewind_help_for_new_view(&mut self) {
        if self.show_help {
            self.help_scroll.reset();
        }
    }

    pub fn cycle_sort_column(&mut self) {
        self.sort_column = self.sort_column.next(self.has_geoip);
        self.sort_ascending = self.sort_column.default_direction();
    }

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
        self.activity_sort = ActivitySort::default();
        self.activity_sort_ascending = false;
        self.activity_direction = ActivityDirection::default();
        self.grouped_scroll_offset = 0;
    }

    pub fn toggle_grouping(&mut self) {
        self.grouping_enabled = !self.grouping_enabled;
        if self.grouping_enabled {
            self.selected_group = None;
            self.grouped_scroll_offset = 0;
        } else {
            self.scroll_offset = 0;
        }
    }

    /// Whether the currently selected group is expanded; `None` when no
    /// group is selected. The single predicate behind the Space key and the
    /// status bar's expand/collapse hint, so the two can never disagree.
    pub fn selected_group_expansion(&self) -> Option<bool> {
        self.selected_group
            .as_ref()
            .map(|group| self.expanded_groups.contains(group))
    }

    pub fn toggle_group_expansion(&mut self) {
        match self.selected_group_expansion() {
            Some(true) => self.collapse_selected_group(),
            Some(false) => self.expand_selected_group(),
            None => {}
        }
    }

    pub fn expand_selected_group(&mut self) {
        if let Some(ref group_name) = self.selected_group {
            self.expanded_groups.insert(group_name.clone());
        }
    }

    pub fn collapse_selected_group(&mut self) {
        if let Some(group_name) = self.selected_group.clone()
            && self.expanded_groups.remove(&group_name)
        {
            self.set_connection_key(None);
        }
    }

    pub fn get_selected_grouped_index(&self, grouped_rows: &[GroupedRow]) -> Option<usize> {
        if grouped_rows.is_empty() {
            self.selected_grouped_index_hint.set(None);
            return None;
        }

        if let Some(index) = self.selected_grouped_index_hint.get()
            && let Some(row) = grouped_rows.get(index)
        {
            let matches = if let Some(ref selected_key) = self.selected_connection_key {
                matches!(row, GroupedRow::Connection { connection, .. } if connection.key() == *selected_key)
            } else if let Some(ref selected_group) = self.selected_group {
                matches!(row, GroupedRow::Group { process_name, .. } if process_name == selected_group)
            } else {
                false
            };
            if matches {
                return Some(index);
            }
        }

        // First check if we have a selected connection that's visible
        if let Some(ref selected_key) = self.selected_connection_key {
            for (idx, row) in grouped_rows.iter().enumerate() {
                if let GroupedRow::Connection { connection, .. } = row
                    && connection.key() == *selected_key
                {
                    self.selected_grouped_index_hint.set(Some(idx));
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
                    self.selected_grouped_index_hint.set(Some(idx));
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
                    self.set_connection_key(None);
                    self.selected_grouped_index_hint.set(Some(index));
                }
                GroupedRow::Connection {
                    process_name,
                    connection,
                    ..
                } => {
                    self.set_connection_key(Some(connection.key()));
                    self.selected_group = Some(process_name.clone());
                    self.selected_grouped_index_hint.set(Some(index));
                }
            }
        }
    }

    /// Apply a motion to the grouped row selection.
    pub(in crate::ui) fn move_selection_grouped(
        &mut self,
        grouped_rows: &[GroupedRow],
        motion: Motion,
    ) {
        if grouped_rows.is_empty() {
            return;
        }

        let current_index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        let new_index = step_index(current_index, grouped_rows.len(), motion);
        self.set_selected_grouped_by_index(grouped_rows, new_index);
    }

    /// Ensure valid selection in grouped view
    pub fn ensure_valid_grouped_selection(&mut self, grouped_rows: &[GroupedRow]) -> Option<usize> {
        if grouped_rows.is_empty() {
            self.selected_group = None;
            self.set_connection_key(None);
            return None;
        }

        // Re-anchor the selection state to the row actually highlighted.
        // `get_selected_grouped_index` falls back to row 0 whenever the
        // selected group or connection vanished from the rows; without this
        // write-back, `selected_group` would keep naming the vanished group
        // and the Space hint and handler would act on a group that is no
        // longer the highlighted row. This also covers first enabling
        // grouping, when nothing is selected yet.
        let index = self.get_selected_grouped_index(grouped_rows).unwrap_or(0);
        self.set_selected_grouped_by_index(grouped_rows, index);
        Some(index)
    }

    pub fn is_group_selected(&self) -> bool {
        self.selected_group.is_some() && self.selected_connection_key.is_none()
    }
}

/// Group label shown for connections without a resolved process name.
pub(super) const UNKNOWN_PROCESS_GROUP: &str = "<unknown>";

/// The process-group label for a connection. Attribution can fail two ways:
/// no owner found at all (`process_name` is `None`), or an owner PID whose
/// name lookup failed and stored the [`UNKNOWN_PROCESS_NAME`] placeholder
/// (protected processes, the pre-resolution ETW window). Both fold into one
/// bucket so the UI never shows two different unknown groups side by side.
pub fn process_group_label(conn: &Connection) -> &str {
    match conn.process_name.as_deref() {
        None | Some(UNKNOWN_PROCESS_NAME) => UNKNOWN_PROCESS_GROUP,
        Some(name) => name,
    }
}

pub fn compute_grouped_rows<'a>(
    connections: &'a [Connection],
    expanded_groups: &HashSet<String>,
) -> Vec<GroupedRow<'a>> {
    use std::collections::HashMap;

    // Group connections by process name, borrowing the name from each connection
    // to avoid cloning N Strings just to use as HashMap keys.
    let mut groups: HashMap<&'a str, Vec<&'a Connection>> = HashMap::new();
    for conn in connections {
        groups
            .entry(process_group_label(conn))
            .or_default()
            .push(conn);
    }

    // Build stats for each group in a single pass over each group's connections
    let mut group_stats: Vec<(&'a str, ProcessGroupStats, Vec<&'a Connection>)> = groups
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
        let expanded = expanded_groups.contains(name);
        rows.push(GroupedRow::Group {
            process_name: name.to_owned(),
            stats,
            expanded,
        });

        if expanded {
            let conn_count = conns.len();
            for (idx, conn) in conns.into_iter().enumerate() {
                rows.push(GroupedRow::Connection {
                    process_name: name.to_owned(),
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
    use crate::ui::TAB_COUNT;
    use crate::ui::test_support::local_tcp;

    #[test]
    fn step_index_wraps_and_clamps() {
        assert_eq!(step_index(0, 5, Motion::Up), 4);
        assert_eq!(step_index(3, 5, Motion::Up), 2);
        assert_eq!(step_index(4, 5, Motion::Down), 0);
        assert_eq!(step_index(1, 5, Motion::Down), 2);
        assert_eq!(step_index(1, 5, Motion::PageUp(10)), 0);
        assert_eq!(step_index(4, 5, Motion::PageUp(2)), 2);
        assert_eq!(step_index(1, 5, Motion::PageDown(10)), 4);
        assert_eq!(step_index(1, 5, Motion::PageDown(2)), 3);
        assert_eq!(step_index(3, 5, Motion::First), 0);
        assert_eq!(step_index(0, 5, Motion::Last), 4);
        // A single row is a fixed point for every motion.
        for motion in [
            Motion::Up,
            Motion::Down,
            Motion::PageUp(3),
            Motion::PageDown(3),
            Motion::First,
            Motion::Last,
        ] {
            assert_eq!(step_index(0, 1, motion), 0);
        }
    }

    #[test]
    fn whitespace_only_filter_is_inactive_and_cleared_on_exit() {
        let mut ui = UiState {
            filter_mode: true,
            filter_query: "   ".to_string(),
            filter_cursor_position: 3,
            ..UiState::default()
        };

        assert!(!ui.has_active_filter());
        ui.exit_filter_mode();

        assert!(!ui.filter_mode);
        assert!(ui.filter_query.is_empty());
        assert_eq!(ui.filter_cursor_position, 0);
    }

    #[test]
    fn is_filtering_covers_both_typing_and_a_persisted_query() {
        assert!(!UiState::default().is_filtering());

        // Filter mode with an empty query still counts: the user is typing.
        let typing = UiState {
            filter_mode: true,
            ..UiState::default()
        };
        assert!(typing.is_filtering());

        // A persisted query counts after filter mode is left.
        let persisted = UiState {
            filter_query: "port:443".to_string(),
            ..UiState::default()
        };
        assert!(persisted.is_filtering());

        // Whitespace alone narrows nothing.
        let blank = UiState {
            filter_query: "   ".to_string(),
            ..UiState::default()
        };
        assert!(!blank.is_filtering());
    }

    #[test]
    fn jump_to_tab_preserves_overlay_visibility() {
        // Tab selection and overlay visibility are independent so help can
        // describe the view that remains underneath it.
        for idx in 0..TAB_COUNT {
            let mut ui = UiState {
                show_help: true,
                ..UiState::default()
            };
            ui.jump_to_tab(idx);
            assert_eq!(
                ui.selected_tab, idx,
                "selected_tab after jump_to_tab({idx})"
            );
            assert!(ui.show_help, "overlay after jump_to_tab({idx})");
        }
    }

    #[test]
    fn jump_to_tab_ignores_out_of_range() {
        // Lock the invariant that the public API does not silently corrupt
        // `selected_tab` to a value outside `0..TAB_COUNT`; `tabs_bar.rs`
        // indexes into `TAB_TITLES` by that value when drawing.
        let mut ui = UiState {
            selected_tab: 2,
            show_help: false,
            ..UiState::default()
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
        let mut ui = UiState::default();
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
        let mut ui = UiState::default();
        ui.prev_tab();
        assert_eq!(ui.selected_tab, TAB_COUNT - 1);
        ui.prev_tab();
        assert_eq!(ui.selected_tab, TAB_COUNT - 2);
    }

    #[test]
    fn pane_scroll_clamps_to_render_reported_max() {
        let mut scroll = PaneScroll::default();
        // Before any render the max is 0, so scrolling down is a no-op.
        scroll.scroll_down(5);
        assert_eq!(scroll.clamp_for_render(10), 0);

        // After a render reported max=10, downward scrolling sticks to it.
        scroll.scroll_down(25);
        assert_eq!(scroll.clamp_for_render(10), 10);

        // A shorter record (smaller max) clamps the draw offset without
        // mutating the handler-side state.
        assert_eq!(scroll.clamp_for_render(3), 3);

        scroll.scroll_up(1);
        assert_eq!(scroll.clamp_for_render(10), 9);

        scroll.scroll_to_bottom();
        assert_eq!(scroll.clamp_for_render(10), 10);
        scroll.scroll_to_top();
        assert_eq!(scroll.clamp_for_render(10), 0);
    }

    #[test]
    fn activity_direction_keeps_semantic_and_counter_names_paired() {
        let direction = ActivityDirection::Egress;
        assert_eq!(direction.display_name_with_rate(), "Egress (TX)");
        assert_eq!(direction.toggle(), ActivityDirection::Ingress);
        assert_eq!(
            ActivitySort::RetainedTx.display_name(ActivityDirection::Ingress),
            "Retained RX"
        );
    }

    #[test]
    fn details_scroll_resets_when_selection_changes() {
        let mut ui = UiState::default();
        ui.details_scroll.clamp_for_render(20);
        ui.details_scroll.scroll_down(7);

        // Same key: scroll position survives (e.g. periodic refresh).
        ui.set_connection_key(Some("a".to_string()));
        ui.details_scroll.clamp_for_render(20);
        ui.details_scroll.scroll_down(7);
        ui.set_connection_key(Some("a".to_string()));
        assert_eq!(ui.details_scroll.clamp_for_render(20), 7);

        // New key: the new record starts at the top.
        ui.set_connection_key(Some("b".to_string()));
        assert_eq!(ui.details_scroll.clamp_for_render(20), 0);
    }

    #[test]
    fn selection_hint_recovers_after_reordering() {
        let mut connections = vec![local_tcp(1000, "first"), local_tcp(1001, "second")];
        let mut ui = UiState::default();
        ui.set_selected_by_index(&connections, 1);
        assert_eq!(ui.selected_connection_index_hint.get(), Some(1));

        connections.swap(0, 1);

        assert_eq!(ui.get_selected_index(&connections), Some(0));
        assert_eq!(ui.selected_connection_index_hint.get(), Some(0));
    }

    #[test]
    fn grouped_selection_hint_recovers_after_rows_shift() {
        let connections = vec![local_tcp(1000, "alpha"), local_tcp(1001, "beta")];
        let expanded = HashSet::from(["alpha".to_string(), "beta".to_string()]);
        let rows = compute_grouped_rows(&connections, &expanded);
        let mut ui = UiState::default();
        ui.set_selected_grouped_by_index(&rows, 3);
        assert_eq!(ui.selected_grouped_index_hint.get(), Some(3));

        let rows = compute_grouped_rows(&connections, &HashSet::from(["beta".to_string()]));

        assert_eq!(ui.get_selected_grouped_index(&rows), Some(2));
        assert_eq!(ui.selected_grouped_index_hint.get(), Some(2));
    }

    #[test]
    fn vanished_group_is_repaired_to_the_row_actually_highlighted() {
        let mut ui = UiState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            ..UiState::default()
        };
        ui.expanded_groups.insert("firefox".to_string());

        // firefox exits while chrome remains: the highlight falls back to
        // row 0, and the selection state must follow it, or Space (and the
        // status bar hint) would keep acting on the vanished group.
        let survivors = vec![local_tcp(1000, "chrome")];
        let rows = compute_grouped_rows(&survivors, &ui.expanded_groups);
        assert_eq!(ui.ensure_valid_grouped_selection(&rows), Some(0));
        assert_eq!(ui.selected_group.as_deref(), Some("chrome"));
        assert_eq!(ui.selected_group_expansion(), Some(false));
    }

    /// Unattributed connections and ones carrying the "Unknown" name
    /// placeholder (e.g. a PID whose name lookup was denied) must share one
    /// group instead of showing "<unknown>" and "Unknown" side by side.
    #[test]
    fn unknown_placeholder_groups_with_unattributed_connections() {
        let mut unattributed = local_tcp(1000, "ignored");
        unattributed.process_name = None;
        let placeholder = local_tcp(1001, UNKNOWN_PROCESS_NAME);
        let named = local_tcp(1002, "firefox");
        let connections = vec![unattributed, placeholder, named];

        let rows = compute_grouped_rows(&connections, &HashSet::new());
        let mut headers: Vec<&str> = rows
            .iter()
            .filter_map(|row| match row {
                GroupedRow::Group {
                    process_name,
                    stats,
                    ..
                } => {
                    assert_eq!(
                        stats.connection_count,
                        if process_name == UNKNOWN_PROCESS_GROUP {
                            2
                        } else {
                            1
                        }
                    );
                    Some(process_name.as_str())
                }
                _ => None,
            })
            .collect();
        headers.sort_unstable();
        assert_eq!(headers, vec![UNKNOWN_PROCESS_GROUP, "firefox"]);
    }

    #[test]
    fn collapsing_group_from_connection_selects_group_header() {
        let connections = vec![local_tcp(1000, "alpha"), local_tcp(1001, "alpha")];
        let mut ui = UiState {
            grouping_enabled: true,
            expanded_groups: HashSet::from(["alpha".to_string()]),
            ..UiState::default()
        };
        let rows = compute_grouped_rows(&connections, &ui.expanded_groups);
        ui.set_selected_grouped_by_index(&rows, 1);
        assert!(!ui.is_group_selected());

        ui.toggle_group_expansion();

        assert!(!ui.expanded_groups.contains("alpha"));
        assert!(ui.is_group_selected());
        let collapsed_rows = compute_grouped_rows(&connections, &ui.expanded_groups);
        assert_eq!(ui.get_selected_grouped_index(&collapsed_rows), Some(0));
    }
}
