use anyhow::Result;
use arboard::Clipboard; // For clipboard access
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dns_lookup; // For reverse DNS lookups
use log::{debug, error}; // For logging
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant}; // Added Duration

use crate::config::Config;
use crate::i18n::I18n;
use crate::network::{Connection, NetworkMonitor, Process};

/// Application actions
pub enum Action {
    Quit,
    Refresh,
    // Add more actions as needed
}

/// Application view modes
pub enum ViewMode {
    Overview,
    ConnectionDetails,
    Help,
}

/// Fields that can be focused for copying in the Connection Details view
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailFocusField {
    LocalIp,
    RemoteIp,
}

/// Application state
pub struct App {
    /// Application configuration
    pub config: Config,
    /// Internationalization
    pub i18n: I18n,
    /// Current view mode
    pub mode: ViewMode,
    // Whether the application should quit - field removed as it was unused, Action::Quit handles this
    /// Network monitor instance
    network_monitor: Option<Arc<Mutex<NetworkMonitor>>>,
    /// Active connections
    pub connections: Vec<Connection>,
    /// Process map (pid to process)
    pub processes: HashMap<u32, Process>,
    /// Currently selected connection
    pub selected_connection: Option<Connection>,
    /// Currently selected connection index
    pub selected_connection_idx: usize,
    // Currently selected process index - field removed as it was unused
    /// Show IP locations (requires MaxMind DB)
    pub show_locations: bool,
    /// Show DNS hostnames instead of IP addresses
    pub show_hostnames: bool,
    // Last connection sort time - field removed as it was unused
    /// Connection order map (for stable ordering)
    connection_order: HashMap<String, usize>,
    /// Next order index for new connections
    next_order_index: usize,
    /// DNS cache to avoid repeated lookups
    dns_cache: HashMap<IpAddr, String>,
    /// Shared connection data updated by the background thread
    connections_data_shared: Option<Arc<Mutex<Vec<Connection>>>>,
    /// Which field is focused for copying in the details view
    pub detail_focus: DetailFocusField,
    // last_process_info_update field removed, new thread handles its own timing.
    /// Shared process data updated by the new background thread
    processes_data_shared: Option<Arc<Mutex<HashMap<u32, Process>>>>,
}

const PROCESS_INFO_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const RATE_CALCULATION_WINDOW: Duration = Duration::from_secs(5);
const RATE_HISTORY_PRUNE_EXTENSION: Duration = Duration::from_secs(2); // Keep data a bit longer than the window

impl App {
    /// Create a new application instance
    pub fn new(config: Config, i18n: I18n) -> Result<Self> {
        log::info!("App::new - Starting application initialization");
        let app = Self {
            config,
            i18n,
            mode: ViewMode::Overview,
            // should_quit: false, // Field removed
            network_monitor: None,
            connections: Vec::new(),
            processes: HashMap::new(),
            selected_connection: None,
            selected_connection_idx: 0,
            // selected_process_idx: 0, // Field removed
            show_locations: true,
            show_hostnames: false,
            // last_sort_time: std::time::Instant::now(), // Field removed
            connection_order: HashMap::new(),
            next_order_index: 0,
            dns_cache: HashMap::new(),
            connections_data_shared: None,
            processes_data_shared: None, // Initialize new shared data
            detail_focus: DetailFocusField::LocalIp, // Default focus to Local IP
                                         // last_process_info_update removed
        };
        log::info!("App::new - Application initialized successfully");
        Ok(app)
    }

    /// Dumps all current connections to the log file.
    pub fn log_all_connections(&mut self) {
        // Ensuring no hidden characters in this definition
        log::info!("Dumping all current connections to log:");
        if self.connections.is_empty() {
            log::info!("No connections to dump.");
            return;
        }
        for (index, conn) in self.connections.iter().enumerate() {
            log::info!("Connection [{}]: {:?}", index, conn);
        }
        log::info!("Finished dumping {} connections.", self.connections.len());
    }

    /// Start network capture
    pub fn start_capture(&mut self) -> Result<()> {
        log::info!("App::start_capture - Starting network capture setup");
        // Create network monitor
        let interface = self.config.interface.clone();
        let filter_localhost = self.config.filter_localhost;
        log::info!("App::start_capture - Calling NetworkMonitor::new");
        let mut monitor = NetworkMonitor::new(interface, filter_localhost)?; // Made monitor mutable
        log::info!("App::start_capture - NetworkMonitor::new returned");

        // Process info collection is now handled by App::on_tick, so set_collect_process_info is removed.

        // Get initial connections without process info
        log::info!("App::start_capture - Calling initial monitor.get_connections()");
        self.connections = monitor.get_connections()?;
        log::info!(
            "App::start_capture - Initial monitor.get_connections() returned {} connections",
            self.connections.len()
        );

        // Start monitoring in background thread
        let monitor_arc = Arc::new(Mutex::new(monitor)); // Correctly initialize monitor_arc

        // --- Packet Processing Thread ---
        let monitor_clone_packets = Arc::clone(&monitor_arc);
        // Initialize connections_data_shared with the initial connections
        let initial_connections_for_shared = self.connections.clone();
        let original_connections_shared_arc = Arc::new(Mutex::new(initial_connections_for_shared)); 
        self.connections_data_shared = Some(Arc::clone(&original_connections_shared_arc)); // Clone for App's use

        let packet_thread_connections_arc = Arc::clone(&original_connections_shared_arc); // Clone for the packet processing thread
        let app_config_packets = self.config.clone();
        thread::spawn(move || -> Result<()> {
            // packet_thread_connections_arc is moved here
            loop {
                // Lock the Arc<Mutex<NetworkMonitor>> to get MutexGuard<NetworkMonitor>
                let mut monitor_guard = monitor_clone_packets.lock().unwrap();

                // First, process any pending packets
                if let Err(e) = monitor_guard.process_packets() {
                    error!("Packet thread: Error processing packets: {}", e);
                }
                // Then, get the updated connections
                let new_connections = match monitor_guard.get_connections() {
                    Ok(conns) => conns,
                    Err(e) => {
                        error!("Packet thread: Error getting connections: {}", e);
                        Vec::new()
                    }
                };
                // monitor_guard is dropped here, releasing the lock on NetworkMonitor

                // Update shared connections using the thread-specific Arc clone
                let mut connections_shared_guard = packet_thread_connections_arc.lock().unwrap();
                *connections_shared_guard = new_connections;
                drop(connections_shared_guard);

                let sleep_duration_ms = if app_config_packets.packet_processing_interval_ms == 0 {
                    1
                } else {
                    app_config_packets.packet_processing_interval_ms
                };
                thread::sleep(std::time::Duration::from_millis(sleep_duration_ms));
            }
        });

        // --- Process Information Fetching Thread ---
        let monitor_clone_procs = Arc::clone(&monitor_arc);
        let process_thread_connections_arc = Arc::clone(&original_connections_shared_arc); // Clone from original for this thread
        let processes_update_shared = Arc::new(Mutex::new(HashMap::new()));
        self.processes_data_shared = Some(Arc::clone(&processes_update_shared));

        thread::spawn(move || -> Result<()> {
            // process_thread_connections_arc is moved here
            log::info!("PROCESS_THREAD: SPAWNED AND ENTERED CLOSURE");
            loop {
                log::info!(
                    "PROCESS_THREAD: Top of loop, about to sleep for {:?}.",
                    PROCESS_INFO_UPDATE_INTERVAL
                );
                thread::sleep(PROCESS_INFO_UPDATE_INTERVAL);
                log::info!("PROCESS_THREAD: Awake after sleep.");

                log::debug!("PROCESS_THREAD: Attempting to lock connections_data_shared (process_thread_connections_arc).");
                let connections_to_check = {
                    let connections_guard = match process_thread_connections_arc.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            log::error!("PROCESS_THREAD: Failed to lock connections_data_shared (poisoned): {:?}", poisoned);
                            return Err(anyhow::anyhow!(
                                "PROCESS_THREAD: Failed to lock connections_data_shared (poisoned)"
                            ));
                        }
                    };
                    log::debug!("PROCESS_THREAD: Locked connections_data_shared successfully.");
                    let cloned_conns = connections_guard.clone();
                    drop(connections_guard); // Release lock ASAP
                    log::debug!("PROCESS_THREAD: Cloned connections_to_check (count: {}), connections_data_shared lock released.", cloned_conns.len());
                    cloned_conns
                };

                log::debug!(
                    "PROCESS_THREAD: Attempting to lock NetworkMonitor (monitor_clone_procs)."
                );
                let monitor_guard = match monitor_clone_procs.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        log::error!(
                            "PROCESS_THREAD: Failed to lock NetworkMonitor (poisoned): {:?}",
                            poisoned
                        );
                        return Err(anyhow::anyhow!(
                            "PROCESS_THREAD: Failed to lock NetworkMonitor (poisoned)"
                        ));
                    }
                };
                log::debug!("PROCESS_THREAD: Locked NetworkMonitor successfully.");
                let mut collected_processes_this_cycle: HashMap<u32, Process> = HashMap::new();

                // Iterate over connections to gather or update process information
                if !connections_to_check.is_empty() {
                    log::debug!(
                        "Process thread: First few connections_to_check (max 3 of {} total):",
                        connections_to_check.len()
                    );
                    for (i, conn_to_log) in connections_to_check.iter().take(3).enumerate() {
                        log::debug!(
                            "  Connections_to_check[{}]: PID: {:?}, Name: {:?}",
                            i,
                            conn_to_log.pid,
                            conn_to_log.process_name
                        );
                    }
                } else {
                    log::debug!("Process thread: connections_to_check is empty.");
                }

                for conn in connections_to_check {
                    // connections_to_check is a Vec<Connection>
                    let mut final_process_candidate: Option<Process> = None;

                    // Step 1: Use info from 'conn' if PID and non-empty name are present.
                    if let (Some(c_pid), Some(c_name)) = (conn.pid, &conn.process_name) {
                        if !c_name.is_empty() {
                            final_process_candidate = Some(Process {
                                pid: c_pid,
                                name: c_name.clone(),
                            });
                        }
                    }

                    // Step 2: Try to get info from platform-specific lookup.
                    if let Some(platform_p) =
                        monitor_guard.get_platform_process_for_connection(&conn)
                    {
                        if !platform_p.name.is_empty() {
                            // Platform lookup provided a non-empty name; this is preferred.
                            // It will overwrite final_process_candidate if it was set in Step 1,
                            // or set it if it was None.
                            final_process_candidate = Some(platform_p);
                        } else {
                            // Platform lookup provided a PID but an empty name.
                            // We should only use this if final_process_candidate is currently None
                            // (meaning 'conn' didn't have a valid PID and non-empty name),
                            // or if final_process_candidate is for the same PID but also has an empty name.
                            if let Some(ref existing_candidate) = final_process_candidate {
                                if existing_candidate.pid == platform_p.pid {
                                    // Already have a candidate for this PID.
                                    // If existing_candidate.name is non-empty (from Step 1), we keep it.
                                    // If existing_candidate.name is empty (should not happen if Step 1 set it),
                                    // then platform_p (also empty name) is fine.
                                    // So, only update if existing_candidate.name is empty.
                                    if existing_candidate.name.is_empty() {
                                        final_process_candidate = Some(platform_p);
                                    }
                                } else {
                                    // Existing candidate is for a different PID.
                                    // This scenario is tricky: platform lookup (empty name) for P_PID,
                                    // conn had (non-empty name) for C_PID.
                                    // For now, we don't add platform_p if it conflicts PID-wise with a named candidate.
                                    // If final_process_candidate was None, this branch isn't hit.
                                }
                            } else {
                                // No candidate from Step 1, so use platform's result (PID with empty name).
                                final_process_candidate = Some(platform_p);
                            }
                        }
                    }

                    // If we have a candidate, add/update it in our cycle's collection
                    if let Some(p_info) = final_process_candidate {
                        // If the candidate's name is empty, only insert it if the map
                        // doesn't already contain a non-empty name for this PID.
                        if p_info.name.is_empty() {
                            if let Some(existing_entry) =
                                collected_processes_this_cycle.get(&p_info.pid)
                            {
                                if !existing_entry.name.is_empty() {
                                    continue; // Don't overwrite a good name with an empty one.
                                }
                            }
                        }
                        // Insert the candidate. If it has a non-empty name, it might overwrite an
                        // existing empty-named entry. If it has an empty name, it will only be
                        // inserted if no entry exists or the existing one is also empty-named.
                        collected_processes_this_cycle.insert(p_info.pid, p_info);
                    }
                }
                drop(monitor_guard); // Release monitor lock

                if !collected_processes_this_cycle.is_empty() {
                    log::debug!("Process thread: collected_processes_this_cycle (before filter, {} entries, showing max 5):", collected_processes_this_cycle.len());
                    for (i, (pid, process)) in
                        collected_processes_this_cycle.iter().take(5).enumerate()
                    {
                        log::debug!("  Collected[{}]: PID: {}, Name: '{}'", i, pid, process.name);
                    }
                } else {
                    log::debug!("Process thread: collected_processes_this_cycle is empty.");
                }

                // Filter out processes with empty names before updating shared state
                let final_processes_to_update: HashMap<u32, Process> =
                    collected_processes_this_cycle
                        .into_iter()
                        .filter(|(_, process)| !process.name.is_empty())
                        .collect();

                log::debug!(
                    "Process thread: final_processes_to_update (after filter, count: {}):",
                    final_processes_to_update.len()
                );
                if !final_processes_to_update.is_empty() {
                    log::debug!("Process thread: First few final_processes_to_update (max 3):");
                    for (i, (pid, process)) in final_processes_to_update.iter().take(3).enumerate()
                    {
                        log::debug!("  Final[{}]: PID: {}, Name: '{}'", i, pid, process.name);
                    }
                }

                if !final_processes_to_update.is_empty() {
                    log::debug!("PROCESS_THREAD: Attempting to lock processes_update_shared for writing ({} updates).", final_processes_to_update.len());
                    let mut processes_shared_guard = match processes_update_shared.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            log::error!("PROCESS_THREAD: Failed to lock processes_update_shared for writing (poisoned): {:?}", poisoned);
                            return Err(anyhow::anyhow!("PROCESS_THREAD: Failed to lock processes_update_shared for writing (poisoned)"));
                        }
                    };
                    log::debug!(
                        "PROCESS_THREAD: Locked processes_update_shared successfully for writing."
                    );
                    for (pid, process) in final_processes_to_update.iter() {
                        processes_shared_guard.insert(*pid, process.clone());
                    }
                    log::info!("PROCESS_THREAD: Committed {} processes to shared map. Total in shared map now: {}.",
                                final_processes_to_update.len(), processes_shared_guard.len());
                    drop(processes_shared_guard);
                    log::debug!(
                        "PROCESS_THREAD: processes_update_shared lock released after writing."
                    );
                } else {
                    let processes_shared_guard = match processes_update_shared.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            log::error!("PROCESS_THREAD: Failed to lock processes_update_shared for reading count (poisoned): {:?}", poisoned);
                            // Don't terminate the thread for a read failure if just logging count
                            let _dummy: Vec<Process> = Vec::new(); // Specify type for dummy Vec
                                                                   // This path means we can't log the current count.
                            log::warn!("PROCESS_THREAD: Could not read current count from poisoned processes_update_shared.");
                            // Continue the loop
                            continue;
                        }
                    };
                    log::debug!("PROCESS_THREAD: No new/updated processes with non-empty names to commit. Total in shared map: {}.",
                                processes_shared_guard.len());
                    drop(processes_shared_guard);
                }
                log::info!("PROCESS_THREAD: End of loop iteration.");
            }
            // Ok(()) // This line is effectively unreachable due to infinite loop, but kept for type consistency if loop could break.
        });

        self.network_monitor = Some(monitor_arc);
        log::info!("App::start_capture - Network capture and process info threads started");
        Ok(())
    }

    /// Handle key event
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        match self.mode {
            ViewMode::Overview => self.handle_overview_keys(key),
            ViewMode::ConnectionDetails => self.handle_details_keys(key),
            ViewMode::Help => self.handle_help_keys(key),
        }
    }

    /// Handle keys in overview mode
    fn handle_overview_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some(Action::Quit)
            }
            KeyCode::Char('r') => Some(Action::Refresh),
            KeyCode::Down => {
                if !self.connections.is_empty() {
                    self.selected_connection = Some(
                        self.connections
                            [(self.selected_connection_idx + 1) % self.connections.len()]
                        .clone(),
                    );
                    self.selected_connection_idx =
                        (self.selected_connection_idx + 1) % self.connections.len();
                }
                None
            }
            KeyCode::Up => {
                if !self.connections.is_empty() {
                    self.selected_connection = Some(
                        self.connections[self
                            .selected_connection_idx
                            .checked_sub(1)
                            .unwrap_or(self.connections.len() - 1)]
                        .clone(),
                    );
                    self.selected_connection_idx = self
                        .selected_connection_idx
                        .checked_sub(1)
                        .unwrap_or(self.connections.len() - 1);
                }
                None
            }
            KeyCode::Enter => {
                if !self.connections.is_empty() {
                    self.mode = ViewMode::ConnectionDetails;
                }
                None
            }
            KeyCode::Char('h') => {
                self.mode = ViewMode::Help;
                None
            }
            KeyCode::Char('l') => {
                self.show_locations = !self.show_locations;
                None
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl + d
                self.test_method(); // Call the new test method
                self.log_all_connections(); // Ensuring no hidden characters in this call
                None
            }
            KeyCode::Char('d') => {
                self.show_hostnames = !self.show_hostnames;
                // Clear DNS cache when toggling off to ensure fresh lookups when toggled on again
                if !self.show_hostnames {
                    self.dns_cache.clear();
                }
                None
            }
            // This block will be moved up
            _ => None,
        }
    }

    /// Handle keys in connection details mode
    fn handle_details_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = ViewMode::Overview;
                None
            }
            KeyCode::Up | KeyCode::Down => {
                self.detail_focus = match self.detail_focus {
                    DetailFocusField::LocalIp => DetailFocusField::RemoteIp,
                    DetailFocusField::RemoteIp => DetailFocusField::LocalIp,
                };
                None
            }
            KeyCode::Char('c') => {
                if !self.connections.is_empty()
                    && self.selected_connection_idx < self.connections.len()
                {
                    let conn = &self.connections[self.selected_connection_idx];
                    let ip_to_copy = match self.detail_focus {
                        DetailFocusField::LocalIp => conn.local_addr.ip().to_string(),
                        DetailFocusField::RemoteIp => conn.remote_addr.ip().to_string(),
                    };

                    match Clipboard::new() {
                        Ok(mut clipboard) => {
                            if let Err(e) = clipboard.set_text(ip_to_copy.clone()) {
                                error!(
                                    "Failed to copy IP to clipboard: {} for IP: {}",
                                    e, ip_to_copy
                                );
                            } else {
                                // Optionally: Add a status message to App to show "Copied!"
                                // For now, we just log errors or success.
                                log::info!("Copied to clipboard: {}", ip_to_copy);
                            }
                        }
                        Err(e) => {
                            error!("Failed to initialize clipboard: {}", e);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Handle keys in help mode
    fn handle_help_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('h') => {
                self.mode = ViewMode::Overview;
                None
            }
            _ => None,
        }
    }

    /// Update application state on tick
    pub fn on_tick(&mut self) -> Result<()> {
        let now = Instant::now(); // Get current time once for this tick

        // Store currently selected connection (if any)
        let selected_conn_key = self
            .selected_connection
            .as_ref()
            .map(|sc| self.get_connection_key(sc));

        // Update connections from shared data updated by the background thread
        if let Some(shared_data_arc) = &self.connections_data_shared {
            let mut new_connections_list = shared_data_arc.lock().unwrap().clone();

            // Calculate average rates for each connection using its history
            for conn_mut in &mut new_connections_list {
                Self::calculate_and_update_average_rate(conn_mut, now, RATE_CALCULATION_WINDOW);
            }

            // Extract keys for sorting from the (now rate-updated) new_connections_list
            let mut keys_to_process = Vec::new();
            for conn in &new_connections_list {
                let key = self.get_connection_key(conn);
                keys_to_process.push(key);
            }

            // Update connection order
            for key in keys_to_process {
                if !self.connection_order.contains_key(&key) {
                    self.connection_order.insert(key, self.next_order_index);
                    self.next_order_index += 1;
                }
            }

            // Sort connections: non-loopback first, then loopback, then by assigned order
            new_connections_list.sort_by(|a, b| {
                // Sort new_connections_list
                let is_a_loopback =
                    a.local_addr.ip().is_loopback() || a.remote_addr.ip().is_loopback();
                let is_b_loopback =
                    b.local_addr.ip().is_loopback() || b.remote_addr.ip().is_loopback();

                is_a_loopback
                    .cmp(&is_b_loopback) // false (non-loopback) < true (loopback)
                    .then_with(|| {
                        let key_a = self.get_connection_key(a);
                        let key_b = self.get_connection_key(b);
                        let order_a = self.connection_order.get(&key_a).unwrap_or(&usize::MAX);
                        let order_b = self.connection_order.get(&key_b).unwrap_or(&usize::MAX);
                        order_a.cmp(order_b)
                    })
            });

            // Update connections with the sorted list (which now also has correct current rates)
            self.connections = new_connections_list; // self.connections is now updated

            // The block below that previously calculated rates is now removed,
            // as rates are calculated on new_connections_list before this assignment.

            // Restore selected connection position if possible
            if let Some(key) = selected_conn_key {
                if let Some(idx) = self.find_connection_index_by_key(&key) {
                    self.selected_connection_idx = idx;
                    self.selected_connection = Some(self.connections[idx].clone());
                } else if !self.connections.is_empty() {
                    // If previously selected connection is gone, select first one
                    self.selected_connection_idx = 0;
                    self.selected_connection = Some(self.connections[0].clone());
                } else {
                    // If no connections left, clear selection
                    self.selected_connection_idx = 0;
                    self.selected_connection = None;
                }
            } else if !self.connections.is_empty() && self.selected_connection.is_none() {
                // If no previous selection but we have connections, select the first one
                self.selected_connection_idx = 0;
                self.selected_connection = Some(self.connections[0].clone());
            }
        } else {
            // connections_data_shared is None, likely before start_capture fully initializes it.
            // We can still try to update rates for the existing self.connections using their history.
            for conn_mut in &mut self.connections {
                Self::calculate_and_update_average_rate(conn_mut, now, RATE_CALCULATION_WINDOW);
            }
        }

        // If process info was updated, ensure the main connections list reflects this.
        // This part is tricky because self.connections was already updated from shared_data.
        // The iteration above directly mutates self.connections.

        // Update self.processes cache from processes_data_shared (from background thread)
        if let Some(shared_procs_arc) = &self.processes_data_shared {
            match shared_procs_arc.lock() {
                Ok(shared_procs_guard) => {
                    if self.processes.len() != shared_procs_guard.len()
                        || !shared_procs_guard.is_empty()
                    {
                        log::debug!("App::on_tick - Updating self.processes from shared_procs_arc. Old count: {}, New count from shared: {}", self.processes.len(), shared_procs_guard.len());
                    }
                    self.processes = shared_procs_guard.clone(); // Update local cache from background thread's findings
                }
                Err(poisoned) => {
                    log::error!(
                        "App::on_tick - Failed to lock processes_data_shared (poisoned): {:?}",
                        poisoned
                    );
                }
            }
        } else {
            log::warn!("App::on_tick - processes_data_shared is None, cannot update self.processes from background thread.");
        }

        // Directly populate self.processes from self.connections if PIDs and names are already known.
        // This ensures that information gathered by NetworkMonitor during its scans contributes
        // to the process count, even if the background process thread is delayed or encounters issues.
        let mut processes_updated_directly_from_connections = 0;
        for conn in &self.connections {
            if let (Some(pid), Some(name)) = (conn.pid, &conn.process_name) {
                if !name.is_empty() {
                    // Insert or update in self.processes.
                    // If an entry for this PID already exists, this will update its name if different.
                    // If the existing entry had an empty name, it will be updated.
                    // If the existing entry had a non-empty name, it will be updated if `name` is different.
                    let process_entry = self.processes.entry(pid).or_insert_with(|| Process {
                        pid,
                        name: name.clone(),
                    });

                    if process_entry.name != *name {
                        // Update if name is different or was empty
                        process_entry.name = name.clone();
                        processes_updated_directly_from_connections += 1;
                    } else if processes_updated_directly_from_connections == 0
                        && !self.processes.contains_key(&pid)
                    {
                        // This case handles if the entry was just inserted by or_insert_with
                        // and it's the first direct update in this tick.
                        // However, or_insert_with already handles insertion.
                        // The main point is to count if an effective update/insertion happened.
                        // A simpler way to count is if the map size changes or an existing value changes.
                        // For simplicity, we'll count if we performed an assignment to entry.name.
                        // The counter is mainly for logging.
                    }
                }
            }
        }

        if processes_updated_directly_from_connections > 0 {
            log::debug!("App::on_tick - Directly updated/inserted {} processes into self.processes from self.connections. New total count: {}", processes_updated_directly_from_connections, self.processes.len());
        }

        if !self.processes.is_empty() {
            log::debug!(
                "App::on_tick - self.processes is now non-empty. Count: {}",
                self.processes.len()
            );
        } else if self.processes.is_empty() && !self.connections.is_empty() {
            // Only log if connections exist but processes map is still empty after all updates.
            log::debug!("App::on_tick - self.processes is STILL empty despite connections existing and direct update attempt.");
        }

        // Enrich self.connections with process info from the (now potentially more complete) self.processes cache
        for conn in &mut self.connections {
            if let Some(pid) = conn.pid {
                if let Some(cached_process_info) = self.processes.get(&pid) {
                    // Case 1: Cache has process info for this PID.
                    if !cached_process_info.name.is_empty() {
                        // Cache has a non-empty name. This is authoritative.
                        // Update conn.process_name if it's currently None or different.
                        if conn.process_name.as_ref() != Some(&cached_process_info.name) {
                            conn.process_name = Some(cached_process_info.name.clone());
                        }
                    } else {
                        // Cache has PID but with an empty name.
                        // Normalize conn.process_name to None if it's currently Some("").
                        // Otherwise, leave it (it might be None or a valid Some("real_name") from another source).
                        if conn
                            .process_name
                            .as_ref()
                            .map_or(false, |name| name.is_empty())
                        {
                            conn.process_name = None;
                        }
                    }
                } else {
                    // Case 2: PID not found in cache.
                    // Normalize conn.process_name to None if it's currently Some("").
                    // Otherwise, leave it (it might be None or a valid Some("real_name") from another source).
                    if conn
                        .process_name
                        .as_ref()
                        .map_or(false, |name| name.is_empty())
                    {
                        conn.process_name = None;
                    }
                }
            } else {
                // Case 3: Connection has no PID. Ensure process_name is None.
                conn.process_name = None;
            }
        }

        Ok(())
    }

    /// Refresh application data
    pub fn refresh(&mut self) -> Result<()> {
        // Store currently selected connection (if any)
        let selected = self.selected_connection.clone();

        if let Some(monitor_arc) = &self.network_monitor {
            let mut monitor = monitor_arc.lock().unwrap(); // Lock the mutex
            let mut new_connections = monitor.get_connections()?;
            drop(monitor); // Release the mutex lock before self-mutation

            // Extract keys for sorting
            let mut keys_to_process = Vec::new();
            for conn in &new_connections {
                let key = self.get_connection_key(conn);
                keys_to_process.push(key);
            }

            // Update connection order
            for key in keys_to_process {
                if !self.connection_order.contains_key(&key) {
                    self.connection_order.insert(key, self.next_order_index);
                    self.next_order_index += 1;
                }
            }

            // Sort connections: non-loopback first, then loopback, then by assigned order
            new_connections.sort_by(|a, b| {
                let is_a_loopback =
                    a.local_addr.ip().is_loopback() || a.remote_addr.ip().is_loopback();
                let is_b_loopback =
                    b.local_addr.ip().is_loopback() || b.remote_addr.ip().is_loopback();

                is_a_loopback
                    .cmp(&is_b_loopback) // false (non-loopback) < true (loopback)
                    .then_with(|| {
                        let key_a = self.get_connection_key(a);
                        let key_b = self.get_connection_key(b);
                        let order_a = self.connection_order.get(&key_a).unwrap_or(&usize::MAX);
                        let order_b = self.connection_order.get(&key_b).unwrap_or(&usize::MAX);
                        order_a.cmp(order_b)
                    })
            });

            // Update connections with the sorted list
            self.connections = new_connections;

            // Restore selected connection position if possible
            if let Some(ref conn) = selected {
                let selected_key = self.get_connection_key(conn);
                if let Some(idx) = self.find_connection_index_by_key(&selected_key) {
                    self.selected_connection_idx = idx;
                    self.selected_connection = Some(self.connections[idx].clone());
                } else if !self.connections.is_empty() {
                    // If previously selected connection is gone, select first one
                    self.selected_connection_idx = 0;
                    self.selected_connection = Some(self.connections[0].clone());
                } else {
                    // If no connections left, clear selection
                    self.selected_connection_idx = 0;
                    self.selected_connection = None;
                }
            }
        }

        Ok(())
    }

    /// Generate a unique key for a connection
    fn get_connection_key(&self, conn: &Connection) -> String {
        format!(
            "{:?}-{}-{}-{:?}",
            conn.protocol, conn.local_addr, conn.remote_addr, conn.state
        )
    }

    /// Find the index of a connection by its key
    fn find_connection_index_by_key(&self, target_key: &str) -> Option<usize> {
        for (i, conn) in self.connections.iter().enumerate() {
            if self.get_connection_key(conn) == target_key {
                return Some(i);
            }
        }
        None
    }

    /// Format a socket address with hostname if enabled (mutates self to update DNS cache)
    pub fn format_socket_addr(&mut self, addr: std::net::SocketAddr) -> String {
        if !self.show_hostnames {
            return addr.to_string();
        }

        let ip = addr.ip();

        // Check cache first
        if let Some(cached_name) = self.dns_cache.get(&ip) {
            return format!("{}:{}", cached_name, addr.port());
        }

        // Determine hostname or IP string
        let name_to_cache = if ip.is_loopback() {
            "localhost".to_string()
        } else if ip.is_unspecified() {
            "*".to_string()
        } else {
            let is_likely_global = match ip {
                IpAddr::V4(ipv4) => !(ipv4.is_private()
                    || ipv4.is_loopback()
                    || ipv4.is_link_local()
                    || ipv4.is_broadcast()
                    // Check for documentation ranges explicitly for IPv4
                    || ipv4.octets()[0] == 192 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 2 // TEST-NET-1
                    || ipv4.octets()[0] == 198 && ipv4.octets()[1] == 51 && ipv4.octets()[2] == 100 // TEST-NET-2
                    || ipv4.octets()[0] == 203 && ipv4.octets()[1] == 0 && ipv4.octets()[2] == 113 // TEST-NET-3
                    || ipv4.is_multicast()
                    || ipv4.is_unspecified()),
                IpAddr::V6(ipv6) => !(ipv6.is_loopback()
                    // For IPv6, is_documentation() is stable.
                    // is_private() is not a concept for IPv6 in the same way, Unique Local Addresses (ULA) are fc00::/7
                    // but is_global equivalent is often !is_loopback && !is_multicast && !is_link_local && !is_unique_local etc.
                    // We'll rely on not being loopback, multicast, link-local, or documentation.
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80 // Link-local fe80::/10
                    || (ipv6.segments()[0] == 0x2001 && ipv6.segments()[1] == 0x0db8) // Documentation 2001:db8::/32
                    || ipv6.is_multicast()
                    || ipv6.is_unspecified()),
            };

            if is_likely_global {
                // Attempt lookup for likely global IPs
                debug!("Attempting reverse DNS lookup for {}", ip);
            match dns_lookup::lookup_addr(&ip) {
                Ok(hostname) => { // dns_lookup v2.0.4 returns String, not Vec<String>
                    debug!("Resolved {} to {}", ip, &hostname);
                    hostname // It's already a String
                }
                Err(e) => {
                    debug!("Reverse DNS lookup failed for {}: {}", ip, e);
                    ip.to_string() // Lookup failed
                }
            }
        } else { // For non-global IPs (private, link-local, etc.), use the IP string
            ip.to_string()
        } // Closes the `if is_likely_global { ... } else { ... }` expression
    } // Closes the `else { ... }` block that started on line 485
    ; // Terminates the `let name_to_cache = ...;` statement

        // Cache the result (either hostname or IP string)
        self.dns_cache.insert(ip, name_to_cache.clone());
        format!("{}:{}", name_to_cache, addr.port())
    }

    fn test_method(&mut self) {
        // New diagnostic method
        log::info!("<<<<<< App::test_method CALLED >>>>>>");
    }

    /// Calculates and updates the average send/receive rate for a connection based on its history.
    /// Also prunes the history.
    fn calculate_and_update_average_rate(
        conn: &mut Connection,
        current_time: Instant,
        window: Duration,
    ) {
        if conn.rate_history.len() < 2 {
            conn.current_incoming_rate_bps = 0.0;
            conn.current_outgoing_rate_bps = 0.0;
            return;
        }

        // Sort history by timestamp just in case, though it should be appended in order.
        // conn.rate_history.sort_by_key(|k| k.0); // Usually not needed if NetworkMonitor appends correctly

        let latest_entry_data = match conn.rate_history.last().cloned() {
            // Clone the entry data
            Some(entry_data) => entry_data,
            None => {
                // Should be caught by len < 2 check, but defensive
                conn.current_incoming_rate_bps = 0.0;
                conn.current_outgoing_rate_bps = 0.0;
                return;
            }
        };
        let latest_time = latest_entry_data.0;
        let latest_bytes_sent = latest_entry_data.1;
        let latest_bytes_received = latest_entry_data.2;

        // Find the "start_sample_for_rate": the latest sample that is 'window' duration older than 'latest_time'.
        // If no such sample, use the oldest sample in history.
        let target_start_time = latest_time.checked_sub(window);
        
        let start_sample_for_rate = conn.rate_history.iter()
            .rev() // Iterate backwards from the second to last element
            .skip(1) 
            .find(|(t, _, _)| target_start_time.map_or(false, |tgt_st| *t <= tgt_st))
            .unwrap_or_else(|| conn.rate_history.first().unwrap_or(&latest_entry_data)); // Fallback to oldest or latest if only one

        let (rate_in, rate_out) = if latest_time > start_sample_for_rate.0 { // Ensure time has passed
            let time_delta = latest_time.duration_since(start_sample_for_rate.0);
            let time_delta_secs = time_delta.as_secs_f64();

            if time_delta_secs > 0.001 { // Avoid division by zero or tiny intervals
                let bytes_sent_delta = latest_bytes_sent.saturating_sub(start_sample_for_rate.1);
                let bytes_received_delta = latest_bytes_received.saturating_sub(start_sample_for_rate.2);

                let out_bytes_per_sec = bytes_sent_delta as f64 / time_delta_secs;
                let in_bytes_per_sec = bytes_received_delta as f64 / time_delta_secs;
                (in_bytes_per_sec, out_bytes_per_sec)
            } else {
                (0.0, 0.0) // Time delta too small
            }
        } else {
            (0.0, 0.0) // No time difference or start_sample is not older
        };

        conn.current_incoming_rate_bps = rate_in;
        conn.current_outgoing_rate_bps = rate_out;

        // Prune history: keep entries younger than `current_time - (window + buffer)`
        let prune_older_than = current_time.checked_sub(window + RATE_HISTORY_PRUNE_EXTENSION);
        if let Some(prune_time) = prune_older_than {
            conn.rate_history.retain(|(t, _, _)| *t >= prune_time);
        } else {
            // If window + buffer is too large, effectively don't prune based on current_time
            // Or, if history is very short, this might not prune much.
            // A simpler prune: ensure we don't keep excessively old data if current_time is far ahead of latest_time
            if let Some(latest_hist_time) = conn.rate_history.last().map(|e| e.0) {
                let absolute_prune_time =
                    latest_hist_time.checked_sub(window + RATE_HISTORY_PRUNE_EXTENSION);
                if let Some(apt) = absolute_prune_time {
                    conn.rate_history.retain(|(t, _, _)| *t >= apt);
                }
            }
        }
        // Ensure at least one entry is kept if history is not empty, to allow future rate calculations.
        if conn.rate_history.is_empty()
            && latest_entry_data.0
                >= current_time
                    .checked_sub(window + RATE_HISTORY_PRUNE_EXTENSION)
                    .unwrap_or(latest_entry_data.0)
        {
            conn.rate_history.push(latest_entry_data); // Push the cloned data
        }
    }
}
