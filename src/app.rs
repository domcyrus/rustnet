use anyhow::Result;
use arboard::Clipboard; // For clipboard access
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use dns_lookup; // For reverse DNS lookups
use log::{debug, error}; // For logging
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;

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
    ProcessDetails,
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
}

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
            detail_focus: DetailFocusField::LocalIp, // Default focus to Local IP
        };
        log::info!("App::new - Application initialized successfully");
        Ok(app)
    }

    /// Start network capture
    pub fn start_capture(&mut self) -> Result<()> {
        log::info!("App::start_capture - Starting network capture setup");
        // Create network monitor
        let interface = self.config.interface.clone();
        let filter_localhost = self.config.filter_localhost;
        log::info!("App::start_capture - Calling NetworkMonitor::new");
        let mut monitor = NetworkMonitor::new(interface, filter_localhost)?;
        log::info!("App::start_capture - NetworkMonitor::new returned");

        // Disable process information collection by default for better performance
        monitor.set_collect_process_info(false);

        // Get initial connections without process info
        log::info!("App::start_capture - Calling initial monitor.get_connections()");
        self.connections = monitor.get_connections()?;
        log::info!("App::start_capture - Initial monitor.get_connections() returned {} connections", self.connections.len());

        // Start monitoring in background thread
        let monitor = Arc::new(Mutex::new(monitor));
        let monitor_clone = Arc::clone(&monitor);
        let connections_update = Arc::new(Mutex::new(Vec::new()));
        let connections_update_clone = Arc::clone(&connections_update);
        self.connections_data_shared = Some(connections_update_clone.clone()); // Store Arc for on_tick

        thread::spawn(move || -> Result<()> {
            loop {
                let mut monitor = monitor_clone.lock().unwrap();
                let new_connections = monitor.get_connections()?;

                // Update shared connections
                let mut connections = connections_update_clone.lock().unwrap();
                *connections = new_connections;

                // Sleep to avoid high CPU usage
                drop(connections);
                drop(monitor);
                thread::sleep(std::time::Duration::from_millis(250)); // Update data more frequently
            }
        });

        self.network_monitor = Some(monitor);
        log::info!("App::start_capture - Network capture setup complete");
        Ok(())
    }

    /// Handle key event
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        match self.mode {
            ViewMode::Overview => self.handle_overview_keys(key),
            ViewMode::ConnectionDetails => self.handle_details_keys(key),
            ViewMode::ProcessDetails => self.handle_process_keys(key),
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
            KeyCode::Char('d') => {
                self.show_hostnames = !self.show_hostnames;
                // Clear DNS cache when toggling off to ensure fresh lookups when toggled on again
                if !self.show_hostnames {
                    self.dns_cache.clear();
                }
                None
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => { // Ctrl + d
                self.dump_connections_to_log();
                None
            }
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
            KeyCode::Char('p') => {
                self.mode = ViewMode::ProcessDetails;
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
                if !self.connections.is_empty() && self.selected_connection_idx < self.connections.len() {
                    let conn = &self.connections[self.selected_connection_idx];
                    let ip_to_copy = match self.detail_focus {
                        DetailFocusField::LocalIp => conn.local_addr.ip().to_string(),
                        DetailFocusField::RemoteIp => conn.remote_addr.ip().to_string(),
                    };

                    match Clipboard::new() {
                        Ok(mut clipboard) => {
                            if let Err(e) = clipboard.set_text(ip_to_copy.clone()) {
                                error!("Failed to copy IP to clipboard: {} for IP: {}", e, ip_to_copy);
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

    /// Handle keys in process details mode
    fn handle_process_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = ViewMode::ConnectionDetails;
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
        // Store currently selected connection (if any)
        let selected = self.selected_connection.clone();

        // Update connections from shared data updated by the background thread
        if let Some(shared_data_arc) = &self.connections_data_shared {
            let mut new_connections = shared_data_arc.lock().unwrap().clone();

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

            // Sort connections by their assigned order
            new_connections.sort_by(|a, b| {
                let key_a = self.get_connection_key(a);
                let key_b = self.get_connection_key(b);

                let order_a = self.connection_order.get(&key_a).unwrap_or(&usize::MAX);
                let order_b = self.connection_order.get(&key_b).unwrap_or(&usize::MAX);

                order_a.cmp(order_b)
            });

            // Update connections with the sorted list
            self.connections = new_connections;

            // Restore selected connection position if possible
            if let Some(ref conn) = selected {
                if let Some(idx) = self.find_connection_index(conn) {
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
            // self.connections will not be updated this tick.
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

            // Sort connections by their assigned order
            new_connections.sort_by(|a, b| {
                let key_a = self.get_connection_key(a);
                let key_b = self.get_connection_key(b);

                let order_a = self.connection_order.get(&key_a).unwrap_or(&usize::MAX);
                let order_b = self.connection_order.get(&key_b).unwrap_or(&usize::MAX);

                order_a.cmp(order_b)
            });

            // Update connections with the sorted list
            self.connections = new_connections;

            // Restore selected connection position if possible
            if let Some(ref conn) = selected {
                if let Some(idx) = self.find_connection_index(conn) {
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

    /// Get process info for selected connection
    pub fn get_process_for_selected_connection(&mut self) -> Option<Process> {
        if self.connections.is_empty() || self.selected_connection_idx >= self.connections.len() {
            return None;
        }

        // Get the selected connection
        let connection = &mut self.connections[self.selected_connection_idx].clone();

        // Check if we already have process info in our local cache
        if let Some(pid) = connection.pid {
            if let Some(process) = self.processes.get(&pid) {
                return Some(process.clone());
            }
        }

        // Otherwise, look it up on demand
        if let Some(monitor_arc) = &self.network_monitor {
            let monitor = monitor_arc.lock().unwrap();

            // Look up the process info for this specific connection
            if let Some(process) = monitor.get_platform_process_for_connection(connection) {
                // Update our local cache
                let pid = process.pid;
                self.processes.insert(pid, process.clone());

                // Update the connection in our list
                if self.selected_connection_idx < self.connections.len() {
                    self.connections[self.selected_connection_idx].pid = Some(pid);
                    self.connections[self.selected_connection_idx].process_name =
                        Some(self.processes[&pid].name.clone());
                }

                return Some(process);
            }
        }

        None
    }

    /// Generate a unique key for a connection
    fn get_connection_key(&self, conn: &Connection) -> String {
        format!(
            "{:?}-{}-{}-{:?}",
            conn.protocol, conn.local_addr, conn.remote_addr, conn.state
        )
    }

    /// Find the index of a connection that matches the selected connection
    fn find_connection_index(&self, selected: &Connection) -> Option<usize> {
        let selected_key = self.get_connection_key(selected);

        for (i, conn) in self.connections.iter().enumerate() {
            let key = self.get_connection_key(conn);
            if key == selected_key {
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
}
