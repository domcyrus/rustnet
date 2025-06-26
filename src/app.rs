use anyhow::Result;
use arboard::Clipboard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use log::error;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config::Config;
use crate::i18n::I18n;
use crate::network::{self, Connection, NetworkMonitor, Process};

/// Application actions
pub enum Action {
    Quit,
    Refresh,
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
    pub config: Config,
    pub i18n: I18n,
    pub mode: ViewMode,
    network_monitor: Arc<Mutex<NetworkMonitor>>,
    pub connections: Vec<Connection>,
    pub processes: HashMap<u32, Process>,
    pub selected_connection: Option<Connection>,
    pub selected_connection_idx: usize,
    pub show_locations: bool,
    pub show_hostnames: bool,
    connection_order: HashMap<String, usize>,
    next_order_index: usize,
    dns_cache: HashMap<IpAddr, String>,
    connections_data_shared: Arc<Mutex<Vec<Connection>>>,
    pub detail_focus: DetailFocusField,
    processes_data_shared: Arc<Mutex<HashMap<u32, Process>>>,
    pub is_loading: bool,
    pub loading_message: String,
    loading_spinner_index: usize,
}

const PROCESS_INFO_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

impl App {
    pub fn new(config: Config, i18n: I18n) -> Result<Self> {
        log::info!("App::new - Starting application initialization");
        let monitor = NetworkMonitor::new(config.interface.clone(), config.filter_localhost)?;
        let app = Self {
            config,
            i18n,
            mode: ViewMode::Overview,
            network_monitor: Arc::new(Mutex::new(monitor)),
            connections: Vec::new(),
            processes: HashMap::new(),
            selected_connection: None,
            selected_connection_idx: 0,
            show_locations: true,
            show_hostnames: false,
            connection_order: HashMap::new(),
            next_order_index: 0,
            dns_cache: HashMap::new(),
            connections_data_shared: Arc::new(Mutex::new(Vec::new())),
            processes_data_shared: Arc::new(Mutex::new(HashMap::new())),
            detail_focus: DetailFocusField::LocalIp,
            is_loading: true,
            loading_message: "Initializing network monitor...".to_string(),
            loading_spinner_index: 0,
        };
        log::info!("App::new - Application initialized successfully");
        Ok(app)
    }

    pub fn start_capture(&mut self) -> Result<()> {
        log::info!("App::start_capture - Starting network capture setup");

        // Update loading message
        self.loading_message = "Discovering network connections...".to_string();

        // --- Packet Capture Thread ---
        let (packet_tx, packet_rx) = mpsc::channel::<Vec<u8>>();
        let interface_name = self.config.interface.clone();
        thread::spawn(move || {
            log::info!("Starting packet capture thread");
            if let Err(e) = network::packet_capture_thread(interface_name, packet_tx) {
                error!("Packet capture thread failed (this is normal if not running as root): {}", e);
                log::info!("Packet capture disabled, will rely on platform connections only");
            }
        });

        // --- Connection Management Thread ---
        let monitor_clone: Arc<Mutex<NetworkMonitor>> = Arc::clone(&self.network_monitor);
        let connections_shared_clone: Arc<Mutex<Vec<Connection>>> = Arc::clone(&self.connections_data_shared);
        let tick_rate = self.config.refresh_interval;
        thread::spawn(move || {
            log::info!("Starting connection management thread");
            
            // Do immediate initial connection discovery
            log::info!("Performing initial connection discovery...");
            match monitor_clone.lock().unwrap().get_connections() {
                Ok(initial_conns) => {
                    log::info!("Initial discovery found {} connections", initial_conns.len());
                    *connections_shared_clone.lock().unwrap() = initial_conns;
                }
                Err(e) => {
                    error!("Error in initial connection discovery: {}", e);
                }
            }
            
            loop {
                // Process all pending packets from the queue (may be empty if capture failed)
                let packets: Vec<_> = packet_rx.try_iter().collect();
                if !packets.is_empty() {
                    log::debug!("Processing {} packets", packets.len());
                    for packet_data in packets {
                        monitor_clone.lock().unwrap().process_packet(&packet_data);
                    }
                }

                // Update shared connections periodically
                match monitor_clone.lock().unwrap().get_connections() {
                    Ok(conns) => {
                        log::debug!("Connection management thread: Found {} connections", conns.len());
                        *connections_shared_clone.lock().unwrap() = conns;
                    }
                    Err(e) => {
                        error!("Error getting connections in management thread: {}", e);
                    }
                }

                thread::sleep(Duration::from_millis(tick_rate));
            }
        });

        // --- Process Information Fetching Thread ---
        let monitor_clone_procs: Arc<Mutex<NetworkMonitor>> = Arc::clone(&self.network_monitor);
        let connections_shared_procs: Arc<Mutex<Vec<Connection>>> = Arc::clone(&self.connections_data_shared);
        let processes_shared_clone: Arc<Mutex<HashMap<u32, Process>>> = Arc::clone(&self.processes_data_shared);
        thread::spawn(move || -> Result<()> {
            loop {
                thread::sleep(PROCESS_INFO_UPDATE_INTERVAL);

                let connections_to_check = connections_shared_procs.lock().unwrap().clone();
                let mut collected_processes: HashMap<u32, Process> = HashMap::new();

                for conn in connections_to_check {
                    if conn.pid.is_none() {
                        if let Some(process) =
                            monitor_clone_procs.lock().unwrap().get_platform_process_for_connection(&conn)
                        {
                            if !process.name.is_empty() {
                                collected_processes.insert(process.pid, process);
                            }
                        }
                    }
                }

                if !collected_processes.is_empty() {
                    let mut processes_guard = processes_shared_clone.lock().unwrap();
                    for (pid, process) in collected_processes {
                        processes_guard.insert(pid, process);
                    }
                }
            }
        });

        log::info!("App::start_capture - All threads started");
        
        // Mark loading as complete
        self.is_loading = false;
        self.loading_message.clear();
        
        Ok(())
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        match self.mode {
            ViewMode::Overview => self.handle_overview_keys(key),
            ViewMode::ConnectionDetails => self.handle_details_keys(key),
            ViewMode::Help => self.handle_help_keys(key),
        }
    }

    fn handle_overview_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                Some(Action::Quit)
            }
            KeyCode::Char('r') => Some(Action::Refresh),
            KeyCode::Down => {
                if !self.connections.is_empty() {
                    self.selected_connection_idx = (self.selected_connection_idx + 1) % self.connections.len();
                    self.selected_connection = Some(self.connections[self.selected_connection_idx].clone());
                }
                None
            }
            KeyCode::Up => {
                if !self.connections.is_empty() {
                    self.selected_connection_idx = self.selected_connection_idx.checked_sub(1).unwrap_or(self.connections.len() - 1);
                    self.selected_connection = Some(self.connections[self.selected_connection_idx].clone());
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
                if !self.show_hostnames {
                    self.dns_cache.clear();
                }
                None
            }
            _ => None,
        }
    }

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
                if let Some(conn) = self.connections.get(self.selected_connection_idx) {
                    let ip_to_copy = match self.detail_focus {
                        DetailFocusField::LocalIp => conn.local_addr.ip().to_string(),
                        DetailFocusField::RemoteIp => conn.remote_addr.ip().to_string(),
                    };
                    if let Ok(mut clipboard) = Clipboard::new() {
                        if let Err(e) = clipboard.set_text(ip_to_copy.clone()) {
                            error!("Failed to copy IP to clipboard: {}", e);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn handle_help_keys(&mut self, key: KeyEvent) -> Option<Action> {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('h') => {
                self.mode = ViewMode::Overview;
                None
            }
            _ => None,
        }
    }

    fn get_connection_key(&self, conn: &Connection) -> String {
        format!(
            "{:?}-{}-{}-{:?}",
            conn.protocol, conn.local_addr, conn.remote_addr, conn.state
        )
    }

    fn find_connection_index_by_key(&self, target_key: &str) -> Option<usize> {
        self.connections.iter().position(|conn| self.get_connection_key(conn) == target_key)
    }

    pub fn on_tick(&mut self) -> Result<()> {
        let selected_conn_key = self.selected_connection.as_ref().map(|sc| self.get_connection_key(sc));

        let mut new_connections_list = self.connections_data_shared.lock().unwrap().clone();
        log::debug!("on_tick: Processing {} connections from shared data", new_connections_list.len());
        
        // Update loading status based on connections availability
        if self.is_loading {
            if !new_connections_list.is_empty() {
                self.is_loading = false;
                self.loading_message.clear();
            } else {
                // Update spinner animation and vary the loading message
                self.loading_spinner_index = (self.loading_spinner_index + 1) % 4;
                
                // Vary the loading message to show progress
                let elapsed = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() % 10;
                
                self.loading_message = match elapsed {
                    0..=2 => "Scanning network interfaces...".to_string(),
                    3..=5 => "Discovering active connections...".to_string(),
                    6..=8 => "Gathering process information...".to_string(),
                    _ => "Please wait, this may take 10-30 seconds...".to_string(),
                };
            }
        }

        let mut keys_to_process = Vec::new();
        for conn in &new_connections_list {
            keys_to_process.push(self.get_connection_key(conn));
        }

        for key in keys_to_process {
            self.connection_order.entry(key).or_insert_with(|| {
                let index = self.next_order_index;
                self.next_order_index += 1;
                index
            });
        }

        new_connections_list.sort_by(|a, b| {
            let is_a_loopback = a.local_addr.ip().is_loopback() || a.remote_addr.ip().is_loopback();
            let is_b_loopback = b.local_addr.ip().is_loopback() || b.remote_addr.ip().is_loopback();
            is_a_loopback.cmp(&is_b_loopback).then_with(|| {
                let key_a = self.get_connection_key(a);
                let key_b = self.get_connection_key(b);
                let order_a = self.connection_order.get(&key_a).unwrap_or(&usize::MAX);
                let order_b = self.connection_order.get(&key_b).unwrap_or(&usize::MAX);
                order_a.cmp(order_b)
            })
        });

        self.connections = new_connections_list;

        if let Some(key) = selected_conn_key {
            if let Some(idx) = self.find_connection_index_by_key(&key) {
                self.selected_connection_idx = idx;
                self.selected_connection = Some(self.connections[idx].clone());
            } else if !self.connections.is_empty() {
                self.selected_connection_idx = 0;
                self.selected_connection = Some(self.connections[0].clone());
            } else {
                self.selected_connection_idx = 0;
                self.selected_connection = None;
            }
        } else if !self.connections.is_empty() && self.selected_connection.is_none() {
            self.selected_connection_idx = 0;
            self.selected_connection = Some(self.connections[0].clone());
        }

        if let Ok(shared_procs_guard) = self.processes_data_shared.lock() {
            self.processes = shared_procs_guard.clone();
        }

        for conn in &mut self.connections {
            if let Some(pid) = conn.pid {
                if let Some(cached_process_info) = self.processes.get(&pid) {
                    if !cached_process_info.name.is_empty() {
                        conn.process_name = Some(cached_process_info.name.clone());
                    }
                }
            }
        }

        Ok(())
    }

    /// Format a socket address for display
    pub fn format_socket_addr(&mut self, addr: std::net::SocketAddr) -> String {
        if self.show_hostnames {
            // Try to resolve hostname
            if let Some(hostname) = self.dns_cache.get(&addr.ip()) {
                format!("{}:{}", hostname, addr.port())
            } else {
                // Attempt to resolve hostname if not in cache
                if let Ok(hostname) = dns_lookup::lookup_addr(&addr.ip()) {
                    if hostname != addr.ip().to_string() {
                        // Cache the result
                        self.dns_cache.insert(addr.ip(), hostname.clone());
                        return format!("{}:{}", hostname, addr.port());
                    }
                }
                // Cache the IP as fallback to avoid repeated lookups
                self.dns_cache.insert(addr.ip(), addr.ip().to_string());
                addr.to_string()
            }
        } else {
            addr.to_string()
        }
    }

    /// Refresh the application state
    pub fn refresh(&mut self) -> Result<()> {
        // Trigger a fresh connection update
        self.on_tick()
    }

    /// Get the current spinner character for loading animation
    pub fn get_spinner_char(&self) -> &str {
        const SPINNER_CHARS: &[&str] = &["⠋", "⠙", "⠹", "⠸"];
        SPINNER_CHARS[self.loading_spinner_index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::i18n::I18n;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_app() -> App {
        let config = Config::default();
        let i18n = I18n::new("en").unwrap();
        App::new(config, i18n).unwrap()
    }

    #[test]
    fn test_dns_toggle_functionality() {
        let mut app = create_test_app();
        
        // Initially DNS hostnames should be disabled
        assert!(!app.show_hostnames);
        assert!(app.dns_cache.is_empty());
        
        // Test IP address formatting without DNS
        let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let formatted = app.format_socket_addr(test_addr);
        assert_eq!(formatted, "8.8.8.8:53");
        
        // Enable DNS resolution
        app.show_hostnames = true;
        
        // Format the same address with DNS enabled
        let formatted_with_dns = app.format_socket_addr(test_addr);
        // Should either be resolved hostname or cached IP
        assert!(!formatted_with_dns.is_empty());
        assert!(formatted_with_dns.contains(":53"));
        
        // Check that cache is populated
        assert!(app.dns_cache.contains_key(&test_addr.ip()));
    }

    #[test]
    fn test_dns_cache_behavior() {
        let mut app = create_test_app();
        app.show_hostnames = true;
        
        let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        // First call should populate cache
        let first_result = app.format_socket_addr(test_addr);
        assert!(app.dns_cache.contains_key(&test_addr.ip()));
        
        // Second call should use cache
        let second_result = app.format_socket_addr(test_addr);
        assert_eq!(first_result, second_result);
        
        // Disable DNS and clear cache
        app.show_hostnames = false;
        app.dns_cache.clear();
        
        let ip_only_result = app.format_socket_addr(test_addr);
        assert_eq!(ip_only_result, "127.0.0.1:8080");
    }

    #[test]
    fn test_view_mode_switching() {
        let mut app = create_test_app();
        
        // Should start in Overview mode
        assert!(matches!(app.mode, ViewMode::Overview));
        
        // Test switching to Help
        app.mode = ViewMode::Help;
        assert!(matches!(app.mode, ViewMode::Help));
        
        // Test switching to Connection Details
        app.mode = ViewMode::ConnectionDetails;
        assert!(matches!(app.mode, ViewMode::ConnectionDetails));
    }

    #[test]
    fn test_connection_selection() {
        let mut app = create_test_app();
        
        // Initially no connections
        assert!(app.connections.is_empty());
        assert_eq!(app.selected_connection_idx, 0);
        assert!(app.selected_connection.is_none());
        
        // Add some test connections
        let conn1 = crate::network::Connection::new(
            crate::network::Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3000),
            crate::network::ConnectionState::Established,
        );
        let conn2 = crate::network::Connection::new(
            crate::network::Protocol::UDP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 3001),
            crate::network::ConnectionState::Listen,
        );
        
        app.connections = vec![conn1, conn2];
        
        // Test that we can select connections
        assert_eq!(app.connections.len(), 2);
        app.selected_connection_idx = 1;
        assert_eq!(app.selected_connection_idx, 1);
    }

    #[test]
    fn test_detail_focus_field() {
        let mut app = create_test_app();
        
        // Should start with LocalIp focused
        assert!(matches!(app.detail_focus, DetailFocusField::LocalIp));
        
        // Test switching focus
        app.detail_focus = DetailFocusField::RemoteIp;
        assert!(matches!(app.detail_focus, DetailFocusField::RemoteIp));
    }

    #[test]
    fn test_app_initialization() {
        let config = Config::default();
        let i18n = I18n::new("en").unwrap();
        let app_result = App::new(config, i18n);
        
        assert!(app_result.is_ok());
        let app = app_result.unwrap();
        
        // Check initial state
        assert!(matches!(app.mode, ViewMode::Overview));
        assert!(app.show_locations);
        assert!(!app.show_hostnames);
        assert!(app.connections.is_empty());
        assert!(app.dns_cache.is_empty());
        assert_eq!(app.selected_connection_idx, 0);
        assert!(app.is_loading); // Should start in loading state
    }

    #[test]
    fn test_loading_state_and_spinner() {
        let mut app = create_test_app();
        
        // Should start loading
        assert!(app.is_loading);
        assert!(!app.loading_message.is_empty());
        
        // Test spinner animation
        let first_char = app.get_spinner_char().to_string();
        app.loading_spinner_index = (app.loading_spinner_index + 1) % 4;
        let second_char = app.get_spinner_char().to_string();
        assert_ne!(first_char, second_char);
        
        // Test loading completion
        app.is_loading = false;
        app.loading_message.clear();
        assert!(!app.is_loading);
        assert!(app.loading_message.is_empty());
    }
}
