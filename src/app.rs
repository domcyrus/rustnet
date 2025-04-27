use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashMap;
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

/// Application state
pub struct App {
    /// Application configuration
    pub config: Config,
    /// Internationalization
    pub i18n: I18n,
    /// Current view mode
    pub mode: ViewMode,
    /// Whether the application should quit
    pub should_quit: bool,
    /// Network monitor instance
    network_monitor: Option<Arc<Mutex<NetworkMonitor>>>,
    /// Active connections
    pub connections: Vec<Connection>,
    /// Process map (pid to process)
    pub processes: HashMap<u32, Process>,
    /// Currently selected connection index
    pub selected_connection_idx: usize,
    /// Currently selected process index
    pub selected_process_idx: usize,
    /// Show IP locations (requires MaxMind DB)
    pub show_locations: bool,
}

impl App {
    /// Create a new application instance
    pub fn new(config: Config, i18n: I18n) -> Result<Self> {
        Ok(Self {
            config,
            i18n,
            mode: ViewMode::Overview,
            should_quit: false,
            network_monitor: None,
            connections: Vec::new(),
            processes: HashMap::new(),
            selected_connection_idx: 0,
            selected_process_idx: 0,
            show_locations: true,
        })
    }

    /// Start network capture
    pub fn start_capture(&mut self) -> Result<()> {
        // Create network monitor
        let interface = self.config.interface.clone();
        let mut monitor = NetworkMonitor::new(interface)?;

        // Get initial connections
        self.connections = monitor.get_connections()?;

        // Get processes for connections
        for conn in &self.connections {
            // Use the platform-specific method
            if let Some(process) = monitor.get_platform_process_for_connection(conn) {
                self.processes.insert(process.pid, process);
            }
        }

        // Start monitoring in background thread
        let monitor = Arc::new(Mutex::new(monitor));
        let monitor_clone = Arc::clone(&monitor);
        let connections_update = Arc::new(Mutex::new(Vec::new()));
        let connections_update_clone = Arc::clone(&connections_update);

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
                thread::sleep(std::time::Duration::from_millis(1000));
            }
        });

        self.network_monitor = Some(monitor);

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
            KeyCode::Down | KeyCode::Char('j') => {
                if !self.connections.is_empty() {
                    self.selected_connection_idx =
                        (self.selected_connection_idx + 1) % self.connections.len();
                }
                None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if !self.connections.is_empty() {
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
        // Update connections from network monitor if available
        if let Some(monitor_arc) = &self.network_monitor {
            let mut monitor = monitor_arc.lock().unwrap(); // Lock the mutex
            self.connections = monitor.get_connections()?;

            // Update processes
            for conn in &self.connections {
                // Use the platform-specific method
                if let Some(process) = monitor.get_platform_process_for_connection(conn) {
                    self.processes.insert(process.pid, process);
                }
            }
        }

        Ok(())
    }

    /// Refresh application data
    pub fn refresh(&mut self) -> Result<()> {
        if let Some(monitor_arc) = &self.network_monitor {
            let mut monitor = monitor_arc.lock().unwrap(); // Lock the mutex
            self.connections = monitor.get_connections()?;

            // Clear and update processes
            self.processes.clear();
            for conn in &self.connections {
                // Use the platform-specific method
                if let Some(process) = monitor.get_platform_process_for_connection(conn) {
                    self.processes.insert(process.pid, process);
                }
            }
        }

        Ok(())
    }
}
