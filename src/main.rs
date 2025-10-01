use anyhow::Result;
use arboard::Clipboard;
use log::{LevelFilter, debug, error, info};
use ratatui::prelude::CrosstermBackend;
use simplelog::{Config as LogConfig, WriteLogger};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::time::Duration;

mod app;
mod cli;
mod filter;
mod network;
mod ui;

fn main() -> Result<()> {
    // Parse command line arguments
    let matches = cli::build_cli().get_matches();
    // Set up logging only if log-level was provided
    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level)?;
    }

    info!("Starting RustNet Monitor");

    // Build configuration from command line arguments
    let mut config = app::Config::default();

    if let Some(interface) = matches.get_one::<String>("interface") {
        config.interface = Some(interface.to_string());
        info!("Using interface: {}", interface);
    }

    if matches.get_flag("no-localhost") {
        config.filter_localhost = true;
        info!("Filtering localhost connections");
    }

    if let Some(interval) = matches.get_one::<u64>("refresh-interval") {
        config.refresh_interval = *interval;
        info!("Using refresh interval: {}ms", interval);
    }

    if matches.get_flag("no-dpi") {
        config.enable_dpi = false;
        info!("Deep packet inspection disabled");
    }

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create and start the application
    let mut app = app::App::new(config)?;
    app.start()?;
    info!("Application started");

    // Run the UI loop
    let res = run_ui_loop(&mut terminal, &app);

    // Cleanup
    app.stop();
    ui::restore_terminal(&mut terminal)?;

    // Return any error that occurred
    if let Err(err) = res {
        error!("Application error: {}", err);
        println!("Error: {}", err);
    }

    info!("RustNet Monitor shutting down");
    Ok(())
}

fn setup_logging(level: LevelFilter) -> Result<()> {
    // Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    // Create timestamped log file name
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    // Initialize the logger
    WriteLogger::init(level, LogConfig::default(), File::create(log_file_path)?)?;

    Ok(())
}

/// Sort connections based on the specified column and direction
fn sort_connections(
    connections: &mut [network::types::Connection],
    sort_column: ui::SortColumn,
    ascending: bool,
) {
    use ui::SortColumn;

    connections.sort_by(|a, b| {
        let ordering = match sort_column {
            SortColumn::CreatedAt => a.created_at.cmp(&b.created_at),

            SortColumn::BandwidthDown => {
                // Compare as f64, handle NaN cases
                a.current_incoming_rate_bps
                    .partial_cmp(&b.current_incoming_rate_bps)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::BandwidthUp => {
                a.current_outgoing_rate_bps
                    .partial_cmp(&b.current_outgoing_rate_bps)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::Process => {
                let a_process = a.process_name.as_deref().unwrap_or("");
                let b_process = b.process_name.as_deref().unwrap_or("");
                a_process.cmp(b_process)
            }

            SortColumn::LocalAddress => {
                a.local_addr.to_string().cmp(&b.local_addr.to_string())
            }

            SortColumn::RemoteAddress => {
                a.remote_addr.to_string().cmp(&b.remote_addr.to_string())
            }

            SortColumn::Application => {
                let a_app = a.dpi_info.as_ref()
                    .map(|dpi| dpi.application.to_string())
                    .unwrap_or_default();
                let b_app = b.dpi_info.as_ref()
                    .map(|dpi| dpi.application.to_string())
                    .unwrap_or_default();
                a_app.cmp(&b_app)
            }

            SortColumn::Service => {
                let a_service = a.service_name.as_deref().unwrap_or("");
                let b_service = b.service_name.as_deref().unwrap_or("");
                a_service.cmp(b_service)
            }

            SortColumn::State => {
                a.state().cmp(&b.state())
            }

            SortColumn::Protocol => {
                a.protocol.to_string().cmp(&b.protocol.to_string())
            }
        };

        if ascending {
            ordering
        } else {
            ordering.reverse()
        }
    });
}

fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    app: &app::App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut ui_state = ui::UIState::default();

    loop {
        // Get current connections and stats
        let mut connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
            app.get_connections()
        } else {
            app.get_filtered_connections(&ui_state.filter_query)
        };

        // Apply sorting (after filtering)
        sort_connections(&mut connections, ui_state.sort_column, ui_state.sort_ascending);

        let stats = app.get_stats();

        // Ensure we have a valid selection (handles connection removals)
        ui_state.ensure_valid_selection(&connections);

        // Draw the UI
        terminal.draw(|f| {
            if let Err(err) = ui::draw(f, app, &ui_state, &connections, &stats) {
                error!("UI draw error: {}", err);
            }
        })?;

        // Handle timeout for periodic updates
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        // Check if we should tick
        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }

        // Clear clipboard message after timeout
        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
        }

        // Handle input events
        if crossterm::event::poll(timeout)?
            && let crossterm::event::Event::Key(key) = crossterm::event::read()?
        {
            use crossterm::event::{KeyCode, KeyModifiers};

            if ui_state.filter_mode {
                // Handle input in filter mode
                match key.code {
                    KeyCode::Enter => {
                        // Apply filter and exit input mode (now optional)
                        debug!("Exiting filter mode. Filter: '{}'", ui_state.filter_query);
                        ui_state.exit_filter_mode();
                        debug!("Filter mode now: {}", ui_state.filter_mode);
                    }
                    KeyCode::Esc => {
                        // Clear filter and exit filter mode
                        ui_state.clear_filter();
                    }
                    KeyCode::Backspace => {
                        ui_state.filter_backspace();
                    }
                    KeyCode::Delete => {
                        // Handle delete key (remove character after cursor)
                        if ui_state.filter_cursor_position < ui_state.filter_query.len() {
                            ui_state
                                .filter_query
                                .remove(ui_state.filter_cursor_position);
                        }
                    }
                    KeyCode::Left => {
                        ui_state.filter_cursor_left();
                    }
                    KeyCode::Right => {
                        ui_state.filter_cursor_right();
                    }
                    KeyCode::Home => {
                        ui_state.filter_cursor_position = 0;
                    }
                    KeyCode::End => {
                        ui_state.filter_cursor_position = ui_state.filter_query.len();
                    }
                    // Allow navigation while in filter mode!
                    KeyCode::Up => {
                        // Navigate filtered connections while typing
                        let nav_connections = if ui_state.filter_query.is_empty() {
                            app.get_connections()
                        } else {
                            app.get_filtered_connections(&ui_state.filter_query)
                        };
                        debug!(
                            "Filter mode navigation UP: {} connections available",
                            nav_connections.len()
                        );
                        ui_state.move_selection_up(&nav_connections);
                    }
                    KeyCode::Down => {
                        // Navigate filtered connections while typing
                        let nav_connections = if ui_state.filter_query.is_empty() {
                            app.get_connections()
                        } else {
                            app.get_filtered_connections(&ui_state.filter_query)
                        };
                        debug!(
                            "Filter mode navigation DOWN: {} connections available",
                            nav_connections.len()
                        );
                        ui_state.move_selection_down(&nav_connections);
                    }
                    KeyCode::Char(c) => {
                        // Handle Ctrl+H as backspace for SecureCRT compatibility
                        if c == 'h' && key.modifiers.contains(KeyModifiers::CONTROL) {
                            ui_state.filter_backspace();
                            return Ok(());
                        }

                        // Handle navigation keys (j/k) and text input
                        match c {
                            'k' => {
                                // Vim-style up navigation while filtering
                                let nav_connections = if ui_state.filter_query.is_empty() {
                                    app.get_connections()
                                } else {
                                    app.get_filtered_connections(&ui_state.filter_query)
                                };
                                debug!(
                                    "Filter mode navigation UP (k): {} connections available",
                                    nav_connections.len()
                                );
                                ui_state.move_selection_up(&nav_connections);
                            }
                            'j' => {
                                // Vim-style down navigation while filtering
                                let nav_connections = if ui_state.filter_query.is_empty() {
                                    app.get_connections()
                                } else {
                                    app.get_filtered_connections(&ui_state.filter_query)
                                };
                                debug!(
                                    "Filter mode navigation DOWN (j): {} connections available",
                                    nav_connections.len()
                                );
                                ui_state.move_selection_down(&nav_connections);
                            }
                            _ => {
                                // Regular character input for filter
                                ui_state.filter_add_char(c);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // Handle input in normal mode
                match (key.code, key.modifiers) {
                    // Enter filter mode with '/'
                    (KeyCode::Char('/'), _) => {
                        ui_state.quit_confirmation = false;
                        debug!("Entering filter mode");
                        ui_state.enter_filter_mode();
                        debug!("Filter mode now: {}", ui_state.filter_mode);
                    }

                    // Quit with confirmation
                    (KeyCode::Char('q'), _) => {
                        if ui_state.quit_confirmation {
                            info!("User confirmed application exit");
                            break;
                        } else {
                            info!("User requested quit - showing confirmation");
                            ui_state.quit_confirmation = true;
                        }
                    }

                    // Ctrl+C always quits immediately
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        info!("User requested immediate exit with Ctrl+C");
                        break;
                    }

                    // Tab navigation
                    (KeyCode::Tab, _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.selected_tab = (ui_state.selected_tab + 1) % 3;
                    }

                    // Help toggle
                    (KeyCode::Char('h'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.show_help = !ui_state.show_help;
                        if ui_state.show_help {
                            ui_state.selected_tab = 2; // Switch to help tab
                        } else {
                            ui_state.selected_tab = 0; // Back to overview
                        }
                    }

                    // Navigation in connection list
                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                        ui_state.quit_confirmation = false;
                        // Refresh connections for navigation to ensure we have current filtered list
                        let nav_connections =
                            if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                        debug!(
                            "Navigation UP: {} connections available",
                            nav_connections.len()
                        );
                        ui_state.move_selection_up(&nav_connections);
                    }

                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                        ui_state.quit_confirmation = false;
                        // Refresh connections for navigation to ensure we have current filtered list
                        let nav_connections =
                            if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                        debug!(
                            "Navigation DOWN: {} connections available",
                            nav_connections.len()
                        );
                        ui_state.move_selection_down(&nav_connections);
                    }

                    // Page Up/Down navigation
                    (KeyCode::PageUp, _) => {
                        ui_state.quit_confirmation = false;
                        // Refresh connections for navigation
                        let nav_connections =
                            if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                        // Move up by roughly 10 items (or adjust based on terminal height)
                        ui_state.move_selection_page_up(&nav_connections, 10);
                    }

                    (KeyCode::PageDown, _) => {
                        ui_state.quit_confirmation = false;
                        // Refresh connections for navigation
                        let nav_connections =
                            if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                        // Move down by roughly 10 items (or adjust based on terminal height)
                        ui_state.move_selection_page_down(&nav_connections, 10);
                    }

                    // Enter to view details
                    (KeyCode::Enter, _) => {
                        ui_state.quit_confirmation = false;
                        if ui_state.selected_tab == 0 && !connections.is_empty() {
                            ui_state.selected_tab = 1; // Switch to details view
                        }
                    }

                    // Toggle port number display
                    (KeyCode::Char('p'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.show_port_numbers = !ui_state.show_port_numbers;
                        info!(
                            "Toggled port display: {}",
                            if ui_state.show_port_numbers {
                                "showing port numbers"
                            } else {
                                "showing service names"
                            }
                        );
                    }

                    // Cycle sort column with 's'
                    (KeyCode::Char('s'), KeyModifiers::NONE) => {
                        ui_state.quit_confirmation = false;
                        ui_state.cycle_sort_column();
                        info!(
                            "Sort column: {} ({})",
                            ui_state.sort_column.display_name(),
                            if ui_state.sort_ascending { "ascending" } else { "descending" }
                        );
                    }

                    // Toggle sort direction with 'S' (Shift+s)
                    (KeyCode::Char('S'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.toggle_sort_direction();
                        info!(
                            "Sort direction: {} ({})",
                            if ui_state.sort_ascending { "ascending" } else { "descending" },
                            ui_state.sort_column.display_name()
                        );
                    }

                    // Copy remote address to clipboard
                    (KeyCode::Char('c'), _) => {
                        ui_state.quit_confirmation = false;
                        if let Some(selected_idx) = ui_state.get_selected_index(&connections)
                            && let Some(conn) = connections.get(selected_idx)
                        {
                            let remote_addr = conn.remote_addr.to_string();
                            match Clipboard::new() {
                                Ok(mut clipboard) => {
                                    if let Err(e) = clipboard.set_text(&remote_addr) {
                                        error!("Failed to copy to clipboard: {}", e);
                                        ui_state.clipboard_message = Some((
                                            format!("Failed to copy: {}", e),
                                            std::time::Instant::now(),
                                        ));
                                    } else {
                                        info!("Copied {} to clipboard", remote_addr);
                                        ui_state.clipboard_message = Some((
                                            format!("Copied {} to clipboard", remote_addr),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to access clipboard: {}", e);
                                    ui_state.clipboard_message = Some((
                                        format!("Clipboard error: {}", e),
                                        std::time::Instant::now(),
                                    ));
                                }
                            }
                        }
                    }

                    // Escape to go back or clear filter
                    (KeyCode::Esc, _) => {
                        ui_state.quit_confirmation = false;
                        if !ui_state.filter_query.is_empty() {
                            // Clear filter if one is active
                            ui_state.clear_filter();
                        } else if ui_state.selected_tab == 1 {
                            ui_state.selected_tab = 0; // Back to overview
                        } else if ui_state.selected_tab == 2 {
                            ui_state.selected_tab = 0; // Back to overview from help
                        }
                    }

                    // Any other key resets quit confirmation
                    _ => {
                        ui_state.quit_confirmation = false;
                    }
                }
            }
        }
    }

    Ok(())
}
