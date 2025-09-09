use anyhow::Result;
use arboard::Clipboard;
use clap::{Arg, Command};
use log::{LevelFilter, debug, error, info};
use ratatui::prelude::CrosstermBackend;
use simplelog::{Config as LogConfig, WriteLogger};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::time::Duration;

mod app;
mod filter;
mod network;
mod ui;

fn main() -> Result<()> {
    // Parse command line arguments
    let matches = Command::new("rustnet")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Network Monitor")
        .about("Cross-platform network monitoring tool")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to monitor")
                .required(false),
        )
        .arg(
            Arg::new("no-localhost")
                .long("no-localhost")
                .help("Filter out localhost connections")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh-interval")
                .short('r')
                .long("refresh-interval")
                .value_name("MILLISECONDS")
                .help("UI refresh interval in milliseconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("1000")
                .required(false),
        )
        .arg(
            Arg::new("no-dpi")
                .long("no-dpi")
                .help("Disable deep packet inspection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Set the log level (if not provided, no logging will be enabled)")
                .value_parser(clap::value_parser!(LevelFilter))
                .required(false),
        )
        .get_matches();
    // Set up logging only if log-level was provided
    if let Some(log_level) = matches.get_one::<LevelFilter>("log-level") {
        setup_logging(*log_level)?;
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

fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    app: &app::App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut ui_state = ui::UIState::default();

    loop {
        // Get current connections and stats
        let connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
            app.get_connections()
        } else {
            app.get_filtered_connections(&ui_state.filter_query)
        };
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
            && time.elapsed().as_secs() >= 3 {
            ui_state.clipboard_message = None;
        }

        // Handle input events
        if crossterm::event::poll(timeout)?
            && let crossterm::event::Event::Key(key) = crossterm::event::read()? {
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
                                ui_state.filter_query.remove(ui_state.filter_cursor_position);
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
                            debug!("Filter mode navigation UP: {} connections available", nav_connections.len());
                            ui_state.move_selection_up(&nav_connections);
                        }
                        KeyCode::Down => {
                            // Navigate filtered connections while typing
                            let nav_connections = if ui_state.filter_query.is_empty() {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                            debug!("Filter mode navigation DOWN: {} connections available", nav_connections.len());
                            ui_state.move_selection_down(&nav_connections);
                        }
                        KeyCode::Char(c) => {
                            // Handle navigation keys (j/k) and text input
                            match c {
                                'k' => {
                                    // Vim-style up navigation while filtering
                                    let nav_connections = if ui_state.filter_query.is_empty() {
                                        app.get_connections()
                                    } else {
                                        app.get_filtered_connections(&ui_state.filter_query)
                                    };
                                    debug!("Filter mode navigation UP (k): {} connections available", nav_connections.len());
                                    ui_state.move_selection_up(&nav_connections);
                                }
                                'j' => {
                                    // Vim-style down navigation while filtering
                                    let nav_connections = if ui_state.filter_query.is_empty() {
                                        app.get_connections()
                                    } else {
                                        app.get_filtered_connections(&ui_state.filter_query)
                                    };
                                    debug!("Filter mode navigation DOWN (j): {} connections available", nav_connections.len());
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
                            let nav_connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                            debug!("Navigation UP: {} connections available", nav_connections.len());
                            ui_state.move_selection_up(&nav_connections);
                        }

                        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                            ui_state.quit_confirmation = false;
                            // Refresh connections for navigation to ensure we have current filtered list
                            let nav_connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                                app.get_connections()
                            } else {
                                app.get_filtered_connections(&ui_state.filter_query)
                            };
                            debug!("Navigation DOWN: {} connections available", nav_connections.len());
                            ui_state.move_selection_down(&nav_connections);
                        }

                        // Page Up/Down navigation
                        (KeyCode::PageUp, _) => {
                            ui_state.quit_confirmation = false;
                            // Refresh connections for navigation
                            let nav_connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
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
                            let nav_connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
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

                        // Copy remote address to clipboard
                        (KeyCode::Char('c'), _) => {
                            ui_state.quit_confirmation = false;
                            if let Some(selected_idx) = ui_state.get_selected_index(&connections)
                                && let Some(conn) = connections.get(selected_idx) {
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
