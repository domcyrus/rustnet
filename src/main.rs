use anyhow::Result;
use clap::{Arg, Command};
use log::{LevelFilter, error, info};
use ratatui::prelude::CrosstermBackend;
use simplelog::{Config as LogConfig, WriteLogger};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::time::Duration;

mod app;
mod network;
mod ui;

fn main() -> Result<()> {
    // Set up logging
    setup_logging()?;

    info!("Starting RustNet Monitor");

    // Parse command line arguments
    let matches = Command::new("rustnet")
        .version("0.1.0")
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
        .get_matches();

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

fn setup_logging() -> Result<()> {
    // Create logs directory if it doesn't exist
    let log_dir = Path::new("logs");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    // Create timestamped log file name
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    // Initialize the logger
    WriteLogger::init(
        LevelFilter::Debug,
        LogConfig::default(),
        File::create(log_file_path)?,
    )?;

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
        let connections = app.get_connections();
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

        // Handle input events
        if crossterm::event::poll(timeout)? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                use crossterm::event::{KeyCode, KeyModifiers};

                match (key.code, key.modifiers) {
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
                        ui_state.move_selection_up(&connections);
                    }

                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.move_selection_down(&connections);
                    }

                    // Enter to view details
                    (KeyCode::Enter, _) => {
                        ui_state.quit_confirmation = false;
                        if ui_state.selected_tab == 0 && !connections.is_empty() {
                            ui_state.selected_tab = 1; // Switch to details view
                        }
                    }

                    // Escape to go back
                    (KeyCode::Esc, _) => {
                        ui_state.quit_confirmation = false;
                        if ui_state.selected_tab == 1 {
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
