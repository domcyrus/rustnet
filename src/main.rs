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
mod config;
mod i18n;
mod network;
mod ui;

fn main() -> Result<()> {
    // Set up logging
    setup_logging()?;

    info!("Starting RustNet");

    // Parse command line arguments
    let matches = Command::new("rustnet")
        .version("0.1.0")
        .author("Your Name")
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
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Path to configuration file")
                .required(false),
        )
        .arg(
            Arg::new("language")
                .short('l')
                .long("language")
                .value_name("LANG")
                .help("Interface language (en, fr, etc.)")
                .required(false),
        )
        .arg(
            Arg::new("packet_processing_interval")
                .short('P')
                .long("packet-processing-interval")
                .value_name("MILLISECONDS")
                .help("Interval for packet processing loop sleep (ms). 0 for continuous.")
                .value_parser(clap::value_parser!(u64))
                .required(false),
        )
        .get_matches();

    // Initialize configuration
    let config_path = matches.get_one::<String>("config").map(String::as_str);
    let mut config = config::Config::load(config_path)?;

    info!("Configuration loaded");

    // Override config with command line arguments if provided
    if let Some(interface) = matches.get_one::<String>("interface") {
        config.interface = Some(interface.to_string());
        info!("Using interface: {}", interface);
    }

    if let Some(language) = matches.get_one::<String>("language") {
        config.language = language.to_string();
        info!("Using language: {}", language);
    }

    if let Some(interval) = matches.get_one::<u64>("packet_processing_interval") {
        config.packet_processing_interval_ms = *interval;
        info!("Using packet processing interval: {}ms", interval);
    }

    // Initialize internationalization
    let i18n = i18n::I18n::new(&config.language)?;
    info!(
        "Internationalization initialized for language: {}",
        config.language
    );

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create app state
    let app = app::App::new(config, i18n)?;
    info!("Application state initialized");

    // Run the application
    let res = run_app(&mut terminal, app);

    // Restore terminal
    ui::restore_terminal(&mut terminal)?;

    // Return any error that occurred
    if let Err(err) = res {
        error!("Application error: {}", err);
        println!("Error: {}", err);
    }

    info!("RustNet shutting down");
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

fn run_app<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    mut app: app::App,
) -> Result<()> {
    let tick_rate = Duration::from_millis(200); // Faster refresh for better loading animation
    let mut last_tick = std::time::Instant::now();
    let mut capture_started = false;

    loop {
        // Draw the UI first to show loading screen immediately
        terminal.draw(|f| {
            if let Err(err) = ui::draw(f, &mut app) {
                error!("UI draw error: {}", err);
            }
        })?;

        // Start capture on first iteration (after first UI render)
        if !capture_started {
            if let Err(err) = app.start_capture() {
                error!("Failed to start network capture: {}", err);
                // Continue anyway, some features may still work
            }
            info!("Network capture started");
            capture_started = true;
        }

        // Handle timeout (for periodic UI updates)
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        // Update app state on tick (especially important during loading for spinner animation)
        let should_tick = last_tick.elapsed() >= tick_rate;
        if should_tick {
            app.on_tick()?;
            last_tick = std::time::Instant::now();
        }

        // Handle input events (use shorter timeout during loading for responsive spinner)
        let input_timeout = if app.is_loading {
            Duration::from_millis(100)
        } else {
            timeout
        };

        if crossterm::event::poll(input_timeout)? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                // Handle key event
                if let Some(action) = app.handle_key(key) {
                    match action {
                        app::Action::Quit => {
                            info!("User requested application exit");
                            app.shutdown();
                            break;
                        }
                        app::Action::Refresh => {
                            info!("User requested refresh");
                            app.refresh()?;
                        } // Add more actions as needed
                    }
                }
            }
        }
    }

    Ok(())
}
