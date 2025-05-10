use anyhow::Result;
use clap::{Arg, Command};
use log::{error, info, LevelFilter};
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
    // Start the network capture in a separate thread
    app.start_capture()?;
    info!("Network capture started");

    let tick_rate = Duration::from_millis(app.config.refresh_interval); // Use configured refresh interval
    let mut last_tick = std::time::Instant::now();

    loop {
        // Draw the UI
        terminal.draw(|f| {
            if let Err(err) = ui::draw(f, &mut app) {
                error!("UI draw error: {}", err);
            }
        })?;

        // Handle timeout (for periodic UI updates)
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        // Handle input events
        if crossterm::event::poll(timeout)? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                // Handle key event
                if let Some(action) = app.handle_key(key) {
                    match action {
                        app::Action::Quit => {
                            info!("User requested application exit");
                            break;
                        }
                        app::Action::Refresh => {
                            info!("User requested refresh");
                            app.refresh()?;
                        }
                        // Add more actions as needed
                    }
                }
            }
        }

        // Update app state on tick
        if last_tick.elapsed() >= tick_rate {
            app.on_tick()?;
            last_tick = std::time::Instant::now();
        }
    }

    Ok(())
}
