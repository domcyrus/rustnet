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
    // Check for required dependencies on Windows
    #[cfg(target_os = "windows")]
    check_windows_dependencies()?;

    // Parse command line arguments
    let matches = cli::build_cli().get_matches();

    // Check privileges BEFORE initializing TUI (so error messages are visible)
    check_privileges_early()?;
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

    if matches.get_flag("show-localhost") {
        config.filter_localhost = false;
        info!("Showing localhost connections");
    }

    if let Some(interval) = matches.get_one::<u64>("refresh-interval") {
        config.refresh_interval = *interval;
        info!("Using refresh interval: {}ms", interval);
    }

    if matches.get_flag("no-dpi") {
        config.enable_dpi = false;
        info!("Deep packet inspection disabled");
    }

    if let Some(json_log_path) = matches.get_one::<String>("json-log") {
        config.json_log_file = Some(json_log_path.to_string());
        info!("JSON logging enabled: {}", json_log_path);
    }

    if let Some(bpf_filter) = matches.get_one::<String>("bpf-filter") {
        let filter = bpf_filter.trim();
        if !filter.is_empty() {
            config.bpf_filter = Some(filter.to_string());
            info!("Using BPF filter: {}", filter);
        }
    }

    if matches.get_flag("resolve-dns") {
        config.resolve_dns = true;
        info!("Reverse DNS resolution enabled");
    }

    if matches.get_flag("show-ptr-lookups") {
        config.show_ptr_lookups = true;
        info!("PTR lookup connections will be shown in UI");
    }

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create and start the application
    let mut app = app::App::new(config.clone())?;
    app.start()?;
    info!("Application started");

    // Apply Landlock sandbox (Linux only)
    // This must be done AFTER app.start() because:
    // - eBPF programs need to be loaded first (access to /sys/kernel/btf)
    // - Packet capture handles need to be opened first (access to /dev)
    // - Log files need to be created first
    #[cfg(all(target_os = "linux", feature = "landlock"))]
    {
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };
        use std::path::PathBuf;

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        let mut write_paths = Vec::new();

        // Add logs directory if logging is enabled
        if matches.get_one::<String>("log-level").is_some() {
            write_paths.push(PathBuf::from("logs"));
        }

        // Add JSON log path if specified
        if let Some(json_log_path) = &config.json_log_file {
            write_paths.push(PathBuf::from(json_log_path));
        }

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            write_paths,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                // Update UI with sandbox status
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::PartiallyEnforced => {
                        info!("Sandbox partially enforced: {}", result.message);
                        "Partially enforced"
                    }
                    SandboxStatus::NotApplied => {
                        debug!("Sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    cap_dropped: result.cap_net_raw_dropped,
                    landlock_available: result.landlock_available,
                    fs_restricted: result.landlock_fs_applied,
                    net_restricted: result.landlock_net_applied,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Sandbox enforcement required but failed"));
                }
                info!("Sandbox application error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    cap_dropped: false,
                    landlock_available: false,
                    fs_restricted: false,
                    net_restricted: false,
                });
            }
        }
    }

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

            SortColumn::BandwidthTotal => {
                // Compare combined up+down bandwidth, handle NaN cases
                let a_total = a.current_incoming_rate_bps + a.current_outgoing_rate_bps;
                let b_total = b.current_incoming_rate_bps + b.current_outgoing_rate_bps;
                a_total
                    .partial_cmp(&b_total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }

            SortColumn::Process => {
                let a_process = a.process_name.as_deref().unwrap_or("");
                let b_process = b.process_name.as_deref().unwrap_or("");
                a_process.cmp(b_process)
            }

            SortColumn::LocalAddress => a.local_addr.to_string().cmp(&b.local_addr.to_string()),

            SortColumn::RemoteAddress => a.remote_addr.to_string().cmp(&b.remote_addr.to_string()),

            SortColumn::Application => {
                let a_app = a
                    .dpi_info
                    .as_ref()
                    .map(|dpi| dpi.application.to_string())
                    .unwrap_or_default();
                let b_app = b
                    .dpi_info
                    .as_ref()
                    .map(|dpi| dpi.application.to_string())
                    .unwrap_or_default();
                a_app.cmp(&b_app)
            }

            SortColumn::Service => {
                let a_service = a.service_name.as_deref().unwrap_or("");
                let b_service = b.service_name.as_deref().unwrap_or("");
                a_service.cmp(b_service)
            }

            SortColumn::State => a.state().cmp(&b.state()),

            SortColumn::Protocol => a.protocol.to_string().cmp(&b.protocol.to_string()),
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
        // IMPORTANT: Fetch connections ONCE per iteration to ensure consistency
        // between display, navigation, and selection operations
        let mut connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
            app.get_connections()
        } else {
            app.get_filtered_connections(&ui_state.filter_query)
        };

        // Apply sorting (after filtering)
        // This sorted list MUST be used for all operations (display + navigation)
        sort_connections(
            &mut connections,
            ui_state.sort_column,
            ui_state.sort_ascending,
        );

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
            use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

            // On Windows, crossterm reports both Press and Release events
            // On Linux/macOS, only Press events are reported
            // Filter to only handle Press events for consistent cross-platform behavior
            if key.kind != KeyEventKind::Press {
                continue;
            }

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
                        // Use the SAME sorted connections list from the main loop
                        // to ensure index consistency with the displayed table
                        debug!(
                            "Filter mode navigation UP: {} connections available",
                            connections.len()
                        );
                        ui_state.move_selection_up(&connections);
                    }
                    KeyCode::Down => {
                        // Use the SAME sorted connections list from the main loop
                        // to ensure index consistency with the displayed table
                        debug!(
                            "Filter mode navigation DOWN: {} connections available",
                            connections.len()
                        );
                        ui_state.move_selection_down(&connections);
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
                                // Use the SAME sorted connections list from the main loop
                                debug!(
                                    "Filter mode navigation UP (k): {} connections available",
                                    connections.len()
                                );
                                ui_state.move_selection_up(&connections);
                            }
                            'j' => {
                                // Vim-style down navigation while filtering
                                // Use the SAME sorted connections list from the main loop
                                debug!(
                                    "Filter mode navigation DOWN (j): {} connections available",
                                    connections.len()
                                );
                                ui_state.move_selection_down(&connections);
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

                    // Tab navigation (forward)
                    (KeyCode::Tab, KeyModifiers::NONE) => {
                        ui_state.quit_confirmation = false;
                        ui_state.selected_tab = (ui_state.selected_tab + 1) % 5;
                    }

                    // Shift+Tab navigation (backward)
                    (KeyCode::BackTab, _) | (KeyCode::Tab, KeyModifiers::SHIFT) => {
                        ui_state.quit_confirmation = false;
                        ui_state.selected_tab = if ui_state.selected_tab == 0 {
                            4 // Wrap to last tab
                        } else {
                            ui_state.selected_tab - 1
                        };
                    }

                    // Help toggle
                    (KeyCode::Char('h'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.show_help = !ui_state.show_help;
                        if ui_state.show_help {
                            ui_state.selected_tab = 4; // Switch to help tab
                        } else {
                            ui_state.selected_tab = 0; // Back to overview
                        }
                    }

                    // Interface stats toggle (shortcut to Interface tab)
                    (KeyCode::Char('i'), _) | (KeyCode::Char('I'), _) => {
                        ui_state.quit_confirmation = false;
                        if ui_state.selected_tab == 2 {
                            ui_state.selected_tab = 0; // Back to overview
                        } else {
                            ui_state.selected_tab = 2; // Switch to interfaces tab
                        }
                    }

                    // Navigation in connection list
                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
                        ui_state.quit_confirmation = false;
                        // Use the SAME sorted connections list from the main loop
                        // to ensure index consistency with the displayed table
                        debug!("Navigation UP: {} connections available", connections.len());
                        ui_state.move_selection_up(&connections);
                    }

                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
                        ui_state.quit_confirmation = false;
                        // Use the SAME sorted connections list from the main loop
                        // to ensure index consistency with the displayed table
                        debug!(
                            "Navigation DOWN: {} connections available",
                            connections.len()
                        );
                        ui_state.move_selection_down(&connections);
                    }

                    // Page Up/Down navigation
                    (KeyCode::PageUp, _) => {
                        ui_state.quit_confirmation = false;
                        // Use the SAME sorted connections list from the main loop
                        // Move up by roughly 10 items (or adjust based on terminal height)
                        ui_state.move_selection_page_up(&connections, 10);
                    }

                    (KeyCode::PageDown, _) => {
                        ui_state.quit_confirmation = false;
                        // Use the SAME sorted connections list from the main loop
                        // Move down by roughly 10 items (or adjust based on terminal height)
                        ui_state.move_selection_page_down(&connections, 10);
                    }

                    // Vim-style jump to first/last (g/G)
                    (KeyCode::Char('g'), KeyModifiers::NONE) => {
                        ui_state.quit_confirmation = false;
                        // Jump to first connection (vim-style 'g')
                        ui_state.move_selection_to_first(&connections);
                    }

                    (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) => {
                        ui_state.quit_confirmation = false;
                        // Jump to last connection (vim-style 'G')
                        ui_state.move_selection_to_last(&connections);
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

                    // Toggle hostname display (when DNS resolution is enabled)
                    (KeyCode::Char('d'), _) => {
                        if app.is_dns_resolution_enabled() {
                            ui_state.quit_confirmation = false;
                            ui_state.show_hostnames = !ui_state.show_hostnames;
                            info!(
                                "Toggled hostname display: {}",
                                if ui_state.show_hostnames {
                                    "showing hostnames"
                                } else {
                                    "showing IP addresses"
                                }
                            );
                        }
                    }

                    // Cycle sort column with 's'
                    (KeyCode::Char('s'), KeyModifiers::NONE) => {
                        ui_state.quit_confirmation = false;
                        ui_state.cycle_sort_column();
                        info!(
                            "Sort column: {} ({})",
                            ui_state.sort_column.display_name(),
                            if ui_state.sort_ascending {
                                "ascending"
                            } else {
                                "descending"
                            }
                        );
                    }

                    // Toggle sort direction with 'S' (Shift+s)
                    (KeyCode::Char('S'), _) => {
                        ui_state.quit_confirmation = false;
                        ui_state.toggle_sort_direction();
                        info!(
                            "Sort direction: {} ({})",
                            if ui_state.sort_ascending {
                                "ascending"
                            } else {
                                "descending"
                            },
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

                            // Try arboard first, fall back to wl-copy for Wayland (GNOME doesn't
                            // support the wlr-data-control protocol that arboard relies on)
                            let result =
                                Clipboard::new().and_then(|mut cb| cb.set_text(&remote_addr));

                            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
                            let result = result.or_else(|_| {
                                std::process::Command::new("wl-copy")
                                    .arg(&remote_addr)
                                    .status()
                                    .map_err(|e| arboard::Error::Unknown {
                                        description: e.to_string(),
                                    })
                                    .and_then(|s| {
                                        if s.success() {
                                            Ok(())
                                        } else {
                                            Err(arboard::Error::Unknown {
                                                description: "wl-copy failed".to_string(),
                                            })
                                        }
                                    })
                            });

                            match result {
                                Ok(()) => {
                                    info!("Copied {} to clipboard", remote_addr);
                                    ui_state.clipboard_message = Some((
                                        format!("Copied {} to clipboard", remote_addr),
                                        std::time::Instant::now(),
                                    ));
                                }
                                Err(e) => {
                                    // Check if sandbox might be blocking clipboard access
                                    #[cfg(target_os = "linux")]
                                    let msg = if app.get_sandbox_info().fs_restricted {
                                        "Clipboard unavailable (sandbox active). Use --no-sandbox to enable.".to_string()
                                    } else {
                                        format!("Clipboard error: {}", e)
                                    };
                                    #[cfg(not(target_os = "linux"))]
                                    let msg = format!("Clipboard error: {}", e);

                                    error!("{}", msg);
                                    ui_state.clipboard_message =
                                        Some((msg, std::time::Instant::now()));
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

/// Check if we have privileges for packet capture before starting the TUI
fn check_privileges_early() -> Result<()> {
    match network::privileges::check_packet_capture_privileges() {
        Ok(status) if !status.has_privileges => {
            // Print error to stderr before TUI starts
            eprintln!(
                "\n╔═══════════════════════════════════════════════════════════════════════════╗"
            );
            eprintln!(
                "║                   INSUFFICIENT PRIVILEGES                                 ║"
            );
            eprintln!(
                "╚═══════════════════════════════════════════════════════════════════════════╝"
            );
            eprintln!();
            eprintln!("{}", status.error_message());

            return Err(anyhow::anyhow!(
                "Insufficient privileges for packet capture"
            ));
        }
        Err(e) => {
            // Privilege check failed - warn but continue
            eprintln!("Warning: Failed to check privileges: {}", e);
            eprintln!("Continuing anyway, but packet capture may fail...\n");
        }
        _ => {
            // Privileges OK
        }
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_windows_dependencies() -> Result<()> {
    use anyhow::anyhow;

    // Check if Npcap/WinPcap DLLs are available
    // Try to load the DLLs to see if they're in the system path
    let wpcap_available = check_dll_available("wpcap.dll");
    let packet_available = check_dll_available("Packet.dll");

    if !wpcap_available || !packet_available {
        eprintln!(
            "\n╔═══════════════════════════════════════════════════════════════════════════╗"
        );
        eprintln!("║                          MISSING DEPENDENCY                               ║");
        eprintln!("╚═══════════════════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("RustNet requires Npcap for packet capture on Windows.");
        eprintln!();

        if !wpcap_available {
            eprintln!("  ✗ wpcap.dll not found");
        }
        if !packet_available {
            eprintln!("  ✗ Packet.dll not found");
        }

        eprintln!();
        eprintln!("To fix this:");
        eprintln!();
        eprintln!("  1. Download Npcap from: https://npcap.com/dist/");
        eprintln!("  2. Run the installer");
        eprintln!("  3. IMPORTANT: Check \"Install Npcap in WinPcap API-compatible Mode\"");
        eprintln!("  4. Complete the installation");
        eprintln!();
        eprintln!("After installation, restart your terminal and try again.");
        eprintln!();

        return Err(anyhow!(
            "Npcap is not installed or not in WinPcap compatible mode"
        ));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn check_dll_available(dll_name: &str) -> bool {
    use std::ffi::CString;
    use windows::Win32::Foundation::{FreeLibrary, HMODULE};
    use windows::Win32::System::LibraryLoader::LoadLibraryA;
    use windows::core::PCSTR;

    // Try to load the DLL
    let dll_cstring = match CString::new(dll_name) {
        Ok(s) => s,
        Err(_) => return false,
    };

    unsafe {
        // Use LoadLibraryA to check if the DLL can be loaded
        let handle = LoadLibraryA(PCSTR(dll_cstring.as_ptr() as *const u8));

        if let Ok(h) = handle
            && h != HMODULE(std::ptr::null_mut())
        {
            // Free the library if it was loaded
            let _ = FreeLibrary(h);
            true
        } else {
            false
        }
    }
}

/// Check if the current process is running with Administrator privileges (Windows only)
#[cfg(target_os = "windows")]
fn is_admin() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();

        // Open the process token
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length = 0u32;

        // Get the elevation information
        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        // Close the token handle
        let _ = windows::Win32::Foundation::CloseHandle(token_handle);

        if result.is_err() {
            return false;
        }

        elevation.TokenIsElevated != 0
    }
}
