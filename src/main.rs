use anyhow::Result;
use log::{LevelFilter, error, info, warn};
use ratatui::prelude::CrosstermBackend;
use simplelog::{ConfigBuilder, WriteLogger};
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

    // Set up logging only if log-level was provided
    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level)?;
    }

    // Check privileges BEFORE initializing TUI (so error messages are visible)
    check_privileges_early()?;

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

    if let Some(pcap_path) = matches.get_one::<String>("pcap-export") {
        config.pcap_export_file = Some(pcap_path.to_string());
        info!("PCAP export enabled: {}", pcap_path);
    }

    if let Some(bpf_filter) = matches.get_one::<String>("bpf-filter") {
        let filter = bpf_filter.trim();
        if !filter.is_empty() {
            config.bpf_filter = Some(filter.to_string());
            info!("Using BPF filter: {}", filter);
        }
    }

    if matches.get_flag("no-resolve-dns") {
        config.resolve_dns = false;
        info!("Reverse DNS resolution disabled");
    }

    if matches.get_flag("show-ptr-lookups") {
        config.show_ptr_lookups = true;
        info!("PTR lookup connections will be shown in UI");
    }

    // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
    let no_color =
        matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
    if no_color {
        info!("Colors disabled (NO_COLOR)");
        ui::set_no_color(true);
    }

    // GeoIP configuration
    if matches.get_flag("no-geoip") {
        config.disable_geoip = true;
        info!("GeoIP lookups disabled");
    }

    if let Some(country_path) = matches.get_one::<String>("geoip-country") {
        config.geoip_country_path = Some(country_path.to_string());
        info!("Using GeoIP Country database: {}", country_path);
    }

    if let Some(asn_path) = matches.get_one::<String>("geoip-asn") {
        config.geoip_asn_path = Some(asn_path.to_string());
        info!("Using GeoIP ASN database: {}", asn_path);
    }

    if let Some(city_path) = matches.get_one::<String>("geoip-city") {
        config.geoip_city_path = Some(city_path.to_string());
        info!("Using GeoIP City database: {}", city_path);
    }

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create and start the application
    let mut app = app::App::new(config.clone())?;
    let process_ready_rx = app.start()?;
    info!("Application started");

    // Pre-create the PCAP export file and its sidecar JSONL (needed for Landlock
    // permissions). This must be done BEFORE the sandbox is applied so the files
    // exist when adding rules: Landlock requires an open FD to scope a rule to a
    // file, so a not-yet-existing path falls back to granting write on the whole
    // parent directory. Pre-creating keeps the write rule file-scoped. The PCAP
    // writer later reopens the path with truncation, so a zero-byte file is fine.
    if let Some(ref pcap_path) = config.pcap_export_file {
        let jsonl_path = format!("{}.connections.jsonl", pcap_path);
        for (label, path) in [("PCAP", pcap_path.as_str()), ("sidecar JSONL", &jsonl_path)] {
            match std::fs::File::create(path) {
                Ok(_f) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(e) = _f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
                            warn!("Failed to set {} file permissions: {}", label, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to pre-create {} file: {}", label, e);
                }
            }
        }
    }

    // Wait for process detection (including eBPF loading) to complete before
    // applying the sandbox, which drops CAP_BPF and CAP_PERFMON.
    // Without this synchronization, the sandbox could drop these capabilities
    // before the background thread has finished loading eBPF programs.
    match process_ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => info!("Process detection initialized, safe to apply sandbox"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!("Timed out waiting for process detection init, applying sandbox anyway");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("Process detection thread exited early, applying sandbox anyway");
        }
    }

    // Apply Landlock sandbox (Linux only)
    // This must be done AFTER process detection is initialized because:
    // - eBPF programs need to be loaded first (requires CAP_BPF + CAP_PERFMON)
    // - Packet capture handles need to be opened first (access to /dev)
    // - Log files need to be created first
    #[cfg(all(target_os = "linux", feature = "landlock"))]
    {
        use network::geoip::GeoIpResolver;
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

        // Collect read paths (GeoIP databases)
        let read_paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
            .into_iter()
            .filter(|p| p.exists())
            .collect();

        let mut write_paths = Vec::new();

        // Add logs directory if logging is enabled
        if matches.get_one::<String>("log-level").is_some() {
            write_paths.push(PathBuf::from("logs"));
        }

        // Add JSON log path if specified
        if let Some(json_log_path) = &config.json_log_file {
            write_paths.push(PathBuf::from(json_log_path));
        }

        // Add PCAP export paths if specified (both .pcap and .pcap.connections.jsonl)
        if let Some(pcap_path) = &config.pcap_export_file {
            write_paths.push(PathBuf::from(pcap_path));
            write_paths.push(PathBuf::from(format!("{}.connections.jsonl", pcap_path)));
        }

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            read_paths,
            write_paths,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                // Update UI with sandbox status
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => "Fully enforced",
                    SandboxStatus::PartiallyEnforced => "Partially enforced",
                    SandboxStatus::NotApplied => "Not applied",
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    cap_dropped: result.cap_net_raw_dropped,
                    ebpf_caps_dropped: result.ebpf_caps_dropped,
                    landlock_available: result.landlock_available,
                    fs_restricted: result.landlock_fs_applied,
                    net_restricted: result.landlock_net_applied,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Sandbox enforcement required but failed"));
                }
                warn!("Sandbox application error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    cap_dropped: false,
                    ebpf_caps_dropped: false,
                    landlock_available: false,
                    fs_restricted: false,
                    net_restricted: false,
                });
            }
        }
    }

    // Apply Seatbelt sandbox (macOS only)
    // This must be done AFTER app.start() because:
    // - Packet capture handles need to be opened first (BPF/PKTAP fds survive the sandbox)
    // - Log files need to be created first
    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    {
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        let log_dir = if matches.get_one::<String>("log-level").is_some() {
            Some("logs".to_string())
        } else {
            None
        };

        // Collect GeoIP paths that may need read access through the sandbox.
        // User-specified paths take priority; otherwise include auto-discovery
        // search paths so the file-read deny on /Users doesn't block them.
        let geoip_paths: Vec<String> = {
            use network::geoip::GeoIpResolver;
            let mut paths = Vec::new();
            if let Some(ref p) = config.geoip_country_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_asn_path {
                paths.push(p.clone());
            }
            if let Some(ref p) = config.geoip_city_path {
                paths.push(p.clone());
            }
            if paths.is_empty() && !config.disable_geoip {
                // Use auto-discovery search paths (directories, not individual files)
                paths.extend(
                    GeoIpResolver::get_search_paths()
                        .into_iter()
                        .filter(|p| p.exists())
                        .map(|p| p.to_string_lossy().into_owned()),
                );
            }
            paths
        };

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            log_dir,
            json_log_path: config.json_log_file,
            pcap_export_path: config.pcap_export_file,
            geoip_paths,
        };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Seatbelt sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Seatbelt sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    seatbelt_applied: result.seatbelt_applied,
                    fs_restricted: result.fs_restricted,
                    net_restricted: result.net_blocked,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Seatbelt sandbox enforcement required but failed"));
                }
                info!("Seatbelt sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    seatbelt_applied: false,
                    fs_restricted: false,
                    net_restricted: false,
                });
            }
        }
    }

    // Apply restricted token sandbox (Windows only)
    // This must be done AFTER app.start() because:
    // - Npcap handles need to be opened first
    // - Log files need to be created first
    #[cfg(target_os = "windows")]
    {
        use network::platform::sandbox::{
            SandboxConfig, SandboxMode, SandboxStatus, apply_sandbox,
        };

        let sandbox_mode = if matches.get_flag("no-sandbox") {
            SandboxMode::Disabled
        } else if matches.get_flag("sandbox-strict") {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        };

        let sandbox_config = SandboxConfig { mode: sandbox_mode };

        match apply_sandbox(&sandbox_config) {
            Ok(result) => {
                let status_str = match result.status {
                    SandboxStatus::FullyEnforced => {
                        info!("Windows sandbox fully enforced: {}", result.message);
                        "Fully enforced"
                    }
                    SandboxStatus::PartiallyEnforced => {
                        warn!("Windows sandbox partially enforced: {}", result.message);
                        "Partially enforced"
                    }
                    SandboxStatus::NotApplied => {
                        warn!("Windows sandbox not applied: {}", result.message);
                        "Not applied"
                    }
                };

                app.set_sandbox_info(app::SandboxInfo {
                    status: status_str.to_string(),
                    privileges_removed: result.privileges_removed,
                    privileges_removed_count: result.privileges_removed_count,
                    job_object_applied: result.job_object_applied,
                });
            }
            Err(e) => {
                if sandbox_mode == SandboxMode::Strict {
                    return Err(e.context("Windows sandbox enforcement required but failed"));
                }
                warn!("Windows sandbox error (non-strict mode): {}", e);
                app.set_sandbox_info(app::SandboxInfo {
                    status: "Error".to_string(),
                    privileges_removed: false,
                    privileges_removed_count: 0,
                    job_object_applied: false,
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

    // Enable the `target` field on every log line so each entry carries
    // the originating module (e.g. `network::dpi::dns`). Combined with
    // the startup-banner lines below, this addresses #310 — users now
    // see both the program identity (name/version/pid) at the top of
    // the file and which subsystem emitted each subsequent line.
    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();

    WriteLogger::init(level, config, File::create(log_file_path)?)?;

    // Startup banner — one identifying header so a user grepping a
    // long-lived log file can immediately see which binary, which
    // version, and which pid produced these lines. The `pkg_name` is
    // the cargo package name (`rustnet-monitor`), not `argv[0]`, so it
    // stays correct when the binary is renamed or symlinked.
    info!(
        "{} v{} starting (pid {})",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    );

    Ok(())
}

/// Sort connections based on the specified column and direction
use ui::{clear_all_with_confirmation, copy_to_clipboard, sort_connections};

fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    app: &app::App,
) -> Result<()>
where
    <B as ratatui::prelude::Backend>::Error: Send + Sync + 'static,
{
    let tick_rate = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut ui_state = ui::UIState::default();
    let (has_country_db, _, _) = app.get_geoip_status();
    ui_state.has_geoip = has_country_db;
    let mut click_regions = ui::ClickableRegions::default();

    // Data state persists across loop iterations — only refreshed on timer tick
    // or when an event changes the underlying data (filter, sort, historic toggle, etc.)
    let mut connections: Vec<network::types::Connection> = Vec::new();
    let mut grouped_rows: Vec<ui::GroupedRow<'_>> = Vec::new();
    let mut stats = app.get_stats();
    let mut needs_data_refresh = true;
    let mut needs_regroup = false;

    loop {
        // Refresh connection data only when needed:
        // - On timer tick (every 200ms) for live updates
        // - When an event changes filter, sort, or data source
        if needs_data_refresh || last_tick.elapsed() >= tick_rate {
            connections = if ui_state.filter_query.is_empty() && !ui_state.filter_mode {
                app.get_connections()
            } else {
                app.get_filtered_connections(&ui_state.filter_query)
            };
            sort_connections(
                &mut connections,
                ui_state.sort_column,
                ui_state.sort_ascending,
            );
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            stats = app.get_stats();
            last_tick = std::time::Instant::now();
            needs_data_refresh = false;
            needs_regroup = false;
        } else if needs_regroup {
            // Only rebuild grouped rows from existing connections
            // (e.g., after expand/collapse or grouping toggle)
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            needs_regroup = false;
        }

        // Ensure we have a valid selection (handles connection removals)
        if ui_state.grouping_enabled {
            ui_state.ensure_valid_grouped_selection(&grouped_rows);
            let selected_idx = ui_state
                .get_selected_grouped_index(&grouped_rows)
                .unwrap_or(0);
            ui_state.grouped_scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.grouped_scroll_offset,
                ui_state.visible_rows,
                grouped_rows.len(),
            );
        } else {
            ui_state.ensure_valid_selection(&connections);
            let selected_idx = ui_state.get_selected_index(&connections).unwrap_or(0);
            ui_state.scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.scroll_offset,
                ui_state.visible_rows,
                connections.len(),
            );
        }

        // Draw the UI
        terminal.draw(|f| {
            let grouped = if ui_state.grouping_enabled {
                Some(grouped_rows.as_slice())
            } else {
                None
            };
            if let Err(err) = ui::draw(
                f,
                app,
                &ui_state,
                &connections,
                grouped,
                &stats,
                &mut click_regions,
            ) {
                error!("UI draw error: {}", err);
            }
        })?;

        // Update visible rows for page navigation based on terminal height
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_mode || !ui_state.filter_query.is_empty() {
                11
            } else {
                8
            };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        // Handle timeout for periodic updates
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0));

        // Clear clipboard message after timeout
        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
        }

        // Handle input events
        if crossterm::event::poll(timeout)? {
            let event = crossterm::event::read()?;
            match event {
                crossterm::event::Event::Mouse(mouse) => {
                    use crossterm::event::{MouseButton, MouseEventKind};

                    // Active tab's Component gets first crack — currently
                    // only OverviewTab claims (scroll wheel inside the
                    // scroll area). Click events fall through to the
                    // global ClickableRegions dispatch below.
                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    if let Some(effects) =
                        ui::dispatch_mouse(hctx.ui_state.selected_tab, mouse, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        continue;
                    }

                    if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                        {
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;

                            // Detect double-click (two clicks within 400ms at the same row)
                            let is_double_click =
                                if let Some((_, prev_row, prev_time)) = ui_state.last_click {
                                    prev_row == mouse.row && prev_time.elapsed().as_millis() < 400
                                } else {
                                    false
                                };
                            ui_state.last_click =
                                Some((mouse.column, mouse.row, std::time::Instant::now()));

                            if let Some(action) = click_regions.hit_test(mouse.column, mouse.row) {
                                match action.clone() {
                                    ui::ClickAction::SwitchTab(tab_idx) => {
                                        ui_state.selected_tab = tab_idx;
                                    }
                                    ui::ClickAction::SelectConnection(conn_idx) => {
                                        if ui_state.grouping_enabled {
                                            ui_state.set_selected_grouped_by_index(
                                                &grouped_rows,
                                                conn_idx,
                                            );
                                            if is_double_click
                                                && let Some(row) = grouped_rows.get(conn_idx)
                                            {
                                                match row {
                                                    ui::GroupedRow::Group { .. } => {
                                                        // Double-click group header: toggle expand/collapse
                                                        ui_state.toggle_group_expansion();
                                                        needs_regroup = true;
                                                    }
                                                    ui::GroupedRow::Connection { .. } => {
                                                        // Double-click connection: open Details tab
                                                        ui_state.selected_tab = 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            ui_state.set_selected_by_index(&connections, conn_idx);
                                            if is_double_click {
                                                // Double-click connection in flat view: open Details tab
                                                ui_state.selected_tab = 1;
                                            }
                                        }
                                    }
                                    ui::ClickAction::CopyField { label, value } => {
                                        copy_to_clipboard(
                                            &value,
                                            &format!("{}: {}", label, value),
                                            &mut ui_state,
                                            app,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Scroll events are handled by OverviewTab::handle_mouse above.
                }
                crossterm::event::Event::Key(key) => {
                    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

                    // On Windows, crossterm reports both Press and Release events
                    // On Linux/macOS, only Press events are reported
                    // Filter to only handle Press events for consistent cross-platform behavior
                    if key.kind != KeyEventKind::Press {
                        continue;
                    }

                    // Give the active tab's Component first crack
                    // at the key (including filter-mode input — OverviewTab
                    // owns that). If it claims (returns Some), the loop
                    // skips its fallback match. The per-key confirmation
                    // reset happens here for both branches so q / x can
                    // still set their own confirmations without the
                    // catch-all clobbering them.
                    match key.code {
                        KeyCode::Char('q') => ui_state.clear_confirmation = false,
                        KeyCode::Char('x') => ui_state.quit_confirmation = false,
                        _ => {
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;
                        }
                    }

                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    let claimed = if let Some(effects) =
                        ui::dispatch_key(hctx.ui_state.selected_tab, key, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        true
                    } else {
                        false
                    };

                    if claimed {
                        // Component handled the key end-to-end.
                    } else {
                        // Normal-mode fallback: keys that weren't claimed
                        // by the active tab's Component. Global navigation
                        // and quit/help/interface-toggle live here, plus
                        // cross-tab fallbacks for x (clear) and Esc which
                        // would otherwise stop working on non-Overview
                        // tabs. Per-arm confirmation clearing is no longer
                        // needed — the dispatcher above already applied
                        // the per-key reset rule.
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

                            // Tab navigation (forward)
                            (KeyCode::Tab, KeyModifiers::NONE) => {
                                ui_state.selected_tab = (ui_state.selected_tab + 1) % 5;
                            }

                            // Shift+Tab navigation (backward)
                            (KeyCode::BackTab, _) | (KeyCode::Tab, KeyModifiers::SHIFT) => {
                                ui_state.selected_tab = if ui_state.selected_tab == 0 {
                                    4 // Wrap to last tab
                                } else {
                                    ui_state.selected_tab - 1
                                };
                            }

                            // Help toggle
                            (KeyCode::Char('h'), _) => {
                                ui_state.show_help = !ui_state.show_help;
                                if ui_state.show_help {
                                    ui_state.selected_tab = 4; // Switch to help tab
                                } else {
                                    ui_state.selected_tab = 0; // Back to overview
                                }
                            }

                            // Interface stats toggle (shortcut to Interface tab)
                            (KeyCode::Char('i'), _) | (KeyCode::Char('I'), _) => {
                                if ui_state.selected_tab == 2 {
                                    ui_state.selected_tab = 0; // Back to overview
                                } else {
                                    ui_state.selected_tab = 2; // Switch to interfaces tab
                                }
                            }

                            // x and Esc keep cross-tab fallbacks here so
                            // clear / filter-clear / tab-back still work
                            // from Details / Interfaces / Graph / Help
                            // (OverviewTab only claims them on Overview).
                            (KeyCode::Char('x'), _)
                                if clear_all_with_confirmation(&mut ui_state, app) =>
                            {
                                needs_data_refresh = true;
                            }

                            (KeyCode::Esc, _) => {
                                if !ui_state.filter_query.is_empty() {
                                    ui_state.clear_filter();
                                    needs_data_refresh = true;
                                } else if ui_state.selected_tab != 0 {
                                    ui_state.selected_tab = 0;
                                }
                            }

                            _ => {}
                        }
                    }
                } // end Event::Key
                _ => {} // ignore resize, focus, paste, etc.
            } // end match event
        } // end if poll
    } // end loop

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
