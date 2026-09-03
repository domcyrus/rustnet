use anyhow::{Context, Result};
use log::{LevelFilter, error, info, warn};
use ratatui::prelude::CrosstermBackend;
use rustnet_monitor::{app, cli, config, network, ui};
use simplelog::{ConfigBuilder, WriteLogger};
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::time::Duration;

fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let headless = matches.get_flag("headless");

    // Never start terminal control or privileged capture accidentally from a
    // pipe, scheduler, or service. Machine consumers must opt in explicitly.
    if !headless && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        anyhow::bail!(
            "interactive mode requires a terminal; use --headless for scripts and services"
        );
    }

    // Clap handles --help and --version before this point, so both remain
    // available even when Npcap is not installed. The Npcap DLLs are
    // delay-loaded so Windows can enter main() before resolving those imports.
    #[cfg(target_os = "windows")]
    initialize_windows_npcap()?;

    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level)?;
    }

    // Check privileges BEFORE initializing TUI (so error messages are visible)
    check_privileges_early()?;

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

    if let Some(pcapng_path) = matches.get_one::<String>("pcapng-export") {
        config.pcapng_export_file = Some(pcapng_path.to_string());
        info!("PCAPNG export enabled: {}", pcapng_path);
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

    if !headless {
        // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
        let no_color =
            matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
        if no_color {
            info!("Colors disabled (NO_COLOR)");
            ui::set_no_color(true);
        }

        // Color theme: CLI --theme > config file > muted default. Warnings go
        // to stderr here, before the terminal enters raw mode.
        let user_config = config::load();
        let theme_name = matches
            .get_one::<String>("theme")
            .map(String::as_str)
            .or(user_config.theme.as_deref())
            .unwrap_or("muted");
        let preset = ui::ThemePreset::from_name(theme_name).unwrap_or_else(|| {
            // Only reachable via the config file; clap validates the CLI value.
            eprintln!("rustnet: unknown theme {theme_name:?} in config, using \"muted\"");
            ui::ThemePreset::Muted
        });
        let mut spec = ui::ThemeSpec::builtin(preset);
        for (token, value) in &user_config.overrides {
            if let Err(e) = spec.set_token(token, value) {
                eprintln!("rustnet: ignoring theme override {token:?}: {e}");
            }
        }
        info!("Using {preset:?} color theme");
        // ANSI Gray (the muted/label text tier) is nearly unreadable on light
        // backgrounds, so ask the terminal for its background (OSC 11) and
        // darken those tiers when it reports a light one.
        if !no_color && ui::detect_light_background() == Some(true) {
            info!("Light terminal background detected; darkening gray text tiers");
            spec.adapt_to_light_background();
        }
        ui::set_theme(ui::Theme::resolve(&spec, ui::detect_truecolor()));
    }

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

    // Kubernetes pod/container attribution mode (values validated by clap)
    #[cfg(feature = "kubernetes")]
    if let Some(mode) = matches.get_one::<String>("kubernetes")
        && let Some(parsed) = network::kubernetes::KubernetesMode::parse(mode)
    {
        config.kubernetes_mode = parsed;
        info!("Kubernetes attribution mode: {}", mode);
    }

    // Resolve the identity to drop root to after privileged init (Linux,
    // macOS, and FreeBSD): the invoking sudo user, or nobody when started as
    // plain root.
    // Resolved before output files are opened so they can be chowned to the
    // target user. Retained descriptors remain usable after the drop, and the
    // resulting files have ownership consistent with the runtime identity.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let uid_drop_target = if matches.get_flag("no-uid-drop") {
        info!("Root uid drop disabled by --no-uid-drop");
        None
    } else {
        rustnet_sandbox::privdrop::resolve_drop_target()
    };

    let mut output_handles = app::AppOutputHandles::default();

    // Open JSONL outputs before sandboxing and uid drop. The descriptors stay
    // open for the whole run: ownership changes alone are not sufficient for a
    // path under a directory such as /root, which the drop target cannot
    // traverse when trying to reopen the file.
    if let Some(ref json_log_path) = config.json_log_file {
        let file = app::open_private_append_file(json_log_path).map_err(|e| {
            anyhow::anyhow!("Failed to open JSON log file '{}': {}", json_log_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "JSON log", json_log_path);
        output_handles.json_log = Some(file);
    }

    // Pre-create the PCAP export file and retain both it and its sidecar JSONL
    // descriptor.
    // This must be done BEFORE the sandbox is applied so the files exist when
    // adding rules: Landlock requires an open FD to scope a rule to a file, so
    // a not-yet-existing path falls back to granting write on the whole parent
    // directory. Pre-creating keeps the write rule file-scoped. The PCAP
    // serializer receives this exact descriptor instead of reopening the path.
    //
    // Done before terminal setup: pre-creation can fail hard (see below), and we
    // want the error to print to a normal terminal rather than into the TUI
    // alt-screen (which would also leave the terminal in raw mode).
    let mut pcap_export_file = None;
    if let Some(ref pcap_path) = config.pcap_export_file {
        let jsonl_path = format!("{}.connections.jsonl", pcap_path);
        for (label, path) in [("PCAP", pcap_path.as_str()), ("sidecar JSONL", &jsonl_path)] {
            // Fail hard rather than continue: if we can't safely create the file
            // (e.g. the path is a symlink, rejected by O_NOFOLLOW), aborting now
            // is the only way the protection is meaningful.
            let file = app::precreate_private_file(path).map_err(|e| {
                anyhow::anyhow!("Failed to pre-create {} file '{}': {}", label, path, e)
            })?;
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            chown_to_uid_drop_target(&file, uid_drop_target, label, path);
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            let _ = &file;

            if label == "PCAP" {
                pcap_export_file = Some(file);
            } else {
                output_handles.pcap_sidecar = Some(file);
            }
        }
    }

    if let Some(ref pcapng_path) = config.pcapng_export_file {
        let file = app::precreate_private_file(pcapng_path).map_err(|e| {
            anyhow::anyhow!("Failed to pre-create PCAPNG file '{}': {}", pcapng_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "PCAPNG", pcapng_path);
        output_handles.pcapng_export = Some(file);
    }

    let mut app =
        app::App::new_with_preopened_pcap(config.clone(), output_handles, pcap_export_file)?;
    let (process_status, capture_status) = app.start()?;
    info!("Application started");

    // Process attribution initialization, including eBPF loading, completed
    // synchronously. The prepared lookup is moved into its worker only after
    // the sandbox is applied.
    match process_status {
        app::InitStatus::Ready => info!("process detection initialized, safe to apply sandbox"),
        app::InitStatus::Failed(message) => {
            warn!("process detection initialization failed: {}", message)
        }
    }

    // Capture initialization ran synchronously and returned a typed result.
    // The TUI deliberately preserves its process-only fallback on failure.
    match capture_status {
        app::InitStatus::Ready => info!("packet capture initialized, safe to apply sandbox"),
        app::InitStatus::Failed(message) => {
            if headless {
                let stop_report = app.stop();
                ensure_clean_shutdown(stop_report)?;
                anyhow::bail!("packet capture initialization failed: {message}");
            }
            warn!("packet capture initialization failed: {}", message)
        }
    }

    // Apply the sandbox (rustnet-sandbox crate: Landlock + capability drops
    // on Linux, uid drop + Seatbelt on macOS, restricted token + job object
    // on Windows, uid drop on FreeBSD).
    // This must be done AFTER process detection and capture init because:
    // - eBPF programs need to be loaded first (requires CAP_BPF + CAP_PERFMON)
    // - Packet capture handles need to be opened first (raw sockets, /dev/bpf*)
    // - Log files need to be created first
    let worker_startup_permit = {
        use rustnet_sandbox::{SandboxConfig, SandboxMode};
        use std::path::PathBuf;

        let sandbox_mode = SandboxMode::from_flags(
            matches.get_flag("no-sandbox"),
            matches.get_flag("sandbox-strict"),
        );

        // Collect read paths (GeoIP databases). Exclude the bare current-directory
        // entry: a Landlock PathBeneath rule on "." grants recursive read access to
        // the entire CWD subtree (e.g. all of $HOME when rustnet is launched from
        // there), which defeats the point of the read-path whitelist. The concrete
        // GeoIP locations (resources/geoip2, XDG/system dirs) stay covered.
        //
        // When Kubernetes attribution is enabled (Linux), the resolver also reads
        // pod and container names from the kubelet log directories; these need
        // explicit read access or the periodic metadata refresh would be denied
        // once Landlock applies.
        #[cfg(target_os = "linux")]
        let read_paths: Vec<PathBuf> = {
            use network::geoip::GeoIpResolver;
            let paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
                .into_iter()
                .filter(|p| p.exists() && p.as_os_str() != ".")
                .collect();
            #[cfg(feature = "kubernetes")]
            let paths = {
                let mut paths = paths;
                if config.kubernetes_mode.enabled() {
                    for dir in ["/var/log/containers", "/var/log/pods"] {
                        let pb = PathBuf::from(dir);
                        if pb.exists() {
                            paths.push(pb);
                        }
                    }
                }
                paths
            };
            paths
        };

        // On macOS user-specified GeoIP paths take priority; otherwise include
        // auto-discovery search paths so the file-read deny on /Users doesn't
        // block them.
        #[cfg(target_os = "macos")]
        let read_paths: Vec<PathBuf> = {
            use network::geoip::GeoIpResolver;
            let mut paths: Vec<PathBuf> = [
                &config.geoip_country_path,
                &config.geoip_asn_path,
                &config.geoip_city_path,
            ]
            .into_iter()
            .flatten()
            .map(PathBuf::from)
            .collect();
            if paths.is_empty() && !config.disable_geoip {
                // Use auto-discovery search paths (directories, not individual files)
                paths.extend(
                    GeoIpResolver::get_search_paths()
                        .into_iter()
                        .filter(|p| p.exists()),
                );
            }
            paths
        };

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let read_paths: Vec<PathBuf> = Vec::new();

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            read_paths,
            // Every runtime output is already open and retained. No pathname
            // write grants are needed, which also avoids a rename/swap window
            // between the secure open and sandbox rule construction.
            write_paths: Vec::new(),
            ..SandboxConfig::default()
        };
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        let sandbox_config = SandboxConfig {
            drop_uid: uid_drop_target,
            ..sandbox_config
        };

        app.apply_sandbox(&sandbox_config)?
    };

    // Before this point the platform default remains in effect, so SIGTERM or
    // SIGHUP can still terminate a slow synchronous capture/process setup.
    install_signal_handlers()?;

    // Now that the sandbox has been applied on the main thread, start the worker
    // threads (DPI packet processors, enrichment, snapshot, cleanup, collectors).
    // On Linux these inherit the Landlock domain and the dropped capabilities, so
    // a compromise in a DPI parser is contained even when running as root.
    app.start_workers(worker_startup_permit)?;

    if headless {
        return run_headless(&matches, &mut app);
    }

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    let res = run_ui_loop(&mut terminal, &app);

    let stop_report = app.stop();
    ui::restore_terminal(&mut terminal)?;

    ensure_clean_shutdown(stop_report)?;
    res.context("terminal UI failed")?;

    info!("RustNet Monitor shutting down");
    Ok(())
}

fn run_headless(matches: &clap::ArgMatches, app: &mut app::App) -> Result<()> {
    let format = matches
        .get_one::<String>("output")
        .map(|value| value.parse::<rustnet_monitor::headless::HeadlessFormat>())
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    let options = rustnet_monitor::headless::HeadlessOptions {
        format,
        duration: matches
            .get_one::<u64>("duration")
            .map(|seconds| Duration::from_secs(*seconds)),
        filter_query: matches.get_one::<String>("filter").cloned(),
    };
    let outcome =
        match rustnet_monitor::headless::run(app, io::stdout(), &options, &SHUTDOWN_REQUESTED) {
            Ok(outcome) => outcome,
            Err(error) => {
                let stop_report = app.stop();
                if let Err(shutdown_error) = ensure_clean_shutdown(stop_report) {
                    return Err(anyhow::anyhow!("{error}; {shutdown_error}"));
                }
                return Err(error);
            }
        };
    ensure_clean_shutdown(outcome.stop_report)
}

fn ensure_clean_shutdown(report: app::StopReport) -> Result<()> {
    if report.timed_out_workers > 0 || report.panicked_workers > 0 || report.output_errors > 0 {
        anyhow::bail!(
            "runtime shutdown failed: {} worker(s) timed out, {} worker(s) panicked, {} output operation(s) failed",
            report.timed_out_workers,
            report.panicked_workers,
            report.output_errors
        );
    }
    Ok(())
}

fn setup_logging(level: LevelFilter) -> Result<()> {
    // The log directory is resolved relative to the current working directory.
    // rustnet typically runs as root, so a pre-planted symlink at `logs/` (e.g.
    // `logs -> /etc`) would let an attacker who controls the launch directory
    // redirect root-owned writes to an arbitrary location. Refuse to use it if
    // it is a symlink (symlink_metadata does not follow the link).
    let log_dir = Path::new("logs");
    #[cfg(unix)]
    if let Ok(meta) = fs::symlink_metadata(log_dir)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!("refusing to use log directory 'logs': it is a symlink");
    }

    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
        // Restrict the directory to the owner: the diagnostic log can contain
        // connection metadata and (at debug/trace) DNS/SNI hostnames, and rustnet
        // typically runs as root, so it must not be world-readable. Mirrors the
        // 0o600 treatment of the JSON/PCAP outputs.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(log_dir, fs::Permissions::from_mode(0o700)) {
                warn!("Failed to set logs directory permissions: {}", e);
            }
        }
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    // The path is predictable (timestamped), so it gets the same
    // symlink-refusing, private-mode open as the other output files.
    let log_file = app::precreate_private_file(&log_file_path)?;

    // `target` names the emitting subsystem (e.g. `network::dpi::dns`); the
    // banner below identifies the binary.
    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();

    WriteLogger::init(level, config, log_file)?;

    // Startup banner: one identifying header so a user grepping a
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

/// Hand an output file over to the uid-drop target.
///
/// Retained descriptors remain usable regardless of path traversal, but the
/// resulting file should still belong to the runtime identity. Best-effort:
/// failure does not prevent the privilege drop.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn chown_to_uid_drop_target(
    file: &fs::File,
    target: Option<rustnet_sandbox::privdrop::DropTarget>,
    label: &str,
    path: &str,
) {
    if let Some(target) = target
        && let Err(e) = rustnet_sandbox::privdrop::chown_to_target(file, target)
    {
        warn!(
            "Failed to chown {} file '{}' to uid {}: {} (the file may not be writable after the root uid drop)",
            label, path, target.uid, e
        );
    }
}

use ui::{clear_all_with_confirmation, copy_to_clipboard, sort_connections};

/// Set from the signal handler; the UI loop exits through its normal
/// cleanup path (flush outputs, restore the terminal) when it flips.
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Route termination signals through the regular shutdown path so output is
/// flushed and an interactive terminal can be restored.
#[cfg(unix)]
fn install_signal_handlers() -> io::Result<()> {
    extern "C" fn on_signal(_sig: libc::c_int) {
        // Only async-signal-safe work here: set the flag, nothing else.
        SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let handler: extern "C" fn(libc::c_int) = on_signal;
    // SAFETY: installing a handler that only stores to an atomic.
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        // SAFETY: installing a handler that only stores to an atomic.
        if unsafe { libc::signal(signal, handler as libc::sighandler_t) } == libc::SIG_ERR {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn install_signal_handlers() -> io::Result<()> {
    use windows::Win32::Foundation::TRUE;
    use windows::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
    use windows::core::BOOL;

    unsafe extern "system" fn on_console_control(control: u32) -> BOOL {
        if matches!(control, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
            SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
            TRUE
        } else {
            BOOL(0)
        }
    }

    // SAFETY: the process-lifetime callback only stores to an atomic.
    unsafe { SetConsoleCtrlHandler(Some(on_console_control), true) }
        .map_err(|error| io::Error::other(format!("failed to install console handler: {error}")))
}

#[cfg(not(any(unix, windows)))]
fn install_signal_handlers() -> io::Result<()> {
    Ok(())
}

fn run_ui_loop<B: ratatui::prelude::Backend>(
    terminal: &mut ui::Terminal<B>,
    app: &app::App,
) -> Result<()>
where
    <B as ratatui::prelude::Backend>::Error: Send + Sync + 'static,
{
    let tick_rate = Duration::from_millis(200);
    // Idle redraw ceiling. Terminal emulators repaint whenever output
    // arrives (iTerm2's renderer repaints the window on any content
    // change), so the draw cadence directly sets the terminal's CPU
    // cost. Input and data changes redraw immediately; graph animation
    // and the live sidebar counters advance at this heartbeat.
    let redraw_interval = Duration::from_millis(500);
    // Full-size traffic waves scroll between 500ms samples in smaller
    // increments. The one-row Overview waves keep the lower idle repaint rate
    // because their four-dot vertical resolution makes faster motion flicker.
    let wave_redraw_interval = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut last_draw = std::time::Instant::now();
    let mut needs_redraw = true; // first frame
    let mut ui_state = ui::UiState::default();
    let (has_country_db, _, _) = app.get_geoip_status();
    ui_state.has_geoip = has_country_db;
    let mut click_regions = ui::ClickableRegions::default();

    // Data state persists across loop iterations; only refreshed on timer tick
    // or when an event changes the underlying data (filter, sort, historic toggle, etc.)
    let mut connections: Vec<network::types::Connection> = Vec::new();
    let mut grouped_rows: Vec<ui::GroupedRow<'_>> = Vec::new();
    let mut stats = app.get_stats();
    let mut needs_data_refresh = true;
    let mut needs_regroup = false;
    let mut last_seen_generation = u64::MAX; // force the first refresh

    'main: loop {
        if shutdown_requested() {
            info!("Termination signal received, shutting down");
            break 'main;
        }

        // Refresh connection data only when needed:
        // - On timer tick (every 200ms), but only if the snapshot actually
        //   changed since we last consumed it (it rebuilds every
        //   refresh-interval ms, so most ticks would re-clone and re-sort
        //   identical data)
        // - When an event changes filter, sort, or data source
        let tick_elapsed = last_tick.elapsed() >= tick_rate;
        let snapshot_generation = app.snapshot_generation();
        if tick_elapsed {
            // Keep counters (packets processed/dropped, etc.) live on every
            // tick even when the connection list is unchanged.
            stats = app.get_stats();
            last_tick = std::time::Instant::now();
        }
        if needs_data_refresh || (tick_elapsed && snapshot_generation != last_seen_generation) {
            connections = if !ui_state.has_active_filter() && !ui_state.filter_mode {
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
            last_seen_generation = snapshot_generation;
            needs_data_refresh = false;
            needs_regroup = false;
            needs_redraw = true;
        } else if needs_regroup {
            // Only rebuild grouped rows from existing connections
            // (e.g., after expand/collapse or grouping toggle)
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            needs_regroup = false;
            needs_redraw = true;
        }

        // Ensure we have a valid selection (handles connection removals)
        if ui_state.grouping_enabled {
            let selected_idx = ui_state
                .ensure_valid_grouped_selection(&grouped_rows)
                .unwrap_or(0);
            ui_state.grouped_scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.grouped_scroll_offset,
                ui_state.visible_rows,
                grouped_rows.len(),
            );
        } else {
            let selected_idx = ui_state.ensure_valid_selection(&connections).unwrap_or(0);
            ui_state.scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.scroll_offset,
                ui_state.visible_rows,
                connections.len(),
            );
        }

        // Draw the UI, but only when something warrants it: immediately
        // after input or a data change, otherwise at the idle heartbeat.
        // The sidebar counters are live atomics read at render time, so
        // an unconditional draw here would emit fresh cells (and force a
        // terminal repaint) on every 200ms tick even with nothing going on.
        // The startup splash animates faster than the idle heartbeat, so
        // it gets a shorter redraw interval for its ~1s lifetime.
        let idle_redraw = if app.is_loading() {
            Duration::from_millis(100)
        } else if matches!(ui_state.selected_tab, 1 | 3) {
            wave_redraw_interval
        } else {
            redraw_interval
        };
        if needs_redraw || last_draw.elapsed() >= idle_redraw {
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
            last_draw = std::time::Instant::now();
            needs_redraw = false;
        }

        // Update visible rows for page navigation based on terminal height.
        // Chrome rows: tab bar (2) + section title (1) + table header incl.
        // margin (2) + status bar (1) = 6, plus the filter line (1) while a
        // filter is being typed. This must track the layout in `ui::draw`
        // exactly: a confirmed filter keeps no row of its own, so counting
        // one here would scroll the selection a row early and hand the
        // scrollbar a viewport shorter than what is drawn.
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_row_visible() { 7 } else { 6 };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        // Sleep until the next data tick or redraw heartbeat, whichever
        // comes first, unless an event arrives earlier.
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0))
            .min(idle_redraw.saturating_sub(last_draw.elapsed()));

        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
            needs_redraw = true;
        }

        // Handle input events, draining any queued burst (mouse motion,
        // key auto-repeat) before the next iteration so a flood of
        // events costs one redraw instead of one redraw per event.
        let mut poll_timeout = timeout;
        'events: while crossterm::event::poll(poll_timeout)? {
            poll_timeout = Duration::ZERO;
            let event = crossterm::event::read()?;
            match event {
                crossterm::event::Event::Mouse(mouse) => {
                    use crossterm::event::{MouseButton, MouseEventKind};

                    // Active tab's Component gets first crack; currently
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
                        needs_redraw = true;
                        continue 'events;
                    }

                    if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                        {
                            needs_redraw = true;
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
                                    ui::ClickAction::SelectConnectionKey(key) => {
                                        // Keep the grouped selection coherent: adopt the
                                        // clicked connection's group when grouping is on.
                                        if ui_state.grouping_enabled {
                                            for row in &grouped_rows {
                                                if let ui::GroupedRow::Connection {
                                                    process_name,
                                                    connection,
                                                    ..
                                                } = row
                                                    && connection.key() == key
                                                {
                                                    ui_state.selected_group =
                                                        Some(process_name.clone());
                                                    break;
                                                }
                                            }
                                        }
                                        ui_state.set_connection_key(Some(key));
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

                    // Windows crossterm reports Release events too; only
                    // Press is handled so all platforms behave the same.
                    if key.kind != KeyEventKind::Press {
                        continue 'events;
                    }
                    needs_redraw = true;

                    // Give the active tab's Component first crack
                    // at the key (including filter-mode input; OverviewTab
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
                        // tabs.
                        match (key.code, key.modifiers) {
                            (KeyCode::Char('q'), _) => {
                                if ui_state.quit_confirmation {
                                    info!("User confirmed application exit");
                                    break 'main;
                                } else {
                                    info!("User requested quit - showing confirmation");
                                    ui_state.quit_confirmation = true;
                                }
                            }

                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                info!("User requested immediate exit with Ctrl+C");
                                break 'main;
                            }

                            (KeyCode::Tab, KeyModifiers::NONE)
                            | (KeyCode::Char(']'), KeyModifiers::NONE) => {
                                ui_state.next_tab();
                            }

                            (KeyCode::BackTab, _)
                            | (KeyCode::Tab, KeyModifiers::SHIFT)
                            | (KeyCode::Char('['), KeyModifiers::NONE) => {
                                ui_state.prev_tab();
                            }

                            // Direct-jump shortcuts to each tab (mirrors the
                            // numeric-jump convention used by htop, tmux, etc.).
                            // Tab indices match `TAB_TITLES` in
                            // `ui::widgets::tabs_bar`: Overview, Details,
                            // Activity, Graph, Host.
                            (KeyCode::Char('1'), KeyModifiers::NONE) => ui_state.jump_to_tab(0),
                            (KeyCode::Char('2'), KeyModifiers::NONE) => ui_state.jump_to_tab(1),
                            (KeyCode::Char('3'), KeyModifiers::NONE) => ui_state.jump_to_tab(2),
                            (KeyCode::Char('4'), KeyModifiers::NONE) => ui_state.jump_to_tab(3),
                            (KeyCode::Char('5'), KeyModifiers::NONE) => ui_state.jump_to_tab(4),

                            // Help overlay, kept because `h` is the universal
                            // mnemonic for help across less / man / vim / tmux.
                            (KeyCode::Char('h'), _) => {
                                ui_state.show_help = true;
                                ui_state.help_scroll.reset();
                            }

                            // x and Esc keep cross-tab fallbacks here so
                            // clear / filter-clear / tab-back still work
                            // from Details / Activity / Graph / Host
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
                crossterm::event::Event::Resize(..) => {
                    needs_redraw = true;
                }
                _ => {} // ignore focus, paste, etc.
            } // end match event
        } // end event drain
    } // end loop

    Ok(())
}

/// Check if we have privileges for packet capture before starting the TUI
fn check_privileges_early() -> Result<()> {
    match network::privileges::check_packet_capture_privileges() {
        Ok(status) if !status.has_privileges => {
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
            eprintln!("Warning: Failed to check privileges: {}", e);
            eprintln!("Continuing anyway, but packet capture may fail...\n");
        }
        _ => {}
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn initialize_windows_npcap() -> Result<()> {
    use anyhow::{Context, anyhow};
    use windows::Win32::System::LibraryLoader::{LoadLibraryW, SetDllDirectoryW};
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows::core::{PCWSTR, w};

    // Windows paths can exceed MAX_PATH when long-path support is enabled.
    // The system directory is normally short, but a full-size UTF-16 buffer
    // avoids depending on that configuration detail.
    let mut system_directory = vec![0u16; 32_768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut system_directory)) } as usize;
    if length == 0 {
        return Err(anyhow!(windows::core::Error::from_thread()))
            .context("Failed to locate the Windows system directory");
    }
    if length >= system_directory.len() {
        return Err(anyhow!(
            "Windows system directory path exceeds the supported length"
        ));
    }

    system_directory.truncate(length);
    if system_directory.last() != Some(&u16::from(b'\\')) {
        system_directory.push(u16::from(b'\\'));
    }
    system_directory.extend("Npcap".encode_utf16());
    system_directory.push(0);

    let npcap_directory =
        String::from_utf16_lossy(&system_directory[..system_directory.len().saturating_sub(1)]);

    if let Err(error) = unsafe { SetDllDirectoryW(PCWSTR(system_directory.as_ptr())) } {
        return Err(anyhow!(error)).with_context(|| {
            format!("Failed to add the Npcap directory '{npcap_directory}' to the DLL search path")
        });
    }

    // Keep the module loaded for the life of the process. When the first pcap
    // function is called, the delay-load helper reuses this module by name.
    if let Err(error) = unsafe { LoadLibraryW(w!("wpcap.dll")) } {
        eprintln!(
            "\n╔═══════════════════════════════════════════════════════════════════════════╗"
        );
        eprintln!("║                          MISSING DEPENDENCY                               ║");
        eprintln!("╚═══════════════════════════════════════════════════════════════════════════╝");
        eprintln!();
        eprintln!("RustNet requires Npcap for packet capture on Windows.");
        eprintln!();
        eprintln!("  ✗ Could not load wpcap.dll from {npcap_directory}");
        eprintln!("    {error}");
        eprintln!();
        eprintln!("To fix this:");
        eprintln!();
        eprintln!("  1. Download Npcap from: https://npcap.com/dist/");
        eprintln!("  2. Run the installer");
        eprintln!("  3. Complete the installation with the default settings");
        eprintln!();
        eprintln!("After installation, restart your terminal and try again.");
        eprintln!();

        return Err(anyhow!(
            "Npcap is not installed or its runtime could not be loaded"
        ));
    }

    Ok(())
}
