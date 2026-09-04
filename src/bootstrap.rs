//! CLI startup, privileged resource preparation, and frontend dispatch.
//!
//! Capture and process lookup prepare synchronously before sandboxing.
//! Only the sandbox handoff permits long-lived workers to start.

use crate::{app, cli, config, network, ui};
use anyhow::{Context, Result};
use log::{LevelFilter, info, warn};
use ratatui::prelude::CrosstermBackend;
use simplelog::{ConfigBuilder, WriteLogger};
use std::fs;
use std::io::{self, IsTerminal};
use std::path::Path;
use std::time::Duration;

/// Parse CLI options and initialize the selected frontend.
pub fn run() -> Result<()> {
    let matches = cli::build_cli().get_matches();
    let headless = matches.get_flag("headless");

    // Never start terminal control or privileged capture accidentally from a
    // pipe, scheduler, or service. Machine consumers must opt in explicitly.
    if !headless && (!io::stdin().is_terminal() || !io::stdout().is_terminal()) {
        anyhow::bail!(
            "interactive mode requires a terminal; use --headless for scripts and services"
        );
    }

    let mut config = app::Config {
        json_log_file: matches.get_one::<String>("json-log").cloned(),
        pcap_export_file: matches.get_one::<String>("pcap-export").cloned(),
        pcapng_export_file: matches.get_one::<String>("pcapng-export").cloned(),
        ..app::Config::default()
    };
    // Validate before logging, Npcap loading, privilege checks, or output
    // creation so a bad combination cannot truncate an existing destination.
    app::validate_output_paths(&config).context("invalid output paths")?;

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
        info!("JSON logging enabled: {}", json_log_path);
    }

    if let Some(pcap_path) = matches.get_one::<String>("pcap-export") {
        info!("PCAP export enabled: {}", pcap_path);
    }

    if let Some(pcapng_path) = matches.get_one::<String>("pcapng-export") {
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

    let res = crate::tui::run(&mut terminal, &app, &SHUTDOWN_REQUESTED);

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
        .map(|value| value.parse::<crate::headless::HeadlessFormat>())
        .transpose()
        .map_err(anyhow::Error::msg)?
        .unwrap_or_default();
    let options = crate::headless::HeadlessOptions {
        format,
        duration: matches
            .get_one::<u64>("duration")
            .map(|seconds| Duration::from_secs(*seconds)),
        filter_query: matches.get_one::<String>("filter").cloned(),
    };
    let outcome = match crate::headless::run(app, io::stdout(), &options, &SHUTDOWN_REQUESTED) {
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

/// Set from the signal handler; the UI loop exits through its normal
/// cleanup path (flush outputs, restore the terminal) when it flips.
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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
