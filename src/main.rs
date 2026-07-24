use anyhow::Result;
use log::{LevelFilter, error, info, warn};
use ratatui::prelude::CrosstermBackend;
use rustnet_monitor::{app, cli, network, ui};
use simplelog::{ConfigBuilder, WriteLogger};
use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

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

    // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
    let no_color =
        matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
    if no_color {
        info!("Colors disabled (NO_COLOR)");
        ui::set_no_color(true);
    }

    // Color theme preset
    let theme_preset = match matches.get_one::<String>("theme").map(String::as_str) {
        Some("classic") => ui::ThemePreset::Classic,
        _ => ui::ThemePreset::Muted,
    };
    info!("Using {theme_preset:?} color theme");
    ui::set_theme_preset(theme_preset);

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
        network::platform::privdrop::resolve_drop_target()
    };

    let mut output_handles = app::AppOutputHandles::default();

    // Open JSONL outputs before sandboxing and uid drop. The descriptors stay
    // open for the whole run: ownership changes alone are not sufficient for a
    // path under a directory such as /root, which the drop target cannot
    // traverse when trying to reopen the file.
    if let Some(ref json_log_path) = config.json_log_file {
        let file = open_private_append_file(json_log_path).map_err(|e| {
            anyhow::anyhow!("Failed to open JSON log file '{}': {}", json_log_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "JSON log", json_log_path);
        output_handles.json_log = Some(file);
    }

    // Pre-create the PCAP export file and retain its sidecar JSONL descriptor.
    // This must be done BEFORE the sandbox is applied so the files exist when
    // adding rules: Landlock requires an open FD to scope a rule to a file, so
    // a not-yet-existing path falls back to granting write on the whole parent
    // directory. Pre-creating keeps the write rule file-scoped. The PCAP writer
    // later reopens the path with truncation while it still has startup
    // privileges, so a zero-byte file is fine.
    //
    // Done before terminal setup: pre-creation can fail hard (see below), and we
    // want the error to print to a normal terminal rather than into the TUI
    // alt-screen (which would also leave the terminal in raw mode).
    if let Some(ref pcap_path) = config.pcap_export_file {
        let jsonl_path = format!("{}.connections.jsonl", pcap_path);
        for (label, path) in [("PCAP", pcap_path.as_str()), ("sidecar JSONL", &jsonl_path)] {
            // Fail hard rather than continue: if we can't safely create the file
            // (e.g. the path is a symlink, rejected by O_NOFOLLOW), aborting now
            // is the only way the protection is meaningful. The PCAP itself is
            // later written by libpcap's pcap_dump_open, which does NOT honor
            // O_NOFOLLOW, so a warn-and-continue here would let libpcap follow an
            // attacker-controlled symlink and write the capture there anyway.
            let file = precreate_private_file(path).map_err(|e| {
                anyhow::anyhow!("Failed to pre-create {} file '{}': {}", label, path, e)
            })?;
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
            chown_to_uid_drop_target(&file, uid_drop_target, label, path);
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            let _ = &file;

            if label == "sidecar JSONL" {
                output_handles.pcap_sidecar = Some(file);
            }
        }
    }

    if let Some(ref pcapng_path) = config.pcapng_export_file {
        let file = precreate_private_file(pcapng_path).map_err(|e| {
            anyhow::anyhow!("Failed to pre-create PCAPNG file '{}': {}", pcapng_path, e)
        })?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
        chown_to_uid_drop_target(&file, uid_drop_target, "PCAPNG", pcapng_path);
        output_handles.pcapng_export = Some(file);
    }

    // Set up terminal
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    // Create and start the application
    let mut app = app::App::new_with_output_handles(config.clone(), output_handles)?;
    let (process_ready_rx, capture_ready_rx) = app.start()?;
    info!("Application started");

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

    // Also wait for the capture thread to finish opening the capture device.
    // The open runs on a background thread and needs the startup privileges;
    // without this synchronization the uid drop (Linux/FreeBSD) or sandbox
    // could win the race and the open would fail with EPERM, leaving the UI
    // running with no traffic.
    match capture_ready_rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(()) => info!("Packet capture initialized, safe to apply sandbox"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!("Timed out waiting for packet capture init, applying sandbox anyway");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("Capture thread exited early, applying sandbox anyway");
        }
    }

    // Apply Landlock sandbox (Linux only)
    // This must be done AFTER process detection is initialized because:
    // - eBPF programs need to be loaded first (requires CAP_BPF + CAP_PERFMON)
    // - Packet capture handles need to be opened first (access to /dev)
    // - Log files need to be created first
    #[cfg(target_os = "linux")]
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

        // Collect read paths (GeoIP databases). Exclude the bare current-directory
        // entry: a Landlock PathBeneath rule on "." grants recursive read access to
        // the entire CWD subtree (e.g. all of $HOME when rustnet is launched from
        // there), which defeats the point of the read-path whitelist. The concrete
        // GeoIP locations (resources/geoip2, XDG/system dirs) stay covered.
        #[cfg(not(feature = "kubernetes"))]
        let read_paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
            .into_iter()
            .filter(|p| p.exists() && p.as_os_str() != ".")
            .collect();

        // When Kubernetes attribution is enabled, the resolver also reads pod
        // and container names from the kubelet log directories. /proc is
        // already granted below for process lookup; these need explicit read
        // access or the periodic metadata refresh would be denied once Landlock
        // applies.
        #[cfg(feature = "kubernetes")]
        let read_paths: Vec<PathBuf> = {
            let mut paths: Vec<PathBuf> = GeoIpResolver::get_search_paths()
                .into_iter()
                .filter(|p| p.exists() && p.as_os_str() != ".")
                .collect();
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

        if let Some(pcapng_path) = &config.pcapng_export_file {
            write_paths.push(PathBuf::from(pcapng_path));
        }

        let sandbox_config = SandboxConfig {
            mode: sandbox_mode,
            block_network: true, // RustNet is passive, doesn't need TCP
            read_paths,
            write_paths,
            drop_uid: uid_drop_target,
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
                    uid_dropped: result.uid_dropped,
                    landlock_available: result.landlock_available,
                    fs_restricted: result.landlock_fs_applied,
                    net_restricted: result.landlock_net_applied,
                    scope_restricted: result.landlock_scope_applied,
                    landlock_abi: result.landlock_effective_abi,
                    no_new_privs: result.no_new_privs,
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
                    uid_dropped: false,
                    landlock_available: false,
                    fs_restricted: false,
                    net_restricted: false,
                    scope_restricted: false,
                    landlock_abi: None,
                    no_new_privs: false,
                });
            }
        }
    }

    // Drop root privileges (macOS only). Done after process detection init
    // (capture fds are open, PKTAP is set up) and BEFORE Seatbelt, so the
    // profile does not need to allow the setuid/setgid syscalls. Compiled
    // without the macos-sandbox feature too; only the flag lookups depend on
    // the feature (the flags do not exist in non-sandbox builds).
    #[cfg(target_os = "macos")]
    let uid_dropped = {
        #[cfg(feature = "macos-sandbox")]
        let (skip, strict) = (
            matches.get_flag("no-sandbox"),
            matches.get_flag("sandbox-strict"),
        );
        #[cfg(not(feature = "macos-sandbox"))]
        let (skip, strict) = (false, false);

        match uid_drop_target {
            Some(target) if !skip => match network::platform::privdrop::drop_to(target) {
                Ok(()) => {
                    info!(
                        "Dropped root privileges to uid {} gid {} (verified); lsof-fallback \
                         process attribution is now limited to that user's processes (PKTAP \
                         attribution unaffected)",
                        target.uid, target.gid
                    );
                    true
                }
                Err(e) => {
                    if strict {
                        return Err(e.context("Strict mode requires the root uid drop to succeed"));
                    }
                    warn!("Failed to drop root uid/gid: {}", e);
                    false
                }
            },
            Some(_) => {
                info!("Root uid drop skipped (--no-sandbox)");
                false
            }
            None => false,
        }
    };
    #[cfg(all(target_os = "macos", not(feature = "macos-sandbox")))]
    let _ = uid_dropped;

    // Drop root privileges (FreeBSD only). Done after process detection init,
    // when the BPF capture fds are open and nothing needs root anymore. There
    // is no sandbox on FreeBSD yet (Capsicum is planned), so until then this
    // is the primary containment.
    #[cfg(target_os = "freebsd")]
    if let Some(target) = uid_drop_target {
        match network::platform::privdrop::drop_to(target) {
            Ok(()) => info!(
                "Dropped root privileges to uid {} gid {} (verified); sockstat process \
                 attribution is now limited to that user's processes",
                target.uid, target.gid
            ),
            Err(e) => warn!("Failed to drop root uid/gid: {}", e),
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
            pcapng_export_path: config.pcapng_export_file,
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
                    uid_dropped,
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
                    uid_dropped,
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

    // Now that the sandbox has been applied on the main thread, start the worker
    // threads (DPI packet processors, enrichment, snapshot, cleanup, collectors).
    // On Linux these inherit the Landlock domain and the dropped capabilities, so
    // a compromise in a DPI parser is contained even when running as root.
    app.start_workers()?;

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

    // Create timestamped log file name
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_file_path = log_dir.join(format!("rustnet_{}.log", timestamp));

    // On Unix, open with O_NOFOLLOW so a symlink pre-planted at the (predictable,
    // timestamped) path cannot redirect the write, and set the 0o600 mode at
    // creation time to avoid a create-then-chmod window where the file is briefly
    // world-readable.
    #[cfg(unix)]
    let log_file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&log_file_path)?
    };
    #[cfg(not(unix))]
    let log_file = fs::File::create(&log_file_path)?;

    // Enable the `target` field on every log line so each entry carries
    // the originating module (e.g. `network::dpi::dns`). Combined with
    // the startup-banner lines below, this addresses #310 — users now
    // see both the program identity (name/version/pid) at the top of
    // the file and which subsystem emitted each subsequent line.
    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();

    WriteLogger::init(level, config, log_file)?;

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

/// Hand an output file over to the uid-drop target.
///
/// Retained descriptors remain usable regardless of path traversal, but the
/// resulting file should still belong to the runtime identity. Best-effort:
/// failure does not prevent the privilege drop.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
fn chown_to_uid_drop_target(
    file: &fs::File,
    target: Option<network::platform::privdrop::DropTarget>,
    label: &str,
    path: &str,
) {
    if let Some(target) = target
        && let Err(e) = network::platform::privdrop::chown_to_target(file, target)
    {
        warn!(
            "Failed to chown {} file '{}' to uid {}: {} (the file may not be writable after the root uid drop)",
            label, path, target.uid, e
        );
    }
}

fn precreate_private_file(path: &str) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        fs::File::create(path)
    }
}

/// Open an append-only private output before privileges are reduced.
///
/// Unlike [`precreate_private_file`], this preserves existing contents because
/// `--json-log` has append semantics.
fn open_private_append_file(path: &str) -> io::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    {
        fs::OpenOptions::new().create(true).append(true).open(path)
    }
}

#[cfg(all(test, unix))]
mod output_file_tests {
    use super::open_private_append_file;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "rustnet-output-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            ScratchDir(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn creates_file_with_0600_permissions() {
        let dir = ScratchDir::new("perms");
        let path = dir.path("events.log");

        let file =
            open_private_append_file(path.to_str().unwrap()).expect("fresh open should succeed");
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new output must be created mode 0o600");
    }

    #[test]
    fn appends_rather_than_truncates() {
        let dir = ScratchDir::new("append");
        let path = dir.path("events.log");
        let path = path.to_str().unwrap();

        writeln!(open_private_append_file(path).unwrap(), "line1").unwrap();
        writeln!(open_private_append_file(path).unwrap(), "line2").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "line1\nline2\n");
    }

    #[test]
    fn retained_descriptor_survives_inaccessible_parent() {
        let dir = ScratchDir::new("retained");
        let path = dir.path("events.log");
        let mut file = open_private_append_file(path.to_str().unwrap()).unwrap();

        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o000)).unwrap();
        writeln!(file, "still writable").unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "still writable\n");
    }

    #[test]
    fn refuses_symlinked_path() {
        let dir = ScratchDir::new("symlink");
        let target = dir.path("real_target.log");
        let link = dir.path("evil.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let err = open_private_append_file(link.to_str().unwrap())
            .expect_err("O_NOFOLLOW must refuse a symlinked path");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got: {err}"
        );
        assert!(std::fs::read(&target).unwrap().is_empty());
    }
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
    let mut last_seen_generation = u64::MAX; // force the first refresh

    'main: loop {
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
        // margin (2) + status bar (1) = 6, plus the filter line (1) when a
        // filter is being edited or active.
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_mode || ui_state.has_active_filter() {
                7
            } else {
                6
            };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        // Sleep until the next data tick or redraw heartbeat, whichever
        // comes first, unless an event arrives earlier.
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0))
            .min(idle_redraw.saturating_sub(last_draw.elapsed()));

        // Clear clipboard message after timeout
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

                    // On Windows, crossterm reports both Press and Release events
                    // On Linux/macOS, only Press events are reported
                    // Filter to only handle Press events for consistent cross-platform behavior
                    if key.kind != KeyEventKind::Press {
                        continue 'events;
                    }
                    needs_redraw = true;

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
                                    break 'main;
                                } else {
                                    info!("User requested quit - showing confirmation");
                                    ui_state.quit_confirmation = true;
                                }
                            }

                            // Ctrl+C always quits immediately
                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                info!("User requested immediate exit with Ctrl+C");
                                break 'main;
                            }

                            // Tab navigation (forward)
                            (KeyCode::Tab, KeyModifiers::NONE)
                            | (KeyCode::Char(']'), KeyModifiers::NONE) => {
                                ui_state.next_tab();
                            }

                            // Shift+Tab navigation (backward)
                            (KeyCode::BackTab, _)
                            | (KeyCode::Tab, KeyModifiers::SHIFT)
                            | (KeyCode::Char('['), KeyModifiers::NONE) => {
                                ui_state.prev_tab();
                            }

                            // Direct-jump shortcuts to each tab (mirrors the
                            // numeric-jump convention used by htop, tmux, etc.).
                            // Tab indices match `TAB_TITLES` in
                            // `ui::widgets::tabs_bar`: Overview, Details,
                            // Activity, Graph, Help.
                            (KeyCode::Char('1'), KeyModifiers::NONE) => ui_state.jump_to_tab(0),
                            (KeyCode::Char('2'), KeyModifiers::NONE) => ui_state.jump_to_tab(1),
                            (KeyCode::Char('3'), KeyModifiers::NONE) => ui_state.jump_to_tab(2),
                            (KeyCode::Char('4'), KeyModifiers::NONE) => ui_state.jump_to_tab(3),
                            (KeyCode::Char('5'), KeyModifiers::NONE) => ui_state.jump_to_tab(4),

                            // Help toggle — kept because `h` is the universal
                            // mnemonic for help across less / man / vim / tmux.
                            (KeyCode::Char('h'), _) => {
                                ui_state.show_help = !ui_state.show_help;
                                if ui_state.show_help {
                                    ui_state.selected_tab = 4; // Switch to help tab
                                } else {
                                    ui_state.selected_tab = 0; // Back to overview
                                }
                            }

                            // x and Esc keep cross-tab fallbacks here so
                            // clear / filter-clear / tab-back still work
                            // from Details / Activity / Graph / Help
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
