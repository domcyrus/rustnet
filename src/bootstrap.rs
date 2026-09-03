//! Front-end independent startup: logging, the privilege check, the
//! [`Config`] built from CLI flags, output files, the privileged [`App`]
//! initialization, sandboxing, and worker start.

use anyhow::Result;
use clap::ArgMatches;
use log::{LevelFilter, info, warn};
use rustnet_sandbox::{SandboxConfig, SandboxMode, SandboxReport, apply_sandbox};
use simplelog::{ConfigBuilder, WriteLogger};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::app::{App, AppOutputHandles, Config};
use crate::headless::sink::EventSink;
use crate::network;

/// Which front-end is starting. Decides where diagnostics go: the TUI owns
/// the terminal, so its log goes to `logs/`; the headless stream owns
/// stdout, so its log goes to stderr and no log directory is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    Tui,
    Headless,
}

/// Everything resolved before the application starts: the [`Config`], the
/// retained output descriptors, and the sandbox policy. The privileged
/// initialization is deferred to [`Prepared::launch`] so a front-end can
/// set up its display in between, after every error that should print to
/// a normal terminal has had its chance.
pub struct Prepared {
    config: Config,
    output_handles: AppOutputHandles,
    sandbox_config: SandboxConfig,
}

/// Run the unprivileged startup steps: Npcap delay-load (Windows), logging,
/// the privilege check (its banner goes to stderr), the [`Config`], the uid
/// drop target, the output files, and the sandbox policy. Only the TUI gets
/// the startup splash.
pub fn prepare(matches: &ArgMatches, frontend: Frontend) -> Result<Prepared> {
    // Clap handles --help and --version before this point, so both remain
    // available even when Npcap is not installed. The Npcap DLLs are
    // delay-loaded so Windows can enter main() before resolving those imports.
    #[cfg(target_os = "windows")]
    initialize_windows_npcap()?;

    if let Some(log_level_str) = matches.get_one::<String>("log-level") {
        let log_level = log_level_str
            .parse::<LevelFilter>()
            .map_err(|_| anyhow::anyhow!("Invalid log level: {}", log_level_str))?;
        setup_logging(log_level, frontend)?;
    }

    // Check privileges before any front-end takes over the terminal, so the
    // error message stays visible.
    check_privileges_early()?;

    let config = build_config(matches, frontend == Frontend::Tui);

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

    let mut output_handles = AppOutputHandles::default();

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

    let (read_paths, write_paths) = sandbox_paths(matches, &config, frontend);
    let sandbox_config = SandboxConfig {
        mode: SandboxMode::from_flags(
            matches.get_flag("no-sandbox"),
            matches.get_flag("sandbox-strict"),
        ),
        block_network: true, // RustNet is passive, doesn't need TCP
        read_paths,
        write_paths,
        ..SandboxConfig::default()
    };
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    let sandbox_config = SandboxConfig {
        drop_uid: uid_drop_target,
        ..sandbox_config
    };

    Ok(Prepared {
        config,
        output_handles,
        sandbox_config,
    })
}

impl Prepared {
    /// Add a destination for the connection events, alongside `--json-log`.
    pub(crate) fn add_event_sink(&mut self, sink: Arc<dyn EventSink>) {
        self.output_handles.event_sinks.push(sink);
    }

    /// Start the privileged subsystems, wait for them, apply the sandbox on
    /// the calling thread, then start the worker threads and install the
    /// shutdown signal handlers. Must run on the main thread: the sandbox
    /// restrictions are per-thread state that the workers inherit from it.
    pub(crate) fn launch(self) -> Result<App> {
        self.launch_with(|_| {})
    }

    /// [`launch`](Self::launch) with a hook that runs once the capture
    /// device is open and the sandbox is applied, but before any worker
    /// thread exists: nothing has been emitted to the event sinks yet, so
    /// a line written from the hook is the first one in every stream.
    pub(crate) fn launch_with(self, before_workers: impl FnOnce(&App)) -> Result<App> {
        let mut app = App::new_with_output_handles(self.config, self.output_handles)?;
        let (process_ready_rx, capture_ready_rx) = app.start()?;
        info!("Application started");

        // Wait for process detection (including eBPF loading) to complete before
        // applying the sandbox, which drops CAP_BPF and CAP_PERFMON.
        // Without this synchronization, the sandbox could drop these capabilities
        // before the background thread has finished loading eBPF programs.
        wait_for_init(&process_ready_rx, "process detection");

        // Also wait for the capture thread to finish opening the capture device.
        // The open runs on a background thread and needs the startup privileges;
        // without this synchronization the uid drop (Linux/FreeBSD) or sandbox
        // could win the race and the open would fail with EPERM, leaving the UI
        // running with no traffic.
        wait_for_init(&capture_ready_rx, "packet capture");

        // Apply the sandbox (rustnet-sandbox crate: Landlock + capability drops
        // on Linux, uid drop + Seatbelt on macOS, restricted token + job object
        // on Windows, uid drop on FreeBSD).
        // This must be done AFTER process detection and capture init because:
        // - eBPF programs need to be loaded first (requires CAP_BPF + CAP_PERFMON)
        // - Packet capture handles need to be opened first (raw sockets, /dev/bpf*)
        // - Log files need to be created first
        match apply_sandbox(&self.sandbox_config) {
            Ok(report) => app.set_sandbox_info(report),
            Err(e) => {
                if self.sandbox_config.mode == SandboxMode::Strict {
                    return Err(e.context("Sandbox enforcement required but failed"));
                }
                warn!("Sandbox application error (non-strict mode): {}", e);
                app.set_sandbox_info(SandboxReport::from_error(&e));
            }
        }

        before_workers(&app);

        // Now that the sandbox has been applied on the main thread, start the worker
        // threads (DPI packet processors, enrichment, snapshot, cleanup, collectors).
        // On Linux these inherit the Landlock domain and the dropped capabilities, so
        // a compromise in a DPI parser is contained even when running as root.
        app.start_workers()?;

        install_signal_handlers();
        Ok(app)
    }
}

fn build_config(matches: &ArgMatches, show_startup_splash: bool) -> Config {
    let mut config = Config {
        show_startup_splash,
        ..Default::default()
    };

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

    config
}

/// The filesystem paths the sandbox must keep readable and writable.
fn sandbox_paths(
    matches: &ArgMatches,
    config: &Config,
    frontend: Frontend,
) -> (Vec<PathBuf>, Vec<PathBuf>) {
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

    // Collect write paths: the logs directory when logging is enabled, plus
    // every configured output file (JSON log, PCAP export + its sidecar
    // JSONL, PCAPNG export). Ignored by backends without filesystem rules.
    let mut write_paths: Vec<PathBuf> = Vec::new();
    if frontend == Frontend::Tui && matches.get_one::<String>("log-level").is_some() {
        write_paths.push(PathBuf::from("logs"));
    }
    if let Some(json_log_path) = &config.json_log_file {
        write_paths.push(PathBuf::from(json_log_path));
    }
    if let Some(pcap_path) = &config.pcap_export_file {
        write_paths.push(PathBuf::from(pcap_path));
        write_paths.push(PathBuf::from(format!("{}.connections.jsonl", pcap_path)));
    }
    if let Some(pcapng_path) = &config.pcapng_export_file {
        write_paths.push(PathBuf::from(pcapng_path));
    }

    (read_paths, write_paths)
}

/// Install the logger: a timestamped file under `logs/` for the TUI, stderr
/// for the headless stream (stdout carries the events).
fn setup_logging(level: LevelFilter, frontend: Frontend) -> Result<()> {
    // `target` names the emitting subsystem (e.g. `network::dpi::dns`); the
    // banner below identifies the binary.
    let config = ConfigBuilder::new()
        .set_target_level(LevelFilter::Error)
        .build();

    match frontend {
        Frontend::Tui => WriteLogger::init(level, config, open_log_file()?)?,
        Frontend::Headless => WriteLogger::init(level, config, io::stderr())?,
    }

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

fn open_log_file() -> Result<fs::File> {
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
    Ok(open_private(&log_file_path, false)?)
}

/// Wait up to 10 s for a background subsystem to signal that its
/// privileged setup is done, so the sandbox can be applied. A timeout or an
/// early thread exit is logged but does not block startup.
fn wait_for_init(ready_rx: &std::sync::mpsc::Receiver<()>, what: &str) {
    match ready_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(()) => info!("{} initialized, safe to apply sandbox", what),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!(
                "Timed out waiting for {} init, applying sandbox anyway",
                what
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("{} thread exited early, applying sandbox anyway", what);
        }
    }
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

/// Open a private output file, either truncating or appending.
///
/// On Unix, opens with O_NOFOLLOW so a symlink pre-planted at a predictable
/// path cannot redirect the write, and sets the 0o600 mode at creation time
/// to avoid a create-then-chmod window where the file is briefly
/// world-readable.
fn open_private(path: impl AsRef<Path>, append: bool) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create(true);
    if append {
        options.append(true);
    } else {
        options.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
    }
    options.open(path)
}

/// Create (or truncate) a private output file before privileges are reduced.
fn precreate_private_file(path: &str) -> io::Result<fs::File> {
    open_private(path, false)
}

/// Open an append-only private output before privileges are reduced.
///
/// Unlike [`precreate_private_file`], this preserves existing contents because
/// `--json-log` has append semantics.
fn open_private_append_file(path: &str) -> io::Result<fs::File> {
    open_private(path, true)
}

/// Set from the signal handler; a front-end's main loop exits through its
/// normal cleanup path (flush outputs, restore the terminal) when it flips.
static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

pub(crate) fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::Relaxed)
}

/// Route SIGTERM/SIGHUP/SIGINT through the regular shutdown path. Without
/// this, `kill` (or a session manager closing the terminal) ends the process
/// before the JSONL/PCAP outputs are flushed and leaves the terminal in
/// raw mode. With raw mode on, Ctrl+C arrives as a key event and SIGINT is
/// never delivered; the SIGINT handler only matters when raw mode is off.
#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn on_signal(_sig: libc::c_int) {
        // Only async-signal-safe work here: set the flag, nothing else.
        SHUTDOWN_REQUESTED.store(true, Ordering::Relaxed);
    }
    let handler: extern "C" fn(libc::c_int) = on_signal;
    // SAFETY: installing a handler that only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
    }
}

#[cfg(not(unix))]
fn install_signal_handlers() {}

/// Check if we have privileges for packet capture before a front-end starts
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

#[cfg(all(test, unix))]
mod output_file_tests {
    use super::open_private_append_file;
    use crate::test_support::scratch_dir::ScratchDir;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn scratch(tag: &str) -> ScratchDir {
        ScratchDir::new("output", tag)
    }

    #[test]
    fn creates_file_with_0600_permissions() {
        let dir = scratch("perms");
        let path = dir.join("events.log");

        let file =
            open_private_append_file(path.to_str().unwrap()).expect("fresh open should succeed");
        let mode = file.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new output must be created mode 0o600");
    }

    #[test]
    fn appends_rather_than_truncates() {
        let dir = scratch("append");
        let path = dir.join("events.log");
        let path = path.to_str().unwrap();

        writeln!(open_private_append_file(path).unwrap(), "line1").unwrap();
        writeln!(open_private_append_file(path).unwrap(), "line2").unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "line1\nline2\n");
    }

    #[test]
    fn retained_descriptor_survives_inaccessible_parent() {
        let dir = scratch("retained");
        let path = dir.join("events.log");
        let mut file = open_private_append_file(path.to_str().unwrap()).unwrap();

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        writeln!(file, "still writable").unwrap();
        file.sync_all().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(std::fs::read_to_string(path).unwrap(), "still writable\n");
    }

    #[test]
    fn refuses_symlinked_path() {
        let dir = scratch("symlink");
        let target = dir.join("real_target.log");
        let link = dir.join("evil.log");
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
