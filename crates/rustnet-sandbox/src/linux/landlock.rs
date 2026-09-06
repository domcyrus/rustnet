//! Landlock sandboxing implementation
//!
//! Landlock is a Linux Security Module (LSM) that allows unprivileged
//! processes to restrict their own ambient rights (filesystem access,
//! network access).
//!
//! # Kernel Requirements
//!
//! - Linux 5.13+: Filesystem access control (ABI v1)
//! - Linux 5.19+: File referring/REFER (ABI v2)
//! - Linux 6.2+:  Truncate control (ABI v3)
//! - Linux 6.7+:  Network TCP bind/connect (ABI v4)
//! - Linux 6.12+: Scoping of abstract UNIX sockets and signals (ABI v6)
//!
//! We rely on the `landlock` crate's default best-effort compatibility: on
//! older kernels any unsupported rights are silently dropped rather than
//! causing an error. Filesystem rights are deliberately capped at ABI v4
//! ([`ABI_FS`]) to avoid ABI v5's `IoctlDev` (which would break the TUI's
//! terminal ioctls), while scoping uses ABI v6 ([`ABI_SCOPE`]).
//!
//! # What We Restrict
//!
//! - Filesystem: Allow read access to `/proc` (needed for process lookup)
//! - Filesystem: Allow read access to the public account databases used for
//!   UID/GID names
//! - Filesystem: Only allow read access to specified paths (e.g., GeoIP databases)
//! - Filesystem: Only allow write access to specified paths (logs)
//! - Network: Block TCP bind and connect, optionally allowing DNS connections
//!   to destination port 53 (RustNet is otherwise passive)
//! - Scope: Deny connecting to abstract UNIX sockets created outside our domain
//!   and deny sending signals to processes outside our domain (limits a
//!   compromised process from reaching local IPC like D-Bus/X11 or signalling
//!   other processes)

use anyhow::{Context, Result};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, LandlockStatus, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};
use std::path::Path;

use crate::{SandboxConfig, SandboxMode};

/// Highest ABI whose *filesystem* rights we handle.
///
/// Capped at V4 on purpose: ABI v5 adds `AccessFs::IoctlDev`, and
/// `AccessFs::from_all(V5+)` would handle it. Since we add no allow-rule for
/// ioctls on the controlling terminal (a character device), handling IoctlDev
/// would deny the ratatui/crossterm ioctls (e.g. `TIOCGWINSZ`, `TCSETS`) and
/// break the TUI. V4's `from_all` covers all filesystem rights we want
/// (read/write/truncate) without IoctlDev.
const ABI_FS: ABI = ABI::V4;

/// ABI used for scoping (abstract UNIX sockets + signals).
///
/// V6 (Linux 6.12+) is the first ABI with scoping. We stop at V6 rather than V7
/// because V7 only adds audit-logging controls, which we don't use. The crate
/// downgrades automatically (best effort) on kernels that support less.
const ABI_SCOPE: ABI = ABI::V6;

/// Public account files needed by libc's `getpwuid_r` and `getgrgid_r`.
///
/// These are file-scoped rules rather than an `/etc` subtree rule, so the
/// sandbox does not expose unrelated system configuration or credentials.
const ACCOUNT_DATABASE_PATHS: [&str; 3] = ["/etc/passwd", "/etc/group", "/etc/nsswitch.conf"];

/// Files used by libc's resolver in addition to `nsswitch.conf`.
///
/// Rules target the exact files, not the containing `/etc` directory. Landlock
/// resolves symlinks such as `/etc/resolv.conf` to the file opened by `PathFd`.
const DNS_RESOLVER_PATHS: [&str; 3] = ["/etc/host.conf", "/etc/hosts", "/etc/resolv.conf"];

/// TCP destination ports permitted when DNS resolution is enabled.
const DNS_TCP_CONNECT_PORTS: [u16; 1] = [53];

fn dns_resolver_paths(allow_dns_resolution: bool) -> &'static [&'static str] {
    if allow_dns_resolution {
        &DNS_RESOLVER_PATHS
    } else {
        &[]
    }
}

fn allowed_tcp_connect_ports(config: &SandboxConfig, allow_dns_resolution: bool) -> &'static [u16] {
    if config.block_network && allow_dns_resolution {
        &DNS_TCP_CONNECT_PORTS
    } else {
        &[]
    }
}

/// Result of Landlock application
pub(super) struct LandlockResult {
    /// Whether filesystem restrictions were applied
    pub fs_applied: bool,
    /// Whether every requested filesystem right and path rule was enforced.
    pub fs_fully_enforced: bool,
    /// Whether network restrictions were applied
    pub net_applied: bool,
    /// Whether scoping restrictions (abstract UNIX sockets + signals) were applied
    pub scope_applied: bool,
    /// Effective Landlock ABI the kernel negotiated (e.g. `Some(6)`), or `None`
    /// when Landlock is unavailable / not enforced. This is the tier that is
    /// actually in effect, which may be lower than what we requested.
    pub effective_abi: Option<u8>,
    /// Human-readable message
    pub message: String,
}

/// Map a `landlock::ABI` to its numeric version for display/reporting.
///
/// The `landlock` 0.4.5 crate knows up to `V7`; `restrict_self` never reports an
/// effective ABI above the crate's compiled-in maximum, so the catch-all is only
/// future-proofing and not expected to trigger.
fn abi_version(abi: ABI) -> u8 {
    match abi {
        ABI::Unsupported => 0,
        ABI::V1 => 1,
        ABI::V2 => 2,
        ABI::V3 => 3,
        ABI::V4 => 4,
        ABI::V5 => 5,
        ABI::V6 => 6,
        ABI::V7 => 7,
        _ => 0,
    }
}

/// Check if Landlock is available by attempting to create a minimal ruleset.
pub(super) fn is_available() -> bool {
    Ruleset::default()
        .handle_access(AccessFs::Execute)
        .and_then(|r| r.create())
        .is_ok()
}

/// Apply Landlock restrictions based on configuration
pub(super) fn apply_landlock(
    config: &SandboxConfig,
    allow_dns_resolution: bool,
) -> Result<LandlockResult> {
    if config.mode == SandboxMode::Disabled {
        return Ok(LandlockResult {
            fs_applied: false,
            fs_fully_enforced: false,
            net_applied: false,
            scope_applied: false,
            effective_abi: None,
            message: "Sandbox disabled".to_string(),
        });
    }

    // Filesystem rights are capped at ABI v4 (see ABI_FS); the crate's default
    // best-effort compatibility downgrades automatically on older kernels.
    let abi = ABI_FS;

    let read_access = AccessFs::from_read(abi);

    // Write paths get only what output files need: create regular files,
    // read/write/truncate them, and list their directories.
    let write_access = AccessFs::WriteFile
        | AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::MakeReg
        | AccessFs::Truncate;

    // Start building the ruleset. `Ruleset::default()` uses the crate's
    // best-effort compatibility, so requesting rights newer than the running
    // kernel supports silently drops them instead of erroring.
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .context("Failed to handle filesystem access")?;

    // Add network + scope restrictions if requested (the passive-monitor profile).
    //
    // Network: handling BindTcp/ConnectTcp denies TCP bind/connect by default
    // (kernel 6.7+, ABI v4). When requested, one NetPort rule permits outbound
    // TCP connections to DNS port 53. On older kernels best-effort drops these
    // restrictions silently.
    //
    // Scope: denying abstract UNIX socket connects and signal sending to
    // processes outside our domain (kernel 6.12+, ABI v6). This closes a local
    // exfiltration / lateral-movement channel (D-Bus session bus, X11's
    // `@/tmp/.X11-unix`, etc.) that RustNet never legitimately uses. Pathname
    // UNIX sockets (nss/nscd/systemd-resolved, the reverse-DNS IPC path) are NOT
    // abstract sockets and are unaffected.
    //
    // TODO(udp landlock): UDP restrictions (LANDLOCK_ACCESS_NET_CONNECT_UDP /
    // SENDTO_UDP) are an RFC kernel patch series as of 2026-05 and not yet
    // exposed by the `landlock` crate. When `AccessNet::ConnectUdp` / `SendtoUdp`
    // land, add them to the chain below (they degrade via best effort too). Note
    // the tension: a blanket UDP block breaks reverse DNS (glibc resolver,
    // UDP/53) and the routing heuristic in the capture layer, so add a UDP/53
    // allow rule alongside the TCP rule when the crate exposes those rights.
    if config.block_network {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp)
            .and_then(|r| r.handle_access(AccessNet::ConnectTcp))
            .context("Failed to handle TCP network access")?
            .scope(Scope::from_all(ABI_SCOPE))
            .context("Failed to handle scope restrictions")?;
    }

    let mut ruleset_created = ruleset
        .create()
        .context("Failed to create Landlock ruleset")?;
    let mut path_rule_failures = Vec::new();

    // Read access to all of /proc is required for process identification via
    // procfs: Landlock PathBeneath rules apply to entire subtrees, and we need
    // to enumerate PIDs via read_dir("/proc") and then access per-PID files
    // (/proc/<pid>/comm, /proc/<pid>/fd/).
    // Landlock's ptrace domain restrictions provide automatic protection
    // against reading sensitive /proc files of processes outside our domain.
    add_policy_path_rule(
        &mut ruleset_created,
        Path::new("/proc"),
        read_access,
        config.mode,
        &mut path_rule_failures,
    )?;

    // The Details tab resolves process UID/GID values through libc after the
    // sandbox is active. NSS needs its service configuration and the local
    // account databases for that lookup. Grant only ReadFile on the exact
    // files, never the containing /etc directory or the shadow databases.
    for account_path in ACCOUNT_DATABASE_PATHS {
        let account_path = Path::new(account_path);
        if account_path.exists() {
            add_policy_path_rule(
                &mut ruleset_created,
                account_path,
                AccessFs::ReadFile.into(),
                config.mode,
                &mut path_rule_failures,
            )?;
        }
    }

    // Reverse DNS uses libc's NSS resolver. Grant only its exact configuration
    // and hosts files when resolution was explicitly enabled. `nsswitch.conf`
    // is already included in ACCOUNT_DATABASE_PATHS because account lookup also
    // requires it.
    for resolver_path in dns_resolver_paths(allow_dns_resolution) {
        let resolver_path = Path::new(resolver_path);
        if resolver_path.exists() {
            add_policy_path_rule(
                &mut ruleset_created,
                resolver_path,
                AccessFs::ReadFile.into(),
                config.mode,
                &mut path_rule_failures,
            )?;
        }
    }

    // sysfs (read-only): the interface-stats poller enumerates
    // interfaces via read_dir("/sys/class/net") and then reads each
    // /sys/class/net/<iface>/statistics/* counter. Those per-interface entries
    // are symlinks into /sys/devices/.../net/<iface>, and Landlock evaluates the
    // *resolved* path, so both subtrees need an allow-rule; without them the
    // reads fail with EACCES and the Interfaces panel shows
    // "No interface stats available". sysfs is not process-sensitive the way
    // /proc is, and this is read-only, so granting the two subtrees is fine.
    for sysfs_path in ["/sys/class/net", "/sys/devices"] {
        add_policy_path_rule(
            &mut ruleset_created,
            Path::new(sysfs_path),
            read_access,
            config.mode,
            &mut path_rule_failures,
        )?;
    }

    for path in &config.read_paths {
        if path.exists() {
            add_policy_path_rule(
                &mut ruleset_created,
                path,
                read_access,
                config.mode,
                &mut path_rule_failures,
            )?;
        } else {
            record_missing_path(config.mode, path, &mut path_rule_failures)?;
        }
    }

    for path in &config.write_paths {
        if path.exists() {
            add_policy_path_rule(
                &mut ruleset_created,
                path,
                write_access,
                config.mode,
                &mut path_rule_failures,
            )?;
        } else {
            // For paths that don't exist yet, fall back to the parent directory.
            // Landlock requires an open FD (PathFd) to create rules, so non-existent
            // paths can't be directly referenced. This grants write access to the
            // entire parent directory, which is broader than ideal, so callers should
            // pre-create output files before applying the sandbox when possible.
            record_missing_path(config.mode, path, &mut path_rule_failures)?;
            if let Some(parent) = path.parent()
                && parent.exists()
            {
                log::warn!(
                    "Write path {:?} does not exist; granting write to parent {:?}",
                    path,
                    parent
                );
                add_policy_path_rule(
                    &mut ruleset_created,
                    parent,
                    write_access,
                    config.mode,
                    &mut path_rule_failures,
                )?;
            }
        }
    }

    // DNS resolution needs TCP for truncated responses and responses that do
    // not fit in UDP. Bind remains denied, as do connects to every other TCP
    // port. UDP is not currently mediated by Landlock.
    for port in allowed_tcp_connect_ports(config, allow_dns_resolution) {
        ruleset_created = ruleset_created
            .add_rule(NetPort::new(*port, AccessNet::ConnectTcp))
            .with_context(|| format!("Failed to allow TCP connect to DNS port {port}"))?;
    }

    // No scope allow-rules are added. Cross-domain abstract-socket connects and
    // signals remain denied when network blocking is enabled.

    let status = ruleset_created
        .restrict_self()
        .context("Failed to apply Landlock restrictions")?;

    let fs_applied = matches!(
        status.ruleset,
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced
    );
    let fs_fully_enforced =
        path_rule_failures.is_empty() && matches!(status.ruleset, RulesetStatus::FullyEnforced);

    // TCP net needs ABI v4 (Linux 6.7+); scoping needs ABI v6 (Linux 6.12+). We
    // read the effective ABI the kernel negotiated rather than what we requested.
    let net_applied = config.block_network
        && fs_applied
        && matches!(
            status.landlock,
            LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI::V4
        );

    let scope_applied = config.block_network
        && fs_applied
        && matches!(
            status.landlock,
            LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI_SCOPE
        );

    // The ABI tier actually negotiated with the running kernel (only meaningful
    // when Landlock is available and something was enforced).
    let effective_abi = match status.landlock {
        LandlockStatus::Available { effective_abi, .. } if fs_applied => {
            Some(abi_version(effective_abi))
        }
        _ => None,
    };

    let mut message = match (&status.ruleset, &status.landlock) {
        (RulesetStatus::FullyEnforced, _) => "Landlock fully enforced".to_string(),
        (RulesetStatus::PartiallyEnforced, _) => "Landlock partially enforced".to_string(),
        (RulesetStatus::NotEnforced, LandlockStatus::NotEnabled) => {
            "Landlock disabled in kernel".to_string()
        }
        (RulesetStatus::NotEnforced, LandlockStatus::NotImplemented) => {
            "Landlock not implemented in kernel".to_string()
        }
        (RulesetStatus::NotEnforced, _) => "Landlock not enforced".to_string(),
    };
    if !path_rule_failures.is_empty() {
        message.push_str(&format!(
            "; {} filesystem path rule(s) incomplete",
            path_rule_failures.len()
        ));
    }

    log::info!("Landlock: {}", message);
    log::info!(
        "Landlock: filesystem={}, network={}, scope={}, landlock_status={:?}",
        fs_applied,
        net_applied,
        scope_applied,
        status.landlock
    );

    Ok(LandlockResult {
        fs_applied,
        fs_fully_enforced,
        net_applied,
        scope_applied,
        effective_abi,
        message,
    })
}

fn add_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    let path = path.as_ref();
    let fd = PathFd::new(path).with_context(|| format!("Failed to open {:?}", path))?;
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .with_context(|| format!("Failed to add rule for {:?}", path))?;
    log::debug!("Landlock: Added rule for {:?}", path);
    Ok(())
}

fn add_policy_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: &Path,
    access: BitFlags<AccessFs>,
    mode: SandboxMode,
    failures: &mut Vec<String>,
) -> Result<()> {
    if let Err(error) = add_path_rule(ruleset, path, access) {
        if mode == SandboxMode::Strict {
            return Err(error)
                .with_context(|| format!("Strict mode requires the Landlock rule for {:?}", path));
        }
        log::warn!("Could not add Landlock rule for {:?}: {}", path, error);
        failures.push(path.display().to_string());
    }
    Ok(())
}

fn record_missing_path(mode: SandboxMode, path: &Path, failures: &mut Vec<String>) -> Result<()> {
    if mode == SandboxMode::Strict {
        anyhow::bail!(
            "Strict mode requires configured sandbox path {:?} to exist",
            path
        );
    }
    log::warn!("Configured sandbox path {:?} does not exist", path);
    failures.push(path.display().to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_does_not_panic() {
        let _ = is_available();
    }

    #[test]
    fn test_disabled_mode() {
        let config = SandboxConfig {
            mode: SandboxMode::Disabled,
            block_network: true,
            read_paths: vec![],
            write_paths: vec![],
            drop_uid: None,
        };
        let result = apply_landlock(&config, true).unwrap();
        assert!(!result.fs_applied);
        assert!(!result.net_applied);
        assert!(!result.scope_applied);
        assert_eq!(result.effective_abi, None);
    }

    #[test]
    fn test_best_effort_does_not_panic() {
        // Requesting the highest ABI plus network/scope must not error or panic
        // regardless of the running kernel: best-effort silently drops any
        // unsupported rights. On kernels without Landlock this returns a result
        // with nothing applied; on modern kernels it enforces.
        let config = SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: true,
            read_paths: vec![],
            write_paths: vec![],
            drop_uid: None,
        };
        let result = apply_landlock(&config, true).expect("best-effort must not error");
        // scope can only be reported applied when fs was applied too
        assert!(result.fs_applied || !result.scope_applied);
    }

    #[test]
    fn test_dns_resolver_file_policy_is_exact() {
        assert_eq!(dns_resolver_paths(false), &[] as &[&str]);
        assert_eq!(
            dns_resolver_paths(true),
            ["/etc/host.conf", "/etc/hosts", "/etc/resolv.conf"]
        );
    }

    #[test]
    fn test_dns_tcp_connect_policy_is_exact() {
        let blocked_without_dns = SandboxConfig {
            block_network: true,
            ..SandboxConfig::default()
        };
        assert_eq!(
            allowed_tcp_connect_ports(&blocked_without_dns, false),
            &[] as &[u16]
        );

        let blocked_with_dns = SandboxConfig {
            block_network: true,
            ..SandboxConfig::default()
        };
        assert_eq!(allowed_tcp_connect_ports(&blocked_with_dns, true), [53]);

        let unrestricted = SandboxConfig::default();
        assert_eq!(
            allowed_tcp_connect_ports(&unrestricted, true),
            &[] as &[u16]
        );
    }

    #[test]
    fn strict_mode_rejects_a_missing_requested_path() {
        let mut failures = Vec::new();
        let error = record_missing_path(
            SandboxMode::Strict,
            Path::new("/rustnet-test-path-that-does-not-exist"),
            &mut failures,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("requires configured sandbox path")
        );
        assert!(failures.is_empty());
    }

    #[test]
    fn best_effort_records_a_missing_requested_path() {
        let mut failures = Vec::new();
        record_missing_path(
            SandboxMode::BestEffort,
            Path::new("/rustnet-test-path-that-does-not-exist"),
            &mut failures,
        )
        .unwrap();

        assert_eq!(failures.len(), 1);
    }
}
