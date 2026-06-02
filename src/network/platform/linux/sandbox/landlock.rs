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
//! - Filesystem: Only allow read access to `/proc` (needed for process lookup)
//! - Filesystem: Only allow read access to specified paths (e.g., GeoIP databases)
//! - Filesystem: Only allow write access to specified paths (logs)
//! - Network: Block TCP bind and connect (RustNet is passive)
//! - Scope: Deny connecting to abstract UNIX sockets created outside our domain
//!   and deny sending signals to processes outside our domain (limits a
//!   compromised process from reaching local IPC like D-Bus/X11 or signalling
//!   other processes)

use anyhow::{Context, Result};
use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};
use std::path::Path;

use super::{SandboxConfig, SandboxMode};

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

/// Result of Landlock application
pub struct LandlockResult {
    /// Whether filesystem restrictions were applied
    pub fs_applied: bool,
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

/// Check if Landlock is available by attempting a test restriction
/// Note: This actually attempts to create a minimal ruleset to check
pub fn is_available() -> bool {
    // Try to create a minimal ruleset - this will fail if Landlock isn't available
    Ruleset::default()
        .handle_access(AccessFs::Execute)
        .and_then(|r| r.create())
        .is_ok()
}

/// Apply Landlock restrictions based on configuration
pub fn apply_landlock(config: &SandboxConfig) -> Result<LandlockResult> {
    // Check if disabled
    if config.mode == SandboxMode::Disabled {
        return Ok(LandlockResult {
            fs_applied: false,
            net_applied: false,
            scope_applied: false,
            effective_abi: None,
            message: "Sandbox disabled".to_string(),
        });
    }

    // Filesystem rights are capped at ABI v4 (see ABI_FS); the crate's default
    // best-effort compatibility downgrades automatically on older kernels.
    let abi = ABI_FS;

    // Build filesystem access rights for reading
    // We need read access to /proc for process identification
    let read_access = AccessFs::from_read(abi);

    // Build filesystem access rights for writing (principle of least privilege)
    // RustNet only needs to create regular files, write/append to them, and traverse dirs.
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
    // Network: handling BindTcp/ConnectTcp without adding any allow-rule denies
    // all TCP bind/connect (kernel 6.7+, ABI v4). On older kernels best-effort
    // drops these silently.
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
    // UDP/53) and the `UdpSocket::connect("8.8.8.8:53")` routing heuristic in
    // capture.rs, so a UDP/53 allow-rule or reliance on `--no-resolve-dns` would
    // be needed.
    if config.block_network {
        ruleset = ruleset
            .handle_access(AccessNet::BindTcp)
            .and_then(|r| r.handle_access(AccessNet::ConnectTcp))
            .context("Failed to handle TCP network access")?
            .scope(Scope::from_all(ABI_SCOPE))
            .context("Failed to handle scope restrictions")?;
    }

    // Create the ruleset
    let mut ruleset_created = ruleset
        .create()
        .context("Failed to create Landlock ruleset")?;

    // Add rule for /proc (read-only)
    // This is required for process identification via procfs. We grant read
    // access to all of /proc because Landlock PathBeneath rules apply to
    // entire subtrees, and we need to enumerate PIDs via read_dir("/proc")
    // and then access per-PID files (/proc/<pid>/comm, /proc/<pid>/fd/).
    // Landlock's ptrace domain restrictions provide automatic protection
    // against reading sensitive /proc files of processes outside our domain.
    if let Err(e) = add_path_rule(&mut ruleset_created, "/proc", read_access) {
        log::warn!("Could not add /proc rule: {}", e);
    }

    // Add rules for sysfs (read-only). The interface-stats poller enumerates
    // interfaces via read_dir("/sys/class/net") and then reads each
    // /sys/class/net/<iface>/statistics/* counter. Those per-interface entries
    // are symlinks into /sys/devices/.../net/<iface>, and Landlock evaluates the
    // *resolved* path, so both subtrees need an allow-rule — without them the
    // reads fail with EACCES and the Interfaces panel shows
    // "No interface stats available". sysfs is not process-sensitive the way
    // /proc is, and this is read-only, so granting the two subtrees is fine.
    for sysfs_path in ["/sys/class/net", "/sys/devices"] {
        if let Err(e) = add_path_rule(&mut ruleset_created, sysfs_path, read_access) {
            log::warn!("Could not add {} rule: {}", sysfs_path, e);
        }
    }

    // Add rules for read-only paths (e.g., GeoIP databases)
    for path in &config.read_paths {
        if path.exists()
            && let Err(e) = add_path_rule(&mut ruleset_created, path, read_access)
        {
            log::warn!("Could not add read rule for {:?}: {}", path, e);
        }
    }

    // Add rules for write paths (logs, etc.)
    for path in &config.write_paths {
        if path.exists() {
            if let Err(e) = add_path_rule(&mut ruleset_created, path, write_access) {
                log::warn!("Could not add write rule for {:?}: {}", path, e);
            }
        } else {
            // For paths that don't exist yet, fall back to the parent directory.
            // Landlock requires an open FD (PathFd) to create rules, so non-existent
            // paths can't be directly referenced. This grants write access to the
            // entire parent directory, which is broader than ideal — callers should
            // pre-create output files before applying the sandbox when possible.
            if let Some(parent) = path.parent()
                && parent.exists()
            {
                log::warn!(
                    "Write path {:?} does not exist; granting write to parent {:?}",
                    path,
                    parent
                );
                if let Err(e) = add_path_rule(&mut ruleset_created, parent, write_access) {
                    log::warn!("Could not add write rule for parent {:?}: {}", parent, e);
                }
            }
        }
    }

    // If network blocking is enabled, we DON'T add any NetPort rules and no
    // scope allow-rules. Handling the access/scope types without allowing any
    // port (or any abstract socket) blocks all TCP bind/connect and all
    // cross-domain abstract-socket connects / signals by default.

    // Apply the restrictions
    let status = ruleset_created
        .restrict_self()
        .context("Failed to apply Landlock restrictions")?;

    // Determine what was actually applied based on the returned status
    let fs_applied = matches!(
        status.ruleset,
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced
    );

    // Check if network restrictions were actually applied. TCP net needs ABI v4
    // (Linux 6.7+); scoping needs ABI v6 (Linux 6.12+). We read the effective ABI
    // the kernel negotiated rather than what we requested.
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

    let message = match (&status.ruleset, &status.landlock) {
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
        net_applied,
        scope_applied,
        effective_abi,
        message,
    })
}

/// Add a rule for a path with the specified access rights
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_does_not_panic() {
        // Should not panic regardless of kernel support
        let _ = is_available();
    }

    #[test]
    fn test_disabled_mode() {
        let config = SandboxConfig {
            mode: SandboxMode::Disabled,
            block_network: true,
            read_paths: vec![],
            write_paths: vec![],
        };
        let result = apply_landlock(&config).unwrap();
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
        };
        let result = apply_landlock(&config).expect("best-effort must not error");
        // scope can only be reported applied when fs was applied too
        assert!(result.fs_applied || !result.scope_applied);
    }
}
