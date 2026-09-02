//! Post-initialization sandboxing and privilege dropping for rustnet.
//!
//! One [`apply_sandbox`] entry point with a platform backend behind it:
//!
//! - **Linux**: `PR_SET_NO_NEW_PRIVS`, capability drops (CAP_NET_RAW,
//!   CAP_BPF, CAP_PERFMON), the root uid drop, and Landlock
//!   filesystem/network/scope restrictions (behind the `landlock` feature).
//! - **macOS**: the root uid drop, then a Seatbelt profile blocking outbound
//!   network, credential reads, and writes outside configured output paths
//!   (behind the `macos-sandbox` feature).
//! - **Windows**: dangerous token privileges removed and a job object that
//!   blocks child process creation.
//! - **FreeBSD**: the root uid drop (Capsicum is planned).
//!
//! # Application order contract
//!
//! Sandboxing is a *post-initialization* step. Callers must apply it only
//! after every privileged operation is done, in this order:
//!
//! 1. Open capture handles (raw sockets, BPF/PKTAP devices, Npcap) — the
//!    descriptors stay valid across the sandbox and uid drop.
//! 2. Load eBPF programs (needs CAP_BPF/CAP_PERFMON, which the sandbox
//!    drops).
//! 3. Pre-create output files (logs, PCAP exports) and, when dropping root,
//!    chown them to the drop target ([`privdrop::chown_to_target`]) — Landlock
//!    needs an existing file to scope a write rule to it, and a path under a
//!    root-only directory cannot be reopened after the drop.
//! 4. Call [`apply_sandbox`] on the **main thread**.
//! 5. Only then spawn worker threads that should inherit the restrictions:
//!    Landlock domains and capability sets are per-thread state that new
//!    threads inherit from their spawner; threads started before step 4 keep
//!    the unrestricted state.
//!
//! Threads that must run before the sandbox (capture, enrichment) should shed
//! the capabilities they do not need themselves via [`capabilities`]
//! (Linux, `landlock` feature). A thread that keeps calling `bpf(2)` must
//! retain CAP_BPF ([`capabilities::drop_thread_cap_net_raw`]); all others can
//! use [`capabilities::drop_unused_thread_caps`].

use std::path::PathBuf;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub mod privdrop;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(all(target_os = "linux", feature = "landlock"))]
pub use linux::capabilities;

/// Sandbox enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// Apply sandbox with best-effort (graceful degradation on older kernels)
    #[default]
    BestEffort,
    /// Require full sandbox enforcement or fail
    Strict,
    /// Disable sandboxing entirely
    Disabled,
}

impl SandboxMode {
    /// Map the `--no-sandbox` / `--sandbox-strict` CLI flags to a mode.
    pub fn from_flags(no_sandbox: bool, strict: bool) -> Self {
        if no_sandbox {
            SandboxMode::Disabled
        } else if strict {
            SandboxMode::Strict
        } else {
            SandboxMode::BestEffort
        }
    }
}

/// Status of sandbox application
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxStatus {
    /// Sandbox fully enforced (all requested restrictions applied)
    FullyEnforced,
    /// Sandbox partially enforced (some features unavailable)
    PartiallyEnforced,
    /// Sandbox not applied (disabled, or platform support missing)
    #[default]
    NotApplied,
    /// Applying the sandbox failed (only set by callers on an `Err` from
    /// [`apply_sandbox`]; the backends themselves never return it)
    Error,
}

impl SandboxStatus {
    /// Short human-readable label for status displays.
    pub fn label(&self) -> &'static str {
        match self {
            SandboxStatus::FullyEnforced => "Fully enforced",
            SandboxStatus::PartiallyEnforced => "Partially enforced",
            SandboxStatus::NotApplied => "Not applied",
            SandboxStatus::Error => "Error",
        }
    }
}

/// Configuration for the sandbox
///
/// One cross-platform shape; each backend reads what applies to it. Windows
/// reads only `mode`; FreeBSD reads `mode` and `drop_uid`.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Sandbox enforcement mode
    pub mode: SandboxMode,
    /// Block TCP bind/connect (Linux) or outbound TCP/UDP (macOS).
    /// Recommended for passive monitors.
    pub block_network: bool,
    /// Paths that need read access after sandboxing (e.g., GeoIP databases)
    pub read_paths: Vec<PathBuf>,
    /// Paths that need write access after sandboxing (e.g., log files,
    /// PCAP exports). Directories grant their whole subtree.
    pub write_paths: Vec<PathBuf>,
    /// When running as root: the identity to drop to after initialization
    /// (`None` = not root, or drop disabled via `--no-uid-drop`)
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    pub drop_uid: Option<privdrop::DropTarget>,
}

/// Result of sandbox application
///
/// One struct for every platform: the cross-platform fields always exist
/// (and stay `false` where a platform has no such restriction), the
/// platform-specific details are cfg-gated. This is both the enforcement
/// report and the UI/status shape, so a new field automatically reaches
/// every consumer.
#[derive(Debug, Clone, Default)]
pub struct SandboxReport {
    /// Overall status
    pub status: SandboxStatus,
    /// Human-readable message
    pub message: String,
    /// Whether filesystem restrictions are active (Landlock / Seatbelt)
    pub fs_restricted: bool,
    /// Whether network restrictions are active (Landlock TCP block /
    /// Seatbelt outbound block)
    pub net_restricted: bool,
    /// Whether the root uid/gid were dropped (Linux/macOS/FreeBSD)
    pub uid_dropped: bool,
    /// Whether CAP_NET_RAW was dropped
    #[cfg(target_os = "linux")]
    pub cap_net_raw_dropped: bool,
    /// Whether CAP_BPF/CAP_PERFMON were dropped
    #[cfg(target_os = "linux")]
    pub ebpf_caps_dropped: bool,
    /// Whether Landlock scope restrictions (abstract UNIX sockets + signals)
    /// are applied
    #[cfg(target_os = "linux")]
    pub scope_restricted: bool,
    /// Whether Landlock is available on this kernel
    #[cfg(target_os = "linux")]
    pub landlock_available: bool,
    /// Effective Landlock ABI negotiated with the kernel (e.g. `Some(6)`),
    /// or `None` when Landlock is unavailable / not enforced
    #[cfg(target_os = "linux")]
    pub landlock_abi: Option<u8>,
    /// Whether PR_SET_NO_NEW_PRIVS is set (applied even with `--no-sandbox`)
    #[cfg(target_os = "linux")]
    pub no_new_privs: bool,
    /// Whether the Seatbelt profile was applied
    #[cfg(target_os = "macos")]
    pub seatbelt_applied: bool,
    /// Whether dangerous privileges were removed
    #[cfg(target_os = "windows")]
    pub privileges_removed: bool,
    /// Number of privileges removed
    #[cfg(target_os = "windows")]
    pub privileges_removed_count: u32,
    /// Whether the job object was applied
    #[cfg(target_os = "windows")]
    pub job_object_applied: bool,
}

impl SandboxReport {
    /// Report for a failed [`apply_sandbox`] call (non-strict callers).
    pub fn from_error(error: &anyhow::Error) -> Self {
        Self {
            status: SandboxStatus::Error,
            message: error.to_string(),
            ..Self::default()
        }
    }

    /// Report for a backend whose only enforcement was the root uid drop
    /// (no platform sandbox available or compiled in): partially enforced
    /// when the drop happened, not applied otherwise.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    pub(crate) fn uid_drop_only(banner: &str, outcome: &UidDropOutcome) -> Self {
        Self {
            status: if outcome.dropped {
                SandboxStatus::PartiallyEnforced
            } else {
                SandboxStatus::NotApplied
            },
            message: outcome.message_after(banner),
            uid_dropped: outcome.dropped,
            ..Self::default()
        }
    }
}

/// Outcome of the root uid drop step shared by the Linux, macOS and FreeBSD
/// backends (see [`drop_root_step`]).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub(crate) struct UidDropOutcome {
    /// Whether the root uid/gid were dropped.
    pub(crate) dropped: bool,
    /// Human-readable summary of the step (success or non-strict failure);
    /// `None` when no drop was requested.
    pub(crate) message: Option<String>,
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
impl UidDropOutcome {
    /// `banner`, followed by the step summary as a `; `-separated suffix when
    /// a drop was attempted. (Linux folds the summary into its own message
    /// list instead.)
    pub(crate) fn message_after(&self, banner: &str) -> String {
        match &self.message {
            Some(message) => format!("{}; {}", banner, message),
            None => banner.to_string(),
        }
    }
}

/// Drop the root uid/gid when `config.drop_uid` is set.
///
/// Capture fds opened during initialization remain valid across the drop.
/// `attribution_note` names the platform's process-attribution fallback that
/// is limited to the target user's processes afterwards; it is appended to
/// the success log line. In [`SandboxMode::Strict`] a failed drop is an
/// error; otherwise it is logged and reported in the outcome message.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub(crate) fn drop_root_step(
    config: &SandboxConfig,
    attribution_note: &str,
) -> anyhow::Result<UidDropOutcome> {
    let Some(target) = config.drop_uid else {
        return Ok(UidDropOutcome {
            dropped: false,
            message: None,
        });
    };
    match privdrop::drop_to(target) {
        Ok(()) => {
            log::info!(
                "Dropped root privileges to uid {} gid {} (verified); {}",
                target.uid,
                target.gid,
                attribution_note
            );
            Ok(UidDropOutcome {
                dropped: true,
                message: Some(format!(
                    "root dropped to uid {} gid {}",
                    target.uid, target.gid
                )),
            })
        }
        Err(e) => {
            if config.mode == SandboxMode::Strict {
                return Err(e.context("Strict mode requires the root uid drop to succeed"));
            }
            log::warn!("Failed to drop root uid/gid: {}", e);
            Ok(UidDropOutcome {
                dropped: false,
                message: Some(format!("root uid drop failed: {}", e)),
            })
        }
    }
}

/// Apply the sandbox with the given configuration.
///
/// See the crate docs for the required application order. Returns
/// `Ok(SandboxReport)` with details about what was applied; in
/// [`SandboxMode::Strict`], returns `Err` if enforcement cannot be achieved.
pub fn apply_sandbox(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    #[cfg(target_os = "linux")]
    return linux::apply(config);
    #[cfg(target_os = "macos")]
    return macos::apply(config);
    #[cfg(target_os = "windows")]
    return windows::apply(config);
    #[cfg(target_os = "freebsd")]
    return freebsd::apply(config);
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    )))]
    {
        log::warn!("Sandboxing not implemented for this platform");
        let _ = config;
        Ok(SandboxReport {
            message: "Sandboxing not implemented for this platform".to_string(),
            ..SandboxReport::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_from_flags() {
        assert_eq!(
            SandboxMode::from_flags(false, false),
            SandboxMode::BestEffort
        );
        assert_eq!(SandboxMode::from_flags(false, true), SandboxMode::Strict);
        assert_eq!(SandboxMode::from_flags(true, false), SandboxMode::Disabled);
    }

    #[test]
    fn test_report_from_error_defaults_everything_off() {
        let report = SandboxReport::from_error(&anyhow::anyhow!("boom"));
        assert_eq!(report.status, SandboxStatus::Error);
        assert_eq!(report.message, "boom");
        assert!(!report.fs_restricted);
        assert!(!report.net_restricted);
        assert!(!report.uid_dropped);
    }
}
