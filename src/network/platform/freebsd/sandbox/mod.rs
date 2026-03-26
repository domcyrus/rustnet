//! FreeBSD sandboxing support
//!
//! Provides Capsicum-based sandboxing for restricting file descriptor
//! capabilities after initialization is complete. This is a defense-in-depth
//! measure that limits damage if the application (processing untrusted
//! network data) is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Output file FDs: restricted to write-only (no reading sensitive data)
//!
//! **Note:** This is FD-level hardening only, not full Capsicum capability
//! mode (`cap_enter()`). A compromised process can still open new files and
//! sockets. See `capsicum.rs` for details and the rationale.
//!
//! # Why cap_rights_limit Instead of cap_enter
//!
//! RustNet on FreeBSD uses `sockstat` subprocess for process identification.
//! `cap_enter()` would block fork/exec, breaking this. We use per-FD
//! restrictions instead, which provide meaningful hardening without
//! disrupting runtime behavior. A future switch to `libprocstat(3)` would
//! eliminate the fork/exec dependency and enable full capability mode.

mod capsicum;

use anyhow::Context;
use std::path::Path;

/// Sandbox enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// Apply sandbox with best-effort (graceful degradation)
    #[default]
    BestEffort,
    /// Require full sandbox enforcement or fail
    Strict,
    /// Disable sandboxing entirely
    Disabled,
}

/// Configuration for the sandbox
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Sandbox enforcement mode
    pub mode: SandboxMode,
    /// Paths that need write access (will be FD-restricted to write-only)
    pub write_paths: Vec<String>,
}

/// Result of sandbox application
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Overall status
    pub status: SandboxStatus,
    /// Human-readable message
    pub message: String,
    /// Whether Capsicum FD restrictions were applied
    pub capsicum_applied: bool,
    /// Number of FDs restricted
    pub fds_restricted: u32,
}

/// Status of sandbox application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Sandbox fully enforced
    FullyEnforced,
    /// Sandbox not applied (disabled or no FDs to restrict)
    NotApplied,
}

/// Apply the sandbox with the given configuration
///
/// This should be called AFTER:
/// - Packet capture handles are opened
/// - Log files are created
pub fn apply_sandbox(config: &SandboxConfig) -> anyhow::Result<SandboxResult> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxResult {
            status: SandboxStatus::NotApplied,
            message: "Sandbox disabled by configuration".to_string(),
            capsicum_applied: false,
            fds_restricted: 0,
        });
    }

    let write_paths: Vec<&Path> = config
        .write_paths
        .iter()
        .map(|p| Path::new(p.as_str()))
        .collect();

    match capsicum::apply_capsicum(&write_paths) {
        Ok(result) => {
            let status = if result.applied {
                log::info!("Capsicum sandbox applied: {}", result.message);
                SandboxStatus::FullyEnforced
            } else {
                log::warn!("Capsicum sandbox not applied: {}", result.message);
                SandboxStatus::NotApplied
            };

            if config.mode == SandboxMode::Strict && !result.applied {
                return Err(anyhow::anyhow!(
                    "Strict mode requires Capsicum enforcement: {}",
                    result.message
                ));
            }

            Ok(SandboxResult {
                status,
                message: result.message,
                capsicum_applied: result.applied,
                fds_restricted: result.fds_restricted,
            })
        }
        Err(e) => {
            let msg = format!("Capsicum application failed: {}", e);
            log::warn!("{}", msg);

            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires Capsicum sandboxing");
            }

            Ok(SandboxResult {
                status: SandboxStatus::NotApplied,
                message: msg,
                capsicum_applied: false,
                fds_restricted: 0,
            })
        }
    }
}
