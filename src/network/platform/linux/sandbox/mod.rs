//! Linux sandboxing support
//!
//! Provides Landlock-based sandboxing for restricting process capabilities
//! after initialization is complete. This is a defense-in-depth measure
//! that limits damage if the application (processing untrusted network data)
//! is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Filesystem: Only `/proc` and specified read paths (e.g., GeoIP databases) readable
//! - Filesystem: Only specified write paths writable (e.g., logs, exports)
//! - Network: TCP bind/connect blocked (kernel 6.4+)
//! - Capabilities: CAP_NET_RAW dropped (cannot create new raw sockets)
//!
//! # Compatibility
//!
//! - Kernel 5.13+: Filesystem sandboxing
//! - Kernel 6.4+: Network sandboxing (TCP bind/connect)
//! - Older kernels: Graceful degradation (sandbox not applied)

#[cfg(feature = "landlock")]
mod capabilities;
#[cfg(feature = "landlock")]
mod landlock;

use std::path::PathBuf;

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

/// Configuration for the sandbox
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Sandbox enforcement mode
    pub mode: SandboxMode,
    /// Block TCP bind/connect (recommended for passive monitors)
    pub block_network: bool,
    /// Paths that need read access (e.g., GeoIP databases)
    pub read_paths: Vec<PathBuf>,
    /// Paths that need write access (e.g., log files)
    pub write_paths: Vec<PathBuf>,
}

/// Result of sandbox application
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Overall status
    pub status: SandboxStatus,
    /// Human-readable message
    pub message: String,
    /// Whether CAP_NET_RAW was dropped
    pub cap_net_raw_dropped: bool,
    /// Whether Landlock is available on this kernel
    pub landlock_available: bool,
    /// Whether Landlock filesystem restrictions were applied
    pub landlock_fs_applied: bool,
    /// Whether Landlock network restrictions were applied
    pub landlock_net_applied: bool,
}

/// Status of sandbox application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Sandbox fully enforced (all requested restrictions applied)
    FullyEnforced,
    /// Sandbox partially enforced (some features unavailable on this kernel)
    PartiallyEnforced,
    /// Sandbox not applied (disabled, or kernel doesn't support)
    NotApplied,
}

/// Apply the sandbox with the given configuration
///
/// This should be called AFTER:
/// - eBPF programs are loaded
/// - Packet capture handles are opened
/// - Log files are created
///
/// # Returns
///
/// Returns `Ok(SandboxResult)` with details about what was applied.
/// In `Strict` mode, returns `Err` if full sandboxing cannot be achieved.
#[cfg(feature = "landlock")]
pub fn apply_sandbox(config: &SandboxConfig) -> anyhow::Result<SandboxResult> {
    use anyhow::Context;

    // Check Landlock availability upfront
    let landlock_available = landlock::is_available();

    // Handle disabled mode
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxResult {
            status: SandboxStatus::NotApplied,
            message: "Sandbox disabled by configuration".to_string(),
            cap_net_raw_dropped: false,
            landlock_available,
            landlock_fs_applied: false,
            landlock_net_applied: false,
        });
    }

    let mut result = SandboxResult {
        status: SandboxStatus::FullyEnforced,
        message: String::new(),
        cap_net_raw_dropped: false,
        landlock_available,
        landlock_fs_applied: false,
        landlock_net_applied: false,
    };

    let mut messages = Vec::new();

    // Step 1: Drop CAP_NET_RAW capability
    // This prevents creating new raw sockets for exfiltration
    match capabilities::drop_cap_net_raw() {
        Ok(dropped) => {
            if dropped {
                // Verify the drop actually worked
                if capabilities::has_cap_net_raw() {
                    log::error!("CAP_NET_RAW drop reported success but capability still present!");
                    result.cap_net_raw_dropped = false;
                    messages.push("CAP_NET_RAW drop verification failed".to_string());
                } else {
                    result.cap_net_raw_dropped = true;
                    messages.push("CAP_NET_RAW dropped".to_string());
                    log::info!("Dropped CAP_NET_RAW capability (verified)");
                }
            } else {
                messages.push("CAP_NET_RAW was not held".to_string());
                log::debug!("CAP_NET_RAW was not in effective set");
            }
        }
        Err(e) => {
            let msg = format!("Failed to drop CAP_NET_RAW: {}", e);
            log::warn!("{}", msg);
            messages.push(msg);
            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires CAP_NET_RAW to be droppable");
            }
            result.status = SandboxStatus::PartiallyEnforced;
        }
    }

    // Step 2: Apply Landlock restrictions
    match landlock::apply_landlock(config) {
        Ok(ll_result) => {
            result.landlock_fs_applied = ll_result.fs_applied;
            result.landlock_net_applied = ll_result.net_applied;

            if ll_result.fs_applied {
                messages.push("Landlock filesystem restrictions applied".to_string());
            }
            if ll_result.net_applied {
                messages.push("Landlock network restrictions applied".to_string());
            }
            if !ll_result.fs_applied && !ll_result.net_applied {
                messages.push(format!("Landlock not applied: {}", ll_result.message));
                if config.mode == SandboxMode::Strict {
                    return Err(anyhow::anyhow!(
                        "Strict mode requires Landlock support: {}",
                        ll_result.message
                    ));
                }
                if result.status == SandboxStatus::FullyEnforced {
                    result.status = SandboxStatus::PartiallyEnforced;
                }
            } else if !ll_result.net_applied && config.block_network {
                // Filesystem applied but network not available
                if result.status == SandboxStatus::FullyEnforced {
                    result.status = SandboxStatus::PartiallyEnforced;
                }
            }
        }
        Err(e) => {
            let msg = format!("Landlock application failed: {}", e);
            log::warn!("{}", msg);
            messages.push(msg);
            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires Landlock");
            }
            result.status = SandboxStatus::PartiallyEnforced;
        }
    }

    // Determine final status
    if !result.cap_net_raw_dropped && !result.landlock_fs_applied && !result.landlock_net_applied {
        result.status = SandboxStatus::NotApplied;
    }

    result.message = messages.join("; ");
    log::info!("Sandbox result: {:?} - {}", result.status, result.message);

    Ok(result)
}

/// Stub implementation when Landlock feature is disabled
#[cfg(not(feature = "landlock"))]
pub fn apply_sandbox(_config: &SandboxConfig) -> anyhow::Result<SandboxResult> {
    log::debug!("Landlock feature not compiled in");
    Ok(SandboxResult {
        status: SandboxStatus::NotApplied,
        message: "Landlock feature not compiled in".to_string(),
        cap_net_raw_dropped: false,
        landlock_available: false,
        landlock_fs_applied: false,
        landlock_net_applied: false,
    })
}
