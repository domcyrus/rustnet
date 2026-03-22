//! macOS sandboxing support
//!
//! Provides Seatbelt-based sandboxing for restricting process capabilities
//! after initialization is complete. This is a defense-in-depth measure
//! that limits damage if the application (processing untrusted network data)
//! is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Network: Outbound TCP/UDP connections blocked (RustNet is passive)
//! - Filesystem writes: Credential directories blocked (~/.ssh, ~/.aws, etc.)
//! - Filesystem writes: Only configured log and PCAP export paths writable
//!
//! # Compatibility
//!
//! - macOS 10.5+: Full support (Seatbelt has been present since Leopard)
//! - All Intel and Apple Silicon hardware supported

mod seatbelt;

/// Sandbox enforcement mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxMode {
    /// Apply sandbox with best-effort (graceful degradation on failure)
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
    /// Block outbound TCP/UDP connections (recommended for passive monitors)
    pub block_network: bool,
    /// Log directory path that needs write access
    pub log_dir: Option<String>,
    /// JSON log file path that needs write access
    pub json_log_path: Option<String>,
    /// PCAP export file path that needs write access
    pub pcap_export_path: Option<String>,
}

/// Result of sandbox application
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Overall status
    pub status: SandboxStatus,
    /// Human-readable message
    pub message: String,
    /// Whether Seatbelt was successfully applied
    pub seatbelt_applied: bool,
}

/// Status of sandbox application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Sandbox fully enforced
    FullyEnforced,
    /// Sandbox not applied (disabled or failed in BestEffort mode)
    NotApplied,
}

/// Apply the sandbox with the given configuration
///
/// This should be called AFTER:
/// - Packet capture handles are opened (BPF/PKTAP fds survive the sandbox)
/// - Log files are created
///
/// # Returns
///
/// Returns `Ok(SandboxResult)` with details about what was applied.
/// In `Strict` mode, returns `Err` if sandboxing cannot be applied.
pub fn apply_sandbox(config: &SandboxConfig) -> anyhow::Result<SandboxResult> {
    use anyhow::Context;

    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxResult {
            status: SandboxStatus::NotApplied,
            message: "Sandbox disabled by configuration".to_string(),
            seatbelt_applied: false,
        });
    }

    match seatbelt::apply_seatbelt(config) {
        Ok(result) => {
            let status = if result.applied {
                SandboxStatus::FullyEnforced
            } else {
                SandboxStatus::NotApplied
            };

            log::info!("Seatbelt: {}", result.message);

            Ok(SandboxResult {
                status,
                message: result.message,
                seatbelt_applied: result.applied,
            })
        }
        Err(e) => {
            let msg = format!("Seatbelt application failed: {}", e);
            log::warn!("{}", msg);

            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires Seatbelt sandboxing");
            }

            Ok(SandboxResult {
                status: SandboxStatus::NotApplied,
                message: msg,
                seatbelt_applied: false,
            })
        }
    }
}
