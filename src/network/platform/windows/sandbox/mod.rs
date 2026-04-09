//! Windows sandboxing support
//!
//! Provides privilege removal and job object restrictions to reduce blast
//! radius if the application (processing untrusted network data) is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Dangerous privileges removed (SeDebugPrivilege, SeTakeOwnershipPrivilege, etc.)
//! - Child process creation blocked via Job Object
//!
//! # Limitations
//!
//! Windows sandboxing is weaker than Linux/macOS/FreeBSD:
//! - No filesystem restriction (Windows ACLs are per-object, not process-wide)
//! - No network restriction (would break Npcap packet capture)
//! - Privilege removal only affects privileges the process held

mod restricted;

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
}

/// Result of sandbox application
#[derive(Debug, Clone)]
pub struct SandboxResult {
    /// Overall status
    pub status: SandboxStatus,
    /// Human-readable message
    pub message: String,
    /// Whether dangerous privileges were removed
    pub privileges_removed: bool,
    /// Number of privileges removed
    pub privileges_removed_count: u32,
    /// Whether job object was applied
    pub job_object_applied: bool,
}

/// Status of sandbox application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Sandbox fully enforced (privileges removed + job object)
    FullyEnforced,
    /// Sandbox partially enforced (some components failed)
    PartiallyEnforced,
    /// Sandbox not applied (disabled or all components failed)
    NotApplied,
}

/// Apply the sandbox with the given configuration
///
/// This should be called AFTER:
/// - Npcap handles are opened
/// - Log files are created
pub fn apply_sandbox(config: &SandboxConfig) -> anyhow::Result<SandboxResult> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxResult {
            status: SandboxStatus::NotApplied,
            message: "Sandbox disabled by configuration".to_string(),
            privileges_removed: false,
            privileges_removed_count: 0,
            job_object_applied: false,
        });
    }

    let mut messages = Vec::new();
    let mut privileges_removed = false;
    let mut privileges_removed_count = 0u32;
    let mut privileges_succeeded = false;
    let mut job_object_applied = false;

    // Step 1: Remove dangerous privileges
    match restricted::remove_dangerous_privileges() {
        Ok(result) => {
            privileges_removed = result.privileges_removed;
            privileges_removed_count = result.privileges_removed_count;
            privileges_succeeded = result.succeeded;
            log::info!("Privilege restriction: {}", result.message);
            messages.push(result.message);
        }
        Err(e) => {
            let msg = format!("Privilege restriction failed: {}", e);
            log::warn!("{}", msg);
            messages.push(msg);
        }
    }

    // Step 2: Apply job object to prevent child process creation
    match restricted::apply_job_object() {
        Ok(result) => {
            job_object_applied = result.applied;
            log::info!("Job object: {}", result.message);
            messages.push(result.message);
        }
        Err(e) => {
            let msg = format!("Job object failed: {}", e);
            log::warn!("{}", msg);
            messages.push(msg);
        }
    }

    // Status reflects whether each step *succeeded*, not whether anything
    // was actually removed. A standard (non-elevated) user never held the
    // dangerous privileges, so a successful no-op is the desired end state.
    let status = if privileges_succeeded && job_object_applied {
        SandboxStatus::FullyEnforced
    } else if privileges_succeeded || job_object_applied {
        SandboxStatus::PartiallyEnforced
    } else {
        SandboxStatus::NotApplied
    };

    if config.mode == SandboxMode::Strict && status != SandboxStatus::FullyEnforced {
        return Err(anyhow::anyhow!(
            "Strict mode requires full sandbox enforcement: {}",
            messages.join("; ")
        ));
    }

    Ok(SandboxResult {
        status,
        message: messages.join("; "),
        privileges_removed,
        privileges_removed_count,
        job_object_applied,
    })
}
