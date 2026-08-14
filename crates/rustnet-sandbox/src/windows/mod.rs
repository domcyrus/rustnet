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

use crate::{SandboxConfig, SandboxMode, SandboxReport, SandboxStatus};

/// Apply the sandbox with the given configuration (see crate docs for the
/// required application order).
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxReport {
            message: "Sandbox disabled by configuration".to_string(),
            ..SandboxReport::default()
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

    Ok(SandboxReport {
        status,
        message: messages.join("; "),
        privileges_removed,
        privileges_removed_count,
        job_object_applied,
        ..SandboxReport::default()
    })
}
