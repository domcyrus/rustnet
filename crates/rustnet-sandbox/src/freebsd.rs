//! FreeBSD sandboxing support
//!
//! FreeBSD has no sandbox implementation yet (Capsicum is planned); until
//! then the root uid drop is the primary containment: done after
//! initialization, when the BPF capture fds are open and nothing needs root
//! anymore.

use crate::{SandboxConfig, SandboxMode, SandboxReport, SandboxStatus, privdrop};

/// Apply the sandbox: currently the uid drop only (Capsicum planned).
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxReport {
            message: "Sandbox disabled by configuration".to_string(),
            ..SandboxReport::default()
        });
    }

    let mut uid_dropped = false;
    let mut drop_message = String::new();
    if let Some(target) = config.drop_uid {
        match privdrop::drop_to(target) {
            Ok(()) => {
                uid_dropped = true;
                drop_message = format!("; root dropped to uid {} gid {}", target.uid, target.gid);
                log::info!(
                    "Dropped root privileges to uid {} gid {} (verified); sockstat process \
                     attribution is now limited to that user's processes",
                    target.uid,
                    target.gid
                );
            }
            Err(e) => {
                if config.mode == SandboxMode::Strict {
                    return Err(e.context("Strict mode requires the root uid drop to succeed"));
                }
                log::warn!("Failed to drop root uid/gid: {}", e);
                drop_message = format!("; root uid drop failed: {}", e);
            }
        }
    }

    Ok(SandboxReport {
        status: if uid_dropped {
            SandboxStatus::PartiallyEnforced
        } else {
            SandboxStatus::NotApplied
        },
        message: format!("No sandbox on FreeBSD yet (Capsicum planned){}", drop_message),
        uid_dropped,
        ..SandboxReport::default()
    })
}
