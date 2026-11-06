//! FreeBSD sandboxing support
//!
//! FreeBSD has no sandbox implementation yet (Capsicum is planned); until
//! then the root uid drop is the primary containment: done after
//! initialization, when the BPF capture fds are open and nothing needs root
//! anymore.

use crate::{SandboxConfig, SandboxMode, SandboxReport, drop_root_step};

/// Apply the sandbox: currently the uid drop only (Capsicum planned).
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxReport {
            message: "Sandbox disabled by configuration".to_string(),
            ..SandboxReport::default()
        });
    }

    let outcome = drop_root_step(
        config,
        "sockstat process attribution is now limited to that user's processes",
    )?;

    Ok(SandboxReport::uid_drop_only(
        "No sandbox on FreeBSD yet (Capsicum planned)",
        &outcome,
    ))
}
