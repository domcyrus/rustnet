//! macOS sandboxing support
//!
//! Drops the root uid (when applicable) and then applies a Seatbelt profile
//! restricting the process after initialization is complete. This is a
//! defense-in-depth measure that limits damage if the application (processing
//! untrusted network data) is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Identity: when started as root (e.g. `sudo rustnet`), euid/egid drop to
//!   the invoking user (SUDO_UID/SUDO_GID) or `nobody`, see
//!   [`privdrop`](crate::privdrop). Disable with `--no-uid-drop`.
//! - Network: Outbound TCP/UDP connections blocked, optionally allowing DNS
//!   traffic only to destination port 53
//! - Filesystem writes: Credential directories blocked (~/.ssh, ~/.aws, etc.)
//! - Filesystem writes: Only configured log and PCAP export paths writable
//!
//! The uid drop runs BEFORE Seatbelt so the profile does not need to allow
//! the setuid/setgid syscalls. Without the `macos-sandbox` feature only the
//! uid drop is performed.
//!
//! # Compatibility
//!
//! - macOS 10.5+: Full support (Seatbelt has been present since Leopard)
//! - All Intel and Apple Silicon hardware supported

#[cfg(feature = "macos-sandbox")]
mod seatbelt;

use crate::{SandboxConfig, SandboxMode, SandboxReport, drop_root_step};

/// Apply the sandbox: uid drop first, then Seatbelt (feature-gated).
pub(crate) fn apply(
    config: &SandboxConfig,
    allow_dns_resolution: bool,
) -> anyhow::Result<SandboxReport> {
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        return Ok(SandboxReport {
            message: "Sandbox disabled by configuration".to_string(),
            ..SandboxReport::default()
        });
    }

    // Drop root privileges before Seatbelt so the profile does not need to
    // allow the setuid/setgid syscalls. Capture fds opened during
    // initialization (BPF/PKTAP) remain valid across the drop.
    let outcome = drop_root_step(
        config,
        "lsof-fallback process attribution is now limited to that user's processes \
         (PKTAP attribution unaffected)",
    )?;

    #[cfg(feature = "macos-sandbox")]
    {
        use crate::SandboxStatus;

        match seatbelt::apply_seatbelt(config, allow_dns_resolution) {
            Ok(result) => {
                // The uid drop counts towards enforcement: Seatbelt without
                // a requested drop (or vice versa) is partial.
                let drop_ok = config.drop_uid.is_none() || outcome.dropped;
                let status = match (result.applied, drop_ok, outcome.dropped) {
                    (true, true, _) => SandboxStatus::FullyEnforced,
                    (true, false, _) | (false, _, true) => SandboxStatus::PartiallyEnforced,
                    _ => SandboxStatus::NotApplied,
                };

                if result.applied {
                    log::info!("Seatbelt: {}", result.message);
                } else {
                    log::warn!("Seatbelt sandbox not applied: {}", result.message);
                }

                Ok(SandboxReport {
                    status,
                    message: outcome.message_after(&result.message),
                    seatbelt_applied: result.applied,
                    fs_restricted: result.fs_restricted,
                    net_restricted: result.net_restricted,
                    uid_dropped: outcome.dropped,
                })
            }
            Err(e) => {
                let msg = format!("Seatbelt application failed: {}", e);
                log::warn!("{}", msg);

                if config.mode == SandboxMode::Strict {
                    return Err(e.context("Strict mode requires Seatbelt sandboxing"));
                }

                Ok(SandboxReport::uid_drop_only(&msg, &outcome))
            }
        }
    }

    #[cfg(not(feature = "macos-sandbox"))]
    {
        let _ = allow_dns_resolution;
        if config.mode == SandboxMode::Strict {
            anyhow::bail!("Strict mode requires a build with Seatbelt support");
        }
        log::warn!("Seatbelt feature not compiled in");
        Ok(SandboxReport::uid_drop_only(
            "Seatbelt feature not compiled in",
            &outcome,
        ))
    }
}
