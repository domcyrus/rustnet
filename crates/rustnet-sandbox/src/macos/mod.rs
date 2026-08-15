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
//! - Network: Outbound TCP/UDP connections blocked (RustNet is passive)
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

use crate::{SandboxConfig, SandboxMode, SandboxReport, SandboxStatus, privdrop};

/// Apply the sandbox: uid drop first, then Seatbelt (feature-gated).
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
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
    let mut uid_dropped = false;
    let mut drop_message = String::new();
    if let Some(target) = config.drop_uid {
        match privdrop::drop_to(target) {
            Ok(()) => {
                uid_dropped = true;
                drop_message = format!("; root dropped to uid {} gid {}", target.uid, target.gid);
                log::info!(
                    "Dropped root privileges to uid {} gid {} (verified); lsof-fallback \
                     process attribution is now limited to that user's processes (PKTAP \
                     attribution unaffected)",
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

    #[cfg(feature = "macos-sandbox")]
    {
        match seatbelt::apply_seatbelt(config) {
            Ok(result) => {
                // The uid drop counts towards enforcement: Seatbelt without
                // a requested drop (or vice versa) is partial.
                let drop_ok = config.drop_uid.is_none() || uid_dropped;
                let status = match (result.applied, drop_ok, uid_dropped) {
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
                    message: format!("{}{}", result.message, drop_message),
                    seatbelt_applied: result.applied,
                    fs_restricted: result.fs_restricted,
                    net_restricted: result.net_blocked,
                    uid_dropped,
                })
            }
            Err(e) => {
                let msg = format!("Seatbelt application failed: {}", e);
                log::warn!("{}", msg);

                if config.mode == SandboxMode::Strict {
                    return Err(e.context("Strict mode requires Seatbelt sandboxing"));
                }

                Ok(SandboxReport {
                    status: if uid_dropped {
                        SandboxStatus::PartiallyEnforced
                    } else {
                        SandboxStatus::NotApplied
                    },
                    message: format!("{}{}", msg, drop_message),
                    uid_dropped,
                    ..SandboxReport::default()
                })
            }
        }
    }

    #[cfg(not(feature = "macos-sandbox"))]
    {
        log::warn!("Seatbelt feature not compiled in");
        Ok(SandboxReport {
            status: if uid_dropped {
                SandboxStatus::PartiallyEnforced
            } else {
                SandboxStatus::NotApplied
            },
            message: format!("Seatbelt feature not compiled in{}", drop_message),
            uid_dropped,
            ..SandboxReport::default()
        })
    }
}
