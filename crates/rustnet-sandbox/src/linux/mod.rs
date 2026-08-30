//! Linux sandboxing support
//!
//! Provides multi-layered sandboxing for restricting process capabilities
//! after initialization is complete. This is a defense-in-depth measure
//! that limits damage if the application (processing untrusted network data)
//! is compromised.
//!
//! # Security Model
//!
//! After sandboxing is applied:
//! - Filesystem: Only `/proc`, public account databases, and specified read paths
//!   (e.g., GeoIP databases) readable
//! - Filesystem: Only specified write paths writable (e.g., logs, exports)
//! - Network: TCP bind/connect blocked (kernel 6.7+, ABI v4)
//! - Scope: abstract UNIX socket connects + signals to outside processes blocked
//!   (kernel 6.12+, ABI v6)
//! - Capabilities: CAP_NET_RAW, CAP_BPF, CAP_PERFMON dropped
//! - Identity: when started as root (e.g. `sudo rustnet`), euid/egid drop to
//!   the invoking user (SUDO_UID/SUDO_GID) or `nobody`, see
//!   [`privdrop`](crate::privdrop). Disable with `--no-uid-drop`.
//! - Privileges: PR_SET_NO_NEW_PRIVS set by rustnet itself (no privilege
//!   escalation via execve). This is applied unconditionally — even with
//!   `--no-sandbox` or when Landlock is unavailable — since it is privilege
//!   hygiene rather than sandboxing and rustnet never execs on Linux.
//!
//! # Application Order
//!
//! 1. Set PR_SET_NO_NEW_PRIVS
//! 2. Drop capabilities (CAP_NET_RAW, CAP_BPF, CAP_PERFMON)
//! 3. Drop root uid/gid (setresuid to SUDO_UID/SUDO_GID or nobody)
//! 4. Apply Landlock (filesystem + network restrictions; needs no privileges
//!    since PR_SET_NO_NEW_PRIVS is already set)
//!
//! # Compatibility
//!
//! - Kernel 5.13+: Filesystem sandboxing
//! - Kernel 6.7+:  Network sandboxing (TCP bind/connect, ABI v4)
//! - Kernel 6.12+: Scope sandboxing (abstract UNIX sockets + signals, ABI v6)
//! - Older kernels: Graceful degradation (unsupported restrictions dropped)

#[cfg(feature = "landlock")]
pub mod capabilities;
#[cfg(feature = "landlock")]
mod landlock;

use crate::{SandboxConfig, SandboxMode, SandboxReport, SandboxStatus, privdrop};

/// Set PR_SET_NO_NEW_PRIVS: execve() can never grant new privileges
/// (setuid/setgid bits, file capabilities). Irreversible and inherited by
/// children/threads. The landlock crate sets this again in `restrict_self()`;
/// setting it twice is a no-op.
fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) takes no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Apply the sandbox with the given configuration (see crate docs for the
/// required application order).
#[cfg(feature = "landlock")]
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    use anyhow::Context;

    // Set PR_SET_NO_NEW_PRIVS first, regardless of sandbox mode. This is
    // privilege hygiene (blocks setuid/file-caps escalation via execve), not
    // sandboxing, and rustnet never execs on Linux — so it applies even with
    // --no-sandbox.
    let no_new_privs = match set_no_new_privs() {
        Ok(()) => {
            log::info!("PR_SET_NO_NEW_PRIVS set");
            true
        }
        Err(e) => {
            log::warn!("Failed to set PR_SET_NO_NEW_PRIVS: {}", e);
            false
        }
    };
    if !no_new_privs && config.mode == SandboxMode::Strict {
        return Err(anyhow::anyhow!(
            "Strict mode requires PR_SET_NO_NEW_PRIVS to be settable"
        ));
    }

    // Check Landlock availability upfront
    let landlock_available = landlock::is_available();

    // Handle disabled mode
    if config.mode == SandboxMode::Disabled {
        log::info!("Sandbox disabled by configuration");
        let message = if no_new_privs {
            "Sandbox disabled by configuration (no-new-privs still set)"
        } else {
            "Sandbox disabled by configuration"
        };
        return Ok(SandboxReport {
            message: message.to_string(),
            landlock_available,
            no_new_privs,
            ..SandboxReport::default()
        });
    }

    let mut result = SandboxReport {
        status: SandboxStatus::FullyEnforced,
        landlock_available,
        no_new_privs,
        ..SandboxReport::default()
    };

    let mut messages = Vec::new();
    if no_new_privs {
        messages.push("no-new-privs set".to_string());
    } else {
        messages.push("no-new-privs could not be set".to_string());
    }

    // Step 0: Clear ambient capability set
    // Ambient caps survive execve() — clearing prevents child processes
    // from inheriting any capabilities if fork/exec somehow succeeds.
    if let Err(e) = capabilities::clear_ambient_caps() {
        log::debug!("Could not clear ambient capabilities: {}", e);
    }

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

    // Step 2: Drop CAP_BPF and CAP_PERFMON
    // These are only needed for loading eBPF programs (already done)
    match capabilities::drop_ebpf_caps() {
        Ok(count) => {
            if count > 0 {
                result.ebpf_caps_dropped = true;
                messages.push(format!("eBPF capabilities dropped ({})", count));
                log::info!("Dropped {} eBPF capabilities", count);
            } else {
                log::debug!("No eBPF capabilities were held");
            }
        }
        Err(e) => {
            let msg = format!("Failed to drop eBPF capabilities: {}", e);
            log::warn!("{}", msg);
            messages.push(msg);
            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires eBPF capabilities to be droppable");
            }
        }
    }

    // Step 3: Drop the root uid/gid (sudo case)
    // Capabilities alone leave euid 0; on kernels without Landlock this drop
    // is the main containment. Runs after the capability drops purely for
    // reporting; transitioning all uids away from 0 clears the capability
    // sets anyway. Runs before Landlock, which needs no privileges since
    // PR_SET_NO_NEW_PRIVS is already set. The libc set*id wrappers apply the
    // change to every thread, including those spawned before this point.
    if let Some(target) = config.drop_uid {
        match privdrop::drop_to(target) {
            Ok(()) => {
                result.uid_dropped = true;
                messages.push(format!(
                    "root dropped to uid {} gid {}",
                    target.uid, target.gid
                ));
                log::info!(
                    "Dropped root privileges to the target uid/gid (verified); \
                     procfs process attribution is now limited to that user's \
                     processes (eBPF attribution unaffected)"
                );
            }
            Err(e) => {
                let msg = format!("Failed to drop root uid/gid: {}", e);
                log::warn!("{}", msg);
                messages.push(msg);
                if config.mode == SandboxMode::Strict {
                    return Err(e).context("Strict mode requires the root uid drop to succeed");
                }
                result.status = SandboxStatus::PartiallyEnforced;
            }
        }
    }

    // Step 4: Apply Landlock restrictions
    match landlock::apply_landlock(config) {
        Ok(ll_result) => {
            result.fs_restricted = ll_result.fs_applied;
            result.net_restricted = ll_result.net_applied;
            result.scope_restricted = ll_result.scope_applied;
            result.landlock_abi = ll_result.effective_abi;

            if ll_result.fs_applied {
                messages.push("Landlock filesystem restrictions applied".to_string());
            }
            if ll_result.net_applied {
                messages.push("Landlock network restrictions applied".to_string());
            }
            if ll_result.scope_applied {
                messages.push("Landlock scope restrictions applied".to_string());
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
    if !result.cap_net_raw_dropped
        && !result.uid_dropped
        && !result.fs_restricted
        && !result.net_restricted
    {
        result.status = SandboxStatus::NotApplied;
    }

    // Use appropriate log level based on status
    match result.status {
        SandboxStatus::FullyEnforced => {
            log::info!("Sandbox fully enforced: {}", messages.join("; "));
        }
        SandboxStatus::PartiallyEnforced => {
            log::warn!("Sandbox partially enforced: {}", messages.join("; "));
        }
        _ => {
            log::warn!("Sandbox not applied: {}", messages.join("; "));
        }
    }

    result.message = messages.join("; ");

    Ok(result)
}

/// Stub implementation when the Landlock feature is disabled
#[cfg(not(feature = "landlock"))]
pub(crate) fn apply(config: &SandboxConfig) -> anyhow::Result<SandboxReport> {
    // PR_SET_NO_NEW_PRIVS is independent of Landlock support, so non-landlock
    // builds still get the execve privilege lock.
    let no_new_privs = match set_no_new_privs() {
        Ok(()) => {
            log::info!("PR_SET_NO_NEW_PRIVS set");
            true
        }
        Err(e) => {
            log::warn!("Failed to set PR_SET_NO_NEW_PRIVS: {}", e);
            false
        }
    };
    if !no_new_privs && config.mode == SandboxMode::Strict {
        return Err(anyhow::anyhow!(
            "Strict mode requires PR_SET_NO_NEW_PRIVS to be settable"
        ));
    }

    // The uid drop needs only libc, so non-landlock builds still shed root
    // after initialization (unless the sandbox is disabled entirely).
    let mut uid_dropped = false;
    let mut drop_message = String::new();
    if config.mode != SandboxMode::Disabled
        && let Some(target) = config.drop_uid
    {
        match privdrop::drop_to(target) {
            Ok(()) => {
                uid_dropped = true;
                drop_message = format!("; root dropped to uid {} gid {}", target.uid, target.gid);
                log::info!(
                    "Dropped root privileges to the target uid/gid (verified); \
                     procfs process attribution is now limited to that user's \
                     processes"
                );
            }
            Err(e) => {
                log::warn!("Failed to drop root uid/gid: {}", e);
                if config.mode == SandboxMode::Strict {
                    return Err(e.context("Strict mode requires the root uid drop to succeed"));
                }
                drop_message = format!("; root uid drop failed: {}", e);
            }
        }
    }

    log::warn!("Landlock feature not compiled in");
    let message = if no_new_privs {
        "Landlock feature not compiled in (no-new-privs still set)"
    } else {
        "Landlock feature not compiled in"
    };
    Ok(SandboxReport {
        status: if uid_dropped {
            SandboxStatus::PartiallyEnforced
        } else {
            SandboxStatus::NotApplied
        },
        message: format!("{}{}", message, drop_message),
        uid_dropped,
        no_new_privs,
        ..SandboxReport::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_no_new_privs_is_idempotent_and_sticks() {
        // NNP is per-task and irreversible, but nothing in the test suite
        // execs setuid binaries, so restricting the test process is safe
        // (same precedent as the landlock restrict_self test).
        set_no_new_privs().expect("first set_no_new_privs call");
        set_no_new_privs().expect("second set_no_new_privs call (idempotent)");
        // SAFETY: prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) takes no pointers.
        let value = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        assert_eq!(value, 1, "NoNewPrivs should be set after set_no_new_privs");
    }
}
