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
//! - Filesystem: Only `/proc`, public account databases, optionally the exact
//!   DNS resolver files, and specified read paths (e.g., GeoIP databases)
//!   readable
//! - Filesystem: Only specified write paths writable (e.g., logs, exports)
//! - Network: TCP bind/connect blocked, optionally allowing DNS connects to
//!   destination port 53 (kernel 6.7+, ABI v4)
//! - Scope: abstract UNIX socket connects + signals to outside processes blocked
//!   (kernel 6.12+, ABI v6)
//! - Capabilities: CAP_NET_RAW, CAP_BPF, CAP_PERFMON dropped
//! - Identity: when started as root (e.g. `sudo rustnet`), euid/egid drop to
//!   the invoking user (SUDO_UID/SUDO_GID) or `nobody`, see
//!   [`privdrop`](crate::privdrop). Disable with `--no-uid-drop`.
//! - Privileges: PR_SET_NO_NEW_PRIVS set by rustnet itself (no privilege
//!   escalation via execve). This is applied unconditionally (even with
//!   `--no-sandbox` or when Landlock is unavailable) since it is privilege
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

use crate::{SandboxConfig, SandboxMode, SandboxReport, SandboxStatus, drop_root_step};

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
///
/// Without the `landlock` feature the capability drops and Landlock steps
/// are compiled out; PR_SET_NO_NEW_PRIVS and the root uid drop still run.
pub(crate) fn apply(
    config: &SandboxConfig,
    allow_dns_resolution: bool,
) -> anyhow::Result<SandboxReport> {
    #[cfg(feature = "landlock")]
    use anyhow::Context;

    // Set PR_SET_NO_NEW_PRIVS first, regardless of sandbox mode. This is
    // privilege hygiene (blocks setuid/file-caps escalation via execve), not
    // sandboxing, and rustnet never execs on Linux, so it applies even with
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

    #[cfg(feature = "landlock")]
    let landlock_available = landlock::is_available();
    #[cfg(not(feature = "landlock"))]
    let landlock_available = false;

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

    #[cfg(feature = "landlock")]
    {
        // Ambient caps survive execve(): clearing prevents child processes
        // from inheriting any capabilities if fork/exec somehow succeeds.
        if let Err(e) = capabilities::clear_ambient_caps() {
            if config.mode == SandboxMode::Strict {
                return Err(e).context("Strict mode requires ambient capabilities to be cleared");
            }
            log::warn!("Could not clear ambient capabilities: {}", e);
            messages.push(format!("Failed to clear ambient capabilities: {e}"));
            result.status = SandboxStatus::PartiallyEnforced;
        }

        // Dropping CAP_NET_RAW prevents creating new raw sockets for exfiltration.
        match capabilities::drop_cap_net_raw() {
            Ok(dropped) => {
                if dropped {
                    result.cap_net_raw_dropped = true;
                    messages.push("CAP_NET_RAW dropped".to_string());
                    log::info!("Dropped CAP_NET_RAW capability (verified)");
                } else {
                    messages.push("CAP_NET_RAW was not held".to_string());
                    log::debug!("CAP_NET_RAW was not effective or permitted");
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

        // CAP_BPF and CAP_PERFMON are only needed for loading eBPF programs
        // (already done).
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
                    return Err(e)
                        .context("Strict mode requires eBPF capabilities to be droppable");
                }
            }
        }
    }

    // Capabilities alone leave euid 0; on kernels without Landlock (or in
    // builds without the landlock feature) this drop is the main containment.
    // Runs after the capability drops purely for reporting; transitioning all
    // uids away from 0 clears the capability sets anyway. Runs before
    // Landlock, which needs no privileges since PR_SET_NO_NEW_PRIVS is
    // already set. The libc set*id wrappers apply the change to every thread,
    // including those spawned before this point.
    let uid_drop = drop_root_step(
        config,
        "procfs process attribution is now limited to that user's processes \
         (eBPF attribution unaffected)",
    )?;
    result.uid_dropped = uid_drop.dropped;
    if let Some(msg) = uid_drop.message {
        messages.push(msg);
        if !uid_drop.dropped {
            result.status = SandboxStatus::PartiallyEnforced;
        }
    }

    #[cfg(feature = "landlock")]
    match landlock::apply_landlock(config, allow_dns_resolution) {
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
            let missing_fs = !ll_result.fs_fully_enforced;
            let missing_net = config.block_network && !ll_result.net_applied;
            let missing_scope = config.block_network && !ll_result.scope_applied;
            if missing_fs || missing_net || missing_scope {
                messages.push(format!("Landlock incomplete: {}", ll_result.message));
                if config.mode == SandboxMode::Strict {
                    return Err(anyhow::anyhow!(
                        "Strict mode requires all requested Landlock restrictions (filesystem={}, network={}, scope={}): {}",
                        !missing_fs,
                        !missing_net,
                        !missing_scope,
                        ll_result.message
                    ));
                }
                result.status = SandboxStatus::PartiallyEnforced;
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

    // Without the landlock feature there is nothing to enforce beyond the uid drop.
    #[cfg(not(feature = "landlock"))]
    {
        if config.mode == SandboxMode::Strict {
            anyhow::bail!("Strict mode requires a build with Landlock support");
        }
        log::warn!("Landlock feature not compiled in");
        messages.push("Landlock feature not compiled in".to_string());
        result.status = SandboxStatus::PartiallyEnforced;
    }

    if !result.cap_net_raw_dropped
        && !result.uid_dropped
        && !result.fs_restricted
        && !result.net_restricted
    {
        result.status = SandboxStatus::NotApplied;
    }

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
