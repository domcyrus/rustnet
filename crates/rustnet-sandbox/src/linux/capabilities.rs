//! Linux capability management
//!
//! Handles dropping capabilities after they are no longer needed.
//! This follows the principle of least privilege - capabilities are
//! only held while necessary for initialization.
//!
//! # CAP_NET_RAW
//!
//! CAP_NET_RAW is required to create raw sockets for packet capture.
//! However, once the pcap handle is opened, the capability is no longer
//! needed and can be safely dropped. This prevents an attacker from
//! creating new raw sockets if they gain code execution.
//!
//! This is the same pattern used by `ping` and other network utilities.

use anyhow::{Context, Result};
use caps::{CapSet, Capability};

const ACTIVE_SETS: [CapSet; 2] = [CapSet::Effective, CapSet::Permitted];

fn has_cap_in_active_sets(capability: Capability) -> Result<bool> {
    for set in ACTIVE_SETS {
        if caps::has_cap(None, set, capability)
            .with_context(|| format!("Failed to check {capability:?} in {set:?} set"))?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn drop_and_verify(capability: Capability) -> Result<bool> {
    let mut dropped = false;
    for set in ACTIVE_SETS {
        if caps::has_cap(None, set, capability)
            .with_context(|| format!("Failed to check {capability:?} in {set:?} set"))?
        {
            caps::drop(None, set, capability)
                .with_context(|| format!("Failed to drop {capability:?} from {set:?} set"))?;
            dropped = true;
        }
    }

    if has_cap_in_active_sets(capability)? {
        anyhow::bail!("{capability:?} remained in an effective or permitted capability set");
    }
    Ok(dropped)
}

/// Drop CAP_NET_RAW from the current process
///
/// This removes CAP_NET_RAW from both the effective and permitted
/// capability sets. The existing pcap socket file descriptor remains
/// valid since the capability was only needed to create it.
///
/// # Returns
///
/// - `Ok(true)` if CAP_NET_RAW was dropped
/// - `Ok(false)` if CAP_NET_RAW was not held (nothing to drop)
/// - `Err` if dropping failed
pub(crate) fn drop_cap_net_raw() -> Result<bool> {
    drop_and_verify(Capability::CAP_NET_RAW)
}

/// Check if CAP_NET_RAW remains effective or permitted.
#[cfg(test)]
pub(crate) fn has_cap_net_raw() -> Result<bool> {
    has_cap_in_active_sets(Capability::CAP_NET_RAW)
}

/// Drop CAP_BPF and CAP_PERFMON from the current process
///
/// These capabilities are required for loading eBPF programs but are no
/// longer needed once the programs are loaded. Dropping them limits the
/// blast radius if the process is compromised.
///
/// # Returns
///
/// - `Ok(count)` where count is how many capabilities were dropped (0-2)
/// - `Err` if dropping failed
pub(crate) fn drop_ebpf_caps() -> Result<u32> {
    let mut dropped = 0;

    for cap in [Capability::CAP_BPF, Capability::CAP_PERFMON] {
        if drop_and_verify(cap)? {
            log::debug!("Dropped {:?} from effective and permitted sets", cap);
            dropped += 1;
        }
    }

    Ok(dropped)
}

/// Drop CAP_NET_RAW from a worker thread, logging the outcome.
///
/// Linux capabilities are per-thread, so threads spawned before the main
/// thread applies the sandbox keep their own copies and have to drop what they
/// do not use themselves. `thread` names the caller for the log line.
pub fn drop_thread_cap_net_raw(thread: &str) {
    match drop_cap_net_raw() {
        Ok(_) => log::debug!("Dropped CAP_NET_RAW in {thread}"),
        Err(e) => log::warn!("Failed to drop CAP_NET_RAW in {thread}: {e}"),
    }
}

/// Drop CAP_NET_RAW, CAP_BPF and CAP_PERFMON from a worker thread that needs
/// none of them.
///
/// Existing capture handles and eBPF map descriptors remain usable after these
/// capabilities are dropped. Program and map creation must already be complete.
pub fn drop_unused_thread_caps(thread: &str) {
    drop_thread_cap_net_raw(thread);
    match drop_ebpf_caps() {
        Ok(_) => log::debug!("Dropped eBPF capabilities in {thread}"),
        Err(e) => log::warn!("Failed to drop eBPF capabilities in {thread}: {e}"),
    }
}

/// Clear all ambient capabilities
///
/// Ambient capabilities survive `execve()` of non-privileged programs.
/// Clearing them prevents child processes from inheriting any capabilities
/// that were held by the parent. This is standard practice in container
/// runtimes (Docker, systemd) and security-sensitive daemons.
pub(crate) fn clear_ambient_caps() -> Result<()> {
    caps::clear(None, CapSet::Ambient).context("Failed to clear ambient capability set")?;
    log::debug!("Cleared ambient capability set");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_cap_net_raw_does_not_panic() {
        assert!(has_cap_net_raw().is_ok());
    }

    #[test]
    fn test_drop_cap_net_raw_without_capability() {
        let result = drop_cap_net_raw();
        assert!(result.is_ok());
    }

    #[test]
    fn test_drop_ebpf_caps_does_not_panic() {
        let result = drop_ebpf_caps();
        assert!(result.is_ok());
    }

    #[test]
    #[ignore = "requires root with capture and identity-change capabilities in a dedicated process"]
    fn capture_capability_drops_preserve_uid_and_gid_changes() {
        // SAFETY: geteuid has no arguments or failure mode.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let required = [
            Capability::CAP_SETUID,
            Capability::CAP_SETGID,
            Capability::CAP_NET_RAW,
            Capability::CAP_BPF,
            Capability::CAP_PERFMON,
        ];
        let mut expected = ACTIVE_SETS.map(|set| {
            let held = caps::read(None, set).unwrap();
            for capability in required {
                assert!(
                    held.contains(&capability),
                    "{capability:?} missing from {set:?}"
                );
            }
            held
        });

        clear_ambient_caps().unwrap();
        for capability in [
            Capability::CAP_NET_RAW,
            Capability::CAP_BPF,
            Capability::CAP_PERFMON,
        ] {
            assert!(drop_and_verify(capability).unwrap());
            for (set, held) in ACTIVE_SETS.into_iter().zip(&mut expected) {
                held.remove(&capability);
                assert_eq!(caps::read(None, set).unwrap(), *held);
                assert!(held.contains(&Capability::CAP_SETUID));
                assert!(held.contains(&Capability::CAP_SETGID));
            }
        }

        // This changes every test-process thread's identity. Run only this
        // ignored test in its own process, never alongside other tests.
        crate::privdrop::drop_to(crate::privdrop::DropTarget {
            uid: 65534,
            gid: 65534,
        })
        .unwrap();
        // SAFETY: these identity queries have no arguments or failure mode.
        assert_eq!(unsafe { libc::geteuid() }, 65534);
        assert_eq!(unsafe { libc::getegid() }, 65534);
    }
}
