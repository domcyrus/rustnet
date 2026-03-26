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
pub fn drop_cap_net_raw() -> Result<bool> {
    // Check if we have CAP_NET_RAW in the effective set
    let has_cap = caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW)
        .context("Failed to check CAP_NET_RAW in effective set")?;

    if !has_cap {
        log::debug!("CAP_NET_RAW not in effective set, nothing to drop");
        return Ok(false);
    }

    // Drop from effective set first
    caps::drop(None, CapSet::Effective, Capability::CAP_NET_RAW)
        .context("Failed to drop CAP_NET_RAW from effective set")?;

    log::debug!("Dropped CAP_NET_RAW from effective set");

    // Also drop from permitted set to prevent re-acquiring
    // This is optional but provides stronger security
    if caps::has_cap(None, CapSet::Permitted, Capability::CAP_NET_RAW).unwrap_or(false) {
        if let Err(e) = caps::drop(None, CapSet::Permitted, Capability::CAP_NET_RAW) {
            // Not fatal - we already dropped from effective
            log::warn!("Could not drop CAP_NET_RAW from permitted set: {}", e);
        } else {
            log::debug!("Dropped CAP_NET_RAW from permitted set");
        }
    }

    Ok(true)
}

/// Check if CAP_NET_RAW is currently held in the effective set
pub fn has_cap_net_raw() -> bool {
    caps::has_cap(None, CapSet::Effective, Capability::CAP_NET_RAW).unwrap_or(false)
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
pub fn drop_ebpf_caps() -> Result<u32> {
    let mut dropped = 0;

    for cap in [Capability::CAP_BPF, Capability::CAP_PERFMON] {
        let has_effective = caps::has_cap(None, CapSet::Effective, cap).unwrap_or(false);

        if !has_effective {
            continue;
        }

        caps::drop(None, CapSet::Effective, cap)
            .with_context(|| format!("Failed to drop {:?} from effective set", cap))?;

        // Also drop from permitted set to prevent re-acquiring
        if caps::has_cap(None, CapSet::Permitted, cap).unwrap_or(false)
            && let Err(e) = caps::drop(None, CapSet::Permitted, cap)
        {
            log::warn!("Could not drop {:?} from permitted set: {}", cap, e);
        }

        log::debug!("Dropped {:?}", cap);
        dropped += 1;
    }

    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_cap_net_raw_does_not_panic() {
        // This should not panic regardless of capabilities
        let _ = has_cap_net_raw();
    }

    #[test]
    fn test_drop_cap_net_raw_without_capability() {
        // If we don't have CAP_NET_RAW, drop should return Ok(false)
        // This test may behave differently depending on test environment
        let result = drop_cap_net_raw();
        // Should not error, just return whether it was dropped
        assert!(result.is_ok());
    }

    #[test]
    fn test_drop_ebpf_caps_does_not_panic() {
        // Should not panic regardless of capabilities held
        let result = drop_ebpf_caps();
        assert!(result.is_ok());
    }
}
