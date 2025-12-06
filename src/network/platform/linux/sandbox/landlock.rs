//! Landlock sandboxing implementation
//!
//! Landlock is a Linux Security Module (LSM) that allows unprivileged
//! processes to restrict their own ambient rights (filesystem access,
//! network access).
//!
//! # Kernel Requirements
//!
//! - Linux 5.13+: Filesystem access control (ABI v1)
//! - Linux 5.19+: File referring/REFER (ABI v2)
//! - Linux 6.2+: Truncate control (ABI v3)
//! - Linux 6.4+: Network TCP bind/connect (ABI v4)
//!
//! # What We Restrict
//!
//! - Filesystem: Only allow read access to `/proc` (needed for process lookup)
//! - Filesystem: Only allow write access to specified paths (logs)
//! - Network: Block TCP bind and connect (RustNet is passive)

use anyhow::{Context, Result};
use landlock::{
    Access, AccessFs, AccessNet, BitFlags, LandlockStatus, PathBeneath, PathFd, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
};
use std::path::Path;

use super::{SandboxConfig, SandboxMode};

/// Result of Landlock application
pub struct LandlockResult {
    /// Whether filesystem restrictions were applied
    pub fs_applied: bool,
    /// Whether network restrictions were applied
    pub net_applied: bool,
    /// Human-readable message
    pub message: String,
}

/// Check if Landlock is available by attempting a test restriction
/// Note: This actually attempts to create a minimal ruleset to check
pub fn is_available() -> bool {
    // Try to create a minimal ruleset - this will fail if Landlock isn't available
    Ruleset::default()
        .handle_access(AccessFs::Execute)
        .and_then(|r| r.create())
        .is_ok()
}

/// Apply Landlock restrictions based on configuration
pub fn apply_landlock(config: &SandboxConfig) -> Result<LandlockResult> {
    // Check if disabled
    if config.mode == SandboxMode::Disabled {
        return Ok(LandlockResult {
            fs_applied: false,
            net_applied: false,
            message: "Sandbox disabled".to_string(),
        });
    }

    // Use ABI V4 which includes network support
    // The crate will automatically handle compatibility with older kernels
    let abi = ABI::V4;

    // Build filesystem access rights for reading
    // We need read access to /proc for process identification
    let read_access = AccessFs::from_read(abi);

    // Build filesystem access rights for writing
    let write_access = AccessFs::from_all(abi);

    // Start building the ruleset
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .context("Failed to handle filesystem access")?;

    // Add network handling if requested
    // This will be ignored on kernels that don't support it (< 6.4)
    let ruleset = if config.block_network {
        // Try to handle network access - ignore errors for older kernels
        match ruleset
            .handle_access(AccessNet::BindTcp)
            .and_then(|r| r.handle_access(AccessNet::ConnectTcp))
        {
            Ok(r) => r,
            Err(_) => {
                // Network access handling failed, recreate without network
                log::debug!("Network access handling not supported, continuing without");
                Ruleset::default()
                    .handle_access(AccessFs::from_all(abi))
                    .context("Failed to handle filesystem access")?
            }
        }
    } else {
        ruleset
    };

    // Create the ruleset
    let mut ruleset_created = ruleset.create().context("Failed to create Landlock ruleset")?;

    // Add rule for /proc (read-only)
    // This is required for process identification via procfs
    if let Err(e) = add_path_rule(&mut ruleset_created, "/proc", read_access) {
        log::warn!("Could not add /proc rule: {}", e);
    }

    // Add rules for write paths (logs, etc.)
    for path in &config.write_paths {
        if path.exists() {
            if let Err(e) = add_path_rule(&mut ruleset_created, path, write_access) {
                log::warn!("Could not add write rule for {:?}: {}", path, e);
            }
        } else {
            // For paths that don't exist yet, try to add rule for parent directory
            if let Some(parent) = path.parent()
                && parent.exists()
                && let Err(e) = add_path_rule(&mut ruleset_created, parent, write_access)
            {
                log::warn!("Could not add write rule for parent {:?}: {}", parent, e);
            }
        }
    }

    // If network blocking is enabled, we DON'T add any NetPort rules
    // This means all TCP bind/connect operations are blocked by default
    // (We're handling the access types but not allowing any ports)

    // Apply the restrictions
    let status = ruleset_created
        .restrict_self()
        .context("Failed to apply Landlock restrictions")?;

    // Determine what was actually applied based on the returned status
    let fs_applied = matches!(
        status.ruleset,
        RulesetStatus::FullyEnforced | RulesetStatus::PartiallyEnforced
    );

    // Check if network restrictions were actually applied
    let net_applied = config.block_network
        && fs_applied
        && matches!(
            status.landlock,
            LandlockStatus::Available { effective_abi, .. } if effective_abi >= ABI::V4
        );

    let message = match (&status.ruleset, &status.landlock) {
        (RulesetStatus::FullyEnforced, _) => "Landlock fully enforced".to_string(),
        (RulesetStatus::PartiallyEnforced, _) => "Landlock partially enforced".to_string(),
        (RulesetStatus::NotEnforced, LandlockStatus::NotEnabled) => {
            "Landlock disabled in kernel".to_string()
        }
        (RulesetStatus::NotEnforced, LandlockStatus::NotImplemented) => {
            "Landlock not implemented in kernel".to_string()
        }
        (RulesetStatus::NotEnforced, _) => "Landlock not enforced".to_string(),
    };

    log::info!("Landlock: {}", message);
    log::info!(
        "Landlock: filesystem={}, network={}, landlock_status={:?}",
        fs_applied,
        net_applied,
        status.landlock
    );

    Ok(LandlockResult {
        fs_applied,
        net_applied,
        message,
    })
}

/// Add a rule for a path with the specified access rights
fn add_path_rule(
    ruleset: &mut landlock::RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
) -> Result<()> {
    let path = path.as_ref();
    let fd = PathFd::new(path).with_context(|| format!("Failed to open {:?}", path))?;
    ruleset
        .add_rule(PathBeneath::new(fd, access))
        .with_context(|| format!("Failed to add rule for {:?}", path))?;
    log::debug!("Landlock: Added rule for {:?}", path);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_available_does_not_panic() {
        // Should not panic regardless of kernel support
        let _ = is_available();
    }

    #[test]
    fn test_disabled_mode() {
        let config = SandboxConfig {
            mode: SandboxMode::Disabled,
            block_network: true,
            write_paths: vec![],
        };
        let result = apply_landlock(&config).unwrap();
        assert!(!result.fs_applied);
        assert!(!result.net_applied);
    }
}
