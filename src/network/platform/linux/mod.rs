// network/platform/linux/mod.rs - Linux platform implementation

mod interface_stats;
mod process;

#[cfg(feature = "ebpf")]
pub mod ebpf;
#[cfg(feature = "ebpf")]
mod enhanced;

pub use interface_stats::LinuxStatsProvider;
pub use process::LinuxProcessLookup;

use super::ProcessLookup;
use anyhow::Result;

/// Create a Linux process lookup implementation
/// Tries enhanced eBPF lookup first (if feature enabled), falls back to procfs
/// The `_use_pktap` parameter is ignored on Linux (only used on macOS)
pub fn create_process_lookup(_use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    #[cfg(feature = "ebpf")]
    {
        // Try enhanced lookup first (with eBPF if available), fall back to basic
        match enhanced::EnhancedLinuxProcessLookup::new() {
            Ok(enhanced) => {
                log::info!("Using enhanced Linux process lookup (eBPF + procfs)");
                return Ok(Box::new(enhanced));
            }
            Err(e) => {
                log::warn!(
                    "Enhanced lookup failed, falling back to basic procfs: {}",
                    e
                );
            }
        }
    }
    // Use basic procfs lookup (either as fallback or when eBPF is not enabled)
    log::info!("Using Linux process lookup (procfs)");
    Ok(Box::new(LinuxProcessLookup::new()?))
}

