// network/platform/windows/mod.rs - Windows platform implementation

mod interface_stats;
mod process;

pub use interface_stats::WindowsStatsProvider;
pub use process::WindowsProcessLookup;

use super::ProcessLookup;
use anyhow::Result;

/// Create a Windows process lookup implementation
/// The `_use_pktap` parameter is ignored on Windows (only used on macOS)
pub fn create_process_lookup(_use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    log::info!("Using Windows process lookup (IP Helper API)");
    Ok(Box::new(WindowsProcessLookup::new()?))
}

