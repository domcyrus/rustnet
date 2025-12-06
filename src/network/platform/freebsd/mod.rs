// network/platform/freebsd/mod.rs - FreeBSD platform implementation

mod interface_stats;
mod process;

pub use interface_stats::FreeBSDStatsProvider;
pub use process::FreeBSDProcessLookup;

use super::ProcessLookup;
use anyhow::Result;

/// Create a FreeBSD process lookup implementation
/// The `_use_pktap` parameter is ignored on FreeBSD (only used on macOS)
pub fn create_process_lookup(_use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    log::info!("Using FreeBSD process lookup (sockstat)");
    Ok(Box::new(FreeBSDProcessLookup::new()?))
}
