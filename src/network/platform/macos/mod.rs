// network/platform/macos/mod.rs - macOS platform implementation

mod interface_stats;
mod process;

pub use interface_stats::MacOSStatsProvider;
pub use process::MacOSProcessLookup;

use super::ProcessLookup;
use anyhow::Result;

/// No-op process lookup for when PKTAP is providing process metadata
pub struct NoOpProcessLookup;

impl ProcessLookup for NoOpProcessLookup {
    fn get_process_for_connection(
        &self,
        _conn: &crate::network::types::Connection,
    ) -> Option<(u32, String)> {
        None // PKTAP provides this information directly
    }

    fn refresh(&self) -> Result<()> {
        Ok(()) // Nothing to refresh
    }

    fn get_detection_method(&self) -> &str {
        "pktap"
    }
}

/// Create a macOS process lookup implementation
/// Uses NoOp when PKTAP is active, otherwise falls back to lsof
pub fn create_process_lookup(use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    if use_pktap {
        log::info!("Using no-op process lookup - PKTAP provides process metadata");
        Ok(Box::new(NoOpProcessLookup))
    } else {
        log::info!("Using macOS process lookup (lsof)");
        Ok(Box::new(MacOSProcessLookup::new()?))
    }
}

