// Windows process attribution via the IP Helper API.

mod process;

pub use process::WindowsProcessLookup;

use crate::ProcessLookup;
use anyhow::Result;

/// Create a Windows process lookup implementation.
/// The `_use_pktap` parameter is ignored on Windows (macOS only).
pub fn create_process_lookup(_use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    log::info!("Using Windows process lookup (IP Helper API)");
    Ok(Box::new(WindowsProcessLookup::new()?))
}
