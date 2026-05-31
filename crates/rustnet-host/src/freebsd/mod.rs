// FreeBSD process attribution via the `sockstat` command.

mod process;

pub use process::FreeBSDProcessLookup;

use crate::ProcessLookup;
use anyhow::Result;

/// Create a FreeBSD process lookup implementation.
/// The `_use_pktap` parameter is ignored on FreeBSD (macOS only).
pub fn create_process_lookup(_use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    log::info!("Using FreeBSD process lookup (sockstat)");
    Ok(Box::new(FreeBSDProcessLookup::new()?))
}
