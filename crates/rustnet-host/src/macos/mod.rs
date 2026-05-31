// macOS process attribution: PKTAP packet metadata when active, else lsof.

mod process;

pub use process::MacOSProcessLookup;

use crate::{DegradationReason, ProcessLookup};
use anyhow::Result;
use std::sync::OnceLock;

/// Why the PKTAP fast path is unavailable, as reported by the orchestrator.
///
/// PKTAP availability is decided by the capture layer, not by process
/// attribution. Rather than depend on `rustnet-capture`, this crate lets the
/// application inject the reason via [`report_pktap_degradation`]; the lsof
/// lookup reads it back in `get_degradation_reason`.
static PKTAP_DEGRADATION: OnceLock<DegradationReason> = OnceLock::new();

/// Record why PKTAP could not be used so process-attribution degradation can be
/// surfaced to the user. Intended to be called once, by the application, after
/// it has determined PKTAP availability from the capture layer. No-op if already
/// set.
pub fn report_pktap_degradation(reason: DegradationReason) {
    let _ = PKTAP_DEGRADATION.set(reason);
}

/// The reported PKTAP degradation reason, or the conservative default
/// (missing root) when nothing has been reported.
pub(crate) fn pktap_degradation() -> DegradationReason {
    PKTAP_DEGRADATION
        .get()
        .cloned()
        .unwrap_or(DegradationReason::MissingRootPrivileges)
}

/// No-op process lookup for when PKTAP is providing process metadata
pub struct NoOpProcessLookup;

impl ProcessLookup for NoOpProcessLookup {
    fn get_process_for_connection(
        &self,
        _conn: &rustnet_core::network::types::Connection,
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

/// Create a macOS process lookup implementation.
/// Uses NoOp when PKTAP is active, otherwise falls back to lsof.
pub fn create_process_lookup(use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    if use_pktap {
        log::info!("Using no-op process lookup - PKTAP provides process metadata");
        Ok(Box::new(NoOpProcessLookup))
    } else {
        log::info!("Using macOS process lookup (lsof)");
        Ok(Box::new(MacOSProcessLookup::new()?))
    }
}
