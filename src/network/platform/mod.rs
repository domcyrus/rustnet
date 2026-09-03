//! Re-export shim for the `rustnet-host` process-attribution API, so the
//! binary uses `crate::network::platform::*`. Interface statistics live in
//! rustnet-core (`interface_stats::create_stats_provider`); sandboxing and the
//! root uid drop live in `rustnet_sandbox`.

pub use rustnet_host::{DegradationReason, create_process_lookup};
// macOS: the app injects the PKTAP-unavailable reason into rustnet-host so the
// host crate need not depend on rustnet-capture.
#[cfg(target_os = "macos")]
pub use rustnet_host::report_pktap_degradation;
