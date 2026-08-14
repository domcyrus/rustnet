// network/platform/mod.rs - re-export shim for host-tied functionality.
//
// Per-connection process attribution lives in the `rustnet-host` crate; its
// public API (`ProcessLookup`, `DegradationReason`, `ConnectionKey`, and the
// `create_process_lookup` factory) is re-exported here so the rest of the
// binary keeps using `crate::network::platform::*` unchanged. Interface
// statistics live in rustnet-core (`interface_stats::create_stats_provider`),
// and sandboxing plus the root uid drop live in the `rustnet-sandbox` crate
// (used directly as `rustnet_sandbox`).

// Process attribution lives in the rustnet-host crate. Re-export the bits the
// binary uses; the full API (ProcessLookup, ConnectionKey, ...) is available
// directly from `rustnet_host` for other consumers.
pub use rustnet_host::{DegradationReason, create_process_lookup};
// macOS: the app injects the PKTAP-unavailable reason into rustnet-host so the
// host crate need not depend on rustnet-capture.
#[cfg(target_os = "macos")]
pub use rustnet_host::report_pktap_degradation;
