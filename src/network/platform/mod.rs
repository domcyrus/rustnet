// network/platform/mod.rs - Platform-specific interface stats and sandboxing.
//
// Per-connection process attribution moved to the `rustnet-host` crate; its
// public API (`ProcessLookup`, `DegradationReason`, `ConnectionKey`, and the
// `create_process_lookup` factory) is re-exported here so the rest of the
// binary keeps using `crate::network::platform::*` unchanged. What remains in
// the binary is the per-platform interface-statistics providers and the
// privilege-dropping sandbox (Landlock / Seatbelt / restricted token).

// Process attribution lives in the rustnet-host crate. Re-export the bits the
// binary uses; the full API (ProcessLookup, ConnectionKey, ...) is available
// directly from `rustnet_host` for other consumers.
pub use rustnet_host::{DegradationReason, create_process_lookup};
// macOS: the app injects the PKTAP-unavailable reason into rustnet-host so the
// host crate need not depend on rustnet-capture.
#[cfg(target_os = "macos")]
pub use rustnet_host::report_pktap_degradation;

// Platform-specific modules (interface stats + sandbox)
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// Re-export interface-stats providers and the sandbox entry points.
#[cfg(target_os = "freebsd")]
pub use freebsd::FreeBSDStatsProvider;
#[cfg(target_os = "linux")]
pub use linux::LinuxStatsProvider;
// Not gated on the `landlock` feature: the sandbox module always compiles on
// Linux (a non-landlock build still sets PR_SET_NO_NEW_PRIVS via the stub).
#[cfg(target_os = "linux")]
pub use linux::sandbox;
// Linux keeps privdrop inside the sandbox module; re-export it at the platform
// level so callers can use `platform::privdrop` uniformly across platforms.
#[cfg(target_os = "linux")]
pub use linux::sandbox::privdrop;
#[cfg(target_os = "macos")]
pub use macos::MacOSStatsProvider;
// Not gated on the `macos-sandbox` feature: the uid drop works without Seatbelt.
#[cfg(target_os = "macos")]
pub use macos::privdrop;
#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
pub use macos::sandbox;
#[cfg(target_os = "windows")]
pub use windows::WindowsStatsProvider;
#[cfg(target_os = "windows")]
pub use windows::sandbox;
