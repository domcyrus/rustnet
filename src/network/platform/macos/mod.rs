// network/platform/macos/mod.rs - macOS interface stats + sandbox.
// Process attribution (PKTAP/lsof) lives in the rustnet-host crate.

mod interface_stats;
// Not gated on `macos-sandbox`: the uid drop only needs libc and applies even
// in builds without Seatbelt support.
pub mod privdrop;
#[cfg(feature = "macos-sandbox")]
pub mod sandbox;

pub use interface_stats::MacOSStatsProvider;
