// network/platform/macos/mod.rs - macOS interface stats + sandbox.
// Process attribution (PKTAP/lsof) lives in the rustnet-host crate.

mod interface_stats;
#[cfg(feature = "macos-sandbox")]
pub mod sandbox;

pub use interface_stats::MacOSStatsProvider;
