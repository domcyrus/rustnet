// network/platform/macos/mod.rs - macOS interface stats.
// Process attribution (PKTAP/lsof) lives in the rustnet-host crate; the
// sandbox (Seatbelt/uid drop) lives in the rustnet-sandbox crate.

mod interface_stats;

pub use interface_stats::MacOSStatsProvider;
