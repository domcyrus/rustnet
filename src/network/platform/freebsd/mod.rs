// network/platform/freebsd/mod.rs - FreeBSD interface stats.
// Process attribution (sockstat) lives in the rustnet-host crate.

mod interface_stats;

pub use interface_stats::FreeBSDStatsProvider;
