// network/platform/windows/mod.rs - Windows interface stats.
// Process attribution (IP Helper API) lives in the rustnet-host crate; the
// sandbox (restricted token/job object) lives in the rustnet-sandbox crate.

mod interface_stats;

pub use interface_stats::WindowsStatsProvider;
