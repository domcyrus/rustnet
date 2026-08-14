// network/platform/linux/mod.rs - Linux interface stats.
// Process attribution (procfs/eBPF) lives in the rustnet-host crate; the
// sandbox (Landlock/capabilities/uid drop) lives in the rustnet-sandbox crate.

mod interface_stats;

pub use interface_stats::LinuxStatsProvider;
