// network/platform/linux/mod.rs - Linux interface stats + sandbox.
// Process attribution (procfs/eBPF) lives in the rustnet-host crate.

mod interface_stats;

// Always compiled: without the `landlock` feature the module still provides
// the stub apply_sandbox() that sets PR_SET_NO_NEW_PRIVS.
pub mod sandbox;

pub use interface_stats::LinuxStatsProvider;
