// network/platform/linux/mod.rs - Linux sandbox.
// Process attribution (procfs/eBPF) lives in the rustnet-host crate;
// interface stats live in rustnet-core.

// Always compiled: without the `landlock` feature the module still provides
// the stub apply_sandbox() that sets PR_SET_NO_NEW_PRIVS.
pub mod sandbox;
