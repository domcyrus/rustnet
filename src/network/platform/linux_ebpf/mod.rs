//! Linux eBPF process tracking module
//!
//! This module provides enhanced process lookup using eBPF for TCP/UDP connections.
//! It maintains compatibility with the existing procfs approach as a fallback.

#[cfg(feature = "ebpf")]
pub mod loader;
#[cfg(feature = "ebpf")]
pub mod maps_libbpf;
#[cfg(feature = "ebpf")]
pub mod tracker_libbpf;

#[cfg(feature = "ebpf")]
pub use tracker_libbpf::LibbpfSocketTracker as EbpfSocketTracker;

/// Process information from eBPF
#[cfg(feature = "ebpf")]
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    #[allow(dead_code)]
    pub uid: u32,
    pub comm: String,
    #[allow(dead_code)]
    pub timestamp: u64,
}
