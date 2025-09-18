//! Linux eBPF process tracking module
//!
//! This module provides enhanced process lookup using eBPF for TCP/UDP connections.
//! It maintains compatibility with the existing procfs approach as a fallback.

pub mod loader;
pub mod maps_libbpf;
pub mod tracker_libbpf;

pub use tracker_libbpf::LibbpfSocketTracker as EbpfSocketTracker;

/// Process information from eBPF
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub timestamp: u64,
}
