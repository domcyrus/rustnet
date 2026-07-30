//! Linux eBPF process tracking module
//!
//! This module provides enhanced process lookup using eBPF for TCP/UDP connections.
//! It maintains compatibility with the existing procfs approach as a fallback.

pub mod loader;
pub mod maps_libbpf;
pub mod tracker_libbpf;

pub use tracker_libbpf::LibbpfSocketTracker as EbpfSocketTracker;

use crate::MatchQuality;

/// Process information from eBPF
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Thread group id (the PID as user space understands it).
    pub pid: u32,
    /// Kernel thread id that created the socket.
    pub tid: u32,
    /// Effective user id at socket creation.
    pub uid: u32,
    /// Effective group id at socket creation.
    pub gid: u32,
    /// Short `comm` of the task, as recorded by the BPF program.
    pub comm: String,
    /// `bpf_ktime_get_ns` reading: nanoseconds on a **monotonic** clock, not
    /// wall-clock time.
    pub timestamp: u64,
}

/// A socket-map hit together with how the lookup key matched it.
///
/// The tracker retries a miss with a zeroed source address, so the caller can
/// no longer assume a hit means the exact tuple was recorded.
#[derive(Debug, Clone)]
pub struct SocketMatch {
    pub info: ProcessInfo,
    pub quality: MatchQuality,
}

impl SocketMatch {
    fn new(info: ProcessInfo, quality: MatchQuality) -> Self {
        Self { info, quality }
    }
}
