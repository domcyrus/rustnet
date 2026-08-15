//! Linux eBPF process tracking module
//!
//! This module provides enhanced process lookup using eBPF for TCP/UDP connections.
//! It maintains compatibility with the existing procfs approach as a fallback.

mod loader;
mod maps_libbpf;
mod tracker_libbpf;

pub(super) use tracker_libbpf::LibbpfSocketTracker as EbpfSocketTracker;

use crate::MatchQuality;

/// Process information from eBPF
#[derive(Debug, Clone)]
pub(super) struct ProcessInfo {
    /// Thread group id (the PID as user space understands it).
    pub(super) pid: u32,
    /// Kernel thread id that created the socket.
    pub(super) tid: u32,
    /// Effective user id at socket creation.
    pub(super) uid: u32,
    /// Effective group id at socket creation.
    pub(super) gid: u32,
    /// Short `comm` of the task, as recorded by the BPF program.
    pub(super) comm: String,
    /// `bpf_ktime_get_ns` reading: nanoseconds on a **monotonic** clock, not
    /// wall-clock time.
    pub(super) timestamp: u64,
}

/// A socket-map hit together with how the lookup key matched it.
///
/// The tracker retries a miss with a zeroed source address, so the caller can
/// no longer assume a hit means the exact tuple was recorded.
#[derive(Debug, Clone)]
pub(super) struct SocketMatch {
    pub(super) info: ProcessInfo,
    pub(super) quality: MatchQuality,
}

impl SocketMatch {
    fn new(info: ProcessInfo, quality: MatchQuality) -> Self {
        Self { info, quality }
    }
}
