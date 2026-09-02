//! Linux eBPF process tracking module
//!
//! This module provides enhanced process lookup using eBPF for TCP/UDP connections.
//! It maintains compatibility with the existing procfs approach as a fallback.

mod loader;
mod maps_libbpf;
mod task_file;
mod tracker_libbpf;

pub(super) use task_file::snapshot_task_file_owners;
pub(super) use tracker_libbpf::LibbpfSocketTracker as EbpfSocketTracker;

use crate::MatchQuality;

/// Size of the kernel's `task_struct.comm` buffer, NUL terminator included.
pub(super) const TASK_COMM_LEN: usize = 16;

/// Decode a `comm` buffer as the kernel fills it: the bytes before the
/// first NUL, or the whole buffer when no NUL is present.
pub(super) fn decode_comm(comm: &[u8]) -> String {
    let len = comm
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

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
