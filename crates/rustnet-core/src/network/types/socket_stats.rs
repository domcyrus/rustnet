//! Optional operating-system socket measurements, separate from packet analytics.

use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketStatsSource {
    LinuxSockDiag,
}

static_names! { SocketStatsSource { LinuxSockDiag => "linux_sock_diag" } }

/// Units and interpretation of the operating system's queue counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketQueueKind {
    /// TCP: unread receive bytes and unacknowledged send bytes.
    Bytes,
    /// UDP: memory accounting, including kernel overhead, not payload length.
    MemoryBytes,
    /// Listener: receive is pending accepts, send is the backlog limit.
    Backlog,
}

static_names! { SocketQueueKind {
    Bytes => "bytes", MemoryBytes => "memory_bytes", Backlog => "backlog"
} }

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketQueues {
    pub kind: SocketQueueKind,
    pub receive: u32,
    pub send: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SocketMemoryStats {
    pub receive_allocated: Option<u32>,
    pub receive_limit: Option<u32>,
    pub send_allocated: Option<u32>,
    pub send_limit: Option<u32>,
    pub drops: Option<u32>,
}

/// Fields absent from an older kernel response remain unknown, not zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TcpSocketStats {
    pub rtt: Option<Duration>,
    pub rtt_variance: Option<Duration>,
    pub min_rtt: Option<Duration>,
    pub retransmission_timeout: Option<Duration>,
    pub congestion_window_segments: Option<u32>,
    pub slow_start_threshold_segments: Option<u32>,
    pub send_mss: Option<u32>,
    pub total_retransmissions: Option<u32>,
    pub bytes_sent: Option<u64>,
    pub bytes_acked: Option<u64>,
    pub bytes_received: Option<u64>,
    pub bytes_retransmitted: Option<u64>,
    pub not_sent_bytes: Option<u32>,
    pub congestion_control: Option<String>,
}

/// One sample of a local socket. Counters have socket lifetime semantics;
/// they must never be added to packet-capture counters or copied to UDP peers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KernelSocketStats {
    pub source: SocketStatsSource,
    pub sampled_at: SystemTime,
    pub socket_cookie: Option<u64>,
    pub network_namespace: Option<u64>,
    pub state: &'static str,
    pub queues: SocketQueues,
    pub memory: Option<SocketMemoryStats>,
    pub tcp: Option<TcpSocketStats>,
}

impl KernelSocketStats {
    pub fn age(&self) -> Duration {
        self.sampled_at.elapsed().unwrap_or_default()
    }

    /// Two missed five-second refreshes make a retained sample stale.
    pub fn is_stale(&self) -> bool {
        self.age() >= Duration::from_secs(10)
    }
}
