//! Additive socket telemetry fields for schema version 1.

use super::schema::{duration_ms, timestamp};
use crate::network::types::{KernelSocketStats, SocketMemoryStats, TcpSocketStats};
use serde::Serialize;

#[derive(Serialize)]
pub(super) struct SocketInventorySnapshot {
    telemetry_status: &'static str,
    sockets: Vec<HostSocketSnapshot>,
}

#[derive(Serialize)]
struct HostSocketSnapshot {
    protocol: &'static str,
    local: String,
    remote: Option<String>,
    state: String,
    pid: Option<u32>,
    kernel_stats: Option<KernelSocketSnapshot>,
}

impl From<rustnet_host::SocketSnapshot> for SocketInventorySnapshot {
    fn from(snapshot: rustnet_host::SocketSnapshot) -> Self {
        let mut sockets: Vec<_> = snapshot
            .sockets
            .iter()
            .map(|s| HostSocketSnapshot {
                protocol: s.protocol.as_str(),
                local: s.local_addr.to_string(),
                remote: s.remote_addr.map(|a| a.to_string()),
                state: match s.state {
                    rustnet_host::HostSocketState::Tcp(state) => state.to_string(),
                    rustnet_host::HostSocketState::UdpBound => "BOUND".into(),
                },
                pid: s.owner.as_ref().map(|o| o.pid),
                kernel_stats: s.kernel_stats.as_deref().map(KernelSocketSnapshot::from),
            })
            .collect();
        sockets.sort_by(|a, b| {
            (&a.protocol, &a.local, &a.remote).cmp(&(&b.protocol, &b.local, &b.remote))
        });
        Self {
            telemetry_status: snapshot.telemetry_status.as_str(),
            sockets,
        }
    }
}

#[derive(Serialize)]
pub(super) struct KernelSocketSnapshot {
    source: &'static str,
    sampled_at: String,
    age_ms: u128,
    stale: bool,
    state: &'static str,
    socket_cookie: Option<u64>,
    network_namespace: Option<u64>,
    queues: QueueSnapshot,
    memory: Option<MemorySnapshot>,
    tcp: Option<TcpSnapshot>,
}

#[derive(Serialize)]
struct QueueSnapshot {
    kind: &'static str,
    receive: u32,
    send: u32,
}

#[derive(Serialize)]
struct MemorySnapshot {
    receive_allocated_bytes: Option<u32>,
    receive_limit_bytes: Option<u32>,
    send_allocated_bytes: Option<u32>,
    send_limit_bytes: Option<u32>,
    drops: Option<u32>,
}

impl From<&SocketMemoryStats> for MemorySnapshot {
    fn from(s: &SocketMemoryStats) -> Self {
        Self {
            receive_allocated_bytes: s.receive_allocated,
            receive_limit_bytes: s.receive_limit,
            send_allocated_bytes: s.send_allocated,
            send_limit_bytes: s.send_limit,
            drops: s.drops,
        }
    }
}

#[derive(Serialize)]
struct TcpSnapshot {
    rtt_ms: Option<f64>,
    rtt_variance_ms: Option<f64>,
    min_rtt_ms: Option<f64>,
    retransmission_timeout_ms: Option<f64>,
    congestion_window_segments: Option<u32>,
    slow_start_threshold_segments: Option<u32>,
    send_mss_bytes: Option<u32>,
    total_retransmissions: Option<u32>,
    bytes_sent: Option<u64>,
    bytes_acked: Option<u64>,
    bytes_received: Option<u64>,
    bytes_retransmitted: Option<u64>,
    not_sent_bytes: Option<u32>,
    congestion_control: Option<String>,
}

impl From<&TcpSocketStats> for TcpSnapshot {
    fn from(s: &TcpSocketStats) -> Self {
        Self {
            rtt_ms: duration_ms(s.rtt),
            rtt_variance_ms: duration_ms(s.rtt_variance),
            min_rtt_ms: duration_ms(s.min_rtt),
            retransmission_timeout_ms: duration_ms(s.retransmission_timeout),
            congestion_window_segments: s.congestion_window_segments,
            slow_start_threshold_segments: s.slow_start_threshold_segments,
            send_mss_bytes: s.send_mss,
            total_retransmissions: s.total_retransmissions,
            bytes_sent: s.bytes_sent,
            bytes_acked: s.bytes_acked,
            bytes_received: s.bytes_received,
            bytes_retransmitted: s.bytes_retransmitted,
            not_sent_bytes: s.not_sent_bytes,
            congestion_control: s.congestion_control.clone(),
        }
    }
}

impl From<&KernelSocketStats> for KernelSocketSnapshot {
    fn from(s: &KernelSocketStats) -> Self {
        Self {
            source: s.source.as_str(),
            sampled_at: timestamp(s.sampled_at),
            age_ms: s.age().as_millis(),
            stale: s.is_stale(),
            state: s.state,
            socket_cookie: s.socket_cookie,
            network_namespace: s.network_namespace,
            queues: QueueSnapshot {
                kind: s.queues.kind.as_str(),
                receive: s.queues.receive,
                send: s.queues.send,
            },
            memory: s.memory.as_ref().map(MemorySnapshot::from),
            tcp: s.tcp.as_ref().map(TcpSnapshot::from),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_units_unknown_fields_and_staleness_without_capture_totals() {
        let stats = crate::ui::test_support::kernel_stats();
        let value = serde_json::to_value(KernelSocketSnapshot::from(&stats)).unwrap();
        assert_eq!(value["source"], "linux_sock_diag");
        assert_eq!(value["stale"], true);
        assert_eq!(value["tcp"]["rtt_ms"], 12.5);
        assert_eq!(value["tcp"]["congestion_window_segments"], 10);
        assert_eq!(value["tcp"]["bytes_sent"], 999_999);
        assert!(value["tcp"]["bytes_acked"].is_null());
        assert_eq!(value["queues"]["kind"], "bytes");
        assert!(value.get("traffic").is_none());
    }
}
