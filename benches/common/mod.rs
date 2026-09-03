//! Helpers shared by the criterion benches. Cargo treats every top-level
//! `benches/*.rs` file as its own bench target, so shared code lives in this
//! subdirectory and each bench pulls it in with `mod common;`.

// Not every bench uses every helper.
#![allow(dead_code)]

use rustnet_monitor::network::parser::{ParsedPacket, TcpFlags, TcpHeaderInfo};
use rustnet_monitor::network::types::{Connection, Protocol, ProtocolState, TcpState};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Build a synthetic established TCP data packet (1400 payload bytes,
/// outgoing) from `local_port` to 93.184.216.34:443 carrying `seq`.
///
/// Varying the local port distinguishes flows so tracker workloads exercise
/// key hashing and DashMap sharding the same way live traffic does.
pub fn make_packet(local_port: u16, seq: u32) -> ParsedPacket {
    let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), local_port);
    let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    let mut packet = ParsedPacket::new(
        Protocol::Tcp,
        local_addr,
        remote_addr,
        ProtocolState::Tcp(TcpState::Established),
        true,
        1400,
        None,
        None,
    );
    packet.tcp_header = Some(TcpHeaderInfo {
        seq,
        ack: seq.wrapping_add(1),
        window: 65535,
        flags: TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
        },
        payload_len: 1400,
        window_scale: None,
    });
    packet
}

/// Create a Connection with a RateTracker filled to `n_samples` entries.
/// `prune_every` sprinkles in `prune()` calls at the given interval to keep
/// the tracker realistic; `None` skips pruning entirely.
pub fn make_connection_with_samples(n_samples: usize, prune_every: Option<usize>) -> Connection {
    let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
    let mut conn = Connection::new(
        Protocol::Tcp,
        local,
        remote,
        ProtocolState::Tcp(TcpState::Established),
    );

    for i in 0..n_samples {
        conn.bytes_sent += 100;
        conn.bytes_received += 200;
        conn.rate_tracker
            .update(conn.bytes_sent, conn.bytes_received);
        conn.packets_sent += 1;
        conn.packets_received += 1;
        if let Some(every) = prune_every
            && i % every == 0
        {
            conn.rate_tracker.prune();
        }
    }
    conn
}
