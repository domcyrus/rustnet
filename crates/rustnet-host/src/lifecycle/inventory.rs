//! Socket-inventory retirement for platforms without Linux pidfds.
//!
//! Only a socket seen during this flow's lifetime can enroll it. Two distinct,
//! complete scans after its last packet must then confirm absence. Ownership
//! does not constrain presence, so inherited sockets and PID reuse cannot make
//! a live socket disappear from the reconciliation result.

use super::SocketObservation;
use crate::{HostSocket, HostSocketState, HostTcpState, SocketSnapshot};
use rustnet_core::network::types::{Connection, ConnectionKey, ProcessExitStatus, Protocol};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::SystemTime;

#[derive(Clone, Copy, Debug)]
pub struct TrackedConnection {
    pub key: ConnectionKey,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    pub packet_counts: (u64, u64),
}

impl TrackedConnection {
    pub fn from_connection(conn: &Connection) -> Option<Self> {
        matches!(conn.protocol, Protocol::Tcp | Protocol::Udp).then_some(Self {
            key: ConnectionKey::from_connection(conn),
            created_at: conn.created_at,
            last_activity: conn.last_activity,
            packet_counts: (conn.packets_sent, conn.packets_received),
        })
    }

    fn identity(&self) -> (ConnectionKey, SystemTime) {
        (self.key, self.created_at)
    }

    fn activity(&self) -> (SystemTime, (u64, u64)) {
        (self.last_activity, self.packet_counts)
    }
}

#[derive(Default)]
pub struct SocketLifecycleTracker {
    observations: HashMap<(ConnectionKey, SystemTime), SocketObservation>,
    last_scan: Option<SystemTime>,
}

impl SocketLifecycleTracker {
    /// Failed refreshes must break pending absence confirmations, even if the
    /// backend keeps its previous inventory for display.
    pub(super) fn invalidate(&mut self) {
        for observation in self.observations.values_mut() {
            observation.missing = None;
            observation.status = Some(ProcessExitStatus::SocketScanIncomplete);
        }
    }

    pub(crate) fn observation_status(&self, conn: &TrackedConnection) -> ProcessExitStatus {
        self.observations
            .get(&conn.identity())
            .and_then(|entry| entry.status)
            .unwrap_or(ProcessExitStatus::WaitingForSocket)
    }

    pub(crate) fn scan_closed(
        &mut self,
        connections: &[TrackedConnection],
        snapshot: &SocketSnapshot,
    ) -> Vec<TrackedConnection> {
        let active: HashSet<_> = connections
            .iter()
            .map(TrackedConnection::identity)
            .collect();
        self.observations.retain(|key, _| active.contains(key));
        for conn in connections {
            let entry = self.observations.entry(conn.identity()).or_default();
            if entry
                .missing
                .is_some_and(|activity| activity != conn.activity())
            {
                entry.missing = None;
                entry.status = Some(ProcessExitStatus::WaitingForSocket);
            }
        }
        let Some(started) = snapshot.closure_scan_started else {
            self.invalidate();
            return Vec::new();
        };
        // Repeated UI ticks, retained failed snapshots, and clock rollback
        // cannot turn one observation into two independent absence checks.
        if self.last_scan.is_some_and(|last| started <= last) {
            return Vec::new();
        }
        self.last_scan = Some(started);
        let mut sockets: HashMap<(Protocol, u16), Vec<&HostSocket>> = HashMap::new();
        for socket in snapshot.sockets.iter() {
            sockets
                .entry((socket.protocol, socket.local_addr.port()))
                .or_default()
                .push(socket);
        }
        let mut closed = Vec::new();
        for conn in connections {
            let entry = self.observations.get_mut(&conn.identity()).unwrap();
            if started <= conn.created_at {
                entry.missing = None;
                continue;
            }
            let present = sockets
                .get(&(conn.key.protocol, conn.key.local_addr.port()))
                .is_some_and(|candidates| {
                    candidates
                        .iter()
                        .any(|socket| matches_socket(socket, &conn.key))
                });
            if present {
                entry.enrolled = true;
                entry.missing = None;
                entry.status = Some(ProcessExitStatus::WatchingSocket);
            } else if started <= conn.last_activity {
                // Traffic during a scan invalidates negative evidence. It
                // does not invalidate a positive sighting above, otherwise
                // busy sockets could never enroll before their owner exits.
                entry.missing = None;
                entry.status = Some(ProcessExitStatus::WaitingForSocket);
            } else if entry.enrolled {
                entry.status = Some(ProcessExitStatus::ConfirmingSocketClosure);
                if entry.missing.replace(conn.activity()) == Some(conn.activity()) {
                    closed.push(*conn);
                }
            } else {
                entry.status = Some(ProcessExitStatus::WaitingForSocket);
            }
        }
        closed
    }
}

fn matches_socket(socket: &HostSocket, key: &ConnectionKey) -> bool {
    if socket.protocol != key.protocol || !local_matches(socket.local_addr, key.local_addr) {
        return false;
    }
    if matches!(
        socket.state,
        HostSocketState::Tcp(
            HostTcpState::Listen
                | HostTcpState::Closed
                | HostTcpState::TimeWait
                | HostTcpState::DeleteTcb
        )
    ) {
        return false;
    }
    match socket.remote_addr {
        Some(remote) => {
            remote.port() == key.remote_addr.port()
                && remote.ip().to_canonical() == key.remote_addr.ip().to_canonical()
        }
        None => key.protocol == Protocol::Udp,
    }
}

fn local_matches(socket: SocketAddr, flow: SocketAddr) -> bool {
    let socket_ip = socket.ip().to_canonical();
    let flow_ip = flow.ip().to_canonical();
    socket.port() == flow.port()
        && (socket_ip == flow_ip
            // An IPv6 wildcard may accept IPv4 too. Keep the flow rather than
            // infer IPV6_V6ONLY from inventories that do not expose it.
            || (socket_ip.is_unspecified() && (socket_ip.is_ipv6() || flow_ip.is_ipv4())))
}

#[cfg(test)]
mod tests;
