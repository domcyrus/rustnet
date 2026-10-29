//! Conservative Linux process-exit retirement. Pidfds report whole-process
//! exit, and a fresh socket table protects sockets inherited by another owner.

use super::process::process_start_ticks;
use crate::{lifecycle::SocketObservation, procfs::parse_proc_net_line};
use rustnet_core::network::types::{
    Connection, ConnectionKey, ConnectionObservation, ProcessExitStatus, Protocol,
};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant, SystemTime};

/// A small observation copied while holding a connection-table entry guard.
/// No guard is held while reading procfs or polling process descriptors.
#[derive(Clone, Copy, Debug)]
pub struct TrackedConnection {
    pub observation: ConnectionObservation,
    pid: u32,
    start_id: u64,
    socket_netns_id: Option<u64>,
}

impl TrackedConnection {
    /// Only TCP/UDP flows with a verified process generation are eligible.
    pub fn from_connection(conn: &Connection) -> Option<Self> {
        Some(Self {
            observation: ConnectionObservation::from_connection(conn)?,
            pid: conn.pid?,
            start_id: conn.process_start_id?,
            socket_netns_id: conn.socket_netns_id,
        })
    }

    fn identity(&self) -> (ConnectionKey, SystemTime) {
        self.observation.identity()
    }

    fn process(&self) -> (u32, u64) {
        (self.pid, self.start_id)
    }
}

struct Watch {
    fd: Option<OwnedFd>,
    exited_at: Option<Instant>,
}

impl Watch {
    fn exited(&self) -> bool {
        self.exited_at.is_some()
    }

    fn open(pid: u32, start_id: u64) -> Result<Self, ProcessExitStatus> {
        let current = process_start_ticks(pid).ok_or(ProcessExitStatus::IdentityUnreadable)?;
        if current != start_id {
            log::debug!(
                "Process-exit identity mismatch: pid={pid} attributed={start_id} procfs={current}"
            );
            return Err(ProcessExitStatus::IdentityChanged);
        }
        // SAFETY: pidfd_open has scalar arguments. Flags zero select the whole
        // process, not an individual thread. The returned fd is owned here.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(ProcessExitStatus::WatchFailed(
                io::Error::last_os_error().raw_os_error().unwrap_or(0),
            ));
        }
        let fd = fd as i32;
        // SAFETY: the successful syscall returned a fresh descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // Check both sides of registration, rejecting exit/reuse races.
        if process_start_ticks(pid) != Some(start_id) {
            return Err(ProcessExitStatus::IdentityChanged);
        }
        Ok(Self {
            fd: Some(fd),
            exited_at: None,
        })
    }
}

pub(super) fn local_netns_id() -> Option<u64> {
    fs::metadata("/proc/self/ns/net")
        .ok()
        .map(|meta| meta.ino())
}

/// Best-effort exit watches for processes already attributed to live flows.
/// Missing permissions, unsupported pidfds, namespace mismatches and failed
/// socket scans leave ordinary timeout cleanup in charge.
#[derive(Default)]
pub struct ProcessExitTracker {
    watches: HashMap<(u32, u64), Result<Watch, ProcessExitStatus>>,
    observations: HashMap<(ConnectionKey, SystemTime), SocketObservation>,
    last_scan: Option<Instant>,
}

impl ProcessExitTracker {
    /// Return observations safe to retire, without changing protocol states.
    /// The caller must recheck generation and activity before removing rows.
    pub(crate) fn scan_closed(
        &mut self,
        connections: &[TrackedConnection],
    ) -> Vec<ConnectionObservation> {
        let processes: HashSet<_> = connections.iter().map(TrackedConnection::process).collect();
        let identities: HashSet<_> = connections
            .iter()
            .map(TrackedConnection::identity)
            .collect();
        // Keep confirmed exits briefly for delayed UDP packets that recreate
        // a tuple after retirement. No pidfd is retained after it signals.
        self.watches.retain(|process, watch| {
            processes.contains(process)
                || watch
                    .as_ref()
                    .ok()
                    .and_then(|watch| watch.exited_at)
                    .is_some_and(|exit| exit.elapsed() < Duration::from_secs(300))
        });
        self.observations
            .retain(|identity, _| identities.contains(identity));
        if connections.is_empty() {
            return Vec::new();
        }

        // Bound descriptor use independently of the connection-table limit.
        // Failed registrations are cached for this generation, so restricted
        // processes do not cause repeated syscalls every enrichment tick.
        const MAX_WATCHES: usize = 4096;
        for process in processes {
            if self.watches.len() >= MAX_WATCHES {
                break;
            }
            self.watches.entry(process).or_insert_with(|| {
                let result = Watch::open(process.0, process.1);
                match &result {
                    Ok(_) => log::debug!(
                        "Process-exit watch registered: pid={} start={}",
                        process.0,
                        process.1
                    ),
                    Err(reason) => log::debug!(
                        "Process-exit watch unavailable: pid={} start={}: {reason}",
                        process.0,
                        process.1
                    ),
                }
                result
            });
        }
        self.poll_exits();
        let local_netns = local_netns_id();
        let mut needs_scan = false;
        for conn in connections {
            let Some(watch) = self
                .watches
                .get(&conn.process())
                .and_then(|watch| watch.as_ref().ok())
            else {
                continue;
            };
            let observation = self.observations.entry(conn.identity()).or_default();
            // Attribution already observed this socket in this namespace.
            // Requiring another live procfs observation misses short-lived
            // sockets that close between enrichment scans. Still enroll only
            // for a verified process generation, including cached exits.
            if conn.socket_netns_id.is_some()
                && conn.socket_netns_id == local_netns
                && !observation.enrolled
            {
                observation.enrolled = true;
                observation.status = Some(ProcessExitStatus::Watching);
                log::debug!(
                    "Process-exit enrolled captured socket: pid={} tuple={:?} namespace={:?}",
                    conn.pid,
                    conn.observation.key,
                    conn.socket_netns_id
                );
            }
            needs_scan |= watch.exited() || !observation.enrolled;
        }
        if !needs_scan
            || self
                .last_scan
                .is_some_and(|last| last.elapsed() < Duration::from_secs(1))
        {
            return Vec::new();
        }
        let tables = SocketTables::read(connections);
        self.last_scan = Some(Instant::now());
        self.reconcile(connections, &tables)
    }

    /// Last observed cleanup stage, for the connection Details view.
    pub(crate) fn observation_status(&self, conn: &TrackedConnection) -> ProcessExitStatus {
        match self.watches.get(&conn.process()) {
            Some(Err(reason)) => *reason,
            Some(Ok(_)) => self
                .observations
                .get(&conn.identity())
                .and_then(|observation| observation.status)
                .unwrap_or(ProcessExitStatus::WaitingForSocket),
            None => ProcessExitStatus::WatchLimit,
        }
    }

    fn reconcile(
        &mut self,
        connections: &[TrackedConnection],
        tables: &SocketTables,
    ) -> Vec<ConnectionObservation> {
        let mut closed = Vec::new();
        let local_netns = local_netns_id();
        for conn in connections {
            let Some(watch) = self
                .watches
                .get(&conn.process())
                .and_then(|watch| watch.as_ref().ok())
            else {
                continue;
            };
            let observation = self.observations.entry(conn.identity()).or_default();
            let Some(present) = tables.contains(conn.observation.key) else {
                observation.missing = None;
                observation.status = Some(ProcessExitStatus::SocketTableUnreadable);
                continue;
            };
            let local_socket = !watch.exited() && socket_in_local_namespace(conn, local_netns);
            let status = if watch.exited() {
                if !observation.enrolled {
                    ProcessExitStatus::MissedSocket
                } else if present {
                    ProcessExitStatus::SocketPresentAfterExit
                } else {
                    ProcessExitStatus::ConfirmingClosure
                }
            } else if conn.socket_netns_id.is_some()
                && local_netns.is_some()
                && conn.socket_netns_id != local_netns
            {
                ProcessExitStatus::OtherNamespace
            } else if !local_socket {
                ProcessExitStatus::NamespaceUnknown
            } else if present || observation.enrolled {
                ProcessExitStatus::Watching
            } else {
                ProcessExitStatus::WaitingForSocket
            };
            if observation.status.replace(status) != Some(status) {
                log::debug!(
                    "Process-exit cleanup: pid={} tuple={:?} namespace={:?} local_namespace={:?}: {status}",
                    conn.pid,
                    conn.observation.key,
                    conn.socket_netns_id,
                    local_netns
                );
            }
            if watch.exited() {
                if observation.enrolled && !present {
                    // Procfs scans are not atomic. Require two consecutive
                    // successful scans with no intervening packet activity.
                    let activity = conn.observation.activity();
                    if observation.missing.replace(activity) == Some(activity) {
                        closed.push(conn.observation);
                    }
                }
            } else if present && local_socket {
                observation.enrolled = true;
            }
            if present {
                observation.missing = None;
            }
        }
        closed
    }

    fn poll_exits(&mut self) {
        let mut pending: Vec<_> = self
            .watches
            .values_mut()
            .flatten()
            .filter(|watch| !watch.exited())
            .collect();
        let mut fds: Vec<_> = pending
            .iter()
            .map(|watch| libc::pollfd {
                fd: watch
                    .fd
                    .as_ref()
                    .expect("pending watch has a pidfd")
                    .as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: fds is a valid writable array; zero timeout never blocks.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 0) } < 0 {
            return;
        }
        for (watch, fd) in pending.iter_mut().zip(fds) {
            if fd.revents & (libc::POLLIN | libc::POLLHUP) != 0 {
                watch.exited_at = Some(Instant::now());
                watch.fd.take();
                log::debug!("Process-exit watch signaled: fd={}", fd.fd);
            }
        }
    }
}

// Namespace evidence belongs to each socket, not just its process. BPF and
// verified procfs attribution avoid a ptrace-gated read of the owner's namespace.
fn socket_in_local_namespace(conn: &TrackedConnection, local: Option<u64>) -> bool {
    let Some(local) = local else {
        return false;
    };
    if let Some(socket) = conn.socket_netns_id {
        return socket == local;
    }
    fs::metadata(format!("/proc/{}/ns/net", conn.pid))
        .ok()
        .is_some_and(|meta| meta.ino() == local)
}

/// Each required family/protocol table is either fully parsed or unknown.
/// Unlike attribution's best-effort scanner, absence is never inferred from
/// a missing file, a denied read, or a malformed row.
struct SocketTables {
    tables: HashMap<(Protocol, bool), Option<HashSet<ConnectionKey>>>,
}

impl SocketTables {
    fn read(connections: &[TrackedConnection]) -> Self {
        let mut tables = HashMap::new();
        for conn in connections {
            for ipv6 in [false, true] {
                let family = (conn.observation.key.protocol, ipv6);
                tables.entry(family).or_insert_with(|| {
                    let path = match family {
                        (Protocol::Tcp, false) => "/proc/self/net/tcp",
                        (Protocol::Tcp, true) => "/proc/self/net/tcp6",
                        (Protocol::Udp, false) => "/proc/self/net/udp",
                        (Protocol::Udp, true) => "/proc/self/net/udp6",
                        _ => return None,
                    };
                    match fs::read_to_string(path).and_then(|text| parse_table(&text, family.0)) {
                        Ok(table) => Some(table),
                        Err(error) => {
                            log::debug!("Process-exit socket scan failed: {path}: {error}");
                            None
                        }
                    }
                });
            }
        }
        Self { tables }
    }

    fn contains(&self, key: ConnectionKey) -> Option<bool> {
        let key = ConnectionKey {
            local_addr: std::net::SocketAddr::new(
                key.local_addr.ip().to_canonical(),
                key.local_addr.port(),
            ),
            remote_addr: std::net::SocketAddr::new(
                key.remote_addr.ip().to_canonical(),
                key.remote_addr.port(),
            ),
            ..key
        };
        let table = self
            .tables
            .get(&(key.protocol, key.local_addr.is_ipv6()))?
            .as_ref()?;
        if Self::contains_in(table, key) {
            return Some(true);
        }
        if let (std::net::IpAddr::V4(local), std::net::IpAddr::V4(remote)) =
            (key.local_addr.ip(), key.remote_addr.ip())
        {
            let ipv6 = self.tables.get(&(key.protocol, true))?.as_ref()?;
            let mapped = ConnectionKey {
                local_addr: std::net::SocketAddr::new(
                    local.to_ipv6_mapped().into(),
                    key.local_addr.port(),
                ),
                remote_addr: std::net::SocketAddr::new(
                    remote.to_ipv6_mapped().into(),
                    key.remote_addr.port(),
                ),
                ..key
            };
            return Some(Self::contains_in(ipv6, mapped));
        }
        Some(false)
    }

    fn contains_in(table: &HashSet<ConnectionKey>, key: ConnectionKey) -> bool {
        if table.contains(&key) {
            return true;
        }
        // UDP may be unconnected or bound to a wildcard local address.
        // Preserve the flow if any such endpoint could still carry it,
        // regardless of which process owns it now.
        if key.protocol == Protocol::Udp {
            let wildcard_ip = if key.local_addr.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            };
            let mut candidate = key;
            candidate.local_addr.set_ip(wildcard_ip);
            if table.contains(&candidate) {
                return true;
            }
            candidate.remote_addr = std::net::SocketAddr::new(wildcard_ip, 0);
            if table.contains(&candidate) {
                return true;
            }
            candidate.local_addr = key.local_addr;
            if table.contains(&candidate) {
                return true;
            }
        }
        false
    }
}

fn parse_table(text: &str, protocol: Protocol) -> io::Result<HashSet<ConnectionKey>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "incomplete socket table");
    let mut lines = text.lines();
    let header = lines.next().ok_or_else(invalid)?;
    if !header.contains("local_address") || !header.contains("inode") {
        return Err(invalid());
    }
    let mut keys = HashSet::new();
    for line in lines {
        let row = parse_proc_net_line(line).ok_or_else(invalid)?;
        let inode: u64 = row
            .inode
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        // TIME_WAIT and orphaned TCP teardown can outlive the application's
        // socket. Preserve their observed transport state in the archive.
        if inode != 0 {
            keys.insert(ConnectionKey {
                protocol,
                local_addr: row.local_addr,
                remote_addr: row.remote_addr,
            });
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests;
