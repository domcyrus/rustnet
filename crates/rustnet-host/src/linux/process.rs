//! Linux procfs-based process lookup.

use crate::procfs::{parse_proc_net_addr, read_comm, read_comm_in};
use crate::{
    ConnectionKey, HostSocket, HostSocketState, HostTcpState, MatchQuality, ProcessAncestor,
    ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner, SocketSnapshot,
    collect_process_lineage, memoized, relaxed_lookup, remote_if_present,
};
use anyhow::Result;
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

/// Resolve the executable path of a TGID from `/proc/<tgid>/exe`.
///
/// Resolved in user space immediately after a successful attribution, while the
/// process is most likely still alive. `None` is a normal outcome and never
/// fails the attribution: the process may have exited already, be a kernel
/// thread (no `exe` link), or belong to another user, whose `exe` link needs
/// `CAP_SYS_PTRACE` to read.
pub(crate) fn resolve_executable(tgid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{tgid}/exe")).ok()
}

/// Read the effective UID/GID of a TGID from the ownership of `/proc/<tgid>`,
/// which the kernel stamps with the task's effective credentials.
///
/// `None` when the process is gone or hidden (`hidepid`).
pub(crate) fn resolve_credentials(tgid: u32) -> Option<(u32, u32)> {
    let metadata = fs::metadata(format!("/proc/{tgid}")).ok()?;
    Some((metadata.uid(), metadata.gid()))
}

/// Recover a comm-truncated process name from the executable's file name.
///
/// The kernel `comm` field holds at most 15 bytes, so both eBPF and the procfs
/// scan see "chromium-browse" for chromium-browser. When a name sits exactly at
/// that limit and the resolved executable's file name strictly extends it, the
/// executable name is the untruncated original. Shorter names and interpreter
/// cases (comm "myscript", exe "python3") never match and pass through
/// unchanged.
pub(crate) fn refine_truncated_name(name: String, executable: Option<&Path>) -> String {
    const COMM_MAX: usize = 15;
    if name.len() != COMM_MAX {
        return name;
    }
    match executable
        .and_then(|path| path.file_name())
        .and_then(|file_name| file_name.to_str())
    {
        Some(basename) if basename.len() > COMM_MAX && basename.starts_with(name.as_str()) => {
            basename.to_string()
        }
        _ => name,
    }
}

/// Read the parent process id from `/proc/<tgid>/status`.
///
/// This is resolved in user space for both procfs and eBPF socket matches. It
/// remains best effort because a short-lived process may exit before
/// enrichment runs.
pub(crate) fn resolve_parent_pid(tgid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{tgid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
}

#[derive(Debug, PartialEq, Eq)]
struct ProcStat {
    name: String,
    ppid: u32,
    start_ticks: u64,
}

fn parse_proc_stat(stat: &str) -> Option<ProcStat> {
    let name_start = stat.find('(')?;
    let name_end = stat.rfind(')')?;
    if name_end <= name_start {
        return None;
    }

    // Fields after the closing parenthesis start at field 3 (`state`). The
    // parent PID is field 4 and process start ticks are field 22.
    let fields: Vec<&str> = stat.get(name_end + 1..)?.split_whitespace().collect();
    Some(ProcStat {
        name: stat.get(name_start + 1..name_end)?.to_string(),
        ppid: fields.get(1)?.parse().ok()?,
        start_ticks: fields.get(19)?.parse().ok()?,
    })
}

fn boot_time_unix_ms() -> Option<u64> {
    static BOOT_TIME: OnceLock<Option<u64>> = OnceLock::new();
    *BOOT_TIME.get_or_init(|| {
        fs::read_to_string("/proc/stat")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("btime "))?
            .parse::<u64>()
            .ok()?
            .checked_mul(1_000)
    })
}

fn clock_ticks_per_second() -> Option<u64> {
    static CLOCK_TICKS: OnceLock<Option<u64>> = OnceLock::new();
    *CLOCK_TICKS.get_or_init(|| {
        // SAFETY: `sysconf` reads a process-wide constant and has no pointer
        // arguments or side effects.
        u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
            .ok()
            .filter(|ticks| *ticks > 0)
    })
}

fn process_start_unix_ms(start_ticks: u64) -> Option<u64> {
    let ticks_per_second = clock_ticks_per_second()?;
    let since_boot_ms = start_ticks.checked_mul(1_000)? / ticks_per_second;
    boot_time_unix_ms()?.checked_add(since_boot_ms)
}

fn resolve_process_ancestor(pid: u32) -> Option<(ProcessAncestor, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let stat = parse_proc_stat(&stat)?;
    let executable = resolve_executable(pid);
    let name = refine_truncated_name(stat.name, executable.as_deref());
    Some((
        ProcessAncestor {
            pid,
            name,
            executable,
            started_at_unix_ms: process_start_unix_ms(stat.start_ticks),
        },
        stat.ppid,
    ))
}

fn resolve_process_lineage(tgid: u32, ppid: u32) -> Option<ProcessLineage> {
    collect_process_lineage(tgid, ppid, resolve_process_ancestor)
}

/// Map of socket inode to its best-effort process owner.
type InodeProcessMap = HashMap<u64, SocketOwner>;

/// Socket owners discovered before the procfs connection tables are parsed.
///
/// The BPF task-file iterator and procfs may both report an inode. Repeated
/// reports from the same TGID are harmless, but fork and fd passing let
/// several processes hold one socket: a pre-forking server's workers all
/// carry the listening inode their master opened. Those inodes keep a
/// best-effort owner for the live table, chosen by lowest PID so that
/// /proc iteration order cannot change the answer between refreshes, and are
/// reported separately as shared so the startup snapshot can skip them.
#[derive(Debug, Default)]
pub(super) struct StartupSocketOwners {
    owners: InodeProcessMap,
    shared: HashSet<u64>,
}

impl StartupSocketOwners {
    pub(super) fn insert(&mut self, inode: u64, owner: SocketOwner) {
        if inode == 0 {
            return;
        }

        match self.owners.entry(inode) {
            Entry::Vacant(entry) => {
                entry.insert(owner);
            }
            // The same process seen twice: prefer the later report, which is
            // the procfs scan refreshing what BPF recorded first.
            Entry::Occupied(mut entry) if entry.get().pid == owner.pid => {
                entry.insert(owner);
            }
            Entry::Occupied(mut entry) => {
                self.shared.insert(inode);
                if owner.pid < entry.get().pid {
                    entry.insert(owner);
                }
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.owners.len()
    }

    #[cfg(test)]
    pub(super) fn get(&self, inode: u64) -> Option<&SocketOwner> {
        self.owners.get(&inode)
    }

    /// The owner map for the live socket table, plus the inodes held by more
    /// than one process.
    fn into_parts(self) -> (InodeProcessMap, HashSet<u64>) {
        (self.owners, self.shared)
    }
}
/// Map of PID to process name
#[cfg(feature = "ebpf")]
type PidNameMap = HashMap<u32, String>;
#[cfg(not(feature = "ebpf"))]
type PidNameMap = ();
/// Map of connection key to (PID, process name)
type ConnectionProcessMap = HashMap<ConnectionKey, (u32, String)>;

/// The procfs socket tables, in scan order: a later table wins when two
/// report the same tuple.
const PROC_NET_TABLES: [(&str, Protocol); 4] = [
    ("/proc/net/tcp", Protocol::Tcp),
    ("/proc/net/tcp6", Protocol::Tcp),
    ("/proc/net/udp", Protocol::Udp),
    ("/proc/net/udp6", Protocol::Udp),
];

/// Owner recorded by the BPF or privileged procfs startup scan for one
/// pre-existing socket, keyed by its exact 4-tuple. The inode pins the
/// attribution to the socket object itself, not merely the tuple.
#[derive(Debug, Clone)]
struct SnapshotOwner {
    pid: u32,
    name: String,
    inode: u64,
    /// Process start time in clock ticks, when it was readable at startup.
    /// `comm` alone cannot survive PID reuse because any process may rename
    /// itself with `prctl(PR_SET_NAME)`; the start time cannot be forged.
    start_ticks: Option<u64>,
}

/// Process start time in clock ticks, stable for the life of the process.
fn process_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(parse_proc_stat(&stat)?.start_ticks)
}

/// Build the startup fallback table from the startup socket inventory,
/// pairing each owner with the inode of its own row so the two can never
/// come from different sockets. A tuple occupied by more than one socket
/// (SO_REUSEPORT plus connected UDP makes exact duplicates legal) is
/// dropped entirely, even when only one of its rows resolved an owner:
/// observed traffic cannot be assigned to either socket. So is a socket held
/// by several processes, whose single owner is a best-effort pick the live
/// table can live with but a long-lived fallback should not freeze. Rows
/// without an inode or a resolved owner contribute no entry of their own.
fn build_startup_snapshot(
    sockets: &SocketSnapshot,
    shared_inodes: &HashSet<u64>,
) -> HashMap<ConnectionKey, SnapshotOwner> {
    let key_of = |socket: &HostSocket| {
        socket.remote_addr.map(|remote_addr| ConnectionKey {
            protocol: socket.protocol,
            local_addr: socket.local_addr,
            remote_addr,
        })
    };

    let mut occupancy: HashMap<ConnectionKey, u32> = HashMap::new();
    for socket in sockets.sockets.iter() {
        if let Some(key) = key_of(socket) {
            *occupancy.entry(key).or_insert(0) += 1;
        }
    }

    let mut snapshot = HashMap::new();
    for socket in sockets.sockets.iter() {
        let (Some(key), Some(inode), Some(owner)) =
            (key_of(socket), socket.native_id, socket.owner.as_ref())
        else {
            continue;
        };
        if occupancy.get(&key) != Some(&1) || shared_inodes.contains(&inode) {
            continue;
        }
        snapshot.insert(
            key,
            SnapshotOwner {
                pid: owner.pid,
                name: owner.name.clone(),
                inode,
                start_ticks: process_start_ticks(owner.pid),
            },
        );
    }
    snapshot
}

/// Whether a startup-snapshot entry's recorded owner is still the same
/// process. `/proc/<pid>` stays world-readable after the uid drop, so both
/// the name captured at startup and, when it was readable, the process start
/// time must still match. This rejects owners that have exited and PIDs
/// since reused by a different program, including one that renamed itself to
/// impersonate the original.
fn snapshot_owner_still_matches(owner: &SnapshotOwner) -> bool {
    let name_matches = read_comm(owner.pid).as_deref() == Some(owner.name.as_str());

    name_matches
        && match owner.start_ticks {
            Some(start_ticks) => process_start_ticks(owner.pid) == Some(start_ticks),
            None => true,
        }
}

fn parse_proc_tcp_state(value: &str) -> HostTcpState {
    match value {
        "01" => HostTcpState::Established,
        "02" => HostTcpState::SynSent,
        "03" | "0C" => HostTcpState::SynReceived,
        "04" => HostTcpState::FinWait1,
        "05" => HostTcpState::FinWait2,
        "06" => HostTcpState::TimeWait,
        "07" => HostTcpState::Closed,
        "08" => HostTcpState::CloseWait,
        "09" => HostTcpState::LastAck,
        "0A" => HostTcpState::Listen,
        "0B" => HostTcpState::Closing,
        _ => HostTcpState::Unknown,
    }
}

pub(super) struct LinuxProcessLookup {
    // Cache: ConnectionKey -> (pid, process_name)
    cache: RwLock<ConnectionProcessMap>,
    // The socket table as scanned at startup, while the process still had
    // its full privileges. After the uid drop, rescans only see the drop
    // target's own /proc/<pid>/fd entries, so connections that already
    // existed at launch (other users' daemons, root services) would lose
    // their owner on the first refresh. This immutable snapshot keeps them
    // attributable. The live cache always wins; the snapshot only fills
    // holes, so a reused 4-tuple visible to the rescan is never shadowed.
    startup_snapshot: HashMap<ConnectionKey, SnapshotOwner>,
    // PID -> process_name, for resolving eBPF thread names to main process names.
    #[cfg(feature = "ebpf")]
    pid_names: RwLock<HashMap<u32, String>>,
    // Memo: TGID -> lineage, so many connections of one process walk /proc
    // once per refresh instead of once each. Failures are memoized too.
    lineages: RwLock<HashMap<u32, Option<ProcessLineage>>>,
    socket_snapshot: RwLock<SocketSnapshot>,
}

impl LinuxProcessLookup {
    pub(super) fn new() -> Result<Self> {
        Self::new_with_startup_socket_owners(StartupSocketOwners::default())
    }

    #[cfg(feature = "ebpf")]
    pub(super) fn new_with_bpf_startup_owners(owners: StartupSocketOwners) -> Result<Self> {
        Self::new_with_startup_socket_owners(owners)
    }

    fn new_with_startup_socket_owners(owners: StartupSocketOwners) -> Result<Self> {
        // Populate the cache immediately so it is ready before packet capture starts.
        let (process_map, _pid_names, socket_snapshot, shared_inodes) =
            Self::build_process_map(owners)?;

        Ok(Self {
            startup_snapshot: build_startup_snapshot(&socket_snapshot, &shared_inodes),
            cache: RwLock::new(process_map),
            #[cfg(feature = "ebpf")]
            pid_names: RwLock::new(_pid_names),
            lineages: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(socket_snapshot),
        })
    }

    /// Build a lookup over a caller-supplied socket table instead of scanning
    /// `/proc/net/*`, so match-quality behaviour can be tested deterministically.
    #[cfg(test)]
    fn with_socket_table(lookup: ConnectionProcessMap) -> Self {
        Self {
            startup_snapshot: HashMap::new(),
            cache: RwLock::new(lookup),
            #[cfg(feature = "ebpf")]
            pid_names: RwLock::new(HashMap::new()),
            lineages: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        }
    }

    /// Get process name by PID. Tries the cached procfs scan first, then
    /// falls back to reading `/proc/<pid>/comm` directly: the cache only
    /// refreshes every few seconds, so a freshly started process (exactly
    /// the case for short-lived tools like curl/dig) is often missing
    /// from it while still being perfectly readable from /proc. One tiny
    /// file read; the result is cached so repeated lookups stay cheap.
    /// Returns None if the process has already exited and was never scanned.
    #[cfg(feature = "ebpf")]
    pub(super) fn get_process_name_by_pid(&self, pid: u32) -> Option<String> {
        if let Some(name) = self
            .pid_names
            .read()
            .expect("pid_names lock poisoned")
            .get(&pid)
            .cloned()
        {
            return Some(name);
        }

        let name = read_comm(pid)?;
        self.pid_names
            .write()
            .expect("pid_names lock poisoned")
            .insert(pid, name.clone());
        Some(name)
    }

    /// Match a connection against the cached procfs socket table.
    ///
    /// Returns the owner together with how it was matched, so callers can tell
    /// a proven 4-tuple hit from a relaxed guess. Ambiguous relaxed matches
    /// (two candidates, two different owners) yield `None`.
    ///
    /// Never refreshes on a miss: the enrichment thread refreshes every few
    /// seconds, and refreshing here runs once per unattributed connection,
    /// which is a CPU hotspot.
    fn lookup_match(&self, conn: &Connection) -> Option<(u32, String, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("process cache lock poisoned");

        // Fast path: exact 4-tuple match (always works for TCP).
        if let Some((pid, name)) = cache.get(&key) {
            return Some((*pid, name.clone(), MatchQuality::ProcfsExact));
        }

        // Fallback: /proc/net may store sockets with wildcard addresses.
        // Progressively relax the key until we find a match. The relaxation
        // shape is deliberately collapsed into a single `ProcfsRelaxed`: what
        // matters downstream is that procfs needed to guess, not which of the
        // three wildcard shapes it guessed with.
        if let Some(((pid, name), _shape)) = relaxed_lookup(&cache, &key) {
            return Some((*pid, name.clone(), MatchQuality::ProcfsRelaxed));
        }
        drop(cache);

        // Last resort: the BPF or privileged procfs startup snapshot, for
        // connections that already existed at launch but whose owner the
        // post-uid-drop rescan can no longer see. Exact 4-tuple hits only:
        // relaxed matching against the snapshot would let a stale listener
        // entry claim new inbound connections indefinitely. The hit is only
        // trusted while (a) the very same socket, by inode, still occupies
        // the tuple in the periodically refreshed socket inventory (which
        // stays readable after the uid drop even when owners do not), so a
        // closed-and-reused tuple is rejected; and (b) the recorded owner is
        // verifiably still the same process. The refresh cadence bounds the
        // reuse-detection window to one refresh interval.
        let owner = self.startup_snapshot.get(&key)?;
        if self.snapshot_socket_unchanged(&key, owner.inode) && snapshot_owner_still_matches(owner)
        {
            return Some((owner.pid, owner.name.clone(), MatchQuality::StartupSnapshot));
        }
        None
    }

    /// Whether the current socket inventory still shows the startup socket
    /// (same inode) on this exact tuple.
    fn snapshot_socket_unchanged(&self, key: &ConnectionKey, inode: u64) -> bool {
        let snapshot = self
            .socket_snapshot
            .read()
            .expect("socket snapshot lock poisoned");
        snapshot.sockets.iter().any(|socket| {
            socket.native_id == Some(inode)
                && socket.protocol == key.protocol
                && socket.local_addr == key.local_addr
                && socket.remote_addr == Some(key.remote_addr)
        })
    }

    /// Resolve a process's parent chain, memoized per TGID until the next
    /// socket-table refresh bounds PID-reuse staleness.
    pub(crate) fn lineage_for(&self, tgid: u32, ppid: u32) -> Option<ProcessLineage> {
        memoized(&self.lineages, tgid, "lineages lock poisoned", || {
            resolve_process_lineage(tgid, ppid)
        })
    }

    /// Turn a procfs socket-table match into a rich attribution by reading the
    /// live `/proc/<tgid>` entries for the owner.
    ///
    /// The socket table sources the name from `/proc/<tgid>/comm` during the
    /// scan, so a comm-truncated name is recovered from the executable here.
    fn build_attribution(
        &self,
        tgid: u32,
        name: String,
        quality: MatchQuality,
    ) -> ProcessAttribution {
        let executable = resolve_executable(tgid);
        let name = refine_truncated_name(name, executable.as_deref());
        let mut attribution =
            ProcessAttribution::new(tgid, name, quality).with_executable(executable);
        if let Some(ppid) = resolve_parent_pid(tgid) {
            attribution = attribution
                .with_parent_pid(ppid)
                .with_lineage(self.lineage_for(tgid, ppid));
        }

        match resolve_credentials(tgid) {
            Some((uid, gid)) => attribution.with_credentials(uid, gid),
            None => attribution,
        }
    }

    /// Build connection -> process mapping and PID -> name mapping
    fn build_process_map(
        startup_owners: StartupSocketOwners,
    ) -> Result<(
        ConnectionProcessMap,
        PidNameMap,
        SocketSnapshot,
        HashSet<u64>,
    )> {
        let mut process_map = HashMap::new();
        let mut sockets = Vec::new();

        let (inode_to_process, pid_names, shared_inodes) = Self::build_inode_map(startup_owners)?;

        for (path, protocol) in PROC_NET_TABLES {
            Self::parse_and_map(
                path,
                protocol,
                &inode_to_process,
                &mut process_map,
                &mut sockets,
            )?;
        }

        Ok((
            process_map,
            pid_names,
            SocketSnapshot::new(sockets),
            shared_inodes,
        ))
    }

    /// Build inode -> (pid, process_name) mapping and PID -> process_name mapping
    fn build_inode_map(
        mut startup_owners: StartupSocketOwners,
    ) -> Result<(InodeProcessMap, PidNameMap, HashSet<u64>)> {
        #[cfg(feature = "ebpf")]
        let mut pid_names = startup_owners
            .owners
            .values()
            .map(|owner| (owner.pid, owner.name.clone()))
            .collect::<HashMap<_, _>>();
        #[cfg(not(feature = "ebpf"))]
        let pid_names = ();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();

            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str())
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                if pid == 0 {
                    continue;
                }

                // Get process name, skipping the process when comm is
                // unreadable (see `procfs::read_comm_in`).
                let Some(process_name) = read_comm_in(&path) else {
                    continue;
                };

                #[cfg(feature = "ebpf")]
                pid_names.insert(pid, process_name.clone());

                let uid = fs::metadata(&path).ok().map(|metadata| metadata.uid());

                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path())
                            && let Some(link_str) = link.to_str()
                            && let Some(inode) = Self::extract_socket_inode(link_str)
                        {
                            startup_owners.insert(
                                inode,
                                SocketOwner {
                                    pid,
                                    name: process_name.clone(),
                                    uid,
                                },
                            );
                        }
                    }
                }
            }
        }

        let (inode_map, shared_inodes) = startup_owners.into_parts();
        Ok((inode_map, pid_names, shared_inodes))
    }

    /// Parse /proc/net file and map connections to processes
    fn parse_and_map(
        path: &str,
        protocol: Protocol,
        inode_map: &InodeProcessMap,
        result: &mut ConnectionProcessMap,
        sockets: &mut Vec<HostSocket>,
    ) -> Result<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // File might not exist
        };

        Self::parse_and_map_content(&content, protocol, inode_map, result, sockets);
        Ok(())
    }

    fn parse_and_map_content(
        content: &str,
        protocol: Protocol,
        inode_map: &InodeProcessMap,
        result: &mut ConnectionProcessMap,
        sockets: &mut Vec<HostSocket>,
    ) {
        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let local_addr = match parse_proc_net_addr(parts[1]) {
                Some(addr) => addr,
                None => continue,
            };

            let remote_addr = match parse_proc_net_addr(parts[2]) {
                Some(addr) => addr,
                None => continue,
            };
            if protocol == Protocol::Udp && local_addr.port() == 0 {
                continue;
            }

            let inode = parts[9].parse::<u64>().ok();
            let owner = inode.and_then(|inode| inode_map.get(&inode)).cloned();
            let state = match protocol {
                Protocol::Tcp => HostSocketState::Tcp(parse_proc_tcp_state(parts[3])),
                Protocol::Udp => HostSocketState::UdpBound,
                _ => continue,
            };

            let key = ConnectionKey {
                protocol,
                local_addr,
                remote_addr,
            };
            if let Some(owner) = &owner {
                result.insert(key, (owner.pid, owner.name.clone()));
            }

            sockets.push(HostSocket {
                protocol,
                local_addr,
                remote_addr: remote_if_present(remote_addr),
                state,
                owner,
                native_id: inode,
            });
        }
    }

    fn extract_socket_inode(link: &str) -> Option<u64> {
        if link.starts_with("socket:[") && link.ends_with(']') {
            let inode_str = &link[8..link.len() - 1];
            inode_str.parse().ok()
        } else {
            None
        }
    }
}

impl ProcessLookup for LinuxProcessLookup {
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (tgid, name, quality) = self.lookup_match(conn)?;
        Some(self.build_attribution(tgid, name, quality))
    }

    fn refresh(&self) -> Result<()> {
        let (process_map, _pid_names, socket_snapshot, _shared_inodes) =
            Self::build_process_map(StartupSocketOwners::default())?;

        *self.cache.write().expect("process cache lock poisoned") = process_map;
        *self
            .socket_snapshot
            .write()
            .expect("socket snapshot lock poisoned") = socket_snapshot;

        #[cfg(feature = "ebpf")]
        {
            *self.pid_names.write().expect("pid_names lock poisoned") = _pid_names;
        }
        self.lineages
            .write()
            .expect("lineages lock poisoned")
            .clear();

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "procfs"
    }

    fn socket_snapshot(&self) -> SocketSnapshot {
        self.socket_snapshot
            .read()
            .expect("socket snapshot lock poisoned")
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{tcp_connection, tcp_key as key};
    use rustnet_core::network::types::{ProtocolState, TcpState};

    #[test]
    fn startup_socket_owners_report_a_shared_inode_without_losing_its_owner() {
        // A pre-forking server: the master opened the listening socket and
        // every worker inherited it. Dropping the inode would leave the
        // listener ownerless in the live table, so the lowest PID (the
        // master) wins and the inode is reported as shared instead.
        let mut owners = StartupSocketOwners::default();
        owners.insert(42, SocketOwner::new(1001, "nginx", Some(33)));
        owners.insert(42, SocketOwner::new(1000, "nginx", Some(0)));
        owners.insert(42, SocketOwner::new(1002, "nginx", Some(33)));

        assert_eq!(
            owners.get(42),
            Some(&SocketOwner::new(1000, "nginx", Some(0)))
        );

        let (inode_map, shared) = owners.into_parts();
        assert_eq!(
            inode_map.get(&42),
            Some(&SocketOwner::new(1000, "nginx", Some(0)))
        );
        assert!(shared.contains(&42));
    }

    #[test]
    fn startup_socket_owners_pick_a_shared_inode_owner_independent_of_scan_order() {
        // /proc iteration order must not change the answer between refreshes.
        let mut forward = StartupSocketOwners::default();
        for pid in [1000, 1001, 1002] {
            forward.insert(42, SocketOwner::new(pid, "nginx", Some(0)));
        }
        let mut reverse = StartupSocketOwners::default();
        for pid in [1002, 1001, 1000] {
            reverse.insert(42, SocketOwner::new(pid, "nginx", Some(0)));
        }

        assert_eq!(forward.get(42).map(|owner| owner.pid), Some(1000));
        assert_eq!(reverse.get(42).map(|owner| owner.pid), Some(1000));
    }

    #[test]
    fn startup_socket_owners_collapse_same_process_duplicates() {
        let mut owners = StartupSocketOwners::default();
        owners.insert(42, SocketOwner::new(10, "old-name", None));
        owners.insert(42, SocketOwner::new(10, "current-name", Some(1000)));

        assert_eq!(
            owners.get(42),
            Some(&SocketOwner::new(10, "current-name", Some(1000)))
        );
    }

    #[test]
    fn bpf_startup_owner_joins_the_procfs_socket_inode() {
        let mut owners = StartupSocketOwners::default();
        owners.insert(123, SocketOwner::new(10, "nordvpnd", Some(0)));
        let (inode_map, _shared) = owners.into_parts();
        let mut process_map = ConnectionProcessMap::new();
        let mut sockets = Vec::new();
        let table = concat!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n",
            "   0: 0100007F:1F90 08080808:01BB 01 00000000:00000000 00:00000000 00000000 0 0 123\n",
        );

        LinuxProcessLookup::parse_and_map_content(
            table,
            Protocol::Tcp,
            &inode_map,
            &mut process_map,
            &mut sockets,
        );

        let socket = sockets.first().expect("socket row must parse");
        assert_eq!(socket.native_id, Some(123));
        assert_eq!(
            socket.owner,
            Some(SocketOwner::new(10, "nordvpnd", Some(0)))
        );
        assert_eq!(
            process_map.get(&key("127.0.0.1:8080", "8.8.8.8:443")),
            Some(&(10, "nordvpnd".to_string()))
        );
    }

    /// Attribute to this very test process so the /proc reads have a live
    /// target with known credentials and a known executable.
    fn own_pid() -> u32 {
        std::process::id()
    }

    #[test]
    fn proc_tcp_states_include_listen_and_established() {
        assert_eq!(parse_proc_tcp_state("0A"), HostTcpState::Listen);
        assert_eq!(parse_proc_tcp_state("01"), HostTcpState::Established);
        assert_eq!(parse_proc_tcp_state("06"), HostTcpState::TimeWait);
        assert_eq!(parse_proc_tcp_state("FF"), HostTcpState::Unknown);
    }

    fn own_comm() -> String {
        fs::read_to_string(format!("/proc/{}/comm", own_pid()))
            .expect("own comm readable")
            .trim()
            .to_string()
    }

    /// An established TCP socket row as the refreshed inventory would list
    /// it after the uid drop: tuple and inode visible, owner or not.
    fn host_socket(local: &str, remote: &str, inode: u64) -> HostSocket {
        let mut socket = HostSocket::new(
            Protocol::Tcp,
            local.parse().unwrap(),
            HostSocketState::Tcp(HostTcpState::Established),
        );
        socket.remote_addr = Some(remote.parse().unwrap());
        socket.native_id = Some(inode);
        socket
    }

    fn snapshot_lookup(
        owner: (&str, &str, u32, String, u64),
        inventory: Vec<HostSocket>,
    ) -> LinuxProcessLookup {
        let (local, remote, pid, name, inode) = owner;
        let mut startup = HashMap::new();
        startup.insert(
            key(local, remote),
            SnapshotOwner {
                pid,
                name,
                inode,
                start_ticks: process_start_ticks(pid),
            },
        );
        LinuxProcessLookup {
            startup_snapshot: startup,
            cache: RwLock::new(ConnectionProcessMap::new()),
            #[cfg(feature = "ebpf")]
            pid_names: RwLock::new(HashMap::new()),
            lineages: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::new(inventory)),
        }
    }

    fn owned_socket(local: &str, remote: &str, inode: u64, pid: u32, name: &str) -> HostSocket {
        let mut socket = host_socket(local, remote, inode);
        socket.owner = Some(SocketOwner::new(pid, name, None));
        socket
    }

    #[test]
    fn startup_snapshot_pairs_owner_and_inode_from_the_same_row() {
        // Two owned sockets: each snapshot entry must carry its own row's
        // inode and owner, never a mix.
        let sockets = SocketSnapshot::new(vec![
            owned_socket("192.168.1.10:44444", "203.0.113.5:22", 777, 41, "sshd"),
            owned_socket("192.168.1.10:55555", "203.0.113.6:443", 888, 42, "nginx"),
        ]);
        let snapshot = build_startup_snapshot(&sockets, &HashSet::new());

        let a = &snapshot[&key("192.168.1.10:44444", "203.0.113.5:22")];
        assert_eq!((a.pid, a.name.as_str(), a.inode), (41, "sshd", 777));
        let b = &snapshot[&key("192.168.1.10:55555", "203.0.113.6:443")];
        assert_eq!((b.pid, b.name.as_str(), b.inode), (42, "nginx", 888));
    }

    #[test]
    fn startup_snapshot_drops_a_tuple_occupied_by_two_sockets() {
        // SO_REUSEPORT plus connected UDP permits exact duplicate tuples.
        // Even when only one row resolved an owner (the other hidden by
        // permissions or a scan race), the tuple is ambiguous: the owner
        // must not be paired with either inode.
        let owned = owned_socket("192.168.1.10:5353", "203.0.113.5:5353", 777, 41, "resolver");
        let ownerless = host_socket("192.168.1.10:5353", "203.0.113.5:5353", 778);
        let sockets = SocketSnapshot::new(vec![owned, ownerless]);
        let snapshot = build_startup_snapshot(&sockets, &HashSet::new());

        assert!(snapshot.is_empty());
    }

    #[test]
    fn startup_snapshot_skips_a_socket_held_by_several_processes() {
        // The live table keeps the master as a best-effort owner, but the
        // long-lived fallback must not freeze that pick: the master can exit
        // while a worker keeps the socket open.
        let sockets = SocketSnapshot::new(vec![owned_socket(
            "192.168.1.10:44444",
            "203.0.113.5:22",
            777,
            1000,
            "nginx",
        )]);
        let shared = HashSet::from([777]);

        assert!(build_startup_snapshot(&sockets, &shared).is_empty());
    }

    #[test]
    fn startup_snapshot_skips_ownerless_and_inodeless_rows() {
        let ownerless = host_socket("192.168.1.10:44444", "203.0.113.5:22", 777);
        let mut inodeless = owned_socket("192.168.1.10:55555", "203.0.113.6:443", 0, 41, "sshd");
        inodeless.native_id = None;
        let sockets = SocketSnapshot::new(vec![ownerless, inodeless]);

        assert!(build_startup_snapshot(&sockets, &HashSet::new()).is_empty());
    }

    #[test]
    fn startup_snapshot_attributes_when_the_rescanned_table_cannot() {
        // A connection whose owner is present in the startup owner scan but
        // invisible to every post-uid-drop rescan: same socket
        // (same inode) still on the tuple, owner still alive. The snapshot
        // records this very test process so /proc validation has a real
        // target.
        let lookup = snapshot_lookup(
            (
                "192.168.1.10:44444",
                "203.0.113.5:22",
                own_pid(),
                own_comm(),
                777,
            ),
            vec![host_socket("192.168.1.10:44444", "203.0.113.5:22", 777)],
        );

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:22");
        let (got_pid, got_name, quality) =
            lookup.lookup_match(&conn).expect("snapshot should match");
        assert_eq!(got_pid, own_pid());
        assert_eq!(got_name, own_comm());
        assert_eq!(quality, MatchQuality::StartupSnapshot);
    }

    #[test]
    fn startup_snapshot_rejects_a_reused_tuple() {
        // The startup socket closed and another (owner-invisible) socket
        // reuses the exact tuple: the inventory shows a different inode,
        // so the stale owner must not attribute, even though it still runs.
        let lookup = snapshot_lookup(
            (
                "192.168.1.10:44444",
                "203.0.113.5:22",
                own_pid(),
                own_comm(),
                777,
            ),
            vec![host_socket("192.168.1.10:44444", "203.0.113.5:22", 778)],
        );

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:22");
        assert!(lookup.lookup_match(&conn).is_none());
    }

    #[test]
    fn startup_snapshot_rejects_a_closed_socket() {
        // The tuple is gone from the current inventory entirely.
        let lookup = snapshot_lookup(
            (
                "192.168.1.10:44444",
                "203.0.113.5:22",
                own_pid(),
                own_comm(),
                777,
            ),
            Vec::new(),
        );

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:22");
        assert!(lookup.lookup_match(&conn).is_none());
    }

    #[test]
    fn startup_snapshot_rejects_an_owner_that_no_longer_matches() {
        // Socket unchanged, but the recorded owner has exited (or its PID
        // was reused): a PID above the kernel's pid_max cannot exist.
        let lookup = snapshot_lookup(
            (
                "192.168.1.10:44444",
                "203.0.113.5:22",
                u32::MAX,
                "sshd".to_string(),
                777,
            ),
            vec![host_socket("192.168.1.10:44444", "203.0.113.5:22", 777)],
        );

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:22");
        assert!(lookup.lookup_match(&conn).is_none());
    }

    #[test]
    fn startup_snapshot_rejects_a_reused_pid_that_took_the_owner_name() {
        // Socket unchanged and a live process answers to the recorded name,
        // but it started later: any process can rename itself with
        // prctl(PR_SET_NAME), so only the start time settles PID reuse.
        let mut startup = HashMap::new();
        startup.insert(
            key("192.168.1.10:44444", "203.0.113.5:22"),
            SnapshotOwner {
                pid: own_pid(),
                name: own_comm(),
                inode: 777,
                start_ticks: process_start_ticks(own_pid()).map(|ticks| ticks + 1),
            },
        );
        let lookup = LinuxProcessLookup {
            startup_snapshot: startup,
            cache: RwLock::new(ConnectionProcessMap::new()),
            #[cfg(feature = "ebpf")]
            pid_names: RwLock::new(HashMap::new()),
            lineages: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::new(vec![host_socket(
                "192.168.1.10:44444",
                "203.0.113.5:22",
                777,
            )])),
        };

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:22");
        assert!(lookup.lookup_match(&conn).is_none());
    }

    #[test]
    fn startup_snapshot_never_matches_relaxed_shapes() {
        // A stale wildcard listener entry in the snapshot must not claim
        // new inbound connections; only exact 4-tuple hits are trusted.
        let lookup = snapshot_lookup(
            ("0.0.0.0:80", "0.0.0.0:0", own_pid(), own_comm(), 777),
            vec![host_socket("192.168.1.10:80", "203.0.113.5:50000", 900)],
        );

        let conn = tcp_connection("192.168.1.10:80", "203.0.113.5:50000");
        assert!(lookup.lookup_match(&conn).is_none());
    }

    #[test]
    fn live_table_wins_over_the_startup_snapshot() {
        // A 4-tuple reused after startup: the rescan sees the new owner and
        // must shadow the stale snapshot entry.
        let k = key("192.168.1.10:44444", "203.0.113.5:443");
        let mut snapshot = HashMap::new();
        snapshot.insert(
            k,
            SnapshotOwner {
                pid: 4242,
                name: "old-owner".to_string(),
                inode: 777,
                start_ticks: None,
            },
        );
        let mut live = ConnectionProcessMap::new();
        live.insert(k, (5555, "curl".to_string()));

        let lookup = LinuxProcessLookup {
            startup_snapshot: snapshot,
            cache: RwLock::new(live),
            #[cfg(feature = "ebpf")]
            pid_names: RwLock::new(HashMap::new()),
            lineages: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        };

        let conn = tcp_connection("192.168.1.10:44444", "203.0.113.5:443");
        let (pid, name, quality) = lookup.lookup_match(&conn).expect("live table should match");
        assert_eq!(pid, 5555);
        assert_eq!(name, "curl");
        assert_eq!(quality, MatchQuality::ProcfsExact);
    }

    #[test]
    fn truncated_comm_is_recovered_from_the_executable_name() {
        assert_eq!(
            refine_truncated_name(
                "chromium-browse".to_string(),
                Some(Path::new("/usr/lib/chromium/chromium-browser")),
            ),
            "chromium-browser"
        );
    }

    #[test]
    fn short_names_are_never_touched() {
        // Below the 15-byte comm limit nothing was truncated, even when the
        // executable name would extend it (a comm may be legitimately renamed).
        assert_eq!(
            refine_truncated_name(
                "firefox".to_string(),
                Some(Path::new("/usr/lib/firefox/firefox-esr")),
            ),
            "firefox"
        );
    }

    #[test]
    fn interpreter_executables_do_not_replace_the_comm() {
        // comm at the limit but the executable is the interpreter, not an
        // extension of the name: keep the comm.
        assert_eq!(
            refine_truncated_name(
                "very-long-scrip".to_string(),
                Some(Path::new("/usr/bin/python3")),
            ),
            "very-long-scrip"
        );
    }

    #[test]
    fn missing_executable_keeps_the_truncated_comm() {
        assert_eq!(
            refine_truncated_name("chromium-browse".to_string(), None),
            "chromium-browse"
        );
    }

    #[test]
    fn executable_name_at_the_limit_is_not_an_extension() {
        assert_eq!(
            refine_truncated_name(
                "chromium-browse".to_string(),
                Some(Path::new("/opt/chromium-browse")),
            ),
            "chromium-browse"
        );
    }

    #[test]
    fn resolves_the_executable_of_a_live_process() {
        assert_eq!(
            resolve_executable(own_pid()),
            std::env::current_exe().ok(),
            "/proc/<tgid>/exe must resolve to the test binary"
        );
    }

    #[test]
    fn unreadable_executable_is_reported_as_none_rather_than_an_error() {
        // u32::MAX is above every reachable pid_max, so /proc/<tgid>/exe cannot
        // exist. Attribution must survive this, with executable = None.
        assert_eq!(resolve_executable(u32::MAX), None);
    }

    #[test]
    fn reads_the_credentials_of_a_live_process() {
        let (uid, gid) = resolve_credentials(own_pid()).expect("own /proc entry must be readable");
        assert_eq!(uid, unsafe { libc::geteuid() });
        assert_eq!(gid, unsafe { libc::getegid() });
    }

    #[test]
    fn missing_process_has_no_credentials() {
        assert_eq!(resolve_credentials(u32::MAX), None);
    }

    #[test]
    fn reads_the_parent_of_a_live_process() {
        let expected = u32::try_from(unsafe { libc::getppid() }).unwrap();
        assert_eq!(resolve_parent_pid(own_pid()), Some(expected));
    }

    #[test]
    fn missing_process_has_no_parent() {
        assert_eq!(resolve_parent_pid(u32::MAX), None);
    }

    #[test]
    fn proc_stat_parser_handles_spaces_and_parentheses_in_names() {
        let mut fields = vec!["S", "7"];
        fields.resize(19, "0");
        fields.push("12345");
        let stat = format!("42 (worker ) pool) {}", fields.join(" "));

        assert_eq!(
            parse_proc_stat(&stat),
            Some(ProcStat {
                name: "worker ) pool".to_string(),
                ppid: 7,
                start_ticks: 12345,
            })
        );
    }

    /// Many connections share one owner, so the lineage memo must answer
    /// repeat lookups (including failed walks) without re-walking `/proc`.
    #[test]
    fn lineage_memo_serves_repeat_lookups_without_rewalking() {
        let lookup = LinuxProcessLookup::with_socket_table(HashMap::new());
        let sentinel = ProcessLineage {
            ancestors: vec![ProcessAncestor {
                pid: 7,
                name: "sentinel".to_string(),
                executable: None,
                started_at_unix_ms: None,
            }],
            truncated: false,
        };
        lookup
            .lineages
            .write()
            .unwrap()
            .insert(own_pid(), Some(sentinel.clone()));

        // A live walk would resolve the real parent chain; getting the
        // sentinel back proves the memo was consulted instead.
        let parent_pid = u32::try_from(unsafe { libc::getppid() }).unwrap();
        assert_eq!(lookup.lineage_for(own_pid(), parent_pid), Some(sentinel));

        // Failed walks are memoized too, so a gone process is walked once.
        assert_eq!(lookup.lineage_for(u32::MAX, u32::MAX - 1), None);
        assert_eq!(lookup.lineages.read().unwrap().get(&u32::MAX), Some(&None));
    }

    #[test]
    fn resolves_the_live_parent_chain() {
        let parent_pid = u32::try_from(unsafe { libc::getppid() }).unwrap();
        let lineage = resolve_process_lineage(own_pid(), parent_pid)
            .expect("the test process parent must be readable");

        assert!(lineage.ancestors.len() <= crate::MAX_PROCESS_ANCESTORS);
        assert_eq!(lineage.ancestors.last().unwrap().pid, parent_pid);
        assert!(!lineage.ancestors.last().unwrap().name.is_empty());
        assert!(
            lineage
                .ancestors
                .last()
                .unwrap()
                .started_at_unix_ms
                .is_some()
        );
    }

    #[test]
    fn exact_socket_table_hit_is_reported_as_an_exact_procfs_match() {
        let mut table = HashMap::new();
        table.insert(
            key("192.168.1.10:5000", "1.1.1.1:443"),
            (own_pid(), "scanned-name".to_string()),
        );
        let lookup = LinuxProcessLookup::with_socket_table(table);

        let attribution = lookup
            .get_process_attribution(&tcp_connection("192.168.1.10:5000", "1.1.1.1:443"))
            .expect("exact tuple must match");

        assert_eq!(attribution.tgid, own_pid());
        assert_eq!(attribution.name, "scanned-name");
        assert_eq!(attribution.quality, MatchQuality::ProcfsExact);
        assert_eq!(attribution.executable, std::env::current_exe().ok());
        assert_eq!(
            attribution.ppid,
            Some(u32::try_from(unsafe { libc::getppid() }).unwrap())
        );
        assert_eq!(attribution.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(attribution.gid, Some(unsafe { libc::getegid() }));
        assert_eq!(
            attribution
                .lineage
                .as_ref()
                .and_then(|lineage| lineage.ancestors.last())
                .map(|ancestor| ancestor.pid),
            attribution.ppid
        );
    }

    #[test]
    fn wildcard_listener_hit_is_never_reported_as_exact() {
        let mut table = HashMap::new();
        table.insert(
            key("0.0.0.0:8080", "0.0.0.0:0"),
            (own_pid(), "listener".to_string()),
        );
        let lookup = LinuxProcessLookup::with_socket_table(table);

        let attribution = lookup
            .get_process_attribution(&tcp_connection("192.168.1.10:8080", "203.0.113.5:44321"))
            .expect("wildcard listener must match");

        assert_eq!(attribution.tgid, own_pid());
        assert_eq!(attribution.quality, MatchQuality::ProcfsRelaxed);
        assert!(!attribution.quality.is_exact());
    }

    #[test]
    fn conflicting_relaxed_candidates_produce_no_attribution() {
        let mut table = HashMap::new();
        table.insert(
            key("0.0.0.0:8080", "203.0.113.5:44321"),
            (own_pid(), "envoy".to_string()),
        );
        table.insert(
            key("0.0.0.0:8080", "0.0.0.0:0"),
            (own_pid() + 1, "nginx".to_string()),
        );
        let lookup = LinuxProcessLookup::with_socket_table(table);

        let conn = tcp_connection("192.168.1.10:8080", "203.0.113.5:44321");
        assert!(lookup.get_process_attribution(&conn).is_none());
    }

    /// End-to-end against the real `/proc/net/tcp` table rather than an
    /// injected one: open a listener, rescan, and confirm the attribution that
    /// comes back is fully populated. Needs no privileges, because the socket
    /// belongs to this process.
    #[test]
    fn attributes_a_real_listening_socket_from_procfs() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = listener.local_addr().unwrap();

        let lookup = LinuxProcessLookup::new().expect("procfs scan must succeed");
        // The listener was opened after the constructor's scan.
        lookup.refresh().expect("refresh must succeed");

        // /proc/net/tcp records a listener with a zeroed peer.
        let conn = Connection::new(
            Protocol::Tcp,
            local,
            "0.0.0.0:0".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Unknown),
        );

        let attribution = lookup
            .get_process_attribution(&conn)
            .expect("our own listening socket must be attributable");

        assert_eq!(attribution.tgid, own_pid());
        assert_eq!(attribution.quality, MatchQuality::ProcfsExact);
        assert_eq!(attribution.executable, std::env::current_exe().ok());
        assert_eq!(
            attribution.ppid,
            Some(u32::try_from(unsafe { libc::getppid() }).unwrap())
        );
        assert_eq!(attribution.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(attribution.gid, Some(unsafe { libc::getegid() }));
        assert!(!attribution.name.is_empty());
    }
}
