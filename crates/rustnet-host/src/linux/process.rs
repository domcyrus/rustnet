// network/platform/linux/process.rs - Linux procfs-based process lookup

use crate::{
    AttributionBackend, ConnectionKey, MatchQuality, ProcessAncestor, ProcessAttribution,
    ProcessLineage, ProcessLookup, collect_process_lineage, memoized, relaxed_lookup,
};
use anyhow::Result;
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::Instant;

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

/// Map of socket inode to (PID, process name)
type InodeProcessMap = HashMap<u64, (u32, String)>;
/// Map of PID to process name
type PidNameMap = HashMap<u32, String>;
/// Map of connection key to (PID, process name)
type ConnectionProcessMap = HashMap<ConnectionKey, (u32, String)>;

pub struct LinuxProcessLookup {
    // Cache: ConnectionKey -> (pid, process_name)
    cache: RwLock<ProcessCache>,
    // Cache: PID -> process_name (for resolving eBPF thread names to main process names)
    pid_names: RwLock<HashMap<u32, String>>,
    // Memo: TGID -> lineage, so many connections of one process walk /proc
    // once per refresh instead of once each. Failures are memoized too.
    lineages: RwLock<HashMap<u32, Option<ProcessLineage>>>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, (u32, String)>,
    last_refresh: Instant,
}

impl LinuxProcessLookup {
    pub fn new() -> Result<Self> {
        // Populate the cache immediately so early connections have process names available.
        // This ensures the PID→name cache is ready before packet capture starts.
        let (process_map, pid_names) = Self::build_process_map()?;

        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: process_map,
                last_refresh: Instant::now(),
            }),
            pid_names: RwLock::new(pid_names),
            lineages: RwLock::new(HashMap::new()),
        })
    }

    /// Build a lookup over a caller-supplied socket table instead of scanning
    /// `/proc/net/*`, so match-quality behaviour can be tested deterministically.
    #[cfg(test)]
    fn with_socket_table(lookup: ConnectionProcessMap) -> Self {
        Self {
            cache: RwLock::new(ProcessCache {
                lookup,
                last_refresh: Instant::now(),
            }),
            pid_names: RwLock::new(HashMap::new()),
            lineages: RwLock::new(HashMap::new()),
        }
    }

    /// Get process name by PID. Tries the cached procfs scan first, then
    /// falls back to reading `/proc/<pid>/comm` directly: the cache only
    /// refreshes every few seconds, so a freshly started process — exactly
    /// the case for short-lived tools like curl/dig — is often missing
    /// from it while still being perfectly readable from /proc. One tiny
    /// file read; the result is cached so repeated lookups stay cheap.
    /// Returns None if the process has already exited and was never scanned.
    pub fn get_process_name_by_pid(&self, pid: u32) -> Option<String> {
        if let Some(name) = self
            .pid_names
            .read()
            .expect("pid_names lock poisoned")
            .get(&pid)
            .cloned()
        {
            return Some(name);
        }

        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
        let comm = comm.trim();
        if comm.is_empty() {
            return None;
        }
        let name = comm.to_string();
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
    /// Simple cache lookup with no refresh on cache miss. The enrichment thread
    /// handles periodic refresh every 5 seconds.
    /// IMPORTANT: Do NOT refresh here as it caused high CPU usage when called for every
    /// connection without process info (flamegraph showed this was the main bottleneck).
    fn lookup_match(&self, conn: &Connection) -> Option<(u32, String, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("process cache lock poisoned");

        // Fast path: exact 4-tuple match (always works for TCP).
        if let Some((pid, name)) = cache.lookup.get(&key) {
            return Some((*pid, name.clone(), MatchQuality::ProcfsExact));
        }

        // Fallback: /proc/net may store sockets with wildcard addresses.
        // Progressively relax the key until we find a match. The relaxation
        // shape is deliberately collapsed into a single `ProcfsRelaxed`: what
        // matters downstream is that procfs needed to guess, not which of the
        // three wildcard shapes it guessed with.
        let ((pid, name), _shape) = relaxed_lookup(&cache.lookup, &key)?;
        Some((*pid, name.clone(), MatchQuality::ProcfsRelaxed))
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
            ProcessAttribution::new(tgid, name, AttributionBackend::Procfs, quality)
                .with_executable(executable);
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
    fn build_process_map() -> Result<(ConnectionProcessMap, PidNameMap)> {
        let mut process_map = HashMap::new();

        // First, build inode -> process mapping and PID -> name mapping
        let (inode_to_process, pid_names) = Self::build_inode_map()?;

        // Then, parse network files to map connections -> inodes -> processes
        Self::parse_and_map(
            "/proc/net/tcp",
            Protocol::Tcp,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/tcp6",
            Protocol::Tcp,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/udp",
            Protocol::Udp,
            &inode_to_process,
            &mut process_map,
        )?;
        Self::parse_and_map(
            "/proc/net/udp6",
            Protocol::Udp,
            &inode_to_process,
            &mut process_map,
        )?;

        Ok((process_map, pid_names))
    }

    /// Build inode -> (pid, process_name) mapping and PID -> process_name mapping
    fn build_inode_map() -> Result<(InodeProcessMap, PidNameMap)> {
        let mut inode_map = HashMap::new();
        let mut pid_names = HashMap::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let path = entry.path();

            if let Some(pid_str) = path.file_name().and_then(|s| s.to_str())
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                if pid == 0 {
                    continue;
                }

                // Get process name
                let comm_path = path.join("comm");
                let process_name = fs::read_to_string(&comm_path)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                // Store PID -> name mapping for all processes
                pid_names.insert(pid, process_name.clone());

                // Check file descriptors for socket inodes
                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(link) = fs::read_link(fd_entry.path())
                            && let Some(link_str) = link.to_str()
                            && let Some(inode) = Self::extract_socket_inode(link_str)
                        {
                            inode_map.insert(inode, (pid, process_name.clone()));
                        }
                    }
                }
            }
        }

        Ok((inode_map, pid_names))
    }

    /// Parse /proc/net file and map connections to processes
    fn parse_and_map(
        path: &str,
        protocol: Protocol,
        inode_map: &InodeProcessMap,
        result: &mut ConnectionProcessMap,
    ) -> Result<()> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return Ok(()), // File might not exist
        };

        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue; // Skip header
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            // Parse addresses
            let local_addr = match Self::parse_hex_address(parts[1]) {
                Some(addr) => addr,
                None => continue,
            };

            let remote_addr = match Self::parse_hex_address(parts[2]) {
                Some(addr) => addr,
                None => continue,
            };

            // Get inode
            if let Ok(inode) = parts[9].parse::<u64>()
                && let Some((pid, name)) = inode_map.get(&inode)
            {
                let key = ConnectionKey {
                    protocol,
                    local_addr,
                    remote_addr,
                };
                result.insert(key, (*pid, name.clone()));
            }
        }

        Ok(())
    }

    fn parse_hex_address(hex_addr: &str) -> Option<SocketAddr> {
        let parts: Vec<&str> = hex_addr.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip_hex = parts[0];
        let port = u16::from_str_radix(parts[1], 16).ok()?;

        if ip_hex.len() == 8 {
            // IPv4
            let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
            let ip = Ipv4Addr::from(ip_bytes.to_le_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        } else if ip_hex.len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let chunk = &ip_hex[i * 8..(i + 1) * 8];
                let value = u32::from_str_radix(chunk, 16).ok()?;
                bytes[i * 4..(i + 1) * 4].copy_from_slice(&value.to_le_bytes());
            }
            let ip = Ipv6Addr::from(bytes);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            None
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
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        // Deliberately not routed through `get_process_attribution`: the tuple
        // API has no use for the executable path or credentials, and resolving
        // them costs two syscalls per hit.
        self.lookup_match(conn).map(|(pid, name, _)| (pid, name))
    }

    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (tgid, name, quality) = self.lookup_match(conn)?;
        Some(self.build_attribution(tgid, name, quality))
    }

    fn refresh(&self) -> Result<()> {
        let (process_map, pid_names) = Self::build_process_map()?;

        let mut cache = self.cache.write().expect("process cache lock poisoned");
        cache.lookup = process_map;
        cache.last_refresh = Instant::now();

        *self.pid_names.write().expect("pid_names lock poisoned") = pid_names;
        self.lineages
            .write()
            .expect("lineages lock poisoned")
            .clear();

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "procfs"
    }

    fn get_attribution_backend(&self) -> AttributionBackend {
        AttributionBackend::Procfs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnet_core::network::types::{ProtocolState, TcpState};

    fn connection(local: &str, remote: &str) -> Connection {
        Connection::new(
            Protocol::Tcp,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    fn key(local: &str, remote: &str) -> ConnectionKey {
        ConnectionKey {
            protocol: Protocol::Tcp,
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
        }
    }

    /// Attribute to this very test process so the /proc reads have a live
    /// target with known credentials and a known executable.
    fn own_pid() -> u32 {
        std::process::id()
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
            .get_process_attribution(&connection("192.168.1.10:5000", "1.1.1.1:443"))
            .expect("exact tuple must match");

        assert_eq!(attribution.tgid, own_pid());
        assert_eq!(attribution.name, "scanned-name");
        assert_eq!(attribution.quality, MatchQuality::ProcfsExact);
        assert_eq!(attribution.backend, AttributionBackend::Procfs);
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
            .get_process_attribution(&connection("192.168.1.10:8080", "203.0.113.5:44321"))
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

        let conn = connection("192.168.1.10:8080", "203.0.113.5:44321");
        assert!(lookup.get_process_attribution(&conn).is_none());
        assert!(lookup.get_process_for_connection(&conn).is_none());
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
        assert_eq!(attribution.backend, AttributionBackend::Procfs);
        assert_eq!(attribution.executable, std::env::current_exe().ok());
        assert_eq!(
            attribution.ppid,
            Some(u32::try_from(unsafe { libc::getppid() }).unwrap())
        );
        assert_eq!(attribution.uid, Some(unsafe { libc::geteuid() }));
        assert_eq!(attribution.gid, Some(unsafe { libc::getegid() }));
        assert!(!attribution.name.is_empty());
    }

    #[test]
    fn the_tuple_api_agrees_with_the_rich_api() {
        let mut table = HashMap::new();
        table.insert(
            key("192.168.1.10:5000", "1.1.1.1:443"),
            (own_pid(), "scanned-name".to_string()),
        );
        table.insert(
            key("0.0.0.0:8080", "0.0.0.0:0"),
            (own_pid(), "listener".to_string()),
        );
        let lookup = LinuxProcessLookup::with_socket_table(table);

        for (local, remote) in [
            ("192.168.1.10:5000", "1.1.1.1:443"),
            ("192.168.1.10:8080", "203.0.113.5:44321"),
        ] {
            let conn = connection(local, remote);
            let tuple = lookup
                .get_process_for_connection(&conn)
                .expect("tuple API must keep working");
            let attribution = lookup.get_process_attribution(&conn).unwrap();

            assert_eq!(tuple, (attribution.tgid, attribution.name));
        }
    }
}
