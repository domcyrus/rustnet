// network/platform/freebsd/process.rs - FreeBSD sockstat-based process lookup

use crate::{
    AttributionBackend, ConnectionKey, MatchQuality, ProcessAncestor, ProcessAttribution,
    ProcessLineage, ProcessLookup, ancestor_display_name, collect_process_lineage,
    decode_process_name, memoized, parse_socket_addr_text, relaxed_lookup,
};
use anyhow::{Context, Result};
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::{MaybeUninit, size_of};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const SOCKSTAT_PATH: &str = "/usr/bin/sockstat";

pub struct FreeBSDProcessLookup {
    // Cache: ConnectionKey -> socket owner
    cache: RwLock<ProcessCache>,
    // A process may own many sockets. Resolve its metadata through sysctl once
    // per refresh generation rather than once per connection.
    process_details: RwLock<HashMap<u32, Option<FreeBsdProcessDetails>>>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, FreeBsdProcessInfo>,
    last_refresh: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FreeBsdProcessInfo {
    pid: u32,
    name: String,
    uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FreeBsdProcessDetails {
    ppid: u32,
    uid: u32,
    gid: u32,
    name: String,
    executable: Option<PathBuf>,
    started_at_unix_ms: Option<u64>,
}

impl FreeBSDProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: Instant::now() - Duration::from_secs(3600),
            }),
            process_details: RwLock::new(HashMap::new()),
        })
    }

    fn lookup_match(&self, conn: &Connection) -> Option<(FreeBsdProcessInfo, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("process cache lock poisoned");

        if let Some(process) = cache.lookup.get(&key) {
            return Some((process.clone(), MatchQuality::ExactTuple));
        }

        relaxed_lookup(&cache.lookup, &key).map(|(process, quality)| (process.clone(), quality))
    }

    fn resolve_executable(pid: libc::pid_t) -> Option<PathBuf> {
        let mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PATHNAME,
            pid,
        ];
        let mut buffer = vec![0_u8; usize::try_from(libc::PATH_MAX).ok()?];
        let mut buffer_len = buffer.len();

        // SAFETY: `mib` and `buffer` are valid for their supplied lengths,
        // `sysctl` only writes to `buffer`, and all other pointers are null.
        let result = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                u32::try_from(mib.len()).expect("FreeBSD sysctl MIB length fits in u32"),
                buffer.as_mut_ptr().cast(),
                &mut buffer_len,
                ptr::null(),
                0,
            )
        };
        if result != 0 {
            return None;
        }

        let returned = buffer_len.min(buffer.len());
        let path_len = buffer[..returned]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(returned);
        if path_len == 0 {
            return None;
        }
        Some(PathBuf::from(OsStr::from_bytes(&buffer[..path_len])))
    }

    fn read_process_details(pid: u32) -> Option<FreeBsdProcessDetails> {
        let pid = libc::pid_t::try_from(pid).ok()?;
        let mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
        let mut info = MaybeUninit::<libc::kinfo_proc>::zeroed();
        let expected_len = size_of::<libc::kinfo_proc>();
        let mut info_len = expected_len;

        // SAFETY: `info` is an aligned, writable `kinfo_proc` buffer.
        // It is initialized only when `sysctl` succeeds with the exact
        // structure length and the kernel confirms the embedded layout size.
        let result = unsafe {
            libc::sysctl(
                mib.as_ptr(),
                u32::try_from(mib.len()).expect("FreeBSD sysctl MIB length fits in u32"),
                info.as_mut_ptr().cast(),
                &mut info_len,
                ptr::null(),
                0,
            )
        };
        if result != 0 || info_len != expected_len {
            return None;
        }

        // SAFETY: the successful exact-size sysctl call initialized `info`.
        let info = unsafe { info.assume_init() };
        if info.ki_structsize != libc::c_int::try_from(expected_len).ok()? || info.ki_pid != pid {
            return None;
        }

        // The kernel exports the effective GID as `ki_groups[0]`
        // (`fill_kinfo_proc` copies `cr_gid` there first), a convention kept
        // even after the FreeBSD 15 ucred rework moved the effective GID out
        // of `cr_groups`. Fall back to the real GID only for the structurally
        // unusual case where the kernel reports no groups.
        let gid = if info.ki_ngroups > 0 {
            info.ki_groups[0]
        } else {
            info.ki_rgid
        };

        Some(FreeBsdProcessDetails {
            ppid: u32::try_from(info.ki_ppid).ok()?,
            uid: info.ki_uid,
            gid,
            name: decode_process_name(&info.ki_comm).unwrap_or_default(),
            executable: Self::resolve_executable(pid),
            started_at_unix_ms: Self::timeval_unix_ms(&info.ki_start),
        })
    }

    fn timeval_unix_ms(time: &libc::timeval) -> Option<u64> {
        let seconds = u64::try_from(time.tv_sec).ok()?;
        let micros = u64::try_from(time.tv_usec).ok()?;
        seconds.checked_mul(1_000)?.checked_add(micros / 1_000)
    }

    fn process_details(&self, pid: u32) -> Option<FreeBsdProcessDetails> {
        memoized(
            &self.process_details,
            pid,
            "process details cache lock poisoned",
            || Self::read_process_details(pid),
        )
    }

    fn process_lineage(&self, pid: u32, ppid: u32) -> Option<ProcessLineage> {
        collect_process_lineage(pid, ppid, |ancestor_pid| {
            let details = self.process_details(ancestor_pid)?;
            let parent_pid = details.ppid;
            let name =
                ancestor_display_name(details.name, details.executable.as_deref(), ancestor_pid);
            Some((
                ProcessAncestor {
                    pid: ancestor_pid,
                    name,
                    executable: details.executable,
                    started_at_unix_ms: details.started_at_unix_ms,
                },
                parent_pid,
            ))
        })
    }

    /// Build connection -> process mapping using sysctl
    fn build_process_map() -> Result<HashMap<ConnectionKey, FreeBsdProcessInfo>> {
        let mut process_map = HashMap::new();

        // Parse TCP connections
        if let Ok(tcp_connections) = Self::parse_sockstat_output("tcp") {
            process_map.extend(tcp_connections);
        }

        // Parse TCP6 connections
        if let Ok(tcp6_connections) = Self::parse_sockstat_output("tcp6") {
            process_map.extend(tcp6_connections);
        }

        // Parse UDP connections
        if let Ok(udp_connections) = Self::parse_sockstat_output("udp") {
            process_map.extend(udp_connections);
        }

        // Parse UDP6 connections
        if let Ok(udp6_connections) = Self::parse_sockstat_output("udp6") {
            process_map.extend(udp6_connections);
        }

        Ok(process_map)
    }

    /// Parse sockstat output for a given protocol
    /// Format: user command pid fd proto local_addr foreign_addr
    fn parse_sockstat_output(proto: &str) -> Result<HashMap<ConnectionKey, FreeBsdProcessInfo>> {
        use std::process::Command;

        // Determine protocol type
        let protocol = if proto.starts_with("tcp") {
            Protocol::Tcp
        } else {
            Protocol::Udp
        };

        // Run sockstat command
        // -4: IPv4, -6: IPv6, -c: connected sockets, -l: listening sockets, -n: numeric
        let ipv6_flag = proto.ends_with('6');

        let output = Command::new(SOCKSTAT_PATH)
            .arg(if ipv6_flag { "-6" } else { "-4" })
            .arg("-n") // numeric UIDs
            .arg("-P")
            .arg(if proto.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            })
            .output()
            .context("Failed to execute sockstat")?;

        if !output.status.success() {
            return Ok(HashMap::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_sockstat_rows(&stdout, protocol))
    }

    fn parse_sockstat_rows(
        stdout: &str,
        protocol: Protocol,
    ) -> HashMap<ConnectionKey, FreeBsdProcessInfo> {
        let mut result = HashMap::new();

        for line in stdout.lines().skip(1) {
            // Skip header
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Expected format:
            // USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
            // 1001     sshd       1234  3  tcp4   192.168.1.1:22        192.168.1.2:54321

            if parts.len() < 7 {
                continue;
            }

            // Extract fields
            let uid = match parts[0].parse::<u32>() {
                Ok(uid) => uid,
                Err(_) => continue,
            };
            let process_name = parts[1].to_string();
            let pid = match parts[2].parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Parse local address (index 5)
            let local_addr = match parse_socket_addr_text(parts[5]) {
                Some(addr) => addr,
                None => continue,
            };

            // Parse foreign address (index 6)
            let foreign_addr = match parse_socket_addr_text(parts[6]) {
                Some(addr) => addr,
                None => continue,
            };

            let key = ConnectionKey {
                protocol,
                local_addr,
                remote_addr: foreign_addr,
            };

            result.insert(
                key,
                FreeBsdProcessInfo {
                    pid,
                    name: process_name,
                    uid,
                },
            );
        }

        result
    }
}

impl ProcessLookup for FreeBSDProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        self.lookup_match(conn)
            .map(|(process, _quality)| (process.pid, process.name))
    }

    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (process, quality) = self.lookup_match(conn)?;
        let mut attribution = ProcessAttribution::new(
            process.pid,
            process.name,
            AttributionBackend::PlatformNative,
            quality,
        );
        attribution.uid = Some(process.uid);
        if let Some(details) = self.process_details(process.pid) {
            let lineage = self.process_lineage(process.pid, details.ppid);
            attribution = attribution.with_details(
                details.ppid,
                Some((details.uid, details.gid)),
                details.executable,
                lineage,
            );
        }
        Some(attribution)
    }

    fn refresh(&self) -> Result<()> {
        let process_map = Self::build_process_map()?;

        let mut cache = self.cache.write().expect("cache lock poisoned");
        cache.lookup = process_map;
        cache.last_refresh = Instant::now();
        self.process_details
            .write()
            .expect("process details cache lock poisoned")
            .clear();

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "sockstat"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnet_core::network::types::{ProtocolState, TcpState};

    fn tcp_connection(local: &str, remote: &str) -> Connection {
        Connection::new(
            Protocol::Tcp,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn sockstat_numeric_uid_reaches_attribution_without_process_details() {
        let output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
1001 curl 4294967295 3 tcp4 127.0.0.1:5000 1.1.1.1:443
";
        let lookup = FreeBSDProcessLookup {
            cache: RwLock::new(ProcessCache {
                lookup: FreeBSDProcessLookup::parse_sockstat_rows(output, Protocol::Tcp),
                last_refresh: Instant::now(),
            }),
            process_details: RwLock::new(HashMap::new()),
        };
        let conn = tcp_connection("127.0.0.1:5000", "1.1.1.1:443");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.tgid, u32::MAX);
        assert_eq!(attribution.name, "curl");
        assert_eq!(attribution.uid, Some(1001));
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
        assert_eq!(
            lookup.get_process_for_connection(&conn),
            Some((u32::MAX, "curl".to_string()))
        );
    }

    #[test]
    fn sockstat_parser_requires_numeric_uid_enabled_by_dash_n() {
        let output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
root server 42 3 tcp4 127.0.0.1:8080 0.0.0.0:0
";

        assert!(FreeBSDProcessLookup::parse_sockstat_rows(output, Protocol::Tcp).is_empty());
    }

    #[test]
    fn test_current_process_details() {
        let details = FreeBSDProcessLookup::read_process_details(std::process::id())
            .expect("current process details must resolve");

        assert_eq!(
            details.ppid,
            u32::try_from(unsafe { libc::getppid() }).unwrap()
        );
        assert_eq!(details.uid, unsafe { libc::geteuid() });
        assert_eq!(details.gid, unsafe { libc::getegid() });
        assert_eq!(details.executable, std::env::current_exe().ok());
        assert!(!details.name.is_empty());
        assert!(details.started_at_unix_ms.is_some());

        let lookup = FreeBSDProcessLookup::new().unwrap();
        let lineage = lookup
            .process_lineage(std::process::id(), details.ppid)
            .expect("current process parent must resolve");
        assert_eq!(lineage.ancestors.last().unwrap().pid, details.ppid);
    }

    #[test]
    fn test_missing_process_has_no_details() {
        assert!(FreeBSDProcessLookup::read_process_details(u32::MAX).is_none());
    }
}
