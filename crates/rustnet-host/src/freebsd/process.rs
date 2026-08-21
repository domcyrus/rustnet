// network/platform/freebsd/process.rs - FreeBSD sockstat-based process lookup

use crate::{
    ConnectionKey, HostSocket, HostSocketState, HostTcpState, MatchQuality, ProcessAncestor,
    ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner, SocketSnapshot,
    ancestor_display_name, collect_process_lineage, decode_process_name, memoized,
    parse_socket_addr_text, relaxed_lookup, remote_if_present,
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

const SOCKSTAT_PATH: &str = "/usr/bin/sockstat";

pub(super) struct FreeBSDProcessLookup {
    // Cache: ConnectionKey -> socket owner
    cache: RwLock<HashMap<ConnectionKey, FreeBsdProcessInfo>>,
    // A process may own many sockets. Resolve its metadata through sysctl once
    // per refresh generation rather than once per connection.
    process_details: RwLock<HashMap<u32, Option<FreeBsdProcessDetails>>>,
    socket_snapshot: RwLock<SocketSnapshot>,
}

struct FreeBsdSocketScan {
    lookup: HashMap<ConnectionKey, FreeBsdProcessInfo>,
    sockets: Vec<HostSocket>,
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
    pub(super) fn new() -> Result<Self> {
        let scan = Self::build_process_map()?;
        Ok(Self {
            cache: RwLock::new(scan.lookup),
            process_details: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::new(scan.sockets)),
        })
    }

    fn lookup_match(&self, conn: &Connection) -> Option<(FreeBsdProcessInfo, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("process cache lock poisoned");

        if let Some(process) = cache.get(&key) {
            return Some((process.clone(), MatchQuality::ExactTuple));
        }

        relaxed_lookup(&cache, &key).map(|(process, quality)| (process.clone(), quality))
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
    fn build_process_map() -> Result<FreeBsdSocketScan> {
        let mut process_map = HashMap::new();
        let mut sockets = Vec::new();

        // Parse TCP connections
        if let Ok(tcp_connections) = Self::parse_sockstat_output("tcp") {
            process_map.extend(tcp_connections.lookup);
            sockets.extend(tcp_connections.sockets);
        }

        // Parse TCP6 connections
        if let Ok(tcp6_connections) = Self::parse_sockstat_output("tcp6") {
            process_map.extend(tcp6_connections.lookup);
            sockets.extend(tcp6_connections.sockets);
        }

        // Parse UDP connections
        if let Ok(udp_connections) = Self::parse_sockstat_output("udp") {
            process_map.extend(udp_connections.lookup);
            sockets.extend(udp_connections.sockets);
        }

        // Parse UDP6 connections
        if let Ok(udp6_connections) = Self::parse_sockstat_output("udp6") {
            process_map.extend(udp6_connections.lookup);
            sockets.extend(udp6_connections.sockets);
        }

        Ok(FreeBsdSocketScan {
            lookup: process_map,
            sockets,
        })
    }

    /// Parse sockstat output for a given protocol
    /// Format: user command pid fd proto local_addr foreign_addr
    fn parse_sockstat_output(proto: &str) -> Result<FreeBsdSocketScan> {
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
            .args(proto.starts_with("tcp").then_some("-s"))
            .arg("-P")
            .arg(if proto.starts_with("tcp") {
                "tcp"
            } else {
                "udp"
            })
            .output()
            .context("Failed to execute sockstat")?;

        if !output.status.success() {
            return Ok(FreeBsdSocketScan {
                lookup: HashMap::new(),
                sockets: Vec::new(),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_sockstat_rows(&stdout, protocol))
    }

    fn parse_sockstat_rows(stdout: &str, protocol: Protocol) -> FreeBsdSocketScan {
        let mut result = HashMap::new();
        let mut sockets = Vec::new();

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
            let uid = parts[0].parse::<u32>().ok();
            let process_name = parts[1].to_string();
            let pid = parts[2].parse::<u32>().ok();

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
            if protocol == Protocol::Udp && local_addr.port() == 0 {
                continue;
            }

            let key = ConnectionKey {
                protocol,
                local_addr,
                remote_addr: foreign_addr,
            };

            let owner = pid.zip(uid).map(|(pid, uid)| SocketOwner {
                pid,
                name: process_name.clone(),
                uid: Some(uid),
            });
            if let Some(owner) = &owner {
                result.insert(
                    key,
                    FreeBsdProcessInfo {
                        pid: owner.pid,
                        name: owner.name.clone(),
                        uid: owner.uid.expect("FreeBSD socket owner has a numeric UID"),
                    },
                );
            }

            let state = match protocol {
                Protocol::Tcp => HostSocketState::Tcp(parts.get(7).map_or_else(
                    || infer_tcp_state(foreign_addr),
                    |value| parse_tcp_state(value),
                )),
                Protocol::Udp => HostSocketState::UdpBound,
                _ => continue,
            };
            sockets.push(HostSocket {
                protocol,
                local_addr,
                remote_addr: remote_if_present(foreign_addr),
                state,
                owner,
                native_id: None,
            });
        }

        FreeBsdSocketScan {
            lookup: result,
            sockets,
        }
    }
}

fn parse_tcp_state(value: &str) -> HostTcpState {
    match value.to_ascii_uppercase().as_str() {
        "CLOSED" => HostTcpState::Closed,
        "LISTEN" => HostTcpState::Listen,
        "SYN_SENT" => HostTcpState::SynSent,
        "SYN_RECEIVED" | "SYN_RCVD" => HostTcpState::SynReceived,
        "ESTABLISHED" => HostTcpState::Established,
        "FIN_WAIT_1" => HostTcpState::FinWait1,
        "FIN_WAIT_2" => HostTcpState::FinWait2,
        "CLOSE_WAIT" => HostTcpState::CloseWait,
        "CLOSING" => HostTcpState::Closing,
        "LAST_ACK" => HostTcpState::LastAck,
        "TIME_WAIT" => HostTcpState::TimeWait,
        _ => HostTcpState::Unknown,
    }
}

fn infer_tcp_state(remote_addr: std::net::SocketAddr) -> HostTcpState {
    if remote_addr.port() == 0 && remote_addr.ip().is_unspecified() {
        HostTcpState::Listen
    } else {
        HostTcpState::Unknown
    }
}

impl ProcessLookup for FreeBSDProcessLookup {
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (process, quality) = self.lookup_match(conn)?;
        let mut attribution = ProcessAttribution::new(process.pid, process.name, quality);
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
        let scan = Self::build_process_map()?;

        *self.cache.write().expect("cache lock poisoned") = scan.lookup;
        *self
            .socket_snapshot
            .write()
            .expect("socket snapshot lock poisoned") = SocketSnapshot::new(scan.sockets);
        self.process_details
            .write()
            .expect("process details cache lock poisoned")
            .clear();

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "sockstat"
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
            cache: RwLock::new(
                FreeBSDProcessLookup::parse_sockstat_rows(output, Protocol::Tcp).lookup,
            ),
            process_details: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        };
        let conn = tcp_connection("127.0.0.1:5000", "1.1.1.1:443");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.tgid, u32::MAX);
        assert_eq!(attribution.name, "curl");
        assert_eq!(attribution.uid, Some(1001));
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
    }

    #[test]
    fn sockstat_parser_requires_numeric_uid_enabled_by_dash_n() {
        let output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
root server 42 3 tcp4 127.0.0.1:8080 0.0.0.0:0
";

        assert!(
            FreeBSDProcessLookup::parse_sockstat_rows(output, Protocol::Tcp)
                .lookup
                .is_empty()
        );
    }

    #[test]
    fn sockstat_parser_reports_tcp_listeners_and_udp_binds() {
        // sockstat prints a wildcard peer as `*:*`, never `0.0.0.0:0`.
        let tcp_output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS STATE
1001 server 42 3 tcp4 *:8080 *:* LISTEN
";
        let udp_output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
1001 resolver 43 4 udp4 127.0.0.1:5353 *:*
";

        let tcp = FreeBSDProcessLookup::parse_sockstat_rows(tcp_output, Protocol::Tcp);
        let udp = FreeBSDProcessLookup::parse_sockstat_rows(udp_output, Protocol::Udp);

        assert_eq!(tcp.sockets.len(), 1);
        assert_eq!(
            tcp.sockets[0].state,
            HostSocketState::Tcp(HostTcpState::Listen)
        );
        assert_eq!(tcp.sockets[0].local_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(tcp.sockets[0].remote_addr, None);
        assert_eq!(udp.sockets.len(), 1);
        assert_eq!(udp.sockets[0].state, HostSocketState::UdpBound);
        assert_eq!(udp.sockets[0].remote_addr, None);
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
