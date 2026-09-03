//! FreeBSD sockstat-based process lookup.

use crate::{
    ConnectionKey, HostSocket, HostSocketState, HostTcpState, MatchQuality, ProcessAncestor,
    ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner, SocketScan, SocketSnapshot,
    ancestor_display_name, collect_process_lineage,
    command::{PROCESS_TABLE_COMMAND_TIMEOUT, output_with_timeout_or_cancel},
    decode_process_name, memoized, owner_match, parse_socket_addr_text, path_from_c_buffer,
    remote_if_present,
};
use anyhow::{Context, Result};
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::mem::{MaybeUninit, size_of};
use std::path::PathBuf;
use std::ptr;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, Ordering};

const SOCKSTAT_PATH: &str = "/usr/bin/sockstat";

pub(super) struct FreeBSDProcessLookup {
    // Cache: ConnectionKey -> socket owner
    cache: RwLock<HashMap<ConnectionKey, SocketOwner>>,
    // A process may own many sockets. Resolve its metadata through sysctl once
    // per refresh generation rather than once per connection.
    process_details: RwLock<HashMap<u32, Option<FreeBsdProcessDetails>>>,
    socket_snapshot: RwLock<SocketSnapshot>,
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
        let scan = Self::build_process_map(None)?;
        Ok(Self {
            cache: RwLock::new(scan.lookup),
            process_details: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::new(scan.sockets)),
        })
    }

    fn lookup_match(&self, conn: &Connection) -> Option<(SocketOwner, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("process cache lock poisoned");
        owner_match(&cache, &key)
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

        path_from_c_buffer(&buffer, buffer_len)
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

    /// Build connection -> process mapping using sockstat. The TCP, TCP6,
    /// UDP and UDP6 tables are scanned in that order, so a later table wins
    /// when two report the same tuple.
    fn build_process_map(cancelled: Option<&AtomicBool>) -> Result<SocketScan> {
        let mut scan = SocketScan::default();

        for (protocol, ipv6) in [
            (Protocol::Tcp, false),
            (Protocol::Tcp, true),
            (Protocol::Udp, false),
            (Protocol::Udp, true),
        ] {
            match Self::parse_sockstat_output(protocol, ipv6, cancelled) {
                Ok(table) => {
                    scan.lookup.extend(table.lookup);
                    scan.sockets.extend(table.sockets);
                }
                Err(error) if command_was_interrupted(&error) => return Err(error),
                Err(error) => {
                    log::debug!("sockstat table scan failed for {protocol:?}: {error}");
                }
            }
        }

        if cancellation_requested(cancelled) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "sockstat scan cancelled",
            )
            .into());
        }

        Ok(scan)
    }

    /// Parse sockstat output for a given protocol and address family.
    fn parse_sockstat_output(
        protocol: Protocol,
        ipv6: bool,
        cancelled: Option<&AtomicBool>,
    ) -> Result<SocketScan> {
        use std::process::Command;

        let is_tcp = protocol == Protocol::Tcp;

        // -4/-6: address family, -n: numeric UIDs, -s: TCP state column,
        // -P: protocol filter
        let output = output_with_timeout_or_cancel(
            Command::new(SOCKSTAT_PATH)
                .arg(if ipv6 { "-6" } else { "-4" })
                .arg("-n")
                .args(is_tcp.then_some("-s"))
                .arg("-P")
                .arg(if is_tcp { "tcp" } else { "udp" }),
            PROCESS_TABLE_COMMAND_TIMEOUT,
            cancelled,
        )
        .context("Failed to execute sockstat")?;

        if !output.status.success() {
            return Ok(SocketScan::default());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_sockstat_rows(&stdout, protocol))
    }

    fn parse_sockstat_rows(stdout: &str, protocol: Protocol) -> SocketScan {
        let mut result = HashMap::new();
        let mut sockets = Vec::new();

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();

            // Expected format:
            // USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
            // 1001     sshd       1234  3  tcp4   192.168.1.1:22        192.168.1.2:54321

            if parts.len() < 7 {
                continue;
            }

            let uid = parts[0].parse::<u32>().ok();
            let process_name = parts[1].to_string();
            let pid = parts[2].parse::<u32>().ok();

            let local_addr = match parse_socket_addr_text(parts[5]) {
                Some(addr) => addr,
                None => continue,
            };

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
                result.insert(key, owner.clone());
            }

            let state = match protocol {
                Protocol::Tcp => HostSocketState::Tcp(parts.get(7).map_or_else(
                    || infer_tcp_state(foreign_addr),
                    |value| HostTcpState::parse_name(value),
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

        SocketScan {
            lookup: result,
            sockets,
        }
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
        attribution.uid = process.uid;
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
        self.refresh_cache(None)
    }

    fn refresh_interruptible(&self, cancelled: &AtomicBool) -> Result<()> {
        self.refresh_cache(Some(cancelled))
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

impl FreeBSDProcessLookup {
    fn refresh_cache(&self, cancelled: Option<&AtomicBool>) -> Result<()> {
        let scan = Self::build_process_map(cancelled)?;

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
}

fn cancellation_requested(cancelled: Option<&AtomicBool>) -> bool {
    cancelled.is_some_and(|flag| flag.load(Ordering::Acquire))
}

fn command_was_interrupted(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tcp_connection;

    #[test]
    fn cancelled_sockstat_scan_returns_an_error() {
        let cancelled = AtomicBool::new(true);

        let error = match FreeBSDProcessLookup::build_process_map(Some(&cancelled)) {
            Ok(_) => panic!("cancelled scan must not replace the process cache"),
            Err(error) => error,
        };

        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::Interrupted)
        );
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
