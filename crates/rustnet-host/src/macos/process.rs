//! macOS lsof-based process lookup.

use crate::{
    ConnectionKey, DegradationReason, HostSocket, MatchQuality, ProcessAncestor,
    ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner, SocketScan, SocketSnapshot,
    ancestor_display_name, collect_process_lineage,
    command::{PROCESS_TABLE_COMMAND_TIMEOUT, output_with_timeout_or_cancel},
    decode_process_name, owner_match, path_from_c_buffer,
};
use anyhow::Result;
use log::{debug, error, info, warn};
use rustnet_core::network::types::Connection;
use std::collections::HashMap;
use std::mem::{MaybeUninit, size_of};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

const LSOF_PATH: &str = "/usr/sbin/lsof";

pub(super) struct MacOSProcessLookup {
    cache: RwLock<HashMap<ConnectionKey, SocketOwner>>,
    socket_snapshot: RwLock<SocketSnapshot>,
}

pub(super) struct ProcessDetails {
    pub(super) ppid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
    name: String,
    started_at_unix_ms: Option<u64>,
}

pub(super) fn resolve_executable(pid: u32) -> Option<PathBuf> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let mut buffer = [0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];

    // SAFETY: libproc receives a valid writable buffer and its exact size.
    let length = unsafe {
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).expect("path buffer fits in u32"),
        )
    };
    if length <= 0 {
        return None;
    }

    path_from_c_buffer(&buffer, usize::try_from(length).ok()?)
}

pub(super) fn resolve_process_details(pid: u32) -> Option<ProcessDetails> {
    let pid = libc::c_int::try_from(pid).ok()?;
    resolve_full_process_details(pid).or_else(|| resolve_short_process_details(pid))
}

/// Fill `flavor`-shaped process info for `pid` via `proc_pidinfo`.
fn query_proc_pidinfo<T>(pid: libc::c_int, flavor: libc::c_int) -> Option<T> {
    let expected_size = size_of::<T>();
    let mut info = MaybeUninit::<T>::zeroed();

    // SAFETY: libproc writes at most `expected_size` bytes into an aligned
    // buffer with the C layout of the requested flavor.
    let returned_size = unsafe {
        libc::proc_pidinfo(
            pid,
            flavor,
            0,
            info.as_mut_ptr().cast(),
            libc::c_int::try_from(expected_size).expect("proc info size fits in c_int"),
        )
    };
    if returned_size != libc::c_int::try_from(expected_size).ok()? {
        return None;
    }

    // SAFETY: a full `T` was initialized by the successful call.
    Some(unsafe { info.assume_init() })
}

fn resolve_full_process_details(pid: libc::c_int) -> Option<ProcessDetails> {
    let info: libc::proc_bsdinfo = query_proc_pidinfo(pid, libc::PROC_PIDTBSDINFO)?;
    let name = decode_process_name(&info.pbi_name)
        .or_else(|| decode_process_name(&info.pbi_comm))
        .unwrap_or_default();
    Some(ProcessDetails {
        ppid: info.pbi_ppid,
        uid: info.pbi_uid,
        gid: info.pbi_gid,
        name,
        started_at_unix_ms: info
            .pbi_start_tvsec
            .checked_mul(1_000)
            .and_then(|millis| millis.checked_add(info.pbi_start_tvusec / 1_000)),
    })
}

/// Fallback for processes the kernel's same-user policy hides from
/// `PROC_PIDTBSDINFO`: the short flavor is exempt from that check, so an
/// unprivileged run still resolves the PPID and credentials of other users'
/// processes. It carries no start time and only a 16-character name.
fn resolve_short_process_details(pid: libc::c_int) -> Option<ProcessDetails> {
    let info: libc::proc_bsdshortinfo = query_proc_pidinfo(pid, libc::PROC_PIDT_SHORTBSDINFO)?;
    Some(ProcessDetails {
        ppid: info.pbsi_ppid,
        uid: info.pbsi_uid,
        gid: info.pbsi_gid,
        name: decode_process_name(&info.pbsi_comm).unwrap_or_default(),
        started_at_unix_ms: None,
    })
}

pub(super) fn resolve_process_lineage(pid: u32, ppid: u32) -> Option<ProcessLineage> {
    collect_process_lineage(pid, ppid, |ancestor_pid| {
        let details = resolve_process_details(ancestor_pid)?;
        let executable = resolve_executable(ancestor_pid);
        let name = ancestor_display_name(details.name, executable.as_deref(), ancestor_pid);
        Some((
            ProcessAncestor {
                pid: ancestor_pid,
                name,
                executable,
                started_at_unix_ms: details.started_at_unix_ms,
            },
            details.ppid,
        ))
    })
}

impl MacOSProcessLookup {
    pub(super) fn new() -> Result<Self> {
        // Populate eagerly so early connections and the first Host snapshot
        // have data, but tolerate a failed lsof spawn: constructor failure
        // would abort the whole enrichment thread (including the mid-run
        // PKTAP switch), while an empty scan is retried by the periodic
        // refresh a few seconds later.
        let started = SystemTime::now();
        let scan = Self::parse_lsof(None).unwrap_or_else(|e| {
            warn!("Initial lsof scan failed, deferring to periodic refresh: {e}");
            SocketScan::default()
        });
        Ok(Self {
            cache: RwLock::new(scan.lookup),
            socket_snapshot: RwLock::new(snapshot_from_scan(
                scan.sockets,
                scan.diagnostics,
                scan.complete,
                started,
            )),
        })
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        }
    }

    fn parse_lsof(cancelled: Option<&AtomicBool>) -> Result<SocketScan> {
        info!("Running lsof to get network connections");

        let output = output_with_timeout_or_cancel(
            Command::new(LSOF_PATH)
                .args(["-i", "-n", "-P", "-l", "-Tqs", "+c", "0"])
                .env("LC_ALL", "C"),
            PROCESS_TABLE_COMMAND_TIMEOUT,
            cancelled,
        )?;

        Self::parse_lsof_result(&output)
    }

    fn parse_lsof_result(output: &std::process::Output) -> Result<SocketScan> {
        // With one unrestricted Internet selector, exit 1 and no output
        // means no matching sockets. Actual diagnostics remain failures.
        if output.status.code() == Some(1) && output.stdout.is_empty() && output.stderr.is_empty() {
            return Ok(SocketScan {
                complete: true,
                ..Default::default()
            });
        }
        if !output.status.success() {
            error!("lsof command failed with status: {}", output.status);
            error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            anyhow::bail!("lsof command failed: {}", output.status);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut scan = crate::lsof::parse_output(&stdout);
        // Warnings can mean hidden processes or sockets, even on exit zero.
        scan.complete &= output.stderr.is_empty();
        Ok(scan)
    }

    fn lookup_match(&self, conn: &Connection) -> Option<(SocketOwner, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("cache lock poisoned");

        let matched = owner_match(&cache, &key);
        match &matched {
            Some((owner, MatchQuality::ExactTuple)) => {
                debug!("Found process info for connection {:?}: {:?}", key, owner);
            }
            _ => {
                debug!("No process info found for connection {:?}", key);
                debug!("Available keys in cache:");
                for (cached_key, process) in cache.iter().take(10) {
                    debug!("  {:?} -> {} ({})", cached_key, process.name, process.pid);
                }
                if cache.len() > 10 {
                    debug!("  ... and {} more entries", cache.len() - 10);
                }
            }
        }
        matched
    }

    fn refresh_cache(&self, cancelled: Option<&AtomicBool>) -> Result<()> {
        info!("Refreshing macOS process lookup cache");
        let started = SystemTime::now();
        let scan = Self::parse_lsof(cancelled)?;
        let cache_size = scan.lookup.len();
        *self.cache.write().expect("cache lock poisoned") = scan.lookup;
        *self
            .socket_snapshot
            .write()
            .expect("socket snapshot lock poisoned") =
            snapshot_from_scan(scan.sockets, scan.diagnostics, scan.complete, started);
        info!("Process lookup cache refreshed with {} entries", cache_size);
        Ok(())
    }
}

impl ProcessLookup for MacOSProcessLookup {
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (process, quality) = self.lookup_match(conn)?;
        let mut attribution = ProcessAttribution::new(process.pid, process.name, quality)
            .with_executable(resolve_executable(process.pid));
        attribution.uid = process.uid;
        if let Some(details) = resolve_process_details(process.pid) {
            attribution = attribution.with_details(
                details.ppid,
                Some((details.uid, details.gid)),
                None,
                resolve_process_lineage(process.pid, details.ppid),
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
        "lsof"
    }

    fn get_degradation_reason(&self) -> DegradationReason {
        // The reason PKTAP wasn't used is injected by the application (which
        // learns it from the capture layer); see `super::report_pktap_degradation`.
        super::pktap_degradation()
    }

    fn socket_snapshot(&self) -> SocketSnapshot {
        self.socket_snapshot
            .read()
            .expect("socket snapshot lock poisoned")
            .clone()
    }
}

// Unprivileged lsof can silently omit sockets owned by other users.
fn snapshot_from_scan(
    sockets: Vec<HostSocket>,
    diagnostics: HashMap<HostSocket, Arc<rustnet_core::network::types::SocketSample>>,
    complete: bool,
    started: SystemTime,
) -> SocketSnapshot {
    let mut snapshot = SocketSnapshot::from_inventory(sockets, complete);
    snapshot.diagnostics = Arc::new(diagnostics);
    snapshot.diagnostics_status.queues =
        "lsof TCP byte queues; visibility follows current credentials; missing fields unavailable"
            .into();
    // SAFETY: geteuid has no arguments or pointer preconditions.
    if complete && unsafe { libc::geteuid() } == 0 {
        snapshot.with_closure_evidence(started)
    } else {
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tcp_connection;

    #[test]
    fn lsof_accepts_single_protocol_and_empty_inventories_but_rejects_failures() {
        use std::os::unix::process::ExitStatusExt;
        let output = |code, stdout: &str, stderr: &str| std::process::Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        let header = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n";
        for row in [
            "browser 42 501 7u IPv4 0x1 0t0 UDP *:45000\n",
            "browser 42 501 7u IPv4 0x1 0t0 TCP 192.0.2.1:45000->198.51.100.1:443 (ESTABLISHED)\n",
        ] {
            let stdout = format!("{header}{row}");
            let scan = MacOSProcessLookup::parse_lsof_result(&output(0, &stdout, "")).unwrap();
            assert!(scan.complete);
            assert_eq!(scan.sockets.len(), 1);
            let warned =
                MacOSProcessLookup::parse_lsof_result(&output(0, &stdout, "warning")).unwrap();
            assert!(!warned.complete);
            assert!(MacOSProcessLookup::parse_lsof_result(&output(1, &stdout, "")).is_err());
        }
        let empty = MacOSProcessLookup::parse_lsof_result(&output(1, "", "")).unwrap();
        assert!(empty.complete);
        assert!(empty.sockets.is_empty());
        assert!(
            MacOSProcessLookup::parse_lsof_result(&output(1, "", "permission denied")).is_err()
        );
        assert!(MacOSProcessLookup::parse_lsof_result(&output(2, "", "")).is_err());
    }

    #[test]
    fn lsof_numeric_uid_and_exact_match_reach_rich_attribution() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
curl\\x20helper 4294967295 501 9u IPv4 0x1 0t0 TCP 127.0.0.1:5000->1.1.1.1:443 (ESTABLISHED)
";
        let lookup = MacOSProcessLookup {
            cache: RwLock::new(crate::lsof::parse_output(output).lookup),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        };
        let conn = tcp_connection("127.0.0.1:5000", "1.1.1.1:443");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.tgid, u32::MAX);
        assert_eq!(attribution.name, "curl helper");
        assert_eq!(attribution.uid, Some(501));
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.executable, None);
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
    }

    #[test]
    fn lsof_relaxed_lookup_preserves_match_quality() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 4294967295 0 3u IPv4 0x1 0t0 TCP *:8080 (LISTEN)
";
        let lookup = MacOSProcessLookup {
            cache: RwLock::new(crate::lsof::parse_output(output).lookup),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        };
        let conn = tcp_connection("127.0.0.1:8080", "203.0.113.7:45000");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.uid, Some(0));
        assert_eq!(attribution.quality, MatchQuality::ListenerSocket);
    }

    #[test]
    fn libproc_resolves_the_current_process() {
        let pid = std::process::id();
        let executable = resolve_executable(pid).expect("current executable should resolve");
        assert!(executable.is_absolute());
        assert_eq!(executable, std::env::current_exe().unwrap());

        let details = resolve_process_details(pid).expect("current process details should resolve");
        // SAFETY: these libc calls only read the credentials of this process.
        let expected = unsafe { (libc::geteuid(), libc::getegid()) };
        assert_eq!((details.uid, details.gid), expected);
        assert_eq!(
            details.ppid,
            u32::try_from(unsafe { libc::getppid() }).unwrap()
        );
        assert!(!details.name.is_empty());
        assert!(details.started_at_unix_ms.is_some());

        let lineage = resolve_process_lineage(pid, details.ppid)
            .expect("current process parent should resolve");
        assert_eq!(lineage.ancestors.last().unwrap().pid, details.ppid);
    }

    #[test]
    fn libproc_failure_keeps_optional_fields_empty() {
        assert_eq!(resolve_executable(u32::MAX), None);
        assert!(resolve_process_details(u32::MAX).is_none());
    }

    #[test]
    fn real_lsof_scan_attributes_an_unprivileged_listener() {
        use std::net::{Ipv4Addr, TcpListener};

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let local = listener.local_addr().unwrap();
        let lookup = MacOSProcessLookup::new().unwrap();
        lookup.refresh().expect("lsof scan should succeed");
        let conn = tcp_connection(&local.to_string(), "0.0.0.0:0");

        let attribution = lookup
            .get_process_attribution(&conn)
            .expect("the current process listener should be attributable");
        // SAFETY: this libc call only reads the effective UID of this process.
        let expected_uid = unsafe { libc::geteuid() };

        assert_eq!(attribution.tgid, std::process::id());
        assert_eq!(
            attribution.ppid,
            Some(u32::try_from(unsafe { libc::getppid() }).unwrap())
        );
        assert_eq!(attribution.uid, Some(expected_uid));
        assert_eq!(attribution.executable, std::env::current_exe().ok());
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
    }
}
