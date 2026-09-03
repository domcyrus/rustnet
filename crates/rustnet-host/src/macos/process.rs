//! macOS lsof-based process lookup.

use crate::{
    ConnectionKey, DegradationReason, HostSocket, HostSocketState, HostTcpState, MatchQuality,
    ProcessAncestor, ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner, SocketScan,
    SocketSnapshot, ancestor_display_name, collect_process_lineage, decode_process_name,
    owner_match, parse_socket_addr_text, path_from_c_buffer, remote_if_present,
};
use anyhow::Result;
use log::{debug, error, info, warn};
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::mem::{MaybeUninit, size_of};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::RwLock;

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
        let scan = Self::parse_lsof().unwrap_or_else(|e| {
            warn!("Initial lsof scan failed, deferring to periodic refresh: {e}");
            SocketScan::default()
        });
        Ok(Self {
            cache: RwLock::new(scan.lookup),
            socket_snapshot: RwLock::new(SocketSnapshot::new(scan.sockets)),
        })
    }

    #[cfg(test)]
    pub(super) fn empty_for_test() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        }
    }

    fn parse_lsof() -> Result<SocketScan> {
        info!("Running lsof to get network connections");

        let output = Command::new(LSOF_PATH)
            .args(["-i", "-n", "-P", "-l", "+c", "0"])
            .output()?;

        if !output.status.success() {
            error!("lsof command failed with status: {}", output.status);
            error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(SocketScan::default());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_lsof_output(&stdout))
    }

    fn parse_lsof_output(stdout: &str) -> SocketScan {
        let mut lookup = HashMap::new();
        let mut sockets = Vec::new();
        let lines: Vec<&str> = stdout.lines().collect();
        info!("lsof returned {} lines", lines.len());

        if lines.is_empty() {
            warn!("lsof returned no output");
            return SocketScan { lookup, sockets };
        }

        debug!("lsof header: {}", lines.first().unwrap_or(&""));
        debug!("First few lines of lsof output:");
        for (i, line) in lines.iter().take(5).enumerate() {
            debug!("  {}: {}", i, line);
        }

        let mut processed_lines = 0;
        let mut successful_parsers = 0;

        for line in stdout.lines().skip(1) {
            processed_lines += 1;
            let parts: Vec<&str> = line.split_whitespace().collect();

            debug!("Processing line {}: {} parts", processed_lines, parts.len());
            debug!("  Raw line: {}", line);

            if parts.len() < 8 {
                debug!("  Skipping line with too few parts ({})", parts.len());
                continue;
            }

            let process_name = normalize_process_name_robust(&decode_lsof_string(parts[0]));
            let pid = match parts[1].parse::<u32>() {
                Ok(p) => p,
                Err(e) => {
                    debug!("  Failed to parse PID '{}': {}", parts[1], e);
                    continue;
                }
            };
            let uid = match parts[2].parse::<u32>() {
                Ok(uid) => uid,
                Err(e) => {
                    debug!("  Failed to parse numeric UID '{}': {}", parts[2], e);
                    continue;
                }
            };

            debug!("  Process: {} (PID: {})", process_name, pid);
            debug!("  Parts: {:?}", parts);

            // TYPE (parts[4]) says IPv4/IPv6; NODE (parts[7]) carries the protocol.
            let protocol_hint = if parts.len() > 4 {
                match parts[4] {
                    "IPv4" | "IPv6" => {
                        if parts.len() > 7 && (parts[7] == "TCP" || parts[7].contains("TCP")) {
                            debug!("  Detected TCP from NODE field: {}", parts[7]);
                            Some(Protocol::Tcp)
                        } else if parts.len() > 7 && (parts[7] == "UDP" || parts[7].contains("UDP"))
                        {
                            debug!("  Detected UDP from NODE field: {}", parts[7]);
                            Some(Protocol::Udp)
                        } else {
                            debug!(
                                "  No protocol detected from NODE field: {}",
                                parts.get(7).unwrap_or(&"")
                            );
                            None
                        }
                    }
                    _ => {
                        debug!("  TYPE field not IPv4/IPv6: {}", parts[4]);
                        None
                    }
                }
            } else {
                debug!("  Not enough parts for TYPE field");
                None
            };

            // A trailing "(STATE)" field pushes the connection info to the
            // second-to-last field; otherwise it is the last field.
            let last_field = parts.last().map_or("", |v| v);
            let connection_field = if last_field.starts_with('(') && last_field.ends_with(')') {
                if parts.len() >= 2 {
                    parts[parts.len() - 2]
                } else {
                    last_field
                }
            } else {
                last_field
            };

            debug!("  Connection field: '{}'", connection_field);

            if let Some((protocol, local, remote)) =
                parse_lsof_connection_with_hint(connection_field, protocol_hint)
            {
                if protocol == Protocol::Udp && local.port() == 0 {
                    debug!("  Skipping unbound UDP socket");
                    continue;
                }
                let key = ConnectionKey {
                    protocol,
                    local_addr: local,
                    remote_addr: remote,
                };
                debug!(
                    "  Successfully parsed connection: {:?} -> {} ({})",
                    key, process_name, pid
                );
                let owner = SocketOwner {
                    pid,
                    name: process_name,
                    uid: Some(uid),
                };
                lookup.insert(key, owner.clone());
                let state = match protocol {
                    Protocol::Tcp => HostSocketState::Tcp(parse_lsof_tcp_state(last_field)),
                    Protocol::Udp => HostSocketState::UdpBound,
                    _ => continue,
                };
                sockets.push(HostSocket {
                    protocol,
                    local_addr: local,
                    remote_addr: remote_if_present(remote),
                    state,
                    owner: Some(owner),
                    native_id: parts.get(5).and_then(|value| parse_lsof_native_id(value)),
                });
                successful_parsers += 1;
            } else {
                debug!("  Failed to parse connection from NAME field");
            }
        }

        info!(
            "Processed {} lines, successfully parsed {} connections",
            processed_lines, successful_parsers
        );
        info!("Total connections in lookup table: {}", lookup.len());

        SocketScan { lookup, sockets }
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
        info!("Refreshing macOS process lookup cache");
        let scan = Self::parse_lsof()?;
        let cache_size = scan.lookup.len();
        *self.cache.write().expect("cache lock poisoned") = scan.lookup;
        *self
            .socket_snapshot
            .write()
            .expect("socket snapshot lock poisoned") = SocketSnapshot::new(scan.sockets);
        info!("Process lookup cache refreshed with {} entries", cache_size);
        Ok(())
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

fn parse_lsof_connection_with_hint(
    name: &str,
    protocol_hint: Option<Protocol>,
) -> Option<(Protocol, SocketAddr, SocketAddr)> {
    // lsof NAME field formats:
    // "192.168.1.1:443->10.0.0.1:12345" (TCP)
    // "192.168.1.1:53" (UDP)
    // "*:80" (listening)
    debug!(
        "    Parsing NAME field: '{}' with hint: {:?}",
        name, protocol_hint
    );

    if name.contains("->") {
        let parts: Vec<&str> = name.split("->").collect();
        if parts.len() != 2 {
            debug!("    Failed: arrow connection doesn't have exactly 2 parts");
            return None;
        }

        debug!(
            "    Parsing arrow connection: '{}' -> '{}'",
            parts[0], parts[1]
        );
        let local = parse_socket_addr_text(parts[0])?;
        let remote = parse_socket_addr_text(parts[1])?;

        // Without a hint, an established connection is assumed to be TCP.
        let protocol = protocol_hint.unwrap_or(Protocol::Tcp);
        debug!(
            "    Success: {:?} {}:{} -> {}:{}",
            protocol,
            local.ip(),
            local.port(),
            remote.ip(),
            remote.port()
        );
        Some((protocol, local, remote))
    } else if name.contains(":") {
        debug!("    Parsing single address: '{}'", name);
        let local = parse_socket_addr_text(name)?;

        // UDP and listening sockets get an unspecified remote address.
        let remote = match local {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
            SocketAddr::V6(_) => "[::]:0".parse().ok()?,
        };

        // Without a hint, a single address is assumed to be UDP.
        let protocol = protocol_hint.unwrap_or(Protocol::Udp);
        debug!(
            "    Success: {:?} {}:{} (listening/UDP)",
            protocol,
            local.ip(),
            local.port()
        );
        Some((protocol, local, remote))
    } else {
        debug!("    Failed: no recognizable connection format");
        None
    }
}

/// lsof prints the TCP state in parentheses, such as `(ESTABLISHED)`.
fn parse_lsof_tcp_state(value: &str) -> HostTcpState {
    HostTcpState::parse_name(value.trim_matches(['(', ')']))
}

fn parse_lsof_native_id(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
}

/// Normalize a process name the same way PKTAP names are normalized
/// (shared with rustnet-core so both sides stay identical).
fn normalize_process_name_robust(name: &str) -> String {
    let normalized = rustnet_core::network::link_layer::pktap::normalize_process_name(name);

    debug!(
        "📝 Normalized lsof process name: '{}' -> '{}'",
        name, normalized
    );
    normalized
}

/// Decode lsof escape sequences like `\x20` back to regular characters.
fn decode_lsof_string(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'x') {
            chars.next();

            let hex_digits: String = chars.by_ref().take(2).collect();
            if hex_digits.len() == 2
                && let Ok(byte_val) = u8::from_str_radix(&hex_digits, 16)
                && let Some(decoded_char) = std::char::from_u32(byte_val as u32)
            {
                result.push(decoded_char);
                continue;
            }

            result.push('\\');
            result.push('x');
            result.push_str(&hex_digits);
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::tcp_connection;

    #[test]
    fn lsof_numeric_uid_and_exact_match_reach_rich_attribution() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
curl\\x20helper 4294967295 501 9u IPv4 0x1 0t0 TCP 127.0.0.1:5000->1.1.1.1:443 (ESTABLISHED)
";
        let lookup = MacOSProcessLookup {
            cache: RwLock::new(MacOSProcessLookup::parse_lsof_output(output).lookup),
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
            cache: RwLock::new(MacOSProcessLookup::parse_lsof_output(output).lookup),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
        };
        let conn = tcp_connection("127.0.0.1:8080", "203.0.113.7:45000");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.uid, Some(0));
        assert_eq!(attribution.quality, MatchQuality::ListenerSocket);
    }

    #[test]
    fn lsof_parser_requires_the_numeric_uid_enabled_by_dash_l() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 42 root 3u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)
";

        assert!(
            MacOSProcessLookup::parse_lsof_output(output)
                .lookup
                .is_empty()
        );
    }

    #[test]
    fn lsof_parser_reports_tcp_listeners_and_udp_binds() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 42 1000 3u IPv4 0x1 0t0 TCP *:8080 (LISTEN)
resolver 43 1000 4u IPv6 0x2 0t0 UDP [::1]:5353
client 44 1000 5u IPv4 0x3 0t0 UDP *:0 (Unbound)
";

        let scan = MacOSProcessLookup::parse_lsof_output(output);

        assert_eq!(scan.sockets.len(), 2);
        assert_eq!(
            scan.sockets[0].state,
            HostSocketState::Tcp(HostTcpState::Listen)
        );
        assert_eq!(scan.sockets[1].state, HostSocketState::UdpBound);
        assert_eq!(scan.sockets[0].owner.as_ref().unwrap().pid, 42);
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

    #[test]
    fn test_decode_lsof_string() {
        assert_eq!(
            decode_lsof_string("Microsoft\\x20Teams\\x20WebView\\x20Helper"),
            "Microsoft Teams WebView Helper"
        );

        assert_eq!(decode_lsof_string("Brave\\x20Browser"), "Brave Browser");

        assert_eq!(decode_lsof_string("firefox"), "firefox");

        assert_eq!(decode_lsof_string("App\\x20Name"), "App Name");

        assert_eq!(decode_lsof_string(""), "");

        assert_eq!(decode_lsof_string("launchd"), "launchd");

        // Malformed escape sequences are preserved.
        assert_eq!(
            decode_lsof_string("App\\x2G"),
            "App\\x2G" // Invalid hex
        );

        assert_eq!(
            decode_lsof_string("App\\x2"),
            "App\\x2" // Incomplete escape at the end
        );

        assert_eq!(
            decode_lsof_string("Test\\x20App\\x2D\\x2EExe"),
            "Test App-.Exe" // \x20 = space, \x2D = hyphen, \x2E = period
        );

        assert_eq!(
            decode_lsof_string("App\\Normal"),
            "App\\Normal" // Non-escape backslashes are preserved
        );
    }
}
