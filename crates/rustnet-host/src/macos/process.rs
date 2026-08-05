// network/platform/macos/process.rs - macOS lsof-based process lookup

use crate::{
    AttributionBackend, ConnectionKey, DegradationReason, MatchQuality, ProcessAncestor,
    ProcessAttribution, ProcessLineage, ProcessLookup, collect_process_lineage, relaxed_lookup,
};
use anyhow::Result;
use log::{debug, error, info, warn};
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::mem::{MaybeUninit, size_of};
use std::net::SocketAddr;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::RwLock;

const LSOF_PATH: &str = "/usr/sbin/lsof";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacOSProcessInfo {
    pid: u32,
    name: String,
    uid: u32,
}

pub struct MacOSProcessLookup {
    cache: RwLock<HashMap<ConnectionKey, MacOSProcessInfo>>,
}

pub(super) struct ProcessDetails {
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
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

    let returned = usize::try_from(length).ok()?.min(buffer.len());
    let path_length = buffer[..returned]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(returned);
    if path_length == 0 {
        return None;
    }

    Some(PathBuf::from(OsStr::from_bytes(&buffer[..path_length])))
}

pub(super) fn resolve_process_details(pid: u32) -> Option<ProcessDetails> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let expected_size = size_of::<libc::proc_bsdinfo>();
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();

    // SAFETY: libproc writes at most `expected_size` bytes into an aligned
    // buffer with the C layout of `proc_bsdinfo`.
    let returned_size = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            libc::c_int::try_from(expected_size).expect("proc info size fits in c_int"),
        )
    };
    if returned_size != libc::c_int::try_from(expected_size).ok()? {
        return None;
    }

    // SAFETY: a full `proc_bsdinfo` was initialized by the successful call.
    let info = unsafe { info.assume_init() };
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

fn decode_process_name(chars: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = chars
        .iter()
        .copied()
        .take_while(|value| *value != 0)
        .map(|value| value as u8)
        .collect();
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

pub(super) fn resolve_process_lineage(pid: u32, ppid: u32) -> Option<ProcessLineage> {
    collect_process_lineage(pid, ppid, |ancestor_pid| {
        let details = resolve_process_details(ancestor_pid)?;
        let executable = resolve_executable(ancestor_pid);
        let name = if details.name.is_empty() {
            executable
                .as_deref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| format!("PID {ancestor_pid}"))
        } else {
            details.name
        };
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
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn parse_lsof() -> Result<HashMap<ConnectionKey, MacOSProcessInfo>> {
        let lookup = HashMap::new();

        info!("Running lsof to get network connections");

        // Run lsof to get network connections
        let output = Command::new(LSOF_PATH)
            .args(["-i", "-n", "-P", "-l", "+c", "0"])
            .output()?;

        if !output.status.success() {
            error!("lsof command failed with status: {}", output.status);
            error!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            return Ok(lookup);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(Self::parse_lsof_output(&stdout))
    }

    fn parse_lsof_output(stdout: &str) -> HashMap<ConnectionKey, MacOSProcessInfo> {
        let mut lookup = HashMap::new();
        let lines: Vec<&str> = stdout.lines().collect();
        info!("lsof returned {} lines", lines.len());

        if lines.is_empty() {
            warn!("lsof returned no output");
            return lookup;
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

            // Check TYPE field (usually parts[4]) to determine protocol
            let protocol_hint = if parts.len() > 4 {
                match parts[4] {
                    "IPv4" | "IPv6" => {
                        // Need to look at NODE field for protocol
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

            // For lsof output, the connection info can be in different places:
            // If the last field looks like a state (starts with "(" and ends with ")"),
            // then the connection info is in the second-to-last field.
            // Otherwise, it's in the last field.
            let last_field = parts.last().map_or("", |v| v);
            let connection_field = if last_field.starts_with('(') && last_field.ends_with(')') {
                // Connection address is in the second-to-last field (before the state)
                if parts.len() >= 2 {
                    parts[parts.len() - 2]
                } else {
                    last_field
                }
            } else {
                // Connection info is in the last field
                last_field
            };

            debug!("  Connection field: '{}'", connection_field);

            if let Some((protocol, local, remote)) =
                parse_lsof_connection_with_hint(connection_field, protocol_hint)
            {
                let key = ConnectionKey {
                    protocol,
                    local_addr: local,
                    remote_addr: remote,
                };
                debug!(
                    "  Successfully parsed connection: {:?} -> {} ({})",
                    key, process_name, pid
                );
                lookup.insert(
                    key,
                    MacOSProcessInfo {
                        pid,
                        name: process_name,
                        uid,
                    },
                );
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

        lookup
    }

    fn lookup_match(&self, conn: &Connection) -> Option<(MacOSProcessInfo, MatchQuality)> {
        let key = ConnectionKey::from_connection(conn);
        let cache = self.cache.read().expect("cache lock poisoned");

        if let Some(result) = cache.get(&key).cloned() {
            debug!("Found process info for connection {:?}: {:?}", key, result);
            Some((result, MatchQuality::ExactTuple))
        } else {
            debug!("No process info found for connection {:?}", key);
            debug!("Available keys in cache:");
            for (cached_key, process) in cache.iter().take(10) {
                debug!("  {:?} -> {} ({})", cached_key, process.name, process.pid);
            }
            if cache.len() > 10 {
                debug!("  ... and {} more entries", cache.len() - 10);
            }
            relaxed_lookup(&cache, &key).map(|(process, quality)| (process.clone(), quality))
        }
    }
}

impl ProcessLookup for MacOSProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        self.lookup_match(conn)
            .map(|(process, _quality)| (process.pid, process.name))
    }

    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (process, quality) = self.lookup_match(conn)?;
        let mut attribution =
            ProcessAttribution::new(process.pid, process.name, AttributionBackend::Lsof, quality)
                .with_executable(resolve_executable(process.pid));
        attribution.uid = Some(process.uid);
        if let Some(details) = resolve_process_details(process.pid) {
            attribution = attribution
                .with_parent_pid(details.ppid)
                .with_credentials(process.uid, details.gid)
                .with_lineage(resolve_process_lineage(process.pid, details.ppid));
        }
        Some(attribution)
    }

    fn refresh(&self) -> Result<()> {
        info!("Refreshing macOS process lookup cache");
        let new_cache = Self::parse_lsof()?;
        let cache_size = new_cache.len();
        *self.cache.write().expect("cache lock poisoned") = new_cache;
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

    fn get_attribution_backend(&self) -> AttributionBackend {
        AttributionBackend::Lsof
    }
}

fn parse_lsof_connection_with_hint(
    name: &str,
    protocol_hint: Option<Protocol>,
) -> Option<(Protocol, SocketAddr, SocketAddr)> {
    // Parse lsof NAME field format:
    // "192.168.1.1:443->10.0.0.1:12345" (TCP)
    // "192.168.1.1:53" (UDP)
    // "*:80" (listening)

    debug!(
        "    Parsing NAME field: '{}' with hint: {:?}",
        name, protocol_hint
    );

    if name.contains("->") {
        // Established connection with remote address
        let parts: Vec<&str> = name.split("->").collect();
        if parts.len() != 2 {
            debug!("    Failed: arrow connection doesn't have exactly 2 parts");
            return None;
        }

        debug!(
            "    Parsing arrow connection: '{}' -> '{}'",
            parts[0], parts[1]
        );
        let local = parse_socket_addr(parts[0])?;
        let remote = parse_socket_addr(parts[1])?;

        // Use hint if available, otherwise assume TCP for established connections
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
        // UDP or listening socket
        debug!("    Parsing single address: '{}'", name);
        let local = parse_socket_addr(name)?;

        // For UDP or listening, we create a dummy remote address
        let remote = match local {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
            SocketAddr::V6(_) => "[::]:0".parse().ok()?,
        };

        // Use hint if available, otherwise assume UDP for single address
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

fn parse_socket_addr(addr_str: &str) -> Option<SocketAddr> {
    debug!("      Parsing socket address: '{}'", addr_str);

    // Handle IPv6 addresses in brackets
    if addr_str.starts_with('[') {
        let result = addr_str.parse().ok();
        debug!("      IPv6 parse result: {:?}", result);
        result
    } else if addr_str.starts_with('*') {
        // Listening on all interfaces
        let port_str = addr_str.strip_prefix("*:")?;
        let port = port_str.parse().ok()?;
        let result = Some(SocketAddr::new("0.0.0.0".parse().ok()?, port));
        debug!("      Wildcard parse result: {:?}", result);
        result
    } else {
        let result = addr_str.parse().ok();
        debug!("      Regular parse result: {:?}", result);
        result
    }
}

/// Robust normalization of process names to match PKTAP normalization
/// Handles all types of whitespace and control characters consistently
fn normalize_process_name_robust(name: &str) -> String {
    let normalized = name
        .chars()
        .map(|c| {
            if c.is_whitespace() || c.is_control() {
                ' ' // Convert whitespace and control characters to space
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace() // Split on any whitespace
        .collect::<Vec<&str>>()
        .join(" "); // Join with single spaces

    debug!(
        "📝 Normalized lsof process name: '{}' -> '{}'",
        name, normalized
    );
    normalized
}

/// Decode lsof escape sequences like \x20 back to regular characters
fn decode_lsof_string(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'x') {
            // Skip the 'x'
            chars.next();

            // Try to read two hex digits
            let hex_digits: String = chars.by_ref().take(2).collect();
            if hex_digits.len() == 2
                && let Ok(byte_val) = u8::from_str_radix(&hex_digits, 16)
                && let Some(decoded_char) = std::char::from_u32(byte_val as u32)
            {
                result.push(decoded_char);
                continue;
            }

            // If decoding failed, push the original characters
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
    fn lsof_numeric_uid_and_exact_match_reach_rich_attribution() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
curl\\x20helper 4294967295 501 9u IPv4 0x1 0t0 TCP 127.0.0.1:5000->1.1.1.1:443 (ESTABLISHED)
";
        let lookup = MacOSProcessLookup {
            cache: RwLock::new(MacOSProcessLookup::parse_lsof_output(output)),
        };
        let conn = tcp_connection("127.0.0.1:5000", "1.1.1.1:443");

        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.tgid, u32::MAX);
        assert_eq!(attribution.name, "curl helper");
        assert_eq!(attribution.uid, Some(501));
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.executable, None);
        assert_eq!(attribution.backend, AttributionBackend::Lsof);
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
        assert_eq!(
            lookup.get_process_for_connection(&conn),
            Some((u32::MAX, "curl helper".to_string()))
        );
    }

    #[test]
    fn lsof_relaxed_lookup_preserves_match_quality() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 4294967295 0 3u IPv4 0x1 0t0 TCP *:8080 (LISTEN)
";
        let lookup = MacOSProcessLookup {
            cache: RwLock::new(MacOSProcessLookup::parse_lsof_output(output)),
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

        assert!(MacOSProcessLookup::parse_lsof_output(output).is_empty());
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
        assert_eq!(attribution.backend, AttributionBackend::Lsof);
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
    }

    #[test]
    fn test_decode_lsof_string() {
        // Test basic space decoding
        assert_eq!(
            decode_lsof_string("Microsoft\\x20Teams\\x20WebView\\x20Helper"),
            "Microsoft Teams WebView Helper"
        );

        // Test single word with space
        assert_eq!(decode_lsof_string("Brave\\x20Browser"), "Brave Browser");

        // Test process name without escaping
        assert_eq!(decode_lsof_string("firefox"), "firefox");

        // Test process name with single escaped space
        assert_eq!(decode_lsof_string("App\\x20Name"), "App Name");

        // Test empty string
        assert_eq!(decode_lsof_string(""), "");

        // Test string with no escape sequences
        assert_eq!(decode_lsof_string("launchd"), "launchd");

        // Test malformed escape sequence (should be preserved)
        assert_eq!(
            decode_lsof_string("App\\x2G"),
            "App\\x2G" // Invalid hex, should remain unchanged
        );

        // Test incomplete escape sequence at end
        assert_eq!(
            decode_lsof_string("App\\x2"),
            "App\\x2" // Incomplete, should remain unchanged
        );

        // Test multiple different escape sequences
        assert_eq!(
            decode_lsof_string("Test\\x20App\\x2D\\x2EExe"),
            "Test App-.Exe" // \x20 = space, \x2D = hyphen, \x2E = period
        );

        // Test backslash without escape sequence
        assert_eq!(
            decode_lsof_string("App\\Normal"),
            "App\\Normal" // Should preserve non-escape backslashes
        );
    }
}
