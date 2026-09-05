//! # rustnet-host
//!
//! Per-connection **process attribution** and a host **socket inventory** for
//! [RustNet](https://github.com/domcyrus/rustnet): given a [`Connection`], find
//! the owning process (pid + name). Each platform uses its best available
//! strategy behind one [`ProcessLookup`] trait, selected by
//! [`create_process_lookup`]:
//!
//! - **Linux**: eBPF socket tracking (with the `ebpf` feature) and a procfs
//!   fallback.
//! - **macOS**: PKTAP packet metadata when available, enriched through libproc,
//!   otherwise `lsof` plus libproc.
//! - **Windows**: kernel ETW events with an IP Helper API
//!   (`GetExtendedTcpTable`/`...UdpTable`) fallback.
//! - **FreeBSD**: `sockstat` enriched with native `sysctl` process metadata.
//!
//! [`ProcessLookup::get_process_attribution`] returns the richer
//! [`ProcessAttribution`]: parent process id, effective UID/GID, executable
//! path, process lineage, and a [`MatchQuality`] saying how the connection was
//! matched.
//!
//! [`ProcessLookup::socket_snapshot`] exposes the operating system's TCP and
//! UDP tables independently from captured traffic. This includes TCP LISTEN
//! sockets and UDP BOUND endpoints that may never emit a captured packet.
//!
//! When a platform can't use its optimal method, [`ProcessLookup::get_degradation_reason`]
//! reports why via [`DegradationReason`] (e.g. missing `CAP_BPF`, no root for
//! PKTAP), which front-ends can surface to the user.
//! Construct lookups during privileged preparation, call
//! [`ProcessLookup::start_runtime`] after sandboxing, and use
//! [`ProcessLookup::refresh_interruptible`] in long-lived workers so shutdown
//! can cancel host commands promptly.
//!
//! This crate depends only on `rustnet-core` (for [`Connection`]/[`Protocol`]).
//! It does not depend on `rustnet-capture`; on macOS the application injects
//! whether PKTAP is active (via `report_pktap_degradation`) rather than this
//! crate querying capture. It has no UI or capture-loop dependency, so headless
//! tools can attribute processes the same way the `rustnet` TUI does.

use anyhow::Result;
use rustnet_core::network::types::{
    Connection, ConnectionKey, MAX_PROCESS_ANCESTORS, MatchQuality, ProcessAncestor,
    ProcessLineage, Protocol,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

/// TCP state reported by the host operating system's socket table.
///
/// This is intentionally separate from `rustnet_core::TcpState`, which is an
/// observed state reconstructed from captured packets. Host socket tables can
/// also report sockets that never emit a packet, most notably listeners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostTcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    /// Windows exposes deletion of the TCP control block as a separate state.
    DeleteTcb,
    Unknown,
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
impl HostTcpState {
    /// Parse a state name as printed by `sockstat` or `lsof`, case
    /// insensitively. The two tools spell a few states differently
    /// (`SYN_RCVD` vs `SYN_RECV`, `FIN_WAIT_1` vs `FIN_WAIT1`); every
    /// spelling is accepted, and anything else is [`Self::Unknown`].
    pub(crate) fn parse_name(value: &str) -> Self {
        match value.to_ascii_uppercase().as_str() {
            "CLOSED" => Self::Closed,
            "LISTEN" => Self::Listen,
            "SYN_SENT" => Self::SynSent,
            "SYN_RECEIVED" | "SYN_RCVD" | "SYN_RECV" => Self::SynReceived,
            "ESTABLISHED" => Self::Established,
            "FIN_WAIT_1" | "FIN_WAIT1" => Self::FinWait1,
            "FIN_WAIT_2" | "FIN_WAIT2" => Self::FinWait2,
            "CLOSE_WAIT" => Self::CloseWait,
            "CLOSING" => Self::Closing,
            "LAST_ACK" => Self::LastAck,
            "TIME_WAIT" => Self::TimeWait,
            _ => Self::Unknown,
        }
    }
}

impl std::fmt::Display for HostTcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECV",
            Self::Established => "ESTAB",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown => "UNKNOWN",
        })
    }
}

/// State of a host socket record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostSocketState {
    Tcp(HostTcpState),
    /// UDP has no LISTEN state. A row in the host UDP table represents a local
    /// endpoint that has been bound, explicitly or implicitly.
    UdpBound,
}

/// Best-effort process ownership attached to a host socket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SocketOwner {
    pub pid: u32,
    pub name: String,
    pub uid: Option<u32>,
}

impl SocketOwner {
    pub fn new(pid: u32, name: impl Into<String>, uid: Option<u32>) -> Self {
        Self {
            pid,
            name: name.into(),
            uid,
        }
    }
}

/// One socket returned by the host operating system.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HostSocket {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    /// TCP listeners and unconnected UDP endpoints have no remote peer.
    pub remote_addr: Option<SocketAddr>,
    pub state: HostSocketState,
    /// Missing when the platform does not expose an owner or permissions hide
    /// it. The socket record itself remains useful and must not be discarded.
    pub owner: Option<SocketOwner>,
    /// Platform-native identity when cheaply available, such as a Linux socket
    /// inode. It is not displayed, but can distinguish otherwise equal rows.
    pub native_id: Option<u64>,
}

impl HostSocket {
    pub fn new(protocol: Protocol, local_addr: SocketAddr, state: HostSocketState) -> Self {
        Self {
            protocol,
            local_addr,
            remote_addr: None,
            state,
            owner: None,
            native_id: None,
        }
    }

    pub fn with_remote_addr(mut self, remote_addr: SocketAddr) -> Self {
        self.remote_addr = Some(remote_addr);
        self
    }

    pub fn with_owner(mut self, owner: SocketOwner) -> Self {
        self.owner = Some(owner);
        self
    }

    pub fn with_native_id(mut self, native_id: u64) -> Self {
        self.native_id = Some(native_id);
        self
    }
}

/// Point-in-time host socket inventory.
#[derive(Debug, Clone, Default)]
pub struct SocketSnapshot {
    pub sockets: Arc<[HostSocket]>,
    pub collected_at: Option<SystemTime>,
}

impl SocketSnapshot {
    pub(crate) fn new(sockets: Vec<HostSocket>) -> Self {
        Self {
            sockets: sockets.into(),
            collected_at: Some(SystemTime::now()),
        }
    }
}

pub(crate) fn remote_if_present(addr: SocketAddr) -> Option<SocketAddr> {
    (addr.port() != 0 || !addr.ip().is_unspecified()).then_some(addr)
}

/// Active process-attribution backend.
#[cfg(all(target_os = "linux", feature = "ebpf"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttributionBackend {
    /// Linux BPF trampoline programs using fentry and fexit.
    EbpfFentry,
    /// Linux legacy kprobe and kretprobe programs.
    EbpfKprobe,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl std::fmt::Display for AttributionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::EbpfFentry => "eBPF fentry/fexit",
            Self::EbpfKprobe => "eBPF kprobe",
        };
        f.write_str(name)
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
bitflags::bitflags! {
    /// Connection operations covered by the active Linux eBPF backend.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub(crate) struct AttributionCapabilities: u32 {
        const TCP_V4_CONNECT = 1 << 0;
        const TCP_V6_CONNECT = 1 << 1;
        const TCP_ACCEPT     = 1 << 2;
        const UDP_V4_SEND    = 1 << 3;
        const UDP_V6_SEND    = 1 << 4;
        const ICMP_V4_SEND   = 1 << 5;
        const ICMP_V6_SEND   = 1 << 6;
    }
}

/// A rich process-attribution result.
///
/// Everything past `tgid`/`name` is best effort: a backend fills in what it
/// actually observed and leaves the rest `None` rather than guessing. Every
/// supported platform can report parent process ids, executable paths, and a
/// capped parent chain. Linux, macOS, and FreeBSD can report credentials.
///
/// Marked `#[non_exhaustive]`: more fields are expected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessAttribution {
    /// Thread group id, i.e. the PID as user space understands it.
    pub tgid: u32,
    /// Parent process id, resolved from the live process when available.
    pub ppid: Option<u32>,
    /// Process name: `/proc/<tgid>/comm` on Linux, the OS-reported name elsewhere.
    pub name: String,
    /// Effective user id of the owning process.
    pub uid: Option<u32>,
    /// Effective group id of the owning process.
    pub gid: Option<u32>,
    /// Absolute executable path, resolved once at attribution time. `None` when
    /// the process already exited or the path is unreadable.
    pub executable: Option<PathBuf>,
    /// How the connection key matched the backend's records.
    pub quality: MatchQuality,
    /// Best-effort parent chain, ordered oldest retained ancestor first.
    pub lineage: Option<ProcessLineage>,
}

impl ProcessAttribution {
    /// Create an attribution with only the fields every backend can supply.
    pub(crate) fn new(tgid: u32, name: impl Into<String>, quality: MatchQuality) -> Self {
        Self {
            tgid,
            ppid: None,
            name: name.into(),
            uid: None,
            gid: None,
            executable: None,
            quality,
            lineage: None,
        }
    }

    /// Attach the parent process id.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn with_parent_pid(mut self, ppid: u32) -> Self {
        self.ppid = Some(ppid);
        self
    }

    /// Attach the effective user and group id.
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn with_credentials(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    /// Attach the resolved executable path. `None` is a valid outcome and is
    /// stored as such: failing to read the path never fails the attribution.
    #[cfg(any(test, target_os = "linux", target_os = "macos"))]
    pub(crate) fn with_executable(mut self, executable: Option<PathBuf>) -> Self {
        self.executable = executable;
        self
    }

    /// Attach the owning process's best-effort parent chain.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_lineage(mut self, lineage: Option<ProcessLineage>) -> Self {
        self.lineage = lineage;
        self
    }

    /// Attach everything a platform's per-process details lookup resolved in
    /// one step: parent pid, credentials, executable path, and lineage.
    /// Credentials and executable are left untouched when the lookup does not
    /// resolve them.
    #[cfg(any(
        test,
        target_os = "freebsd",
        target_os = "macos",
        target_os = "windows"
    ))]
    pub(crate) fn with_details(
        mut self,
        ppid: u32,
        credentials: Option<(u32, u32)>,
        executable: Option<PathBuf>,
        lineage: Option<ProcessLineage>,
    ) -> Self {
        self.ppid = Some(ppid);
        if let Some((uid, gid)) = credentials {
            self.uid = Some(uid);
            self.gid = Some(gid);
        }
        if let Some(executable) = executable {
            self.executable = Some(executable);
        }
        self.lineage = lineage;
        self
    }
}

/// Walk a platform-specific parent resolver into the shared lineage shape.
///
/// The resolver returns one ancestor and that process's parent PID. Missing
/// metadata ends the best-effort walk without discarding ancestors already
/// collected.
pub(crate) fn collect_process_lineage<F>(
    owner_pid: u32,
    parent_pid: u32,
    mut resolve: F,
) -> Option<ProcessLineage>
where
    F: FnMut(u32) -> Option<(ProcessAncestor, u32)>,
{
    if parent_pid == 0 || parent_pid == owner_pid {
        return None;
    }

    let mut ancestors = Vec::with_capacity(MAX_PROCESS_ANCESTORS);
    let mut seen = vec![owner_pid];
    let mut current_pid = parent_pid;
    let mut truncated = false;

    while current_pid != 0 && !seen.contains(&current_pid) {
        let Some((ancestor, next_parent_pid)) = resolve(current_pid) else {
            break;
        };
        seen.push(current_pid);
        ancestors.push(ancestor);

        if ancestors.len() == MAX_PROCESS_ANCESTORS {
            truncated = next_parent_pid != 0 && !seen.contains(&next_parent_pid);
            break;
        }
        current_pid = next_parent_pid;
    }

    if ancestors.is_empty() {
        return None;
    }
    ancestors.reverse();
    Some(ProcessLineage {
        ancestors,
        truncated,
    })
}

/// One pass over the operating system's socket table (`sockstat`, `lsof`):
/// the attribution lookup keyed by connection tuple, plus every socket for
/// the host snapshot.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
#[derive(Default)]
pub(crate) struct SocketScan {
    pub(crate) lookup: HashMap<ConnectionKey, SocketOwner>,
    pub(crate) sockets: Vec<HostSocket>,
}

/// The owner recorded for `key`: an exact tuple hit, else the best
/// [`relaxed_lookup`] candidate.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) fn owner_match(
    cache: &HashMap<ConnectionKey, SocketOwner>,
    key: &ConnectionKey,
) -> Option<(SocketOwner, MatchQuality)> {
    if let Some(owner) = cache.get(key) {
        return Some((owner.clone(), MatchQuality::ExactTuple));
    }
    relaxed_lookup(cache, key).map(|(owner, quality)| (owner.clone(), quality))
}

/// Decode a NUL-terminated C char array (`ki_comm`, `pbi_comm`, ...) into a
/// process name. `None` when the array is empty.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) fn decode_process_name(chars: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = chars
        .iter()
        .copied()
        .take_while(|value| *value != 0)
        .map(|value| value as u8)
        .collect();
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// The path a C API wrote into `buffer`: the first `returned` bytes, cut at
/// the first NUL. `None` when the path is empty.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) fn path_from_c_buffer(buffer: &[u8], returned: usize) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let returned = returned.min(buffer.len());
    let path_len = buffer[..returned]
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(returned);
    (path_len > 0).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..path_len])))
}

/// Display name for a lineage ancestor: the OS-reported name, else the
/// executable's file name, else a `PID <n>` placeholder.
#[cfg(any(target_os = "freebsd", target_os = "macos"))]
pub(crate) fn ancestor_display_name(
    name: String,
    executable: Option<&std::path::Path>,
    pid: u32,
) -> String {
    if name.is_empty() {
        executable
            .and_then(|path| path.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("PID {pid}"))
    } else {
        name
    }
}

/// Return the cached value for `key`, computing and caching it on a miss.
/// Caches misses too when `V` is an `Option`. `poisoned` is the lock's
/// expect message.
#[cfg(any(target_os = "freebsd", target_os = "linux"))]
pub(crate) fn memoized<K, V>(
    cache: &std::sync::RwLock<HashMap<K, V>>,
    key: K,
    poisoned: &str,
    compute: impl FnOnce() -> V,
) -> V
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    if let Some(value) = cache.read().expect(poisoned).get(&key) {
        return value.clone();
    }

    let value = compute();
    cache.write().expect(poisoned).insert(key, value.clone());
    value
}

/// Parse a socket address as printed by OS socket-table tools (`sockstat`,
/// `lsof`): `ip:port`, `*:port` (wildcard), `[ipv6]:port`, or bracketless
/// IPv6 like `::1:8080` (the last colon splits off the port). A `*` port
/// (sockstat prints a wildcard peer as `*:*`) parses as port 0, so listener
/// rows survive and `remote_if_present` reads them as "no peer".
#[cfg(any(test, target_os = "freebsd", target_os = "macos"))]
pub(crate) fn parse_socket_addr_text(addr_str: &str) -> Option<SocketAddr> {
    fn parse_port(port_str: &str) -> Option<u16> {
        if port_str == "*" {
            return Some(0);
        }
        port_str.parse::<u16>().ok()
    }

    if let Some(port_str) = addr_str.strip_prefix("*:") {
        let port = parse_port(port_str)?;
        return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
    }

    // Handle IPv6 with brackets: [::1]:8080. Std parsing also accepts scope
    // ids like [fe80::1%1]:22, which Ipv6Addr alone would reject.
    if addr_str.starts_with('[') {
        return addr_str.parse().ok();
    }

    let last_colon = addr_str.rfind(':')?;
    let (ip_str, port_str) = addr_str.split_at(last_colon);
    let port_str = &port_str[1..];

    let port = parse_port(port_str)?;

    let ip = if ip_str.contains(':') {
        IpAddr::V6(ip_str.parse().ok()?)
    } else {
        IpAddr::V4(ip_str.parse().ok()?)
    };

    Some(SocketAddr::new(ip, port))
}

/// Reasons why process detection may be degraded from optimal
#[derive(Debug, Clone, PartialEq, Default)]
pub enum DegradationReason {
    /// No degradation, the optimal method is available.
    #[default]
    None,
    // Linux eBPF reasons
    /// Missing CAP_BPF capability (Linux 5.8+)
    #[cfg(target_os = "linux")]
    MissingCapBpf,
    /// Missing CAP_PERFMON capability (Linux 5.8+)
    #[cfg(target_os = "linux")]
    MissingCapPerfmon,
    /// Missing both CAP_BPF and CAP_PERFMON
    #[cfg(target_os = "linux")]
    MissingBpfCapabilities,
    /// Kernel doesn't support required eBPF features (e.g. ENOSYS from bpf(2))
    #[cfg(target_os = "linux")]
    KernelUnsupported,
    /// BPF syscall denied despite caps - typically AppArmor, kernel lockdown,
    /// or unprivileged_bpf_disabled interactions
    #[cfg(target_os = "linux")]
    BpfPermissionDenied,
    /// Failed to attach a kprobe (e.g. symbol missing from kernel). The
    /// String carries the symbol name where known.
    #[cfg(target_os = "linux")]
    KprobeAttachFailed(String),
    /// Kernel BTF unavailable / CO-RE relocation failed (no /sys/kernel/btf/vmlinux)
    #[cfg(target_os = "linux")]
    BtfUnavailable,
    /// Generic eBPF load failure carrying the truncated libbpf error text
    #[cfg(target_os = "linux")]
    EbpfLoadFailed(String),
    /// Binary lives on a filesystem mounted with `nosuid`, which makes the
    /// kernel silently ignore file capabilities set via `setcap`. Common when
    /// the binary is under `/home`, `/tmp`, or a removable mount.
    #[cfg(target_os = "linux")]
    BinaryOnNosuidMount,
    // macOS PKTAP reasons
    /// No root privileges for PKTAP
    #[cfg(target_os = "macos")]
    MissingRootPrivileges,
    /// Cannot access BPF devices (/dev/bpf*)
    #[cfg(target_os = "macos")]
    NoBpfDeviceAccess,
    /// BPF filter specified (incompatible with PKTAP)
    #[cfg(target_os = "macos")]
    BpfFilterIncompatible,
    /// Specific interface requested (PKTAP only works with pktap pseudo-device)
    #[cfg(target_os = "macos")]
    InterfaceSpecified,
    // Windows ETW reason
    /// Kernel ETW could not be started; IP Helper polling remains available.
    #[cfg(target_os = "windows")]
    EtwUnavailable,
}

impl DegradationReason {
    /// Human-readable description of what is needed to lift the degradation.
    pub fn description(&self) -> Cow<'_, str> {
        match self {
            Self::None => Cow::Borrowed(""),
            #[cfg(target_os = "linux")]
            Self::MissingCapBpf => Cow::Borrowed("needs CAP_BPF"),
            #[cfg(target_os = "linux")]
            Self::MissingCapPerfmon => Cow::Borrowed("needs CAP_PERFMON"),
            #[cfg(target_os = "linux")]
            Self::MissingBpfCapabilities => Cow::Borrowed("needs CAP_BPF+CAP_PERFMON"),
            #[cfg(target_os = "linux")]
            Self::KernelUnsupported => Cow::Borrowed("kernel unsupported"),
            #[cfg(target_os = "linux")]
            Self::BpfPermissionDenied => Cow::Borrowed(
                "BPF denied (check perf_event_paranoid / AppArmor / unprivileged_bpf_disabled)",
            ),
            #[cfg(target_os = "linux")]
            Self::KprobeAttachFailed(sym) => {
                if sym.is_empty() {
                    Cow::Borrowed("kprobe attach failed")
                } else {
                    Cow::Owned(format!("kprobe attach failed: {sym}"))
                }
            }
            #[cfg(target_os = "linux")]
            Self::BtfUnavailable => Cow::Borrowed("kernel BTF unavailable"),
            #[cfg(target_os = "linux")]
            Self::EbpfLoadFailed(s) => Cow::Owned(format!("eBPF load failed: {s}")),
            #[cfg(target_os = "linux")]
            Self::BinaryOnNosuidMount => {
                Cow::Borrowed("file caps ignored: binary on a nosuid mount")
            }
            #[cfg(target_os = "macos")]
            Self::MissingRootPrivileges => Cow::Borrowed("needs root"),
            #[cfg(target_os = "macos")]
            Self::NoBpfDeviceAccess => Cow::Borrowed("no BPF device access"),
            #[cfg(target_os = "macos")]
            Self::BpfFilterIncompatible => Cow::Borrowed("BPF filter incompatible"),
            #[cfg(target_os = "macos")]
            Self::InterfaceSpecified => Cow::Borrowed("interface specified"),
            #[cfg(target_os = "windows")]
            Self::EtwUnavailable => Cow::Borrowed("May miss short-lived processes"),
        }
    }

    /// Name of the unavailable feature.
    pub fn unavailable_feature(&self) -> Option<&str> {
        match self {
            Self::None => None,
            #[cfg(target_os = "linux")]
            Self::MissingCapBpf
            | Self::MissingCapPerfmon
            | Self::MissingBpfCapabilities
            | Self::KernelUnsupported
            | Self::BpfPermissionDenied
            | Self::KprobeAttachFailed(_)
            | Self::BtfUnavailable
            | Self::EbpfLoadFailed(_)
            | Self::BinaryOnNosuidMount => Some("eBPF"),
            #[cfg(target_os = "macos")]
            Self::MissingRootPrivileges
            | Self::NoBpfDeviceAccess
            | Self::BpfFilterIncompatible
            | Self::InterfaceSpecified => Some("PKTAP"),
            #[cfg(target_os = "windows")]
            Self::EtwUnavailable => Some("ETW"),
        }
    }
}

pub mod procfs;

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
mod command;
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "freebsd")]
pub use freebsd::create_process_lookup;
#[cfg(target_os = "linux")]
pub use linux::create_process_lookup;
#[cfg(target_os = "macos")]
pub use macos::{create_process_lookup, report_pktap_degradation};
#[cfg(target_os = "windows")]
pub use windows::create_process_lookup;

/// Platform-specific process lookup.
pub trait ProcessLookup: Send + Sync {
    /// Start long-lived background collection after the caller has applied its
    /// runtime sandbox. Implementations without background work keep the
    /// default no-op behavior.
    fn start_runtime(&mut self) -> Result<()> {
        Ok(())
    }

    /// Rich attribution for a connection: identity, credentials, executable
    /// path, and the provenance of the match.
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution>;

    /// Refresh internal caches, if any (best effort).
    fn refresh(&self) -> Result<()> {
        Ok(())
    }

    /// Refresh internal caches, returning promptly when shutdown is requested.
    ///
    /// The default preserves compatibility for in-process implementations.
    /// Backends that launch host commands override this to cancel the child.
    fn refresh_interruptible(&self, cancelled: &AtomicBool) -> Result<()> {
        if cancelled.load(Ordering::Acquire) {
            Ok(())
        } else {
            self.refresh()
        }
    }

    /// Latest operating-system socket table, independent from packet capture.
    ///
    /// The empty default keeps third-party process lookup implementations
    /// source-compatible when they do not provide host socket inventory.
    fn socket_snapshot(&self) -> SocketSnapshot {
        SocketSnapshot::default()
    }

    /// Detection method name for display.
    fn get_detection_method(&self) -> &str;

    /// Why process detection is degraded; [`DegradationReason::None`] when
    /// the optimal method is in use.
    fn get_degradation_reason(&self) -> DegradationReason {
        DegradationReason::None
    }
}

/// Match a connection key against an OS socket table keyed by exact 4-tuples,
/// progressively relaxing the key, and report which shape matched.
///
/// Three shapes actually appear in OS socket tables:
///   1. (0:lport,  rip:rport): wildcard-bound socket with a known remote
///   2. (lip:lport, 0:0):      listening on a specific local IP
///   3. (0:lport,  0:0):       listening on the wildcard address
///
/// Candidates are tried most-specific first, so the reported
/// [`MatchQuality`] describes the tightest shape that matched.
///
/// Every candidate is still probed even after a hit: if two candidates resolve
/// to *different* owners the answer is ambiguous and `None` is returned rather
/// than a coin flip. Candidates that agree are not a conflict.
pub(crate) fn relaxed_lookup<'map, V: PartialEq>(
    map: &'map HashMap<ConnectionKey, V>,
    key: &ConnectionKey,
) -> Option<(&'map V, MatchQuality)> {
    // Only TCP and UDP sockets appear in OS network tables with wildcard
    // addresses. Other protocols (ICMP, IGMP, ARP) have no entries to fall back to.
    if !matches!(key.protocol, Protocol::Tcp | Protocol::Udp) {
        return None;
    }

    let zero = |addr: SocketAddr| -> IpAddr {
        match addr {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    };

    let lip = key.local_addr.ip();
    let lport = key.local_addr.port();
    let rip = key.remote_addr.ip();
    let rport = key.remote_addr.port();
    let zlip = zero(key.local_addr);
    let zrip = zero(key.remote_addr);

    let candidates: [(IpAddr, u16, IpAddr, u16, MatchQuality); 3] = [
        // 1. wildcard local address, known remote
        (zlip, lport, rip, rport, MatchQuality::WildcardLocalAddress),
        // 2. listening on a specific local IP
        (lip, lport, zrip, 0, MatchQuality::ListenerSocket),
        // 3. listening on the wildcard address
        (zlip, lport, zrip, 0, MatchQuality::ListenerSocket),
    ];

    let mut found: Option<(&V, MatchQuality)> = None;
    for (l_ip, l_port, r_ip, r_port, quality) in candidates {
        let candidate = ConnectionKey {
            protocol: key.protocol,
            local_addr: SocketAddr::new(l_ip, l_port),
            remote_addr: SocketAddr::new(r_ip, r_port),
        };
        if let Some(entry) = map.get(&candidate) {
            match found {
                None => found = Some((entry, quality)),
                Some((existing, _)) if existing == entry => {} // same owner, no conflict
                Some(_) => return None,                        // two different processes: ambiguous
            }
        }
    }
    found
}

/// Fixtures shared by the platform test modules. Not every platform uses
/// each one, so unused fixtures are not an error.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use crate::ConnectionKey;
    use rustnet_core::network::types::{Connection, Protocol, ProtocolState, TcpState};

    /// An established TCP connection between two `ip:port` literals.
    pub(crate) fn tcp_connection(local: &str, remote: &str) -> Connection {
        Connection::new(
            Protocol::Tcp,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    /// The lookup key for two `ip:port` literals under `protocol`.
    pub(crate) fn connection_key(protocol: Protocol, local: &str, remote: &str) -> ConnectionKey {
        ConnectionKey {
            protocol,
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
        }
    }

    /// The TCP lookup key for two `ip:port` literals.
    pub(crate) fn tcp_key(local: &str, remote: &str) -> ConnectionKey {
        connection_key(Protocol::Tcp, local, remote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::connection_key as key;
    use std::path::Path;

    fn owner(pid: u32, name: &str) -> (u32, String) {
        (pid, name.to_string())
    }

    #[test]
    fn attribution_builders_preserve_rich_fields() {
        let attribution = ProcessAttribution::new(42, "curl", MatchQuality::ExactTuple)
            .with_parent_pid(1)
            .with_credentials(1000, 100)
            .with_executable(Some(PathBuf::from("/usr/bin/curl")));

        assert_eq!(attribution.ppid, Some(1));
        assert_eq!(attribution.uid, Some(1000));
        assert_eq!(attribution.gid, Some(100));
        assert_eq!(
            attribution.executable.as_deref(),
            Some(Path::new("/usr/bin/curl"))
        );
        assert_eq!(attribution.lineage, None);
    }

    #[test]
    fn attribution_leaves_unobserved_fields_empty() {
        let attribution =
            ProcessAttribution::new(7, "sshd", MatchQuality::ProcfsExact).with_executable(None);

        assert_eq!(attribution.ppid, None);
        assert_eq!(attribution.uid, None);
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.executable, None);
        assert_eq!(attribution.lineage, None);
    }

    #[test]
    fn with_details_leaves_unresolved_credentials_and_executable_untouched() {
        let base = || ProcessAttribution::new(7, "sshd", MatchQuality::Unspecified);

        let full = base().with_details(
            1,
            Some((1000, 100)),
            Some(PathBuf::from("/usr/sbin/sshd")),
            None,
        );
        assert_eq!(full.ppid, Some(1));
        assert_eq!((full.uid, full.gid), (Some(1000), Some(100)));
        assert_eq!(full.executable, Some(PathBuf::from("/usr/sbin/sshd")));

        let sparse = base()
            .with_credentials(500, 50)
            .with_executable(Some(PathBuf::from("/usr/sbin/sshd")))
            .with_details(1, None, None, None);
        assert_eq!(sparse.ppid, Some(1));
        assert_eq!((sparse.uid, sparse.gid), (Some(500), Some(50)));
        assert_eq!(sparse.executable, Some(PathBuf::from("/usr/sbin/sshd")));
    }

    fn ancestor(pid: u32) -> ProcessAncestor {
        ProcessAncestor {
            pid,
            name: format!("process-{pid}"),
            executable: None,
            started_at_unix_ms: Some(u64::from(pid) * 1_000),
        }
    }

    #[test]
    fn lineage_is_rootward_ordered_and_capped() {
        let parents = HashMap::from([(5, 4), (4, 3), (3, 2), (2, 1), (1, 0)]);
        let lineage =
            collect_process_lineage(6, 5, |pid| Some((ancestor(pid), *parents.get(&pid)?)))
                .unwrap();

        assert_eq!(
            lineage
                .ancestors
                .iter()
                .map(|entry| entry.pid)
                .collect::<Vec<_>>(),
            [2, 3, 4, 5]
        );
        assert!(lineage.truncated);
    }

    #[test]
    fn lineage_stops_at_cycles_without_claiming_cap_truncation() {
        let parents = HashMap::from([(3, 2), (2, 3)]);
        let lineage =
            collect_process_lineage(4, 3, |pid| Some((ancestor(pid), *parents.get(&pid)?)))
                .unwrap();

        assert_eq!(
            lineage
                .ancestors
                .iter()
                .map(|entry| entry.pid)
                .collect::<Vec<_>>(),
            [2, 3]
        );
        assert!(!lineage.truncated);
    }

    #[test]
    fn only_exact_tuple_matches_count_as_exact() {
        assert!(MatchQuality::ExactTuple.is_exact());
        assert!(MatchQuality::ProcfsExact.is_exact());
        assert!(!MatchQuality::WildcardLocalAddress.is_exact());
        assert!(!MatchQuality::ListenerSocket.is_exact());
        assert!(!MatchQuality::ProcfsRelaxed.is_exact());
        assert!(!MatchQuality::Unspecified.is_exact());
    }

    #[test]
    fn relaxed_lookup_reports_a_wildcard_local_address_match() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Udp, "0.0.0.0:5353", "224.0.0.251:5353"),
            owner(10, "avahi"),
        );

        let (entry, quality) = relaxed_lookup(
            &map,
            &key(Protocol::Udp, "192.168.1.10:5353", "224.0.0.251:5353"),
        )
        .expect("wildcard-bound socket must match");

        assert_eq!(entry, &owner(10, "avahi"));
        assert_eq!(quality, MatchQuality::WildcardLocalAddress);
    }

    #[test]
    fn relaxed_lookup_reports_a_listener_bound_to_a_specific_address() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Tcp, "192.168.1.10:8080", "0.0.0.0:0"),
            owner(11, "nginx"),
        );

        let (entry, quality) = relaxed_lookup(
            &map,
            &key(Protocol::Tcp, "192.168.1.10:8080", "203.0.113.5:44321"),
        )
        .expect("specific-address listener must match");

        assert_eq!(entry, &owner(11, "nginx"));
        assert_eq!(quality, MatchQuality::ListenerSocket);
    }

    #[test]
    fn relaxed_lookup_reports_a_wildcard_listener() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:22", "0.0.0.0:0"),
            owner(12, "sshd"),
        );

        let (entry, quality) = relaxed_lookup(
            &map,
            &key(Protocol::Tcp, "192.168.1.10:22", "203.0.113.5:51000"),
        )
        .expect("wildcard listener must match");

        assert_eq!(entry, &owner(12, "sshd"));
        assert_eq!(quality, MatchQuality::ListenerSocket);
    }

    #[test]
    fn relaxed_lookup_prefers_the_tightest_shape_when_several_agree() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:8080", "203.0.113.5:44321"),
            owner(13, "envoy"),
        );
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:8080", "0.0.0.0:0"),
            owner(13, "envoy"),
        );

        let (entry, quality) = relaxed_lookup(
            &map,
            &key(Protocol::Tcp, "192.168.1.10:8080", "203.0.113.5:44321"),
        )
        .expect("agreeing candidates are not a conflict");

        assert_eq!(entry, &owner(13, "envoy"));
        assert_eq!(quality, MatchQuality::WildcardLocalAddress);
    }

    #[test]
    fn relaxed_lookup_refuses_to_pick_between_conflicting_owners() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:8080", "203.0.113.5:44321"),
            owner(14, "envoy"),
        );
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:8080", "0.0.0.0:0"),
            owner(15, "nginx"),
        );

        assert!(
            relaxed_lookup(
                &map,
                &key(Protocol::Tcp, "192.168.1.10:8080", "203.0.113.5:44321")
            )
            .is_none(),
            "two candidates naming different processes must produce no attribution"
        );
    }

    #[test]
    fn relaxed_lookup_skips_protocols_without_socket_table_entries() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Icmp, "0.0.0.0:0", "0.0.0.0:0"),
            owner(16, "ping"),
        );

        assert!(
            relaxed_lookup(&map, &key(Protocol::Icmp, "192.168.1.10:0", "8.8.8.8:0")).is_none()
        );
    }

    #[test]
    fn socket_addr_text_parses_ipv4() {
        assert_eq!(
            parse_socket_addr_text("192.168.1.1:8080"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                8080
            ))
        );
        assert_eq!(
            parse_socket_addr_text("127.0.0.1:80"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80))
        );
    }

    #[test]
    fn socket_addr_text_parses_ipv6_with_brackets() {
        assert_eq!(
            parse_socket_addr_text("[::1]:8080"),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
        );
        assert_eq!(
            parse_socket_addr_text("[2001:db8::1]:443"),
            Some(SocketAddr::new(
                IpAddr::V6("2001:db8::1".parse().unwrap()),
                443
            ))
        );
        assert_eq!(
            parse_socket_addr_text("[fe80::1]:22"),
            Some(SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 22))
        );
        // Numeric scope id
        assert_eq!(
            parse_socket_addr_text("[fe80::1%1]:22"),
            Some("[fe80::1%1]:22".parse().unwrap())
        );
    }

    #[test]
    fn socket_addr_text_parses_ipv4_mapped_ipv6() {
        assert_eq!(
            parse_socket_addr_text("[::ffff:192.168.1.1]:80"),
            Some(SocketAddr::new(
                IpAddr::V6("::ffff:192.168.1.1".parse().unwrap()),
                80
            ))
        );
    }

    #[test]
    fn socket_addr_text_parses_bare_ipv6_without_brackets() {
        // Occurs in some sockstat outputs. Ambiguous, but multiple colons
        // are treated as IPv6 with the last colon splitting off the port.
        assert_eq!(
            parse_socket_addr_text("::1:8080"),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080))
        );
    }

    #[test]
    fn socket_addr_text_parses_wildcards_as_unspecified() {
        assert_eq!(
            parse_socket_addr_text("*:80"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80))
        );
        assert_eq!(
            parse_socket_addr_text("*:65535"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 65535))
        );
        // sockstat prints a wildcard peer as `*:*`; the port parses as 0 so
        // `remote_if_present` reads the row as "no peer" instead of dropping it.
        assert_eq!(
            parse_socket_addr_text("*:*"),
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        );
        assert_eq!(
            remote_if_present(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
            None
        );
    }

    #[test]
    fn socket_addr_text_rejects_malformed_input() {
        // Missing port
        assert_eq!(parse_socket_addr_text("192.168.1.1"), None);
        // Missing closing bracket
        assert_eq!(parse_socket_addr_text("[::1:8080"), None);
        // Missing ':' after the closing bracket
        assert_eq!(parse_socket_addr_text("[::1]x80"), None);
        // Port out of range
        assert_eq!(parse_socket_addr_text("192.168.1.1:99999"), None);
        assert_eq!(parse_socket_addr_text(""), None);
    }
}
