//! # rustnet-host
//!
//! Per-connection **process attribution** for
//! [RustNet](https://github.com/domcyrus/rustnet): given a [`Connection`], find
//! the owning process (pid + name). Each platform uses its best available
//! strategy behind one [`ProcessLookup`] trait, selected by
//! [`create_process_lookup`]:
//!
//! - **Linux** — eBPF socket tracking (with the `ebpf` feature) and a procfs
//!   fallback.
//! - **macOS** — PKTAP packet metadata when available (capture provides it
//!   directly, so lookup is a no-op), otherwise `lsof`.
//! - **Windows** — kernel ETW events with an IP Helper API
//!   (`GetExtendedTcpTable`/`...UdpTable`) fallback.
//! - **FreeBSD** — `sockstat`.
//!
//! [`ProcessLookup::get_process_attribution`] returns the richer
//! [`ProcessAttribution`]: thread id, effective UID/GID, executable path, the
//! producing [`AttributionBackend`], a [`MatchQuality`] saying how the
//! connection was matched, and a monotonic observation time. Platforms that
//! only implement the tuple API are bridged automatically, so
//! `get_process_for_connection` keeps working everywhere.
//!
//! When a platform can't use its optimal method, [`ProcessLookup::get_degradation_reason`]
//! reports why via [`DegradationReason`] (e.g. missing `CAP_BPF`, no root for
//! PKTAP), which front-ends can surface to the user.
//!
//! This crate depends only on `rustnet-core` (for [`Connection`]/[`Protocol`]).
//! It does not depend on `rustnet-capture`; on macOS the application injects
//! whether PKTAP is active (via `report_pktap_degradation`) rather than this
//! crate querying capture. It has no UI or capture-loop dependency, so headless
//! tools can attribute processes the same way the `rustnet` TUI does.

use anyhow::Result;
use rustnet_core::network::types::{Connection, Protocol};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

/// Active process-attribution backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AttributionBackend {
    /// Linux BPF trampoline programs using fentry and fexit.
    EbpfFentry,
    /// Linux legacy kprobe and kretprobe programs.
    EbpfKprobe,
    /// Linux procfs socket-table scanning.
    Procfs,
    /// A platform-native backend outside the Linux eBPF stack.
    #[default]
    PlatformNative,
}

impl std::fmt::Display for AttributionBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::EbpfFentry => "eBPF fentry/fexit",
            Self::EbpfKprobe => "eBPF kprobe",
            Self::Procfs => "procfs",
            Self::PlatformNative => "platform native",
        };
        f.write_str(name)
    }
}

bitflags::bitflags! {
    /// Connection operations covered by the active Linux eBPF backend.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AttributionCapabilities: u32 {
        const TCP_V4_CONNECT = 1 << 0;
        const TCP_V6_CONNECT = 1 << 1;
        const TCP_ACCEPT     = 1 << 2;
        const UDP_V4_SEND    = 1 << 3;
        const UDP_V6_SEND    = 1 << 4;
        const ICMP_V4_SEND   = 1 << 5;
        const ICMP_V6_SEND   = 1 << 6;
    }
}

/// How closely an attribution result matched the connection it was asked about.
///
/// Backends record sockets under the tuple they saw at creation time, which is
/// not always the tuple the capture side observes on the wire. A lookup may
/// therefore have to relax the key, and the caller deserves to know that it
/// did: a relaxed hit is a plausible owner, not a proven one.
///
/// Marked `#[non_exhaustive]` so new relaxation shapes can be added without
/// breaking downstream `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatchQuality {
    /// The full 4-tuple matched a recorded socket.
    ExactTuple,
    /// Matched only after zeroing the local address, i.e. the socket was
    /// recorded while bound to a wildcard address.
    WildcardLocalAddress,
    /// Matched a listening socket (the recorded entry has no remote peer).
    ListenerSocket,
    /// Exact 4-tuple match in the procfs socket table.
    ProcfsExact,
    /// procfs match that needed a relaxed key.
    ProcfsRelaxed,
    /// The backend reported an owner but not how it matched. Produced by the
    /// compatibility bridge in [`ProcessLookup::get_process_attribution`] for
    /// platforms that still only implement the tuple API.
    Unspecified,
}

impl MatchQuality {
    /// Whether the connection's exact 4-tuple was found, with no relaxation.
    pub fn is_exact(self) -> bool {
        matches!(self, Self::ExactTuple | Self::ProcfsExact)
    }
}

impl std::fmt::Display for MatchQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::ExactTuple => "exact tuple",
            Self::WildcardLocalAddress => "wildcard local address",
            Self::ListenerSocket => "listener socket",
            Self::ProcfsExact => "procfs exact",
            Self::ProcfsRelaxed => "procfs relaxed",
            Self::Unspecified => "unspecified",
        };
        f.write_str(name)
    }
}

/// A rich process-attribution result.
///
/// Everything past `tgid`/`name` is best effort: a backend fills in what it
/// actually observed and leaves the rest `None` rather than guessing. Only the
/// Linux eBPF backends currently report thread ids, credentials, and an
/// observation timestamp.
///
/// Marked `#[non_exhaustive]` because cgroup and container fields are expected
/// to land here later. Build values with [`ProcessAttribution::new`] plus the
/// `with_*` methods instead of a struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessAttribution {
    /// Thread group id, i.e. the PID as user space understands it.
    pub tgid: u32,
    /// Kernel thread id that performed the operation, when the backend sees
    /// per-thread identity. `None` for socket-table backends, and equal to
    /// `tgid` when the main thread did the work.
    pub tid: Option<u32>,
    /// Process name: `/proc/<tgid>/comm` on Linux, the OS-reported name elsewhere.
    pub name: String,
    /// Effective user id of the owning process.
    pub uid: Option<u32>,
    /// Effective group id of the owning process.
    pub gid: Option<u32>,
    /// Absolute executable path, resolved once at attribution time. `None` when
    /// the process already exited or the path is unreadable.
    pub executable: Option<PathBuf>,
    /// Backend that produced this result.
    pub backend: AttributionBackend,
    /// How the connection key matched the backend's records.
    pub quality: MatchQuality,
    /// Observation time in nanoseconds on a **monotonic** clock
    /// (`CLOCK_MONOTONIC` on Linux). This is not wall-clock time: it is only
    /// meaningful relative to other monotonic readings from the same boot, and
    /// must never be formatted as a date.
    pub observed_at_ns: Option<u64>,
}

impl ProcessAttribution {
    /// Create an attribution with only the fields every backend can supply.
    pub fn new(
        tgid: u32,
        name: impl Into<String>,
        backend: AttributionBackend,
        quality: MatchQuality,
    ) -> Self {
        Self {
            tgid,
            tid: None,
            name: name.into(),
            uid: None,
            gid: None,
            executable: None,
            backend,
            quality,
            observed_at_ns: None,
        }
    }

    /// Attach the kernel thread id that performed the operation.
    pub fn with_tid(mut self, tid: u32) -> Self {
        self.tid = Some(tid);
        self
    }

    /// Attach the effective user and group id.
    pub fn with_credentials(mut self, uid: u32, gid: u32) -> Self {
        self.uid = Some(uid);
        self.gid = Some(gid);
        self
    }

    /// Attach the resolved executable path. `None` is a valid outcome and is
    /// stored as such: failing to read the path never fails the attribution.
    pub fn with_executable(mut self, executable: Option<PathBuf>) -> Self {
        self.executable = executable;
        self
    }

    /// Attach a **monotonic** observation timestamp in nanoseconds.
    pub fn with_observed_at_ns(mut self, observed_at_ns: u64) -> Self {
        self.observed_at_ns = Some(observed_at_ns);
        self
    }

    /// Reduce to the legacy `(pid, process_name)` pair.
    pub fn into_pid_name(self) -> (u32, String) {
        (self.tgid, self.name)
    }
}

impl From<ProcessAttribution> for (u32, String) {
    fn from(attribution: ProcessAttribution) -> Self {
        attribution.into_pid_name()
    }
}

/// Reasons why process detection may be degraded from optimal
#[derive(Debug, Clone, PartialEq, Default)]
pub enum DegradationReason {
    /// No degradation - optimal method available
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
    /// eBPF feature not compiled in
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    EbpfFeatureDisabled,
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
    /// Get human-readable description of what's needed
    pub fn description(&self) -> Cow<'_, str> {
        match self {
            Self::None => Cow::Borrowed(""),
            #[cfg(target_os = "linux")]
            Self::MissingCapBpf => Cow::Borrowed("needs CAP_BPF"),
            #[cfg(target_os = "linux")]
            Self::MissingCapPerfmon => Cow::Borrowed("needs CAP_PERFMON"),
            #[cfg(target_os = "linux")]
            Self::MissingBpfCapabilities => Cow::Borrowed("needs CAP_BPF+CAP_PERFMON"),
            #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
            Self::EbpfFeatureDisabled => Cow::Borrowed("eBPF feature disabled"),
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

    /// Get the name of the unavailable feature
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
            #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
            Self::EbpfFeatureDisabled => Some("eBPF"),
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

// Platform-specific modules (one cfg per platform instead of many)
#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// Re-export the per-platform process-lookup factory.
#[cfg(target_os = "freebsd")]
pub use freebsd::create_process_lookup;
#[cfg(target_os = "linux")]
pub use linux::create_process_lookup;
#[cfg(target_os = "macos")]
pub use macos::{create_process_lookup, report_pktap_degradation};
#[cfg(target_os = "windows")]
pub use windows::create_process_lookup;

/// Trait for platform-specific process lookup
pub trait ProcessLookup: Send + Sync {
    /// Look up process information for a connection
    /// Returns (pid, process_name) if found
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)>;

    /// Rich attribution for a connection: identity, credentials, executable
    /// path, and the provenance of the match.
    ///
    /// The default implementation bridges the legacy tuple returned by
    /// [`ProcessLookup::get_process_for_connection`], so platforms that have
    /// not been ported keep working unchanged. It reports
    /// [`MatchQuality::Unspecified`] because the tuple API carries no
    /// provenance, and never claims an exact match it cannot prove.
    ///
    /// Overriding is only half the contract: an implementation whose
    /// `get_process_for_connection` delegates *to this method* **must** also
    /// override this method, otherwise the two default paths call each other
    /// forever.
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (tgid, name) = self.get_process_for_connection(conn)?;
        Some(ProcessAttribution::new(
            tgid,
            name,
            self.get_attribution_backend(),
            MatchQuality::Unspecified,
        ))
    }

    /// Refresh internal caches if any (best-effort)
    fn refresh(&self) -> Result<()> {
        Ok(()) // Default no-op
    }

    /// Get the detection method name for display purposes
    fn get_detection_method(&self) -> &str;

    /// Get the reason why process detection is degraded (if any)
    /// Returns DegradationReason::None if using optimal detection method
    fn get_degradation_reason(&self) -> DegradationReason {
        DegradationReason::None // Default: no degradation
    }

    /// Return the active attribution backend.
    fn get_attribution_backend(&self) -> AttributionBackend {
        AttributionBackend::PlatformNative
    }

    /// Return the connection operations covered by the active eBPF backend.
    ///
    /// Non-eBPF backends return an empty set.
    fn get_attribution_capabilities(&self) -> AttributionCapabilities {
        AttributionCapabilities::empty()
    }

    /// Fallback lookup that relaxes the connection key to handle sockets stored
    /// with wildcard addresses in OS-level tables.
    ///
    /// Thin wrapper over [`relaxed_lookup`] for callers that only want the
    /// owner and not the match provenance.
    fn fallback_lookup(
        map: &HashMap<ConnectionKey, (u32, String)>,
        key: &ConnectionKey,
    ) -> Option<(u32, String)>
    where
        Self: Sized,
    {
        relaxed_lookup(map, key).map(|(entry, _quality)| entry.clone())
    }
}

/// Match a connection key against an OS socket table keyed by exact 4-tuples,
/// progressively relaxing the key, and report which shape matched.
///
/// Three shapes actually appear in OS socket tables:
///   1. (0:lport,  rip:rport) — wildcard-bound socket with a known remote
///   2. (lip:lport, 0:0)      — listening on a specific local IP
///   3. (0:lport,  0:0)       — listening on the wildcard address
///
/// Candidates are tried most-specific first, so the reported
/// [`MatchQuality`] describes the tightest shape that matched.
///
/// Every candidate is still probed even after a hit: if two candidates resolve
/// to *different* owners the answer is ambiguous and `None` is returned rather
/// than a coin flip. Candidates that agree are not a conflict.
pub fn relaxed_lookup<'map, V: PartialEq>(
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
                Some(_) => return None, // two different processes → ambiguous
            }
        }
    }
    found
}

/// Connection identifier for lookups
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionKey {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl ConnectionKey {
    pub fn from_connection(conn: &Connection) -> Self {
        Self {
            protocol: conn.protocol,
            local_addr: conn.local_addr,
            remote_addr: conn.remote_addr,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnet_core::network::types::{ProtocolState, TcpState};
    use std::path::Path;

    fn connection(local: &str, remote: &str) -> Connection {
        Connection::new(
            Protocol::Tcp,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    fn key(protocol: Protocol, local: &str, remote: &str) -> ConnectionKey {
        ConnectionKey {
            protocol,
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
        }
    }

    fn owner(pid: u32, name: &str) -> (u32, String) {
        (pid, name.to_string())
    }

    /// A platform that only implements the legacy tuple API, standing in for
    /// the macOS/Windows/FreeBSD lookups.
    struct LegacyOnlyLookup {
        result: Option<(u32, String)>,
    }

    impl ProcessLookup for LegacyOnlyLookup {
        fn get_process_for_connection(&self, _conn: &Connection) -> Option<(u32, String)> {
            self.result.clone()
        }

        fn get_detection_method(&self) -> &str {
            "legacy"
        }
    }

    #[test]
    fn attribution_reduces_to_the_legacy_pid_and_name_pair() {
        let attribution = ProcessAttribution::new(
            42,
            "curl",
            AttributionBackend::EbpfFentry,
            MatchQuality::ExactTuple,
        )
        .with_tid(43)
        .with_credentials(1000, 100)
        .with_executable(Some(PathBuf::from("/usr/bin/curl")))
        .with_observed_at_ns(9_000);

        assert_eq!(attribution.tid, Some(43));
        assert_eq!(attribution.uid, Some(1000));
        assert_eq!(attribution.gid, Some(100));
        assert_eq!(
            attribution.executable.as_deref(),
            Some(Path::new("/usr/bin/curl"))
        );
        assert_eq!(attribution.observed_at_ns, Some(9_000));

        let (pid, name) = <(u32, String)>::from(attribution);
        assert_eq!(pid, 42);
        assert_eq!(name, "curl");
    }

    #[test]
    fn attribution_leaves_unobserved_fields_empty() {
        let attribution = ProcessAttribution::new(
            7,
            "sshd",
            AttributionBackend::Procfs,
            MatchQuality::ProcfsExact,
        )
        .with_executable(None);

        assert_eq!(attribution.tid, None);
        assert_eq!(attribution.uid, None);
        assert_eq!(attribution.gid, None);
        assert_eq!(attribution.executable, None);
        assert_eq!(attribution.observed_at_ns, None);
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
    fn default_rich_lookup_bridges_the_legacy_tuple_without_claiming_an_exact_match() {
        let lookup = LegacyOnlyLookup {
            result: Some(owner(99, "Safari")),
        };

        let attribution = lookup
            .get_process_attribution(&connection("192.168.1.10:5000", "1.1.1.1:443"))
            .expect("legacy tuple must bridge to an attribution");

        assert_eq!(attribution.tgid, 99);
        assert_eq!(attribution.name, "Safari");
        assert_eq!(attribution.backend, AttributionBackend::PlatformNative);
        // The tuple API carries no provenance, so the bridge must not pretend
        // the exact 4-tuple was proven.
        assert_eq!(attribution.quality, MatchQuality::Unspecified);
        assert!(!attribution.quality.is_exact());
        assert_eq!(attribution.tid, None);
        assert_eq!(attribution.executable, None);
    }

    #[test]
    fn default_rich_lookup_propagates_a_legacy_miss() {
        let lookup = LegacyOnlyLookup { result: None };
        assert!(
            lookup
                .get_process_attribution(&connection("192.168.1.10:5000", "1.1.1.1:443"))
                .is_none()
        );
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
    fn fallback_lookup_still_returns_the_plain_tuple() {
        let mut map = HashMap::new();
        map.insert(
            key(Protocol::Tcp, "0.0.0.0:22", "0.0.0.0:0"),
            owner(17, "sshd"),
        );

        assert_eq!(
            LegacyOnlyLookup::fallback_lookup(
                &map,
                &key(Protocol::Tcp, "192.168.1.10:22", "203.0.113.5:51000")
            ),
            Some(owner(17, "sshd"))
        );
    }
}
