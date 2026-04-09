// network/platform/mod.rs - Platform-specific process lookup
//
// Each platform is organized in its own subdirectory with consistent exports:
// - {platform}/mod.rs: create_process_lookup() factory function
// - {platform}/process.rs: ProcessLookup implementation
// - {platform}/interface_stats.rs: InterfaceStatsProvider implementation

use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
    /// Missing both CAP_BPF and CAP_PERFMON (and no CAP_SYS_ADMIN fallback)
    #[cfg(target_os = "linux")]
    MissingBpfCapabilities,
    /// eBPF feature not compiled in
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    EbpfFeatureDisabled,
    /// Kernel doesn't support required eBPF features
    #[cfg(target_os = "linux")]
    KernelUnsupported,
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
}

impl DegradationReason {
    /// Get human-readable description of what's needed
    pub fn description(&self) -> &str {
        match self {
            Self::None => "",
            #[cfg(target_os = "linux")]
            Self::MissingCapBpf => "needs CAP_BPF",
            #[cfg(target_os = "linux")]
            Self::MissingCapPerfmon => "needs CAP_PERFMON",
            #[cfg(target_os = "linux")]
            Self::MissingBpfCapabilities => "needs CAP_BPF+CAP_PERFMON",
            #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
            Self::EbpfFeatureDisabled => "eBPF feature disabled",
            #[cfg(target_os = "linux")]
            Self::KernelUnsupported => "kernel unsupported",
            #[cfg(target_os = "macos")]
            Self::MissingRootPrivileges => "needs root",
            #[cfg(target_os = "macos")]
            Self::NoBpfDeviceAccess => "no BPF device access",
            #[cfg(target_os = "macos")]
            Self::BpfFilterIncompatible => "BPF filter incompatible",
            #[cfg(target_os = "macos")]
            Self::InterfaceSpecified => "interface specified",
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
            | Self::KernelUnsupported => Some("eBPF"),
            #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
            Self::EbpfFeatureDisabled => Some("eBPF"),
            #[cfg(target_os = "macos")]
            Self::MissingRootPrivileges
            | Self::NoBpfDeviceAccess
            | Self::BpfFilterIncompatible
            | Self::InterfaceSpecified => Some("PKTAP"),
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

// Re-export factory functions and types from platform modules
#[cfg(target_os = "freebsd")]
pub use freebsd::{FreeBSDStatsProvider, create_process_lookup};
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub use linux::sandbox;
#[cfg(target_os = "linux")]
pub use linux::{LinuxStatsProvider, create_process_lookup};
#[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
pub use macos::sandbox;
#[cfg(target_os = "macos")]
pub use macos::{MacOSStatsProvider, create_process_lookup};
#[cfg(target_os = "windows")]
pub use windows::sandbox;
#[cfg(target_os = "windows")]
pub use windows::{WindowsStatsProvider, create_process_lookup};

/// Trait for platform-specific process lookup
pub trait ProcessLookup: Send + Sync {
    /// Look up process information for a connection
    /// Returns (pid, process_name) if found
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)>;

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

    /// Fallback lookup that relaxes the connection key to handle sockets stored with
    /// wildcard addresses in OS-level tables.
    ///
    /// Three shapes that actually appear in OS socket tables:
    ///   1. (lip:lport, 0:0)      — listening on a specific local IP
    ///   2. (0:lport,  rip:rport) — INADDR_ANY socket connected to a known remote
    ///   3. (0:lport,  0:0)       — listening on INADDR_ANY
    ///
    /// If two candidates resolve to different processes the result is ambiguous and
    /// `None` is returned to avoid mis-attribution.
    fn fallback_lookup(
        map: &HashMap<ConnectionKey, (u32, String)>,
        key: &ConnectionKey,
    ) -> Option<(u32, String)>
    where
        Self: Sized,
    {
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

        let candidates: [(IpAddr, u16, IpAddr, u16); 3] = [
            (lip, lport, zrip, 0),     // 1. listening on specific local IP
            (zlip, lport, rip, rport), // 2. INADDR_ANY with known remote
            (zlip, lport, zrip, 0),    // 3. INADDR_ANY listener
        ];

        // Collect all matches across every candidate. If two candidates resolve to
        // different processes the result is ambiguous — return nothing to avoid
        // attributing traffic to the wrong process.
        let mut found: Option<(u32, String)> = None;
        for (l_ip, l_port, r_ip, r_port) in candidates {
            let candidate = ConnectionKey {
                protocol: key.protocol,
                local_addr: SocketAddr::new(l_ip, l_port),
                remote_addr: SocketAddr::new(r_ip, r_port),
            };
            if let Some(entry) = map.get(&candidate) {
                match &found {
                    None => found = Some(entry.clone()),
                    Some(existing) if existing == entry => {} // same result, no conflict
                    Some(_) => return None,                   // two different processes → ambiguous
                }
            }
        }
        found
    }
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
