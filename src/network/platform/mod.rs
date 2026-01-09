// network/platform/mod.rs - Platform-specific process lookup
//
// Each platform is organized in its own subdirectory with consistent exports:
// - {platform}/mod.rs: create_process_lookup() factory function
// - {platform}/process.rs: ProcessLookup implementation
// - {platform}/interface_stats.rs: InterfaceStatsProvider implementation

use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::net::SocketAddr;

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
pub use freebsd::{FreeBSDProcessLookup, FreeBSDStatsProvider, create_process_lookup};
#[cfg(all(target_os = "linux", feature = "landlock"))]
pub use linux::sandbox;
#[cfg(target_os = "linux")]
pub use linux::{LinuxStatsProvider, create_process_lookup};
#[cfg(target_os = "macos")]
pub use macos::{MacOSStatsProvider, create_process_lookup};
#[cfg(target_os = "windows")]
pub use windows::{WindowsProcessLookup, WindowsStatsProvider, create_process_lookup};

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
