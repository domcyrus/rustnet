// network/platform/mod.rs - Platform-specific process lookup
//
// Each platform is organized in its own subdirectory with consistent exports:
// - {platform}/mod.rs: create_process_lookup() factory function
// - {platform}/process.rs: ProcessLookup implementation
// - {platform}/interface_stats.rs: InterfaceStatsProvider implementation

use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::net::SocketAddr;

// Platform-specific modules (one cfg per platform instead of many)
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "freebsd")]
mod freebsd;

// Re-export factory functions and types from platform modules
#[cfg(target_os = "linux")]
pub use linux::{create_process_lookup, LinuxStatsProvider};
#[cfg(target_os = "macos")]
pub use macos::{create_process_lookup, MacOSStatsProvider};
#[cfg(target_os = "windows")]
pub use windows::{create_process_lookup, WindowsProcessLookup, WindowsStatsProvider};
#[cfg(target_os = "freebsd")]
pub use freebsd::{create_process_lookup, FreeBSDProcessLookup, FreeBSDStatsProvider};

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
