// network/platform/mod.rs - Platform process lookup
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::net::SocketAddr;

// Platform-specific modules
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// Re-export the appropriate implementation
#[cfg(target_os = "linux")]
pub use linux::LinuxProcessLookup;
#[cfg(target_os = "macos")]
pub use macos::MacOSProcessLookup;
#[cfg(target_os = "windows")]
pub use windows::WindowsProcessLookup;

/// Trait for platform-specific process lookup
pub trait ProcessLookup: Send + Sync {
    /// Look up process information for a connection
    /// Returns (pid, process_name) if found
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)>;

    /// Refresh internal caches if any (best-effort)
    fn refresh(&self) -> Result<()> {
        Ok(()) // Default no-op
    }
}

/// No-op process lookup for when PKTAP is providing process metadata
pub struct NoOpProcessLookup;

impl ProcessLookup for NoOpProcessLookup {
    fn get_process_for_connection(&self, _conn: &Connection) -> Option<(u32, String)> {
        None // PKTAP provides this information directly
    }

    fn refresh(&self) -> Result<()> {
        Ok(()) // Nothing to refresh
    }
}

/// Create a platform-specific process lookup with PKTAP status awareness
pub fn create_process_lookup_with_pktap_status(
    pktap_active: bool,
) -> Result<Box<dyn ProcessLookup>> {
    #[cfg(target_os = "macos")]
    if pktap_active {
        log::info!("Using no-op process lookup - PKTAP provides process metadata");
        return Ok(Box::new(NoOpProcessLookup));
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(LinuxProcessLookup::new()?))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsProcessLookup::new()?))
    }

    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(MacOSProcessLookup::new()?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("Unsupported platform"))
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
