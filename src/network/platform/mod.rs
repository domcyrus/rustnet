// network/platform/mod.rs - Platform process lookup
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::net::SocketAddr;

// Platform-specific modules
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux_ebpf;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux_enhanced;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// Re-export the appropriate implementation
#[cfg(target_os = "linux")]
pub use linux::LinuxProcessLookup;
#[cfg(target_os = "linux")]
// pub use linux_enhanced::EnhancedLinuxProcessLookup;
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

    /// Get the detection method name for display purposes
    fn get_detection_method(&self) -> &str;
}

/// No-op process lookup for when PKTAP is providing process metadata
#[cfg(target_os = "macos")]
pub struct NoOpProcessLookup;

#[cfg(target_os = "macos")]
impl ProcessLookup for NoOpProcessLookup {
    fn get_process_for_connection(&self, _conn: &Connection) -> Option<(u32, String)> {
        None // PKTAP provides this information directly
    }

    fn refresh(&self) -> Result<()> {
        Ok(()) // Nothing to refresh
    }

    fn get_detection_method(&self) -> &str {
        "pktap"
    }
}

/// Create a platform-specific process lookup with PKTAP status awareness
pub fn create_process_lookup_with_pktap_status(
    _pktap_active: bool,
) -> Result<Box<dyn ProcessLookup>> {
    #[cfg(target_os = "macos")]
    {
        use crate::network::platform::macos::MacOSProcessLookup;

        if _pktap_active {
            log::info!("Using no-op process lookup - PKTAP provides process metadata");
            Ok(Box::new(NoOpProcessLookup))
        } else {
            Ok(Box::new(MacOSProcessLookup::new()?))
        }
    }

    #[cfg(target_os = "linux")]
    {
        #[cfg(feature = "ebpf")]
        {
            // Try enhanced lookup first (with eBPF if available), fall back to basic
            match linux_enhanced::EnhancedLinuxProcessLookup::new() {
                Ok(enhanced) => {
                    log::info!("Using enhanced Linux process lookup (eBPF + procfs)");
                    return Ok(Box::new(enhanced));
                }
                Err(e) => {
                    log::warn!(
                        "Enhanced lookup failed, falling back to basic procfs: {}",
                        e
                    );
                }
            }
        }
        // Use basic procfs lookup (either as fallback or when eBPF is not enabled)
        Ok(Box::new(LinuxProcessLookup::new()?))
    }

    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(WindowsProcessLookup::new()?))
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        Err(anyhow::anyhow!("Unsupported platform"))
    }
}

/// Create a basic process lookup (procfs only on Linux) - for testing or fallback
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn create_basic_process_lookup() -> Result<Box<dyn ProcessLookup>> {
    Ok(Box::new(LinuxProcessLookup::new()?))
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
