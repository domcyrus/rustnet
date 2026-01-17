//! Enhanced Linux process lookup combining eBPF and procfs approaches

use crate::network::platform::{ConnectionKey, DegradationReason, ProcessLookup};

use super::process::LinuxProcessLookup;
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[cfg(feature = "ebpf")]
use super::ebpf::EbpfSocketTracker;

// When eBPF is enabled, use the full enhanced implementation
#[cfg(feature = "ebpf")]
mod ebpf_enhanced {
    use super::*;
    use crate::network::types::ProtocolState;

    /// Enhanced process lookup that combines eBPF (fast path) with procfs (fallback)
    pub struct EnhancedLinuxProcessLookup {
        ebpf_tracker: RwLock<Option<Box<EbpfSocketTracker>>>,
        procfs_lookup: LinuxProcessLookup,
        unified_cache: RwLock<ProcessCache>,
        stats: RwLock<LookupStats>,
        cleanup_config: CleanupConfig,
        last_cleanup: RwLock<Instant>,
        degradation_reason: DegradationReason,
    }

    pub struct ProcessCache {
        lookup: HashMap<ConnectionKey, (u32, String)>,
        last_refresh: Instant,
    }

    #[derive(Debug, Clone)]
    pub struct CleanupConfig {
        pub cleanup_interval_secs: u64,
        pub stale_threshold_secs: u64,
    }

    impl Default for CleanupConfig {
        fn default() -> Self {
            Self {
                cleanup_interval_secs: 30,
                stale_threshold_secs: 60,
            }
        }
    }

    #[derive(Debug, Default)]
    pub struct LookupStats {
        ebpf_hits: u64,
        procfs_hits: u64,
        cache_hits: u64,
        total_lookups: u64,
        ipv4_lookups: u64,
        ipv6_lookups: u64,
        tcp_lookups: u64,
        udp_lookups: u64,
        cache_entries: u64,
        failed_lookups: u64,
        ebpf_available: bool,
    }

    impl EnhancedLinuxProcessLookup {
        pub fn new() -> Result<Self> {
            Self::new_with_config(CleanupConfig::default())
        }

        pub fn new_with_config(cleanup_config: CleanupConfig) -> Result<Self> {
            let procfs_lookup = LinuxProcessLookup::new()?;

            let (ebpf_tracker, degradation_reason) = match EbpfSocketTracker::new() {
                Ok((tracker_opt, reason)) => {
                    if tracker_opt.is_some() {
                        info!("eBPF socket tracker initialized successfully");
                    } else {
                        info!(
                            "eBPF not available ({}), using procfs only",
                            reason.description()
                        );
                    }
                    (tracker_opt.map(Box::new), reason)
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize eBPF tracker: {}, falling back to procfs",
                        e
                    );
                    (None, DegradationReason::KernelUnsupported)
                }
            };

            Ok(Self {
                ebpf_tracker: RwLock::new(ebpf_tracker),
                procfs_lookup,
                unified_cache: RwLock::new(ProcessCache {
                    lookup: HashMap::new(),
                    last_refresh: Instant::now() - Duration::from_secs(3600),
                }),
                stats: RwLock::new(LookupStats::default()),
                cleanup_config,
                last_cleanup: RwLock::new(Instant::now() - Duration::from_secs(3600)),
                degradation_reason,
            })
        }

        /// Try eBPF lookup first, fall back to procfs
        fn lookup_process_enhanced(&self, conn: &Connection) -> Option<(u32, String)> {
            // Try eBPF first for TCP/UDP/ICMP connections
            match conn.protocol {
                Protocol::TCP | Protocol::UDP => {
                    debug!(
                        "Enhanced lookup: Trying eBPF for {}:{} -> {}:{} ({})",
                        conn.local_addr.ip(),
                        conn.local_addr.port(),
                        conn.remote_addr.ip(),
                        conn.remote_addr.port(),
                        match conn.protocol {
                            Protocol::TCP => "TCP",
                            Protocol::UDP => "UDP",
                            _ => "Unknown",
                        }
                    );

                    if let Some(result) = self.try_ebpf_lookup(conn) {
                        let mut stats = self.stats.write().unwrap();
                        stats.ebpf_hits += 1;
                        debug!(
                            "Enhanced lookup: eBPF hit for PID {} ({})",
                            result.0, result.1
                        );
                        return Some(result);
                    } else {
                        debug!("Enhanced lookup: eBPF miss, falling back to procfs");
                    }
                }
                Protocol::ICMP => {
                    // Try eBPF lookup for ICMP using the echo ID
                    if let ProtocolState::Icmp {
                        icmp_id: Some(id), ..
                    } = &conn.protocol_state
                    {
                        debug!(
                            "Enhanced lookup: Trying eBPF for ICMP {} -> {} (ID: {})",
                            conn.local_addr.ip(),
                            conn.remote_addr.ip(),
                            id
                        );

                        if let Some(result) = self.try_ebpf_icmp_lookup(conn, *id) {
                            let mut stats = self.stats.write().unwrap();
                            stats.ebpf_hits += 1;
                            debug!(
                                "Enhanced lookup: eBPF ICMP hit for PID {} ({})",
                                result.0, result.1
                            );
                            return Some(result);
                        } else {
                            debug!("Enhanced lookup: eBPF ICMP miss");
                        }
                    }
                }
                _ => {}
            }

            // Fall back to procfs approach
            if let Some(result) = self.procfs_lookup.get_process_for_connection(conn) {
                let mut stats = self.stats.write().unwrap();
                stats.procfs_hits += 1;
                return Some(result);
            }

            None
        }

        fn try_ebpf_lookup(&self, conn: &Connection) -> Option<(u32, String)> {
            let mut tracker_guard = self.ebpf_tracker.write().unwrap();
            let tracker = match tracker_guard.as_mut() {
                Some(t) => {
                    debug!("eBPF lookup: Tracker available, performing lookup");
                    t
                }
                None => {
                    debug!("eBPF lookup: No tracker available");
                    return None;
                }
            };

            let is_tcp = matches!(conn.protocol, Protocol::TCP);

            match tracker.lookup(
                conn.local_addr.ip(),
                conn.remote_addr.ip(),
                conn.local_addr.port(),
                conn.remote_addr.port(),
                is_tcp,
            ) {
                Some(process_info) => {
                    // Try to resolve the correct main process name using the PID.
                    // eBPF captures thread names (e.g., "Socket Thread"), but we want
                    // the main process name (e.g., "firefox"). The procfs cache maps
                    // PIDs to main process names from /proc/<pid>/comm.
                    // For short-lived processes (like curl), the PID won't be in the
                    // cache (process already exited), so we fall back to the eBPF name.
                    let resolved_name = self
                        .procfs_lookup
                        .get_process_name_by_pid(process_info.pid)
                        .unwrap_or_else(|| process_info.comm.clone());

                    debug!(
                        "eBPF lookup successful for {}:{} -> {}:{} - PID: {}, UID: {}, eBPF comm: {}, Resolved: {}, Age: {}ns",
                        conn.local_addr.ip(),
                        conn.local_addr.port(),
                        conn.remote_addr.ip(),
                        conn.remote_addr.port(),
                        process_info.pid,
                        process_info.uid,
                        process_info.comm,
                        resolved_name,
                        process_info.timestamp
                    );
                    Some((process_info.pid, resolved_name))
                }
                None => {
                    debug!(
                        "eBPF lookup missed for {}:{} -> {}:{}",
                        conn.local_addr.ip(),
                        conn.local_addr.port(),
                        conn.remote_addr.ip(),
                        conn.remote_addr.port()
                    );
                    None
                }
            }
        }

        fn try_ebpf_icmp_lookup(&self, conn: &Connection, icmp_id: u16) -> Option<(u32, String)> {
            let mut tracker_guard = self.ebpf_tracker.write().unwrap();
            let tracker = tracker_guard.as_mut()?;

            match tracker.lookup_icmp(conn.local_addr.ip(), conn.remote_addr.ip(), icmp_id) {
                Some(process_info) => {
                    let resolved_name = self
                        .procfs_lookup
                        .get_process_name_by_pid(process_info.pid)
                        .unwrap_or_else(|| process_info.comm.clone());

                    debug!(
                        "eBPF ICMP lookup successful for {} -> {} (ID: {}) - PID: {}, Resolved: {}",
                        conn.local_addr.ip(),
                        conn.remote_addr.ip(),
                        icmp_id,
                        process_info.pid,
                        resolved_name
                    );
                    Some((process_info.pid, resolved_name))
                }
                None => {
                    debug!(
                        "eBPF ICMP lookup missed for {} -> {} (ID: {})",
                        conn.local_addr.ip(),
                        conn.remote_addr.ip(),
                        icmp_id
                    );
                    None
                }
            }
        }

        /// Check if eBPF is available and functioning
        pub fn is_ebpf_available(&self) -> bool {
            self.ebpf_tracker
                .read()
                .unwrap()
                .as_ref()
                .map(|t| t.is_healthy())
                .unwrap_or(false)
        }

        /// Perform periodic cleanup of stale eBPF map entries
        fn maybe_cleanup_ebpf_map(&self) {
            let now = Instant::now();
            let mut last_cleanup = self.last_cleanup.write().unwrap();

            if now.duration_since(*last_cleanup).as_secs()
                >= self.cleanup_config.cleanup_interval_secs
            {
                *last_cleanup = now;
                drop(last_cleanup);

                // Perform cleanup
                if let Some(tracker) = self.ebpf_tracker.write().unwrap().as_mut() {
                    let cleaned =
                        tracker.cleanup_stale_entries(self.cleanup_config.stale_threshold_secs);
                    if cleaned > 0 {
                        debug!("eBPF map cleanup: removed {} stale entries", cleaned);
                    }
                }
            }
        }
    }

    impl ProcessLookup for EnhancedLinuxProcessLookup {
        fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
            // Perform periodic cleanup of stale eBPF entries
            self.maybe_cleanup_ebpf_map();

            let key = ConnectionKey::from_connection(conn);

            // Update protocol statistics
            {
                let mut stats = self.stats.write().unwrap();
                stats.total_lookups += 1;

                // Track IP version
                match conn.local_addr.ip() {
                    IpAddr::V4(_) => stats.ipv4_lookups += 1,
                    IpAddr::V6(_) => stats.ipv6_lookups += 1,
                }

                // Track protocol type
                match conn.protocol {
                    Protocol::TCP => stats.tcp_lookups += 1,
                    Protocol::UDP => stats.udp_lookups += 1,
                    _ => {}
                }

                // Update eBPF availability status
                stats.ebpf_available = self.is_ebpf_available();
            }

            // Try cache first
            {
                let cache = self.unified_cache.read().unwrap();
                if cache.last_refresh.elapsed() < Duration::from_secs(2)
                    && let Some(process_info) = cache.lookup.get(&key)
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.cache_hits += 1;
                    return Some(process_info.clone());
                }
            }

            // Cache miss or stale - do enhanced lookup
            if let Some(result) = self.lookup_process_enhanced(conn) {
                // Update cache with the result
                {
                    let mut cache = self.unified_cache.write().unwrap();
                    cache.lookup.insert(key, result.clone());

                    let mut stats = self.stats.write().unwrap();
                    stats.cache_entries = cache.lookup.len() as u64;
                }
                Some(result)
            } else {
                // Track failed lookups
                let mut stats = self.stats.write().unwrap();
                stats.failed_lookups += 1;
                None
            }
        }

        fn refresh(&self) -> Result<()> {
            // Refresh the procfs lookup
            self.procfs_lookup.refresh()?;

            // Update our cache timestamp
            {
                let mut cache = self.unified_cache.write().unwrap();
                cache.last_refresh = Instant::now();
                // Optionally clear cache to force fresh lookups
                cache.lookup.clear();
            }

            debug!("Enhanced process lookup refreshed");
            Ok(())
        }

        fn get_detection_method(&self) -> &str {
            if self.is_ebpf_available() {
                "eBPF + procfs"
            } else {
                "procfs"
            }
        }

        fn get_degradation_reason(&self) -> DegradationReason {
            self.degradation_reason.clone()
        }
    }

    impl Clone for LookupStats {
        fn clone(&self) -> Self {
            Self {
                ebpf_hits: self.ebpf_hits,
                procfs_hits: self.procfs_hits,
                cache_hits: self.cache_hits,
                total_lookups: self.total_lookups,
                ipv4_lookups: self.ipv4_lookups,
                ipv6_lookups: self.ipv6_lookups,
                tcp_lookups: self.tcp_lookups,
                udp_lookups: self.udp_lookups,
                cache_entries: self.cache_entries,
                failed_lookups: self.failed_lookups,
                ebpf_available: self.ebpf_available,
            }
        }
    }

    impl std::fmt::Display for LookupStats {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.total_lookups == 0 {
                write!(f, "No lookups performed yet")
            } else {
                let cache_hit_rate = (self.cache_hits as f64 / self.total_lookups as f64) * 100.0;
                let ebpf_rate = (self.ebpf_hits as f64 / self.total_lookups as f64) * 100.0;
                let procfs_rate = (self.procfs_hits as f64 / self.total_lookups as f64) * 100.0;
                let success_rate = ((self.total_lookups - self.failed_lookups) as f64
                    / self.total_lookups as f64)
                    * 100.0;

                writeln!(f, "Process Lookup Statistics:")?;
                writeln!(
                    f,
                    "  Total lookups: {} (success: {:.1}%)",
                    self.total_lookups, success_rate
                )?;
                writeln!(
                    f,
                    "  Cache: {} hits ({:.1}%)",
                    self.cache_hits, cache_hit_rate
                )?;
                writeln!(
                    f,
                    "  eBPF: {} lookups ({:.1}%) | Available: {}",
                    self.ebpf_hits, ebpf_rate, self.ebpf_available
                )?;
                writeln!(
                    f,
                    "  procfs: {} lookups ({:.1}%)",
                    self.procfs_hits, procfs_rate
                )?;
                writeln!(
                    f,
                    "  Protocols - IPv4: {} | IPv6: {}",
                    self.ipv4_lookups, self.ipv6_lookups
                )?;
                write!(
                    f,
                    "  Types - TCP: {} | UDP: {} | Cache entries: {}",
                    self.tcp_lookups, self.udp_lookups, self.cache_entries
                )
            }
        }
    }
}

// When eBPF is disabled, use a simpler procfs-only implementation
#[cfg(not(feature = "ebpf"))]
mod procfs_only {
    use super::*;

    /// Simplified process lookup using only procfs (no eBPF)
    pub struct EnhancedLinuxProcessLookup {
        procfs_lookup: LinuxProcessLookup,
        unified_cache: RwLock<ProcessCache>,
        stats: RwLock<LookupStats>,
    }

    // Stub tracker for non-eBPF builds
    pub struct EbpfSocketTracker;

    impl EbpfSocketTracker {
        pub fn new() -> anyhow::Result<Option<Self>> {
            Ok(None)
        }

        pub fn cleanup_stale_entries(&mut self, _stale_threshold_secs: u64) -> u32 {
            0
        }

        pub fn is_healthy(&self) -> bool {
            false
        }
    }

    pub struct ProcessCache {
        lookup: HashMap<ConnectionKey, (u32, String)>,
        last_refresh: Instant,
    }

    #[derive(Debug, Default)]
    pub struct LookupStats {
        procfs_hits: u64,
        cache_hits: u64,
        total_lookups: u64,
        ipv4_lookups: u64,
        ipv6_lookups: u64,
        tcp_lookups: u64,
        udp_lookups: u64,
        cache_entries: u64,
        failed_lookups: u64,
        ebpf_available: bool,
    }

    impl EnhancedLinuxProcessLookup {
        pub fn new() -> Result<Self> {
            Self::new_with_config()
        }

        pub fn new_with_config() -> Result<Self> {
            let procfs_lookup = LinuxProcessLookup::new()?;

            Ok(Self {
                procfs_lookup,
                unified_cache: RwLock::new(ProcessCache {
                    lookup: HashMap::new(),
                    last_refresh: Instant::now() - Duration::from_secs(3600),
                }),
                stats: RwLock::new(LookupStats::default()),
            })
        }

        /// Check if eBPF is available (always false when feature disabled)
        pub fn is_ebpf_available(&self) -> bool {
            false
        }
    }

    impl ProcessLookup for EnhancedLinuxProcessLookup {
        fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
            let key = ConnectionKey::from_connection(conn);

            // Update protocol statistics
            {
                let mut stats = self.stats.write().unwrap();
                stats.total_lookups += 1;

                // Track IP version
                match conn.local_addr.ip() {
                    IpAddr::V4(_) => stats.ipv4_lookups += 1,
                    IpAddr::V6(_) => stats.ipv6_lookups += 1,
                }

                // Track protocol type
                match conn.protocol {
                    Protocol::TCP => stats.tcp_lookups += 1,
                    Protocol::UDP => stats.udp_lookups += 1,
                    _ => {}
                }

                // eBPF is never available in this build
                stats.ebpf_available = false;
            }

            // Try cache first
            {
                let cache = self.unified_cache.read().unwrap();
                if cache.last_refresh.elapsed() < Duration::from_secs(2)
                    && let Some(process_info) = cache.lookup.get(&key)
                {
                    let mut stats = self.stats.write().unwrap();
                    stats.cache_hits += 1;
                    return Some(process_info.clone());
                }
            }

            // Cache miss or stale - use procfs lookup
            if let Some(result) = self.procfs_lookup.get_process_for_connection(conn) {
                // Update cache with the result
                {
                    let mut cache = self.unified_cache.write().unwrap();
                    cache.lookup.insert(key, result.clone());

                    let mut stats = self.stats.write().unwrap();
                    stats.cache_entries = cache.lookup.len() as u64;
                    stats.procfs_hits += 1;
                }
                Some(result)
            } else {
                // Track failed lookups
                let mut stats = self.stats.write().unwrap();
                stats.failed_lookups += 1;
                None
            }
        }

        fn refresh(&self) -> Result<()> {
            // Refresh the procfs lookup
            self.procfs_lookup.refresh()?;

            // Update our cache timestamp
            {
                let mut cache = self.unified_cache.write().unwrap();
                cache.last_refresh = Instant::now();
                // Optionally clear cache to force fresh lookups
                cache.lookup.clear();
            }

            debug!("Enhanced process lookup refreshed");
            Ok(())
        }

        fn get_detection_method(&self) -> &str {
            if self.is_ebpf_available() {
                "eBPF + procfs"
            } else {
                "procfs"
            }
        }

        fn get_degradation_reason(&self) -> DegradationReason {
            // eBPF feature is disabled at compile time
            DegradationReason::EbpfFeatureDisabled
        }
    }

    impl Clone for LookupStats {
        fn clone(&self) -> Self {
            Self {
                procfs_hits: self.procfs_hits,
                cache_hits: self.cache_hits,
                total_lookups: self.total_lookups,
                ipv4_lookups: self.ipv4_lookups,
                ipv6_lookups: self.ipv6_lookups,
                tcp_lookups: self.tcp_lookups,
                udp_lookups: self.udp_lookups,
                cache_entries: self.cache_entries,
                failed_lookups: self.failed_lookups,
                ebpf_available: self.ebpf_available,
            }
        }
    }

    impl std::fmt::Display for LookupStats {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            if self.total_lookups == 0 {
                write!(f, "No lookups performed yet")
            } else {
                let cache_hit_rate = (self.cache_hits as f64 / self.total_lookups as f64) * 100.0;
                let procfs_rate = (self.procfs_hits as f64 / self.total_lookups as f64) * 100.0;
                let success_rate = ((self.total_lookups - self.failed_lookups) as f64
                    / self.total_lookups as f64)
                    * 100.0;

                writeln!(f, "Process Lookup Statistics:")?;
                writeln!(
                    f,
                    "  Total lookups: {} (success: {:.1}%)",
                    self.total_lookups, success_rate
                )?;
                writeln!(
                    f,
                    "  Cache: {} hits ({:.1}%)",
                    self.cache_hits, cache_hit_rate
                )?;
                writeln!(f, "  eBPF: Not available (feature disabled)")?;
                writeln!(
                    f,
                    "  procfs: {} lookups ({:.1}%)",
                    self.procfs_hits, procfs_rate
                )?;
                writeln!(
                    f,
                    "  Protocols - IPv4: {} | IPv6: {}",
                    self.ipv4_lookups, self.ipv6_lookups
                )?;
                write!(
                    f,
                    "  Types - TCP: {} | UDP: {} | Cache entries: {}",
                    self.tcp_lookups, self.udp_lookups, self.cache_entries
                )
            }
        }
    }
}

// Re-export the appropriate implementation based on feature flag
#[cfg(feature = "ebpf")]
pub use ebpf_enhanced::*;

#[cfg(not(feature = "ebpf"))]
pub use procfs_only::*;
