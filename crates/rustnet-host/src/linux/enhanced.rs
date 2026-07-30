//! Enhanced Linux process lookup combining eBPF and procfs approaches

use crate::{
    AttributionBackend, AttributionCapabilities, ConnectionKey, DegradationReason,
    ProcessAttribution, ProcessLookup,
};

use super::process::LinuxProcessLookup;
use anyhow::Result;
use log::{debug, info, warn};
use rustnet_core::network::types::{Connection, Protocol};
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
    use crate::linux::ebpf::SocketMatch;
    use crate::linux::process::{resolve_executable, resolve_parent_pid};
    use rustnet_core::network::types::ProtocolState;

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
        // Full attributions, not just (pid, name): caching the tuple would drop
        // the credentials, thread id, executable path, and match quality on the
        // first hit and silently downgrade every subsequent lookup.
        lookup: HashMap<ConnectionKey, ProcessAttribution>,
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
                    (None, DegradationReason::EbpfLoadFailed(e.to_string()))
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
        fn lookup_process_enhanced(&self, conn: &Connection) -> Option<ProcessAttribution> {
            // Try eBPF first for TCP/UDP/ICMP connections
            match conn.protocol {
                Protocol::Tcp | Protocol::Udp => {
                    debug!(
                        "Enhanced lookup: Trying eBPF for {}:{} -> {}:{} ({})",
                        conn.local_addr.ip(),
                        conn.local_addr.port(),
                        conn.remote_addr.ip(),
                        conn.remote_addr.port(),
                        match conn.protocol {
                            Protocol::Tcp => "TCP",
                            Protocol::Udp => "UDP",
                            _ => "Unknown",
                        }
                    );

                    if let Some(result) = self.try_ebpf_lookup(conn) {
                        let mut stats = self.stats.write().expect("stats lock poisoned");
                        stats.ebpf_hits += 1;
                        debug!(
                            "Enhanced lookup: eBPF hit for PID {} ({}, {} match)",
                            result.tgid, result.name, result.quality
                        );
                        return Some(result);
                    } else {
                        debug!("Enhanced lookup: eBPF miss, falling back to procfs");
                    }
                }
                Protocol::Icmp => {
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
                            let mut stats = self.stats.write().expect("stats lock poisoned");
                            stats.ebpf_hits += 1;
                            debug!(
                                "Enhanced lookup: eBPF ICMP hit for PID {} ({}, {} match)",
                                result.tgid, result.name, result.quality
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
            if let Some(result) = self.procfs_lookup.get_process_attribution(conn) {
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.procfs_hits += 1;
                return Some(result);
            }

            None
        }

        /// Turn a socket-map hit into a rich attribution.
        ///
        /// Everything the kernel recorded is carried through unchanged: TGID,
        /// TID, credentials, and the monotonic observation timestamp. The
        /// process name, parent PID, and executable path are resolved in user
        /// space.
        fn attribution_from_ebpf(
            &self,
            matched: SocketMatch,
            backend: AttributionBackend,
        ) -> ProcessAttribution {
            let SocketMatch { info, quality } = matched;

            // eBPF captures the group leader's short comm at socket creation.
            // /proc/<tgid>/comm is the current main-process name and wins when
            // the process is still alive. Short-lived tools (curl, dig) have
            // already exited by the time we look, so the eBPF comm is the
            // fallback rather than the other way round.
            let name = self
                .procfs_lookup
                .get_process_name_by_pid(info.pid)
                .unwrap_or_else(|| info.comm.clone());

            // Resolve the executable now, while the process is most likely
            // still around. Failure is not an attribution failure.
            let executable = resolve_executable(info.pid);
            let ppid = resolve_parent_pid(info.pid);

            debug!(
                "eBPF attribution: TGID {}, PPID {:?}, TID {}, UID {}, GID {}, eBPF comm {}, resolved {}, exe {:?}, {} match, observed {}ns (monotonic)",
                info.pid,
                ppid,
                info.tid,
                info.uid,
                info.gid,
                info.comm,
                name,
                executable,
                quality,
                info.timestamp
            );

            let mut attribution = ProcessAttribution::new(info.pid, name, backend, quality)
                .with_tid(info.tid)
                .with_credentials(info.uid, info.gid)
                .with_executable(executable)
                .with_observed_at_ns(info.timestamp);
            if let Some(ppid) = ppid {
                attribution = attribution.with_parent_pid(ppid);
            }
            attribution
        }

        fn try_ebpf_lookup(&self, conn: &Connection) -> Option<ProcessAttribution> {
            // Scoped so the tracker write lock is released before
            // attribution_from_ebpf touches /proc. Note `backend()` is read
            // here rather than via get_attribution_backend(), which would take
            // the same non-reentrant lock again.
            let (matched, backend) = {
                let mut tracker_guard = self
                    .ebpf_tracker
                    .write()
                    .expect("ebpf_tracker lock poisoned");
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

                let is_tcp = matches!(conn.protocol, Protocol::Tcp);
                let backend = tracker.backend();

                match tracker.lookup(
                    conn.local_addr.ip(),
                    conn.remote_addr.ip(),
                    conn.local_addr.port(),
                    conn.remote_addr.port(),
                    is_tcp,
                ) {
                    Some(matched) => (matched, backend),
                    None => {
                        debug!(
                            "eBPF lookup missed for {}:{} -> {}:{}",
                            conn.local_addr.ip(),
                            conn.local_addr.port(),
                            conn.remote_addr.ip(),
                            conn.remote_addr.port()
                        );
                        return None;
                    }
                }
            };

            Some(self.attribution_from_ebpf(matched, backend))
        }

        fn try_ebpf_icmp_lookup(
            &self,
            conn: &Connection,
            icmp_id: u16,
        ) -> Option<ProcessAttribution> {
            let (matched, backend) = {
                let mut tracker_guard = self
                    .ebpf_tracker
                    .write()
                    .expect("ebpf_tracker lock poisoned");
                let tracker = tracker_guard.as_mut()?;
                let backend = tracker.backend();

                match tracker.lookup_icmp(conn.local_addr.ip(), conn.remote_addr.ip(), icmp_id) {
                    Some(matched) => (matched, backend),
                    None => {
                        debug!(
                            "eBPF ICMP lookup missed for {} -> {} (ID: {})",
                            conn.local_addr.ip(),
                            conn.remote_addr.ip(),
                            icmp_id
                        );
                        return None;
                    }
                }
            };

            Some(self.attribution_from_ebpf(matched, backend))
        }

        /// Seed the unified cache with a ready-made attribution and mark it
        /// fresh, so cache-preservation behaviour can be tested without a
        /// loaded eBPF backend.
        #[cfg(test)]
        fn seed_cache(&self, key: ConnectionKey, attribution: ProcessAttribution) {
            let mut cache = self
                .unified_cache
                .write()
                .expect("unified_cache lock poisoned");
            cache.last_refresh = Instant::now();
            cache.lookup.insert(key, attribution);
        }

        /// Check if eBPF is available and functioning
        pub fn is_ebpf_available(&self) -> bool {
            self.ebpf_tracker
                .read()
                .expect("ebpf_tracker lock poisoned")
                .as_ref()
                .map(|t| t.is_healthy())
                .unwrap_or(false)
        }

        /// Perform periodic cleanup of stale eBPF map entries
        fn maybe_cleanup_ebpf_map(&self) {
            let now = Instant::now();
            let mut last_cleanup = self
                .last_cleanup
                .write()
                .expect("last_cleanup lock poisoned");

            if now.duration_since(*last_cleanup).as_secs()
                >= self.cleanup_config.cleanup_interval_secs
            {
                *last_cleanup = now;
                drop(last_cleanup);

                // Perform cleanup
                if let Some(tracker) = self
                    .ebpf_tracker
                    .write()
                    .expect("ebpf_tracker lock poisoned")
                    .as_mut()
                {
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
            // Safe because get_process_attribution is overridden below: this
            // does not fall through to the trait's default bridge.
            self.get_process_attribution(conn).map(Into::into)
        }

        fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
            // Perform periodic cleanup of stale eBPF entries
            self.maybe_cleanup_ebpf_map();

            let key = ConnectionKey::from_connection(conn);

            // Update protocol statistics
            {
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.total_lookups += 1;

                // Track IP version
                match conn.local_addr.ip() {
                    IpAddr::V4(_) => stats.ipv4_lookups += 1,
                    IpAddr::V6(_) => stats.ipv6_lookups += 1,
                }

                // Track protocol type
                match conn.protocol {
                    Protocol::Tcp => stats.tcp_lookups += 1,
                    Protocol::Udp => stats.udp_lookups += 1,
                    _ => {}
                }

                // Update eBPF availability status
                stats.ebpf_available = self.is_ebpf_available();
            }

            // Try cache first
            {
                let cache = self
                    .unified_cache
                    .read()
                    .expect("unified_cache lock poisoned");
                if cache.last_refresh.elapsed() < Duration::from_secs(2)
                    && let Some(attribution) = cache.lookup.get(&key)
                {
                    let mut stats = self.stats.write().expect("stats lock poisoned");
                    stats.cache_hits += 1;
                    // Returned verbatim, match quality included: a cached
                    // relaxed match stays a relaxed match.
                    return Some(attribution.clone());
                }
            }

            // Cache miss or stale - do enhanced lookup
            if let Some(result) = self.lookup_process_enhanced(conn) {
                // Update cache with the result
                {
                    let mut cache = self
                        .unified_cache
                        .write()
                        .expect("unified_cache lock poisoned");
                    cache.lookup.insert(key, result.clone());

                    let mut stats = self.stats.write().expect("stats lock poisoned");
                    stats.cache_entries = cache.lookup.len() as u64;
                }
                Some(result)
            } else {
                // Track failed lookups
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.failed_lookups += 1;
                None
            }
        }

        fn refresh(&self) -> Result<()> {
            // Refresh the procfs lookup
            self.procfs_lookup.refresh()?;

            // Update our cache timestamp
            {
                let mut cache = self
                    .unified_cache
                    .write()
                    .expect("unified_cache lock poisoned");
                cache.last_refresh = Instant::now();
                // Optionally clear cache to force fresh lookups
                cache.lookup.clear();
            }

            debug!("Enhanced process lookup refreshed");
            Ok(())
        }

        fn get_detection_method(&self) -> &str {
            match self.get_attribution_backend() {
                AttributionBackend::EbpfFentry => "eBPF fentry/fexit + procfs",
                AttributionBackend::EbpfKprobe => "eBPF kprobe + procfs",
                _ => "procfs",
            }
        }

        fn get_degradation_reason(&self) -> DegradationReason {
            self.degradation_reason.clone()
        }

        fn get_attribution_backend(&self) -> AttributionBackend {
            self.ebpf_tracker
                .read()
                .expect("ebpf_tracker lock poisoned")
                .as_ref()
                .map(|tracker| tracker.backend())
                .unwrap_or(AttributionBackend::Procfs)
        }

        fn get_attribution_capabilities(&self) -> AttributionCapabilities {
            self.ebpf_tracker
                .read()
                .expect("ebpf_tracker lock poisoned")
                .as_ref()
                .map(|tracker| tracker.capabilities())
                .unwrap_or_default()
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::MatchQuality;
        use rustnet_core::network::types::{ProtocolState, TcpState};
        use std::path::PathBuf;

        fn connection(local: &str, remote: &str) -> Connection {
            Connection::new(
                Protocol::Tcp,
                local.parse().unwrap(),
                remote.parse().unwrap(),
                ProtocolState::Tcp(TcpState::Established),
            )
        }

        /// A result carrying everything only eBPF can observe, so a cache round
        /// trip that drops any of it is visible.
        fn ebpf_attribution() -> ProcessAttribution {
            ProcessAttribution::new(
                4242,
                "curl",
                AttributionBackend::EbpfFentry,
                MatchQuality::WildcardLocalAddress,
            )
            .with_parent_pid(4000)
            .with_tid(4299)
            .with_credentials(1000, 100)
            .with_executable(Some(PathBuf::from("/usr/bin/curl")))
            .with_observed_at_ns(123_456_789)
        }

        #[test]
        fn cached_results_keep_every_field_the_backend_reported() {
            let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
            let conn = connection("192.168.1.10:5000", "1.1.1.1:443");
            let expected = ebpf_attribution();
            lookup.seed_cache(ConnectionKey::from_connection(&conn), expected.clone());

            let cached = lookup
                .get_process_attribution(&conn)
                .expect("seeded entry must be served from the cache");

            // The whole struct, not just (pid, name): storing the tuple would
            // silently drop the TID, credentials, executable, and timestamp.
            assert_eq!(cached, expected);
        }

        #[test]
        fn a_cached_relaxed_match_is_not_upgraded_to_exact() {
            let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
            let conn = connection("192.168.1.10:5001", "1.1.1.1:443");
            lookup.seed_cache(ConnectionKey::from_connection(&conn), ebpf_attribution());

            for _ in 0..3 {
                let cached = lookup.get_process_attribution(&conn).unwrap();
                assert_eq!(cached.quality, MatchQuality::WildcardLocalAddress);
                assert!(!cached.quality.is_exact());
            }
        }

        #[test]
        fn the_tuple_api_serves_the_cached_attribution() {
            let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
            let conn = connection("192.168.1.10:5002", "1.1.1.1:443");
            lookup.seed_cache(ConnectionKey::from_connection(&conn), ebpf_attribution());

            assert_eq!(
                lookup.get_process_for_connection(&conn),
                Some((4242, "curl".to_string()))
            );
        }

        #[test]
        fn refresh_clears_the_cache() {
            let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
            let conn = connection("192.168.1.10:5003", "1.1.1.1:443");
            lookup.seed_cache(ConnectionKey::from_connection(&conn), ebpf_attribution());
            lookup.refresh().expect("refresh must succeed");

            // The synthetic entry is gone; a real /proc scan cannot produce it.
            assert!(lookup.get_process_attribution(&conn).is_none());
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
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.total_lookups += 1;

                // Track IP version
                match conn.local_addr.ip() {
                    IpAddr::V4(_) => stats.ipv4_lookups += 1,
                    IpAddr::V6(_) => stats.ipv6_lookups += 1,
                }

                // Track protocol type
                match conn.protocol {
                    Protocol::Tcp => stats.tcp_lookups += 1,
                    Protocol::Udp => stats.udp_lookups += 1,
                    _ => {}
                }

                // eBPF is never available in this build
                stats.ebpf_available = false;
            }

            // Try cache first
            {
                let cache = self
                    .unified_cache
                    .read()
                    .expect("unified_cache lock poisoned");
                if cache.last_refresh.elapsed() < Duration::from_secs(2)
                    && let Some(process_info) = cache.lookup.get(&key)
                {
                    let mut stats = self.stats.write().expect("stats lock poisoned");
                    stats.cache_hits += 1;
                    return Some(process_info.clone());
                }
            }

            // Cache miss or stale - use procfs lookup
            if let Some(result) = self.procfs_lookup.get_process_for_connection(conn) {
                // Update cache with the result
                {
                    let mut cache = self
                        .unified_cache
                        .write()
                        .expect("unified_cache lock poisoned");
                    cache.lookup.insert(key, result.clone());

                    let mut stats = self.stats.write().expect("stats lock poisoned");
                    stats.cache_entries = cache.lookup.len() as u64;
                    stats.procfs_hits += 1;
                }
                Some(result)
            } else {
                // Track failed lookups
                let mut stats = self.stats.write().expect("stats lock poisoned");
                stats.failed_lookups += 1;
                None
            }
        }

        fn refresh(&self) -> Result<()> {
            // Refresh the procfs lookup
            self.procfs_lookup.refresh()?;

            // Update our cache timestamp
            {
                let mut cache = self
                    .unified_cache
                    .write()
                    .expect("unified_cache lock poisoned");
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

        fn get_attribution_backend(&self) -> AttributionBackend {
            AttributionBackend::Procfs
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
