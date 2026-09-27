//! Enhanced Linux process lookup combining eBPF and procfs approaches

use crate::{
    AttributionBackend, ConnectionKey, DegradationReason, ProcessAttribution, ProcessLookup,
    SocketSnapshot,
};

use super::process::LinuxProcessLookup;
use anyhow::Result;
use log::{debug, info, warn};
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::ebpf::{EbpfSocketTracker, snapshot_task_file_owners};
use crate::linux::ebpf::SocketMatch;
use crate::linux::process::{refine_truncated_name, retained_lineage};
use rustnet_core::network::types::ProtocolState;

/// Enhanced process lookup that combines eBPF (fast path) with procfs (fallback)
pub(super) struct EnhancedLinuxProcessLookup {
    ebpf_tracker: RwLock<Option<Box<EbpfSocketTracker>>>,
    procfs_lookup: LinuxProcessLookup,
    unified_cache: RwLock<ProcessCache>,
    cleanup_config: CleanupConfig,
    last_cleanup: RwLock<Instant>,
    degradation_reason: DegradationReason,
}

struct ProcessCache {
    // Full attributions, not just (pid, name): caching the tuple would drop
    // the credentials, executable path, and match quality on the first hit
    // and silently downgrade every subsequent lookup.
    lookup: HashMap<ConnectionKey, ProcessAttribution>,
    last_refresh: Instant,
}

#[derive(Debug, Clone)]
struct CleanupConfig {
    cleanup_interval_secs: u64,
    stale_threshold_secs: u64,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            cleanup_interval_secs: 30,
            stale_threshold_secs: 60,
        }
    }
}

impl EnhancedLinuxProcessLookup {
    pub(super) fn new() -> Result<Self> {
        let cleanup_config = CleanupConfig::default();

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

        // Attach the live tracker before taking the one-shot task-file
        // inventory. Connections created during or after the inventory are
        // then covered by fentry/kprobe even if the iterator does not visit
        // them. Keep the iterator in a separate BPF object so an older kernel
        // can reject it without disabling the live tracker.
        let startup_owners = if ebpf_tracker.is_some() {
            match snapshot_task_file_owners() {
                Ok(owners) => {
                    info!(
                        "eBPF task-file startup snapshot found owners for {} socket inodes",
                        owners.len()
                    );
                    owners
                }
                Err(error) => {
                    info!(
                        "eBPF task-file startup snapshot unavailable: {}; using procfs ownership",
                        error
                    );
                    Default::default()
                }
            }
        } else {
            Default::default()
        };
        let procfs_lookup = LinuxProcessLookup::new_with_bpf_startup_owners(startup_owners)?;

        Ok(Self {
            ebpf_tracker: RwLock::new(ebpf_tracker),
            procfs_lookup,
            unified_cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: Instant::now() - Duration::from_secs(3600),
            }),
            cleanup_config,
            last_cleanup: RwLock::new(Instant::now() - Duration::from_secs(3600)),
            degradation_reason,
        })
    }

    /// Try eBPF lookup first, fall back to procfs
    fn lookup_process_enhanced(&self, conn: &Connection) -> Option<ProcessAttribution> {
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
                    if result.quality == crate::MatchQuality::SocketCookie {
                        // A descriptor can be transferred after the observed
                        // create/connect/send. Preserve procfs ownership when
                        // available before falling back to that earlier actor.
                        return self
                            .procfs_lookup
                            .get_process_attribution(conn)
                            .or(Some(result));
                    }
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

        self.procfs_lookup.get_process_attribution(conn)
    }

    /// Use the identity observed by BPF, including after exit or exec. Looking
    /// up the current holder of a retained PID could attribute an old socket
    /// to a different executable or a recycled process ID.
    fn attribution_from_ebpf(&self, matched: SocketMatch) -> ProcessAttribution {
        let SocketMatch { info, quality } = matched;
        let lineage = retained_lineage(&info);
        let parent_pid = info.parent.as_ref().map(|parent| parent.pid);
        let name = refine_truncated_name(info.comm, info.executable.as_deref());
        debug!(
            "eBPF attribution: TGID {}, PPID {:?}, TID {}, observed {}ns (monotonic)",
            info.pid, parent_pid, info.tid, info.timestamp
        );
        let mut attribution = ProcessAttribution::new(info.pid, name, quality)
            .with_credentials(info.uid, info.gid)
            .with_executable(info.executable)
            .with_lineage(lineage);
        attribution.socket_cgroup = info.socket_cgroup;
        if let Some(ppid) = parent_pid {
            attribution = attribution.with_parent_pid(ppid);
        }
        attribution
    }

    fn try_ebpf_lookup(&self, conn: &Connection) -> Option<ProcessAttribution> {
        // Scope the tracker lock so it is released before attribution reads
        // process metadata from procfs.
        let matched = {
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
            match tracker.lookup(
                conn.local_addr.ip(),
                conn.remote_addr.ip(),
                conn.local_addr.port(),
                conn.remote_addr.port(),
                is_tcp,
            ) {
                Some(matched) => matched,
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

        Some(self.attribution_from_ebpf(matched))
    }

    fn try_ebpf_icmp_lookup(&self, conn: &Connection, icmp_id: u16) -> Option<ProcessAttribution> {
        let matched = {
            let mut tracker_guard = self
                .ebpf_tracker
                .write()
                .expect("ebpf_tracker lock poisoned");
            let tracker = tracker_guard.as_mut()?;
            match tracker.lookup_icmp(conn.local_addr.ip(), conn.remote_addr.ip(), icmp_id) {
                Some(matched) => matched,
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

        Some(self.attribution_from_ebpf(matched))
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

    /// Periodic cleanup of stale eBPF map entries.
    fn maybe_cleanup_ebpf_map(&self) {
        let now = Instant::now();
        let mut last_cleanup = self
            .last_cleanup
            .write()
            .expect("last_cleanup lock poisoned");

        if now.duration_since(*last_cleanup).as_secs() >= self.cleanup_config.cleanup_interval_secs
        {
            *last_cleanup = now;
            drop(last_cleanup);

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
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        self.maybe_cleanup_ebpf_map();

        let key = ConnectionKey::from_connection(conn);

        {
            let cache = self
                .unified_cache
                .read()
                .expect("unified_cache lock poisoned");
            if cache.last_refresh.elapsed() < Duration::from_secs(2)
                && let Some(attribution) = cache.lookup.get(&key)
            {
                // Returned verbatim, match quality included: a cached
                // relaxed match stays a relaxed match.
                return Some(attribution.clone());
            }
        }

        if let Some(result) = self.lookup_process_enhanced(conn) {
            let mut cache = self
                .unified_cache
                .write()
                .expect("unified_cache lock poisoned");
            cache.lookup.insert(key, result.clone());
            Some(result)
        } else {
            None
        }
    }

    fn refresh(&self) -> Result<()> {
        self.procfs_lookup.refresh()?;

        {
            let mut cache = self
                .unified_cache
                .write()
                .expect("unified_cache lock poisoned");
            cache.last_refresh = Instant::now();
            cache.lookup.clear();
        }

        debug!("Enhanced process lookup refreshed");
        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        match self
            .ebpf_tracker
            .read()
            .expect("ebpf_tracker lock poisoned")
            .as_ref()
            .map(|tracker| tracker.backend())
        {
            Some(AttributionBackend::EbpfFentry) => "eBPF fentry/fexit + procfs",
            Some(AttributionBackend::EbpfKprobe) => "eBPF kprobe + procfs",
            None => "procfs",
        }
    }

    fn get_degradation_reason(&self) -> DegradationReason {
        self.degradation_reason.clone()
    }

    fn socket_snapshot(&self) -> SocketSnapshot {
        self.procfs_lookup.socket_snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchQuality;
    use crate::test_support::tcp_connection;
    use std::path::PathBuf;

    #[test]
    fn retained_identity_does_not_enrich_a_reused_pid() {
        let lookup = EnhancedLinuxProcessLookup::new().unwrap();
        let parent = crate::ProcessAncestor {
            pid: unsafe { libc::getppid() } as u32,
            name: "old-parent".into(),
            executable: Some("/old/parent".into()),
            started_at_unix_ms: Some(1),
        };
        let info = crate::linux::ebpf::ProcessInfo {
            // The PID is live, but the recorded generation is deliberately old.
            pid: std::process::id(),
            tid: 1,
            uid: 123,
            gid: 456,
            comm: "old-process".into(),
            timestamp: 1,
            executable: Some("/old/executable".into()),
            start_boottime: 1,
            parent_start_boottime: 1,
            parent: Some(parent.clone()),
            socket_cgroup: None,
        };
        let got = lookup.attribution_from_ebpf(SocketMatch {
            info,
            quality: MatchQuality::ExactTuple,
        });
        assert_eq!(got.name, "old-process");
        assert_eq!(got.executable, Some("/old/executable".into()));
        assert_eq!(got.lineage.unwrap().ancestors, vec![parent]);
    }

    /// A result carrying everything only eBPF can observe, so a cache round
    /// trip that drops any of it is visible.
    fn ebpf_attribution() -> ProcessAttribution {
        let mut attribution =
            ProcessAttribution::new(4242, "curl", MatchQuality::WildcardLocalAddress)
                .with_parent_pid(4000)
                .with_credentials(1000, 100)
                .with_executable(Some(PathBuf::from("/usr/bin/curl")));
        attribution.socket_cgroup = Some(crate::SocketCgroup {
            name: "container".into(),
            parent: "pod".into(),
        });
        attribution
    }

    #[test]
    fn cached_results_keep_every_field_the_backend_reported() {
        let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
        let conn = tcp_connection("192.168.1.10:5000", "1.1.1.1:443");
        let expected = ebpf_attribution();
        lookup.seed_cache(ConnectionKey::from_connection(&conn), expected.clone());

        let cached = lookup
            .get_process_attribution(&conn)
            .expect("seeded entry must be served from the cache");

        // The whole struct, not just (pid, name): storing the tuple would
        // silently drop the credentials, executable, and match quality.
        assert_eq!(cached, expected);
    }

    #[test]
    fn a_cached_relaxed_match_is_not_upgraded_to_exact() {
        let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
        let conn = tcp_connection("192.168.1.10:5001", "1.1.1.1:443");
        lookup.seed_cache(ConnectionKey::from_connection(&conn), ebpf_attribution());

        for _ in 0..3 {
            let cached = lookup.get_process_attribution(&conn).unwrap();
            assert_eq!(cached.quality, MatchQuality::WildcardLocalAddress);
            assert!(!cached.quality.is_exact());
        }
    }

    #[test]
    fn refresh_clears_the_cache() {
        let lookup = EnhancedLinuxProcessLookup::new().expect("procfs lookup must initialize");
        let conn = tcp_connection("192.168.1.10:5003", "1.1.1.1:443");
        lookup.seed_cache(ConnectionKey::from_connection(&conn), ebpf_attribution());
        lookup.refresh().expect("refresh must succeed");

        // The synthetic entry is gone; a real /proc scan cannot produce it.
        assert!(lookup.get_process_attribution(&conn).is_none());
    }
}
