//! Process-attribution and GeoIP enrichment threads.

use anyhow::Result;
use log::{debug, error, info};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::network::platform::create_process_lookup;
use crate::network::tracker::ConnectionTracker;
use crate::network::types::{Connection, ProcessLineage, UNKNOWN_PROCESS_NAME};

use super::runtime::ShutdownSignal;
use super::sampling::spawn_loop;
use super::state::App;
use super::types::ProcessDetectionStatus;

/// Process-attribution resources initialized during the privileged startup
/// phase and moved into the long-lived worker after sandboxing.
///
/// On Linux the loaded object owns the program, link, and map descriptors.
/// CAP_BPF and CAP_PERFMON are needed to create and attach those objects, but
/// later map operations through the existing descriptors are authorized by
/// their read/write modes. The worker therefore needs no retained capability.
pub(super) struct PreparedProcessEnrichment {
    process_lookup: Box<dyn rustnet_host::ProcessLookup>,
}

fn prepare_process_lookup_with<F>(use_pktap: bool, create: F) -> Result<PreparedProcessEnrichment>
where
    F: FnOnce(bool) -> Result<Box<dyn rustnet_host::ProcessLookup>>,
{
    create(use_pktap).map(|process_lookup| PreparedProcessEnrichment { process_lookup })
}

fn activate_process_lookup(
    prepared: PreparedProcessEnrichment,
) -> Result<Box<dyn rustnet_host::ProcessLookup>> {
    let mut process_lookup = prepared.process_lookup;
    process_lookup.start_runtime()?;
    Ok(process_lookup)
}

/// Whether a connection needs no further process enrichment. A connection
/// still carrying the [`UNKNOWN_PROCESS_NAME`] placeholder (a PID whose
/// image name could not be resolved yet) stays eligible so the resolver can
/// upgrade it once the real name is known.
#[inline]
fn process_enrichment_complete(conn: &Connection) -> bool {
    conn.pid.is_some()
        && conn
            .process_name
            .as_deref()
            .is_some_and(|name| name != UNKNOWN_PROCESS_NAME)
        && conn.attribution_quality.is_some()
}

impl App {
    /// Initialize process attribution synchronously while startup privileges
    /// are still available. In particular, Linux eBPF programs and maps are
    /// loaded here, but no thread is allowed to outlive this pre-sandbox phase.
    pub(super) fn prepare_process_enrichment(&self) -> Result<PreparedProcessEnrichment> {
        // Capture preparation has already recorded the link type, so PKTAP
        // selection is known without starting a thread or waiting for packets.
        let use_pktap = self.pktap_active.load(Ordering::Relaxed);
        let prepared = match prepare_process_lookup_with(use_pktap, create_process_lookup) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Ok(mut status) = self.process_detection_status.write() {
                    *status = ProcessDetectionStatus::degraded(
                        "unavailable",
                        "process attribution",
                        error.to_string(),
                    );
                }
                return Err(error);
            }
        };
        let process_lookup = &prepared.process_lookup;

        if let Ok(mut snapshot) = self.socket_snapshot.write() {
            *snapshot = process_lookup.socket_snapshot();
        }

        Ok(prepared)
    }

    /// Move the prepared process lookup into its long-lived worker. The typed
    /// application lifecycle calls this only from the post-sandbox phase.
    pub(super) fn start_process_enrichment_thread(
        &mut self,
        tracker: Arc<ConnectionTracker>,
        prepared: PreparedProcessEnrichment,
    ) -> Result<Option<SystemTime>> {
        let process_lookup = activate_process_lookup(prepared)?;
        let process_detection_status = Arc::clone(&self.process_detection_status);
        let socket_snapshot = Arc::clone(&self.socket_snapshot);
        let method = process_lookup.get_detection_method().to_string();
        let capture_not_before =
            (cfg!(target_os = "windows") && method == "windows-etw+iphlpapi").then(SystemTime::now);
        let degradation = process_lookup.get_degradation_reason();
        *process_detection_status
            .write()
            .map_err(|_| anyhow::anyhow!("process detection status lock is poisoned"))? =
            if degradation != rustnet_host::DegradationReason::None {
                ProcessDetectionStatus::degraded(
                    method,
                    degradation.unavailable_feature().unwrap_or("enhanced"),
                    degradation.description(),
                )
            } else {
                ProcessDetectionStatus::with_method(method)
            };
        let shutdown = self.runtime.shutdown_signal();
        #[cfg(feature = "kubernetes")]
        let kubernetes_mode = self.config.kubernetes_mode;

        let handle = thread::Builder::new()
            .name("process-enrichment".to_string())
            .spawn(move || {
                let failure_status = Arc::clone(&process_detection_status);
                if let Err(e) = Self::run_process_enrichment(
                    process_lookup,
                    tracker,
                    shutdown,
                    socket_snapshot,
                    #[cfg(feature = "kubernetes")]
                    kubernetes_mode,
                ) {
                    if let Ok(mut status) = failure_status.write() {
                        *status = ProcessDetectionStatus::degraded(
                            "unavailable",
                            "process attribution",
                            e.to_string(),
                        );
                    }
                    error!("Process enrichment thread failed: {}", e);
                }
            })
            .map_err(|error| {
                anyhow::anyhow!("failed to spawn process-enrichment worker: {error}")
            })?;
        self.runtime.register(handle);

        Ok(capture_not_before)
    }

    fn run_process_enrichment(
        process_lookup: Box<dyn rustnet_host::ProcessLookup>,
        tracker: Arc<ConnectionTracker>,
        shutdown: ShutdownSignal,
        socket_snapshot: Arc<RwLock<rustnet_host::SocketSnapshot>>,
        #[cfg(feature = "kubernetes")] kubernetes_mode: crate::network::kubernetes::KubernetesMode,
    ) -> Result<()> {
        if shutdown.is_requested() {
            return Ok(());
        }

        // Kubernetes pod/container attribution. `auto` enables only when rustnet
        // is itself running inside a pod, so the resolver and the cross-namespace
        // socket table are only built when enabled and non-Kubernetes hosts do
        // no extra /proc work. The table stays empty when disabled.
        #[cfg(feature = "kubernetes")]
        let kubernetes_resolver = kubernetes_mode
            .enabled()
            .then(crate::network::kubernetes::KubernetesResolver::new);
        #[cfg(feature = "kubernetes")]
        if kubernetes_resolver.is_some() {
            info!("Kubernetes pod/container attribution enabled");
        }
        #[cfg(feature = "kubernetes")]
        let mut k8s_socket_table = crate::network::kubernetes::KubernetesSocketTable::empty();
        #[cfg(feature = "kubernetes")]
        if let Some(resolver) = &kubernetes_resolver {
            k8s_socket_table = crate::network::kubernetes::KubernetesSocketTable::build(resolver);
        }

        // Fast/slow enrichment cadence. Young connections are retried on a
        // quick tick so their process name appears almost immediately (the
        // eBPF map entry exists from the moment the socket connects; a
        // slower cadence only buys a visible "-" in the UI). Older
        // stragglers (e.g. NAT-translated container traffic the lookup can
        // never resolve) are retried only on the full pass so the fast
        // tick stays cheap, and fully attributed connections are skipped
        // entirely.
        let tick = Duration::from_millis(250);
        let full_pass_interval = Duration::from_secs(2);
        // Connections younger than this are retried on every fast tick.
        const YOUNG_CONNECTION_SECS: u64 = 10;
        let mut last_full_pass = Instant::now() - full_pass_interval;
        // Executable paths are shared by every connection of a process, and
        // `Connection` is cloned in bulk on every snapshot tick. Interning here
        // means the clone copies an Arc pointer instead of a fresh PathBuf.
        let mut executables: HashMap<PathBuf, Arc<Path>> = HashMap::new();
        // Lineage follows the same sharing rule, keyed by owner PID. Unlike the
        // content-keyed executable map, a PID key can go stale on PID reuse, so
        // the map is cleared on every full pass.
        let mut lineages: HashMap<u32, Arc<ProcessLineage>> = HashMap::new();

        info!(
            "Process enrichment thread started with detection method: {}",
            process_lookup.get_detection_method()
        );
        let mut last_refresh = Instant::now();

        loop {
            if shutdown.is_requested() {
                info!("Process enrichment thread stopping");
                break;
            }

            if last_refresh.elapsed() > Duration::from_secs(5) {
                if let Err(e) = process_lookup.refresh_interruptible(shutdown.requested_flag()) {
                    debug!("Process lookup refresh failed: {}", e);
                } else if let Ok(mut snapshot) = socket_snapshot.write() {
                    *snapshot = process_lookup.socket_snapshot();
                }
                // Refresh pod-name metadata and rebuild the cross-namespace
                // socket table on the same cadence.
                #[cfg(feature = "kubernetes")]
                if let Some(resolver) = &kubernetes_resolver {
                    resolver.refresh_metadata();
                    k8s_socket_table =
                        crate::network::kubernetes::KubernetesSocketTable::build(resolver);
                }
                last_refresh = Instant::now();
            }

            let full_pass = last_full_pass.elapsed() >= full_pass_interval;
            if full_pass {
                last_full_pass = Instant::now();
                lineages.clear();
            }

            let mut enriched = 0;
            for mut entry in tracker.connections().iter_mut() {
                // Match quality is also the completion marker for rich
                // enrichment. PKTAP seeds PID and name in the capture path, so
                // those connections remain eligible for exactly one libproc
                // attempt. Optional fields are best effort; requiring every
                // one would retry permanent permission or process-exit failures
                // on every fast tick.
                if process_enrichment_complete(&entry) {
                    continue;
                }
                // Fast ticks only retry young connections; older ones wait
                // for the full pass.
                if !full_pass {
                    let young = entry
                        .created_at
                        .elapsed()
                        .map(|age| age.as_secs() < YOUNG_CONNECTION_SECS)
                        .unwrap_or(true);
                    if !young {
                        continue;
                    }
                }

                // Partial enrichment: fill missing pieces without overwriting.
                if let Some(attribution) = process_lookup.get_process_attribution(&entry) {
                    let pid = attribution.tgid;
                    let name = attribution.name;
                    let mut did_enrich = false;

                    let upgrades_placeholder = name != UNKNOWN_PROCESS_NAME
                        && entry.process_name.as_deref() == Some(UNKNOWN_PROCESS_NAME);
                    if entry.process_name.is_none() || upgrades_placeholder {
                        entry.process_name = Some(name.clone());
                        did_enrich = true;
                        debug!(
                            "✓ Set process name for connection {}: {}",
                            entry.key(),
                            name
                        );
                    }
                    if entry.pid.is_none() {
                        entry.pid = Some(pid);
                        did_enrich = true;
                        debug!("✓ Set PID for connection {}: {}", entry.key(), pid);
                    }
                    if entry.process_ppid.is_none()
                        && let Some(ppid) = attribution.ppid
                    {
                        entry.process_ppid = Some(ppid);
                        did_enrich = true;
                    }

                    // The richer fields follow the same write-once rule as the
                    // name and PID above: the first backend to answer owns the
                    // connection, so a later relaxed guess cannot overwrite an
                    // earlier exact one.
                    if entry.executable.is_none()
                        && let Some(path) = attribution.executable
                    {
                        let interned = executables
                            .entry(path)
                            .or_insert_with_key(|path| Arc::from(path.as_path()))
                            .clone();
                        entry.executable = Some(interned);
                        did_enrich = true;
                    }
                    if entry.process_uid.is_none()
                        && let Some(uid) = attribution.uid
                    {
                        entry.process_uid = Some(uid);
                        did_enrich = true;
                    }
                    if entry.process_gid.is_none()
                        && let Some(gid) = attribution.gid
                    {
                        entry.process_gid = Some(gid);
                        did_enrich = true;
                    }
                    if entry.process_lineage.is_none()
                        && let Some(lineage) = attribution.lineage
                    {
                        let interned = lineages
                            .entry(pid)
                            .or_insert_with(|| Arc::new(lineage))
                            .clone();
                        entry.process_lineage = Some(interned);
                        did_enrich = true;
                    }
                    if entry.attribution_quality.is_none() {
                        entry.attribution_quality = Some(attribution.quality);
                        did_enrich = true;
                    }

                    if did_enrich {
                        enriched += 1;
                    }

                    // Look up Kubernetes pod/container metadata for the PID.
                    // Cheap after the first hit per PID (cached in the resolver).
                    #[cfg(feature = "kubernetes")]
                    if let Some(resolver) = &kubernetes_resolver
                        && entry.k8s_info.is_none()
                        && let Some(k8s) = resolver.enrich(pid)
                    {
                        entry.k8s_info = Some(k8s);
                    }
                } else {
                    // The primary lookup couldn't attribute this connection.
                    // Under hostNetwork, that includes every pod-owned socket
                    // living in another network namespace. The socket table
                    // walks per-PID /proc/<pid>/net/* (netns-aware) for kubepods
                    // PIDs and matches the 4-tuple, yielding both the PID and
                    // its pod/container metadata.
                    #[cfg(feature = "kubernetes")]
                    if entry.pid.is_none()
                        && let Some((pid, k8s)) = k8s_socket_table.lookup_connection(&entry)
                    {
                        entry.pid = Some(pid);
                        if entry.process_name.is_none() {
                            entry.process_name = crate::network::kubernetes::read_process_name(pid);
                        }
                        if entry.attribution_quality.is_none() {
                            entry.attribution_quality =
                                Some(crate::network::types::MatchQuality::ProcfsExact);
                        }
                        if entry.k8s_info.is_none() {
                            entry.k8s_info = Some(k8s);
                        }
                        enriched += 1;
                    }
                }
            }

            if enriched > 0 {
                debug!("Enriched {} connections with process info", enriched);
            }

            if shutdown.wait_timeout(tick) {
                info!("Process enrichment thread stopping");
                break;
            }
        }

        Ok(())
    }

    pub(super) fn start_geoip_enrichment_thread(
        &mut self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<()> {
        let geoip_resolver = match &self.geoip_resolver {
            Some(resolver) => Arc::clone(resolver),
            None => return Ok(()), // No resolver available
        };

        let handle = spawn_loop(
            "geoip-enrichment",
            "GeoIP enrichment thread started",
            "GeoIP enrichment thread stopping",
            Duration::from_millis(500),
            self.runtime.shutdown_signal(),
            move || {
                let mut enriched = 0;
                for mut entry in tracker.connections().iter_mut() {
                    if entry.geoip_info.is_none() {
                        let remote_ip = entry.remote_addr.ip();
                        let info = geoip_resolver.lookup(remote_ip);
                        if info.has_data() {
                            entry.geoip_info = Some(info);
                            enriched += 1;
                        }
                    }
                }

                if enriched > 0 {
                    debug!("Enriched {} connections with GeoIP info", enriched);
                }
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to spawn GeoIP enrichment worker: {error}"))?;
        self.runtime.register(handle);

        Ok(())
    }
}

#[cfg(test)]
mod process_enrichment_tests {
    use super::{
        activate_process_lookup, prepare_process_lookup_with, process_enrichment_complete,
    };
    use crate::app::logging::process_lineage_json;
    use crate::network::types::UNKNOWN_PROCESS_NAME;
    use crate::network::types::{
        Connection, MatchQuality, ProcessAncestor, ProcessLineage, Protocol, ProtocolState,
        TcpState,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::thread;

    struct ThreadRecordingLookup {
        calls: Arc<Mutex<Vec<thread::ThreadId>>>,
        runtime_starts: Arc<Mutex<Vec<thread::ThreadId>>>,
    }

    impl rustnet_host::ProcessLookup for ThreadRecordingLookup {
        fn start_runtime(&mut self) -> anyhow::Result<()> {
            self.runtime_starts
                .lock()
                .unwrap()
                .push(thread::current().id());
            Ok(())
        }

        fn get_process_attribution(
            &self,
            _conn: &Connection,
        ) -> Option<rustnet_host::ProcessAttribution> {
            None
        }

        fn get_detection_method(&self) -> &str {
            self.calls.lock().unwrap().push(thread::current().id());
            "test"
        }
    }

    fn connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            "127.0.0.1:5000".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn prepared_lookup_starts_inline_after_the_sandbox_handoff() {
        let caller = thread::current().id();
        let construction_thread = Arc::new(Mutex::new(None));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let runtime_starts = Arc::new(Mutex::new(Vec::new()));

        let prepared = prepare_process_lookup_with(false, {
            let construction_thread = Arc::clone(&construction_thread);
            let calls = Arc::clone(&calls);
            let runtime_starts = Arc::clone(&runtime_starts);
            move |use_pktap| {
                assert!(!use_pktap);
                *construction_thread.lock().unwrap() = Some(thread::current().id());
                Ok(Box::new(ThreadRecordingLookup {
                    calls,
                    runtime_starts,
                }) as Box<dyn rustnet_host::ProcessLookup>)
            }
        })
        .unwrap();

        assert_eq!(*construction_thread.lock().unwrap(), Some(caller));
        assert!(calls.lock().unwrap().is_empty());
        assert!(runtime_starts.lock().unwrap().is_empty());

        let process_lookup = activate_process_lookup(prepared).unwrap();
        process_lookup.get_detection_method();

        assert_eq!(runtime_starts.lock().unwrap().as_slice(), &[caller]);
        assert_eq!(calls.lock().unwrap().as_slice(), &[caller]);
    }

    #[test]
    fn packet_seeded_identity_still_gets_one_rich_enrichment_attempt() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some("curl".to_string());

        assert!(!process_enrichment_complete(&conn));

        conn.attribution_quality = Some(MatchQuality::ExactTuple);
        assert!(process_enrichment_complete(&conn));
    }

    #[test]
    fn missing_optional_libproc_fields_do_not_cause_permanent_retries() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some("curl".to_string());
        conn.attribution_quality = Some(MatchQuality::ExactTuple);

        assert!(conn.executable.is_none());
        assert!(conn.process_uid.is_none());
        assert!(process_enrichment_complete(&conn));
    }

    #[test]
    fn placeholder_identity_remains_eligible_for_an_upgrade() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some(UNKNOWN_PROCESS_NAME.to_string());
        conn.attribution_quality = Some(MatchQuality::Unspecified);

        assert!(!process_enrichment_complete(&conn));
    }

    #[test]
    fn lineage_json_preserves_process_identity_fields() {
        let lineage = ProcessLineage {
            ancestors: vec![ProcessAncestor {
                pid: 1,
                name: "systemd".to_string(),
                executable: Some(PathBuf::from("/usr/lib/systemd/systemd")),
                started_at_unix_ms: Some(1_700_000_000_000),
            }],
            truncated: true,
        };

        assert_eq!(
            process_lineage_json(&lineage),
            json!({
                "ancestors": [{
                    "pid": 1,
                    "name": "systemd",
                    "executable": "/usr/lib/systemd/systemd",
                    "started_at_unix_ms": 1_700_000_000_000_u64,
                }],
                "truncated": true,
            })
        );
    }
}
