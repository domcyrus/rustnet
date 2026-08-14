//! Process-attribution and GeoIP enrichment threads.

use anyhow::Result;
use log::{debug, error, info};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::network::platform::create_process_lookup;
use crate::network::tracker::ConnectionTracker;
use crate::network::types::{Connection, ProcessLineage};

use super::state::App;
use super::types::ProcessDetectionStatus;

#[inline]
fn process_enrichment_complete(conn: &Connection, unknown_process_name: &str) -> bool {
    conn.pid.is_some()
        && conn
            .process_name
            .as_deref()
            .is_some_and(|name| name != unknown_process_name)
        && conn.attribution_quality.is_some()
}

impl App {
    /// Start process enrichment thread conditionally based on PKTAP status
    pub(super) fn start_process_enrichment_conditional(
        &self,
        tracker: Arc<ConnectionTracker>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
    ) -> Result<()> {
        let pktap_active = Arc::clone(&self.pktap_active);
        let should_stop = Arc::clone(&self.should_stop);
        let process_detection_status = Arc::clone(&self.process_detection_status);
        #[cfg(feature = "kubernetes")]
        let kubernetes_mode = self.config.kubernetes_mode;

        thread::Builder::new()
            .name("process-enrichment".to_string())
            .spawn(move || {
            // On macOS, wait for PKTAP detection to avoid unnecessary lsof calls
            #[cfg(target_os = "macos")]
            {
                // Wait up to 5 seconds for PKTAP detection with shorter polling intervals
                let wait_start = Instant::now();
                while wait_start.elapsed() < Duration::from_secs(5)
                    && !should_stop.load(Ordering::Relaxed)
                    && !pktap_active.load(Ordering::Relaxed)
                {
                    // Check more frequently for faster detection
                    thread::sleep(Duration::from_millis(50));
                }

                if pktap_active.load(Ordering::Relaxed) {
                    info!(
                        "PKTAP is active, starting libproc enrichment for packet process metadata"
                    );
                    if let Ok(mut status) = process_detection_status.write() {
                        *status = ProcessDetectionStatus::with_method("pktap");
                    }
                } else {
                    info!(
                        "⚠️  PKTAP not detected after 5 seconds, starting process enrichment thread with lsof"
                    );
                    info!(
                        "    This may cause process name formatting differences with PKTAP if it activates later"
                    );
                }
            }

            // Start the actual process enrichment
            if let Err(e) = Self::run_process_enrichment(
                tracker,
                should_stop,
                pktap_active,
                process_detection_status,
                process_ready_tx,
                #[cfg(feature = "kubernetes")]
                kubernetes_mode,
            ) {
                error!("Process enrichment thread failed: {}", e);
            }
        })
        .expect("Failed to spawn process-enrichment thread");

        Ok(())
    }

    /// Run the actual process enrichment logic
    fn run_process_enrichment(
        tracker: Arc<ConnectionTracker>,
        should_stop: Arc<AtomicBool>,
        pktap_active: Arc<AtomicBool>,
        process_detection_status: Arc<RwLock<ProcessDetectionStatus>>,
        process_ready_tx: std::sync::mpsc::SyncSender<()>,
        #[cfg(feature = "kubernetes")] kubernetes_mode: crate::network::kubernetes::KubernetesMode,
    ) -> Result<()> {
        use crate::network::platform::DegradationReason;

        // Check PKTAP status before creating process lookup
        let use_pktap = pktap_active.load(Ordering::Relaxed);

        let process_lookup = create_process_lookup(use_pktap)?;
        #[cfg(target_os = "macos")]
        let mut process_lookup = process_lookup;
        #[cfg(target_os = "macos")]
        let mut using_pktap = use_pktap;

        // Linux capabilities are per-thread. This thread inherited the startup
        // capabilities before loading eBPF, so drop the ones it will not use
        // again. CAP_BPF and CAP_PERFMON deliberately stay: this thread keeps
        // reading the eBPF socket map for the process lifetime, and with
        // kernel.unprivileged_bpf_disabled set every bpf(2) call — map lookups
        // included — is rejected without CAP_BPF.
        #[cfg(all(target_os = "linux", feature = "landlock"))]
        crate::network::platform::sandbox::capabilities::drop_thread_cap_net_raw(
            "process enrichment thread",
        );

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

        // Signal that process detection (including eBPF loading) is complete.
        // The main thread waits for this before dropping eBPF capabilities.
        let _ = process_ready_tx.send(());

        // Fast/slow enrichment cadence. Young connections are retried on a
        // quick tick so their process name appears almost immediately (the
        // eBPF map entry exists from the moment the socket connects — a
        // slower cadence only buys a visible "-" in the UI). Older
        // stragglers (e.g. NAT-translated container traffic the lookup can
        // never resolve) are retried only on the full pass so the fast
        // tick stays cheap, and fully attributed connections are skipped
        // entirely.
        let tick = Duration::from_millis(250);
        let full_pass_interval = Duration::from_secs(2);
        // Connections younger than this are retried on every fast tick.
        const YOUNG_CONNECTION_SECS: u64 = 10;
        // Placeholder name that lookups store for a PID whose image name
        // could not be resolved (yet). Kept eligible for re-enrichment so the
        // resolver can upgrade it once the real name is known.
        const UNKNOWN_PROCESS_NAME: &str = "Unknown";
        let mut last_full_pass = Instant::now() - full_pass_interval;
        // Executable paths are shared by every connection of a process, and
        // `Connection` is cloned in bulk on every snapshot tick. Interning here
        // means the clone copies an Arc pointer instead of a fresh PathBuf.
        let mut executables: HashMap<PathBuf, Arc<Path>> = HashMap::new();
        // Lineage follows the same sharing rule, keyed by owner PID. Unlike the
        // content-keyed executable map, a PID key can go stale on PID reuse, so
        // the map is cleared on every full pass.
        let mut lineages: HashMap<u32, Arc<ProcessLineage>> = HashMap::new();

        // Build and set the detection status from the process lookup implementation
        // Only set if not already detected as pktap (to handle race conditions)
        if let Ok(mut status) = process_detection_status.write()
            && status.method != "pktap"
        {
            let method = process_lookup.get_detection_method().to_string();
            let degradation = process_lookup.get_degradation_reason();

            *status = if degradation != DegradationReason::None {
                ProcessDetectionStatus::degraded(
                    method,
                    degradation.unavailable_feature().unwrap_or("enhanced"),
                    degradation.description(),
                )
            } else {
                ProcessDetectionStatus::with_method(method)
            };
        }

        info!(
            "Process enrichment thread started with detection method: {}",
            process_lookup.get_detection_method()
        );
        let mut last_refresh = Instant::now();

        loop {
            if should_stop.load(Ordering::Relaxed) {
                info!("Process enrichment thread stopping");
                break;
            }

            // If PKTAP activates after the startup grace period, stop polling
            // lsof and enrich the packet-provided identity through libproc.
            #[cfg(target_os = "macos")]
            if !using_pktap && pktap_active.load(Ordering::Relaxed) {
                process_lookup = create_process_lookup(true)?;
                using_pktap = true;
                if let Ok(mut status) = process_detection_status.write() {
                    *status = ProcessDetectionStatus::with_method("pktap");
                }
                info!("PKTAP became active, switched process enrichment from lsof to libproc");
            }

            // Refresh process lookup periodically
            if last_refresh.elapsed() > Duration::from_secs(5) {
                if let Err(e) = process_lookup.refresh() {
                    debug!("Process lookup refresh failed: {}", e);
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

            // Enrich connections without process info
            let mut enriched = 0;
            for mut entry in tracker.connections().iter_mut() {
                // Match quality is also the completion marker for rich
                // enrichment. PKTAP seeds PID and name in the capture path, so
                // those connections remain eligible for exactly one libproc
                // attempt. Optional fields are best effort; requiring every
                // one would retry permanent permission or process-exit failures
                // on every fast tick.
                if process_enrichment_complete(&entry, UNKNOWN_PROCESS_NAME) {
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

                // Allow partial enrichment - fill in missing pieces without overwriting existing data
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

            thread::sleep(tick);
        }

        Ok(())
    }

    /// Start GeoIP enrichment thread to populate location/ASN info for connections
    pub(super) fn start_geoip_enrichment_thread(
        &self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<()> {
        let geoip_resolver = match &self.geoip_resolver {
            Some(resolver) => Arc::clone(resolver),
            None => return Ok(()), // No resolver available
        };

        let should_stop = Arc::clone(&self.should_stop);

        thread::Builder::new()
            .name("geoip-enrichment".to_string())
            .spawn(move || {
                info!("GeoIP enrichment thread started");
                let interval = Duration::from_millis(500);

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("GeoIP enrichment thread stopping");
                        break;
                    }

                    // Enrich connections without GeoIP info
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

                    thread::sleep(interval);
                }
            })
            .expect("Failed to spawn GeoIP enrichment thread");

        Ok(())
    }
}

#[cfg(test)]
mod process_enrichment_tests {
    use super::process_enrichment_complete;
    use crate::app::logging::process_lineage_json;
    use crate::network::types::{
        Connection, MatchQuality, ProcessAncestor, ProcessLineage, Protocol, ProtocolState,
        TcpState,
    };
    use serde_json::json;
    use std::path::PathBuf;

    fn connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            "127.0.0.1:5000".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn packet_seeded_identity_still_gets_one_rich_enrichment_attempt() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some("curl".to_string());

        assert!(!process_enrichment_complete(&conn, "Unknown"));

        conn.attribution_quality = Some(MatchQuality::ExactTuple);
        assert!(process_enrichment_complete(&conn, "Unknown"));
    }

    #[test]
    fn missing_optional_libproc_fields_do_not_cause_permanent_retries() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some("curl".to_string());
        conn.attribution_quality = Some(MatchQuality::ExactTuple);

        assert!(conn.executable.is_none());
        assert!(conn.process_uid.is_none());
        assert!(process_enrichment_complete(&conn, "Unknown"));
    }

    #[test]
    fn placeholder_identity_remains_eligible_for_an_upgrade() {
        let mut conn = connection();
        conn.pid = Some(42);
        conn.process_name = Some("Unknown".to_string());
        conn.attribution_quality = Some(MatchQuality::Unspecified);

        assert!(!process_enrichment_complete(&conn, "Unknown"));
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
