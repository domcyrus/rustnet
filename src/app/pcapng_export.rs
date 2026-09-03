//! Annotated PCAPNG export: attribution-delayed queueing, retry limits, and
//! per-packet comment construction. Wraps the wire-format writer in
//! `crate::export::pcapng`.

use anyhow::Result;
use crossbeam::channel::{self, Sender};
use log::{error, info, warn};
use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::export::pcapng::{self, PcapngWriter};
use crate::headless::events::dpi_domain;
use crate::network::capture::CaptureConfig;
use crate::network::tracker::ConnectionTracker;
use crate::network::types::{Connection, ConnectionKey};

use super::capture::{LinktypeWait, wait_for_linktype};
use super::state::App;
use super::types::AppStats;
use super::{MAX_PCAPNG_QUEUE, MAX_PCAPNG_RETRY_BYTES, MAX_PCAPNG_RETRY_RECORDS};

#[derive(Debug)]
pub(super) struct PcapngRecord {
    pub(super) data: Vec<u8>,
    pub(super) timestamp: SystemTime,
    pub(super) original_len: u32,
    pub(super) key: Option<ConnectionKey>,
    /// `created_at` of the connection that owned `key` when the packet was
    /// queued. Live keys are tuple-only, so a comment lookup at flush time
    /// must verify the tuple still belongs to the same generation; otherwise
    /// a rapidly reused tuple annotates this packet with the metadata of a
    /// connection it never belonged to.
    pub(super) conn_created_at: Option<SystemTime>,
    pub(super) deadline: Instant,
}

impl App {
    pub(super) fn start_pcapng_export_thread(
        &mut self,
        tracker: Arc<ConnectionTracker>,
    ) -> Result<Option<Sender<PcapngRecord>>> {
        if self.config.pcapng_export_file.is_none() {
            return Ok(None);
        }

        let stats = Arc::clone(&self.stats);
        let Some(file) = self.pcapng_export_file.take() else {
            warn!(
                "PCAPNG export configured but no pre-created file handle was provided; skipping export"
            );
            stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let export_path = self.config.pcapng_export_file.clone().unwrap_or_default();
        let (tx, rx) = channel::bounded::<PcapngRecord>(MAX_PCAPNG_QUEUE);
        let should_stop = Arc::clone(&self.should_stop);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_status = Arc::clone(&self.capture_status);
        let current_interface = Arc::clone(&self.current_interface);

        let handle = thread::Builder::new()
            .name("pcapng-export".to_string())
            .spawn(move || {
                info!("PCAPNG export thread starting: {}", export_path);
                let linktype =
                    match wait_for_linktype(&linktype_storage, &capture_status, &should_stop) {
                        LinktypeWait::Ready(linktype) => Some(linktype),
                        LinktypeWait::CaptureFailed => {
                            warn!(
                                "PCAPNG export could not observe capture linktype because capture setup failed; writing empty fallback section"
                            );
                            stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                        LinktypeWait::Stopped => {
                            info!(
                                "PCAPNG export did not observe capture linktype before shutdown; writing empty fallback section"
                            );
                            None
                        }
                    };
                let if_name = current_interface.read().unwrap().clone();
                let linktype = linktype.map(pcapng::linktype_to_u16).unwrap_or(1);
                let writer = std::io::BufWriter::new(file);
                let mut writer = match PcapngWriter::new(
                    writer,
                    linktype,
                    CaptureConfig::default().snaplen as u32,
                    if_name.as_deref(),
                ) {
                    Ok(writer) => writer,
                    Err(e) => {
                        error!("Failed to initialize PCAPNG writer: {}", e);
                        stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };

                let mut pending = VecDeque::<PcapngRecord>::new();
                let mut pending_bytes = 0usize;
                let mut next_retry_scan = Instant::now() + Duration::from_millis(50);

                loop {
                    if should_stop.load(Ordering::Relaxed) && rx.is_empty() {
                        break;
                    }

                    match rx.recv_timeout(Duration::from_millis(50)) {
                        Ok(record) => {
                            handle_pcapng_record(
                                record,
                                &tracker,
                                &mut writer,
                                &mut pending,
                                &mut pending_bytes,
                                &stats,
                            );
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
                    }

                    if Instant::now() >= next_retry_scan {
                        flush_ready_pcapng_records(
                            &tracker,
                            &mut writer,
                            &mut pending,
                            &mut pending_bytes,
                            &stats,
                            false,
                        );
                        next_retry_scan = Instant::now() + Duration::from_millis(50);
                    }
                }

                while let Ok(record) = rx.try_recv() {
                    handle_pcapng_record(
                        record,
                        &tracker,
                        &mut writer,
                        &mut pending,
                        &mut pending_bytes,
                        &stats,
                    );
                }
                flush_ready_pcapng_records(
                    &tracker,
                    &mut writer,
                    &mut pending,
                    &mut pending_bytes,
                    &stats,
                    true,
                );
                if let Err(e) = writer.flush() {
                    error!("Failed to flush PCAPNG export: {}", e);
                    stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
                }
                let dropped = stats.pcapng_records_dropped.load(Ordering::Relaxed);
                if dropped > 0 {
                    warn!(
                        "PCAPNG export dropped {} records under backpressure",
                        dropped
                    );
                }
                info!("PCAPNG export completed: {}", export_path);
            })
            .expect("Failed to spawn pcapng-export thread");
        self.retain_worker(handle);

        Ok(Some(tx))
    }
}

pub(super) fn send_pcapng_record(
    pcapng_tx: Option<&Sender<PcapngRecord>>,
    stats: &AppStats,
    record: PcapngRecord,
) {
    let Some(tx) = pcapng_tx else {
        return;
    };
    match tx.try_send(record) {
        Ok(()) => {
            stats.pcapng_records_queued.fetch_add(1, Ordering::Relaxed);
        }
        Err(crossbeam::channel::TrySendError::Full(_)) => {
            stats.pcapng_records_dropped.fetch_add(1, Ordering::Relaxed);
            static WARNED: AtomicBool = AtomicBool::new(false);
            if !WARNED.swap(true, Ordering::Relaxed) {
                warn!("PCAPNG export queue full; dropping export records under load");
            }
        }
        Err(crossbeam::channel::TrySendError::Disconnected(_)) => {}
    }
}

/// Queue one record, write out everything that is ready, then apply the
/// retry-queue caps.
fn handle_pcapng_record<W: Write>(
    record: PcapngRecord,
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
) {
    // Always enqueue so records leave in arrival order: an attributed packet
    // must not be written ahead of an older packet still waiting for
    // attribution, or the export file ends up out of timestamp order.
    *pending_bytes = pending_bytes.saturating_add(record.data.len());
    pending.push_back(record);
    flush_ready_pcapng_records(tracker, writer, pending, pending_bytes, stats, false);
    enforce_pcapng_retry_limits(tracker, writer, pending, pending_bytes, stats);
}

/// Write out pending records in FIFO order, stopping at the first record that
/// is still waiting for process attribution (unless `force`d or expired).
fn flush_ready_pcapng_records<W: Write>(
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
    force: bool,
) {
    let now = Instant::now();
    while let Some(record) = pending.front() {
        let comment = pcapng_comment(record, tracker);
        let attributed = comment.is_some();
        let expired = force || record.deadline <= now;
        if record.key.is_some() && !attributed && !expired {
            break;
        }
        let record = pending.pop_front().expect("front() was Some");
        *pending_bytes = pending_bytes.saturating_sub(record.data.len());
        // A record that expired unattributed may still have partial metadata
        // (direction, DPI, GeoIP) worth annotating.
        let comment = comment.or_else(|| pcapng_comment_if_any_metadata(&record, tracker));
        write_pcapng_record(writer, &record, comment.as_deref(), stats);
    }
}

/// Bound the retry queue: once it exceeds the record or byte cap, the oldest
/// records are written out with whatever metadata is available.
fn enforce_pcapng_retry_limits<W: Write>(
    tracker: &ConnectionTracker,
    writer: &mut PcapngWriter<W>,
    pending: &mut VecDeque<PcapngRecord>,
    pending_bytes: &mut usize,
    stats: &AppStats,
) {
    while pending.len() > MAX_PCAPNG_RETRY_RECORDS || *pending_bytes > MAX_PCAPNG_RETRY_BYTES {
        if let Some(record) = pending.pop_front() {
            *pending_bytes = pending_bytes.saturating_sub(record.data.len());
            let comment = pcapng_comment_if_any_metadata(&record, tracker);
            write_pcapng_record(writer, &record, comment.as_deref(), stats);
        } else {
            break;
        }
    }
}

fn write_pcapng_record<W: Write>(
    writer: &mut PcapngWriter<W>,
    record: &PcapngRecord,
    comment: Option<&str>,
    stats: &AppStats,
) {
    if let Err(e) =
        writer.write_packet(record.timestamp, &record.data, record.original_len, comment)
    {
        stats.pcapng_export_errors.fetch_add(1, Ordering::Relaxed);
        static WARNED: AtomicBool = AtomicBool::new(false);
        if !WARNED.swap(true, Ordering::Relaxed) {
            error!("Failed to write PCAPNG packet: {}", e);
        }
        return;
    }

    stats.pcapng_records_written.fetch_add(1, Ordering::Relaxed);
    if comment.is_some() {
        stats
            .pcapng_records_annotated
            .fetch_add(1, Ordering::Relaxed);
    } else {
        stats
            .pcapng_records_unannotated
            .fetch_add(1, Ordering::Relaxed);
    }
}

/// The live connection a queued record belongs to, if it is still tracked.
/// Rejects a connection whose `created_at` differs from the one the packet
/// was queued under: live keys are tuple-only, so a rapidly reused tuple
/// would otherwise annotate this packet with a later generation's metadata.
fn live_connection<'a>(
    record: &PcapngRecord,
    tracker: &'a ConnectionTracker,
) -> Option<impl std::ops::Deref<Target = Connection> + 'a> {
    let key = record.key?;
    let conn = tracker.connections().get(&key)?;
    if record.conn_created_at != Some(conn.created_at) {
        return None;
    }
    Some(conn)
}

/// Comment for a record whose connection already has process attribution;
/// `None` while attribution is still pending (or for keyless records).
fn pcapng_comment(record: &PcapngRecord, tracker: &ConnectionTracker) -> Option<String> {
    let conn = live_connection(record, tracker)?;
    if conn.pid.is_none() && conn.process_name.is_none() {
        return None;
    }
    build_pcapng_comment(&conn)
}

/// Like [`pcapng_comment`], but without requiring process attribution.
fn pcapng_comment_if_any_metadata(
    record: &PcapngRecord,
    tracker: &ConnectionTracker,
) -> Option<String> {
    let conn = live_connection(record, tracker)?;
    build_pcapng_comment(&conn)
}

fn build_pcapng_comment(conn: &Connection) -> Option<String> {
    let mut fields = vec!["rustnet".to_string()];
    if let Some(process) = &conn.process_name {
        fields.push(format!("process={}", sanitize_comment_value(process)));
    }
    if let Some(pid) = conn.pid {
        fields.push(format!("pid={pid}"));
    }
    if let Some(ppid) = conn.process_ppid {
        fields.push(format!("ppid={ppid}"));
    }
    // Deliberately no `exe=` here. This comment is written into every Enhanced
    // Packet Block, so a 40-character path would be repeated once per packet
    // and bloat the capture by tens of megabytes over a long run. The full path
    // lives in the per-connection JSONL sidecar instead. `ppid`, `uid`, and the
    // match quality are a handful of bytes and earn their place: uid=0 and a
    // relaxed match are both things an analyst wants to see without leaving
    // Wireshark.
    if let Some(uid) = conn.process_uid {
        fields.push(format!("uid={uid}"));
    }
    if let Some(quality) = conn.attribution_quality {
        // Already whitespace-free, so no sanitization needed.
        fields.push(format!("attr={}", quality.as_token()));
    }
    #[cfg(feature = "kubernetes")]
    if let Some(k8s) = &conn.k8s_info {
        if let Some(name) = &k8s.pod_name {
            fields.push(format!("pod={}", sanitize_comment_value(name)));
        }
        if let Some(ns) = &k8s.pod_namespace {
            fields.push(format!("ns={}", sanitize_comment_value(ns)));
        }
        if let Some(uid) = &k8s.pod_uid {
            fields.push(format!("pod_uid={}", sanitize_comment_value(uid)));
        }
        if let Some(name) = &k8s.container_name {
            fields.push(format!("container={}", sanitize_comment_value(name)));
        }
        if let Some(id) = &k8s.container_id {
            fields.push(format!("container_id={}", sanitize_comment_value(id)));
        }
    }
    if let Some(is_outgoing) = conn.connection_direction {
        fields.push(format!(
            "direction={}",
            if is_outgoing { "outgoing" } else { "incoming" }
        ));
    }
    if let Some(dpi) = &conn.dpi_info {
        fields.push(format!(
            "app={}",
            sanitize_comment_value(&dpi.application.to_string())
        ));
        if let Some(domain) = dpi_domain(&dpi.application) {
            fields.push(format!("sni={}", sanitize_comment_value(domain)));
        }
    }
    if let Some(geoip) = &conn.geoip_info {
        if let Some(country) = &geoip.country_code {
            fields.push(format!("country={}", sanitize_comment_value(country)));
        }
        if let Some(asn) = geoip.asn {
            fields.push(format!("asn={asn}"));
        }
    }
    if fields.len() == 1 {
        None
    } else {
        Some(fields.join(" "))
    }
}

fn sanitize_comment_value(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|c| {
            if c.is_control() || c.is_whitespace() || c == '\0' {
                '_'
            } else {
                c
            }
        })
        .collect();
    sanitized.trim_matches('_').to_string()
}

#[cfg(test)]
mod pcapng_export_tests {
    use super::*;
    use crate::network::parser::ParsedPacket;
    use crate::network::types::Protocol;
    use std::net::SocketAddr;

    fn record(data: u8, key: Option<ConnectionKey>, deadline: Instant) -> PcapngRecord {
        PcapngRecord {
            data: vec![data],
            timestamp: std::time::UNIX_EPOCH,
            original_len: 1,
            key,
            conn_created_at: None,
            deadline,
        }
    }

    /// A queued record must only be annotated with metadata from the exact
    /// connection generation it was captured under; a reused tuple's newer
    /// generation must not claim it.
    #[test]
    fn annotation_requires_matching_connection_generation() {
        use crate::network::types::{ProtocolState, TcpState};
        use rustnet_core::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};

        let tracker = ConnectionTracker::new();
        let mut packet = ParsedPacket::new(
            Protocol::Tcp,
            SocketAddr::from(([192, 0, 2, 9], 41_000)),
            SocketAddr::from(([198, 51, 100, 9], 443)),
            ProtocolState::Tcp(TcpState::Unknown),
            true,
            60,
            None,
            None,
        );
        packet.tcp_header = Some(TcpHeaderInfo {
            seq: 1,
            ack: 0,
            window: 65_535,
            flags: TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
            },
            payload_len: 0,
            window_scale: None,
        });
        let outcome = tracker.ingest_at(&packet, std::time::SystemTime::now());
        let key = outcome.key;
        tracker.connections().get_mut(&key).unwrap().process_name = Some("nginx".to_string());
        let created_at = tracker.connections().get(&key).unwrap().created_at;

        let mut matching = record(0xAA, Some(key), Instant::now());
        matching.conn_created_at = Some(created_at);
        assert!(pcapng_comment(&matching, &tracker).is_some());

        let mut stale = record(0xBB, Some(key), Instant::now());
        stale.conn_created_at = Some(created_at - Duration::from_secs(1));
        assert!(pcapng_comment(&stale, &tracker).is_none());
        assert!(pcapng_comment_if_any_metadata(&stale, &tracker).is_none());
    }

    /// Kubernetes attribution must be carried into the per-packet comment so
    /// annotated PCAPNG files are pod-aware without the sidecar JSONL.
    #[cfg(feature = "kubernetes")]
    #[test]
    fn comment_includes_kubernetes_attribution() {
        use crate::network::types::{K8sInfo, ProtocolState, TcpState};

        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::from(([10, 0, 0, 1], 4000)),
            SocketAddr::from(([10, 0, 0, 2], 443)),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.k8s_info = Some(K8sInfo {
            pod_uid: Some("c3b4d893-473e-43c2-8013-8ee2955a4630".to_string()),
            pod_name: Some("nginx-86644db9cc-mf5lx".to_string()),
            pod_namespace: Some("demo-traffic".to_string()),
            container_id: Some(
                "c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b".to_string(),
            ),
            container_name: Some("nginx".to_string()),
            cgroup_path: None,
        });

        let comment = build_pcapng_comment(&conn).expect("k8s info alone must produce a comment");
        assert!(comment.contains("pod=nginx-86644db9cc-mf5lx"));
        assert!(comment.contains("ns=demo-traffic"));
        assert!(comment.contains("pod_uid=c3b4d893-473e-43c2-8013-8ee2955a4630"));
        assert!(comment.contains("container=nginx"));
        assert!(comment.contains(
            "container_id=c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b"
        ));
    }

    /// The packet comment is written once per Enhanced Packet Block, so the
    /// cheap attribution fields belong there and the executable path does not.
    #[test]
    fn comment_carries_ppid_uid_and_match_quality_but_not_the_executable_path() {
        use crate::network::types::{MatchQuality, ProtocolState, TcpState};
        use std::path::Path;

        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::from(([10, 0, 0, 1], 4000)),
            SocketAddr::from(([10, 0, 0, 2], 443)),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.process_name = Some("curl".to_string());
        conn.pid = Some(4242);
        conn.process_ppid = Some(4000);
        conn.executable = Some(Arc::from(Path::new("/usr/bin/curl")));
        conn.process_uid = Some(0);
        conn.process_gid = Some(0);
        conn.attribution_quality = Some(MatchQuality::ProcfsRelaxed);

        let comment = build_pcapng_comment(&conn).expect("attributed connection must comment");
        assert!(comment.contains("process=curl"));
        assert!(comment.contains("pid=4242"));
        assert!(comment.contains("ppid=4000"));
        assert!(comment.contains("uid=0"));
        assert!(comment.contains("attr=procfs-relaxed"));
        assert!(
            !comment.contains("/usr/bin/curl"),
            "the executable path would repeat per packet; it belongs in the JSONL sidecar: {comment}"
        );
    }

    /// Attribution fields alone are enough metadata to justify a comment, and
    /// an unattributed connection still produces none.
    #[test]
    fn comment_is_absent_without_any_metadata() {
        use crate::network::types::{ProtocolState, TcpState};

        let conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::from(([10, 0, 0, 1], 4000)),
            SocketAddr::from(([10, 0, 0, 2], 443)),
            ProtocolState::Tcp(TcpState::Established),
        );

        assert_eq!(build_pcapng_comment(&conn), None);
    }

    /// Records must leave the pending queue in arrival order: a keyless
    /// (immediately writable) record queued behind one still waiting for
    /// attribution may not jump ahead of it in the export file.
    #[test]
    fn export_preserves_arrival_order_across_pending_records() {
        let tracker = ConnectionTracker::new();
        let stats = AppStats::default();
        let mut out = Vec::new();
        let mut writer = PcapngWriter::new(&mut out, 1, 1514, None).unwrap();
        let mut pending = VecDeque::new();
        let mut pending_bytes = 0usize;

        let key = ConnectionKey::new(
            Protocol::Tcp,
            SocketAddr::from(([127, 0, 0, 1], 1000)),
            SocketAddr::from(([127, 0, 0, 2], 2000)),
        );
        let far_deadline = Instant::now() + Duration::from_secs(3600);
        handle_pcapng_record(
            record(0xAA, Some(key), far_deadline),
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
        );
        handle_pcapng_record(
            record(0xBB, None, Instant::now()),
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
        );

        // Both records are held: the head is still waiting for attribution.
        assert_eq!(stats.pcapng_records_written.load(Ordering::Relaxed), 0);
        assert_eq!(pending.len(), 2);

        flush_ready_pcapng_records(
            &tracker,
            &mut writer,
            &mut pending,
            &mut pending_bytes,
            &stats,
            true,
        );
        writer.flush().unwrap();

        assert_eq!(stats.pcapng_records_written.load(Ordering::Relaxed), 2);
        assert!(pending.is_empty());
        assert_eq!(pending_bytes, 0);
        let pos_a = out.iter().position(|&b| b == 0xAA).unwrap();
        let pos_b = out.iter().position(|&b| b == 0xBB).unwrap();
        assert!(pos_a < pos_b, "records were written out of arrival order");
    }
}
