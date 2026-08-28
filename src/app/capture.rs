//! The packet-capture thread, the DPI packet-processor threads, and the
//! per-packet connection-update path.

use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use log::{debug, error, info, warn};
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::network::{
    capture::{CaptureConfig, CapturedPacket, PacketReader, setup_packet_capture},
    dns::DnsResolver,
    parser::{PacketParser, ParsedPacket, ParserConfig},
    tracker::{ConnectionTracker, IngestOutcome},
};

use super::logging::{JsonLineWriter, log_connection_event, log_pcap_connection};
use super::pcapng_export::{PcapngRecord, send_pcapng_record};
use super::state::App;
use super::types::AppStats;
use super::{MAX_PACKET_QUEUE, PCAPNG_ATTRIBUTION_WAIT};

#[cfg(target_os = "linux")]
const ANY_INTERFACE_RETRY_DELAY: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const ANY_INTERFACE_RETRY_WINDOW: Duration = Duration::from_secs(5);

/// Current packet-capture health exposed to the UI.
#[derive(Debug, Default)]
pub(super) enum CaptureStatus {
    #[default]
    Healthy,
    Failed(String),
}

impl CaptureStatus {
    pub(super) fn has_failed(&self) -> bool {
        matches!(self, Self::Failed(_))
    }
}

/// Single-line description of a capture failure. Multi-line errors (the
/// privilege hint is several lines) are collapsed so the status bar can render
/// them; the recovery advice is appended by the UI, which knows how much of the
/// line is left for it.
fn capture_failure_message(context: &str, error: &impl std::fmt::Display) -> String {
    let mut detail = error
        .to_string()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if detail.is_empty() {
        detail.push_str("unknown error");
    }
    // Leave an existing "..." alone: shortening it would change what was reported.
    if !detail.ends_with(['.', '!', '?']) {
        detail.push('.');
    }
    format!("{context}: {detail}")
}

/// Linux libpcap can briefly report that the pseudo-device disappeared while
/// an underlying interface is removed. The aggregate `any` handle itself is
/// still usable, so retry only that exact typed libpcap error. A named device
/// with the same error has genuinely disappeared and must remain fatal.
#[cfg(target_os = "linux")]
fn is_recoverable_any_interface_error(device_name: &str, error: &anyhow::Error) -> bool {
    device_name == "any"
        && matches!(
            error.downcast_ref::<pcap::Error>(),
            Some(pcap::Error::PcapError(message))
                if message == "The interface disappeared"
        )
}

fn system_time_to_timeval(timestamp: SystemTime) -> libc::timeval {
    let duration = timestamp
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    #[cfg(unix)]
    {
        libc::timeval {
            tv_sec: duration.as_secs() as libc::time_t,
            tv_usec: duration.subsec_micros() as libc::suseconds_t,
        }
    }
    #[cfg(windows)]
    {
        libc::timeval {
            tv_sec: duration.as_secs() as libc::c_long,
            tv_usec: duration.subsec_micros() as libc::c_long,
        }
    }
}

impl App {
    /// Phase 1 of the capture pipeline: create the packet channel and start the
    /// capture thread (which opens the raw socket). The receiver is stashed in
    /// `self.packet_rx` for [`App::start_packet_processors`], which runs in the
    /// worker phase after the sandbox has been applied.
    ///
    /// Returns a receiver that fires once the capture thread has finished its
    /// privileged setup (capture device opened, or setup failed).
    pub(super) fn start_packet_capture_pipeline(
        &mut self,
    ) -> Result<std::sync::mpsc::Receiver<()>> {
        // Create packet channel — sender batches packets, receiver gets Vec<CapturedPacket> per batch
        let (packet_tx, packet_rx) = channel::bounded::<Vec<CapturedPacket>>(MAX_PACKET_QUEUE);

        // Start capture thread
        let capture_ready_rx = self.start_capture_thread(packet_tx)?;

        // Stash the receiver; the processor threads are spawned post-sandbox.
        self.packet_rx = Some(packet_rx);

        Ok(capture_ready_rx)
    }

    /// Spawn the DPI packet-processor threads, draining the channel stashed by
    /// [`App::start_packet_capture_pipeline`].
    pub(super) fn start_packet_processors(
        &mut self,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) -> Result<()> {
        let packet_rx = self.packet_rx.take().ok_or_else(|| {
            anyhow::anyhow!("packet receiver missing; start() must run before start_workers()")
        })?;

        // Start multiple packet processing threads
        let num_processors = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(4);

        for i in 0..num_processors {
            self.start_packet_processor(i, packet_rx.clone(), tracker.clone(), pcapng_tx.clone());
        }

        Ok(())
    }

    /// Start packet capture thread.
    ///
    /// Returns a receiver that fires once the capture device has been opened
    /// (or the open failed). Callers use it to keep root privileges alive
    /// until the open, which needs them, has actually happened.
    fn start_capture_thread(
        &self,
        packet_tx: Sender<Vec<CapturedPacket>>,
    ) -> Result<std::sync::mpsc::Receiver<()>> {
        // Validate interface exists before spawning thread (fail fast)
        crate::network::capture::validate_interface(&self.config.interface)?;

        let capture_config = CaptureConfig {
            interface: self.config.interface.clone(),
            filter: self.config.bpf_filter.clone(),
            ..Default::default()
        };

        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let current_interface = Arc::clone(&self.current_interface);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_status = Arc::clone(&self.capture_status);
        let _pktap_active = Arc::clone(&self.pktap_active);
        let pcap_export_file = self.config.pcap_export_file.clone();
        *capture_status.write().unwrap() = CaptureStatus::Healthy;

        // Fires once the privileged part of capture setup is done (device
        // opened or open failed), so the main thread can drop privileges.
        let (capture_ready_tx, capture_ready_rx) = std::sync::mpsc::sync_channel::<()>(1);

        thread::Builder::new()
            .name("pcap_tx".to_string())
            .spawn(move || {
            match setup_packet_capture(capture_config) {
                Ok((capture, device_name, linktype)) => {
                    // Store the actual interface name and linktype being used
                    *current_interface.write().unwrap() = Some(device_name.clone());
                    *linktype_storage.write().unwrap() = Some(linktype);

                    // Drop CAP_NET_RAW now that the socket is open (Linux only)
                    #[cfg(all(target_os = "linux", feature = "landlock"))]
                    rustnet_sandbox::capabilities::drop_unused_thread_caps(
                        "capture thread",
                    );

                    // Check if PKTAP is active (linktype 149 or 258)
                    #[cfg(target_os = "macos")]
                    {
                        use crate::network::link_layer::pktap;
                        if pktap::is_pktap_linktype(linktype) {
                            _pktap_active.store(true, Ordering::Relaxed);
                            info!("✓ PKTAP is active - process metadata will be provided directly");
                        } else {
                            // PKTAP not active: bridge the capture layer's reason into
                            // the process-attribution degradation reason. This keeps
                            // rustnet-host decoupled from rustnet-capture — the app
                            // (which orchestrates both) does the translation.
                            use crate::network::capture::PktapUnavailable;
                            use crate::network::platform::{
                                DegradationReason, report_pktap_degradation,
                            };
                            let reason = match crate::network::capture::PKTAP_DEGRADATION_REASON
                                .get()
                            {
                                Some(PktapUnavailable::NoBpfDeviceAccess) => {
                                    DegradationReason::NoBpfDeviceAccess
                                }
                                Some(PktapUnavailable::InterfaceSpecified) => {
                                    DegradationReason::InterfaceSpecified
                                }
                                Some(PktapUnavailable::BpfFilterIncompatible) => {
                                    DegradationReason::BpfFilterIncompatible
                                }
                                Some(PktapUnavailable::MissingRootPrivileges) | None => {
                                    DegradationReason::MissingRootPrivileges
                                }
                            };
                            report_pktap_degradation(reason);
                        }
                    }

                    info!(
                        "Packet capture started successfully on interface: {} (linktype: {})",
                        device_name, linktype
                    );

                    // Initialize PCAP export if configured (must be before PacketReader consumes capture)
                    let mut pcap_savefile = if let Some(ref pcap_path) = pcap_export_file {
                        match capture.savefile(pcap_path) {
                            Ok(savefile) => {
                                info!("PCAP export started: {}", pcap_path);
                                Some(savefile)
                            }
                            Err(e) => {
                                error!("Failed to create PCAP savefile: {}", e);
                                None
                            }
                        }
                    } else {
                        None
                    };

                    // Privileged setup is complete; the main thread may now
                    // drop root / apply the sandbox.
                    let _ = capture_ready_tx.send(());

                    let mut reader = PacketReader::new(capture);
                    let mut packets_read = 0u64;
                    let mut last_log = Instant::now();
                    let mut last_stats_check = Instant::now();
                    let mut batch: Vec<CapturedPacket> = Vec::with_capacity(100);
                    let mut batch_deadline = Instant::now() + Duration::from_millis(100);
                    #[cfg(target_os = "linux")]
                    let mut interface_change_retry_started: Option<Instant> = None;

                    // Every path that ends capture for a reason other than
                    // shutdown has to record it, or the TUI keeps looking
                    // healthy while the connection table silently freezes.
                    let record_failure = |message: String| {
                        if !should_stop.load(Ordering::Relaxed) {
                            *capture_status.write().unwrap() = CaptureStatus::Failed(message);
                        }
                    };

                    // Hand the current batch to the processors and reset the
                    // deadline. Returns `Break` when the receiving side is gone
                    // and the capture loop must exit.
                    let send_batch = |batch: &mut Vec<CapturedPacket>,
                                      batch_deadline: &mut Instant,
                                      what: &str|
                     -> ControlFlow<()> {
                        let to_send = std::mem::replace(batch, Vec::with_capacity(100));
                        let batch_size = to_send.len() as u64;
                        debug!("try_send: {} batch of {} packets", what, batch_size);
                        match packet_tx.try_send(to_send) {
                            Ok(()) => {}
                            Err(crossbeam::channel::TrySendError::Full(_)) => {
                                stats.packets_dropped.fetch_add(batch_size, Ordering::Relaxed);
                            }
                            Err(crossbeam::channel::TrySendError::Disconnected(_)) => {
                                warn!("Packet channel closed");
                                record_failure(capture_failure_message(
                                    "Capture stopped",
                                    &"the packet processing threads exited",
                                ));
                                return ControlFlow::Break(());
                            }
                        }
                        *batch_deadline = Instant::now() + Duration::from_millis(100);
                        ControlFlow::Continue(())
                    };

                    loop {
                        if should_stop.load(Ordering::Relaxed) {
                            info!("Capture thread stopping");
                            break;
                        }

                        match reader.next_packet() {
                            Ok(Some(packet)) => {
                                #[cfg(target_os = "linux")]
                                if interface_change_retry_started.take().is_some() {
                                    info!(
                                        "Packet capture on 'any' resumed after an interface change"
                                    );
                                }

                                packets_read += 1;

                                // Log first packet immediately
                                if packets_read == 1 {
                                    info!(
                                        "First packet captured! Size: {} bytes",
                                        packet.data.len()
                                    );
                                }

                                // Log every 10000 packets or every 5 seconds
                                if packets_read.is_multiple_of(10000)
                                    || last_log.elapsed() > Duration::from_secs(5)
                                {
                                    info!("Read {} packets so far", packets_read);
                                    last_log = Instant::now();
                                }

                                // Write to PCAP file if enabled
                                if let Some(ref mut savefile) = pcap_savefile {
                                    let ts = system_time_to_timeval(packet.timestamp);
                                    let header = pcap::PacketHeader {
                                        ts,
                                        caplen: packet.data.len() as u32,
                                        len: packet.original_len.max(packet.data.len() as u32),
                                    };
                                    savefile.write(&pcap::Packet {
                                        header: &header,
                                        data: &packet.data,
                                    });
                                    stats.pcap_records_written.fetch_add(1, Ordering::Relaxed);
                                }

                                batch.push(packet);

                                // Send batch when full or deadline reached
                                if (batch.len() >= 100 || Instant::now() >= batch_deadline)
                                    && send_batch(&mut batch, &mut batch_deadline, "sending")
                                        .is_break()
                                {
                                    break;
                                }
                            }
                            Ok(None) => {
                                #[cfg(target_os = "linux")]
                                if interface_change_retry_started.take().is_some() {
                                    info!(
                                        "Packet capture on 'any' resumed after an interface change"
                                    );
                                }

                                // Timeout - flush partial batch if deadline reached
                                if !batch.is_empty()
                                    && Instant::now() >= batch_deadline
                                    && send_batch(&mut batch, &mut batch_deadline, "flushing partial")
                                        .is_break()
                                {
                                    break;
                                }

                                // Check stats every second
                                if last_stats_check.elapsed() > Duration::from_secs(1) {
                                    if let Ok(capture_stats) = reader.stats() {
                                        if capture_stats.received > 0 {
                                            debug!(
                                                "Capture stats - Received: {}, Dropped: {}",
                                                capture_stats.received, capture_stats.dropped
                                            );
                                        }
                                        stats
                                            .packets_dropped
                                            .store(capture_stats.dropped as u64, Ordering::Relaxed);
                                    }
                                    last_stats_check = Instant::now();
                                }
                            }
                            Err(e) => {
                                #[cfg(target_os = "linux")]
                                if is_recoverable_any_interface_error(&device_name, &e) {
                                    let first_retry = interface_change_retry_started.is_none();
                                    let retry_started = *interface_change_retry_started
                                        .get_or_insert_with(Instant::now);
                                    if retry_started.elapsed() < ANY_INTERFACE_RETRY_WINDOW {
                                        if first_retry {
                                            warn!(
                                                "An interface changed while capturing on 'any'; retrying the existing capture handle"
                                            );
                                        }
                                        if !batch.is_empty()
                                            && send_batch(
                                                &mut batch,
                                                &mut batch_deadline,
                                                "flushing before interface-change retry",
                                            )
                                            .is_break()
                                        {
                                            break;
                                        }
                                        thread::sleep(ANY_INTERFACE_RETRY_DELAY);
                                        continue;
                                    }
                                }

                                error!("Capture error: {}", e);
                                record_failure(capture_failure_message("Capture stopped", &e));
                                break;
                            }
                        }
                    }

                    // Flush PCAP savefile before exiting
                    if let Some(ref mut savefile) = pcap_savefile {
                        if let Err(e) = savefile.flush() {
                            error!("Failed to flush PCAP savefile: {}", e);
                        } else {
                            info!("PCAP export completed");
                        }
                    }

                    info!(
                        "Capture thread exiting, total packets read: {}",
                        packets_read
                    );
                }
                Err(e) => {
                    *capture_status.write().unwrap() = CaptureStatus::Failed(
                        capture_failure_message("Capture failed to start", &e),
                    );
                    let _ = capture_ready_tx.send(());
                    let error_msg = format!("{}", e);

                    // Check if this is a privilege error
                    if error_msg.contains("Insufficient privileges") {
                        error!("Failed to start packet capture due to insufficient privileges:");
                        // The error message already contains detailed instructions
                        for line in error_msg.lines() {
                            error!("{}", line);
                        }
                    } else {
                        error!("Failed to start packet capture: {}", e);
                        error!(
                            "Make sure you have permission to capture packets (try running with sudo)"
                        );
                    }

                    warn!("Application will run in process-only mode");
                }
            }
        })
        .expect("Failed to spawn pcap_tx thread");

        Ok(capture_ready_rx)
    }

    /// Start a packet processor thread
    fn start_packet_processor(
        &self,
        id: usize,
        packet_rx: Receiver<Vec<CapturedPacket>>,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) {
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let linktype_storage = Arc::clone(&self.linktype);
        let capture_status = Arc::clone(&self.capture_status);
        let json_log_file = self.json_log_file.clone();
        let pcap_sidecar_file = self.pcap_sidecar_file.clone();
        let dns_resolver = self.dns_resolver.clone();
        let oui_lookup = self.oui_lookup.clone();
        let parser_config = ParserConfig {
            enable_dpi: self.config.enable_dpi,
            ..Default::default()
        };

        thread::Builder::new()
            .name(format!("pcap_rx_{}", id))
            .spawn(move || {
                info!("Packet processor {} started", id);

                // This thread only parses captured bytes; it needs neither raw
                // sockets nor bpf(2) (Linux only).
                #[cfg(all(target_os = "linux", feature = "landlock"))]
                rustnet_sandbox::capabilities::drop_unused_thread_caps(&format!(
                    "processor thread {id}"
                ));

                // Wait for linktype to be available
                let mut parser = loop {
                    if let Some(linktype) = *linktype_storage.read().unwrap() {
                        let mut parser = PacketParser::with_config(parser_config.clone())
                            .with_linktype(linktype);
                        if let Some(ref oui) = oui_lookup {
                            parser = parser.with_oui_lookup(Arc::clone(oui));
                        }
                        break parser;
                    }
                    let capture_failed = capture_status
                        .read()
                        .map(|status| status.has_failed())
                        .unwrap_or(true);
                    if capture_failed || should_stop.load(Ordering::Relaxed) {
                        info!("pcap_rx_{} exiting before linktype was available", id);
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                };
                let mut total_processed = 0u64;
                let mut last_log = Instant::now();
                const LOCAL_ADDRESS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

                loop {
                    if should_stop.load(Ordering::Relaxed) {
                        info!("Packet processor {} stopping", id);
                        break;
                    }

                    // Block until sender delivers a full batch (no spin, no polling)
                    let batch = match packet_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(batch) => {
                            debug!("pcap_rx_{}: received batch of {} packets", id, batch.len());
                            batch
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                            info!("pcap_rx_{}: channel disconnected, exiting", id);
                            return;
                        }
                    };

                    // Process batch. Each packet parse is isolated with
                    // catch_unwind so that a single malformed/adversarial
                    // packet that panics a DPI parser cannot take down the
                    // whole pcap_rx thread and leave the monitor running
                    // blind.
                    // Connections are stamped with each packet's own capture
                    // time, not one clock read shared by the batch. Handshake
                    // RTT is the gap between two packets' timestamps, and a
                    // batch spans up to 100 packets or 100ms — wide enough to
                    // swallow a whole handshake and report its round trip as
                    // zero. libpcap already hands us the kernel's timestamp, so
                    // this costs no extra clock reads.
                    parser.refresh_local_ips_if_due(LOCAL_ADDRESS_REFRESH_INTERVAL);
                    let mut parsed_count = 0;
                    let batch_len = batch.len();
                    let pcapng_enabled = pcapng_tx.is_some();
                    for packet in batch {
                        let packet_timestamp = packet.timestamp;
                        let packet_original_len = packet.original_len;
                        let parse_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                parser.parse_packet_with_refresh(&packet.data)
                            }));
                        let key = match parse_result {
                            Ok(Some(parsed)) => {
                                let outcome = update_connection(
                                    &tracker,
                                    parsed,
                                    packet_timestamp,
                                    &stats,
                                    &json_log_file,
                                    &pcap_sidecar_file,
                                    dns_resolver.as_deref(),
                                );
                                parsed_count += 1;
                                if outcome.dropped || outcome.ignored_late {
                                    None
                                } else {
                                    Some(outcome.key)
                                }
                            }
                            Ok(None) => None,
                            Err(_) => {
                                warn!(
                                    "pcap_rx_{}: parser panicked on a packet ({} bytes); skipping",
                                    id,
                                    packet.data.len()
                                );
                                None
                            }
                        };
                        if pcapng_enabled {
                            let conn_created_at = key.and_then(|key| {
                                tracker.connections().get(&key).map(|conn| conn.created_at)
                            });
                            send_pcapng_record(
                                pcapng_tx.as_ref(),
                                &stats,
                                PcapngRecord {
                                    data: packet.data,
                                    timestamp: packet_timestamp,
                                    original_len: packet_original_len,
                                    key,
                                    conn_created_at,
                                    deadline: if key.is_some() {
                                        Instant::now() + PCAPNG_ATTRIBUTION_WAIT
                                    } else {
                                        Instant::now()
                                    },
                                },
                            );
                        }
                    }

                    total_processed += batch_len as u64;
                    stats
                        .packets_processed
                        .fetch_add(batch_len as u64, Ordering::Relaxed);

                    // Log progress
                    if total_processed.is_multiple_of(10000)
                        || last_log.elapsed() > Duration::from_secs(5)
                    {
                        debug!(
                            "Processor {}: {} packets processed ({} parsed)",
                            id, total_processed, parsed_count
                        );
                        last_log = Instant::now();
                    }
                }

                info!(
                    "Packet processor {} exiting, total processed: {}",
                    id, total_processed
                );
            })
            .unwrap_or_else(|_| panic!("Failed to spawn pcap_rx_{} thread", id));
    }
}

/// Update or create a connection from a parsed packet.
///
/// The connection table, RTT tracking, QUIC coalescing, and the connection
/// limit all live in the shared [`ConnectionTracker`]; this wrapper layers the
/// app-specific concerns (global statistics and JSON event logging) on top of
/// the tracker's [`IngestOutcome`].
fn update_connection(
    tracker: &ConnectionTracker,
    parsed: ParsedPacket,
    now: SystemTime,
    stats: &AppStats,
    json_log_file: &Option<Arc<JsonLineWriter>>,
    pcap_sidecar_file: &Option<Arc<JsonLineWriter>>,
    dns_resolver: Option<&DnsResolver>,
) -> IngestOutcome {
    let outcome = tracker.ingest_at(&parsed, now);

    // Fold TCP anomaly counts into the global statistics.
    if outcome.retransmits > 0 {
        stats
            .total_tcp_retransmits
            .fetch_add(outcome.retransmits, Ordering::Relaxed);
    }
    if outcome.out_of_order > 0 {
        stats
            .total_tcp_out_of_order
            .fetch_add(outcome.out_of_order, Ordering::Relaxed);
    }
    if outcome.fast_retransmits > 0 {
        stats
            .total_tcp_fast_retransmits
            .fetch_add(outcome.fast_retransmits, Ordering::Relaxed);
    }

    if outcome.dropped {
        debug!(
            "Connection limit reached, dropping new connection: {}",
            outcome.key
        );
        return outcome;
    }
    if outcome.ignored_late {
        debug!(
            "Ignoring delayed packet for recently archived connection: {}",
            outcome.key
        );
        return outcome;
    }

    if let Some(conn) = &outcome.archived {
        stats
            .total_connections_archived
            .fetch_add(1, Ordering::Relaxed);
        let duration_secs = now
            .duration_since(conn.created_at)
            .map(|duration| duration.as_secs())
            .ok();
        if let Some(writer) = json_log_file {
            log_connection_event(
                writer,
                "connection_closed",
                conn,
                duration_secs,
                dns_resolver,
            );
        }
        if let Some(writer) = pcap_sidecar_file {
            log_pcap_connection(writer, conn);
        }
        debug!(
            "Archived prior connection generation before creating a new one: {}",
            outcome.key
        );
    }

    // Log a new-connection event if JSON logging is enabled.
    if outcome.created {
        stats
            .total_connections_created
            .fetch_add(1, Ordering::Relaxed);
        debug!("New connection detected: {}", outcome.key);
        if let Some(writer) = json_log_file
            && let Some(conn) = tracker.connections().get(&outcome.key)
        {
            log_connection_event(writer, "new_connection", conn.value(), None, dns_resolver);
        }
    }

    outcome
}

#[cfg(test)]
mod capture_failure_message_tests {
    use super::capture_failure_message;
    #[cfg(target_os = "linux")]
    use super::is_recoverable_any_interface_error;

    #[test]
    fn collapses_multi_line_errors_and_terminates_the_sentence() {
        let error = "Insufficient privileges\n  How to fix:\n  1. Run with sudo";
        assert_eq!(
            capture_failure_message("Capture failed to start", &error),
            "Capture failed to start: Insufficient privileges How to fix: 1. Run with sudo."
        );
    }

    #[test]
    fn keeps_existing_terminal_punctuation() {
        assert_eq!(
            capture_failure_message("Capture stopped", &"Device busy, retrying..."),
            "Capture stopped: Device busy, retrying..."
        );
        assert_eq!(
            capture_failure_message("Capture stopped", &"Interface went down."),
            "Capture stopped: Interface went down."
        );
    }

    #[test]
    fn reports_a_cause_even_when_the_error_renders_empty() {
        assert_eq!(
            capture_failure_message("Capture stopped", &"  \n "),
            "Capture stopped: unknown error."
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retries_typed_interface_disappearance_only_for_linux_any() {
        let disappeared: anyhow::Error =
            pcap::Error::PcapError("The interface disappeared".to_string()).into();

        assert!(is_recoverable_any_interface_error("any", &disappeared));
        assert!(!is_recoverable_any_interface_error(
            "nordlynx",
            &disappeared
        ));

        let untyped = anyhow::anyhow!("The interface disappeared");
        assert!(!is_recoverable_any_interface_error("any", &untyped));

        let different: anyhow::Error =
            pcap::Error::PcapError("The interface disappeared.".to_string()).into();
        assert!(!is_recoverable_any_interface_error("any", &different));
    }
}

#[cfg(test)]
mod connection_lifecycle_tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use rustnet_core::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "rustnet-lifecycle-test-{}-{}",
                std::process::id(),
                tag
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn tcp_packet(flags: TcpFlags) -> ParsedPacket {
        let mut packet = ParsedPacket::new(
            Protocol::Tcp,
            SocketAddr::from(([192, 0, 2, 1], 40_000)),
            SocketAddr::from(([198, 51, 100, 1], 443)),
            ProtocolState::Tcp(TcpState::Unknown),
            true,
            60,
            None,
            None,
        );
        packet.tcp_header = Some(TcpHeaderInfo {
            seq: 1_000,
            ack: 0,
            window: 65_535,
            flags,
            payload_len: 0,
            window_scale: None,
        });
        packet
    }

    fn flags(syn: bool, rst: bool) -> TcpFlags {
        TcpFlags {
            syn,
            rst,
            ack: false,
            fin: false,
        }
    }

    fn json_writer(path: &Path) -> Arc<JsonLineWriter> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        Arc::new(JsonLineWriter::new(
            file,
            path.to_string_lossy().into_owned(),
        ))
    }

    #[test]
    fn lifecycle_counters_record_new_and_replaced_generations() {
        let tracker = ConnectionTracker::new();
        let stats = AppStats::default();
        let no_log = None;
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        update_connection(
            &tracker,
            tcp_packet(flags(true, false)),
            started,
            &stats,
            &no_log,
            &no_log,
            None,
        );
        update_connection(
            &tracker,
            tcp_packet(flags(false, true)),
            started + Duration::from_secs(1),
            &stats,
            &no_log,
            &no_log,
            None,
        );
        update_connection(
            &tracker,
            tcp_packet(flags(true, false)),
            started + Duration::from_secs(2),
            &stats,
            &no_log,
            &no_log,
            None,
        );

        assert_eq!(stats.total_connections_created.load(Ordering::Relaxed), 2);
        assert_eq!(stats.total_connections_archived.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn retained_json_writers_record_connection_lifecycle() {
        let dir = ScratchDir::new("writers");
        let events_path = dir.path().join("events.jsonl");
        let sidecar_path = dir.path().join("capture.pcap.connections.jsonl");
        let events = Some(json_writer(&events_path));
        let sidecar = Some(json_writer(&sidecar_path));
        let tracker = ConnectionTracker::new();
        let stats = AppStats::default();
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        update_connection(
            &tracker,
            tcp_packet(flags(true, false)),
            started,
            &stats,
            &events,
            &sidecar,
            None,
        );
        update_connection(
            &tracker,
            tcp_packet(flags(false, true)),
            started + Duration::from_secs(1),
            &stats,
            &events,
            &sidecar,
            None,
        );
        update_connection(
            &tracker,
            tcp_packet(flags(true, false)),
            started + Duration::from_secs(2),
            &stats,
            &events,
            &sidecar,
            None,
        );

        let event_lines = std::fs::read_to_string(events_path).unwrap();
        assert_eq!(event_lines.lines().count(), 3);
        assert_eq!(
            event_lines.matches("\"event\":\"new_connection\"").count(),
            2
        );
        assert_eq!(
            event_lines
                .matches("\"event\":\"connection_closed\"")
                .count(),
            1
        );

        let sidecar_lines = std::fs::read_to_string(sidecar_path).unwrap();
        assert_eq!(sidecar_lines.lines().count(), 1);
        assert!(sidecar_lines.contains("\"protocol\":\"TCP\""));
    }
}
