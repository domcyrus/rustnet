//! The packet-capture thread, the DPI packet-processor threads, and the
//! per-packet connection-update path.

use anyhow::Result;
use crossbeam::channel::{self, Receiver, Sender};
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use crate::network::{
    capture::{CaptureConfig, CapturedPacket, PacketReader, setup_packet_capture},
    dns::DnsResolver,
    parser::{PacketParser, ParsedPacket, ParserConfig},
    tracker::{ConnectionTracker, IngestOutcome},
};

use super::logging::{JsonLineWriter, log_connection_closed, log_connection_event};
use super::pcapng_export::{PcapngRecord, send_pcapng_record};
use super::runtime::InitStatus;
use super::state::App;
use super::types::AppStats;
use super::{PACKET_BATCH_QUEUE_CAPACITY, PACKET_BATCH_SIZE, PCAPNG_ATTRIBUTION_WAIT};

#[cfg(target_os = "linux")]
const ANY_INTERFACE_RETRY_DELAY: Duration = Duration::from_millis(100);
#[cfg(target_os = "linux")]
const ANY_INTERFACE_RETRY_WINDOW: Duration = Duration::from_secs(5);
const FINAL_BATCH_SEND_TIMEOUT: Duration = Duration::from_secs(1);

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

/// Outcome of waiting for the capture thread to publish its linktype.
pub(super) enum LinktypeWait {
    Ready(i32),
    /// Capture setup failed, so no linktype will ever be published.
    CaptureFailed,
    /// Shutdown was requested before the linktype became available.
    Stopped,
}

/// Capture resources opened during the privileged startup phase and moved
/// into the capture worker only after the sandbox has been applied.
pub(super) struct PreparedCapture {
    capture: pcap::Capture<pcap::Active>,
    device_name: String,
    packet_tx: Sender<Vec<CapturedPacket>>,
    pcap_writer: Option<ClassicPcapWriter>,
}

impl PreparedCapture {
    /// Flush a staged PCAP header if shutdown happens before the capture worker
    /// takes ownership of this prepared resource.
    pub(super) fn flush_pcap(&mut self) -> io::Result<()> {
        if let Some(writer) = &mut self.pcap_writer {
            writer.flush()?;
        }
        Ok(())
    }
}

/// Minimal classic-PCAP writer over the descriptor opened by the entry point.
/// Keeping serialization in-process avoids any platform-specific pathname
/// reopen in libpcap, including on Windows.
struct ClassicPcapWriter {
    output: BufWriter<File>,
}

impl ClassicPcapWriter {
    fn new(file: File, linktype: i32, snaplen: u32) -> io::Result<Self> {
        let mut output = BufWriter::new(file);
        output.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
        output.write_all(&2u16.to_le_bytes())?;
        output.write_all(&4u16.to_le_bytes())?;
        output.write_all(&0i32.to_le_bytes())?;
        output.write_all(&0u32.to_le_bytes())?;
        output.write_all(&snaplen.to_le_bytes())?;
        output.write_all(&(linktype as u32).to_le_bytes())?;
        Ok(Self { output })
    }

    fn write_packet(
        &mut self,
        timestamp: SystemTime,
        data: &[u8],
        original_len: u32,
    ) -> io::Result<()> {
        let elapsed = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "PCAP timestamp predates Unix epoch",
                )
            })?;
        let seconds = u32::try_from(elapsed.as_secs()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "PCAP timestamp exceeds u32 seconds",
            )
        })?;
        let captured_len = u32::try_from(data.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "captured packet is too large")
        })?;
        self.output.write_all(&seconds.to_le_bytes())?;
        self.output
            .write_all(&elapsed.subsec_micros().to_le_bytes())?;
        self.output.write_all(&captured_len.to_le_bytes())?;
        self.output
            .write_all(&original_len.max(captured_len).to_le_bytes())?;
        self.output.write_all(data)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

/// Assign a monotonically increasing sequence to batches as they leave the
/// shared receiver. The receiver and counter share one lock so cloned packet
/// processors cannot observe a later batch before an earlier one is numbered.
struct OrderedBatchReceiver<T> {
    state: Mutex<OrderedBatchReceiverState<T>>,
}

struct OrderedBatchReceiverState<T> {
    receiver: Receiver<T>,
    next_sequence: u64,
}

impl<T> OrderedBatchReceiver<T> {
    fn new(receiver: Receiver<T>) -> Self {
        Self {
            state: Mutex::new(OrderedBatchReceiverState {
                receiver,
                next_sequence: 0,
            }),
        }
    }

    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> std::result::Result<(u64, T), crossbeam::channel::RecvTimeoutError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let value = state.receiver.recv_timeout(timeout)?;
        let sequence = state.next_sequence;
        state.next_sequence = state.next_sequence.wrapping_add(1);
        Ok((sequence, value))
    }
}

/// Serializes tracker mutations in capture order while allowing parsing to run
/// concurrently. A guard advances the sequence even when the commit closure
/// unwinds, preventing one failed commit from permanently blocking shutdown.
#[derive(Default)]
struct OrderedBatchCommitter {
    next_sequence: Mutex<u64>,
    turn_changed: Condvar,
}

impl OrderedBatchCommitter {
    fn ticket(self: &Arc<Self>, sequence: u64) -> OrderedCommitTicket {
        OrderedCommitTicket {
            committer: Arc::clone(self),
            sequence,
            completed: false,
        }
    }

    fn commit<R>(&self, sequence: u64, commit: impl FnOnce() -> R) -> R {
        let mut next = self
            .next_sequence
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while *next != sequence {
            next = self
                .turn_changed
                .wait(next)
                .unwrap_or_else(|error| error.into_inner());
        }

        let guard = OrderedCommitGuard {
            committer: self,
            sequence,
        };
        drop(next);
        let result = commit();
        drop(guard);
        result
    }
}

/// Advances an assigned sequence if a processor unwinds before committing.
/// Without this ticket, one failed parser worker could strand every later
/// batch behind a sequence that will never arrive.
struct OrderedCommitTicket {
    committer: Arc<OrderedBatchCommitter>,
    sequence: u64,
    completed: bool,
}

impl OrderedCommitTicket {
    fn commit<R>(mut self, commit: impl FnOnce() -> R) -> R {
        self.completed = true;
        self.committer.commit(self.sequence, commit)
    }
}

impl Drop for OrderedCommitTicket {
    fn drop(&mut self) {
        if !self.completed {
            self.completed = true;
            self.committer.commit(self.sequence, || ());
        }
    }
}

struct OrderedCommitGuard<'a> {
    committer: &'a OrderedBatchCommitter,
    sequence: u64,
}

impl Drop for OrderedCommitGuard<'_> {
    fn drop(&mut self) {
        let mut next = self
            .committer
            .next_sequence
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        debug_assert_eq!(*next, self.sequence);
        *next = next.wrapping_add(1);
        self.committer.turn_changed.notify_all();
    }
}

/// Poll until the capture thread publishes the linktype, capture setup
/// fails, or shutdown is requested. A poisoned capture-status lock counts
/// as a failure.
pub(super) fn wait_for_linktype(
    linktype: &RwLock<Option<i32>>,
    capture_status: &RwLock<CaptureStatus>,
    should_stop: &AtomicBool,
) -> LinktypeWait {
    loop {
        if let Some(linktype) = *linktype.read().unwrap() {
            return LinktypeWait::Ready(linktype);
        }
        let capture_failed = capture_status
            .read()
            .map(|status| status.has_failed())
            .unwrap_or(true);
        if capture_failed {
            return LinktypeWait::CaptureFailed;
        }
        if should_stop.load(Ordering::Relaxed) {
            return LinktypeWait::Stopped;
        }
        thread::sleep(Duration::from_millis(10));
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

/// Send one packet batch without blocking capture. Queue overflow is counted
/// in packets, including the actual size of a partial batch.
fn try_send_packet_batch<T>(
    packet_tx: &Sender<Vec<T>>,
    batch: &mut Vec<T>,
    stats: &AppStats,
) -> ControlFlow<()> {
    let to_send = std::mem::replace(batch, Vec::with_capacity(PACKET_BATCH_SIZE));
    debug!("try_send: batch of {} packets", to_send.len());
    match packet_tx.try_send(to_send) {
        Ok(()) => ControlFlow::Continue(()),
        Err(crossbeam::channel::TrySendError::Full(rejected)) => {
            stats
                .packets_dropped
                .fetch_add(rejected.len() as u64, Ordering::Relaxed);
            ControlFlow::Continue(())
        }
        Err(crossbeam::channel::TrySendError::Disconnected(rejected)) => {
            stats
                .packets_dropped
                .fetch_add(rejected.len() as u64, Ordering::Relaxed);
            ControlFlow::Break(())
        }
    }
}

/// Give processors a bounded chance to accept the final partial batch. They
/// keep draining until the capture sender disconnects, so a short blocking
/// send preserves tail packets without making shutdown unbounded.
fn send_final_packet_batch<T>(
    packet_tx: &Sender<Vec<T>>,
    batch: &mut Vec<T>,
    stats: &AppStats,
    timeout: Duration,
) -> ControlFlow<()> {
    let to_send = std::mem::replace(batch, Vec::with_capacity(PACKET_BATCH_SIZE));
    match packet_tx.send_timeout(to_send, timeout) {
        Ok(()) => ControlFlow::Continue(()),
        Err(crossbeam::channel::SendTimeoutError::Timeout(rejected))
        | Err(crossbeam::channel::SendTimeoutError::Disconnected(rejected)) => {
            stats
                .packets_dropped
                .fetch_add(rejected.len() as u64, Ordering::Relaxed);
            ControlFlow::Break(())
        }
    }
}

/// Add only the change from libpcap's lifetime counters. The UI counters can
/// then be cleared without the next sample restoring pre-clear loss.
fn record_capture_drop_sample(
    stats: &AppStats,
    previous: &mut (u32, u32),
    capture_drops: u32,
    interface_drops: u32,
) {
    let capture_delta = capture_drops.wrapping_sub(previous.0) as u64;
    let interface_delta = interface_drops.wrapping_sub(previous.1) as u64;
    stats
        .capture_packets_dropped
        .fetch_add(capture_delta, Ordering::Relaxed);
    stats
        .interface_packets_dropped
        .fetch_add(interface_delta, Ordering::Relaxed);
    *previous = (capture_drops, interface_drops);
}

/// Initialize classic-PCAP output on the descriptor opened securely by the
/// entry point. No platform reopens the configured pathname.
fn prepare_pcap_writer(
    file: Option<File>,
    linktype: i32,
    snaplen: u32,
) -> io::Result<Option<ClassicPcapWriter>> {
    let Some(file) = file else {
        return Ok(None);
    };
    ClassicPcapWriter::new(file, linktype, snaplen).map(Some)
}

fn packet_predates_attribution_start(
    timestamp: SystemTime,
    capture_not_before: Option<SystemTime>,
) -> bool {
    capture_not_before.is_some_and(|cutoff| timestamp < cutoff)
}

fn route_pre_attribution_packet(
    packet: CapturedPacket,
    capture_not_before: Option<SystemTime>,
    pcapng_tx: Option<&Sender<PcapngRecord>>,
    stats: &AppStats,
) -> Option<CapturedPacket> {
    if !packet_predates_attribution_start(packet.timestamp, capture_not_before) {
        return Some(packet);
    }

    stats
        .pre_attribution_packets
        .fetch_add(1, Ordering::Relaxed);
    send_pcapng_record(
        pcapng_tx,
        stats,
        PcapngRecord {
            data: packet.data,
            timestamp: packet.timestamp,
            original_len: packet.original_len,
            key: None,
            conn_created_at: None,
            deadline: Instant::now(),
        },
    );
    None
}

impl App {
    pub(super) fn record_unavailable_pcap_export(&mut self) {
        if self.config.pcap_export_file.is_some() {
            self.pcap_export_file.take();
            self.stats.record_pcap_export_error();
            error!("Classic PCAP export is unavailable because capture setup failed");
        }
    }

    /// Open privileged capture resources synchronously, without starting a
    /// worker that could outlive the pre-sandbox phase. Capture-open failures
    /// become typed status so the TUI can retain process-only fallback while a
    /// future headless frontend can choose a fatal policy.
    pub(super) fn prepare_packet_capture_pipeline(&mut self) -> InitStatus {
        // Sender batches; derive the channel capacity from the packet limit so
        // queued packet data cannot exceed MAX_PACKET_QUEUE.
        let (packet_tx, packet_rx) =
            channel::bounded::<Vec<CapturedPacket>>(PACKET_BATCH_QUEUE_CAPACITY);

        let capture_config = CaptureConfig {
            interface: self.config.interface.clone(),
            filter: self.config.bpf_filter.clone(),
            ..Default::default()
        };
        let capture_snaplen = capture_config.snaplen as u32;
        *self.capture_status.write().unwrap() = CaptureStatus::Healthy;

        match setup_packet_capture(capture_config) {
            Ok((capture, device_name, linktype)) => {
                *self.current_interface.write().unwrap() = Some(device_name.clone());
                *self.linktype.write().unwrap() = Some(linktype);

                #[cfg(target_os = "macos")]
                self.record_pktap_status(linktype);

                let pcap_writer = match prepare_pcap_writer(
                    self.pcap_export_file.take(),
                    linktype,
                    capture_snaplen,
                ) {
                    Ok(savefile) => {
                        if self.config.pcap_export_file.is_some() {
                            info!("PCAP export initialized from pre-opened descriptor");
                        }
                        savefile
                    }
                    Err(error) => {
                        error!("Failed to initialize PCAP savefile: {}", error);
                        self.stats.record_pcap_export_error();
                        None
                    }
                };

                info!(
                    "Packet capture initialized on interface: {} (linktype: {})",
                    device_name, linktype
                );

                self.packet_rx = Some(packet_rx);
                self.prepared_capture = Some(PreparedCapture {
                    capture,
                    device_name,
                    packet_tx,
                    pcap_writer,
                });
                InitStatus::Ready
            }
            Err(error) => {
                self.record_unavailable_pcap_export();
                let error_msg = error.to_string();
                *self.capture_status.write().unwrap() = CaptureStatus::Failed(
                    capture_failure_message("Capture failed to start", &error),
                );

                if error_msg.contains("Insufficient privileges") {
                    error!("Failed to start packet capture due to insufficient privileges:");
                    for line in error_msg.lines() {
                        error!("{}", line);
                    }
                } else {
                    error!("Failed to start packet capture: {}", error);
                    error!(
                        "Make sure you have permission to capture packets (try running with sudo)"
                    );
                }

                warn!("Application will run in process-only mode");
                InitStatus::Failed(error_msg)
            }
        }
    }

    /// Spawn the DPI packet-processor threads, draining the channel stashed by
    /// [`App::prepare_packet_capture_pipeline`].
    pub(super) fn start_packet_processors(
        &mut self,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) -> Result<()> {
        let packet_rx = self.packet_rx.take().ok_or_else(|| {
            anyhow::anyhow!("packet receiver missing; start() must run before start_workers()")
        })?;

        let num_processors = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(4);

        let packet_rx = Arc::new(OrderedBatchReceiver::new(packet_rx));
        let batch_committer = Arc::new(OrderedBatchCommitter::default());
        for i in 0..num_processors {
            self.start_packet_processor(
                i,
                Arc::clone(&packet_rx),
                Arc::clone(&batch_committer),
                tracker.clone(),
                pcapng_tx.clone(),
            )?;
        }

        Ok(())
    }

    /// Move the prepared capture handle into its long-lived worker. This is
    /// called only after sandboxing, so the worker inherits the restricted
    /// execution context rather than retaining startup privileges.
    pub(super) fn start_capture_thread(
        &mut self,
        capture_not_before: Option<SystemTime>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) -> Result<bool> {
        let Some(PreparedCapture {
            capture,
            device_name,
            packet_tx,
            mut pcap_writer,
        }) = self.prepared_capture.take()
        else {
            return Ok(false);
        };
        let should_stop = Arc::clone(&self.should_stop);
        let stats = Arc::clone(&self.stats);
        let capture_status = Arc::clone(&self.capture_status);

        self.runtime
            .spawn_monitored("pcap_tx", move || {
                    info!("Packet capture worker started on interface: {}", device_name);
                    let mut reader = PacketReader::new(capture);
                    let mut packets_read = 0u64;
                    let mut pre_attribution_packets = 0u64;
                    let mut last_log = Instant::now();
                    let mut last_stats_check = Instant::now();
                    let mut previous_capture_drops = (0, 0);
                    let mut batch: Vec<CapturedPacket> = Vec::with_capacity(PACKET_BATCH_SIZE);
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
                    let send_batch =
                        |batch: &mut Vec<CapturedPacket>, batch_deadline: &mut Instant| {
                            if try_send_packet_batch(&packet_tx, batch, &stats).is_break() {
                                warn!("Packet channel closed");
                                record_failure(capture_failure_message(
                                    "Capture stopped",
                                    &"the packet processing threads exited",
                                ));
                                return ControlFlow::Break(());
                            }
                            *batch_deadline = Instant::now() + Duration::from_millis(100);
                            ControlFlow::Continue(())
                        };

                    loop {
                        if should_stop.load(Ordering::Relaxed) {
                            if !batch.is_empty() {
                                let _ = send_final_packet_batch(
                                    &packet_tx,
                                    &mut batch,
                                    &stats,
                                    FINAL_BATCH_SEND_TIMEOUT,
                                );
                            }
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

                                if let Some(ref mut writer) = pcap_writer {
                                    match writer.write_packet(
                                        packet.timestamp,
                                        &packet.data,
                                        packet.original_len,
                                    ) {
                                        Ok(()) => {
                                            stats
                                                .pcap_records_written
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        Err(error) => {
                                            error!("Failed to write PCAP packet: {error}");
                                            stats.record_pcap_export_error();
                                            pcap_writer = None;
                                        }
                                    }
                                }

                                let Some(packet) = route_pre_attribution_packet(
                                    packet,
                                    capture_not_before,
                                    pcapng_tx.as_ref(),
                                    &stats,
                                ) else {
                                    pre_attribution_packets =
                                        pre_attribution_packets.saturating_add(1);
                                    continue;
                                };

                                packets_read += 1;

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

                                batch.push(packet);

                                if (batch.len() >= PACKET_BATCH_SIZE
                                    || Instant::now() >= batch_deadline)
                                    && send_batch(&mut batch, &mut batch_deadline).is_break()
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
                                    && send_batch(&mut batch, &mut batch_deadline).is_break()
                                {
                                    break;
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
                                            && send_batch(&mut batch, &mut batch_deadline).is_break()
                                        {
                                            break;
                                        }
                                        thread::sleep(ANY_INTERFACE_RETRY_DELAY);
                                        continue;
                                    }
                                }

                                if !batch.is_empty() {
                                    let _ = send_final_packet_batch(
                                        &packet_tx,
                                        &mut batch,
                                        &stats,
                                        FINAL_BATCH_SEND_TIMEOUT,
                                    );
                                }
                                error!("Capture error: {}", e);
                                record_failure(capture_failure_message("Capture stopped", &e));
                                break;
                            }
                        }

                        // Poll independently of packet availability. Under a
                        // sustained stream `next_packet` may never time out,
                        // which is also when kernel loss is most likely.
                        if last_stats_check.elapsed() > Duration::from_secs(1) {
                            if let Ok(capture_stats) = reader.stats() {
                                if capture_stats.received > 0 {
                                    debug!(
                                        "Capture stats - Received: {}, Dropped: {}, Interface dropped: {}",
                                        capture_stats.received,
                                        capture_stats.capture_drops(),
                                        capture_stats.interface_drops()
                                    );
                                }
                                record_capture_drop_sample(
                                    &stats,
                                    &mut previous_capture_drops,
                                    capture_stats.capture_drops(),
                                    capture_stats.interface_drops(),
                                );
                            }
                            last_stats_check = Instant::now();
                        }
                    }

                    // Capture may stop before the next periodic sample. Fold in
                    // one final delta so shutdown reporting is complete.
                    if let Ok(capture_stats) = reader.stats() {
                        record_capture_drop_sample(
                            &stats,
                            &mut previous_capture_drops,
                            capture_stats.capture_drops(),
                            capture_stats.interface_drops(),
                        );
                    }

                    if let Some(ref mut writer) = pcap_writer {
                        if let Err(e) = writer.flush() {
                            error!("Failed to flush PCAP savefile: {}", e);
                            stats.record_pcap_export_error();
                        } else {
                            info!("PCAP export completed");
                        }
                    }

                    if pre_attribution_packets > 0 {
                        info!(
                            "Skipped attribution for {} packet(s) captured before ETW started",
                            pre_attribution_packets
                        );
                    }

                    info!(
                        "Capture thread exiting, total packets read: {}",
                        packets_read
                    );
                })
            .map_err(|error| anyhow::anyhow!("failed to spawn capture worker: {error}"))?;

        Ok(true)
    }

    #[cfg(target_os = "macos")]
    fn record_pktap_status(&self, linktype: i32) {
        use crate::network::capture::PktapUnavailable;
        use crate::network::link_layer::pktap;
        use crate::network::platform::{DegradationReason, report_pktap_degradation};

        if pktap::is_pktap_linktype(linktype) {
            self.pktap_active.store(true, Ordering::Relaxed);
            info!("✓ PKTAP is active - process metadata will be provided directly");
            return;
        }

        let reason = match crate::network::capture::PKTAP_DEGRADATION_REASON.get() {
            Some(PktapUnavailable::NoBpfDeviceAccess) => DegradationReason::NoBpfDeviceAccess,
            Some(PktapUnavailable::InterfaceSpecified) => DegradationReason::InterfaceSpecified,
            Some(PktapUnavailable::BpfFilterIncompatible) => {
                DegradationReason::BpfFilterIncompatible
            }
            Some(PktapUnavailable::MissingRootPrivileges) | None => {
                DegradationReason::MissingRootPrivileges
            }
        };
        report_pktap_degradation(reason);
    }

    fn start_packet_processor(
        &mut self,
        id: usize,
        packet_rx: Arc<OrderedBatchReceiver<Vec<CapturedPacket>>>,
        batch_committer: Arc<OrderedBatchCommitter>,
        tracker: Arc<ConnectionTracker>,
        pcapng_tx: Option<Sender<PcapngRecord>>,
    ) -> Result<()> {
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

        self.runtime
            .spawn_monitored(format!("pcap_rx_{id}"), move || {
                info!("Packet processor {} started", id);

                // This thread only parses captured bytes; it needs neither raw
                // sockets nor bpf(2) (Linux only).
                #[cfg(all(target_os = "linux", feature = "landlock"))]
                rustnet_sandbox::capabilities::drop_unused_thread_caps(&format!(
                    "processor thread {id}"
                ));

                let mut parser =
                    match wait_for_linktype(&linktype_storage, &capture_status, &should_stop) {
                        LinktypeWait::Ready(linktype) => {
                            let mut parser = PacketParser::with_config(parser_config.clone())
                                .with_linktype(linktype);
                            if let Some(ref oui) = oui_lookup {
                                parser = parser.with_oui_lookup(Arc::clone(oui));
                            }
                            parser
                        }
                        LinktypeWait::CaptureFailed | LinktypeWait::Stopped => {
                            info!("pcap_rx_{} exiting before linktype was available", id);
                            return;
                        }
                    };
                let mut total_processed = 0u64;
                let mut last_log = Instant::now();
                const LOCAL_ADDRESS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

                loop {
                    // Keep draining after shutdown is requested. The capture
                    // thread drops the final sender after flushing its partial
                    // batch, and disconnection is the processor's completion
                    // barrier.
                    let (batch_sequence, batch) =
                        match packet_rx.recv_timeout(Duration::from_millis(100)) {
                            Ok((sequence, batch)) => (sequence, batch),
                            Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => {
                                info!("Packet processor {} stopping", id);
                                break;
                            }
                        };
                    let commit_ticket = batch_committer.ticket(batch_sequence);
                    debug!("pcap_rx_{}: received batch of {} packets", id, batch.len());

                    // Process batch. Each packet parse is isolated with
                    // catch_unwind so that a single malformed/adversarial
                    // packet that panics a DPI parser cannot take down the
                    // whole pcap_rx thread and leave the monitor running
                    // blind.
                    // Connections are stamped with each packet's own capture
                    // time, not one clock read shared by the batch. Handshake
                    // RTT is the gap between two packets' timestamps, and a
                    // batch spans up to 100 packets or 100ms, wide enough to
                    // swallow a whole handshake and report its round trip as
                    // zero. libpcap already hands us the kernel's timestamp, so
                    // this costs no extra clock reads.
                    parser.refresh_local_ips_if_due(LOCAL_ADDRESS_REFRESH_INTERVAL);
                    let batch_len = batch.len();
                    let pcapng_enabled = pcapng_tx.is_some();
                    let mut parsed_batch = Vec::with_capacity(batch_len);
                    for packet in batch {
                        let parse_result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                parser.parse_packet_with_refresh(&packet.data)
                            }));
                        let parsed = match parse_result {
                            Ok(parsed) => parsed,
                            Err(_) => {
                                warn!(
                                    "pcap_rx_{}: parser panicked on a packet ({} bytes); skipping",
                                    id,
                                    packet.data.len()
                                );
                                None
                            }
                        };
                        parsed_batch.push((packet, parsed));
                    }

                    // Parsing is parallel, but tracker and export mutations
                    // must observe the capture stream in exact batch order.
                    let parsed_count = commit_ticket.commit(|| {
                        let mut parsed_count = 0;
                        for (packet, parsed) in parsed_batch {
                            let packet_timestamp = packet.timestamp;
                            let key = parsed.and_then(|parsed| {
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
                            });
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
                                        original_len: packet.original_len,
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
                        parsed_count
                    });

                    total_processed += batch_len as u64;
                    stats
                        .packets_processed
                        .fetch_add(batch_len as u64, Ordering::Relaxed);

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
            .map_err(|error| anyhow::anyhow!("failed to spawn packet processor {id}: {error}"))?;
        Ok(())
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
        log_connection_closed(
            conn,
            now,
            json_log_file.as_deref(),
            pcap_sidecar_file.as_deref(),
            dns_resolver,
        );
        debug!(
            "Archived prior connection generation before creating a new one: {}",
            outcome.key
        );
    }

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
    #[cfg(target_os = "linux")]
    use super::is_recoverable_any_interface_error;
    use super::{
        OrderedBatchCommitter, OrderedBatchReceiver, capture_failure_message,
        record_capture_drop_sample, send_final_packet_batch, try_send_packet_batch,
    };
    use crate::app::types::AppStats;
    use crate::app::{MAX_PACKET_QUEUE, PACKET_BATCH_QUEUE_CAPACITY, PACKET_BATCH_SIZE};
    use crossbeam::channel;
    use std::ops::ControlFlow;
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

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

    #[test]
    fn packet_batch_channel_is_bounded_by_packets_not_batches() {
        assert_eq!(
            PACKET_BATCH_QUEUE_CAPACITY * PACKET_BATCH_SIZE,
            MAX_PACKET_QUEUE
        );

        let (packet_tx, _packet_rx) = channel::bounded::<Vec<u8>>(PACKET_BATCH_QUEUE_CAPACITY);
        let stats = AppStats::default();

        for _ in 0..PACKET_BATCH_QUEUE_CAPACITY {
            let mut batch = vec![0; PACKET_BATCH_SIZE];
            assert_eq!(
                try_send_packet_batch(&packet_tx, &mut batch, &stats),
                ControlFlow::Continue(())
            );
        }

        let mut rejected = vec![0; PACKET_BATCH_SIZE];
        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut rejected, &stats),
            ControlFlow::Continue(())
        );
        assert_eq!(
            stats.packets_dropped.load(Ordering::Relaxed),
            PACKET_BATCH_SIZE as u64
        );
    }

    #[test]
    fn queue_overflow_counts_the_size_of_a_partial_batch() {
        let (packet_tx, _packet_rx) = channel::bounded::<Vec<u8>>(1);
        packet_tx.send(vec![0; PACKET_BATCH_SIZE]).unwrap();
        let stats = AppStats::default();
        let mut partial_batch = vec![0; 37];

        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut partial_batch, &stats),
            ControlFlow::Continue(())
        );
        assert!(partial_batch.is_empty());
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 37);
    }

    #[test]
    fn disconnected_processor_counts_the_rejected_batch() {
        let (packet_tx, packet_rx) = channel::bounded::<Vec<u8>>(1);
        drop(packet_rx);
        let stats = AppStats::default();
        let mut rejected = vec![0; 23];

        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut rejected, &stats),
            ControlFlow::Break(())
        );
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 23);
    }

    #[test]
    fn final_batch_waits_for_a_draining_processor() {
        let (tx, rx) = channel::bounded(1);
        tx.send(vec![1]).unwrap();
        let consumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(rx.recv().unwrap(), vec![1]);
            assert_eq!(rx.recv().unwrap(), vec![2, 3]);
        });
        let stats = AppStats::default();
        let mut final_batch = vec![2, 3];

        assert!(
            send_final_packet_batch(&tx, &mut final_batch, &stats, Duration::from_secs(1))
                .is_continue()
        );
        drop(tx);
        consumer.join().unwrap();
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dropped_batches_do_not_create_commit_sequence_gaps() {
        let (packet_tx, packet_rx) = channel::bounded::<Vec<u8>>(1);
        let ordered_rx = OrderedBatchReceiver::new(packet_rx);
        let stats = AppStats::default();

        let mut first = vec![1];
        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut first, &stats),
            ControlFlow::Continue(())
        );
        let mut dropped = vec![2];
        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut dropped, &stats),
            ControlFlow::Continue(())
        );

        let (first_sequence, first_batch) = ordered_rx.recv_timeout(Duration::ZERO).unwrap();
        assert_eq!((first_sequence, first_batch), (0, vec![1]));

        let mut third = vec![3];
        assert_eq!(
            try_send_packet_batch(&packet_tx, &mut third, &stats),
            ControlFlow::Continue(())
        );
        let (second_sequence, second_batch) = ordered_rx.recv_timeout(Duration::ZERO).unwrap();
        assert_eq!((second_sequence, second_batch), (1, vec![3]));
        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn commits_batches_in_capture_order_when_parsing_finishes_out_of_order() {
        let committer = Arc::new(OrderedBatchCommitter::default());
        let committed = Arc::new(Mutex::new(Vec::new()));
        let (release_earlier_tx, release_earlier_rx) = std::sync::mpsc::channel();
        let (later_parsed_tx, later_parsed_rx) = std::sync::mpsc::channel();

        let earlier_committer = Arc::clone(&committer);
        let earlier_committed = Arc::clone(&committed);
        let earlier = std::thread::spawn(move || {
            release_earlier_rx.recv().unwrap();
            earlier_committer.commit(0, || earlier_committed.lock().unwrap().push(0));
        });

        let later_committer = Arc::clone(&committer);
        let later_committed = Arc::clone(&committed);
        let later = std::thread::spawn(move || {
            later_parsed_tx.send(()).unwrap();
            later_committer.commit(1, || later_committed.lock().unwrap().push(1));
        });

        // Batch 1 has finished its simulated parse before batch 0 is allowed
        // to finish, but it cannot mutate the tracker-facing state first.
        later_parsed_rx.recv().unwrap();
        assert!(committed.lock().unwrap().is_empty());
        release_earlier_tx.send(()).unwrap();

        earlier.join().unwrap();
        later.join().unwrap();
        assert_eq!(*committed.lock().unwrap(), vec![0, 1]);
    }

    #[test]
    fn abandoned_batch_ticket_does_not_block_later_commits() {
        let committer = Arc::new(OrderedBatchCommitter::default());
        drop(committer.ticket(0));

        let mut committed = false;
        committer.ticket(1).commit(|| committed = true);

        assert!(committed);
    }

    #[test]
    fn capture_drop_deltas_survive_ui_counter_resets() {
        let stats = AppStats::default();
        stats.packets_dropped.store(23, Ordering::Relaxed);
        let mut previous = (0, 0);

        record_capture_drop_sample(&stats, &mut previous, 41, 7);

        assert_eq!(stats.packets_dropped.load(Ordering::Relaxed), 23);
        assert_eq!(stats.capture_packets_dropped.load(Ordering::Relaxed), 41);
        assert_eq!(stats.interface_packets_dropped.load(Ordering::Relaxed), 7);

        stats.capture_packets_dropped.store(0, Ordering::Relaxed);
        stats.interface_packets_dropped.store(0, Ordering::Relaxed);
        record_capture_drop_sample(&stats, &mut previous, 44, 9);

        assert_eq!(stats.capture_packets_dropped.load(Ordering::Relaxed), 3);
        assert_eq!(stats.interface_packets_dropped.load(Ordering::Relaxed), 2);
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

#[cfg(all(test, unix))]
mod prepared_pcap_tests {
    use super::prepare_pcap_writer;
    use crate::app::scratch_dir::ScratchDir;
    use std::fs::OpenOptions;
    use std::time::SystemTime;

    #[test]
    fn classic_pcap_writer_uses_retained_descriptor_instead_of_path() {
        let dir = ScratchDir::new("capture", "retained_pcap_fd");
        let original_path = dir.join("capture.pcap");
        let retained_path = dir.join("retained.pcap");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&original_path)
            .unwrap();

        std::fs::rename(&original_path, &retained_path).unwrap();
        std::fs::write(&original_path, b"replacement").unwrap();

        let mut writer = prepare_pcap_writer(Some(file), 1, 65_535).unwrap().unwrap();
        writer
            .write_packet(SystemTime::UNIX_EPOCH, &[1, 2, 3, 4], 4)
            .unwrap();
        writer.flush().unwrap();
        drop(writer);

        assert_eq!(std::fs::read(&original_path).unwrap(), b"replacement");
        assert!(std::fs::metadata(&retained_path).unwrap().len() > 24);
    }
}

#[cfg(test)]
mod connection_lifecycle_tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use rustnet_core::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};
    use std::net::SocketAddr;
    use std::path::Path;

    use crate::app::scratch_dir::ScratchDir;

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
    fn out_of_order_parse_completion_preserves_tracker_capture_order() {
        let committer = Arc::new(OrderedBatchCommitter::default());
        let tracker = Arc::new(ConnectionTracker::new());
        let stats = Arc::new(AppStats::default());
        let started = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let key = tcp_packet(flags(false, false)).connection_key();
        let earlier_ticket = committer.ticket(0);
        let later_ticket = committer.ticket(1);
        let (release_earlier_tx, release_earlier_rx) = std::sync::mpsc::channel();
        let (later_parsed_tx, later_parsed_rx) = std::sync::mpsc::channel();

        let earlier_tracker = Arc::clone(&tracker);
        let earlier_stats = Arc::clone(&stats);
        let earlier = std::thread::spawn(move || {
            let parsed = tcp_packet(flags(false, false));
            release_earlier_rx.recv().unwrap();
            earlier_ticket.commit(|| {
                update_connection(
                    &earlier_tracker,
                    parsed,
                    started,
                    &earlier_stats,
                    &None,
                    &None,
                    None,
                );
            });
        });

        let later_tracker = Arc::clone(&tracker);
        let later_stats = Arc::clone(&stats);
        let later = std::thread::spawn(move || {
            let parsed = tcp_packet(flags(false, false));
            later_parsed_tx.send(()).unwrap();
            later_ticket.commit(|| {
                update_connection(
                    &later_tracker,
                    parsed,
                    started + Duration::from_secs(1),
                    &later_stats,
                    &None,
                    &None,
                    None,
                );
            });
        });

        // The later batch has finished parsing but cannot create the
        // connection until the earlier batch reaches the commit phase.
        later_parsed_rx.recv().unwrap();
        assert!(tracker.connections().is_empty());
        release_earlier_tx.send(()).unwrap();

        earlier.join().unwrap();
        later.join().unwrap();
        assert_eq!(tracker.connections().get(&key).unwrap().created_at, started);
        assert_eq!(stats.total_connections_created.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn retained_json_writers_record_connection_lifecycle() {
        let dir = ScratchDir::new("lifecycle", "writers");
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

#[cfg(test)]
mod attribution_cutoff_tests {
    use super::{packet_predates_attribution_start, route_pre_attribution_packet};
    use crate::app::types::AppStats;
    use crate::network::capture::CapturedPacket;
    use crossbeam::channel;
    use std::sync::atomic::Ordering;
    use std::time::{Duration, SystemTime};

    #[test]
    fn packets_from_before_attribution_start_are_discarded() {
        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        assert!(packet_predates_attribution_start(
            cutoff - Duration::from_nanos(100),
            Some(cutoff)
        ));
        assert!(!packet_predates_attribution_start(cutoff, Some(cutoff)));
        assert!(!packet_predates_attribution_start(
            SystemTime::UNIX_EPOCH,
            None
        ));
    }

    #[test]
    fn pre_attribution_packet_is_counted_and_exported_without_a_key() {
        let cutoff = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let packet = CapturedPacket {
            data: vec![1, 2, 3],
            timestamp: cutoff - Duration::from_nanos(100),
            original_len: 3,
        };
        let stats = AppStats::default();
        let (tx, rx) = channel::bounded(1);

        assert!(route_pre_attribution_packet(packet, Some(cutoff), Some(&tx), &stats).is_none());
        assert_eq!(stats.pre_attribution_packets.load(Ordering::Relaxed), 1);
        let exported = rx
            .try_recv()
            .expect("packet should remain in PCAPNG output");
        assert_eq!(exported.data, vec![1, 2, 3]);
        assert!(exported.key.is_none());
    }
}
