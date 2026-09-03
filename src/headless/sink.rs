//! Line sinks for the JSONL event stream: a synchronous writer for the
//! `--json-log` file and the PCAP sidecar, and a queued stdout writer whose
//! producers never block on a slow terminal or pipe.

use crossbeam::channel::{self, Receiver, RecvTimeoutError, Sender, TrySendError};
use log::warn;
use serde::Serialize;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::MAX_EVENT_QUEUE;
use crate::filter::ConnectionFilter;
use crate::network::types::Connection;

/// How long the stdout writer waits for a line before re-checking its stop
/// flag.
const WRITER_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// A destination for JSONL lines, shared by every thread that emits events.
pub trait EventSink: Send + Sync {
    /// Append one line; the sink adds the newline.
    fn write_line(&self, line: &str);

    /// Whether this sink wants the events of `conn`. A sink that declines
    /// every connection of an event still costs nothing: the event is not
    /// even serialized.
    fn accepts(&self, _conn: &Connection) -> bool {
        true
    }

    /// Spawn the sink's writer thread, if it has one. The app calls this
    /// after the sandbox is applied so the thread inherits it.
    fn start(&self) {}

    /// Ask the writer thread to exit once its queue is drained and hand back
    /// its handle for a bounded join.
    fn shutdown(&self) -> Option<JoinHandle<()>> {
        None
    }
}

/// One JSON document as a JSONL line. Serialization of the wire structs
/// cannot fail in practice; a failure is logged rather than propagated so an
/// emitting thread never stops over its own output.
pub fn json_line(value: &impl Serialize) -> Option<String> {
    match serde_json::to_string(value) {
        Ok(line) => Some(line),
        Err(e) => {
            warn!("Failed to serialize JSON event: {e}");
            None
        }
    }
}

/// Hand one event about `conn` to every sink that accepts it, building and
/// serializing the event only when at least one does. The event is built
/// lazily because building a record can queue reverse DNS lookups, which a
/// connection nobody wants to hear about should not trigger.
pub fn write_connection_event<E: Serialize>(
    sinks: &[Arc<dyn EventSink>],
    conn: &Connection,
    event: impl FnOnce() -> E,
) {
    let accepting: Vec<&Arc<dyn EventSink>> =
        sinks.iter().filter(|sink| sink.accepts(conn)).collect();
    if accepting.is_empty() {
        return;
    }
    if let Some(line) = json_line(&event()) {
        for sink in accepting {
            sink.write_line(&line);
        }
    }
}

/// A sink that forwards to another one only the connections matching a
/// [`ConnectionFilter`]. Lines written directly to the inner sink (the
/// startup and snapshot events) are unaffected.
pub struct FilteredSink {
    filter: ConnectionFilter,
    inner: Arc<dyn EventSink>,
}

impl FilteredSink {
    pub fn new(filter: ConnectionFilter, inner: Arc<dyn EventSink>) -> Self {
        Self { filter, inner }
    }
}

impl EventSink for FilteredSink {
    fn write_line(&self, line: &str) {
        self.inner.write_line(line);
    }

    fn accepts(&self, conn: &Connection) -> bool {
        self.filter.matches(conn)
    }

    fn start(&self) {
        self.inner.start();
    }

    fn shutdown(&self) -> Option<JoinHandle<()>> {
        self.inner.shutdown()
    }
}

/// A synchronous JSONL writer over a descriptor opened before sandboxing
/// and uid drop.
///
/// Keeping the descriptor open is required for paths such as `/root`: after
/// dropping to the invoking user or `nobody`, the process may no longer be
/// able to traverse the parent directory even when the file itself was
/// chowned.
pub struct FileSink<W: Write + Send = File> {
    writer: Mutex<W>,
    path: String,
    failure_reported: AtomicBool,
}

impl<W: Write + Send> FileSink<W> {
    pub fn new(writer: W, path: impl Into<String>) -> Self {
        Self {
            writer: Mutex::new(writer),
            path: path.into(),
            failure_reported: AtomicBool::new(false),
        }
    }
}

impl<W: Write + Send> EventSink for FileSink<W> {
    fn write_line(&self, line: &str) {
        // One write call per line so concurrent appenders to the same file
        // cannot interleave inside a record.
        let mut record = String::with_capacity(line.len() + 1);
        record.push_str(line);
        record.push('\n');
        let result = self
            .writer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .write_all(record.as_bytes());

        if let Err(e) = result
            && !self.failure_reported.swap(true, Ordering::Relaxed)
        {
            warn!(
                "Failed to write JSONL output '{}': {}. Further write errors will be suppressed.",
                self.path, e
            );
        }
    }
}

/// A queued line writer for stdout. Producers enqueue without blocking and
/// a dedicated thread writes the queue out in batches; when the consumer
/// falls behind, lines are dropped and counted rather than stalling packet
/// processing. A write failure (a closed pipe, typically) is latched in
/// [`StdoutSink::output_failed`] so the run loop can shut down.
pub struct StdoutSink {
    tx: Sender<String>,
    pending: Mutex<Option<PendingWriter>>,
    writer_thread: Mutex<Option<JoinHandle<()>>>,
    stop: Arc<AtomicBool>,
    output_failed: Arc<AtomicBool>,
    dropped: AtomicU64,
    drop_warned: AtomicBool,
}

/// The receiving half and the output, held until [`EventSink::start`].
struct PendingWriter {
    rx: Receiver<String>,
    output: Box<dyn Write + Send>,
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutSink {
    pub fn new() -> Self {
        Self::with_output(Box::new(io::stdout()), MAX_EVENT_QUEUE)
    }

    fn with_output(output: Box<dyn Write + Send>, capacity: usize) -> Self {
        let (tx, rx) = channel::bounded(capacity);
        Self {
            tx,
            pending: Mutex::new(Some(PendingWriter { rx, output })),
            writer_thread: Mutex::new(None),
            stop: Arc::new(AtomicBool::new(false)),
            output_failed: Arc::new(AtomicBool::new(false)),
            dropped: AtomicU64::new(0),
            drop_warned: AtomicBool::new(false),
        }
    }

    /// Whether the writer thread gave up on the output after a write error.
    pub fn output_failed(&self) -> bool {
        self.output_failed.load(Ordering::Relaxed)
    }

    /// Lines dropped because the queue was full.
    pub fn dropped_lines(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl EventSink for StdoutSink {
    fn write_line(&self, line: &str) {
        match self.tx.try_send(line.to_owned()) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                if !self.drop_warned.swap(true, Ordering::Relaxed) {
                    warn!("Event output queue full; dropping events under load");
                }
            }
            // The writer thread has exited; its failure is already latched.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    fn start(&self) {
        let Some(PendingWriter { rx, output }) = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let stop = Arc::clone(&self.stop);
        let output_failed = Arc::clone(&self.output_failed);
        let handle = thread::Builder::new()
            .name("headless-events".to_string())
            .spawn(move || {
                if let Err(e) = run_writer(&rx, BufWriter::new(output), &stop) {
                    warn!("Event output failed: {e}. Stopping the event stream.");
                    output_failed.store(true, Ordering::Relaxed);
                }
            })
            .expect("Failed to spawn headless-events thread");
        *self
            .writer_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(handle);
    }

    fn shutdown(&self) -> Option<JoinHandle<()>> {
        self.stop.store(true, Ordering::Relaxed);
        let dropped = self.dropped_lines();
        if dropped > 0 {
            warn!("Event output dropped {dropped} events under backpressure");
        }
        self.writer_thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }
}

/// Write queued lines until the stop flag is set, then drain what is left.
/// Every batch ends with one flush so a consumer sees complete lines
/// promptly; the first error ends the stream.
fn run_writer<W: Write>(
    rx: &Receiver<String>,
    mut out: BufWriter<W>,
    stop: &AtomicBool,
) -> io::Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match rx.recv_timeout(WRITER_POLL_INTERVAL) {
            Ok(line) => {
                writeln!(out, "{line}")?;
                write_queued(rx, &mut out)?;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    write_queued(rx, &mut out)
}

fn write_queued<W: Write>(rx: &Receiver<String>, out: &mut BufWriter<W>) -> io::Result<()> {
    while let Ok(line) = rx.try_recv() {
        writeln!(out, "{line}")?;
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState};
    use serde_json::json;

    /// A writer whose contents the test can read back after the sink has
    /// taken ownership of it.
    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    #[test]
    fn file_sink_appends_one_line_per_record() {
        let buffer = SharedBuffer::default();
        let sink = FileSink::new(buffer.clone(), "events.jsonl");

        sink.write_line(r#"{"event":"new_connection"}"#);
        sink.write_line(r#"{"event":"connection_closed"}"#);

        assert_eq!(
            buffer.contents(),
            "{\"event\":\"new_connection\"}\n{\"event\":\"connection_closed\"}\n"
        );
    }

    #[test]
    fn stdout_sink_counts_drops_and_writes_what_it_kept() {
        let buffer = SharedBuffer::default();
        let sink = StdoutSink::with_output(Box::new(buffer.clone()), 2);

        sink.write_line("one");
        sink.write_line("two");
        sink.write_line("three");
        assert_eq!(sink.dropped_lines(), 1);

        sink.start();
        sink.shutdown().unwrap().join().unwrap();

        assert_eq!(buffer.contents(), "one\ntwo\n");
        assert!(!sink.output_failed());
    }

    #[test]
    fn stdout_sink_latches_a_broken_pipe() {
        let sink = StdoutSink::with_output(Box::new(BrokenPipe), 8);
        sink.start();
        sink.write_line("one");
        sink.shutdown().unwrap().join().unwrap();

        assert!(sink.output_failed());
    }

    #[test]
    fn stdout_sink_shutdown_without_start_has_no_thread() {
        let sink = StdoutSink::with_output(Box::new(BrokenPipe), 8);
        assert!(sink.shutdown().is_none());
    }

    fn udp_connection(remote: &str) -> Connection {
        Connection::new(
            Protocol::Udp,
            "10.0.0.2:40000".parse().unwrap(),
            remote.parse().unwrap(),
            ProtocolState::Udp,
        )
    }

    #[test]
    fn filtered_sink_drops_non_matching_connections_and_forwards_the_rest() {
        let buffer = SharedBuffer::default();
        let stdout = Arc::new(StdoutSink::with_output(Box::new(buffer.clone()), 8));
        let unfiltered: Arc<dyn EventSink> = Arc::new(FileSink::new(buffer.clone(), "log"));
        let filtered: Arc<dyn EventSink> = Arc::new(FilteredSink::new(
            ConnectionFilter::parse("dport:53"),
            stdout.clone(),
        ));
        let sinks = vec![filtered, unfiltered];

        let dns = udp_connection("10.0.0.1:53");
        let ntp = udp_connection("10.0.0.1:123");
        let mut built = 0;
        let mut emit = |conn: &Connection, port: u16| {
            write_connection_event(&sinks, conn, || {
                built += 1;
                json!({ "port": port })
            })
        };
        emit(&dns, 53);
        emit(&ntp, 123);
        assert_eq!(built, 2, "the unfiltered sink still wants every event");

        // The file sink is synchronous: both lines are already there. The
        // stdout sink only forwards the DNS line, after its thread drains.
        assert_eq!(buffer.contents(), "{\"port\":53}\n{\"port\":123}\n");
        stdout.start();
        stdout.shutdown().unwrap().join().unwrap();
        assert_eq!(
            buffer.contents(),
            "{\"port\":53}\n{\"port\":123}\n{\"port\":53}\n"
        );
    }

    #[test]
    fn event_is_not_built_when_no_sink_accepts_it() {
        let sinks: Vec<Arc<dyn EventSink>> = vec![Arc::new(FilteredSink::new(
            ConnectionFilter::parse("dport:53"),
            Arc::new(FileSink::new(SharedBuffer::default(), "log")),
        ))];
        let mut built = false;
        write_connection_event(&sinks, &udp_connection("10.0.0.1:123"), || {
            built = true;
            json!({})
        });
        assert!(!built);
    }
}
