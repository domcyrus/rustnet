//! Bounded latest-value output and writer shutdown.

use std::io::{self, Write};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam::channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded};
use serde::Serialize;

use super::HeadlessExit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriterCompletion {
    Written,
    BrokenPipe,
}

#[derive(Debug, Clone)]
enum WriterStatus {
    Finished,
    BrokenPipe,
    Failed(String),
}

struct OutputRecord<T> {
    value: T,
    terminal: bool,
}

pub(super) struct AsyncOutput<T> {
    records_tx: Sender<OutputRecord<T>>,
    pending_rx: Receiver<OutputRecord<T>>,
    status_rx: Receiver<WriterStatus>,
    observed_status: Option<WriterStatus>,
    worker: Option<thread::JoinHandle<()>>,
}

impl<T: Serialize + Send + 'static> AsyncOutput<T> {
    pub(super) fn spawn<W: Write + Send + 'static>(mut writer: W) -> io::Result<Self> {
        let (records_tx, records_rx) = bounded::<OutputRecord<T>>(1);
        let pending_rx = records_rx.clone();
        let (status_tx, status_rx) = bounded(1);
        let worker = thread::Builder::new()
            .name("headless_output".to_string())
            .spawn(move || {
                let status = loop {
                    let OutputRecord { value, terminal } = match records_rx.recv() {
                        Ok(record) => record,
                        Err(_) => break WriterStatus::Finished,
                    };
                    let bytes = match serialize_record(&value) {
                        Ok(bytes) => bytes,
                        Err(error) => break WriterStatus::Failed(format!("{error:#}")),
                    };
                    // Release the projected value before a potentially blocked
                    // write, retaining only this record's serialized bytes.
                    drop(value);
                    if let Err(error) = writer.write_all(&bytes).and_then(|()| writer.flush()) {
                        break if error.kind() == io::ErrorKind::BrokenPipe {
                            WriterStatus::BrokenPipe
                        } else {
                            WriterStatus::Failed(error.to_string())
                        };
                    }
                    if terminal {
                        break WriterStatus::Finished;
                    }
                };
                drop(writer);
                let _ = status_tx.try_send(status);
            })?;

        Ok(Self {
            records_tx,
            pending_rx,
            status_rx,
            observed_status: None,
            worker: Some(worker),
        })
    }

    /// Replace the queued live value before serializing it. The worker handles
    /// one value at a time, with at most one pending value and the producer's
    /// current value. A blocked writer does not retain already replaced values.
    pub(super) fn offer_latest(&mut self, value: T) {
        self.replace_pending(OutputRecord {
            value,
            terminal: false,
        });
    }

    fn replace_pending(&mut self, mut record: OutputRecord<T>) {
        loop {
            match self.records_tx.try_send(record) {
                Ok(()) => return,
                Err(TrySendError::Full(returned)) => {
                    record = returned;
                    match self.pending_rx.try_recv() {
                        Ok(_) | Err(TryRecvError::Empty) => {}
                        Err(TryRecvError::Disconnected) => return,
                    }
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }

    pub(super) fn poll(&mut self) -> Result<Option<HeadlessExit>> {
        if self.observed_status.is_none() {
            match self.status_rx.try_recv() {
                Ok(status) => self.observed_status = Some(status),
                Err(TryRecvError::Empty) => return Ok(None),
                Err(TryRecvError::Disconnected) => {
                    self.join_finished_worker()?;
                    anyhow::bail!("headless output writer stopped unexpectedly")
                }
            }
        }
        match self.observed_status.as_ref().expect("status was populated") {
            WriterStatus::BrokenPipe => Ok(Some(HeadlessExit::BrokenPipe)),
            WriterStatus::Failed(error) => anyhow::bail!("headless output failed: {error}"),
            WriterStatus::Finished => {
                anyhow::bail!("headless output writer stopped before the terminal record")
            }
        }
    }

    /// Replace any pending live value with the terminal value and seal further
    /// offers. The deadline covers terminal serialization, writing, and flushing.
    pub(super) fn finish(mut self, terminal: T, deadline: Duration) -> Result<WriterCompletion> {
        self.replace_pending(OutputRecord {
            value: terminal,
            terminal: true,
        });
        let status = if let Some(status) = self.observed_status.take() {
            status
        } else {
            match self.status_rx.recv_timeout(deadline) {
                Ok(status) => status,
                Err(RecvTimeoutError::Timeout) => {
                    self.worker.take();
                    anyhow::bail!(
                        "headless output writer did not finish within {deadline:?}; detached blocked writer"
                    );
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.join_finished_worker()?;
                    anyhow::bail!("headless output writer stopped unexpectedly");
                }
            }
        };
        self.join_finished_worker()?;
        match status {
            WriterStatus::Finished => Ok(WriterCompletion::Written),
            WriterStatus::BrokenPipe => Ok(WriterCompletion::BrokenPipe),
            WriterStatus::Failed(error) => anyhow::bail!("headless output failed: {error}"),
        }
    }

    fn join_finished_worker(&mut self) -> Result<()> {
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
        {
            anyhow::bail!("headless output writer panicked");
        }
        Ok(())
    }
}

pub(super) fn serialize_record<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut record = serde_json::to_vec(value).context("failed to serialize headless output")?;
    record.push(b'\n');
    Ok(record)
}
