//! Worker lifecycle primitives shared by interactive and headless frontends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const DEFAULT_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);
const JOIN_POLL_INTERVAL: Duration = Duration::from_millis(2);

/// Result of one privileged startup phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitStatus {
    Ready,
    Failed(String),
}

/// Proof that [`App::apply_sandbox`] completed for this runtime.
///
/// The private field prevents callers from constructing a permit without
/// first applying the configured sandbox through the application lifecycle.
/// Worker startup consumes the permit so the ordering contract is explicit in
/// the API instead of depending only on call-site comments.
///
/// [`App::apply_sandbox`]: super::state::App::apply_sandbox
#[derive(Debug)]
#[must_use = "pass this permit to App::start_workers"]
pub struct WorkerStartupPermit {
    _private: (),
}

impl WorkerStartupPermit {
    pub(super) fn after_sandbox_result() -> Self {
        Self { _private: () }
    }
}

/// Cancellation signal that can also wake workers waiting for their next tick.
#[derive(Clone)]
pub(super) struct ShutdownSignal {
    requested: Arc<AtomicBool>,
    wake: Arc<(Mutex<()>, Condvar)>,
}

impl ShutdownSignal {
    fn new(requested: Arc<AtomicBool>) -> Self {
        Self {
            requested,
            wake: Arc::new((Mutex::new(()), Condvar::new())),
        }
    }

    pub(super) fn token(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.requested)
    }

    pub(super) fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    pub(super) fn requested_flag(&self) -> &AtomicBool {
        &self.requested
    }

    /// Wait for `timeout` or until shutdown is requested.
    ///
    /// Returns true when shutdown has been requested.
    pub(super) fn wait_timeout(&self, timeout: Duration) -> bool {
        if self.is_requested() {
            return true;
        }

        let (lock, wake) = &*self.wake;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = wake
            .wait_timeout_while(guard, timeout, |_| !self.is_requested())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.is_requested()
    }

    fn request(&self) -> bool {
        // Hold the same mutex used by `wait_timeout_while` while changing the
        // predicate. Otherwise shutdown can notify after a waiter checks the
        // atomic but just before it sleeps, losing the wakeup until timeout.
        let _guard = self
            .wake
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let already_requested = self.requested.swap(true, Ordering::AcqRel);
        self.wake.1.notify_all();
        !already_requested
    }
}

/// Result of joining the workers owned by a runtime.
#[must_use = "inspect shutdown failures before allowing the process to continue"]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopReport {
    pub joined_workers: usize,
    pub panicked_workers: usize,
    pub timed_out_workers: usize,
    pub output_errors: u64,
}

/// Owns cancellation state and every application worker thread.
pub(super) struct RuntimeSupervisor {
    shutdown: ShutdownSignal,
    workers: Mutex<Vec<JoinHandle<()>>>,
    unexpected_worker_exit: Arc<Mutex<Option<String>>>,
    shutdown_deadline: Duration,
    stop_state: Mutex<StopState>,
    stopped: Condvar,
}

struct MonitoredWorkerCompletion {
    shutdown: ShutdownSignal,
    unexpected_worker_exit: Arc<Mutex<Option<String>>>,
    worker_name: String,
}

impl Drop for MonitoredWorkerCompletion {
    fn drop(&mut self) {
        // Serialize completion with shutdown requests. If completion gets this
        // lock first, the worker exited before shutdown and must be latched.
        // If shutdown gets it first, this was an expected shutdown exit.
        let _shutdown_guard = self
            .shutdown
            .wake
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.shutdown.requested.load(Ordering::Acquire) {
            return;
        }

        let mut unexpected = self
            .unexpected_worker_exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        unexpected.get_or_insert_with(|| self.worker_name.clone());
    }
}

#[derive(Default)]
struct StopState {
    stopping: bool,
    report: Option<StopReport>,
    retryable_worker_timeout: bool,
    joined_workers: usize,
    panicked_workers: usize,
}

impl RuntimeSupervisor {
    pub(super) fn new() -> Self {
        Self::with_shutdown_deadline(DEFAULT_SHUTDOWN_DEADLINE)
    }

    pub(super) fn with_shutdown_deadline(shutdown_deadline: Duration) -> Self {
        Self {
            shutdown: ShutdownSignal::new(Arc::new(AtomicBool::new(false))),
            workers: Mutex::new(Vec::new()),
            unexpected_worker_exit: Arc::new(Mutex::new(None)),
            shutdown_deadline,
            stop_state: Mutex::new(StopState::default()),
            stopped: Condvar::new(),
        }
    }

    pub(super) fn shutdown_signal(&self) -> ShutdownSignal {
        self.shutdown.clone()
    }

    pub(super) fn stop_token(&self) -> Arc<AtomicBool> {
        self.shutdown.token()
    }

    pub(super) fn has_pending_workers(&self) -> bool {
        !self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    /// Spawn and register a critical worker during the exclusive application
    /// startup phase. Normal returns and panics are both latched when they
    /// happen before shutdown is requested.
    pub(super) fn spawn_monitored(
        &mut self,
        worker_name: impl Into<String>,
        worker: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<()> {
        let worker_name = worker_name.into();
        let shutdown = self.shutdown.clone();
        let unexpected_worker_exit = Arc::clone(&self.unexpected_worker_exit);
        let completion_name = worker_name.clone();
        let handle = thread::Builder::new().name(worker_name).spawn(move || {
            let _completion = MonitoredWorkerCompletion {
                shutdown,
                unexpected_worker_exit,
                worker_name: completion_name,
            };
            worker();
        })?;
        self.register_handle(handle);
        Ok(())
    }

    /// Register an auxiliary or intentionally finite worker that should still
    /// be owned and joined, but whose completion does not make the core
    /// monitoring runtime unhealthy.
    pub(super) fn register_unmonitored(&mut self, handle: JoinHandle<()>) {
        self.register_handle(handle);
    }

    fn register_handle(&mut self, handle: JoinHandle<()>) {
        let state = self
            .stop_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!state.stopping, "cannot register a worker after shutdown");
        drop(state);

        self.workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(handle);
    }

    /// Name of a monitored worker that exited before shutdown was requested.
    pub(super) fn unexpected_worker_exit(&self) -> Option<String> {
        self.unexpected_worker_exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn take_workers(&self) -> Vec<JoinHandle<()>> {
        let mut guard = self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *guard)
    }

    fn join_workers(&self, deadline: Instant) -> StopReport {
        let (report, remaining) = Self::join_until(self.take_workers(), deadline);
        *self
            .workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = remaining;
        report
    }

    fn join_until(
        mut workers: Vec<JoinHandle<()>>,
        deadline: Instant,
    ) -> (StopReport, Vec<JoinHandle<()>>) {
        let mut report = StopReport::default();

        while !workers.is_empty() {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    let worker = workers.swap_remove(index);
                    report.joined_workers += 1;
                    if worker.join().is_err() {
                        report.panicked_workers += 1;
                    }
                } else {
                    index += 1;
                }
            }

            if workers.is_empty() {
                break;
            }

            let now = Instant::now();
            if now >= deadline {
                report.timed_out_workers = workers.len();
                break;
            }

            thread::park_timeout(JOIN_POLL_INTERVAL.min(deadline.duration_since(now)));
        }

        (report, workers)
    }

    /// Request shutdown, join all registered workers, then run cleanup and
    /// quiescence-dependent finalization.
    ///
    /// Cleanup always runs, including after a worker timeout. Finalization is
    /// skipped when an owned worker times out. Cleanup may add timeouts for
    /// independent helpers, but those do not invalidate the quiescence of the
    /// workers that access shared output and tracking state.
    ///
    /// Concurrent callers serialize behind the active attempt. Clean reports
    /// are cached. A timed-out report retains its unfinished handles, so a
    /// later call can retry the bounded join and finalize once they exit.
    pub(super) fn stop_and_join(
        &self,
        cleanup: impl FnOnce(&mut StopReport),
        finalize: impl FnOnce(&mut StopReport),
    ) -> StopReport {
        let mut state = self
            .stop_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        loop {
            if let Some(report) = state.report {
                if !state.retryable_worker_timeout {
                    return report;
                }
                // A bounded attempt kept the unfinished handles. A later stop
                // call gets another bounded opportunity to join them and run
                // finalization once they have quiesced.
                state.report = None;
            }
            if !state.stopping {
                state.stopping = true;
                break;
            }
            state = self
                .stopped
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(state);

        self.shutdown.request();
        let deadline = Instant::now() + self.shutdown_deadline;
        let worker_report = self.join_workers(deadline);
        let workers_quiesced = worker_report.timed_out_workers == 0;
        let (joined_workers, panicked_workers) = {
            let state = self
                .stop_state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                state
                    .joined_workers
                    .saturating_add(worker_report.joined_workers),
                state
                    .panicked_workers
                    .saturating_add(worker_report.panicked_workers),
            )
        };
        let mut report = StopReport {
            joined_workers,
            panicked_workers,
            timed_out_workers: worker_report.timed_out_workers,
            output_errors: 0,
        };
        cleanup(&mut report);
        if workers_quiesced {
            finalize(&mut report);
        }

        let mut state = self
            .stop_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.joined_workers = joined_workers;
        state.panicked_workers = panicked_workers;
        state.report = Some(report);
        state.retryable_worker_timeout = !workers_quiesced;
        state.stopping = false;
        self.stopped.notify_all();
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn shutdown_wakes_waiting_workers_and_join_is_idempotent() {
        let mut runtime = RuntimeSupervisor::new();
        let shutdown = runtime.shutdown_signal();
        let (waiting_tx, waiting_rx) = mpsc::sync_channel(1);

        runtime
            .spawn_monitored("waiting-worker", move || {
                waiting_tx.send(()).unwrap();
                assert!(shutdown.wait_timeout(Duration::from_secs(30)));
            })
            .unwrap();

        waiting_rx.recv().unwrap();
        let started = Instant::now();
        let report = runtime.stop_and_join(|_| {}, |_| {});

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(report.joined_workers, 1);
        assert_eq!(report.panicked_workers, 0);
        assert_eq!(
            runtime.stop_and_join(
                |_| panic!("must not clean up twice"),
                |_| panic!("must not finalize twice"),
            ),
            report
        );
    }

    #[test]
    fn join_report_counts_worker_panics() {
        let mut runtime = RuntimeSupervisor::new();
        runtime
            .spawn_monitored("panicking-worker", || panic!("worker failed"))
            .unwrap();

        let report = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(report.joined_workers, 1);
        assert_eq!(report.panicked_workers, 1);
    }

    #[test]
    fn one_deadline_bounds_all_workers_and_skips_finalization() {
        let mut runtime = RuntimeSupervisor::with_shutdown_deadline(Duration::from_millis(40));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::sync_channel(3);
        let (exited_tx, exited_rx) = mpsc::sync_channel(3);

        for i in 0..3 {
            let release = Arc::clone(&release);
            let started_tx = started_tx.clone();
            let exited_tx = exited_tx.clone();
            runtime
                .spawn_monitored(format!("blocked-worker-{i}"), move || {
                    started_tx.send(()).unwrap();
                    let (lock, wake) = &*release;
                    let mut released = lock
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    while !*released {
                        released = wake
                            .wait(released)
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                    exited_tx.send(()).unwrap();
                })
                .unwrap();
        }
        drop(started_tx);
        drop(exited_tx);
        for _ in 0..3 {
            started_rx.recv().unwrap();
        }

        let cleanup_ran = Arc::new(AtomicBool::new(false));
        let finalize_ran = Arc::new(AtomicBool::new(false));
        let cleanup_flag = Arc::clone(&cleanup_ran);
        let finalize_flag = Arc::clone(&finalize_ran);
        let started = Instant::now();
        let report = runtime.stop_and_join(
            move |_| cleanup_flag.store(true, Ordering::Release),
            move |_| finalize_flag.store(true, Ordering::Release),
        );

        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(report.joined_workers, 0);
        assert_eq!(report.panicked_workers, 0);
        assert_eq!(report.timed_out_workers, 3);
        assert!(cleanup_ran.load(Ordering::Acquire));
        assert!(!finalize_ran.load(Ordering::Acquire));
        assert_eq!(runtime.stop_and_join(|_| {}, |_| {}), report);

        let (lock, wake) = &*release;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();
        for _ in 0..3 {
            exited_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }

        let retry_finalized = Arc::new(AtomicBool::new(false));
        let retry_flag = Arc::clone(&retry_finalized);
        let retry_report =
            runtime.stop_and_join(|_| {}, move |_| retry_flag.store(true, Ordering::Release));
        assert_eq!(retry_report.joined_workers, 3);
        assert_eq!(retry_report.timed_out_workers, 0);
        assert!(retry_finalized.load(Ordering::Acquire));
    }

    #[test]
    fn independent_cleanup_timeout_does_not_skip_quiescent_finalization() {
        let runtime = RuntimeSupervisor::new();
        let finalize_ran = Arc::new(AtomicBool::new(false));
        let finalize_flag = Arc::clone(&finalize_ran);

        let report = runtime.stop_and_join(
            |report| report.timed_out_workers += 1,
            move |_| finalize_flag.store(true, Ordering::Release),
        );

        assert_eq!(report.timed_out_workers, 1);
        assert!(finalize_ran.load(Ordering::Acquire));
    }

    #[test]
    fn retry_preserves_workers_joined_and_panicked_by_an_earlier_attempt() {
        let mut runtime = RuntimeSupervisor::with_shutdown_deadline(Duration::from_millis(40));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let worker_release = Arc::clone(&release);

        runtime
            .spawn_monitored("panicking-worker", || panic!("worker failed"))
            .unwrap();
        assert_eq!(
            wait_for_unexpected_exit(&runtime).as_deref(),
            Some("panicking-worker")
        );
        runtime
            .spawn_monitored("blocked-worker", move || {
                started_tx.send(()).unwrap();
                let (lock, wake) = &*worker_release;
                let mut released = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while !*released {
                    released = wake
                        .wait(released)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
            })
            .unwrap();
        started_rx.recv().unwrap();

        let first = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(first.joined_workers, 1);
        assert_eq!(first.panicked_workers, 1);
        assert_eq!(first.timed_out_workers, 1);

        let (lock, wake) = &*release;
        *lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        wake.notify_all();

        let retry = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(retry.joined_workers, 2);
        assert_eq!(retry.panicked_workers, 1);
        assert_eq!(retry.timed_out_workers, 0);
    }

    #[test]
    fn finalization_starts_only_after_every_registered_worker_exits() {
        let mut runtime = RuntimeSupervisor::new();
        let exited = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for i in 0..3 {
            let shutdown = runtime.shutdown_signal();
            let exited = Arc::clone(&exited);
            runtime
                .spawn_monitored(format!("finalization-worker-{i}"), move || {
                    shutdown.wait_timeout(Duration::from_secs(30));
                    exited.fetch_add(1, Ordering::Release);
                })
                .unwrap();
        }

        let report = runtime.stop_and_join(
            |_| {
                assert_eq!(exited.load(Ordering::Acquire), 3);
            },
            |_| {
                assert_eq!(exited.load(Ordering::Acquire), 3);
            },
        );
        assert_eq!(report.joined_workers, 3);
    }

    fn wait_for_unexpected_exit(runtime: &RuntimeSupervisor) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if let Some(worker) = runtime.unexpected_worker_exit() {
                return Some(worker);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::yield_now();
        }
    }

    #[test]
    fn normal_early_exit_is_latched() {
        let mut runtime = RuntimeSupervisor::new();
        runtime.spawn_monitored("early-worker", || {}).unwrap();

        assert_eq!(
            wait_for_unexpected_exit(&runtime).as_deref(),
            Some("early-worker")
        );
        let report = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(report.joined_workers, 1);
        assert_eq!(report.panicked_workers, 0);
        assert_eq!(
            runtime.unexpected_worker_exit().as_deref(),
            Some("early-worker")
        );
    }

    #[test]
    fn panic_before_shutdown_is_latched() {
        let mut runtime = RuntimeSupervisor::new();
        runtime
            .spawn_monitored("panic-worker", || panic!("worker failed"))
            .unwrap();

        assert_eq!(
            wait_for_unexpected_exit(&runtime).as_deref(),
            Some("panic-worker")
        );
        let report = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(report.joined_workers, 1);
        assert_eq!(report.panicked_workers, 1);
        assert_eq!(
            runtime.unexpected_worker_exit().as_deref(),
            Some("panic-worker")
        );
    }

    #[test]
    fn shutdown_caused_exit_is_not_latched() {
        let mut runtime = RuntimeSupervisor::new();
        let shutdown = runtime.shutdown_signal();
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        runtime
            .spawn_monitored("cooperative-worker", move || {
                started_tx.send(()).unwrap();
                assert!(shutdown.wait_timeout(Duration::from_secs(30)));
            })
            .unwrap();
        started_rx.recv().unwrap();

        let report = runtime.stop_and_join(|_| {}, |_| {});
        assert_eq!(report.joined_workers, 1);
        assert_eq!(report.panicked_workers, 0);
        assert_eq!(runtime.unexpected_worker_exit(), None);
    }

    #[test]
    fn concurrent_stop_waits_for_finalization() {
        let runtime = Arc::new(RuntimeSupervisor::new());
        let (finalize_started_tx, finalize_started_rx) = mpsc::sync_channel(1);
        let (finalize_release_tx, finalize_release_rx) = mpsc::sync_channel(1);
        let leader = Arc::clone(&runtime);
        let leader = thread::spawn(move || {
            leader.stop_and_join(
                |_| {},
                |_| {
                    finalize_started_tx.send(()).unwrap();
                    finalize_release_rx.recv().unwrap();
                },
            )
        });

        finalize_started_rx.recv().unwrap();
        let follower = Arc::clone(&runtime);
        let (follower_done_tx, follower_done_rx) = mpsc::sync_channel(1);
        let follower = thread::spawn(move || {
            let report = follower.stop_and_join(
                |_| panic!("must not clean up twice"),
                |_| panic!("must not finalize twice"),
            );
            follower_done_tx.send(report).unwrap();
        });

        assert!(follower_done_rx.try_recv().is_err());
        finalize_release_tx.send(()).unwrap();

        let leader_report = leader.join().unwrap();
        assert_eq!(follower_done_rx.recv().unwrap(), leader_report);
        follower.join().unwrap();
    }
}
