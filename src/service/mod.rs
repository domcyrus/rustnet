//! Service-host lifecycle support.
//!
//! The Windows backend connects this state machine to the Service Control
//! Manager. Keeping the transitions here makes readiness and shutdown behavior
//! testable on every development platform.

use anyhow::{Result, anyhow};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::run_dispatcher;

const START_WAIT_HINT: Duration = Duration::from_secs(30);
const STOP_WAIT_HINT: Duration = Duration::from_secs(10);

/// Handle passed to the application while it runs under a service manager.
#[derive(Clone)]
pub struct ServiceContext {
    lifecycle: Arc<ServiceLifecycle>,
}

impl ServiceContext {
    /// Report that privileged setup and worker startup completed successfully.
    pub fn mark_running(&self) -> Result<()> {
        self.lifecycle.mark_running()
    }

    /// Shared stop condition set by Windows service control requests.
    pub fn shutdown_requested(&self) -> &AtomicBool {
        &self.lifecycle.shutdown_requested
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceStatus {
    StartPending {
        checkpoint: u32,
        wait_hint: Duration,
    },
    Running,
    StopPending {
        checkpoint: u32,
        wait_hint: Duration,
    },
    Stopped {
        failed: bool,
    },
}

pub(crate) trait StatusSink: Send + Sync {
    fn report(&self, status: ServiceStatus) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServicePhase {
    Created,
    StartPending,
    Running,
    StopPending,
    Stopped,
}

pub(crate) struct ServiceLifecycle {
    shutdown_requested: AtomicBool,
    phase: Mutex<ServicePhase>,
    sink: Arc<dyn StatusSink>,
}

impl ServiceLifecycle {
    pub(crate) fn new(sink: Arc<dyn StatusSink>) -> Self {
        Self {
            shutdown_requested: AtomicBool::new(false),
            phase: Mutex::new(ServicePhase::Created),
            sink,
        }
    }

    fn begin(&self) -> Result<()> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *phase != ServicePhase::Created {
            return Err(anyhow!("service lifecycle has already started"));
        }
        self.sink.report(ServiceStatus::StartPending {
            checkpoint: 1,
            wait_hint: START_WAIT_HINT,
        })?;
        *phase = ServicePhase::StartPending;
        Ok(())
    }

    fn mark_running(&self) -> Result<()> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            ServicePhase::StartPending if !self.shutdown_requested.load(Ordering::Acquire) => {
                self.sink.report(ServiceStatus::Running)?;
                *phase = ServicePhase::Running;
                Ok(())
            }
            ServicePhase::StopPending => Ok(()),
            ServicePhase::StartPending => self.report_stop_pending_locked(&mut phase),
            ServicePhase::Running => Ok(()),
            ServicePhase::Created => Err(anyhow!("service lifecycle has not started")),
            ServicePhase::Stopped => Err(anyhow!("service lifecycle has already stopped")),
        }
    }

    pub(crate) fn request_shutdown(&self) -> Result<()> {
        self.shutdown_requested.store(true, Ordering::Release);
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match *phase {
            ServicePhase::StartPending | ServicePhase::Running => {
                self.report_stop_pending_locked(&mut phase)
            }
            ServicePhase::Created | ServicePhase::StopPending | ServicePhase::Stopped => Ok(()),
        }
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn report_current(&self) -> Result<()> {
        let phase = *self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = match phase {
            ServicePhase::Created => return Ok(()),
            ServicePhase::StartPending => ServiceStatus::StartPending {
                checkpoint: 1,
                wait_hint: START_WAIT_HINT,
            },
            ServicePhase::Running => ServiceStatus::Running,
            ServicePhase::StopPending => ServiceStatus::StopPending {
                checkpoint: 1,
                wait_hint: STOP_WAIT_HINT,
            },
            ServicePhase::Stopped => ServiceStatus::Stopped { failed: false },
        };
        self.sink.report(status)
    }

    fn finish(&self, failed: bool) -> Result<()> {
        let mut phase = self
            .phase
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !matches!(*phase, ServicePhase::StopPending | ServicePhase::Stopped) {
            self.report_stop_pending_locked(&mut phase)?;
        }
        if *phase != ServicePhase::Stopped {
            self.sink.report(ServiceStatus::Stopped { failed })?;
            *phase = ServicePhase::Stopped;
        }
        Ok(())
    }

    fn report_stop_pending_locked(&self, phase: &mut ServicePhase) -> Result<()> {
        self.sink.report(ServiceStatus::StopPending {
            checkpoint: 1,
            wait_hint: STOP_WAIT_HINT,
        })?;
        *phase = ServicePhase::StopPending;
        Ok(())
    }
}

pub(crate) fn run_managed<F>(lifecycle: Arc<ServiceLifecycle>, runner: F) -> Result<()>
where
    F: FnOnce(ServiceContext) -> Result<()>,
{
    lifecycle.begin()?;
    let run_result = catch_unwind(AssertUnwindSafe(|| {
        runner(ServiceContext {
            lifecycle: Arc::clone(&lifecycle),
        })
    }))
    .unwrap_or_else(|_| Err(anyhow!("service runner panicked")));
    let finish_result = lifecycle.finish(run_result.is_err());

    match (run_result, finish_result) {
        (Err(run_error), Err(status_error)) => Err(anyhow!(
            "{run_error}; failed to report final service status: {status_error}"
        )),
        (Err(run_error), Ok(())) => Err(run_error),
        (Ok(()), Err(status_error)) => Err(status_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[derive(Default)]
    struct RecordingSink {
        statuses: Mutex<Vec<ServiceStatus>>,
    }

    impl RecordingSink {
        fn statuses(&self) -> Vec<ServiceStatus> {
            self.statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl StatusSink for RecordingSink {
        fn report(&self, status: ServiceStatus) -> Result<()> {
            self.statuses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(status);
            Ok(())
        }
    }

    #[test]
    fn successful_run_reports_full_lifecycle() {
        let sink = Arc::new(RecordingSink::default());
        let lifecycle = Arc::new(ServiceLifecycle::new(sink.clone()));

        run_managed(lifecycle, |context| context.mark_running()).unwrap();

        assert_eq!(
            sink.statuses(),
            vec![
                ServiceStatus::StartPending {
                    checkpoint: 1,
                    wait_hint: START_WAIT_HINT,
                },
                ServiceStatus::Running,
                ServiceStatus::StopPending {
                    checkpoint: 1,
                    wait_hint: STOP_WAIT_HINT,
                },
                ServiceStatus::Stopped { failed: false },
            ]
        );
    }

    #[test]
    fn stop_during_startup_skips_running_state() {
        let sink = Arc::new(RecordingSink::default());
        let lifecycle = Arc::new(ServiceLifecycle::new(sink.clone()));

        run_managed(lifecycle, |context| {
            context.lifecycle.request_shutdown()?;
            context.mark_running()?;
            assert!(context.shutdown_requested().load(Ordering::Acquire));
            Ok(())
        })
        .unwrap();

        assert_eq!(
            sink.statuses(),
            vec![
                ServiceStatus::StartPending {
                    checkpoint: 1,
                    wait_hint: START_WAIT_HINT,
                },
                ServiceStatus::StopPending {
                    checkpoint: 1,
                    wait_hint: STOP_WAIT_HINT,
                },
                ServiceStatus::Stopped { failed: false },
            ]
        );
    }

    #[test]
    fn runner_failure_is_reflected_in_stopped_status() {
        let sink = Arc::new(RecordingSink::default());
        let lifecycle = Arc::new(ServiceLifecycle::new(sink.clone()));

        let error = run_managed(lifecycle, |context| {
            context.mark_running()?;
            Err(anyhow!("capture failed"))
        })
        .unwrap_err();

        assert!(error.to_string().contains("capture failed"));
        assert_eq!(
            sink.statuses(),
            vec![
                ServiceStatus::StartPending {
                    checkpoint: 1,
                    wait_hint: START_WAIT_HINT,
                },
                ServiceStatus::Running,
                ServiceStatus::StopPending {
                    checkpoint: 1,
                    wait_hint: STOP_WAIT_HINT,
                },
                ServiceStatus::Stopped { failed: true },
            ]
        );
    }

    #[test]
    fn runner_panic_is_reflected_in_stopped_status() {
        let sink = Arc::new(RecordingSink::default());
        let lifecycle = Arc::new(ServiceLifecycle::new(sink.clone()));

        let error = run_managed(lifecycle, |context| {
            context.mark_running()?;
            panic!("boom")
        })
        .unwrap_err();

        assert!(error.to_string().contains("service runner panicked"));
        assert_eq!(
            sink.statuses(),
            vec![
                ServiceStatus::StartPending {
                    checkpoint: 1,
                    wait_hint: START_WAIT_HINT,
                },
                ServiceStatus::Running,
                ServiceStatus::StopPending {
                    checkpoint: 1,
                    wait_hint: STOP_WAIT_HINT,
                },
                ServiceStatus::Stopped { failed: true },
            ]
        );
    }

    #[test]
    fn duplicate_stop_requests_are_idempotent() {
        let sink = Arc::new(RecordingSink::default());
        let lifecycle = Arc::new(ServiceLifecycle::new(sink.clone()));

        run_managed(lifecycle, |context| {
            context.mark_running()?;
            context.lifecycle.request_shutdown()?;
            context.lifecycle.request_shutdown()
        })
        .unwrap();

        assert_eq!(
            sink.statuses()
                .iter()
                .filter(|status| matches!(status, ServiceStatus::StopPending { .. }))
                .count(),
            1
        );
    }
}
