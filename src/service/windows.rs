//! Windows Service Control Manager adapter.

use super::{ServiceContext, ServiceLifecycle, ServiceStatus, StatusSink, run_managed};
use anyhow::{Context, Result, anyhow};
use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_PRESHUTDOWN, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_PRESHUTDOWN,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{PWSTR, w};

const SERVICE_NAME: &str = "Rustnet";

type ServiceRunner = Box<dyn FnOnce(ServiceContext) -> Result<()> + Send + 'static>;

#[derive(Default)]
struct DispatchSlot {
    runner: Option<ServiceRunner>,
    result_sender: Option<SyncSender<Result<()>>>,
}

static DISPATCH_SLOT: Mutex<DispatchSlot> = Mutex::new(DispatchSlot {
    runner: None,
    result_sender: None,
});

/// Connect the current process to the Windows Service Control Manager.
///
/// The runner must call [`ServiceContext::mark_running`] after privileged
/// setup and application worker startup complete. It should pass
/// [`ServiceContext::shutdown_requested`] to the headless run loop.
pub fn run_dispatcher<F>(runner: F) -> Result<()>
where
    F: FnOnce(ServiceContext) -> Result<()> + Send + 'static,
{
    let (result_sender, result_receiver) = sync_channel(1);
    {
        let mut slot = DISPATCH_SLOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.runner.is_some() || slot.result_sender.is_some() {
            return Err(anyhow!("Windows service dispatcher is already active"));
        }
        slot.runner = Some(Box::new(runner));
        slot.result_sender = Some(result_sender);
    }

    let mut service_name: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let dispatch_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(service_name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];

    // SAFETY: the table and its UTF-16 service name remain alive until the
    // dispatcher returns, and the second entry is the required null sentinel.
    if let Err(error) = unsafe { StartServiceCtrlDispatcherW(dispatch_table.as_ptr()) } {
        clear_dispatch_slot();
        return Err(anyhow!(error)).context("failed to connect to the Windows service dispatcher");
    }

    result_receiver
        .recv()
        .context("Windows service entry point exited without a result")?
}

fn clear_dispatch_slot() {
    let mut slot = DISPATCH_SLOT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    slot.runner = None;
    slot.result_sender = None;
}

unsafe extern "system" fn service_main(_argument_count: u32, _arguments: *mut PWSTR) {
    let (runner, result_sender) = {
        let mut slot = DISPATCH_SLOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (slot.runner.take(), slot.result_sender.take())
    };

    let Some(runner) = runner else {
        return;
    };
    let result = catch_unwind(AssertUnwindSafe(|| run_service(runner)))
        .unwrap_or_else(|_| Err(anyhow!("Windows service runner panicked")));
    if let Some(result_sender) = result_sender {
        let _ = result_sender.send(result);
    }
}

fn run_service(runner: ServiceRunner) -> Result<()> {
    let status_sink = Arc::new(WindowsStatusSink::default());
    let lifecycle = Arc::new(ServiceLifecycle::new(status_sink.clone()));
    // Keep one process-lifetime owner for the callback context. A control
    // handler may still be returning while the main service thread reports
    // STOPPED, so reclaiming this allocation here could race that callback.
    let lifecycle_context = Arc::into_raw(Arc::clone(&lifecycle));
    let context = lifecycle_context.cast::<c_void>();

    // SAFETY: the callback context has a process-lifetime Arc owner and the
    // service name is a statically allocated, null-terminated UTF-16 string.
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(w!("Rustnet"), Some(control_handler), Some(context))
    };
    let status_handle = match status_handle {
        Ok(handle) => handle,
        Err(error) => {
            // SAFETY: registration failed, so the SCM cannot retain or use the
            // callback context and this is still the sole raw Arc owner.
            drop(unsafe { Arc::from_raw(lifecycle_context) });
            return Err(anyhow!(error))
                .context("failed to register the Windows service control handler");
        }
    };
    status_sink.set_handle(status_handle);

    run_managed(lifecycle, runner)
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if context.is_null() {
        return ERROR_CALL_NOT_IMPLEMENTED.0;
    }
    // SAFETY: `context` points to the process-lifetime `ServiceLifecycle` Arc
    // owner created by `run_service`.
    let lifecycle = unsafe { &*context.cast::<ServiceLifecycle>() };

    let result = match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN | SERVICE_CONTROL_PRESHUTDOWN => {
            lifecycle.request_shutdown()
        }
        SERVICE_CONTROL_INTERROGATE => lifecycle.report_current(),
        _ => return ERROR_CALL_NOT_IMPLEMENTED.0,
    };
    if result.is_ok() {
        NO_ERROR.0
    } else {
        ERROR_SERVICE_SPECIFIC_ERROR.0
    }
}

#[derive(Default)]
struct WindowsStatusSink {
    handle: Mutex<Option<usize>>,
}

impl WindowsStatusSink {
    fn set_handle(&self, handle: SERVICE_STATUS_HANDLE) {
        *self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handle.0 as usize);
    }
}

impl StatusSink for WindowsStatusSink {
    fn report(&self, status: ServiceStatus) -> Result<()> {
        let handle_value = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ok_or_else(|| anyhow!("Windows service status handle is unavailable"))?;
        let handle = SERVICE_STATUS_HANDLE(handle_value as *mut c_void);
        let status = windows_status(status);
        // SAFETY: the status handle was returned by
        // RegisterServiceCtrlHandlerExW and the status value lives for the call.
        unsafe { SetServiceStatus(handle, &raw const status) }
            .context("failed to report Windows service status")
    }
}

fn windows_status(status: ServiceStatus) -> SERVICE_STATUS {
    let (current_state, controls_accepted, exit_code, service_exit_code, checkpoint, wait_hint) =
        match status {
            ServiceStatus::StartPending {
                checkpoint,
                wait_hint,
            } => (
                SERVICE_START_PENDING,
                0,
                NO_ERROR.0,
                0,
                checkpoint,
                wait_hint,
            ),
            ServiceStatus::Running => (
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN,
                NO_ERROR.0,
                0,
                0,
                std::time::Duration::ZERO,
            ),
            ServiceStatus::StopPending {
                checkpoint,
                wait_hint,
            } => (
                SERVICE_STOP_PENDING,
                0,
                NO_ERROR.0,
                0,
                checkpoint,
                wait_hint,
            ),
            ServiceStatus::Stopped { failed: false } => (
                SERVICE_STOPPED,
                0,
                NO_ERROR.0,
                0,
                0,
                std::time::Duration::ZERO,
            ),
            ServiceStatus::Stopped { failed: true } => (
                SERVICE_STOPPED,
                0,
                ERROR_SERVICE_SPECIFIC_ERROR.0,
                1,
                0,
                std::time::Duration::ZERO,
            ),
        };

    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: current_state,
        dwControlsAccepted: controls_accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: service_exit_code,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint.as_millis().try_into().unwrap_or(u32::MAX),
    }
}
