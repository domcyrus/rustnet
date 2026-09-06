//! Borrow Npcap's capture event for bounded waits without taking ownership.

use ::windows::Win32::Foundation::{HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use ::windows::Win32::System::Threading::WaitForSingleObject;
use pcap::{Active, Capture};
use std::io;
use std::time::Duration;

pub(super) struct NativeWait;

impl NativeWait {
    pub(super) fn new(_capture: &Capture<Active>) -> Self {
        Self
    }

    pub(super) fn wait(&self, capture: &Capture<Active>, timeout: Duration) -> io::Result<bool> {
        // SAFETY: capture remains borrowed throughout the wait and owns the
        // returned event. No handle is retained, reset, closed, or transferred.
        let event = unsafe { capture.get_event() };
        // pcap uses windows-sys 0.36's integer HANDLE representation; windows
        // uses a pointer. Preserve the native handle bits without ownership.
        let event = HANDLE(event as *mut std::ffi::c_void);
        // SAFETY: the same capture borrow keeps this event alive until return.
        unsafe { wait_for_event(event, timeout) }
    }
}

fn timeout_millis(timeout: Duration) -> u32 {
    // Round sub-millisecond waits up rather than repeatedly polling. Reserve
    // INFINITE (u32::MAX) so even an excessive caller timeout remains finite.
    timeout
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u128::from(u32::MAX - 1)) as u32
}

/// The caller must keep a valid event alive throughout this wait. Null and
/// INVALID_HANDLE_VALUE are accepted only to report unavailable backend events.
unsafe fn wait_for_event(event: HANDLE, timeout: Duration) -> io::Result<bool> {
    if event.is_invalid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Capture backend did not provide a valid readiness event",
        ));
    }
    // SAFETY: the caller retains the live event for this bounded wait. Waiting
    // does not transfer ownership; Npcap remains responsible for its event.
    let result = unsafe { WaitForSingleObject(event, timeout_millis(timeout)) };
    match result {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        other => Err(io::Error::other(format!(
            "Unexpected capture event wait status: {}",
            other.0
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{timeout_millis, wait_for_event};
    use ::windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use ::windows::Win32::System::Threading::{CreateEventW, SetEvent};
    use ::windows::core::PCWSTR;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn event(initially_ready: bool) -> OwnedHandle {
        // SAFETY: null security/name pointers request an unnamed event with
        // default security. The returned handle belongs exclusively to this test.
        let event = unsafe { CreateEventW(None, true, initially_ready, PCWSTR::null()) }
            .expect("create test readiness event");
        // SAFETY: CreateEventW returned a fresh valid handle. OwnedHandle is
        // its sole owner and closes only this test-created event on drop.
        unsafe { OwnedHandle::from_raw_handle(event.0) }
    }

    fn wait(event: &OwnedHandle, timeout: Duration) -> io::Result<bool> {
        // SAFETY: borrowing OwnedHandle keeps this test event alive for the wait.
        unsafe { wait_for_event(HANDLE(event.as_raw_handle()), timeout) }
    }

    #[test]
    fn ready_event_returns_without_resetting_or_closing_it() {
        let ready = event(true);
        assert!(wait(&ready, Duration::ZERO).unwrap());
        // A manual-reset event remains ready, proving the helper did not reset
        // it or take ownership of the handle during the first wait.
        assert!(wait(&ready, Duration::ZERO).unwrap());
    }

    #[test]
    fn idle_event_times_out_and_remains_usable() {
        let idle = event(false);
        let started = Instant::now();
        assert!(!wait(&idle, Duration::from_millis(100)).unwrap());
        // Leave room for the Windows timer tick while still detecting a
        // mistaken zero-timeout poll that would busy-spin on idle capture.
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert!(started.elapsed() < Duration::from_secs(2));
        // SAFETY: this test owns idle and retains it throughout SetEvent.
        unsafe { SetEvent(HANDLE(idle.as_raw_handle())) }.unwrap();
        assert!(wait(&idle, Duration::ZERO).unwrap());
    }

    #[test]
    fn new_readiness_wakes_a_waiting_thread() {
        let ready = Arc::new(event(false));
        let signal = Arc::clone(&ready);
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            // SAFETY: signal retains the test-owned event through this call.
            unsafe { SetEvent(HANDLE(signal.as_raw_handle())) }.unwrap();
        });
        assert!(wait(&ready, Duration::from_secs(2)).unwrap());
        worker.join().unwrap();
    }

    #[test]
    fn unavailable_handles_report_an_error_without_waiting() {
        for invalid in [HANDLE::default(), INVALID_HANDLE_VALUE] {
            // SAFETY: the helper explicitly accepts these invalid sentinels
            // and rejects them before making any Windows wait call.
            let error = unsafe { wait_for_event(invalid, Duration::from_secs(2)) }.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn timeout_conversion_never_selects_infinite_wait() {
        assert_eq!(timeout_millis(Duration::ZERO), 0);
        assert_eq!(timeout_millis(Duration::from_nanos(1)), 1);
        assert_eq!(timeout_millis(Duration::from_millis(10)), 10);
        assert_eq!(timeout_millis(Duration::MAX), u32::MAX - 1);
    }
}
