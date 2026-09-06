//! libpcap descriptor readiness shared by Linux, macOS, and BSD.

use pcap::{Active, Capture};
use std::io;
use std::os::fd::RawFd;
use std::time::Duration;

// The pcap crate already links libpcap, but its safe selectable wrapper
// consumes and closes captures without a selectable fd. Query without
// transferring ownership so those backends retain bounded sleep polling.
unsafe extern "C" {
    fn pcap_get_selectable_fd(capture: *mut std::ffi::c_void) -> libc::c_int;
}

pub(super) struct NativeWait {
    fd: Option<RawFd>,
}

impl NativeWait {
    pub(super) fn new(capture: &Capture<Active>) -> Self {
        // SAFETY: capture is live and activated. This query does not retain
        // its pointer or transfer/close its descriptor.
        let fd = unsafe { pcap_get_selectable_fd(capture.as_ptr().cast()) };
        Self {
            fd: (fd >= 0).then_some(fd),
        }
    }

    pub(super) fn wait(&self, _capture: &Capture<Active>, timeout: Duration) -> io::Result<bool> {
        self.wait_readable(timeout)
    }

    fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let fd = self.fd.ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "capture has no selectable fd")
        })?;
        let timeout_ms = timeout.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor is one valid, writable pollfd. The cached fd
        // remains owned by PacketReader's capture throughout this poll call.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result == 0 {
            return Ok(false);
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
            || descriptor.revents & libc::POLLIN == 0
        {
            return Err(io::Error::other("capture descriptor is not readable"));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IDLE_POLL_INTERVAL;
    use crate::capture_wait::WaitPolicy;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Instant;

    #[test]
    fn readiness_wakes_an_in_progress_wait() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let wait = NativeWait {
                fd: Some(reader.as_raw_fd()),
            };
            started_tx.send(()).unwrap();
            done_tx
                .send(wait.wait_readable(Duration::from_secs(3)))
                .unwrap();
            reader
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.write_all(&[1]).unwrap();
        let ready = done_rx.recv_timeout(Duration::from_secs(1));
        drop(writer);
        worker.join().unwrap();
        assert!(ready.expect("readiness did not wake capture wait").unwrap());
    }

    #[test]
    fn idle_descriptor_has_a_bounded_nonspinning_wait() {
        let (reader, _writer) = UnixStream::pair().unwrap();
        let wait = NativeWait {
            fd: Some(reader.as_raw_fd()),
        };
        let started = Instant::now();
        assert!(!wait.wait_readable(IDLE_POLL_INTERVAL).unwrap());
        assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn unsupported_invalid_and_hung_up_descriptors_use_shared_fallback() {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(writer);
        for fd in [None, Some(libc::c_int::MAX), Some(reader.as_raw_fd())] {
            let wait = NativeWait { fd };
            let mut policy = WaitPolicy::default();
            let started = Instant::now();
            policy.wait(IDLE_POLL_INTERVAL, || {
                wait.wait_readable(IDLE_POLL_INTERVAL)
            });
            assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(!policy.readiness_unconsumed);
        }
    }
}
