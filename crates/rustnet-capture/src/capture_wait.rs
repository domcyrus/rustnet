//! Bounded Linux capture readiness waits. The capture owns its descriptor;
//! this module only borrows its numeric identity while that capture is alive.

use pcap::{Active, Capture};
use std::io;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use super::IDLE_POLL_INTERVAL;

// The pcap crate already links libpcap, but its safe selectable wrapper
// consumes and closes the capture when a backend has no selectable fd. Query
// without transferring ownership so those backends can retain sleep polling.
unsafe extern "C" {
    fn pcap_get_selectable_fd(capture: *mut std::ffi::c_void) -> libc::c_int;
}

pub(super) struct CaptureWait {
    fd: Option<RawFd>,
    readiness_unconsumed: bool,
}

impl CaptureWait {
    pub(super) fn new(capture: &Capture<Active>) -> Self {
        // SAFETY: as_ptr refers to this live, activated libpcap capture. This
        // query does not retain the pointer or transfer/close its descriptor.
        let fd = unsafe { pcap_get_selectable_fd(capture.as_ptr().cast()) };
        Self {
            fd: (fd >= 0).then_some(fd),
            readiness_unconsumed: false,
        }
    }

    pub(super) fn packet_received(&mut self) {
        self.readiness_unconsumed = false;
    }

    pub(super) fn wait(&mut self) {
        self.wait_with_poll(IDLE_POLL_INTERVAL, poll_readable);
    }

    fn wait_with_poll(
        &mut self,
        interval: Duration,
        poll: impl FnOnce(RawFd, libc::c_int) -> io::Result<bool>,
    ) {
        // A readable descriptor can still yield no accepted packet, for
        // example after filtering. Do not repeatedly return immediately on
        // a persistent readiness indication that libpcap cannot consume.
        if self.readiness_unconsumed {
            self.readiness_unconsumed = false;
            std::thread::sleep(interval);
            return;
        }
        let Some(fd) = self.fd else {
            std::thread::sleep(interval);
            return;
        };
        let started = Instant::now();
        let timeout_ms = interval.as_millis().min(libc::c_int::MAX as u128) as libc::c_int;
        match poll(fd, timeout_ms) {
            Ok(readable) => self.readiness_unconsumed = readable,
            Err(_) => {
                // Invalid descriptors, hangups and EINTR must not spin. Do
                // not retry a full timeout after interruption; retain only
                // the remaining wait budget, then let the caller check stop.
                std::thread::sleep(interval.saturating_sub(started.elapsed()));
            }
        }
    }
}

fn poll_readable(fd: RawFd, timeout_ms: libc::c_int) -> io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor is one valid, writable pollfd. The cached fd remains
    // owned by PacketReader's capture throughout this non-owning poll call.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    fn waiter(fd: Option<RawFd>) -> CaptureWait {
        CaptureWait {
            fd,
            readiness_unconsumed: false,
        }
    }

    #[test]
    fn readiness_wakes_an_in_progress_wait() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut wait = waiter(Some(reader.as_raw_fd()));
            wait.wait_with_poll(Duration::from_secs(3), |fd, timeout| {
                started_tx.send(()).unwrap();
                poll_readable(fd, timeout)
            });
            done_tx.send(wait.readiness_unconsumed).unwrap();
            reader
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.write_all(&[1]).unwrap();
        let ready = done_rx.recv_timeout(Duration::from_secs(1));
        // Closing the peer also bounds cleanup if the assertion fails.
        drop(writer);
        worker.join().unwrap();
        assert!(ready.expect("readiness did not wake capture wait"));
    }

    #[test]
    fn idle_descriptor_has_a_bounded_nonspinning_wait() {
        let (reader, _writer) = UnixStream::pair().unwrap();
        let mut wait = waiter(Some(reader.as_raw_fd()));
        let started = Instant::now();
        wait.wait();
        assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!wait.readiness_unconsumed);
    }

    #[test]
    fn unsupported_invalid_and_hung_up_descriptors_fall_back_without_spinning() {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(writer);
        for fd in [None, Some(libc::c_int::MAX), Some(reader.as_raw_fd())] {
            let mut wait = waiter(fd);
            let started = Instant::now();
            wait.wait();
            assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(!wait.readiness_unconsumed);
        }
    }

    #[test]
    fn interruption_is_not_retried_or_allowed_to_spin() {
        let mut wait = waiter(Some(0));
        let started = Instant::now();
        wait.wait_with_poll(IDLE_POLL_INTERVAL, |_, _| {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        });
        assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!wait.readiness_unconsumed);
    }

    #[test]
    fn persistent_unconsumed_readiness_yields_before_polling_again() {
        let mut wait = waiter(Some(0));
        wait.wait_with_poll(IDLE_POLL_INTERVAL, |_, _| Ok(true));
        assert!(wait.readiness_unconsumed);
        let started = Instant::now();
        wait.wait_with_poll(IDLE_POLL_INTERVAL, |_, _| {
            panic!("unconsumed readiness must yield instead of polling")
        });
        assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
        assert!(!wait.readiness_unconsumed);
        wait.wait_with_poll(IDLE_POLL_INTERVAL, |_, _| Ok(true));
        assert!(wait.readiness_unconsumed);
        wait.packet_received();
        wait.wait_with_poll(IDLE_POLL_INTERVAL, |_, _| Ok(true));
        assert!(wait.readiness_unconsumed);
    }
}
