//! Shared bounded-wait policy, with native readiness isolated in two adapters.
//!
//! Adapters only report readiness, timeout, or an error. This module owns the
//! idle budget and guards against unsupported backends and spurious readiness.
//! No adapter consumes packets or owns the capture's descriptor/event.

use pcap::{Active, Capture};
use std::io;
use std::time::{Duration, Instant};

use super::IDLE_POLL_INTERVAL;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::NativeWait;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::NativeWait;

pub(super) struct CaptureWait {
    native: NativeWait,
    policy: WaitPolicy,
}

impl CaptureWait {
    pub(super) fn new(capture: &Capture<Active>) -> Self {
        Self {
            native: NativeWait::new(capture),
            policy: WaitPolicy::default(),
        }
    }

    pub(super) fn packet_received(&mut self) {
        self.policy.packet_received();
    }

    pub(super) fn wait(&mut self, capture: &Capture<Active>) {
        self.policy.wait(IDLE_POLL_INTERVAL, || {
            self.native.wait(capture, IDLE_POLL_INTERVAL)
        });
    }
}

#[derive(Default)]
struct WaitPolicy {
    readiness_unconsumed: bool,
}

impl WaitPolicy {
    fn packet_received(&mut self) {
        self.readiness_unconsumed = false;
    }

    fn wait(&mut self, interval: Duration, wait: impl FnOnce() -> io::Result<bool>) {
        // Readiness can still yield no accepted packet, for example after
        // filtering. Yield if libpcap could not consume the last notification.
        if self.readiness_unconsumed {
            self.readiness_unconsumed = false;
            std::thread::sleep(interval);
            return;
        }
        let started = Instant::now();
        match wait() {
            Ok(readable) => self.readiness_unconsumed = readable,
            Err(_) => {
                // Unsupported backends, invalid handles and interruptions must
                // not spin or restart a full timeout. Sleep only the remainder
                // of this budget, then let the capture loop check shutdown.
                std::thread::sleep(interval.saturating_sub(started.elapsed()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_reader_remains_send() {
        fn assert_send<T: Send>() {}
        assert_send::<crate::PacketReader>();
    }

    #[test]
    fn errors_fall_back_without_retrying_or_spinning() {
        for kind in [io::ErrorKind::Interrupted, io::ErrorKind::Unsupported] {
            let mut policy = WaitPolicy::default();
            let started = Instant::now();
            policy.wait(IDLE_POLL_INTERVAL, || Err(io::Error::from(kind)));
            assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert!(!policy.readiness_unconsumed);
        }
    }

    #[test]
    fn timeout_does_not_trigger_the_spurious_readiness_guard() {
        let mut policy = WaitPolicy::default();
        policy.wait(IDLE_POLL_INTERVAL, || Ok(false));
        policy.wait(IDLE_POLL_INTERVAL, || Ok(true));
        assert!(policy.readiness_unconsumed);
    }

    #[test]
    fn persistent_unconsumed_readiness_yields_before_waiting_again() {
        let mut policy = WaitPolicy::default();
        policy.wait(IDLE_POLL_INTERVAL, || Ok(true));
        assert!(policy.readiness_unconsumed);
        let started = Instant::now();
        policy.wait(IDLE_POLL_INTERVAL, || {
            panic!("unconsumed readiness must yield instead of waiting")
        });
        assert!(started.elapsed() >= IDLE_POLL_INTERVAL);
        assert!(!policy.readiness_unconsumed);
        policy.wait(IDLE_POLL_INTERVAL, || Ok(true));
        assert!(policy.readiness_unconsumed);
        policy.packet_received();
        policy.wait(IDLE_POLL_INTERVAL, || Ok(true));
        assert!(policy.readiness_unconsumed);
    }
}
