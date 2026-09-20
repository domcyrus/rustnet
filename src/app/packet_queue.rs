//! Bounded backpressure between capture and packet processing.

use crossbeam::channel::{SendTimeoutError, Sender, TrySendError};
use std::time::Duration;

/// Briefly let processors drain a full queue without extending its memory bound.
/// Capture checks shutdown again after this bounded wait. Sustained overload can
/// still exhaust the processing queue or the capture backend's buffer.
pub(super) const CAPTURE_QUEUE_WAIT: Duration = Duration::from_millis(5);

/// Avoid reading the clock or parking when capacity is immediately available.
/// A rejected item is returned intact so callers count its actual packet count.
pub(super) fn send_with_backpressure<T>(
    sender: &Sender<T>,
    item: T,
    timeout: Duration,
) -> Result<(), SendTimeoutError<T>> {
    match sender.try_send(item) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(item)) => sender.send_timeout(item, timeout),
        Err(TrySendError::Disconnected(item)) => Err(SendTimeoutError::Disconnected(item)),
    }
}

#[cfg(test)]
mod tests {
    use super::{CAPTURE_QUEUE_WAIT, send_with_backpressure};
    use crossbeam::channel::{self, SendTimeoutError};
    use std::time::{Duration, Instant};

    #[test]
    fn available_capacity_accepts_the_item_without_waiting() {
        let (sender, receiver) = channel::bounded(1);
        let item = vec![1, 2, 3];
        assert_eq!(
            send_with_backpressure(&sender, item.clone(), Duration::ZERO),
            Ok(())
        );
        assert_eq!(receiver.try_recv().unwrap(), item);
    }

    #[test]
    fn full_queue_with_zero_timeout_returns_the_original_item() {
        let (sender, receiver) = channel::bounded(1);
        sender.send(vec![1]).unwrap();
        let item = vec![2, 3, 4];
        let allocation = item.as_ptr();
        let SendTimeoutError::Timeout(rejected) =
            send_with_backpressure(&sender, item, Duration::ZERO).unwrap_err()
        else {
            panic!("a full connected queue must time out");
        };
        assert_eq!(rejected, vec![2, 3, 4]);
        assert_eq!(rejected.as_ptr(), allocation);
        assert_eq!(receiver.try_recv().unwrap(), vec![1]);
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn disconnected_queue_returns_the_original_item() {
        let (sender, receiver) = channel::bounded(1);
        drop(receiver);
        let item = vec![7, 8];
        let allocation = item.as_ptr();
        let SendTimeoutError::Disconnected(rejected) =
            send_with_backpressure(&sender, item, CAPTURE_QUEUE_WAIT).unwrap_err()
        else {
            panic!("a disconnected queue must not report a timeout");
        };
        assert_eq!(rejected, vec![7, 8]);
        assert_eq!(rejected.as_ptr(), allocation);
    }

    #[test]
    fn draining_a_full_queue_accepts_the_waiting_item_in_order() {
        let (sender, receiver) = channel::bounded(1);
        sender.send(vec![1]).unwrap();
        let consumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(receiver.recv().unwrap(), vec![1]);
            assert_eq!(receiver.recv().unwrap(), vec![2, 3]);
        });
        assert_eq!(
            send_with_backpressure(&sender, vec![2, 3], Duration::from_secs(2)),
            Ok(())
        );
        drop(sender);
        consumer.join().unwrap();
    }

    #[test]
    fn full_queue_wait_is_bounded_and_preserves_the_partial_batch() {
        let (sender, _receiver) = channel::bounded(1);
        sender.send(vec![0]).unwrap();
        let item = vec![1; 37];
        let allocation = item.as_ptr();
        let started = Instant::now();
        let SendTimeoutError::Timeout(rejected) =
            send_with_backpressure(&sender, item, CAPTURE_QUEUE_WAIT).unwrap_err()
        else {
            panic!("an undrained queue must time out");
        };
        // Allow scheduler jitter while detecting an accidentally unbounded wait.
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(rejected, vec![1; 37]);
        assert_eq!(rejected.as_ptr(), allocation);
        assert_eq!(sender.len(), 1);
    }

    #[test]
    fn disconnecting_while_full_returns_the_waiting_item() {
        let (sender, receiver) = channel::bounded(1);
        sender.send(vec![0]).unwrap();
        let consumer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            drop(receiver);
        });
        assert_eq!(
            send_with_backpressure(&sender, vec![9, 10], Duration::from_secs(2)),
            Err(SendTimeoutError::Disconnected(vec![9, 10]))
        );
        consumer.join().unwrap();
    }
}
