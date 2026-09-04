//! Explicit live-capture checks for hosts with packet-capture permissions.

#![cfg(unix)]

use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustnet_capture::{CaptureConfig, PacketReader, setup_packet_capture};

#[test]
#[ignore = "requires packet-capture permissions on the loopback interface"]
fn idle_capture_returns_without_traffic_or_busy_spinning() {
    let interface = if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    };
    let (capture, _, _) = setup_packet_capture(CaptureConfig {
        interface: Some(interface.to_owned()),
        // Valid frames have a positive length, so unrelated host traffic cannot
        // make this test pass by waking a blocking capture read.
        filter: Some("less 0".to_owned()),
        ..CaptureConfig::default()
    })
    .unwrap();
    assert!(capture.is_nonblock());

    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut reader = PacketReader::new(capture);
        let started = Instant::now();
        for _ in 0..3 {
            assert!(reader.next_packet().unwrap().is_none());
        }
        finished_tx.send(started.elapsed()).unwrap();
    });

    let elapsed = finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("idle capture must return before the runtime shutdown deadline");
    assert!(
        elapsed >= Duration::from_millis(30),
        "idle polling must yield"
    );
    worker.join().unwrap();
}
