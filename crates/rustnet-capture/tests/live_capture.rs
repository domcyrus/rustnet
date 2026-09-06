//! Explicit live-capture checks for hosts with packet-capture permissions.

#![cfg(unix)]

use std::net::UdpSocket;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rustnet_capture::{CaptureConfig, PacketReader, setup_packet_capture};

fn loopback_interface() -> &'static str {
    if cfg!(target_os = "linux") {
        "lo"
    } else {
        "lo0"
    }
}

#[test]
#[ignore = "requires packet-capture permissions on the loopback interface"]
fn idle_capture_returns_after_traffic_stops_without_busy_spinning() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = receiver.local_addr().unwrap();
    let (capture, _, _) = setup_packet_capture(CaptureConfig {
        interface: Some(loopback_interface().to_owned()),
        // Capture only this test's reserved loopback UDP port. The sender
        // sends once and stops, reproducing the transition to an idle read.
        filter: Some(format!(
            "udp and dst host 127.0.0.1 and dst port {}",
            address.port()
        )),
        ..CaptureConfig::default()
    })
    .unwrap();
    assert!(capture.is_nonblock());
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"rustnet idle capture regression", address)
        .unwrap();
    drop(sender);

    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut reader = PacketReader::new(capture);
        let packet_deadline = Instant::now() + Duration::from_secs(1);
        let mut captured = false;
        loop {
            assert!(
                Instant::now() < packet_deadline,
                "synthetic packet was not captured"
            );
            match reader.next_packet().unwrap() {
                Some(_) => captured = true,
                None if captured => break,
                None => {}
            }
        }

        let started = Instant::now();
        for _ in 0..3 {
            assert!(reader.next_packet().unwrap().is_none());
        }
        finished_tx.send(started.elapsed()).unwrap();
    });

    let elapsed = finished_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("capture must return after the synthetic traffic stops");
    assert!(
        elapsed >= Duration::from_millis(30),
        "idle polling must yield"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "idle polling must be bounded"
    );
    worker.join().unwrap();
}

#[test]
#[ignore = "requires packet-capture permissions on the loopback interface"]
fn packet_arriving_after_an_idle_read_is_not_consumed_by_the_readiness_wait() {
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = receiver.local_addr().unwrap();
    let (capture, _, _) = setup_packet_capture(CaptureConfig {
        interface: Some(loopback_interface().to_owned()),
        filter: Some(format!(
            "udp and dst host 127.0.0.1 and dst port {}",
            address.port()
        )),
        ..CaptureConfig::default()
    })
    .unwrap();
    let (idle_tx, idle_rx) = mpsc::sync_channel(1);
    let (finished_tx, finished_rx) = mpsc::sync_channel(1);
    let marker = b"rustnet capture readiness regression";
    let worker = std::thread::spawn(move || {
        let mut reader = PacketReader::new(capture);
        assert!(reader.next_packet().unwrap().is_none());
        idle_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if let Some(packet) = reader.next_packet().unwrap() {
                assert!(
                    packet
                        .data
                        .windows(marker.len())
                        .any(|bytes| bytes == marker)
                );
                finished_tx.send(()).unwrap();
                return;
            }
        }
        panic!("packet arriving after idle capture was not returned");
    });
    idle_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    // Give the reader an opportunity to enter its empty-read wait. The
    // socket-level unit test separately verifies early readiness wakeup
    // without imposing sub-millisecond scheduling assumptions here.
    std::thread::sleep(Duration::from_millis(1));
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(marker, address).unwrap();
    finished_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    worker.join().unwrap();
}
