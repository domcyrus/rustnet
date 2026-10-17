//! Exercise process-exit observation from the same sandbox as the real worker.
#![cfg(all(target_os = "linux", feature = "landlock"))]

use rustnet_core::network::types::{Connection, Protocol, ProtocolState};
use rustnet_host::{LifecycleTracker, ProcessAttribution, ProcessLookup, TrackedConnection};
use std::io::{BufRead, BufReader};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// Linux exit cleanup reads fresh procfs tables independently of attribution.
struct NoInventory;
impl ProcessLookup for NoInventory {
    fn get_process_attribution(&self, _: &Connection) -> Option<ProcessAttribution> {
        None
    }

    fn get_detection_method(&self) -> &str {
        "test"
    }
}

struct SocketChild(Child);

impl Drop for SocketChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn socket_child() {
    if std::env::var_os("RUSTNET_SANDBOX_EXIT_CHILD").is_none() {
        return;
    }
    let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
    println!("READY={}", socket.local_addr().unwrap().port());
    loop {
        std::thread::park();
    }
}

#[test]
fn sandboxed_worker_observes_exit_and_socket_disappearance() {
    let mut child = SocketChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "socket_child", "--nocapture"])
            .env("RUSTNET_SANDBOX_EXIT_CHILD", "1")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut reader = BufReader::new(child.0.stdout.take().unwrap());
    let port = loop {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        if let Some((_, port)) = line.split_once("READY=") {
            break port.trim().parse::<u16>().unwrap();
        }
    };
    let pid = child.0.id();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let start = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let mut conn = Connection::new(
        Protocol::Udp,
        format!("[::1]:{port}").parse().unwrap(),
        "[::1]:443".parse().unwrap(),
        ProtocolState::Udp,
    );
    conn.pid = Some(pid);
    conn.process_start_id = Some(start);
    conn.socket_netns_id = Some(std::fs::metadata("/proc/self/ns/net").unwrap().ino());
    let observed = TrackedConnection::from_connection(&conn).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let report = rustnet_sandbox::apply_sandbox(&rustnet_sandbox::SandboxConfig {
            block_network: true,
            ..Default::default()
        })
        .unwrap();
        assert_ne!(report.status, rustnet_sandbox::SandboxStatus::Error);
        let mut tracker = LifecycleTracker::default();
        for _ in 0..6 {
            assert!(
                tracker
                    .closed_connections(&[observed], &NoInventory)
                    .is_empty()
            );
            std::thread::sleep(Duration::from_millis(250));
        }
        assert_eq!(
            tracker.connection_status(&conn),
            Some(rustnet_core::network::types::ProcessExitStatus::Watching)
        );
        ready_tx.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !tracker
                .closed_connections(&[observed], &NoInventory)
                .is_empty()
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        false
    });
    let ready = ready_rx.recv_timeout(Duration::from_secs(10));
    let _ = child.0.kill();
    child.0.wait().unwrap();
    ready.unwrap();
    assert!(
        worker.join().unwrap(),
        "sandboxed worker failed to retire the exited owner's socket"
    );
}
