#![cfg(all(target_os = "linux", feature = "landlock"))]

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::AtomicBool;

#[test]
#[ignore = "requires Linux INET_DIAG and Landlock"]
fn telemetry_refreshes_after_runtime_sandboxing() {
    // Sandbox only this dedicated thread, preserving the test runner.
    std::thread::spawn(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let mut lookup = rustnet_host::create_process_lookup(false).unwrap();
        let report = rustnet_sandbox::apply_sandbox(&rustnet_sandbox::SandboxConfig {
            block_network: true,
            ..Default::default()
        })
        .unwrap();
        assert!(report.fs_restricted, "{}", report.message);
        assert!(report.net_restricted, "{}", report.message);
        lookup.start_runtime().unwrap();
        for received in [32, 64] {
            client.write_all(&[1; 32]).unwrap();
            lookup
                .refresh_interruptible(&AtomicBool::new(false))
                .unwrap();
            let snapshot = lookup.socket_snapshot();
            let socket = snapshot
                .sockets
                .iter()
                .find(|s| {
                    s.local_addr == server.local_addr().unwrap()
                        && s.remote_addr == Some(server.peer_addr().unwrap())
                })
                .unwrap();
            let stats = socket
                .kernel_stats
                .as_ref()
                .expect("diagnostics survive sandbox");
            assert_eq!(stats.queues.receive, received);
            assert!(stats.socket_cookie.is_some());
        }
    })
    .join()
    .unwrap();
}
