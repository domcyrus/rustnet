use super::*;
use crate::SocketOwner;
use rustnet_core::network::types::Connection;
use std::time::Duration;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn flow() -> TrackedConnection {
    let mut conn = Connection::new(
        Protocol::Udp,
        "192.0.2.1:45000".parse().unwrap(),
        "198.51.100.1:443".parse().unwrap(),
        rustnet_core::network::types::ProtocolState::Udp,
    );
    conn.created_at = at(1);
    conn.last_activity = at(2);
    conn.packets_sent = 1;
    conn.packets_received = 1;
    TrackedConnection::from_connection(&conn).unwrap()
}

fn socket() -> HostSocket {
    HostSocket {
        protocol: Protocol::Udp,
        local_addr: "[::]:45000".parse().unwrap(),
        remote_addr: None,
        state: HostSocketState::UdpBound,
        owner: Some(SocketOwner::new(123, "browser", None)),
        native_id: None,
    }
}

fn scan(second: u64, sockets: Vec<HostSocket>) -> SocketSnapshot {
    SocketSnapshot::new(sockets).with_closure_evidence(at(second))
}

#[test]
fn two_fresh_absences_required_and_unseen_flows_are_preserved() {
    let conn = flow();
    let mut tracker = SocketLifecycleTracker::default();
    assert!(tracker.scan_closed(&[conn], &scan(3, vec![])).is_empty());
    assert!(tracker.scan_closed(&[conn], &scan(4, vec![])).is_empty());
    assert!(
        tracker
            .scan_closed(&[conn], &scan(5, vec![socket()]))
            .is_empty()
    );
    assert!(tracker.scan_closed(&[conn], &scan(6, vec![])).is_empty());
    assert!(tracker.scan_closed(&[conn], &scan(6, vec![])).is_empty());
    assert_eq!(tracker.scan_closed(&[conn], &scan(7, vec![])).len(), 1);
}

#[test]
fn traffic_during_a_scan_still_allows_positive_enrollment() {
    let mut conn = flow();
    conn.last_activity = at(4);
    let mut tracker = SocketLifecycleTracker::default();
    tracker.scan_closed(&[conn], &scan(3, vec![socket()]));
    assert_eq!(
        tracker.observation_status(&conn),
        ProcessExitStatus::WatchingSocket
    );
    assert!(tracker.scan_closed(&[conn], &scan(5, vec![])).is_empty());
    assert_eq!(tracker.scan_closed(&[conn], &scan(6, vec![])).len(), 1);
}

#[test]
fn failures_and_activity_reset_confirmation() {
    let mut conn = flow();
    let mut tracker = SocketLifecycleTracker::default();
    tracker.scan_closed(&[conn], &scan(3, vec![socket()]));
    tracker.scan_closed(&[conn], &scan(4, vec![]));
    tracker.scan_closed(&[conn], &SocketSnapshot::default());
    assert_eq!(
        tracker.observation_status(&conn),
        ProcessExitStatus::SocketScanIncomplete
    );
    assert!(tracker.scan_closed(&[conn], &scan(5, vec![])).is_empty());
    conn.packet_counts.0 += 1; // Even equal packet timestamps break confirmation.
    assert!(tracker.scan_closed(&[conn], &scan(6, vec![])).is_empty());
    tracker.invalidate();
    assert!(tracker.scan_closed(&[conn], &scan(7, vec![])).is_empty());
    assert_eq!(tracker.scan_closed(&[conn], &scan(8, vec![])).len(), 1);
}

#[test]
fn shared_or_reused_socket_resets_confirmation_regardless_of_owner() {
    let conn = flow();
    let mut tracker = SocketLifecycleTracker::default();
    tracker.scan_closed(&[conn], &scan(3, vec![socket()]));
    tracker.scan_closed(&[conn], &scan(4, vec![]));
    let mut inherited = socket();
    inherited.owner = Some(SocketOwner::new(456, "child", None));
    assert!(
        tracker
            .scan_closed(&[conn], &scan(5, vec![inherited]))
            .is_empty()
    );
    assert!(tracker.scan_closed(&[conn], &scan(6, vec![])).is_empty());
    assert_eq!(tracker.scan_closed(&[conn], &scan(7, vec![])).len(), 1);
}

#[test]
fn new_generation_and_packets_during_scan_do_not_inherit_absence() {
    let mut conn = flow();
    let mut tracker = SocketLifecycleTracker::default();
    tracker.scan_closed(&[conn], &scan(3, vec![socket()]));
    tracker.scan_closed(&[conn], &scan(4, vec![]));
    conn.last_activity = at(6);
    assert!(tracker.scan_closed(&[conn], &scan(5, vec![])).is_empty());
    assert!(tracker.scan_closed(&[conn], &scan(7, vec![])).is_empty());
    conn.created_at = at(8);
    assert!(tracker.scan_closed(&[conn], &scan(9, vec![])).is_empty());
    assert!(tracker.scan_closed(&[conn], &scan(10, vec![])).is_empty());
    assert_eq!(tracker.observations.len(), 1);
}

#[test]
fn matches_dual_stack_wildcards_mapped_addresses_and_tcp_peers() {
    let conn = flow();
    assert!(matches_socket(&socket(), &conn.key));
    let mut sock = socket();
    sock.local_addr = "[::ffff:192.0.2.1]:45000".parse().unwrap();
    assert!(matches_socket(&sock, &conn.key));
    sock.remote_addr = Some("198.51.100.2:443".parse().unwrap());
    assert!(!matches_socket(&sock, &conn.key));
    let mut tcp = conn.key;
    tcp.protocol = Protocol::Tcp;
    sock.protocol = Protocol::Tcp;
    sock.state = HostSocketState::Tcp(HostTcpState::Established);
    sock.remote_addr = Some(tcp.remote_addr);
    assert!(matches_socket(&sock, &tcp));
    sock.state = HostSocketState::Tcp(HostTcpState::TimeWait);
    assert!(!matches_socket(&sock, &tcp));
    sock.state = HostSocketState::Tcp(HostTcpState::Listen);
    sock.remote_addr = None;
    assert!(!matches_socket(&sock, &tcp));
}
