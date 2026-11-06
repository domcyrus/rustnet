use super::*;
use rustnet_core::network::types::ProtocolState;
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};

const CHILD_MODE: &str = "RUSTNET_LIFECYCLE_TEST_CHILD";

struct TestChild(Child);

impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn socket_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    if mode == "protected" {
        // SAFETY: this changes only the disposable child's dumpability.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) }, 0);
    }
    let socket = (mode == "protected").then(|| UdpSocket::bind("[::]:0").unwrap());
    let socket = socket.or_else(|| {
        matches!(mode.as_str(), "private" | "short").then(|| {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.connect("127.0.0.1:9").unwrap();
            socket
        })
    });
    let socket = socket.or_else(|| match mode.as_str() {
        "unconnected4" => Some(UdpSocket::bind("0.0.0.0:0").unwrap()),
        "unconnected6" => Some(UdpSocket::bind("[::]:0").unwrap()),
        _ => None,
    });
    let tcp = mode
        .strip_prefix("tcp:")
        .map(|target| TcpStream::connect(target).unwrap());
    let addr = tcp
        .as_ref()
        .map(TcpStream::local_addr)
        .transpose()
        .unwrap()
        .or(socket
            .as_ref()
            .map(UdpSocket::local_addr)
            .transpose()
            .unwrap())
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
    if mode == "short" {
        drop(socket);
    }
    println!("LIFECYCLE_READY={addr}");
    // The parent kills and reaps this subprocess after registering its
    // watch. No network traffic or external executable is required.
    loop {
        std::thread::park();
    }
}

fn child(mode: &str, stdin: Stdio) -> (TestChild, SocketAddr) {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux::lifecycle::tests::socket_child",
            "--nocapture",
        ])
        .env(CHILD_MODE, mode)
        .stdin(stdin)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut child = TestChild(child);
    let stdout = child.0.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        assert!(
            reader.read_line(&mut line).unwrap() > 0,
            "child exited before readiness"
        );
        if let Some((_, addr)) = line.split_once("LIFECYCLE_READY=") {
            return (child, addr.trim().parse().unwrap());
        }
    }
}

fn observation(pid: u32, addr: SocketAddr) -> TrackedConnection {
    let mut conn = Connection::new(
        Protocol::Udp,
        addr,
        "127.0.0.1:9".parse().unwrap(),
        ProtocolState::Udp,
    );
    conn.pid = Some(pid);
    conn.process_start_id = process_start_ticks(pid);
    TrackedConnection::from_connection(&conn).unwrap()
}

fn exit(child: &mut TestChild) {
    child.0.kill().unwrap();
    child.0.wait().unwrap();
}

#[cfg(feature = "ebpf")]
#[test]
fn protected_socket_present_at_startup_enrolls_without_reading_owner_fds() {
    use crate::linux::process::{LinuxProcessLookup, StartupSocketOwners};
    use crate::{ProcessLookup, SocketOwner};

    let (mut child, addr) = child("protected", Stdio::null());
    let pid = child.0.id();
    assert!(fs::read_dir(format!("/proc/{pid}/fd")).is_err());
    let table = fs::read_to_string("/proc/net/udp6").unwrap();
    let inode = table
        .lines()
        .skip(1)
        .find_map(|line| {
            let row = parse_proc_net_line(line)?;
            (row.local_addr == addr).then(|| row.inode.unwrap().parse::<u64>().unwrap())
        })
        .unwrap();
    // The startup BPF iterator observes ownership without opening /proc/PID/fd.
    let mut owners = StartupSocketOwners::default();
    owners.insert(
        inode,
        SocketOwner::new(pid, crate::procfs::read_comm(pid).unwrap(), None),
    );
    let lookup = LinuxProcessLookup::new_with_bpf_startup_owners(owners).unwrap();
    let mut conn = Connection::new(
        Protocol::Udp,
        SocketAddr::new("::1".parse().unwrap(), addr.port()),
        "[::1]:443".parse().unwrap(),
        ProtocolState::Udp,
    );
    let attribution = lookup.get_process_attribution(&conn).unwrap();
    assert_eq!(attribution.process_start_id, process_start_ticks(pid));
    assert_eq!(attribution.socket_netns_id, local_netns_id());
    conn.pid = Some(attribution.tgid);
    conn.process_start_id = attribution.process_start_id;
    conn.socket_netns_id = attribution.socket_netns_id;
    let observed = TrackedConnection::from_connection(&conn).unwrap();
    let mut tracker = ProcessExitTracker::default();
    enroll(&mut tracker, observed);
    exit(&mut child);
    assert_eq!(await_closure(&mut tracker, observed), observed.observation);
}

fn is_enrolled(tracker: &ProcessExitTracker, conn: TrackedConnection) -> bool {
    tracker
        .observations
        .get(&conn.identity())
        .is_some_and(|observation| observation.enrolled)
}

fn enroll(tracker: &mut ProcessExitTracker, conn: TrackedConnection) {
    // Procfs enumeration is not atomic while sibling tests open/close
    // sockets. Wait for the actual socket to be observed before exiting.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !is_enrolled(tracker, conn) {
        assert!(Instant::now() < deadline, "socket was not observed");
        tracker.last_scan = None;
        assert!(tracker.scan_closed(&[conn]).is_empty());
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn await_closure(
    tracker: &mut ProcessExitTracker,
    conn: TrackedConnection,
) -> ConnectionObservation {
    // Live procfs reads can be incomplete while parallel tests create and
    // release sockets. Only the deterministic table fixtures assume that
    // every scan succeeds; allow fresh complete scans to confirm closure.
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        tracker.last_scan = None;
        let closed = tracker.scan_closed(&[conn]);
        if let Some(observed) = closed.first() {
            assert_eq!(closed.len(), 1);
            return *observed;
        }
        assert!(
            Instant::now() < deadline,
            "closure not confirmed: {:?}",
            tracker.observation_status(&conn)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn exited_owner_retires_private_socket_but_not_a_new_connection_generation() {
    let (mut child, addr) = child("private", Stdio::null());
    let conn = observation(child.0.id(), addr);
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    enroll(&mut tracker, conn);
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );

    let replacement = TrackedConnection {
        observation: ConnectionObservation {
            created_at: conn.observation.created_at + Duration::from_secs(1),
            ..conn.observation
        },
        ..conn
    };
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[replacement]).is_empty());
    tracker.scan_closed(&[]);
    assert!(
        tracker.watches[&conn.process()]
            .as_ref()
            .unwrap()
            .fd
            .is_none()
    );
    tracker
        .watches
        .get_mut(&conn.process())
        .unwrap()
        .as_mut()
        .unwrap()
        .exited_at = Some(Instant::now() - Duration::from_secs(301));
    tracker.scan_closed(&[]);
    assert!(tracker.watches.is_empty());
    assert!(tracker.observations.is_empty());
}

#[test]
fn exited_tcp_owner_retires_without_waiting_for_transport_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let remote = listener.local_addr().unwrap();
    let (mut child, local) = child(&format!("tcp:{remote}"), Stdio::null());
    let (_server, _) = listener.accept().unwrap();
    let mut conn = observation(child.0.id(), local);
    conn.observation.key.protocol = Protocol::Tcp;
    conn.observation.key.remote_addr = remote;
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    enroll(&mut tracker, conn);
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );
}

#[test]
fn captured_namespace_covers_socket_closed_between_scans() {
    let (mut child, addr) = child("short", Stdio::null());
    let mut conn = observation(child.0.id(), addr);
    conn.socket_netns_id = local_netns_id();
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert!(is_enrolled(&tracker, conn));
    assert_eq!(
        tracker.observation_status(&conn),
        ProcessExitStatus::Watching
    );
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );
}

#[test]
fn delayed_packets_use_cached_exit_but_a_reused_live_socket_is_preserved() {
    let (mut child, addr) = child("private", Stdio::null());
    let mut conn = observation(child.0.id(), addr);
    conn.socket_netns_id = local_netns_id();
    let mut tracker = ProcessExitTracker::default();
    enroll(&mut tracker, conn);
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );
    tracker.scan_closed(&[]);
    let delayed = TrackedConnection {
        observation: ConnectionObservation {
            created_at: conn.observation.created_at + Duration::from_secs(1),
            ..conn.observation
        },
        ..conn
    };
    // A new local socket using this tuple must survive even if an old
    // eBPF attribution is returned for its first incoming packet.
    let replacement = UdpSocket::bind(addr).unwrap();
    replacement
        .connect(conn.observation.key.remote_addr)
        .unwrap();
    for _ in 0..2 {
        tracker.last_scan = None;
        assert!(tracker.scan_closed(&[delayed]).is_empty());
    }
    assert_eq!(
        tracker.observation_status(&delayed),
        ProcessExitStatus::SocketPresentAfterExit
    );
    drop(replacement);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[delayed]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, delayed).identity(),
        delayed.identity()
    );
}

#[test]
fn protected_ipv6_udp_owner_retires_using_captured_socket_namespace() {
    let (mut child, wildcard) = child("protected", Stdio::null());
    // This is the permission boundary hit by protected browser processes.
    assert!(fs::read_link(format!("/proc/{}/ns/net", child.0.id())).is_err());
    let mut conn = observation(child.0.id(), wildcard);
    conn.observation
        .key
        .local_addr
        .set_ip(std::net::Ipv6Addr::LOCALHOST.into());
    conn.observation.key.remote_addr = "[::1]:443".parse().unwrap();
    let mut tracker = ProcessExitTracker::default();
    // A live pidfd alone is not sufficient without namespace evidence.
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert!(!is_enrolled(&tracker, conn));
    assert!(tracker.watches[&conn.process()].is_ok());
    // eBPF supplies the socket namespace without dereferencing that link.
    conn.socket_netns_id = local_netns_id();
    assert!(conn.socket_netns_id.is_some());
    enroll(&mut tracker, conn);
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );
}

#[test]
fn different_socket_namespace_is_not_enrolled_even_if_tuple_matches() {
    let (child, addr) = child("private", Stdio::null());
    let mut conn = observation(child.0.id(), addr);
    conn.socket_netns_id = local_netns_id().map(|id| id + 1);
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert!(!is_enrolled(&tracker, conn));
    assert!(!socket_in_local_namespace(&conn, None));
}

#[test]
fn procfs_attribution_supplies_verified_process_birth_identity() {
    use crate::ProcessLookup;
    let (child, local) = child("private", Stdio::null());
    let lookup = super::super::process::LinuxProcessLookup::new().unwrap();
    let conn = Connection::new(
        Protocol::Udp,
        local,
        "127.0.0.1:9".parse().unwrap(),
        ProtocolState::Udp,
    );
    let attribution = lookup.get_process_attribution(&conn).unwrap();
    assert_eq!(attribution.tgid, child.0.id());
    assert_eq!(
        attribution.process_start_id,
        process_start_ticks(child.0.id())
    );
    assert!(attribution.process_start_id.is_some());
    assert_eq!(attribution.socket_netns_id, local_netns_id());
}

#[test]
fn procfs_unconnected_udp_attribution_enrolls_and_retires_after_exit() {
    use crate::ProcessLookup;
    for (mode, local_ip, remote) in [
        ("unconnected4", "127.0.0.1", "127.0.0.1:9"),
        ("unconnected6", "::1", "[::1]:9"),
    ] {
        let (mut child, mut local) = child(mode, Stdio::null());
        local.set_ip(local_ip.parse().unwrap());
        let lookup = super::super::process::LinuxProcessLookup::new().unwrap();
        let mut conn = Connection::new(
            Protocol::Udp,
            local,
            remote.parse().unwrap(),
            ProtocolState::Udp,
        );
        let attribution = lookup.get_process_attribution(&conn).unwrap();
        assert_eq!(attribution.tgid, child.0.id());
        assert_eq!(
            attribution.quality,
            rustnet_core::network::types::MatchQuality::ProcfsRelaxed
        );
        assert!(attribution.process_start_id.is_some());
        conn.pid = Some(attribution.tgid);
        conn.process_start_id = attribution.process_start_id;
        conn.socket_netns_id = attribution.socket_netns_id;
        let observed = TrackedConnection::from_connection(&conn).unwrap();
        let mut tracker = ProcessExitTracker::default();
        enroll(&mut tracker, observed);
        exit(&mut child);
        tracker.last_scan = None;
        assert!(tracker.scan_closed(&[observed]).is_empty());
        assert_eq!(
            await_closure(&mut tracker, observed).identity(),
            observed.identity()
        );
    }
}

#[test]
fn worker_thread_exit_does_not_signal_whole_process_exit() {
    let pid = std::process::id();
    let start = process_start_ticks(pid).unwrap();
    let mut tracker = ProcessExitTracker::default();
    tracker
        .watches
        .insert((pid, start), Watch::open(pid, start));
    std::thread::spawn(|| {}).join().unwrap();
    tracker.poll_exits();
    assert!(!tracker.watches[&(pid, start)].as_ref().unwrap().exited());
}

#[test]
fn inherited_socket_survives_owner_exit_until_last_reference_closes() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect("127.0.0.1:9").unwrap();
    let inherited: OwnedFd = socket.try_clone().unwrap().into();
    let (mut child, _) = child("shared", Stdio::from(inherited));
    let conn = observation(child.0.id(), socket.local_addr().unwrap());
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    enroll(&mut tracker, conn);
    exit(&mut child);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    drop(socket);
    tracker.last_scan = None;
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert_eq!(
        await_closure(&mut tracker, conn).identity(),
        conn.identity()
    );
}

#[test]
fn missed_registration_and_wrong_process_generation_do_not_prove_closure() {
    let pid = std::process::id();
    let start = process_start_ticks(pid).unwrap();
    assert!(Watch::open(pid, start + 1).is_err());
    assert!(Watch::open(pid, start).is_ok());
    let (mut child, addr) = child("private", Stdio::null());
    let conn = observation(child.0.id(), addr);
    exit(&mut child);
    let mut tracker = ProcessExitTracker::default();
    assert!(tracker.scan_closed(&[conn]).is_empty());
    assert!(!is_enrolled(&tracker, conn));
}

#[test]
fn failed_scan_new_traffic_and_reappearing_socket_reset_confirmation() {
    let conn = observation(std::process::id(), "127.0.0.1:40000".parse().unwrap());
    let mut tracker = ProcessExitTracker::default();
    let mut watch = Watch::open(conn.pid, conn.start_id).unwrap();
    watch.exited_at = Some(Instant::now());
    tracker.watches.insert(conn.process(), Ok(watch));
    tracker
        .observations
        .entry(conn.identity())
        .or_default()
        .enrolled = true;
    let mut tables = SocketTables {
        tables: HashMap::from([
            ((Protocol::Udp, false), Some(HashSet::new())),
            ((Protocol::Udp, true), Some(HashSet::new())),
        ]),
    };
    assert!(tracker.reconcile(&[conn], &tables).is_empty());
    tables.tables.insert((Protocol::Udp, false), None);
    assert!(tracker.reconcile(&[conn], &tables).is_empty());
    tables
        .tables
        .insert((Protocol::Udp, false), Some(HashSet::new()));
    assert!(tracker.reconcile(&[conn], &tables).is_empty());
    let active = TrackedConnection {
        observation: ConnectionObservation {
            packet_counts: (1, 0),
            ..conn.observation
        },
        ..conn
    };
    assert!(tracker.reconcile(&[active], &tables).is_empty());
    tables.tables.insert(
        (Protocol::Udp, false),
        Some(HashSet::from([conn.observation.key])),
    );
    assert!(tracker.reconcile(&[active], &tables).is_empty());
    tables
        .tables
        .insert((Protocol::Udp, false), Some(HashSet::new()));
    assert!(tracker.reconcile(&[active], &tables).is_empty());
    assert_eq!(tracker.reconcile(&[active], &tables).len(), 1);
}

#[test]
fn incomplete_tables_are_unknown_and_wildcard_udp_sockets_are_preserved() {
    let header = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    assert!(parse_table("", Protocol::Udp).is_err());
    assert!(parse_table("not a socket table", Protocol::Udp).is_err());
    assert!(parse_table(&format!("{header}0: broken\n"), Protocol::Udp).is_err());
    let row =
        "0: 00000000:1234 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 42\n";
    let table = parse_table(&format!("{header}{row}"), Protocol::Udp).unwrap();
    let key = ConnectionKey {
        protocol: Protocol::Udp,
        local_addr: "127.0.0.1:4660".parse().unwrap(),
        remote_addr: "127.0.0.1:9".parse().unwrap(),
    };
    let mut tables = SocketTables {
        tables: HashMap::from([((Protocol::Udp, false), Some(table))]),
    };
    assert_eq!(tables.contains(key), Some(true));
    tables.tables.insert((Protocol::Udp, false), None);
    assert_eq!(tables.contains(key), None);
    tables
        .tables
        .insert((Protocol::Udp, false), Some(HashSet::new()));
    tables
        .tables
        .insert((Protocol::Udp, true), Some(HashSet::new()));
    assert_eq!(tables.contains(key), Some(false));
    let dual_stack = ConnectionKey {
        protocol: Protocol::Udp,
        local_addr: "[::]:4660".parse().unwrap(),
        remote_addr: "[::]:0".parse().unwrap(),
    };
    tables
        .tables
        .insert((Protocol::Udp, true), Some(HashSet::from([dual_stack])));
    assert_eq!(tables.contains(key), Some(true));
}
