//! eBPF socket tracker implementation using libbpf-rs

use super::{
    SocketMatch,
    loader::EbpfLoader,
    maps_libbpf::{ConnKey, MapReader},
};
use crate::{AttributionBackend, AttributionCapabilities, DegradationReason, MatchQuality};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) struct LibbpfSocketTracker {
    loader: EbpfLoader,
}

unsafe impl Send for LibbpfSocketTracker {}
unsafe impl Sync for LibbpfSocketTracker {}

impl LibbpfSocketTracker {
    /// Create a new eBPF socket tracker. The returned [`DegradationReason`]
    /// explains why eBPF is unavailable when the tracker is `None`.
    pub(crate) fn new() -> Result<(Option<Self>, DegradationReason)> {
        let (loader_opt, reason) = EbpfLoader::try_load()?;
        match loader_opt {
            Some(loader) => Ok((Some(Self { loader }), reason)),
            None => Ok((None, reason)),
        }
    }

    pub(crate) fn backend(&self) -> AttributionBackend {
        self.loader.backend()
    }

    fn capabilities(&self) -> AttributionCapabilities {
        self.loader.capabilities()
    }

    #[cfg(test)]
    fn new_for_backend(backend: AttributionBackend) -> Result<Self> {
        Ok(Self {
            loader: EbpfLoader::load_backend_for_test(backend)?,
        })
    }

    /// Look up process information for a connection (IPv4)
    fn lookup_v4(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Option<SocketMatch> {
        let required = if is_tcp {
            AttributionCapabilities::TCP_V4_CONNECT
        } else {
            AttributionCapabilities::UDP_V4_SEND
        };
        if !self.capabilities().contains(required) {
            return None;
        }

        self.lookup_keys(
            ConnKey::new_v4(src_ip, dst_ip, src_port, dst_port, is_tcp),
            ConnKey::new_v4(Ipv4Addr::UNSPECIFIED, dst_ip, src_port, dst_port, is_tcp),
            "IPv4",
        )
    }

    /// Look up process information for a connection (IPv6)
    fn lookup_v6(
        &mut self,
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Option<SocketMatch> {
        let required = if is_tcp {
            AttributionCapabilities::TCP_V6_CONNECT
        } else {
            AttributionCapabilities::UDP_V6_SEND
        };
        if !self.capabilities().contains(required) {
            return None;
        }

        self.lookup_keys(
            ConnKey::new_v6(src_ip, dst_ip, src_port, dst_port, is_tcp),
            ConnKey::new_v6(Ipv6Addr::UNSPECIFIED, dst_ip, src_port, dst_port, is_tcp),
            "IPv6",
        )
    }

    /// Look up process information for a connection (generic)
    pub(crate) fn lookup(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Option<SocketMatch> {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                self.lookup_v4(src, dst, src_port, dst_port, is_tcp)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                self.lookup_v6(src, dst, src_port, dst_port, is_tcp)
            }
            _ => {
                log::warn!("Mixed IPv4/IPv6 addresses not supported in eBPF lookup");
                None
            }
        }
    }

    /// Look up process information for an ICMP connection
    pub(crate) fn lookup_icmp(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        icmp_id: u16,
    ) -> Option<SocketMatch> {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst))
                if self
                    .capabilities()
                    .contains(AttributionCapabilities::ICMP_V4_SEND) =>
            {
                self.lookup_keys(
                    ConnKey::new_icmp_v4(src, dst, icmp_id),
                    ConnKey::new_icmp_v4(Ipv4Addr::UNSPECIFIED, dst, icmp_id),
                    "ICMP",
                )
            }
            (IpAddr::V6(src), IpAddr::V6(dst))
                if self
                    .capabilities()
                    .contains(AttributionCapabilities::ICMP_V6_SEND) =>
            {
                self.lookup_keys(
                    ConnKey::new_icmp_v6(src, dst, icmp_id),
                    ConnKey::new_icmp_v6(Ipv6Addr::UNSPECIFIED, dst, icmp_id),
                    "ICMP",
                )
            }
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => None,
            _ => {
                log::warn!("Mixed IPv4/IPv6 addresses not supported in eBPF ICMP lookup");
                None
            }
        }
    }

    /// Look up a socket in both orientations, allowing a zero source
    /// address in each, which is how unbound UDP, ICMP and pre-connect TCP
    /// sockets commonly appear in the map. `label` only names the lookup in
    /// debug logs.
    fn lookup_keys(
        &self,
        exact_key: ConnKey,
        zero_src_key: ConnKey,
        label: &str,
    ) -> Option<SocketMatch> {
        let socket_map = self.loader.socket_map();

        // Neither pod IP is necessarily local to the capture namespace.
        // Preserve a local wildcard match before trying the other endpoint:
        // on loopback both endpoints can have different owners.
        let reverse_key = exact_key.reversed();
        for (key, quality) in [
            (exact_key, MatchQuality::ExactTuple),
            (zero_src_key, MatchQuality::WildcardLocalAddress),
            (reverse_key, MatchQuality::ExactTuple),
            (
                reverse_key.without_source_address(),
                MatchQuality::WildcardLocalAddress,
            ),
        ] {
            match MapReader::lookup_connection(socket_map, key) {
                Ok(Some(result)) => return Some(SocketMatch::new(result, quality)),
                Ok(None) => {}
                Err(error) => log::debug!("eBPF {label} lookup failed: {error}"),
            }
        }
        if log::log_enabled!(log::Level::Debug)
            && let Err(error) = MapReader::debug_lookup_miss(socket_map, &exact_key)
        {
            log::debug!("Failed to debug lookup: {error}");
        }
        None
    }

    /// Remove stale entries from the eBPF map, returning how many were removed.
    pub(crate) fn cleanup_stale_entries(&mut self, stale_threshold_secs: u64) -> u32 {
        let socket_map = self.loader.socket_map();
        let stale_threshold_ns = stale_threshold_secs * 1_000_000_000;

        match MapReader::cleanup_stale_entries(socket_map, stale_threshold_ns) {
            Ok(count) => {
                if count > 0 {
                    log::info!("eBPF map cleanup: removed {} stale entries", count);
                }
                count
            }
            Err(e) => {
                log::debug!("eBPF map cleanup failed: {}", e);
                0
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::linux::ebpf::ProcessInfo;
    use crate::linux::process::resolve_executable;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket};
    use std::thread;
    use std::time::Duration;

    fn current_tid() -> u32 {
        // SAFETY: gettid takes no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    }

    /// Whether BPF-reported ids can be compared against `gettid`/`getpid` and
    /// `/proc` paths. `bpf_get_current_pid_tgid` always reports initial-PID-
    /// namespace values; inside a container those name different tasks than
    /// our own view does, and the comparison would be meaningless.
    fn ids_are_comparable(info: &ProcessInfo) -> bool {
        info.pid == std::process::id()
    }

    fn assert_current_identity(matched: &SocketMatch) {
        let info = &matched.info;
        // bpf_get_current_pid_tgid reports the initial PID namespace value.
        // Some VM/container procfs mounts hide that value, so the portable
        // integration assertion can only require a nonzero TGID and TID.
        assert!(info.pid > 0);
        assert_eq!(info.uid, unsafe { libc::geteuid() });
        assert_eq!(info.gid, unsafe { libc::getegid() });
        assert!(info.tid > 0);
        assert!(info.timestamp > 0);
        assert!(!info.comm.is_empty());

        // The socket belongs to this test process, so a hit is either the
        // exact tuple or the zero-source retry. Nothing else may be reported.
        assert!(
            matches!(
                matched.quality,
                MatchQuality::ExactTuple | MatchQuality::WildcardLocalAddress
            ),
            "unexpected match quality {}",
            matched.quality
        );

        assert_executable_resolves(info);
    }

    fn assert_executable_resolves(info: &ProcessInfo) {
        if !ids_are_comparable(info) {
            eprintln!(
                "skipping executable check: BPF TGID {} differs from our PID {}",
                info.pid,
                std::process::id()
            );
            return;
        }
        assert_eq!(
            resolve_executable(info.pid),
            std::env::current_exe().ok(),
            "/proc/<tgid>/exe must resolve to the test binary"
        );
    }

    fn lookup_with_retry(
        tracker: &mut LibbpfSocketTracker,
        source: IpAddr,
        destination: IpAddr,
        source_port: u16,
        destination_port: u16,
        is_tcp: bool,
    ) -> SocketMatch {
        for _ in 0..20 {
            if let Some(matched) =
                tracker.lookup(source, destination, source_port, destination_port, is_tcp)
            {
                return matched;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "no eBPF attribution for {source}:{source_port} -> {destination}:{destination_port}"
        );
    }

    fn test_tcp(
        tracker: &mut LibbpfSocketTracker,
        loopback: IpAddr,
        check_accept_tid: bool,
    ) -> u32 {
        let listener = TcpListener::bind((loopback, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let client = TcpStream::connect(server).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let client_local = client.local_addr().unwrap();

        let connect_info = lookup_with_retry(
            tracker,
            client_local.ip(),
            server.ip(),
            client_local.port(),
            server.port(),
            true,
        );
        assert_current_identity(&connect_info);

        let accept_info = lookup_with_retry(
            tracker,
            accepted.local_addr().unwrap().ip(),
            accepted.peer_addr().unwrap().ip(),
            accepted.local_addr().unwrap().port(),
            accepted.peer_addr().unwrap().port(),
            true,
        );
        assert_current_identity(&accept_info);

        // accept() ran on this thread, so the accepted socket must be recorded
        // against it rather than against some other task in the process.
        if check_accept_tid && ids_are_comparable(&accept_info.info) {
            assert_eq!(accept_info.info.tid, current_tid());
        }
        connect_info.info.pid
    }

    /// A socket created by a worker thread must be attributed to that thread,
    /// while the TGID stays the process. Without this the TID field would be
    /// indistinguishable from a copy of the TGID.
    fn test_worker_thread_tid(tracker: &mut LibbpfSocketTracker) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let main_tid = current_tid();

        let worker = thread::spawn(move || {
            let client = TcpStream::connect(server).unwrap();
            (current_tid(), client.local_addr().unwrap(), client)
        });
        let (worker_tid, client_local, _client) = worker.join().unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_ne!(worker_tid, main_tid, "worker must be a distinct thread");

        let matched = lookup_with_retry(
            tracker,
            client_local.ip(),
            server.ip(),
            client_local.port(),
            server.port(),
            true,
        );
        assert_current_identity(&matched);

        // Namespace-independent: the recording thread was not the group leader.
        assert_ne!(
            matched.info.tid, matched.info.pid,
            "connect() from a worker thread must record a TID distinct from the TGID"
        );
        if ids_are_comparable(&matched.info) {
            assert_eq!(matched.info.tid, worker_tid);
            assert_eq!(matched.info.pid, std::process::id());
        }
    }

    fn test_udp(tracker: &mut LibbpfSocketTracker, loopback: IpAddr) {
        let unspecified: IpAddr = match loopback {
            IpAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
            IpAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
        };
        let receiver = UdpSocket::bind((loopback, 0)).unwrap();
        let destination = receiver.local_addr().unwrap();

        let connected = UdpSocket::bind((unspecified, 0)).unwrap();
        connected.connect(destination).unwrap();
        connected.send(b"connected").unwrap();
        let source = connected.local_addr().unwrap();
        assert_current_identity(&lookup_with_retry(
            tracker,
            source.ip(),
            destination.ip(),
            source.port(),
            destination.port(),
            false,
        ));

        let unconnected = UdpSocket::bind((unspecified, 0)).unwrap();
        unconnected.send_to(b"sendto", destination).unwrap();
        let source = unconnected.local_addr().unwrap();
        assert_current_identity(&lookup_with_retry(
            tracker,
            loopback,
            destination.ip(),
            source.port(),
            destination.port(),
            false,
        ));
    }

    #[test]
    #[ignore = "helper process for retained socket attribution tests"]
    fn short_lived_socket_child() {
        let Ok(server) = std::env::var("RUSTNET_TEST_FLOW_SERVER") else {
            return;
        };
        if let Some(path) = std::env::var_os("RUSTNET_TEST_FLOW_CGROUP") {
            std::fs::write(
                std::path::Path::new(&path).join("cgroup.procs"),
                std::process::id().to_string(),
            )
            .unwrap();
        }
        if std::env::var_os("RUSTNET_TEST_FLOW_UDP").is_some() {
            let server: std::net::SocketAddr = server.parse().unwrap();
            let socket = UdpSocket::bind((server.ip(), 0)).unwrap();
            socket.connect(server).unwrap();
            socket.send(b"short flow").unwrap();
            println!("FLOW_SOURCE={}", socket.local_addr().unwrap());
        } else {
            let socket = TcpStream::connect(server).unwrap();
            println!("FLOW_SOURCE={}", socket.local_addr().unwrap());
        }
    }

    fn test_exited_process(
        tracker: &mut LibbpfSocketTracker,
        loopback: IpAddr,
        is_tcp: bool,
        parent_tgid: u32,
        cgroup: Option<&std::path::Path>,
    ) -> SocketMatch {
        let tcp = TcpListener::bind((loopback, 0)).unwrap();
        let udp = UdpSocket::bind((loopback, 0)).unwrap();
        let server = if is_tcp {
            tcp.local_addr()
        } else {
            udp.local_addr()
        }
        .unwrap();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "linux::ebpf::tracker_libbpf::integration_tests::short_lived_socket_child",
                "--nocapture",
            ])
            .env("RUSTNET_TEST_FLOW_SERVER", server.to_string());
        if let Some(path) = cgroup {
            command.env("RUSTNET_TEST_FLOW_CGROUP", path);
        }
        if !is_tcp {
            command.env("RUSTNET_TEST_FLOW_UDP", "1");
        }
        let child = command
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "child failed: {output:?}");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let source: std::net::SocketAddr = stdout
            .lines()
            .find_map(|line| line.strip_prefix("FLOW_SOURCE="))
            .expect("child reports its tuple")
            .parse()
            .unwrap();
        // Both socket and process have gone before the first lookup. No
        // namespace scan or earlier userspace cache hit can provide this owner.
        let matched = lookup_with_retry(
            tracker,
            source.ip(),
            server.ip(),
            source.port(),
            server.port(),
            is_tcp,
        );
        if parent_tgid == std::process::id() {
            assert_eq!(matched.info.pid, pid);
        }
        assert!(matched.info.pid > 0);
        assert_ne!(matched.info.pid, parent_tgid);
        assert!(!matched.info.comm.is_empty());
        let reversed = lookup_with_retry(
            tracker,
            server.ip(),
            source.ip(),
            server.port(),
            source.port(),
            is_tcp,
        );
        assert_eq!(reversed.info.pid, matched.info.pid);
        assert_eq!(reversed.info.socket_cgroup, matched.info.socket_cgroup);
        assert_eq!(reversed.quality, MatchQuality::ExactTuple);
        matched
    }

    fn run_socket_attribution_matrix(mut tracker: LibbpfSocketTracker) {
        eprintln!(
            "testing backend {} with capabilities {:?}",
            tracker.backend(),
            tracker.capabilities()
        );
        assert!(
            tracker
                .capabilities()
                .contains(crate::linux::ebpf::loader::CORE_CAPABILITIES)
        );

        // Two local UDP peers can both be recorded, with the sender bound
        // to 0.0.0.0 and the receiver bound to a concrete address. Adding a
        // reverse lookup must not replace the sender with the receiver.
        {
            use libbpf_rs::MapCore;
            let forward = ConnKey::new_v4(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(192, 0, 2, 2),
                40000,
                5300,
                false,
            );
            for (key, pid) in [
                (forward.without_source_address(), 100_u32),
                (forward.reversed(), 200),
            ] {
                let mut value = [0; super::super::maps_libbpf::CONN_INFO_SIZE];
                value[..4].copy_from_slice(&pid.to_ne_bytes());
                tracker
                    .loader
                    .socket_map()
                    .update(&key.as_bytes(), &value, libbpf_rs::MapFlags::ANY)
                    .unwrap();
            }
            let matched = tracker
                .lookup_keys(forward, forward.without_source_address(), "UDP")
                .unwrap();
            assert_eq!(matched.info.pid, 100);
            assert_eq!(matched.quality, MatchQuality::WildcardLocalAddress);
        }

        // The accepted-socket TID assertion runs for v4 only; the v6 run
        // covers the rest of the scenario.
        let parent_tgid = test_tcp(&mut tracker, Ipv4Addr::LOCALHOST.into(), true);
        test_tcp(&mut tracker, Ipv6Addr::LOCALHOST.into(), false);
        test_udp(&mut tracker, Ipv4Addr::LOCALHOST.into());
        test_udp(&mut tracker, Ipv6Addr::LOCALHOST.into());
        test_worker_thread_tid(&mut tracker);
        for loopback in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            test_exited_process(&mut tracker, loopback, true, parent_tgid, None);
            test_exited_process(&mut tracker, loopback, false, parent_tgid, None);
        }
    }

    #[test]
    #[ignore = "requires root, eBPF, and a writable private cgroup v2 mount"]
    fn exited_kubernetes_process_keeps_cgroup_names() {
        // Only create descendants of a unique test directory. Drop removes
        // these empty directories even if a later assertion fails.
        struct Cgroups(Vec<std::path::PathBuf>);
        impl Drop for Cgroups {
            fn drop(&mut self) {
                for path in self.0.iter().rev() {
                    let _ = std::fs::remove_dir(path);
                }
            }
        }
        let mut dirs = Cgroups(Vec::new());
        let root = std::path::Path::new("/sys/fs/cgroup")
            .join(format!("rustnet-flow-test-{}", std::process::id()));
        let parent = "pod123e4567-e89b-12d3-a456-426614174000";
        let name = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let pod = root.join(parent);
        let container = pod.join(name);
        for path in [&root, &pod, &container] {
            std::fs::create_dir(path).unwrap();
            dirs.0.push(path.clone());
        }
        for backend in [
            AttributionBackend::EbpfFentry,
            AttributionBackend::EbpfKprobe,
        ] {
            let mut tracker = LibbpfSocketTracker::new_for_backend(backend).unwrap();
            let parent_tgid = test_tcp(&mut tracker, Ipv4Addr::LOCALHOST.into(), true);
            for is_tcp in [true, false] {
                let matched = test_exited_process(
                    &mut tracker,
                    Ipv4Addr::LOCALHOST.into(),
                    is_tcp,
                    parent_tgid,
                    Some(&container),
                );
                assert_eq!(
                    matched.info.socket_cgroup,
                    Some(crate::SocketCgroup {
                        name: name.into(),
                        parent: parent.into(),
                    })
                );
            }
        }
    }

    #[test]
    #[ignore = "requires root or CAP_BPF+CAP_PERFMON and a compatible Linux kernel"]
    fn socket_attribution_matrix() {
        let (tracker, reason) = LibbpfSocketTracker::new().unwrap();
        let tracker = tracker
            .unwrap_or_else(|| panic!("no eBPF backend available: {}", reason.description()));
        run_socket_attribution_matrix(tracker);
    }

    #[test]
    #[ignore = "requires root or CAP_SYS_ADMIN and a kernel with kprobes"]
    fn legacy_kprobe_socket_attribution_matrix() {
        run_socket_attribution_matrix(
            LibbpfSocketTracker::new_for_backend(AttributionBackend::EbpfKprobe).unwrap(),
        );
    }
}
