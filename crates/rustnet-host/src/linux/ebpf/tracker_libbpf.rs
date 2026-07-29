//! eBPF socket tracker implementation using libbpf-rs

use super::{
    SocketMatch,
    loader::EbpfLoader,
    maps_libbpf::{ConnKey, MapReader},
};
use crate::{AttributionBackend, AttributionCapabilities, DegradationReason, MatchQuality};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct LibbpfSocketTracker {
    loader: EbpfLoader,
}

unsafe impl Send for LibbpfSocketTracker {}
unsafe impl Sync for LibbpfSocketTracker {}

impl LibbpfSocketTracker {
    /// Create a new eBPF socket tracker
    /// Returns (Option<Self>, DegradationReason) - the reason explains why eBPF is unavailable
    pub fn new() -> Result<(Option<Self>, DegradationReason)> {
        let (loader_opt, reason) = EbpfLoader::try_load()?;
        match loader_opt {
            Some(loader) => Ok((Some(Self { loader }), reason)),
            None => Ok((None, reason)),
        }
    }

    pub fn backend(&self) -> AttributionBackend {
        self.loader.backend()
    }

    pub fn capabilities(&self) -> AttributionCapabilities {
        self.loader.capabilities()
    }

    #[cfg(test)]
    fn new_for_backend(backend: AttributionBackend) -> Result<Self> {
        Ok(Self {
            loader: EbpfLoader::load_backend_for_test(backend)?,
        })
    }

    /// Look up process information for a connection (IPv4)
    pub fn lookup_v4(
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

        let socket_map = self.loader.socket_map();

        // Try exact match first
        let key = ConnKey::new_v4(src_ip, dst_ip, src_port, dst_port, is_tcp);
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => {
                return Some(SocketMatch::new(result, MatchQuality::ExactTuple));
            }
            Ok(None) => {
                log::debug!("eBPF exact lookup miss, trying with zero source address");
            }
            Err(e) => {
                log::debug!("eBPF IPv4 lookup failed: {}", e);
            }
        }

        // Try with zero source address (common for eBPF UDP/TCP entries)
        let zero_src_key = ConnKey::new_v4(
            Ipv4Addr::new(0, 0, 0, 0),
            dst_ip,
            src_port,
            dst_port,
            is_tcp,
        );
        log::debug!(
            "eBPF zero-source key bytes: {:02x?}",
            zero_src_key.as_bytes()
        );
        match MapReader::lookup_connection(socket_map, zero_src_key) {
            Ok(Some(result)) => {
                log::debug!(
                    "eBPF lookup succeeded with zero source address: PID {}, comm {}",
                    result.pid,
                    result.comm
                );
                // Let cleanup handle entry deletion based on age
                Some(SocketMatch::new(result, MatchQuality::WildcardLocalAddress))
            }
            Ok(None) => {
                // Debug both keys for comparison
                log::debug!("eBPF lookup missed with both exact and zero-source keys");
                if let Err(e) = MapReader::debug_lookup_miss(socket_map, &key) {
                    log::debug!("Failed to debug lookup: {}", e);
                }
                None
            }
            Err(e) => {
                log::debug!("eBPF zero-source lookup failed: {}", e);
                None
            }
        }
    }

    /// Look up process information for a connection (IPv6)
    pub fn lookup_v6(
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

        let key = ConnKey::new_v6(src_ip, dst_ip, src_port, dst_port, is_tcp);

        let socket_map = self.loader.socket_map();
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => {
                // Let cleanup handle entry deletion based on age
                return Some(SocketMatch::new(result, MatchQuality::ExactTuple));
            }
            Ok(None) => {
                log::debug!("eBPF IPv6 exact lookup miss, trying zero source address");
            }
            Err(e) => {
                log::debug!("eBPF IPv6 lookup failed: {}", e);
            }
        }

        let zero_src_key =
            ConnKey::new_v6(Ipv6Addr::UNSPECIFIED, dst_ip, src_port, dst_port, is_tcp);
        match MapReader::lookup_connection(socket_map, zero_src_key) {
            Ok(Some(result)) => Some(SocketMatch::new(result, MatchQuality::WildcardLocalAddress)),
            Ok(None) => {
                if let Err(e) = MapReader::debug_lookup_miss(socket_map, &key) {
                    log::debug!("Failed to debug lookup: {}", e);
                }
                None
            }
            Err(e) => {
                log::debug!("eBPF IPv6 zero-source lookup failed: {}", e);
                None
            }
        }
    }

    /// Look up process information for a connection (generic)
    pub fn lookup(
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
    pub fn lookup_icmp(
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
                self.lookup_icmp_v4(src, dst, icmp_id)
            }
            (IpAddr::V6(src), IpAddr::V6(dst))
                if self
                    .capabilities()
                    .contains(AttributionCapabilities::ICMP_V6_SEND) =>
            {
                self.lookup_icmp_v6(src, dst, icmp_id)
            }
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => None,
            _ => {
                log::warn!("Mixed IPv4/IPv6 addresses not supported in eBPF ICMP lookup");
                None
            }
        }
    }

    fn lookup_icmp_v4(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        icmp_id: u16,
    ) -> Option<SocketMatch> {
        let socket_map = self.loader.socket_map();

        // Try exact match first
        let key = ConnKey::new_icmp_v4(src_ip, dst_ip, icmp_id);
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => return Some(SocketMatch::new(result, MatchQuality::ExactTuple)),
            Ok(None) => {
                log::debug!("eBPF ICMP exact lookup miss, trying with zero source address");
            }
            Err(e) => {
                log::debug!("eBPF ICMP lookup failed: {}", e);
            }
        }

        // Try with zero source address (common for ICMP - socket not bound to specific IP)
        let zero_src_key = ConnKey::new_icmp_v4(Ipv4Addr::new(0, 0, 0, 0), dst_ip, icmp_id);

        match MapReader::lookup_connection(socket_map, zero_src_key) {
            Ok(Some(result)) => {
                log::debug!(
                    "eBPF ICMP lookup succeeded with zero source address! PID: {}, comm: {}",
                    result.pid,
                    result.comm
                );
                Some(SocketMatch::new(result, MatchQuality::WildcardLocalAddress))
            }
            Ok(None) => {
                log::debug!("eBPF ICMP lookup miss for ID: {}", icmp_id);
                None
            }
            Err(e) => {
                log::debug!("eBPF ICMP zero-source lookup failed: {}", e);
                None
            }
        }
    }

    fn lookup_icmp_v6(
        &mut self,
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        icmp_id: u16,
    ) -> Option<SocketMatch> {
        let socket_map = self.loader.socket_map();

        // Try exact match first
        let key = ConnKey::new_icmp_v6(src_ip, dst_ip, icmp_id);
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => return Some(SocketMatch::new(result, MatchQuality::ExactTuple)),
            Ok(None) => {
                log::debug!("eBPF ICMP exact lookup miss, trying with zero source address");
            }
            Err(e) => {
                log::debug!("eBPF ICMP lookup failed: {}", e);
            }
        }

        // Try with zero source address (common for ICMP - socket not bound to specific IP)
        let zero_src_key = ConnKey::new_icmp_v6(Ipv6Addr::UNSPECIFIED, dst_ip, icmp_id);

        match MapReader::lookup_connection(socket_map, zero_src_key) {
            Ok(Some(result)) => {
                log::debug!(
                    "eBPF ICMP lookup succeeded with zero source address! PID: {}, comm: {}",
                    result.pid,
                    result.comm
                );
                Some(SocketMatch::new(result, MatchQuality::WildcardLocalAddress))
            }
            Ok(None) => {
                log::debug!("eBPF ICMP lookup miss for ID: {}", icmp_id);
                None
            }
            Err(e) => {
                log::debug!("eBPF ICMP zero-source lookup failed: {}", e);
                None
            }
        }
    }

    /// Check if the tracker is healthy and operational
    pub fn is_healthy(&self) -> bool {
        // Simple health check - in a real implementation you might
        // check if programs are still attached, etc.
        true
    }

    /// Clean up stale entries from the eBPF map
    /// Returns the number of entries cleaned up
    pub fn cleanup_stale_entries(&mut self, stale_threshold_secs: u64) -> u32 {
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

    fn test_tcp_v4(tracker: &mut LibbpfSocketTracker) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
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
        if ids_are_comparable(&accept_info.info) {
            assert_eq!(accept_info.info.tid, current_tid());
        }
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

    fn test_tcp_v6(tracker: &mut LibbpfSocketTracker) {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
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
    }

    fn test_udp_v4(tracker: &mut LibbpfSocketTracker) {
        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let destination = receiver.local_addr().unwrap();

        let connected = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
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

        let unconnected = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        unconnected.send_to(b"sendto", destination).unwrap();
        let source = unconnected.local_addr().unwrap();
        assert_current_identity(&lookup_with_retry(
            tracker,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination.ip(),
            source.port(),
            destination.port(),
            false,
        ));
    }

    fn test_udp_v6(tracker: &mut LibbpfSocketTracker) {
        let receiver = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let destination = receiver.local_addr().unwrap();

        let connected = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
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

        let unconnected = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).unwrap();
        unconnected.send_to(b"sendto", destination).unwrap();
        let source = unconnected.local_addr().unwrap();
        assert_current_identity(&lookup_with_retry(
            tracker,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination.ip(),
            source.port(),
            destination.port(),
            false,
        ));
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

        test_tcp_v4(&mut tracker);
        test_tcp_v6(&mut tracker);
        test_udp_v4(&mut tracker);
        test_udp_v6(&mut tracker);
        test_worker_thread_tid(&mut tracker);
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
