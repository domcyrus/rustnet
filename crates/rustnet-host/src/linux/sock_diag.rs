//! Bounded, read-only Linux INET_DIAG dumps. No BPF or network-admin capability
//! is needed for these attributes. Attribution still uses fentry/fexit or procfs.

use crate::{HostSocket, HostSocketState, HostTcpState};
use rustnet_core::network::types::{
    KernelSocketStats, Protocol, SocketMemoryStats, SocketQueueKind, SocketQueues,
    SocketStatsSource, TcpSocketStats,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_CONG: u16 = 4;
const INET_DIAG_SKMEMINFO: u16 = 7;
const MAX_DUMP_BYTES: usize = 32 * 1024 * 1024;
const MAX_SOCKETS: usize = 100_000;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn request(family: u8, protocol: Protocol) -> [u8; 72] {
    let mut bytes = [0; 72];
    bytes[0..4].copy_from_slice(&72_u32.to_ne_bytes());
    bytes[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes[6..8].copy_from_slice(&0x301_u16.to_ne_bytes()); // REQUEST | DUMP
    bytes[8..12].copy_from_slice(&1_u32.to_ne_bytes());
    bytes[16] = family;
    bytes[17] = if protocol == Protocol::Tcp { 6 } else { 17 };
    bytes[18] = (1 << (INET_DIAG_INFO - 1))
        | (1 << (INET_DIAG_CONG - 1))
        | (1 << (INET_DIAG_SKMEMINFO - 1));
    bytes[20..24].fill(0xff); // All states
    bytes[64..72].fill(0xff); // INET_DIAG_NOCOOKIE
    bytes
}

fn scan_remaining(deadline: Instant, cancelled: &AtomicBool) -> io::Result<Duration> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "socket scan cancelled",
        ));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "socket scan timed out",
        ));
    }
    Ok(remaining)
}

pub(super) fn dump(
    family: u8,
    protocol: Protocol,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<Vec<HostSocket>> {
    scan_remaining(deadline, cancelled)?;
    // SAFETY: socket has no pointer arguments. OwnedFd closes the descriptor.
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly created, uniquely owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: a zeroed sockaddr_nl is valid before setting the family.
    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let request = request(family, protocol);
    // SAFETY: request and kernel are valid for the supplied lengths.
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&kernel) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != request.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short socket diagnostic request",
        ));
    }

    use std::os::unix::fs::MetadataExt;
    let namespace = std::fs::metadata("/proc/self/ns/net").ok().map(|m| m.ino());
    let sampled_at = SystemTime::now();
    let mut sockets = Vec::new();
    let mut buffer = vec![0; 64 * 1024];
    let mut received = 0;
    loop {
        let remaining = scan_remaining(deadline, cancelled)?;
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized poll descriptor.
        let ready =
            unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis().clamp(1, 50) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        let mut sender = kernel;
        let mut sender_len = std::mem::size_of_val(&sender) as libc::socklen_t;
        // SAFETY: buffer and sender are writable for their supplied lengths.
        let len = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                (&mut sender as *mut libc::sockaddr_nl).cast(),
                &mut sender_len,
            )
        };
        if len < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        let len = len as usize;
        received += len;
        if len == 0 || len > buffer.len() || received > MAX_DUMP_BYTES {
            return Err(invalid("truncated or oversized socket dump"));
        }
        if sender_len as usize != std::mem::size_of_val(&sender)
            || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || sender.nl_pid != 0
        {
            return Err(invalid("socket dump sender is not the kernel"));
        }
        if decode_messages(
            &buffer[..len],
            family,
            protocol,
            sampled_at,
            namespace,
            &mut sockets,
        )? {
            return Ok(sockets);
        }
    }
}

fn decode_messages(
    mut bytes: &[u8],
    family: u8,
    protocol: Protocol,
    sampled_at: SystemTime,
    namespace: Option<u64>,
    sockets: &mut Vec<HostSocket>,
) -> io::Result<bool> {
    while !bytes.is_empty() {
        let len = u32_at(bytes, 0).ok_or_else(|| invalid("short netlink header"))? as usize;
        if len < 16 || len > bytes.len() {
            return Err(invalid("invalid netlink length"));
        }
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        if u32_at(bytes, 8) != Some(1) || flags & 0x10 != 0 {
            return Err(invalid("mismatched or interrupted socket dump"));
        }
        let body = &bytes[16..len];
        match kind {
            2 => {
                let error = u32_at(body, 0).ok_or_else(|| invalid("short netlink error"))? as i32;
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                }
            }
            3 => {
                if !body.is_empty() {
                    let error = u32_at(body, 0).ok_or_else(|| invalid("short dump result"))? as i32;
                    if error != 0 {
                        return Err(io::Error::from_raw_os_error(error.saturating_neg()));
                    }
                }
                return Ok(true);
            }
            4 => return Err(invalid("socket dump overrun")),
            SOCK_DIAG_BY_FAMILY => {
                if sockets.len() >= MAX_SOCKETS {
                    return Err(invalid("socket dump record limit"));
                }
                sockets.push(decode_socket(
                    body, family, protocol, sampled_at, namespace,
                )?);
            }
            _ => return Err(invalid("unexpected socket dump message")),
        }
        let aligned = (len + 3) & !3;
        bytes = bytes
            .get(aligned..)
            .ok_or_else(|| invalid("short netlink padding"))?;
    }
    Ok(false)
}

fn tcp_state(state: u8) -> (HostTcpState, &'static str) {
    match state {
        1 => (HostTcpState::Established, "ESTABLISHED"),
        2 => (HostTcpState::SynSent, "SYN_SENT"),
        3 => (HostTcpState::SynReceived, "SYN_RECV"),
        4 => (HostTcpState::FinWait1, "FIN_WAIT1"),
        5 => (HostTcpState::FinWait2, "FIN_WAIT2"),
        6 => (HostTcpState::TimeWait, "TIME_WAIT"),
        7 => (HostTcpState::Closed, "CLOSED"),
        8 => (HostTcpState::CloseWait, "CLOSE_WAIT"),
        9 => (HostTcpState::LastAck, "LAST_ACK"),
        10 => (HostTcpState::Listen, "LISTEN"),
        11 => (HostTcpState::Closing, "CLOSING"),
        12 => (HostTcpState::SynReceived, "SYN_RECV"),
        _ => (HostTcpState::Unknown, "UNKNOWN"),
    }
}

fn decode_socket(
    bytes: &[u8],
    family: u8,
    protocol: Protocol,
    sampled_at: SystemTime,
    namespace: Option<u64>,
) -> io::Result<HostSocket> {
    if bytes.len() < 72 || bytes[0] != family {
        return Err(invalid("invalid inet_diag record"));
    }
    let address = |offset: usize, port_offset: usize| -> io::Result<SocketAddr> {
        let port = u16::from_be_bytes([bytes[port_offset], bytes[port_offset + 1]]);
        match i32::from(family) {
            libc::AF_INET => Ok(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    bytes[offset],
                    bytes[offset + 1],
                    bytes[offset + 2],
                    bytes[offset + 3],
                )),
                port,
            )),
            libc::AF_INET6 => {
                let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[offset..offset + 16]).unwrap());
                let scope = if ip.is_unicast_link_local() {
                    u32_at(bytes, 40).unwrap()
                } else {
                    0
                };
                Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope)))
            }
            _ => Err(invalid("unsupported socket family")),
        }
    };
    let local_addr = address(8, 4)?;
    let remote_addr = crate::remote_if_present(address(24, 6)?);
    let (state, state_name) = tcp_state(bytes[1]);
    let is_tcp = protocol == Protocol::Tcp;
    let kind = if !is_tcp {
        SocketQueueKind::MemoryBytes
    } else if state == HostTcpState::Listen {
        SocketQueueKind::Backlog
    } else {
        SocketQueueKind::Bytes
    };
    let cookie =
        Some(u64::from(u32_at(bytes, 44).unwrap()) | (u64::from(u32_at(bytes, 48).unwrap()) << 32));
    let cookie = cookie.filter(|c| *c != u64::MAX);
    let mut stats = KernelSocketStats {
        source: SocketStatsSource::LinuxSockDiag,
        sampled_at,
        socket_cookie: cookie,
        network_namespace: namespace,
        state: if is_tcp {
            state_name
        } else if remote_addr.is_some() {
            "CONNECTED"
        } else {
            "BOUND"
        },
        queues: SocketQueues {
            kind,
            receive: u32_at(bytes, 56).unwrap(),
            send: u32_at(bytes, 60).unwrap(),
        },
        tcp: None,
        memory: None,
    };
    let mut congestion = None;
    let mut attrs = &bytes[72..];
    while !attrs.is_empty() {
        if attrs.len() < 4 {
            return Err(invalid("short socket attribute"));
        }
        let len = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]) & 0x3fff;
        if len < 4 || len > attrs.len() {
            return Err(invalid("invalid socket attribute length"));
        }
        let data = &attrs[4..len];
        match kind {
            INET_DIAG_INFO if is_tcp && state != HostTcpState::Listen => {
                stats.tcp = Some(decode_tcp_info(data))
            }
            INET_DIAG_CONG if is_tcp => {
                let name = data.split(|b| *b == 0).next().unwrap_or_default();
                if name.len() <= 32 && name.iter().all(u8::is_ascii_graphic) {
                    congestion = std::str::from_utf8(name)
                        .ok()
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned);
                }
            }
            INET_DIAG_SKMEMINFO => {
                stats.memory = Some(SocketMemoryStats {
                    receive_allocated: u32_at(data, 0),
                    receive_limit: u32_at(data, 4),
                    send_allocated: u32_at(data, 8),
                    send_limit: u32_at(data, 12),
                    drops: u32_at(data, 32),
                })
            }
            _ => {}
        }
        attrs = attrs
            .get((len + 3) & !3..)
            .ok_or_else(|| invalid("short attribute padding"))?;
    }
    if let Some(tcp) = &mut stats.tcp {
        tcp.congestion_control = congestion;
    }
    Ok(HostSocket {
        protocol,
        local_addr,
        remote_addr,
        state: if is_tcp {
            HostSocketState::Tcp(state)
        } else {
            HostSocketState::UdpBound
        },
        owner: None,
        native_id: u32_at(bytes, 68).filter(|inode| *inode != 0).map(u64::from),
        kernel_stats: Some(Arc::new(stats)),
    })
}

fn decode_tcp_info(bytes: &[u8]) -> TcpSocketStats {
    // Offsets are from the append-only Linux UAPI struct tcp_info in
    // include/uapi/linux/tcp.h. Read only complete fields: kernel versions can
    // return different prefix lengths. Scalars are native-endian; socket
    // addresses and ports in inet_diag_sockid are network-endian instead.
    let duration = |offset| {
        u32_at(bytes, offset)
            .filter(|v| *v != 0 && *v != u32::MAX)
            .map(|v| Duration::from_micros(u64::from(v)))
    };
    TcpSocketStats {
        rtt: duration(68),
        rtt_variance: duration(68)
            .and_then(|_| u32_at(bytes, 72))
            .map(|v| Duration::from_micros(u64::from(v))),
        min_rtt: duration(148),
        retransmission_timeout: duration(8),
        congestion_window_segments: u32_at(bytes, 80),
        slow_start_threshold_segments: u32_at(bytes, 76),
        send_mss: u32_at(bytes, 16),
        total_retransmissions: u32_at(bytes, 100),
        bytes_acked: u64_at(bytes, 120),
        bytes_received: u64_at(bytes, 128),
        not_sent_bytes: u32_at(bytes, 144),
        bytes_sent: u64_at(bytes, 200),
        bytes_retransmitted: u64_at(bytes, 208),
        congestion_control: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn cancellation_and_deadline_are_checked_before_opening_a_socket() {
        assert_eq!(
            dump(
                2,
                Protocol::Tcp,
                Instant::now() + Duration::from_secs(1),
                &AtomicBool::new(true)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            dump(2, Protocol::Tcp, Instant::now(), &AtomicBool::new(false))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    fn record(family: u8, state: u8) -> Vec<u8> {
        let mut bytes = vec![0; 72];
        bytes[0] = family;
        bytes[1] = state;
        bytes[4..6].copy_from_slice(&1234_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&443_u16.to_be_bytes());
        bytes[8..12].copy_from_slice(&[127, 0, 0, 1]);
        bytes[24..28].copy_from_slice(&[192, 0, 2, 1]);
        bytes[44..48].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[48..52].copy_from_slice(&7_u32.to_ne_bytes());
        bytes[68..72].copy_from_slice(&42_u32.to_ne_bytes());
        bytes
    }

    fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let len = 4 + value.len();
        bytes.extend_from_slice(&(len as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((bytes.len() + 3) & !3, 0);
    }

    fn decode(bytes: &[u8], protocol: Protocol) -> io::Result<HostSocket> {
        decode_socket(bytes, bytes[0], protocol, SystemTime::now(), Some(9))
    }

    #[test]
    fn decodes_tcp_units_cookie_and_optional_tail_fields() {
        let mut bytes = record(libc::AF_INET as u8, 1);
        let mut info = vec![0; 104];
        info[68..72].copy_from_slice(&12_345_u32.to_ne_bytes());
        info[80..84].copy_from_slice(&17_u32.to_ne_bytes());
        info[100..104].copy_from_slice(&2_u32.to_ne_bytes());
        attribute(&mut bytes, INET_DIAG_CONG, b"cubic\0");
        attribute(&mut bytes, INET_DIAG_INFO, &info);
        attribute(&mut bytes, 1234, &[1, 2, 3]);
        let socket = decode(&bytes, Protocol::Tcp).unwrap();
        assert_eq!(socket.local_addr.to_string(), "127.0.0.1:1234");
        assert_eq!(socket.native_id, Some(42));
        let stats = socket.kernel_stats.unwrap();
        assert_eq!(stats.socket_cookie, Some((7 << 32) | 3));
        let tcp = stats.tcp.as_ref().unwrap();
        assert_eq!(tcp.rtt, Some(Duration::from_micros(12_345)));
        assert_eq!(tcp.congestion_window_segments, Some(17));
        assert_eq!(tcp.total_retransmissions, Some(2));
        assert_eq!(tcp.congestion_control.as_deref(), Some("cubic"));
        assert_eq!(tcp.bytes_sent, None);
        assert_eq!(tcp.min_rtt, None);
        assert_eq!(stats.queues.kind, SocketQueueKind::Bytes);
        for length in 0..104 {
            let truncated = decode_tcp_info(&info[..length]);
            assert_eq!(truncated.total_retransmissions, None);
        }
    }

    #[test]
    fn ipv6_scope_and_non_tcp_queue_semantics_are_preserved() {
        let mut bytes = record(libc::AF_INET6 as u8, 10);
        bytes[8..24].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
        bytes[24..40].fill(0);
        bytes[6..8].fill(0);
        bytes[40..44].copy_from_slice(&8_u32.to_ne_bytes());
        attribute(&mut bytes, INET_DIAG_INFO, &[0; 104]);
        let listener = decode(&bytes, Protocol::Tcp).unwrap();
        assert_eq!(listener.local_addr.to_string(), "[fe80::1%8]:1234");
        assert_eq!(listener.remote_addr, None);
        let stats = listener.kernel_stats.unwrap();
        assert_eq!(stats.queues.kind, SocketQueueKind::Backlog);
        assert!(stats.tcp.is_none());
        let mut memory = vec![0; 36];
        memory[32..36].copy_from_slice(&19_u32.to_ne_bytes());
        attribute(&mut bytes, INET_DIAG_SKMEMINFO, &memory);
        let udp = decode(&bytes, Protocol::Udp).unwrap().kernel_stats.unwrap();
        assert_eq!(udp.queues.kind, SocketQueueKind::MemoryBytes);
        assert_eq!(udp.memory.as_ref().unwrap().drops, Some(19));
        assert!(udp.tcp.is_none());
    }

    #[test]
    fn rejects_malformed_attributes_and_interrupted_dumps() {
        let bytes = record(libc::AF_INET as u8, 1);
        for len in 1..72 {
            assert!(decode(&bytes[..len], Protocol::Tcp).is_err());
        }
        for length in [0_u16, 3, 12] {
            let mut bad = bytes.clone();
            bad.extend_from_slice(&length.to_ne_bytes());
            bad.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
            assert!(decode(&bad, Protocol::Tcp).is_err());
        }
        let mut done = [0; 20];
        done[0..4].copy_from_slice(&20_u32.to_ne_bytes());
        done[4..6].copy_from_slice(&3_u16.to_ne_bytes());
        done[8..12].copy_from_slice(&1_u32.to_ne_bytes());
        let parse = |data: &[u8]| {
            decode_messages(
                data,
                2,
                Protocol::Tcp,
                SystemTime::now(),
                None,
                &mut Vec::new(),
            )
        };
        assert!(parse(&done).unwrap());
        done[6..8].copy_from_slice(&0x10_u16.to_ne_bytes());
        assert!(parse(&done).is_err());
        done[6..8].fill(0);
        done[16..20].copy_from_slice(&(-libc::ENOBUFS).to_ne_bytes());
        assert_eq!(
            parse(&done).unwrap_err().raw_os_error(),
            Some(libc::ENOBUFS)
        );
    }

    #[test]
    #[ignore = "requires Linux socket diagnostics and loopback IPv4/IPv6"]
    fn live_unprivileged_socket_diagnostics() {
        for (family, address) in [(libc::AF_INET, "127.0.0.1:0"), (libc::AF_INET6, "[::1]:0")] {
            let listener = TcpListener::bind(address).unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            client.write_all(&[42; 4096]).unwrap();
            let scan = |protocol| {
                dump(
                    family as u8,
                    protocol,
                    Instant::now() + Duration::from_secs(2),
                    &AtomicBool::new(false),
                )
                .unwrap()
            };
            let sockets = scan(Protocol::Tcp);
            let listener_row = sockets
                .iter()
                .find(|s| s.local_addr == listener.local_addr().unwrap() && s.remote_addr.is_none())
                .unwrap();
            assert_eq!(
                listener_row.kernel_stats.as_ref().unwrap().queues.kind,
                SocketQueueKind::Backlog
            );
            let server_row = sockets
                .iter()
                .find(|s| {
                    s.local_addr == server.local_addr().unwrap()
                        && s.remote_addr == Some(server.peer_addr().unwrap())
                })
                .unwrap();
            let stats = server_row.kernel_stats.as_ref().unwrap();
            assert_eq!(stats.queues.receive, 4096);
            assert!(stats.tcp.as_ref().unwrap().rtt.is_some());
            let udp = UdpSocket::bind(address).unwrap();
            let sender = UdpSocket::bind(address).unwrap();
            sender
                .send_to(&[42; 256], udp.local_addr().unwrap())
                .unwrap();
            let sockets = scan(Protocol::Udp);
            let row = sockets
                .iter()
                .find(|s| s.local_addr == udp.local_addr().unwrap())
                .unwrap();
            let stats = row.kernel_stats.as_ref().unwrap();
            assert_eq!(stats.queues.kind, SocketQueueKind::MemoryBytes);
            assert!(stats.queues.receive >= 256);
            assert!(stats.memory.as_ref().unwrap().drops.is_some());
        }
    }
}
