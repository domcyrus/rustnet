//! Default-gateway discovery from the operating system's routing table.
//!
//! Supplies the next-hop addresses of the host's default routes so the parser
//! can mark connections whose remote endpoint is the local router. Platform
//! sources: `/proc/net/route` and `/proc/net/ipv6_route` on Linux, a
//! `PF_ROUTE` sysctl dump on macOS/FreeBSD, and `GetIpForwardTable2` on
//! Windows. Failures degrade to an empty set, so the gateway marker simply
//! disappears rather than affecting capture.

use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows,
    test
))]
use std::net::{Ipv4Addr, Ipv6Addr};

/// Log a route-table read failure at warn level once and at debug level on
/// repeats, so a persistent failure is visible without repeating every
/// refresh interval.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
))]
fn log_failure(logged: &std::sync::atomic::AtomicBool, message: &str) {
    if logged.swap(true, std::sync::atomic::Ordering::Relaxed) {
        log::debug!("{message}");
    } else {
        log::warn!("{message}");
    }
}

/// `RTF_UP | RTF_GATEWAY` in the `/proc/net/route` flag encoding.
#[cfg(any(target_os = "linux", test))]
const PROC_RTF_UP_GATEWAY: u32 = 0x3;

#[cfg(target_os = "linux")]
pub(crate) fn default_gateways() -> HashSet<IpAddr> {
    static FAILURE_LOGGED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    let mut gateways = HashSet::new();
    match std::fs::read_to_string("/proc/net/route") {
        Ok(contents) => gateways.extend(parse_proc_route(&contents).map(IpAddr::V4)),
        Err(err) => log_failure(
            &FAILURE_LOGGED,
            &format!("reading /proc/net/route failed: {err}; gateway detection disabled"),
        ),
    }
    // Absent when IPv6 is disabled; not a failure worth warning about.
    if let Ok(contents) = std::fs::read_to_string("/proc/net/ipv6_route") {
        gateways.extend(parse_proc_ipv6_route(&contents).map(IpAddr::V6));
    }
    gateways
}

/// Gateways of default routes in `/proc/net/route` contents. Columns are
/// Iface, Destination, Gateway, Flags, RefCnt, Use, Metric, Mask, ...; the
/// address fields are little-endian hex.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_route(contents: &str) -> impl Iterator<Item = Ipv4Addr> + '_ {
    contents.lines().skip(1).filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (dest, gateway, flags, mask) = (
            fields.get(1)?,
            fields.get(2)?,
            fields.get(3)?,
            fields.get(7)?,
        );
        if *dest != "00000000" || *mask != "00000000" {
            return None;
        }
        let flags = u32::from_str_radix(flags, 16).ok()?;
        if flags & PROC_RTF_UP_GATEWAY != PROC_RTF_UP_GATEWAY {
            return None;
        }
        // Little-endian: "0100A8C0" is 192.168.0.1.
        let gateway = Ipv4Addr::from(u32::from_str_radix(gateway, 16).ok()?.to_le_bytes());
        (!gateway.is_unspecified()).then_some(gateway)
    })
}

/// Next hops of default routes in `/proc/net/ipv6_route` contents. Columns
/// are dest, dest prefix length, source, source prefix length, next hop,
/// metric, refcnt, use, flags, device; addresses are 32 big-endian hex chars.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_ipv6_route(contents: &str) -> impl Iterator<Item = Ipv6Addr> + '_ {
    contents.lines().filter_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (dest, dest_plen, next_hop, flags) = (
            fields.first()?,
            fields.get(1)?,
            fields.get(4)?,
            fields.get(8)?,
        );
        if *dest_plen != "00" || dest.bytes().any(|b| b != b'0') {
            return None;
        }
        let flags = u32::from_str_radix(flags, 16).ok()?;
        if flags & PROC_RTF_UP_GATEWAY != PROC_RTF_UP_GATEWAY {
            return None;
        }
        let next_hop = parse_hex_ipv6(next_hop)?;
        (!next_hop.is_unspecified()).then_some(next_hop)
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for (octet, pair) in octets.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *octet = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Ipv6Addr::from(octets))
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn default_gateways() -> HashSet<IpAddr> {
    static FAILURE_LOGGED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    match route_flags_dump() {
        Ok(buf) => parse_route_dump(&buf),
        Err(errno) => {
            log_failure(
                &FAILURE_LOGGED,
                &format!("PF_ROUTE sysctl dump failed (errno {errno}); gateway detection disabled"),
            );
            HashSet::new()
        }
    }
}

/// Dump every `RTF_GATEWAY` routing entry via sysctl. Retries with a fresh
/// size probe when the table grows between the probe and the read.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn route_flags_dump() -> Result<Vec<u8>, i32> {
    const MAX_ATTEMPTS: usize = 3;
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        0, // AF_UNSPEC: all address families
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];

    for _ in 0..MAX_ATTEMPTS {
        let mut len: libc::size_t = 0;
        let probe = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if probe != 0 {
            return Err(last_errno());
        }
        if len == 0 {
            return Ok(Vec::new());
        }

        // Slack for routes added between the probe and the read.
        len += len / 2;
        let mut buf = vec![0u8; len];
        let read = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if read == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let errno = last_errno();
        if errno != libc::ENOMEM {
            return Err(errno);
        }
    }
    Err(libc::ENOMEM)
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Route-message sockaddrs are padded to this alignment; a zero `sa_len`
/// still occupies one slot.
#[cfg(target_os = "macos")]
const SA_ALIGN: usize = 4;
#[cfg(target_os = "freebsd")]
const SA_ALIGN: usize = std::mem::size_of::<libc::c_long>();

#[cfg(target_os = "macos")]
type RtMsgHdr = libc::rt_msghdr;
#[cfg(target_os = "freebsd")]
type RtMsgHdr = FreebsdRtMsgHdr;

/// FreeBSD's `struct rt_msghdr` (net/route.h), which the libc crate does not
/// provide for FreeBSD. Underscore fields exist only to give the struct the
/// kernel's exact size and offsets.
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct FreebsdRtMsgHdr {
    rtm_msglen: u16,
    rtm_version: u8,
    _rtm_type: u8,
    _rtm_index: u16,
    _rtm_spare1: u16,
    rtm_flags: libc::c_int,
    rtm_addrs: libc::c_int,
    _rtm_pid: libc::pid_t,
    _rtm_seq: libc::c_int,
    _rtm_errno: libc::c_int,
    _rtm_fmask: libc::c_int,
    _rtm_inits: libc::c_ulong,
    /// `struct rt_metrics`: 14 `u_long` fields on every supported release.
    _rtm_rmx: [libc::c_ulong; 14],
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn sa_advance(sa_len: usize) -> usize {
    if sa_len == 0 {
        SA_ALIGN
    } else {
        sa_len.div_ceil(SA_ALIGN) * SA_ALIGN
    }
}

/// Next-hop addresses of default routes in a `NET_RT_FLAGS` sysctl dump.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn parse_route_dump(buf: &[u8]) -> HashSet<IpAddr> {
    let mut gateways = HashSet::new();
    let header_len = std::mem::size_of::<RtMsgHdr>();
    let mut offset = 0;
    while offset + header_len <= buf.len() {
        let header: RtMsgHdr = unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast()) };
        let msg_len = header.rtm_msglen as usize;
        if msg_len < header_len || offset + msg_len > buf.len() {
            // Malformed or truncated dump; stop rather than misparse.
            break;
        }
        let record = &buf[offset..offset + msg_len];
        offset += msg_len;

        if header.rtm_version != libc::RTM_VERSION as u8 {
            continue;
        }
        let required_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        if header.rtm_flags & required_flags != required_flags {
            continue;
        }
        let required_addrs = libc::RTA_DST | libc::RTA_GATEWAY;
        if header.rtm_addrs & required_addrs != required_addrs {
            continue;
        }

        // RTA_DST and RTA_GATEWAY are the two lowest bits, so their sockaddrs
        // are always the first two in the array following the header.
        let mut cursor = header_len;
        let Some((dst, dst_len)) = sockaddr_ip(&record[cursor..]) else {
            continue;
        };
        cursor += sa_advance(dst_len);
        if cursor >= record.len() {
            continue;
        }
        let Some((gateway, _)) = sockaddr_ip(&record[cursor..]) else {
            continue;
        };
        if dst.is_unspecified() && !gateway.is_unspecified() {
            gateways.insert(gateway);
        }
    }
    gateways
}

/// Decode a routing-message sockaddr into its IP address and `sa_len`.
/// The kernel truncates trailing zero bytes, so short sockaddrs are
/// zero-padded (a bare `AF_INET` header means 0.0.0.0). Returns `None` for
/// non-IP families such as `AF_LINK` interface routes.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn sockaddr_ip(sa: &[u8]) -> Option<(IpAddr, usize)> {
    let sa_len = *sa.first()? as usize;
    let family = *sa.get(1)?;
    let data = &sa[..sa_len.min(sa.len())];
    if family == libc::AF_INET as u8 {
        // sockaddr_in: len, family, port (2 bytes), address (4 bytes)
        let mut octets = [0u8; 4];
        copy_from(&mut octets, data, 4);
        Some((IpAddr::V4(Ipv4Addr::from(octets)), sa_len))
    } else if family == libc::AF_INET6 as u8 {
        // sockaddr_in6: len, family, port (2), flowinfo (4), address (16)
        let mut octets = [0u8; 16];
        copy_from(&mut octets, data, 8);
        // KAME kernels embed the scope id in bytes 2-3 of link-local
        // addresses; zero it so the address matches packet addresses.
        if octets[0] == 0xfe && octets[1] & 0xc0 == 0x80 {
            octets[2] = 0;
            octets[3] = 0;
        }
        Some((IpAddr::V6(Ipv6Addr::from(octets)), sa_len))
    } else {
        None
    }
}

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn copy_from(dest: &mut [u8], src: &[u8], start: usize) {
    for (index, byte) in dest.iter_mut().enumerate() {
        if let Some(value) = src.get(start + index) {
            *byte = *value;
        }
    }
}

#[cfg(windows)]
pub(crate) fn default_gateways() -> HashSet<IpAddr> {
    use windows::Win32::Foundation::NO_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_TABLE2,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};

    static FAILURE_LOGGED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    let mut gateways = HashSet::new();
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let result = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    if result != NO_ERROR {
        log_failure(
            &FAILURE_LOGGED,
            &format!(
                "GetIpForwardTable2 failed while collecting default gateways: {}",
                result.0
            ),
        );
        return gateways;
    }

    let rows = unsafe {
        let table = &*table;
        std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize)
    };
    for row in rows {
        if row.DestinationPrefix.PrefixLength != 0 {
            continue;
        }
        let family = unsafe { row.NextHop.si_family };
        if family == AF_INET {
            let bytes = unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_un_b };
            let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);
            // An unspecified next hop marks an on-link route, not a gateway.
            if !ip.is_unspecified() {
                gateways.insert(IpAddr::V4(ip));
            }
        } else if family == AF_INET6 {
            let ip = Ipv6Addr::from(unsafe { row.NextHop.Ipv6.sin6_addr.u.Byte });
            if !ip.is_unspecified() {
                gateways.insert(IpAddr::V6(ip));
            }
        }
    }
    unsafe { FreeMibTable(table.cast()) };
    gateways
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    windows
)))]
pub(crate) fn default_gateways() -> HashSet<IpAddr> {
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_route_default_gateway_is_decoded() {
        let contents = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(
            parse_proc_route(contents).collect::<Vec<_>>(),
            vec![Ipv4Addr::new(192, 168, 0, 1)]
        );
    }

    #[test]
    fn proc_route_skips_down_and_unspecified_gateways() {
        let contents = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0100A8C0\t0002\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t00000000\t00000000\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(parse_proc_route(contents).count(), 0);
    }

    #[test]
    fn proc_ipv6_route_default_next_hop_is_decoded() {
        let contents = "\
            00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n\
            20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n";
        assert_eq!(
            parse_proc_ipv6_route(contents).collect::<Vec<_>>(),
            vec!["fe80::1".parse::<Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn proc_ipv6_route_skips_gatewayless_default() {
        let contents = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 lo\n";
        assert_eq!(parse_proc_ipv6_route(contents).count(), 0);
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    mod route_dump {
        use super::super::*;

        fn record(flags: i32, addrs: i32, sockaddrs: &[Vec<u8>]) -> Vec<u8> {
            let mut body = Vec::new();
            for sa in sockaddrs {
                let mut padded = sa.clone();
                padded.resize(sa_advance(sa[0] as usize), 0);
                body.extend_from_slice(&padded);
            }

            let mut header: RtMsgHdr = unsafe { std::mem::zeroed() };
            header.rtm_msglen = (std::mem::size_of::<RtMsgHdr>() + body.len()) as u16;
            header.rtm_version = libc::RTM_VERSION as u8;
            header.rtm_flags = flags;
            header.rtm_addrs = addrs;

            let mut record = vec![0u8; std::mem::size_of::<RtMsgHdr>()];
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&header as *const RtMsgHdr).cast::<u8>(),
                    record.as_mut_ptr(),
                    record.len(),
                );
            }
            record.extend_from_slice(&body);
            record
        }

        fn sockaddr_v4(addr: Ipv4Addr) -> Vec<u8> {
            let mut sa = vec![0u8; 16];
            sa[0] = 16;
            sa[1] = libc::AF_INET as u8;
            sa[4..8].copy_from_slice(&addr.octets());
            sa
        }

        fn sockaddr_v6(addr: Ipv6Addr) -> Vec<u8> {
            let mut sa = vec![0u8; 28];
            sa[0] = 28;
            sa[1] = libc::AF_INET6 as u8;
            sa[8..24].copy_from_slice(&addr.octets());
            sa
        }

        const UP_GATEWAY: i32 = libc::RTF_UP | libc::RTF_GATEWAY;
        const DST_GATEWAY: i32 = libc::RTA_DST | libc::RTA_GATEWAY;

        #[test]
        fn v4_default_route_gateway_is_extracted() {
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[
                    sockaddr_v4(Ipv4Addr::UNSPECIFIED),
                    sockaddr_v4(Ipv4Addr::new(192, 168, 0, 1)),
                ],
            );
            assert_eq!(
                parse_route_dump(&buf),
                [IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))].into()
            );
        }

        #[test]
        fn truncated_dst_sockaddr_reads_as_default_route() {
            // The kernel truncates trailing zero bytes: a bare len+family
            // sockaddr is how the 0.0.0.0 destination usually arrives.
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[
                    vec![2, libc::AF_INET as u8],
                    sockaddr_v4(Ipv4Addr::new(10, 0, 0, 1)),
                ],
            );
            assert_eq!(
                parse_route_dump(&buf),
                [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))].into()
            );
        }

        #[test]
        fn non_default_destinations_are_skipped() {
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[
                    sockaddr_v4(Ipv4Addr::new(10, 0, 0, 0)),
                    sockaddr_v4(Ipv4Addr::new(192, 168, 0, 1)),
                ],
            );
            assert!(parse_route_dump(&buf).is_empty());
        }

        #[test]
        fn link_layer_gateways_are_skipped() {
            let mut link_sa = vec![0u8; 20];
            link_sa[0] = 20;
            link_sa[1] = libc::AF_LINK as u8;
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[sockaddr_v4(Ipv4Addr::UNSPECIFIED), link_sa],
            );
            assert!(parse_route_dump(&buf).is_empty());
        }

        #[test]
        fn down_routes_are_skipped() {
            let buf = record(
                libc::RTF_GATEWAY,
                DST_GATEWAY,
                &[
                    sockaddr_v4(Ipv4Addr::UNSPECIFIED),
                    sockaddr_v4(Ipv4Addr::new(192, 168, 0, 1)),
                ],
            );
            assert!(parse_route_dump(&buf).is_empty());
        }

        #[test]
        fn v6_link_local_gateway_scope_id_is_zeroed() {
            let mut scoped = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
            scoped[2] = 0x00;
            scoped[3] = 0x05;
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[
                    sockaddr_v6(Ipv6Addr::UNSPECIFIED),
                    sockaddr_v6(Ipv6Addr::from(scoped)),
                ],
            );
            assert_eq!(
                parse_route_dump(&buf),
                ["fe80::1".parse::<IpAddr>().unwrap()].into()
            );
        }

        #[test]
        fn truncated_buffer_does_not_panic() {
            let buf = record(
                UP_GATEWAY,
                DST_GATEWAY,
                &[
                    sockaddr_v4(Ipv4Addr::UNSPECIFIED),
                    sockaddr_v4(Ipv4Addr::new(192, 168, 0, 1)),
                ],
            );
            assert!(parse_route_dump(&buf[..buf.len() - 5]).is_empty());
        }

        #[test]
        fn live_dump_parses_without_panicking() {
            // Smoke test against the real routing table; asserts only that
            // collection succeeds, since CI hosts may have no default route.
            let _ = default_gateways();
        }
    }
}
