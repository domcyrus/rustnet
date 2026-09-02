//! Parsers for the procfs text formats shared by the Linux socket scanner and
//! the application's Kubernetes socket table.
//!
//! The address decoding is pure string parsing and is compiled on every
//! target so it can be unit tested anywhere; only the `/proc/<pid>/comm`
//! readers are Linux-only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(target_os = "linux")]
use std::path::Path;

/// Decode one address column of `/proc/net/{tcp,tcp6,udp,udp6}` (also the
/// per-PID `/proc/<pid>/net/*` tables), e.g. `0100007F:1F90` or
/// `00000000000000000000000001000000:0050`.
///
/// The port is hex. IPv4 is 8 hex chars: the kernel prints the `__be32`
/// with `%08X`, so on a little-endian host the byte order is reversed
/// relative to the network-order address and is recovered via
/// `to_le_bytes`. IPv6 is 32 hex chars representing four `u32`s, each
/// printed in host byte order the same way. IPv4-mapped IPv6 addresses are
/// returned as-is; callers that need them folded to IPv4 do so themselves.
pub fn parse_proc_net_addr(field: &str) -> Option<SocketAddr> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let ip = match ip_hex.len() {
        8 => IpAddr::V4(parse_ipv4_hex(ip_hex)?),
        32 => IpAddr::V6(parse_ipv6_hex(ip_hex)?),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn parse_ipv4_hex(s: &str) -> Option<Ipv4Addr> {
    if s.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(s, 16).ok()?;
    Some(Ipv4Addr::from(val.to_le_bytes()))
}

fn parse_ipv6_hex(s: &str) -> Option<Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &s[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

/// Read a process's short name from `/proc/<pid>/comm`.
///
/// See [`read_comm_in`] for when this yields `None`.
#[cfg(target_os = "linux")]
pub fn read_comm(pid: u32) -> Option<String> {
    read_comm_in(Path::new(&format!("/proc/{pid}")))
}

/// Read a process's name from `<proc_dir>/comm`, given the process directory.
///
/// Returns `None` when comm is unreadable or empty, which happens when the
/// process exits mid-scan. Callers skip such a process rather than storing a
/// placeholder name: the fd scan has nothing left to read either, and a
/// placeholder would surface as its own process group in the UI and outrank
/// the eBPF-captured comm via the PID name cache.
#[cfg(target_os = "linux")]
pub fn read_comm_in(proc_dir: &Path) -> Option<String> {
    let comm = std::fs::read_to_string(proc_dir.join("comm")).ok()?;
    let name = comm.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_hex_is_little_endian() {
        // 0100007F => 127.0.0.1 (kernel printed the be32 with %08X on LE host)
        assert_eq!(
            parse_ipv4_hex("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        // 0F02000A => 10.0.2.15
        assert_eq!(
            parse_ipv4_hex("0F02000A"),
            Some(Ipv4Addr::new(10, 0, 2, 15))
        );
        // 00000000 => 0.0.0.0 (listening wildcard)
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        // wrong length
        assert_eq!(parse_ipv4_hex("0100"), None);
    }

    #[test]
    fn ipv6_hex_chunked_little_endian() {
        // ::1 loopback
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000001000000"),
            Some(Ipv6Addr::LOCALHOST)
        );
        // all zeros => ::
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000000000000"),
            Some(Ipv6Addr::UNSPECIFIED)
        );
        // wrong length
        assert_eq!(parse_ipv6_hex("00"), None);
    }

    #[test]
    fn address_column_selects_family_by_length() {
        assert_eq!(
            parse_proc_net_addr("0100007F:01BB"),
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                443
            ))
        );
        assert_eq!(
            parse_proc_net_addr("00000000000000000000000001000000:1F90"),
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0x1F90))
        );
        // IPv4-mapped addresses stay IPv6 here; folding is the caller's call.
        assert_eq!(
            parse_proc_net_addr("0000000000000000FFFF00000F02000A:0050"),
            Some(SocketAddr::new(
                IpAddr::V6(Ipv4Addr::new(10, 0, 2, 15).to_ipv6_mapped()),
                80
            ))
        );
    }

    #[test]
    fn rejects_malformed_address_columns() {
        assert_eq!(parse_proc_net_addr("nocolon"), None);
        assert_eq!(parse_proc_net_addr("0100:0050"), None);
        assert_eq!(parse_proc_net_addr("0100007F:zz"), None);
        assert_eq!(parse_proc_net_addr("0100007G:0050"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_name_comes_from_comm() {
        let name = read_comm_in(Path::new("/proc/self")).expect("own comm is readable");
        assert!(!name.is_empty());
        assert_eq!(name, name.trim());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_process_name_when_comm_is_unreadable() {
        // A PID that cannot exist: the process directory is gone, as it is
        // for a process that exits between the /proc listing and the read.
        assert_eq!(read_comm_in(Path::new("/proc/0")), None);
        assert_eq!(read_comm(0), None);
    }
}
