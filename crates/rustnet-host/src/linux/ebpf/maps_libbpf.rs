//! eBPF map interaction utilities for libbpf-rs

use super::ProcessInfo;
use anyhow::Result;
use libbpf_rs::MapCore;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Connection key matching the eBPF program structure (supports IPv4 and IPv6)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ConnKey {
    pub saddr: [u32; 4], // IPv4 uses only saddr[0], IPv6 uses all 4
    pub daddr: [u32; 4], // IPv4 uses only daddr[0], IPv6 uses all 4
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,  // IPPROTO_TCP or IPPROTO_UDP
    pub family: u8, // AF_INET or AF_INET6
}

/// Connection info matching the eBPF program structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    pub pid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub timestamp: u64,
}

// AF_INET / AF_INET6 (matches kernel `<linux/socket.h>` numeric values).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// IPPROTO_* values used by the eBPF socket map.
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

impl ConnKey {
    /// Build an empty key for an IPv4 connection. Address fields stay zeroed
    /// and are filled by [`Self::fill_v4`].
    fn empty_v4(sport: u16, dport: u16, proto: u8) -> Self {
        Self {
            saddr: [0; 4],
            daddr: [0; 4],
            sport,
            dport,
            proto,
            family: AF_INET,
        }
    }

    /// Build an empty key for an IPv6 connection. Address fields stay zeroed
    /// and are filled by [`Self::fill_v6`].
    fn empty_v6(sport: u16, dport: u16, proto: u8) -> Self {
        Self {
            saddr: [0; 4],
            daddr: [0; 4],
            sport,
            dport,
            proto,
            family: AF_INET6,
        }
    }

    fn fill_v4(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // Use little-endian to match kernel/eBPF native format.
        self.saddr[0] = u32::from_le_bytes(src_ip.octets());
        self.daddr[0] = u32::from_le_bytes(dst_ip.octets());
    }

    fn fill_v6(&mut self, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) {
        let src_bytes = src_ip.octets();
        let dst_bytes = dst_ip.octets();

        // Convert 16-byte IPv6 addresses to 4 u32 values (big-endian).
        for i in 0..4 {
            let start = i * 4;
            self.saddr[i] = u32::from_be_bytes([
                src_bytes[start],
                src_bytes[start + 1],
                src_bytes[start + 2],
                src_bytes[start + 3],
            ]);
            self.daddr[i] = u32::from_be_bytes([
                dst_bytes[start],
                dst_bytes[start + 1],
                dst_bytes[start + 2],
                dst_bytes[start + 3],
            ]);
        }
    }

    pub fn new_v4(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Self {
        let proto = if is_tcp { IPPROTO_TCP } else { IPPROTO_UDP };
        let mut key = Self::empty_v4(src_port, dst_port, proto);
        key.fill_v4(src_ip, dst_ip);
        key
    }

    pub(crate) fn new_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Self {
        let proto = if is_tcp { IPPROTO_TCP } else { IPPROTO_UDP };
        let mut key = Self::empty_v6(src_port, dst_port, proto);
        key.fill_v6(src_ip, dst_ip);
        key
    }

    /// Create an IPv4 ICMP lookup key. `icmp_id` acts as the "source port",
    /// `dport` is 0.
    pub fn new_icmp_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, icmp_id: u16) -> Self {
        let mut key = Self::empty_v4(icmp_id, 0, IPPROTO_ICMP);
        key.fill_v4(src_ip, dst_ip);
        key
    }

    /// Create an IPv6 ICMPv6 lookup key. `icmp_id` acts as the "source port",
    /// `dport` is 0.
    pub fn new_icmp_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, icmp_id: u16) -> Self {
        let mut key = Self::empty_v6(icmp_id, 0, IPPROTO_ICMPV6);
        key.fill_v6(src_ip, dst_ip);
        key
    }

    /// Convert to bytes for map lookup
    pub fn as_bytes(&self) -> [u8; 38] {
        // SAFETY: ConnKey is #[repr(C, packed)] with no padding (4×u32 + 4×u32 +
        // u16 + u16 + u8 + u8 = 38 bytes). All bit patterns are valid u8 values.
        unsafe { std::mem::transmute(*self) }
    }
}

impl From<ConnInfo> for ProcessInfo {
    fn from(info: ConnInfo) -> Self {
        // Convert C string to Rust String
        let comm_len = info.comm.iter().position(|&x| x == 0).unwrap_or(16);
        let comm = String::from_utf8_lossy(&info.comm[..comm_len]).to_string();

        Self {
            pid: info.pid,
            uid: info.uid,
            comm,
            timestamp: info.timestamp,
        }
    }
}

/// Read CLOCK_MONOTONIC in nanoseconds — the same clock bpf_ktime_get_ns()
/// uses to stamp map entries.
fn monotonic_time_ns() -> Result<u64> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, writable timespec for the duration of the call.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok((ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64)
}

pub struct MapReader;

impl MapReader {
    /// Query the socket map for connection information using libbpf-rs
    pub fn lookup_connection(map: &libbpf_rs::Map, key: ConnKey) -> Result<Option<ProcessInfo>> {
        let key_bytes = key.as_bytes();

        match map.lookup(&key_bytes, libbpf_rs::MapFlags::empty()) {
            Ok(Some(value_bytes)) => {
                if value_bytes.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Invalid map value size: expected 32, got {}",
                        value_bytes.len()
                    ));
                }

                let mut info_bytes = [0u8; 32];
                info_bytes.copy_from_slice(&value_bytes);
                // SAFETY: ConnInfo is #[repr(C, packed)] with size 32 bytes
                // (u32 + u32 + [u8; 16] + u64). All field types accept arbitrary
                // bit patterns, so any 32 bytes constitute a valid ConnInfo.
                let conn_info: ConnInfo = unsafe { std::mem::transmute(info_bytes) };
                Ok(Some(conn_info.into()))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                log::debug!("eBPF map lookup failed: {}", e);
                Ok(None)
            }
        }
    }

    /// Clean up stale entries from the map based on timestamp
    pub fn cleanup_stale_entries(map: &libbpf_rs::Map, stale_threshold_ns: u64) -> Result<u32> {
        // Entries are stamped by the BPF program with bpf_ktime_get_ns()
        // (CLOCK_MONOTONIC), so compare against the same clock, not wall time.
        let current_time_ns = monotonic_time_ns()?;

        let mut cleanup_count = 0u32;
        let mut keys_to_delete = Vec::new();

        // Try to iterate using MapKeyIter
        for key in map.keys() {
            // We have a key, check if its value is stale
            if let Ok(Some(value_bytes)) = map.lookup(&key, libbpf_rs::MapFlags::empty())
                && value_bytes.len() >= 32
            {
                // Extract timestamp from last 8 bytes
                let timestamp_bytes = &value_bytes[24..32];
                let timestamp = u64::from_ne_bytes([
                    timestamp_bytes[0],
                    timestamp_bytes[1],
                    timestamp_bytes[2],
                    timestamp_bytes[3],
                    timestamp_bytes[4],
                    timestamp_bytes[5],
                    timestamp_bytes[6],
                    timestamp_bytes[7],
                ]);

                if current_time_ns.saturating_sub(timestamp) > stale_threshold_ns {
                    // Entry is stale, mark for deletion
                    keys_to_delete.push(key);
                    log::debug!(
                        "Found stale entry, timestamp: {}, current: {}, threshold: {}",
                        timestamp,
                        current_time_ns,
                        stale_threshold_ns
                    );
                }
            }
        }

        // Delete all stale entries
        for key in keys_to_delete {
            if let Err(e) = map.delete(&key) {
                log::debug!("Failed to delete stale entry: {}", e);
            } else {
                cleanup_count += 1;
            }
        }

        if cleanup_count > 0 {
            log::info!("eBPF cleanup: removed {} stale entries", cleanup_count);
        }

        Ok(cleanup_count)
    }

    /// Log map lookup details for debugging
    pub fn debug_lookup_miss(map: &libbpf_rs::Map, lookup_key: &ConnKey) -> Result<()> {
        log::info!("=== eBPF Map Lookup Miss Debug ===");

        // Copy fields to avoid packed struct alignment issues
        let saddr = lookup_key.saddr[0];
        let daddr = lookup_key.daddr[0];
        let sport = lookup_key.sport;
        let dport = lookup_key.dport;
        let proto = lookup_key.proto;
        let family = lookup_key.family;

        log::info!(
            "Looking for key: saddr={:08x} ({}.{}.{}.{}), daddr={:08x} ({}.{}.{}.{}), sport={}, dport={}, proto={}, family={}",
            saddr,
            saddr & 0xff,
            (saddr >> 8) & 0xff,
            (saddr >> 16) & 0xff,
            (saddr >> 24) & 0xff,
            daddr,
            daddr & 0xff,
            (daddr >> 8) & 0xff,
            (daddr >> 16) & 0xff,
            (daddr >> 24) & 0xff,
            sport,
            dport,
            proto,
            family
        );

        log::info!("Key bytes: {:02x?}", lookup_key.as_bytes());

        // Get map info
        let info = map.info();
        match info {
            Ok(map_info) => {
                log::info!(
                    "Map type: {:?}, max_entries: {}, key_size: {}, value_size: {}",
                    map_info.map_type(),
                    map_info.info.max_entries,
                    map_info.info.key_size,
                    map_info.info.value_size
                );
            }
            Err(e) => {
                log::debug!("Failed to get map info: {}", e);
            }
        }

        log::info!("=== End Lookup Debug ===");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ConnKey is #[repr(C, packed)], so test asserts copy each field into
    // a local first — taking a reference to a packed field (including the
    // implicit one assert_eq! creates) is E0793 under Rust 2024.
    #[test]
    fn new_v4_writes_little_endian_addrs_and_tcp_proto() {
        let key = ConnKey::new_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 100),
            12345,
            443,
            true,
        );
        let saddr = key.saddr;
        let daddr = key.daddr;
        let sport = key.sport;
        let dport = key.dport;
        assert_eq!(key.family, AF_INET);
        assert_eq!(key.proto, IPPROTO_TCP);
        assert_eq!(sport, 12345);
        assert_eq!(dport, 443);
        // Octets reinterpreted as host-order u32 — matches what
        // u32::from_le_bytes(ip.octets()) produced previously.
        assert_eq!(
            saddr[0],
            u32::from_le_bytes(Ipv4Addr::new(10, 0, 0, 1).octets())
        );
        assert_eq!(
            daddr[0],
            u32::from_le_bytes(Ipv4Addr::new(192, 168, 1, 100).octets())
        );
        // Upper IPv6 slots stay zeroed for IPv4 keys.
        assert_eq!(&saddr[1..], &[0, 0, 0]);
        assert_eq!(&daddr[1..], &[0, 0, 0]);
    }

    #[test]
    fn new_v4_marks_udp_when_not_tcp() {
        let key = ConnKey::new_v4(
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            53000,
            53,
            false,
        );
        assert_eq!(key.proto, IPPROTO_UDP);
    }

    #[test]
    fn new_v6_writes_big_endian_addrs_across_all_four_slots() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let key = ConnKey::new_v6(src, dst, 1, 2, true);
        let saddr = key.saddr;
        let daddr = key.daddr;
        assert_eq!(key.family, AF_INET6);
        assert_eq!(key.proto, IPPROTO_TCP);

        let src_bytes = src.octets();
        let dst_bytes = dst.octets();
        for i in 0..4 {
            let start = i * 4;
            assert_eq!(
                saddr[i],
                u32::from_be_bytes([
                    src_bytes[start],
                    src_bytes[start + 1],
                    src_bytes[start + 2],
                    src_bytes[start + 3],
                ])
            );
            assert_eq!(
                daddr[i],
                u32::from_be_bytes([
                    dst_bytes[start],
                    dst_bytes[start + 1],
                    dst_bytes[start + 2],
                    dst_bytes[start + 3],
                ])
            );
        }
    }

    #[test]
    fn new_icmp_v4_uses_icmp_proto_and_zero_dport() {
        let key = ConnKey::new_icmp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            0x4242,
        );
        let sport = key.sport;
        let dport = key.dport;
        assert_eq!(key.proto, IPPROTO_ICMP);
        assert_eq!(key.family, AF_INET);
        assert_eq!(sport, 0x4242);
        assert_eq!(dport, 0);
    }

    #[test]
    fn new_icmp_v6_uses_icmpv6_proto_and_zero_dport() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let key = ConnKey::new_icmp_v6(src, dst, 0x0101);
        let sport = key.sport;
        let dport = key.dport;
        assert_eq!(key.proto, IPPROTO_ICMPV6);
        assert_eq!(key.family, AF_INET6);
        assert_eq!(sport, 0x0101);
        assert_eq!(dport, 0);
    }
}
