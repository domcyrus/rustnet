//! eBPF map ABI and map interaction utilities.

use super::{ProcessInfo, TASK_COMM_LEN, decode_comm};
use anyhow::Result;
use libbpf_rs::MapCore;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) const CONN_KEY_SIZE: usize = 40;
pub(super) const CONN_INFO_SIZE: usize = 40;

/// Connection key matching `socket_tracker_types.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ConnKey {
    pub saddr: [u32; 4],
    pub daddr: [u32; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub family: u8,
    padding: [u8; 2],
}

/// Raw process identity matching `socket_tracker_types.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnInfo {
    pub tgid: u32,
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp: u64,
}

const _: () = assert!(std::mem::size_of::<ConnKey>() == CONN_KEY_SIZE);
const _: () = assert!(std::mem::align_of::<ConnKey>() == 4);
const _: () = assert!(std::mem::size_of::<ConnInfo>() == CONN_INFO_SIZE);
const _: () = assert!(std::mem::align_of::<ConnInfo>() == 8);

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

impl ConnKey {
    fn empty(sport: u16, dport: u16, proto: u8, family: u8) -> Self {
        Self {
            saddr: [0; 4],
            daddr: [0; 4],
            sport,
            dport,
            proto,
            family,
            padding: [0; 2],
        }
    }

    fn empty_v4(sport: u16, dport: u16, proto: u8) -> Self {
        Self::empty(sport, dport, proto, AF_INET)
    }

    fn empty_v6(sport: u16, dport: u16, proto: u8) -> Self {
        Self::empty(sport, dport, proto, AF_INET6)
    }

    fn fill_v4(&mut self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) {
        // The BPF program copies network-order address bytes into native u32
        // fields. from_ne_bytes produces the identical in-memory byte layout.
        self.saddr[0] = u32::from_ne_bytes(src_ip.octets());
        self.daddr[0] = u32::from_ne_bytes(dst_ip.octets());
    }

    fn fill_v6(&mut self, src_ip: Ipv6Addr, dst_ip: Ipv6Addr) {
        let src_bytes = src_ip.octets();
        let dst_bytes = dst_ip.octets();

        for index in 0..4 {
            let start = index * 4;
            self.saddr[index] = u32::from_ne_bytes(src_bytes[start..start + 4].try_into().unwrap());
            self.daddr[index] = u32::from_ne_bytes(dst_bytes[start..start + 4].try_into().unwrap());
        }
    }

    pub(super) fn new_v4(
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

    pub(super) fn new_v6(
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

    pub(super) fn new_icmp_v4(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, icmp_id: u16) -> Self {
        let mut key = Self::empty_v4(icmp_id, 0, IPPROTO_ICMP);
        key.fill_v4(src_ip, dst_ip);
        key
    }

    pub(super) fn new_icmp_v6(src_ip: Ipv6Addr, dst_ip: Ipv6Addr, icmp_id: u16) -> Self {
        let mut key = Self::empty_v6(icmp_id, 0, IPPROTO_ICMPV6);
        key.fill_v6(src_ip, dst_ip);
        key
    }

    /// Return the exact C ABI bytes used as the BPF map key.
    pub(super) fn as_bytes(&self) -> [u8; CONN_KEY_SIZE] {
        let mut bytes = [0; CONN_KEY_SIZE];
        // SAFETY: ConnKey has a compile-time checked size, contains explicit
        // initialized padding, and bytes accepts every bit pattern.
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(self).cast::<u8>(),
                bytes.as_mut_ptr(),
                CONN_KEY_SIZE,
            );
        }
        bytes
    }
}

impl ConnInfo {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CONN_INFO_SIZE {
            return Err(anyhow::anyhow!(
                "invalid socket_map value size: expected {CONN_INFO_SIZE}, got {}",
                bytes.len()
            ));
        }

        // SAFETY: The length is checked above. read_unaligned handles Vec<u8>
        // alignment, ConnInfo has a compile-time checked C layout, and every
        // field accepts arbitrary bit patterns.
        Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }
}

impl From<ConnInfo> for ProcessInfo {
    fn from(info: ConnInfo) -> Self {
        Self {
            pid: info.tgid,
            tid: info.tid,
            uid: info.uid,
            gid: info.gid,
            comm: decode_comm(&info.comm),
            timestamp: info.timestamp,
        }
    }
}

fn monotonic_time_ns() -> Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: timestamp is writable for the duration of clock_gettime.
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) };
    if result != 0 {
        return Err(anyhow::anyhow!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(timestamp.tv_sec as u64 * 1_000_000_000 + timestamp.tv_nsec as u64)
}

pub(super) struct MapReader;

impl MapReader {
    pub(super) fn lookup_connection(
        map: &libbpf_rs::Map,
        key: ConnKey,
    ) -> Result<Option<ProcessInfo>> {
        let key_bytes = key.as_bytes();

        match map.lookup(&key_bytes, libbpf_rs::MapFlags::empty()) {
            Ok(Some(value_bytes)) => {
                let info = ConnInfo::from_bytes(&value_bytes)?;
                Ok(Some(info.into()))
            }
            Ok(None) => Ok(None),
            Err(error) => {
                log::debug!("eBPF map lookup failed: {error}");
                Ok(None)
            }
        }
    }

    pub(super) fn cleanup_stale_entries(
        map: &libbpf_rs::Map,
        stale_threshold_ns: u64,
    ) -> Result<u32> {
        let current_time_ns = monotonic_time_ns()?;
        let mut keys_to_delete = Vec::new();

        // One unreadable entry must not abort the sweep: giving up here lets
        // socket_map grow to MAX_ENTRIES, after which the BPF programs can no
        // longer record new connections at all. Skip the entry instead.
        for key in map.keys() {
            let value_bytes = match map.lookup(&key, libbpf_rs::MapFlags::empty()) {
                Ok(Some(value_bytes)) => value_bytes,
                Ok(None) => continue,
                Err(error) => {
                    log::debug!("skipping socket_map entry during cleanup: {error}");
                    continue;
                }
            };
            match ConnInfo::from_bytes(&value_bytes) {
                Ok(info) if current_time_ns.saturating_sub(info.timestamp) > stale_threshold_ns => {
                    keys_to_delete.push(key);
                }
                Ok(_) => {}
                Err(error) => log::debug!("skipping unreadable socket_map value: {error}"),
            }
        }

        let mut cleanup_count = 0;
        for key in keys_to_delete {
            match map.delete(&key) {
                Ok(()) => cleanup_count += 1,
                Err(error) => log::debug!("failed to delete stale eBPF entry: {error}"),
            }
        }
        Ok(cleanup_count)
    }

    pub(super) fn debug_lookup_miss(map: &libbpf_rs::Map, lookup_key: &ConnKey) -> Result<()> {
        log::debug!(
            "eBPF map miss: key={:02x?}, source={:08x}, destination={:08x}, sport={}, dport={}, proto={}, family={}",
            lookup_key.as_bytes(),
            lookup_key.saddr[0],
            lookup_key.daddr[0],
            lookup_key.sport,
            lookup_key.dport,
            lookup_key.proto,
            lookup_key.family
        );

        match map.info() {
            Ok(map_info) => log::debug!(
                "eBPF map: type={:?}, max_entries={}, key_size={}, value_size={}",
                map_info.map_type(),
                map_info.info.max_entries,
                map_info.info.key_size,
                map_info.info.value_size
            ),
            Err(error) => log::debug!("failed to read eBPF map info: {error}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_abi_sizes_and_alignment_are_stable() {
        assert_eq!(std::mem::size_of::<ConnKey>(), CONN_KEY_SIZE);
        assert_eq!(std::mem::align_of::<ConnKey>(), 4);
        assert_eq!(std::mem::size_of::<ConnInfo>(), CONN_INFO_SIZE);
        assert_eq!(std::mem::align_of::<ConnInfo>(), 8);
    }

    // The uid/gid halves of bpf_get_current_uid_gid are split on the BPF side
    // in socket_tracker_helpers.h, so no Rust-side unit test can catch a swap
    // there. `socket_attribution_matrix` in tracker_libbpf.rs is what actually
    // compares the recorded identity against geteuid/getegid.

    #[test]
    fn conn_info_conversion_preserves_tgid_tid_uid_and_gid() {
        let mut comm = [0; TASK_COMM_LEN];
        comm[..7].copy_from_slice(b"rustnet");
        let raw = ConnInfo {
            tgid: 10,
            tid: 11,
            uid: 12,
            gid: 13,
            comm,
            timestamp: 14,
        };

        let converted = ProcessInfo::from(raw);
        assert_eq!(converted.pid, 10);
        assert_eq!(converted.tid, 11);
        assert_eq!(converted.uid, 12);
        assert_eq!(converted.gid, 13);
        assert_eq!(converted.comm, "rustnet");
        assert_eq!(converted.timestamp, 14);
    }

    #[test]
    fn ipv4_key_serializes_addresses_in_network_byte_order() {
        let source = Ipv4Addr::new(10, 0, 0, 1);
        let destination = Ipv4Addr::new(192, 168, 1, 100);
        let key = ConnKey::new_v4(source, destination, 12345, 443, true);
        let bytes = key.as_bytes();

        assert_eq!(&bytes[0..4], &source.octets());
        assert_eq!(&bytes[16..20], &destination.octets());
        assert_eq!(key.family, AF_INET);
        assert_eq!(key.proto, IPPROTO_TCP);
        assert_eq!(key.sport, 12345);
        assert_eq!(key.dport, 443);
    }

    #[test]
    fn ipv6_key_serializes_all_address_bytes_in_network_order() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let key = ConnKey::new_v6(source, destination, 1, 2, true);
        let bytes = key.as_bytes();

        assert_eq!(&bytes[0..16], &source.octets());
        assert_eq!(&bytes[16..32], &destination.octets());
        assert_eq!(key.family, AF_INET6);
        assert_eq!(key.proto, IPPROTO_TCP);
    }

    #[test]
    fn icmp_keys_use_identifier_as_source_port() {
        let v4 = ConnKey::new_icmp_v4(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(8, 8, 8, 8),
            0x4242,
        );
        let v6 = ConnKey::new_icmp_v6(Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST, 0x0101);

        assert_eq!(v4.proto, IPPROTO_ICMP);
        assert_eq!(v4.sport, 0x4242);
        assert_eq!(v4.dport, 0);
        assert_eq!(v6.proto, IPPROTO_ICMPV6);
        assert_eq!(v6.sport, 0x0101);
        assert_eq!(v6.dport, 0);
    }
}
