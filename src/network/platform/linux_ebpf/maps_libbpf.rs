//! eBPF map interaction utilities for libbpf-rs

#[cfg(feature = "ebpf")]
use super::ProcessInfo;
#[cfg(feature = "ebpf")]
use anyhow::Result;
#[cfg(feature = "ebpf")]
use libbpf_rs::MapCore;
#[cfg(feature = "ebpf")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

impl ConnKey {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, is_tcp: bool) -> Self {
        let mut key = Self {
            saddr: [0; 4],
            daddr: [0; 4],
            sport: src_port,
            dport: dst_port,
            proto: if is_tcp { 6 } else { 17 }, // IPPROTO_TCP or IPPROTO_UDP
            family: match src_ip {
                IpAddr::V4(_) => 2,  // AF_INET
                IpAddr::V6(_) => 10, // AF_INET6
            },
        };

        match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                // Use little-endian to match kernel/eBPF native format
                key.saddr[0] = u32::from_le_bytes(src.octets());
                key.daddr[0] = u32::from_le_bytes(dst.octets());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let src_bytes = src.octets();
                let dst_bytes = dst.octets();

                // Convert 16-byte IPv6 addresses to 4 u32 values (big-endian)
                for i in 0..4 {
                    let src_start = i * 4;
                    let dst_start = i * 4;
                    key.saddr[i] = u32::from_be_bytes([
                        src_bytes[src_start],
                        src_bytes[src_start + 1],
                        src_bytes[src_start + 2],
                        src_bytes[src_start + 3],
                    ]);
                    key.daddr[i] = u32::from_be_bytes([
                        dst_bytes[dst_start],
                        dst_bytes[dst_start + 1],
                        dst_bytes[dst_start + 2],
                        dst_bytes[dst_start + 3],
                    ]);
                }
            }
            _ => {
                // Mixed IPv4/IPv6 - shouldn't happen in practice
                panic!("Mixed IPv4/IPv6 addresses not supported");
            }
        }

        key
    }

    pub fn new_v4(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Self {
        Self::new(
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            src_port,
            dst_port,
            is_tcp,
        )
    }

    #[allow(dead_code)]
    pub fn new_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Self {
        Self::new(
            IpAddr::V6(src_ip),
            IpAddr::V6(dst_ip),
            src_port,
            dst_port,
            is_tcp,
        )
    }

    /// Convert to bytes for map lookup
    pub fn as_bytes(&self) -> [u8; 38] {
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

#[cfg(feature = "ebpf")]
pub struct MapReader;

#[cfg(feature = "ebpf")]
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
        use std::time::{SystemTime, UNIX_EPOCH};

        let current_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| anyhow::anyhow!("Time error: {}", e))?
            .as_nanos() as u64;

        let mut cleanup_count = 0u32;
        let mut keys_to_delete = Vec::new();

        // Try to iterate using MapKeyIter
        for key in map.keys() {
            // We have a key, check if its value is stale
            if let Ok(Some(value_bytes)) = map.lookup(&key, libbpf_rs::MapFlags::empty())
                && value_bytes.len() >= 32 {
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

#[cfg(not(feature = "ebpf"))]
#[derive(Debug, Clone, Copy)]
pub struct ConnKey;

#[cfg(not(feature = "ebpf"))]
pub struct MapReader;

#[cfg(not(feature = "ebpf"))]
impl MapReader {
    pub fn lookup_connection(
        _map: (),
        _key: ConnKey,
    ) -> anyhow::Result<Option<super::ProcessInfo>> {
        Ok(None)
    }
}
