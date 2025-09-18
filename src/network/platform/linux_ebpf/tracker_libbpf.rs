//! eBPF socket tracker implementation using libbpf-rs

use super::{
    ProcessInfo,
    loader::EbpfLoader,
    maps_libbpf::{ConnKey, MapReader},
};
use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct LibbpfSocketTracker {
    loader: EbpfLoader,
}

unsafe impl Send for LibbpfSocketTracker {}
unsafe impl Sync for LibbpfSocketTracker {}

impl LibbpfSocketTracker {
    /// Create a new eBPF socket tracker
    /// Returns None if eBPF cannot be loaded (insufficient privileges, etc.)
    pub fn new() -> Result<Option<Self>> {
        match EbpfLoader::try_load()? {
            Some(loader) => Ok(Some(Self { loader })),
            None => Ok(None),
        }
    }

    /// Look up process information for a connection (IPv4)
    pub fn lookup_v4(
        &mut self,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        is_tcp: bool,
    ) -> Option<ProcessInfo> {
        let socket_map = self.loader.socket_map();

        // Try exact match first
        let key = ConnKey::new_v4(src_ip, dst_ip, src_port, dst_port, is_tcp);
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => {
                return Some(result);
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
                log::info!(
                    "🎉 eBPF lookup succeeded with zero source address! PID: {}, comm: {}",
                    result.pid,
                    result.comm
                );
                // Let cleanup handle entry deletion based on age
                Some(result)
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
    ) -> Option<ProcessInfo> {
        let key = ConnKey::new_v6(src_ip, dst_ip, src_port, dst_port, is_tcp);

        let socket_map = self.loader.socket_map();
        match MapReader::lookup_connection(socket_map, key) {
            Ok(Some(result)) => {
                // Let cleanup handle entry deletion based on age
                Some(result)
            }
            Ok(None) => {
                // Debug map lookup miss to see what we're looking for
                if let Err(e) = MapReader::debug_lookup_miss(socket_map, &key) {
                    log::debug!("Failed to debug lookup: {}", e);
                }
                None
            }
            Err(e) => {
                log::debug!("eBPF IPv6 lookup failed: {}", e);
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
    ) -> Option<ProcessInfo> {
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
