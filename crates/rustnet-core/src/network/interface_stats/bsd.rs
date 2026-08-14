//! Shared `getifaddrs`-based interface stats for macOS and FreeBSD.
//!
//! Both platforms expose per-interface counters through the same
//! `getifaddrs` walk over `AF_LINK` entries; only the `libc::if_data`
//! struct layout differs (Apple's counters are `u32`, FreeBSD's are `u64`),
//! so each platform supplies its own extractor to the shared walker.

use super::{InterfaceStats, InterfaceStatsProvider};
use std::ffi::CStr;
use std::io;
use std::ptr;
#[cfg(target_os = "macos")]
use std::time::SystemTime;

/// Walk the `getifaddrs` list and build stats from every `AF_LINK` entry.
fn collect_af_link_stats(
    extract: impl Fn(&libc::if_data, String) -> InterfaceStats,
) -> Result<Vec<InterfaceStats>, io::Error> {
    unsafe {
        let mut ifap: *mut libc::ifaddrs = ptr::null_mut();

        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut stats = Vec::new();
        let mut current = ifap;

        while let Some(ifa) = current.as_ref() {
            // Only process AF_LINK entries (data link layer)
            if let Some(addr) = ifa.ifa_addr.as_ref()
                && addr.sa_family as i32 == libc::AF_LINK
            {
                let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();

                // Get if_data from ifa_data
                if let Some(if_data) = (ifa.ifa_data as *const libc::if_data).as_ref() {
                    stats.push(extract(if_data, name));
                }
            }

            current = ifa.ifa_next;
        }

        libc::freeifaddrs(ifap);
        Ok(stats)
    }
}

/// macOS-specific implementation using getifaddrs
#[cfg(target_os = "macos")]
pub struct MacOSStatsProvider;

/// Sanitize counter values that may be uninitialized or invalid on virtual interfaces.
/// On macOS, some virtual interfaces (like vmenet0) report garbage values for certain
/// statistics fields, particularly ifi_iqdrops. We detect these by checking if:
/// 1. The value is suspiciously large (> 2^31, suggesting signed overflow or garbage)
/// 2. The value is larger than total packets (logically impossible for drops/errors)
#[cfg(target_os = "macos")]
fn sanitize_counter(value: u32, total_packets: u32) -> u64 {
    const MAX_REASONABLE_U32: u32 = 0x7FFF_FFFF; // 2^31 - 1

    // If the value is very large (> 2^31), it's likely garbage or overflow
    if value > MAX_REASONABLE_U32 {
        return 0;
    }

    // If drops/errors exceed total packets, the data is invalid
    if total_packets > 0 && value > total_packets {
        return 0;
    }

    value as u64
}

#[cfg(target_os = "macos")]
impl InterfaceStatsProvider for MacOSStatsProvider {
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        // Apple's if_data carries u32 counters; widen them and sanitize the
        // error/drop fields (may contain garbage on virtual interfaces).
        collect_af_link_stats(|if_data, name| {
            let total_rx_packets = if_data.ifi_ipackets;
            let total_tx_packets = if_data.ifi_opackets;

            InterfaceStats {
                interface_name: name,
                rx_bytes: if_data.ifi_ibytes as u64,
                tx_bytes: if_data.ifi_obytes as u64,
                rx_packets: total_rx_packets as u64,
                tx_packets: total_tx_packets as u64,
                rx_errors: sanitize_counter(if_data.ifi_ierrors, total_rx_packets),
                tx_errors: sanitize_counter(if_data.ifi_oerrors, total_tx_packets),
                rx_dropped: sanitize_counter(if_data.ifi_iqdrops, total_rx_packets),
                tx_dropped: 0, // Limited on macOS
                collisions: sanitize_counter(
                    if_data.ifi_collisions,
                    total_rx_packets + total_tx_packets,
                ),
                timestamp: SystemTime::now(),
            }
        })
    }
}

/// FreeBSD-specific implementation using getifaddrs
#[cfg(target_os = "freebsd")]
pub struct FreeBSDStatsProvider;

#[cfg(target_os = "freebsd")]
impl InterfaceStatsProvider for FreeBSDStatsProvider {
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        // FreeBSD's if_data counters are already u64.
        collect_af_link_stats(|if_data, name| InterfaceStats {
            interface_name: name,
            rx_bytes: if_data.ifi_ibytes,
            tx_bytes: if_data.ifi_obytes,
            rx_packets: if_data.ifi_ipackets,
            tx_packets: if_data.ifi_opackets,
            rx_errors: if_data.ifi_ierrors,
            tx_errors: if_data.ifi_oerrors,
            rx_dropped: if_data.ifi_iqdrops,
            tx_dropped: 0, // Not typically available on FreeBSD
            collisions: if_data.ifi_collisions,
            timestamp: std::time::SystemTime::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn test_macos_list_interfaces() {
        let provider = MacOSStatsProvider;
        let stats = provider.get_all_stats().expect("Failed to list interfaces");
        assert!(!stats.is_empty(), "Expected at least one interface");
        // macOS should have at least loopback (lo0)
        assert!(
            stats.iter().any(|s| s.interface_name.starts_with("lo")),
            "Expected loopback interface"
        );
        for stat in stats {
            assert!(!stat.interface_name.is_empty());
        }
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_freebsd_list_interfaces() {
        let provider = FreeBSDStatsProvider;
        let stats = provider.get_all_stats().expect("Failed to list interfaces");
        assert!(!stats.is_empty(), "Expected at least one interface");
        for stat in stats {
            assert!(!stat.interface_name.is_empty());
        }
    }
}
