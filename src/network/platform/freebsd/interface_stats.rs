// network/platform/freebsd/interface_stats.rs - FreeBSD getifaddrs-based interface stats

use crate::network::interface_stats::{InterfaceStats, InterfaceStatsProvider};
use std::ffi::CStr;
use std::io;
use std::ptr;
use std::time::SystemTime;

/// FreeBSD-specific implementation using getifaddrs
pub struct FreeBSDStatsProvider;

impl InterfaceStatsProvider for FreeBSDStatsProvider {
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = ptr::null_mut();

            if libc::getifaddrs(&mut ifap) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut stats = Vec::new();
            let mut current = ifap;

            while let Some(ifa) = current.as_ref() {
                // Only process AF_LINK entries (data link layer)
                if let Some(addr) = ifa.ifa_addr.as_ref() {
                    if addr.sa_family as i32 == libc::AF_LINK {
                        let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().to_string();

                        // Get if_data from ifa_data
                        #[cfg(target_os = "freebsd")]
                        {
                            if let Some(if_data) = (ifa.ifa_data as *const libc::if_data).as_ref() {
                                stats.push(InterfaceStats {
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
                                    timestamp: SystemTime::now(),
                                });
                            }
                        }
                    }
                }

                current = ifa.ifa_next;
            }

            libc::freeifaddrs(ifap);
            Ok(stats)
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "freebsd")]
mod tests {
    use super::*;

    #[test]
    fn test_freebsd_list_interfaces() {
        let provider = FreeBSDStatsProvider;
        let result = provider.get_all_stats();

        match result {
            Ok(stats) => {
                assert!(!stats.is_empty(), "Expected at least one interface");
            }
            Err(e) => {
                panic!("Failed to list interfaces: {:?}", e);
            }
        }
    }

    #[test]
    fn test_freebsd_get_all_stats() {
        let provider = FreeBSDStatsProvider;
        let result = provider.get_all_stats();

        match result {
            Ok(stats) => {
                assert!(!stats.is_empty(), "Expected at least one interface");
                for stat in stats {
                    assert!(!stat.interface_name.is_empty());
                }
            }
            Err(e) => {
                panic!("Failed to get stats: {:?}", e);
            }
        }
    }
}
