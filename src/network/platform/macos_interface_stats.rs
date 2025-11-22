use crate::network::interface_stats::{InterfaceStats, InterfaceStatsProvider};
use std::ffi::CStr;
use std::io;
use std::ptr;
use std::time::SystemTime;

/// macOS-specific implementation using getifaddrs
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

impl InterfaceStatsProvider for MacOSStatsProvider {
    fn get_stats(&self, interface: &str) -> Result<InterfaceStats, io::Error> {
        let all_stats = self.get_all_stats()?;
        all_stats
            .into_iter()
            .find(|s| s.interface_name == interface)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Interface {} not found", interface),
                )
            })
    }

    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        unsafe {
            let mut ifap: *mut libc::ifaddrs = ptr::null_mut();

            if libc::getifaddrs(&mut ifap) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut stats = Vec::new();
            let mut current = ifap;

            while !current.is_null() {
                let ifa = &*current;

                // Only process AF_LINK entries (data link layer)
                if !ifa.ifa_addr.is_null()
                    && (*ifa.ifa_addr).sa_family as i32 == libc::AF_LINK
                {
                    let name = CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .to_string();

                    // Get if_data from ifa_data
                    if !ifa.ifa_data.is_null() {
                        #[cfg(target_os = "macos")]
                        {
                            let if_data = &*(ifa.ifa_data as *const libc::if_data);

                            // Calculate total packets for validation
                            let total_rx_packets = if_data.ifi_ipackets;
                            let total_tx_packets = if_data.ifi_opackets;

                            stats.push(InterfaceStats {
                                interface_name: name,
                                rx_bytes: if_data.ifi_ibytes as u64,
                                tx_bytes: if_data.ifi_obytes as u64,
                                rx_packets: total_rx_packets as u64,
                                tx_packets: total_tx_packets as u64,
                                // Sanitize error and drop counters (may contain garbage on virtual interfaces)
                                rx_errors: sanitize_counter(if_data.ifi_ierrors, total_rx_packets),
                                tx_errors: sanitize_counter(if_data.ifi_oerrors, total_tx_packets),
                                rx_dropped: sanitize_counter(if_data.ifi_iqdrops, total_rx_packets),
                                tx_dropped: 0, // Limited on macOS
                                collisions: sanitize_counter(if_data.ifi_collisions, total_rx_packets + total_tx_packets),
                                timestamp: SystemTime::now(),
                            });
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
#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    #[test]
    fn test_macos_list_interfaces() {
        let provider = MacOSStatsProvider;
        let result = provider.get_all_stats();

        match result {
            Ok(stats) => {
                assert!(!stats.is_empty(), "Expected at least one interface");
                let interface_names: Vec<String> = stats.iter().map(|s| s.interface_name.clone()).collect();
                // macOS should have at least loopback (lo0)
                assert!(
                    interface_names.iter().any(|i| i.starts_with("lo")),
                    "Expected loopback interface"
                );
            }
            Err(e) => {
                panic!("Failed to list interfaces: {:?}", e);
            }
        }
    }

    #[test]
    fn test_macos_get_all_stats() {
        let provider = MacOSStatsProvider;
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
