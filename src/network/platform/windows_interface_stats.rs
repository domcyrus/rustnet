use crate::network::interface_stats::{InterfaceStats, InterfaceStatsProvider};
use std::io;
use std::time::SystemTime;

#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2};

/// Windows-specific implementation using IP Helper API
pub struct WindowsStatsProvider;

impl InterfaceStatsProvider for WindowsStatsProvider {
    fn get_stats(&self, interface: &str) -> Result<InterfaceStats, io::Error> {
        let all_stats = self.get_all_stats()?;
        all_stats
            .into_iter()
            .find(|s| s.interface_name == interface || s.interface_name.contains(interface))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Interface {} not found", interface),
                )
            })
    }

    #[cfg(target_os = "windows")]
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        unsafe {
            let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

            let result = GetIfTable2(&mut table);
            if result.is_err() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("GetIfTable2 failed with error code: {:?}", result),
                ));
            }

            if table.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to get interface table",
                ));
            }

            let num_entries = (*table).NumEntries as usize;
            let mut stats = Vec::new();

            for i in 0..num_entries {
                let row = &(*table).Table[i];

                // Convert interface alias (friendly name) to string
                let name = String::from_utf16_lossy(&row.Alias)
                    .trim_end_matches('\0')
                    .to_string();

                if name.is_empty() {
                    continue;
                }

                stats.push(InterfaceStats {
                    interface_name: name,
                    rx_bytes: row.InOctets,
                    tx_bytes: row.OutOctets,
                    rx_packets: row.InUcastPkts + row.InNUcastPkts,
                    tx_packets: row.OutUcastPkts + row.OutNUcastPkts,
                    rx_errors: row.InErrors,
                    tx_errors: row.OutErrors,
                    rx_dropped: row.InDiscards,
                    tx_dropped: row.OutDiscards,
                    collisions: 0, // Not available on modern Windows interfaces
                    timestamp: SystemTime::now(),
                });
            }

            FreeMibTable(table.cast());
            Ok(stats)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Windows interface stats not available on this platform",
        ))
    }
}

#[cfg(test)]
#[cfg(target_os = "windows")]
mod tests {
    use super::*;

    #[test]
    fn test_windows_list_interfaces() {
        let provider = WindowsStatsProvider;
        let result = provider.list_interfaces();

        match result {
            Ok(interfaces) => {
                assert!(!interfaces.is_empty(), "Expected at least one interface");
            }
            Err(e) => {
                panic!("Failed to list interfaces: {:?}", e);
            }
        }
    }

    #[test]
    fn test_windows_get_all_stats() {
        let provider = WindowsStatsProvider;
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
