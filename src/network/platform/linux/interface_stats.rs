// network/platform/linux/interface_stats.rs - Linux sysfs-based interface stats

use crate::network::interface_stats::{InterfaceStats, InterfaceStatsProvider};
use std::fs;
use std::io;
use std::time::SystemTime;

/// Linux-specific implementation using sysfs
pub struct LinuxStatsProvider;

impl LinuxStatsProvider {
    pub fn get_stats(&self, interface: &str) -> Result<InterfaceStats, io::Error> {
        let base_path = format!("/sys/class/net/{}/statistics", interface);

        // Check if interface exists
        if !std::path::Path::new(&base_path).exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Interface {} not found", interface),
            ));
        }

        Ok(InterfaceStats {
            interface_name: interface.to_string(),
            rx_bytes: read_stat(&base_path, "rx_bytes")?,
            tx_bytes: read_stat(&base_path, "tx_bytes")?,
            rx_packets: read_stat(&base_path, "rx_packets")?,
            tx_packets: read_stat(&base_path, "tx_packets")?,
            rx_errors: read_stat(&base_path, "rx_errors")?,
            tx_errors: read_stat(&base_path, "tx_errors")?,
            rx_dropped: read_stat(&base_path, "rx_dropped")?,
            tx_dropped: read_stat(&base_path, "tx_dropped")?,
            collisions: read_stat(&base_path, "collisions")?,
            timestamp: SystemTime::now(),
        })
    }
}

impl InterfaceStatsProvider for LinuxStatsProvider {
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error> {
        let mut stats = Vec::new();

        for entry in fs::read_dir("/sys/class/net")? {
            let entry = entry?;
            let interface = entry.file_name().to_string_lossy().to_string();

            // Skip if we can't read stats (some virtual interfaces may not have all stats)
            if let Ok(stat) = self.get_stats(&interface) {
                stats.push(stat);
            }
        }

        Ok(stats)
    }
}

/// Read a single statistic from sysfs
fn read_stat(base_path: &str, stat_name: &str) -> Result<u64, io::Error> {
    let path = format!("{}/{}", base_path, stat_name);
    let content = fs::read_to_string(&path)
        .map_err(|e| io::Error::new(e.kind(), format!("Failed to read {}: {}", path, e)))?;

    content
        .trim()
        .parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[test]
    fn test_linux_stats_loopback() {
        let provider = LinuxStatsProvider;
        let result = provider.get_stats("lo");

        match result {
            Ok(stats) => {
                assert_eq!(stats.interface_name, "lo");
                // Stats are u64, so they're always >= 0 by definition
                // Just verify the struct is properly populated
            }
            Err(e) => {
                // Acceptable errors: NotFound or PermissionDenied
                assert!(
                    e.kind() == io::ErrorKind::NotFound
                        || e.kind() == io::ErrorKind::PermissionDenied,
                    "Unexpected error: {:?}",
                    e
                );
            }
        }
    }

    #[test]
    fn test_list_interfaces() {
        let provider = LinuxStatsProvider;
        let result = provider.get_all_stats();

        match result {
            Ok(stats) => {
                // Should have at least loopback
                assert!(!stats.is_empty(), "Expected at least one interface (lo)");
                let interface_names: Vec<String> =
                    stats.iter().map(|s| s.interface_name.clone()).collect();
                assert!(
                    interface_names.iter().any(|name| name == "lo"),
                    "Expected loopback interface"
                );
            }
            Err(e) => {
                // PermissionDenied is acceptable
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
            }
        }
    }

    #[test]
    fn test_get_all_stats() {
        let provider = LinuxStatsProvider;
        let result = provider.get_all_stats();

        match result {
            Ok(stats) => {
                // Should have at least one interface
                assert!(!stats.is_empty(), "Expected at least one interface");

                // Check that all interfaces have valid names
                for stat in stats {
                    assert!(!stat.interface_name.is_empty());
                }
            }
            Err(e) => {
                // PermissionDenied is acceptable
                assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
            }
        }
    }

    #[test]
    fn test_nonexistent_interface() {
        let provider = LinuxStatsProvider;
        let result = provider.get_stats("nonexistent_interface_12345");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}
