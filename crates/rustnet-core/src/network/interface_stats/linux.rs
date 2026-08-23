// interface_stats/linux.rs - Linux sysfs-based interface stats

use super::{InterfaceStats, InterfaceStatsProvider, LinkCapacity};
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
            link_capacity: read_link_capacity(interface),
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

/// Read the latest negotiated speed exposed by ethtool-backed drivers.
/// Missing files and sentinel values are normal for loopback, tunnels, and
/// virtual interfaces, so capacity discovery must not fail stat collection.
fn read_link_capacity(interface: &str) -> LinkCapacity {
    let path = format!("/sys/class/net/{interface}/speed");
    fs::read_to_string(path)
        .ok()
        .and_then(|value| parse_speed_mbps(&value))
        .map(LinkCapacity::symmetric)
        .unwrap_or_default()
}

fn parse_speed_mbps(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|speed| *speed > 0)
        .and_then(|speed| speed.checked_mul(1_000_000))
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

    #[test]
    fn parses_optional_link_speed() {
        assert_eq!(parse_speed_mbps("1000\n"), Some(1_000_000_000));
        assert_eq!(parse_speed_mbps("-1\n"), None);
        assert_eq!(parse_speed_mbps("0"), None);
        assert_eq!(parse_speed_mbps("not available"), None);
        assert_eq!(parse_speed_mbps(&u64::MAX.to_string()), None);
    }
}
