use std::io;
use std::time::SystemTime;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsd;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "freebsd")]
use bsd::FreeBSDStatsProvider;
#[cfg(target_os = "macos")]
use bsd::MacOSStatsProvider;
#[cfg(target_os = "linux")]
use linux::LinuxStatsProvider;
#[cfg(target_os = "windows")]
use windows::WindowsStatsProvider;

/// Nominal receive and transmit capacity reported by the operating system.
/// Values are bits per second. Either direction may be unavailable for
/// interfaces such as loopback devices, tunnels, and virtual adapters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkCapacity {
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
}

impl LinkCapacity {
    pub const fn symmetric(bits_per_second: u64) -> Self {
        Self {
            rx_bps: Some(bits_per_second),
            tx_bps: Some(bits_per_second),
        }
    }
}

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interface_name: String,
    pub link_capacity: LinkCapacity,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub collisions: u64,
    pub timestamp: SystemTime,
}

impl InterfaceStats {
    /// Calculate rates from two snapshots
    pub fn calculate_rates(&self, previous: &InterfaceStats) -> InterfaceRates {
        let duration = self
            .timestamp
            .duration_since(previous.timestamp)
            .unwrap_or_default()
            .as_secs_f64();

        if duration == 0.0 {
            return InterfaceRates {
                link_capacity: self.link_capacity,
                ..InterfaceRates::default()
            };
        }

        InterfaceRates {
            rx_bytes_per_sec: ((self.rx_bytes.saturating_sub(previous.rx_bytes)) as f64 / duration)
                as u64,
            tx_bytes_per_sec: ((self.tx_bytes.saturating_sub(previous.tx_bytes)) as f64 / duration)
                as u64,
            link_capacity: self.link_capacity,
        }
    }

    /// Calculate traffic transferred between two cumulative snapshots.
    pub fn traffic_since(&self, previous: &InterfaceStats) -> InterfaceTrafficWindow {
        let sampled_for = self
            .timestamp
            .duration_since(previous.timestamp)
            .unwrap_or_default();

        if sampled_for.is_zero() {
            return InterfaceTrafficWindow::default();
        }

        InterfaceTrafficWindow {
            rx_bytes: self.rx_bytes.saturating_sub(previous.rx_bytes),
            tx_bytes: self.tx_bytes.saturating_sub(previous.tx_bytes),
        }
    }
}

/// Rate calculations for interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceRates {
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
    pub link_capacity: LinkCapacity,
}

/// Traffic transferred over a rolling interface-counter window.
#[derive(Debug, Clone, Default)]
pub struct InterfaceTrafficWindow {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Trait for platform-specific interface statistics providers
pub trait InterfaceStatsProvider: Send + Sync {
    /// Get statistics for all available interfaces
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error>;
}

/// Create the interface-stats provider for the current platform: sysfs on
/// Linux, `getifaddrs` on macOS/FreeBSD, the IP Helper API on Windows.
/// The composition point for front-ends, mirroring
/// `rustnet_host::create_process_lookup`.
#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "windows"
))]
pub fn create_stats_provider() -> Box<dyn InterfaceStatsProvider> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxStatsProvider)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacOSStatsProvider)
    }
    #[cfg(target_os = "freebsd")]
    {
        Box::new(FreeBSDStatsProvider)
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsStatsProvider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Snapshot with the given counters and timestamp, error fields zeroed.
    fn stats(
        rx_bytes: u64,
        tx_bytes: u64,
        rx_packets: u64,
        tx_packets: u64,
        timestamp: SystemTime,
    ) -> InterfaceStats {
        InterfaceStats {
            interface_name: "test".to_string(),
            link_capacity: LinkCapacity::default(),
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp,
        }
    }

    #[test]
    fn test_rate_calculation() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = stats(1000, 500, 10, 5, t1);
        let stats2 = stats(2000, 1000, 20, 10, t2);

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 1000);
        assert_eq!(rates.tx_bytes_per_sec, 500);
    }

    #[test]
    fn test_rate_calculation_zero_duration() {
        let t = SystemTime::now();

        let stats1 = stats(1000, 500, 10, 5, t);
        let stats2 = stats1.clone();

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_rate_calculation_with_counter_wrapping() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = stats(1000, 500, 10, 5, t1);

        // Simulate counter reset (should use saturating_sub to avoid panic):
        // counters lower than the previous snapshot's.
        let stats2 = stats(500, 250, 5, 2, t2);

        let rates = stats2.calculate_rates(&stats1);
        // Should result in 0 due to saturating_sub
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_traffic_since() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(60);
        let first = stats(1_000, 500, 0, 0, t1);
        let second = InterfaceStats {
            rx_bytes: 9_000,
            tx_bytes: 2_500,
            timestamp: t2,
            ..first.clone()
        };

        let window = second.traffic_since(&first);
        assert_eq!(window.rx_bytes, 8_000);
        assert_eq!(window.tx_bytes, 2_000);
    }
}
