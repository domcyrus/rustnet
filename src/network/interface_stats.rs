use std::io;
use std::time::SystemTime;

/// Statistics for a network interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub interface_name: String,
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
            return InterfaceRates::default();
        }

        InterfaceRates {
            rx_bytes_per_sec: ((self.rx_bytes.saturating_sub(previous.rx_bytes)) as f64 / duration)
                as u64,
            tx_bytes_per_sec: ((self.tx_bytes.saturating_sub(previous.tx_bytes)) as f64 / duration)
                as u64,
        }
    }
}

/// Rate calculations for interface statistics
#[derive(Debug, Clone, Default)]
pub struct InterfaceRates {
    pub rx_bytes_per_sec: u64,
    pub tx_bytes_per_sec: u64,
}

/// Trait for platform-specific interface statistics providers
pub trait InterfaceStatsProvider: Send + Sync {
    /// Get statistics for all available interfaces
    fn get_all_stats(&self) -> Result<Vec<InterfaceStats>, io::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rate_calculation() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = InterfaceStats {
            interface_name: "test".to_string(),
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_packets: 10,
            tx_packets: 5,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp: t1,
        };

        let stats2 = InterfaceStats {
            interface_name: "test".to_string(),
            rx_bytes: 2000,
            tx_bytes: 1000,
            rx_packets: 20,
            tx_packets: 10,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp: t2,
        };

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 1000);
        assert_eq!(rates.tx_bytes_per_sec, 500);
    }

    #[test]
    fn test_rate_calculation_zero_duration() {
        let t = SystemTime::now();

        let stats1 = InterfaceStats {
            interface_name: "test".to_string(),
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_packets: 10,
            tx_packets: 5,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp: t,
        };

        let stats2 = stats1.clone();

        let rates = stats2.calculate_rates(&stats1);
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }

    #[test]
    fn test_rate_calculation_with_counter_wrapping() {
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);

        let stats1 = InterfaceStats {
            interface_name: "test".to_string(),
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_packets: 10,
            tx_packets: 5,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp: t1,
        };

        // Simulate counter reset (should use saturating_sub to avoid panic)
        let stats2 = InterfaceStats {
            interface_name: "test".to_string(),
            rx_bytes: 500, // Less than previous
            tx_bytes: 250,
            rx_packets: 5,
            tx_packets: 2,
            rx_errors: 0,
            tx_errors: 0,
            rx_dropped: 0,
            tx_dropped: 0,
            collisions: 0,
            timestamp: t2,
        };

        let rates = stats2.calculate_rates(&stats1);
        // Should result in 0 due to saturating_sub
        assert_eq!(rates.rx_bytes_per_sec, 0);
        assert_eq!(rates.tx_bytes_per_sec, 0);
    }
}
