//! Link layer (Layer 2) packet parsing
//!
//! This module handles data-link layer protocols and extracts network-layer packets:
//! - Ethernet (DLT_EN10MB)
//! - Linux Cooked Capture v1 and v2 (DLT_LINUX_SLL, DLT_LINUX_SLL2)
//! - Raw IP packets (DLT_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6)
//! - TUN/TAP interfaces
//! - PKTAP (macOS process metadata)

pub mod ethernet;
pub mod linux_sll;
#[cfg(target_os = "macos")]
pub mod pktap;
pub mod raw_ip;
pub mod tun_tap;

/// Data Link Type (DLT) constants
/// These match the values from libpcap
pub mod dlt {
    pub const EN10MB: i32 = 1; // Ethernet
    pub const RAW: i32 = 12; // Raw IP (no link layer)
    pub const NULL: i32 = 0; // BSD loopback (sometimes used by TUN)
    pub const LINUX_SLL: i32 = 113; // Linux "cooked" capture v1
    pub const PKTAP: i32 = 149; // Apple PKTAP (DLT_USER2)
    pub const PKTAP_STANDARD: i32 = 258; // Standard PKTAP
    pub const LINUX_SLL2: i32 = 276; // Linux "cooked" capture v2

    // Link type values for raw IP packets
    pub const LINKTYPE_RAW: i32 = 101; // Raw IPv4/IPv6
    pub const LINKTYPE_IPV4: i32 = 228; // Raw IPv4 only
    pub const LINKTYPE_IPV6: i32 = 229; // Raw IPv6 only
}

/// Link layer type enum for identifying interface types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayerType {
    Ethernet,
    RawIP,
    LinuxSLL,
    LinuxSLL2,
    Pktap,
    Tun,
    Tap,
    Unknown,
}

impl LinkLayerType {
    /// Determine link layer type from DLT value
    pub fn from_dlt(dlt: i32) -> Self {
        match dlt {
            dlt::EN10MB => LinkLayerType::Ethernet,
            dlt::RAW | dlt::NULL | dlt::LINKTYPE_RAW | dlt::LINKTYPE_IPV4 | dlt::LINKTYPE_IPV6 => {
                LinkLayerType::RawIP
            }
            dlt::LINUX_SLL => LinkLayerType::LinuxSLL,
            dlt::LINUX_SLL2 => LinkLayerType::LinuxSLL2,
            dlt::PKTAP | dlt::PKTAP_STANDARD => LinkLayerType::Pktap,
            _ => LinkLayerType::Unknown,
        }
    }

    /// Determine link layer type from both DLT value and interface name
    ///
    /// This is more accurate than `from_dlt()` alone because it can distinguish
    /// TUN/TAP interfaces from regular interfaces that use the same DLT codes.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let link_type = LinkLayerType::from_dlt_and_name(12, "tun0");
    /// assert!(matches!(link_type, LinkLayerType::Tun));
    ///
    /// let link_type = LinkLayerType::from_dlt_and_name(1, "tap0");
    /// assert!(matches!(link_type, LinkLayerType::Tap));
    /// ```
    pub fn from_dlt_and_name(dlt: i32, interface_name: &str) -> Self {
        // Check if this is a TUN/TAP interface by name
        if tun_tap::is_tun_interface(interface_name) {
            return LinkLayerType::Tun;
        }
        if tun_tap::is_tap_interface(interface_name) {
            return LinkLayerType::Tap;
        }

        // Otherwise, use DLT-based detection
        Self::from_dlt(dlt)
    }

    /// Check if this link type represents a TUN/TAP interface
    pub fn is_tunnel(&self) -> bool {
        matches!(self, LinkLayerType::Tun | LinkLayerType::Tap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linktype_from_dlt() {
        assert_eq!(
            LinkLayerType::from_dlt(dlt::EN10MB),
            LinkLayerType::Ethernet
        );
        assert_eq!(LinkLayerType::from_dlt(dlt::RAW), LinkLayerType::RawIP);
        assert_eq!(LinkLayerType::from_dlt(dlt::NULL), LinkLayerType::RawIP);
        assert_eq!(
            LinkLayerType::from_dlt(dlt::LINUX_SLL),
            LinkLayerType::LinuxSLL
        );
        assert_eq!(
            LinkLayerType::from_dlt(dlt::LINUX_SLL2),
            LinkLayerType::LinuxSLL2
        );
        assert_eq!(LinkLayerType::from_dlt(dlt::PKTAP), LinkLayerType::Pktap);
        assert_eq!(
            LinkLayerType::from_dlt(dlt::PKTAP_STANDARD),
            LinkLayerType::Pktap
        );
        assert_eq!(
            LinkLayerType::from_dlt(dlt::LINKTYPE_RAW),
            LinkLayerType::RawIP
        );
        assert_eq!(
            LinkLayerType::from_dlt(dlt::LINKTYPE_IPV4),
            LinkLayerType::RawIP
        );
        assert_eq!(
            LinkLayerType::from_dlt(dlt::LINKTYPE_IPV6),
            LinkLayerType::RawIP
        );
        assert_eq!(LinkLayerType::from_dlt(999), LinkLayerType::Unknown);
    }

    #[test]
    fn test_is_tunnel() {
        assert!(LinkLayerType::Tun.is_tunnel());
        assert!(LinkLayerType::Tap.is_tunnel());
        assert!(!LinkLayerType::Ethernet.is_tunnel());
        assert!(!LinkLayerType::RawIP.is_tunnel());
        assert!(!LinkLayerType::LinuxSLL.is_tunnel());
        assert!(!LinkLayerType::Pktap.is_tunnel());
    }

    #[test]
    fn test_from_dlt_and_name() {
        // Test TUN interface detection
        assert_eq!(
            LinkLayerType::from_dlt_and_name(dlt::RAW, "tun0"),
            LinkLayerType::Tun
        );
        assert_eq!(
            LinkLayerType::from_dlt_and_name(dlt::RAW, "utun0"),
            LinkLayerType::Tun
        );

        // Test TAP interface detection
        assert_eq!(
            LinkLayerType::from_dlt_and_name(dlt::EN10MB, "tap0"),
            LinkLayerType::Tap
        );

        // Test regular interface (not TUN/TAP)
        assert_eq!(
            LinkLayerType::from_dlt_and_name(dlt::EN10MB, "eth0"),
            LinkLayerType::Ethernet
        );
        assert_eq!(
            LinkLayerType::from_dlt_and_name(dlt::RAW, "wlan0"),
            LinkLayerType::RawIP
        );
    }
}
