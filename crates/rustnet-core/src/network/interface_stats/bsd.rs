//! Shared `getifaddrs`-based interface stats for macOS and FreeBSD.
//!
//! Both platforms expose per-interface counters through the same
//! `getifaddrs` walk over `AF_LINK` entries; only the `libc::if_data`
//! struct layout differs (Apple's counters are `u32`, FreeBSD's are `u64`),
//! so each platform supplies its own extractor to the shared walker.

use super::{InterfaceStats, InterfaceStatsProvider, LinkCapacity};
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

#[cfg(target_os = "macos")]
const IFM_ETHER: i32 = 0x20;
#[cfg(target_os = "macos")]
const IFM_IEEE80211: i32 = 0x80;
#[cfg(target_os = "macos")]
const IFM_NMASK: i32 = 0xe0;
#[cfg(target_os = "macos")]
const IFM_TMASK_COMPAT: i32 = 0x1f;
#[cfg(target_os = "macos")]
const IFM_TMASK_EXT: i32 = 0x000f_0000;
#[cfg(target_os = "macos")]
const IFM_TMASK_EXT_SHIFT: u32 = 11;
#[cfg(target_os = "macos")]
const IFM_AVALID: i32 = 0x1;
#[cfg(target_os = "macos")]
const IFM_ACTIVE: i32 = 0x2;

/// Apple's public `ifmediareq` is packed to four-byte alignment, including
/// its pointer field. The libc crate exposes the ioctl constants but not this
/// userspace request structure on macOS.
#[cfg(target_os = "macos")]
#[repr(C, packed(4))]
struct MacIfMediaReq {
    ifm_name: [libc::c_char; libc::IFNAMSIZ],
    ifm_current: libc::c_int,
    ifm_mask: libc::c_int,
    ifm_status: libc::c_int,
    ifm_active: libc::c_int,
    ifm_count: libc::c_int,
    ifm_ulist: *mut libc::c_int,
}

#[cfg(target_os = "macos")]
fn media_subtype(media: i32) -> i32 {
    (media & IFM_TMASK_COMPAT) | ((media & IFM_TMASK_EXT) >> IFM_TMASK_EXT_SHIFT)
}

#[cfg(target_os = "macos")]
fn ethernet_media_speed_bps(subtype: i32) -> Option<u64> {
    let mbps = match subtype {
        3..=5 | 12 | 13 => 10,
        6..=10 | 52 | 62 => 100,
        11 | 14..=16 | 24 | 25 | 41 => 1_000,
        22 | 32 | 36 | 63 => 2_500,
        23 | 64 | 69 | 70 => 5_000,
        18..=21 | 26..=29 | 33..=35 | 42 | 59 => 10_000,
        30 => 20_000,
        40 | 53..=55 | 58 | 60 | 61 | 65..=68 | 71 | 86 => 25_000,
        37 | 38 | 43..=45 | 72..=74 => 40_000,
        39 | 56 | 57 | 75..=85 | 87 | 88 => 50_000,
        51 => 56_000,
        47..=50 | 89..=102 => 100_000,
        103..=105 => 200_000,
        _ => return None,
    };
    Some(mbps * 1_000_000)
}

#[cfg(target_os = "macos")]
fn wireless_media_speed_bps(subtype: i32) -> Option<u64> {
    let bits_per_second = match subtype {
        3 | 8 => 1_000_000,
        4 | 5 => 2_000_000,
        6 => 5_500_000,
        7 => 11_000_000,
        9 => 22_000_000,
        _ => return None,
    };
    Some(bits_per_second)
}

#[cfg(target_os = "macos")]
fn media_speed_bps(media: i32) -> Option<u64> {
    let subtype = media_subtype(media);
    match media & IFM_NMASK {
        IFM_ETHER => ethernet_media_speed_bps(subtype),
        IFM_IEEE80211 => wireless_media_speed_bps(subtype),
        _ => None,
    }
}

/// Return whether the link is active and the current media word. Extended
/// media is attempted first so links above 20 Gb/s are not collapsed to
/// `IFM_OTHER` by the compatibility ioctl.
#[cfg(target_os = "macos")]
fn query_media(interface: &str) -> Option<(bool, i32)> {
    let name = interface.as_bytes();
    if name.len() >= libc::IFNAMSIZ {
        return None;
    }

    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return None;
    }

    let mut request: MacIfMediaReq = unsafe { std::mem::zeroed() };
    for (target, source) in request.ifm_name.iter_mut().zip(name) {
        *target = *source as libc::c_char;
    }

    let extended = unsafe { libc::ioctl(socket, libc::SIOCGIFXMEDIA, &mut request) };
    let result = if extended == 0 {
        extended
    } else {
        unsafe { libc::ioctl(socket, libc::SIOCGIFMEDIA, &mut request) }
    };
    unsafe { libc::close(socket) };
    if result != 0 {
        return None;
    }

    let status = unsafe { std::ptr::addr_of!(request.ifm_status).read_unaligned() };
    let active_media = unsafe { std::ptr::addr_of!(request.ifm_active).read_unaligned() };
    let active = status & IFM_AVALID == 0 || status & IFM_ACTIVE != 0;
    Some((active, active_media))
}

#[cfg(target_os = "macos")]
fn macos_link_capacity(interface: &str, baudrate: u32) -> LinkCapacity {
    let media = match query_media(interface) {
        Some((false, _)) => return LinkCapacity::default(),
        Some((true, media)) => media_speed_bps(media),
        None => None,
    };
    let baudrate = (baudrate > 0 && baudrate != u32::MAX).then_some(u64::from(baudrate));
    media
        .or(baudrate)
        .map(LinkCapacity::symmetric)
        .unwrap_or_default()
}

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
                link_capacity: macos_link_capacity(&name, if_data.ifi_baudrate),
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
            link_capacity: (if_data.ifi_baudrate > 0)
                .then(|| LinkCapacity::symmetric(if_data.ifi_baudrate))
                .unwrap_or_default(),
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_media_request_matches_system_abi() {
        assert_eq!(std::mem::size_of::<MacIfMediaReq>(), 44);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn maps_common_macos_media_speeds() {
        assert_eq!(ethernet_media_speed_bps(3), Some(10_000_000));
        assert_eq!(ethernet_media_speed_bps(16), Some(1_000_000_000));
        assert_eq!(ethernet_media_speed_bps(22), Some(2_500_000_000));
        assert_eq!(ethernet_media_speed_bps(42), Some(10_000_000_000));
        assert_eq!(ethernet_media_speed_bps(97), Some(100_000_000_000));
        assert_eq!(ethernet_media_speed_bps(0), None);
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
