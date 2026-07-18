use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Collect every address currently assigned to the host.
///
/// `pnet_datalink` supplies the portable implementation. Its Windows backend
/// still uses the IPv4-only `GetAdaptersInfo`, so Windows supplements it with
/// `GetAdaptersAddresses` to include all IPv4 and IPv6 unicast addresses.
pub(crate) fn collect_local_ips() -> HashSet<IpAddr> {
    let mut local_ips = HashSet::new();
    for interface in pnet_datalink::interfaces() {
        local_ips.extend(interface.ips.into_iter().map(|network| network.ip()));
    }

    #[cfg(windows)]
    match windows_unicast_addresses() {
        Ok(addresses) => local_ips.extend(addresses),
        Err(code) => {
            // Warn once so a persistent failure is visible at default log
            // levels without repeating every refresh interval.
            static FAILURE_LOGGED: std::sync::atomic::AtomicBool =
                std::sync::atomic::AtomicBool::new(false);
            let message = format!(
                "GetAdaptersAddresses failed while refreshing local addresses: {code}; \
                 IPv6 endpoint orientation may be degraded"
            );
            if FAILURE_LOGGED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                log::debug!("{message}");
            } else {
                log::warn!("{message}");
            }
        }
    }

    local_ips.insert(IpAddr::V4(Ipv4Addr::LOCALHOST));
    local_ips.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    local_ips
}

#[cfg(windows)]
fn windows_unicast_addresses() -> Result<Vec<IpAddr>, u32> {
    use std::mem::{size_of, size_of_val};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::AF_UNSPEC;

    const INITIAL_BUFFER_SIZE: usize = 15 * 1024;
    const MAX_ATTEMPTS: usize = 3;

    let flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut requested_size = INITIAL_BUFFER_SIZE;

    for _ in 0..MAX_ATTEMPTS {
        // `IP_ADAPTER_ADDRESSES_LH` contains 8-byte-aligned fields, so the
        // buffer must be 8-byte aligned even on 32-bit targets.
        let word_count = requested_size.div_ceil(size_of::<u64>());
        let mut buffer = vec![0u64; word_count];
        let mut buffer_size = size_of_val(buffer.as_slice()) as u32;
        let adapters = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

        let result = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC.0),
                flags,
                None,
                Some(adapters),
                &mut buffer_size,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW.0 {
            requested_size = buffer_size as usize;
            continue;
        }
        if result != NO_ERROR.0 {
            return Err(result);
        }

        let mut addresses = Vec::new();
        let mut adapter = adapters;
        while let Some(current_adapter) = unsafe { adapter.as_ref() } {
            let mut unicast = current_adapter.FirstUnicastAddress;
            while let Some(current_unicast) = unsafe { unicast.as_ref() } {
                if let Some(ip) = unsafe { socket_address_to_ip(&current_unicast.Address) } {
                    addresses.push(ip);
                }
                unicast = current_unicast.Next;
            }
            adapter = current_adapter.Next;
        }
        return Ok(addresses);
    }

    Err(ERROR_BUFFER_OVERFLOW.0)
}

#[cfg(windows)]
unsafe fn socket_address_to_ip(
    address: &windows::Win32::Networking::WinSock::SOCKET_ADDRESS,
) -> Option<IpAddr> {
    use std::mem::size_of;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    };

    if address.lpSockaddr.is_null() {
        return None;
    }

    let family = unsafe { (*address.lpSockaddr.cast::<SOCKADDR>()).sa_family };
    if family == AF_INET && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>() {
        let socket = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
        let bytes = unsafe { socket.sin_addr.S_un.S_un_b };
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
        )));
    }
    if family == AF_INET6 && address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>() {
        let socket = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
        let bytes = unsafe { socket.sin6_addr.u.Byte };
        return Some(IpAddr::V6(Ipv6Addr::from(bytes)));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_always_includes_loopback_addresses() {
        let addresses = collect_local_ips();
        assert!(addresses.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(addresses.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[cfg(windows)]
    #[test]
    fn combined_snapshot_contains_windows_native_addresses() {
        let native = windows_unicast_addresses().expect("GetAdaptersAddresses should succeed");
        let combined = collect_local_ips();

        for address in native {
            assert!(
                combined.contains(&address),
                "native Windows address {address} missing from combined snapshot"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn converts_windows_ipv6_socket_addresses_without_losing_bytes() {
        use std::mem::size_of;
        use windows::Win32::Networking::WinSock::{AF_INET6, SOCKADDR_IN6, SOCKET_ADDRESS};

        let expected = Ipv6Addr::new(0x2001, 0x0db8, 1, 2, 3, 4, 5, 6);
        let mut socket = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            ..Default::default()
        };
        socket.sin6_addr.u.Byte = expected.octets();
        let address = SOCKET_ADDRESS {
            lpSockaddr: (&mut socket as *mut SOCKADDR_IN6).cast(),
            iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
        };

        assert_eq!(
            unsafe { socket_address_to_ip(&address) },
            Some(IpAddr::V6(expected))
        );
    }
}
