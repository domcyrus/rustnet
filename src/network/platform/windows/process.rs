// network/platform/windows/process.rs - Windows IP Helper API process lookup

use crate::network::platform::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStringExt;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

pub struct WindowsProcessLookup {
    cache: RwLock<ProcessCache>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, (u32, String)>,
    last_refresh: Instant,
}

impl WindowsProcessLookup {
    pub fn new() -> Result<Self> {
        // Use a very old timestamp that's guaranteed to be before now
        // by using checked_sub and falling back to epoch
        let now = Instant::now();
        let initial_refresh = now
            .checked_sub(Duration::from_secs(3600))
            .unwrap_or_else(|| now.checked_sub(Duration::from_secs(60)).unwrap_or(now));

        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: initial_refresh,
            }),
        })
    }

    fn refresh_tcp_processes(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        // IPv4 TCP connections
        self.refresh_tcp_table_v4(cache)?;
        // IPv6 TCP connections
        self.refresh_tcp_table_v6(cache)?;
        Ok(())
    }

    fn refresh_tcp_table_v4(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u8>;

            // First call to get buffer size
            let result = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if WIN32_ERROR(result) != ERROR_INSUFFICIENT_BUFFER {
                log::debug!(
                    "GetExtendedTcpTable (IPv4) returned no data or error: {}",
                    result
                );
                return Ok(()); // No connections or error
            }

            if size == 0 || size > 100_000_000 {
                // Sanity check: reject unreasonably large sizes (100MB limit)
                log::warn!("GetExtendedTcpTable (IPv4) returned invalid size: {}", size);
                return Ok(());
            }

            // Allocate buffer and get actual data
            table = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(table.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 {
                log::debug!("GetExtendedTcpTable (IPv4) second call failed: {}", result);
                return Ok(()); // Error getting table
            }

            // Verify we have enough data for the header
            if table.len() < std::mem::size_of::<u32>() {
                log::warn!("TCP table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let tcp_table = &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = tcp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            if table.len() < required_size {
                log::warn!(
                    "TCP table buffer too small: got {} bytes, need {} for {} entries",
                    table.len(),
                    required_size,
                    num_entries
                );
                return Ok(());
            }

            log::debug!("Processing {} TCP IPv4 connections", num_entries);

            // Get pointer to the first entry
            let rows_ptr = &tcp_table.table[0] as *const MIB_TCPROW_OWNER_PID;

            for i in 0..num_entries {
                let row = &*rows_ptr.add(i);

                let local_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    u16::from_be(row.dwLocalPort as u16),
                );

                let remote_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
                    u16::from_be(row.dwRemotePort as u16),
                );

                let key = ConnectionKey {
                    protocol: Protocol::TCP,
                    local_addr,
                    remote_addr,
                };

                if let Some(process_name) = get_process_name_from_pid(row.dwOwningPid) {
                    log::trace!(
                        "Cached: {:?} {} -> {} (PID: {}, {})",
                        key.protocol,
                        local_addr,
                        remote_addr,
                        row.dwOwningPid,
                        process_name
                    );
                    cache.insert(key, (row.dwOwningPid, process_name));
                }
            }
        }

        Ok(())
    }

    fn refresh_tcp_table_v6(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u8>;

            // First call to get buffer size
            let result = GetExtendedTcpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if WIN32_ERROR(result) != ERROR_INSUFFICIENT_BUFFER {
                log::debug!(
                    "GetExtendedTcpTable (IPv6) returned no data or error: {}",
                    result
                );
                return Ok(()); // No connections or error
            }

            if size == 0 || size > 100_000_000 {
                // Sanity check: reject unreasonably large sizes (100MB limit)
                log::warn!("GetExtendedTcpTable (IPv6) returned invalid size: {}", size);
                return Ok(());
            }

            // Allocate buffer and get actual data
            table = vec![0u8; size as usize];
            let result = GetExtendedTcpTable(
                Some(table.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );

            if result != 0 {
                log::debug!("GetExtendedTcpTable (IPv6) second call failed: {}", result);
                return Ok(()); // Error getting table
            }

            // Verify we have enough data for the header
            if table.len() < std::mem::size_of::<u32>() {
                log::warn!("TCP IPv6 table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let tcp_table = &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let num_entries = tcp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            if table.len() < required_size {
                log::warn!(
                    "TCP IPv6 table buffer too small: got {} bytes, need {} for {} entries",
                    table.len(),
                    required_size,
                    num_entries
                );
                return Ok(());
            }

            log::debug!("Processing {} TCP IPv6 connections", num_entries);

            // Get pointer to the first entry
            let rows_ptr = &tcp_table.table[0] as *const MIB_TCP6ROW_OWNER_PID;

            for i in 0..num_entries {
                let row = &*rows_ptr.add(i);

                let local_addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    u16::from_be(row.dwLocalPort as u16),
                );

                let remote_addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                    u16::from_be(row.dwRemotePort as u16),
                );

                let key = ConnectionKey {
                    protocol: Protocol::TCP,
                    local_addr,
                    remote_addr,
                };

                if let Some(process_name) = get_process_name_from_pid(row.dwOwningPid) {
                    log::trace!(
                        "Cached: {:?} {} -> {} (PID: {}, {})",
                        key.protocol,
                        local_addr,
                        remote_addr,
                        row.dwOwningPid,
                        process_name
                    );
                    cache.insert(key, (row.dwOwningPid, process_name));
                }
            }
        }

        Ok(())
    }

    fn refresh_udp_processes(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        // IPv4 UDP connections
        self.refresh_udp_table_v4(cache)?;
        // IPv6 UDP connections
        self.refresh_udp_table_v6(cache)?;
        Ok(())
    }

    fn refresh_udp_table_v4(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u8>;

            // First call to get buffer size
            let result = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if WIN32_ERROR(result) != ERROR_INSUFFICIENT_BUFFER {
                log::debug!(
                    "GetExtendedUdpTable (IPv4) returned no data or error: {}",
                    result
                );
                return Ok(()); // No connections or error
            }

            if size == 0 || size > 100_000_000 {
                // Sanity check: reject unreasonably large sizes (100MB limit)
                log::warn!("GetExtendedUdpTable (IPv4) returned invalid size: {}", size);
                return Ok(());
            }

            // Allocate buffer and get actual data
            table = vec![0u8; size as usize];
            let result = GetExtendedUdpTable(
                Some(table.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 {
                log::debug!("GetExtendedUdpTable (IPv4) second call failed: {}", result);
                return Ok(()); // Error getting table
            }

            // Verify we have enough data for the header
            if table.len() < std::mem::size_of::<u32>() {
                log::warn!("UDP table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let udp_table = &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let num_entries = udp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
            if table.len() < required_size {
                log::warn!(
                    "UDP table buffer too small: got {} bytes, need {} for {} entries",
                    table.len(),
                    required_size,
                    num_entries
                );
                return Ok(());
            }

            log::debug!("Processing {} UDP IPv4 connections", num_entries);

            // Get pointer to the first entry
            let rows_ptr = &udp_table.table[0] as *const MIB_UDPROW_OWNER_PID;

            for i in 0..num_entries {
                let row = &*rows_ptr.add(i);

                let local_addr = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                    u16::from_be(row.dwLocalPort as u16),
                );

                // UDP doesn't have remote address in the table
                let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);

                let key = ConnectionKey {
                    protocol: Protocol::UDP,
                    local_addr,
                    remote_addr,
                };

                if let Some(process_name) = get_process_name_from_pid(row.dwOwningPid) {
                    log::trace!(
                        "Cached: {:?} {} -> {} (PID: {}, {})",
                        key.protocol,
                        local_addr,
                        remote_addr,
                        row.dwOwningPid,
                        process_name
                    );
                    cache.insert(key, (row.dwOwningPid, process_name));
                }
            }
        }

        Ok(())
    }

    fn refresh_udp_table_v6(
        &self,
        _cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        // IPv6 UDP table structures are not available in current windows crate version
        // This will be implemented when the structures are available
        Ok(())
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);

        // Try cache first - handle poisoned lock gracefully
        {
            let cache = match self.cache.read() {
                Ok(cache) => cache,
                Err(poisoned) => {
                    log::warn!("Process cache lock was poisoned, recovering data");
                    poisoned.into_inner()
                }
            };

            if cache.last_refresh.elapsed() < Duration::from_secs(2)
                && let Some(process_info) = cache.lookup.get(&key)
            {
                log::trace!(
                    "✓ Cache hit: {:?} {} -> {} => {:?}",
                    key.protocol,
                    key.local_addr,
                    key.remote_addr,
                    process_info
                );
                return Some(process_info.clone());
            } else {
                log::trace!(
                    "✗ Cache miss: {:?} {} -> {} (cache: {} entries, age: {}s)",
                    key.protocol,
                    key.local_addr,
                    key.remote_addr,
                    cache.lookup.len(),
                    cache.last_refresh.elapsed().as_secs()
                );
            }
        }

        // Cache is stale or miss, refresh
        if self.refresh().is_ok() {
            let cache = match self.cache.read() {
                Ok(cache) => cache,
                Err(poisoned) => {
                    log::warn!("Process cache lock was poisoned after refresh, recovering data");
                    poisoned.into_inner()
                }
            };
            let result = cache.lookup.get(&key).cloned();
            if result.is_some() {
                log::trace!("✓ Found after refresh: {:?} => {:?}", key, result);
            } else {
                log::trace!(
                    "✗ Still no match after refresh for: {:?} {} -> {}",
                    key.protocol,
                    key.local_addr,
                    key.remote_addr
                );
            }
            result
        } else {
            None
        }
    }

    fn refresh(&self) -> Result<()> {
        let mut new_cache = HashMap::new();

        self.refresh_tcp_processes(&mut new_cache)?;
        self.refresh_udp_processes(&mut new_cache)?;

        let mut cache = match self.cache.write() {
            Ok(cache) => cache,
            Err(poisoned) => {
                log::warn!("Process cache write lock was poisoned, recovering and replacing cache");
                poisoned.into_inner()
            }
        };

        let total_entries = new_cache.len();
        cache.lookup = new_cache;
        cache.last_refresh = Instant::now();

        log::debug!(
            "Windows process lookup refresh complete: {} entries cached",
            total_entries
        );

        Ok(())
    }

    fn get_detection_method(&self) -> &str {
        "windows-iphlpapi"
    }
}

fn get_process_name_from_pid(pid: u32) -> Option<String> {
    unsafe {
        // Open process with query information access
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return None,
        };

        // Query process image name
        let mut size: u32 = 260; // MAX_PATH
        let mut buffer: Vec<u16> = vec![0; size as usize];

        let result = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        );

        let _ = CloseHandle(handle);

        if result.is_ok() && size > 0 {
            // Convert to OsString and then to String
            let os_string = OsString::from_wide(&buffer[..size as usize]);
            let path_str = os_string.to_string_lossy().to_string();

            // Extract just the filename
            if let Some(filename) = path_str.split('\\').next_back() {
                return Some(filename.to_string());
            }
        }

        None
    }
}
