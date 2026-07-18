// Windows ETW process attribution with an IP Helper API fallback.

use super::etw::{EtwAttribution, EtwProcessCache};
use crate::{ConnectionKey, DegradationReason, ProcessLookup};
use anyhow::Result;
use rustnet_core::network::types::{Connection, Protocol};
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStringExt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

const UNKNOWN_PROCESS_NAME: &str = "Unknown";

type ProcessMap = HashMap<ConnectionKey, (u32, String)>;
// None marks a PID whose process no longer exists, so repeated rows for it
// skip the OpenProcess retry within one refresh pass.
type ProcessNameCache = HashMap<u32, Option<String>>;

enum ProcessNameLookup {
    Named(String),
    // The process exists but denies PROCESS_QUERY_LIMITED_INFORMATION
    // (protected/system processes) — the kernel-provided owner PID is real.
    Denied,
    // OpenProcess says the PID is gone. IP Helper rows can outlive their
    // owner (TIME_WAIT, terminated UDP binders), and the PID may already
    // have been reused by an unrelated process.
    Gone,
}

fn allocate_table_buffer(size: u32) -> Vec<u32> {
    // IP Helper writes structs aligned to u32. Vec<u8> does not promise that
    // alignment, even though the Windows allocator commonly provides it.
    vec![0; (size as usize).div_ceil(std::mem::size_of::<u32>())]
}

fn table_buffer_len(table: &[u32]) -> usize {
    std::mem::size_of_val(table)
}

pub struct WindowsProcessLookup {
    cache: RwLock<ProcessCache>,
    etw_cache: Arc<EtwProcessCache>,
    _etw: Option<EtwAttribution>,
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

        let etw_cache = Arc::new(EtwProcessCache::default());
        let etw = match EtwAttribution::start(Arc::clone(&etw_cache)) {
            Ok(trace) => {
                log::info!("Windows ETW process attribution enabled");
                Some(trace)
            }
            Err(error) => {
                log::warn!(
                    "Windows ETW process attribution unavailable; using IP Helper polling: {}",
                    error
                );
                None
            }
        };

        Ok(Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: initial_refresh,
            }),
            etw_cache,
            _etw: etw,
        })
    }

    fn refresh_tcp_processes(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        // IPv4 TCP connections
        self.refresh_tcp_table_v4(cache, process_names)?;
        // IPv6 TCP connections
        self.refresh_tcp_table_v6(cache, process_names)?;
        Ok(())
    }

    fn refresh_tcp_table_v4(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u32>;

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
            table = allocate_table_buffer(size);
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
            if table_buffer_len(&table) < std::mem::size_of::<u32>() {
                log::warn!("TCP table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let tcp_table = &*(table.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
            let num_entries = tcp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
            if table_buffer_len(&table) < required_size {
                log::warn!(
                    "TCP table buffer too small: got {} bytes, need {} for {} entries",
                    table_buffer_len(&table),
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
                    protocol: Protocol::Tcp,
                    local_addr,
                    remote_addr,
                };

                cache_process(cache, process_names, key, row.dwOwningPid);
            }
        }

        Ok(())
    }

    fn refresh_tcp_table_v6(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u32>;

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
            table = allocate_table_buffer(size);
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
            if table_buffer_len(&table) < std::mem::size_of::<u32>() {
                log::warn!("TCP IPv6 table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let tcp_table = &*(table.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
            let num_entries = tcp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
            if table_buffer_len(&table) < required_size {
                log::warn!(
                    "TCP IPv6 table buffer too small: got {} bytes, need {} for {} entries",
                    table_buffer_len(&table),
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
                    protocol: Protocol::Tcp,
                    local_addr,
                    remote_addr,
                };

                cache_process(cache, process_names, key, row.dwOwningPid);
            }
        }

        Ok(())
    }

    fn refresh_udp_processes(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        // IPv4 UDP connections
        self.refresh_udp_table_v4(cache, process_names)?;
        // IPv6 UDP connections
        self.refresh_udp_table_v6(cache, process_names)?;
        Ok(())
    }

    fn refresh_udp_table_v4(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;
            let mut table: Vec<u32>;

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
            table = allocate_table_buffer(size);
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
            if table_buffer_len(&table) < std::mem::size_of::<u32>() {
                log::warn!("UDP table buffer too small for header");
                return Ok(());
            }

            // Parse the table
            let udp_table = &*(table.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
            let num_entries = udp_table.dwNumEntries as usize;

            // Bounds check: ensure we have enough space for all entries
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_UDPROW_OWNER_PID>();
            if table_buffer_len(&table) < required_size {
                log::warn!(
                    "UDP table buffer too small: got {} bytes, need {} for {} entries",
                    table_buffer_len(&table),
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
                    protocol: Protocol::Udp,
                    local_addr,
                    remote_addr,
                };

                cache_process(cache, process_names, key, row.dwOwningPid);
            }
        }

        Ok(())
    }

    fn refresh_udp_table_v6(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
    ) -> Result<()> {
        unsafe {
            let mut size: u32 = 0;

            let result = GetExtendedUdpTable(
                None,
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if WIN32_ERROR(result) != ERROR_INSUFFICIENT_BUFFER {
                log::debug!(
                    "GetExtendedUdpTable (IPv6) returned no data or error: {}",
                    result
                );
                return Ok(());
            }

            if size == 0 || size > 100_000_000 {
                log::warn!("GetExtendedUdpTable (IPv6) returned invalid size: {}", size);
                return Ok(());
            }

            let mut table = allocate_table_buffer(size);
            let result = GetExtendedUdpTable(
                Some(table.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET6.0 as u32,
                UDP_TABLE_OWNER_PID,
                0,
            );

            if result != 0 {
                log::debug!("GetExtendedUdpTable (IPv6) second call failed: {}", result);
                return Ok(());
            }

            if table_buffer_len(&table) < std::mem::size_of::<u32>() {
                log::warn!("UDP IPv6 table buffer too small for header");
                return Ok(());
            }

            let udp_table = &*(table.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID);
            let num_entries = udp_table.dwNumEntries as usize;
            let required_size = std::mem::size_of::<u32>()
                + num_entries * std::mem::size_of::<MIB_UDP6ROW_OWNER_PID>();
            if table_buffer_len(&table) < required_size {
                log::warn!(
                    "UDP IPv6 table buffer too small: got {} bytes, need {} for {} entries",
                    table_buffer_len(&table),
                    required_size,
                    num_entries
                );
                return Ok(());
            }

            log::debug!("Processing {} UDP IPv6 connections", num_entries);

            let rows_ptr = &udp_table.table[0] as *const MIB_UDP6ROW_OWNER_PID;
            for i in 0..num_entries {
                let row = &*rows_ptr.add(i);
                let local_addr = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                    u16::from_be(row.dwLocalPort as u16),
                );
                let remote_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
                let key = ConnectionKey {
                    protocol: Protocol::Udp,
                    local_addr,
                    remote_addr,
                };

                cache_process(cache, process_names, key, row.dwOwningPid);
            }
        }

        Ok(())
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);

        // A fresh IP Helper snapshot reflects the kernel's current socket
        // owner and takes precedence over the ETW tuple cache, whose entries
        // can be up to ENTRY_TTL old and outlive a port reuse. ETW wins when
        // the table has no row: processes that exited between refreshes.
        let mut table_is_fresh = false;
        {
            let cache = match self.cache.read() {
                Ok(cache) => cache,
                Err(poisoned) => {
                    log::warn!("Process cache lock was poisoned, recovering data");
                    poisoned.into_inner()
                }
            };

            if cache.last_refresh.elapsed() < Duration::from_secs(2) {
                table_is_fresh = true;
                if let Some(process_info) = cache.lookup.get(&key) {
                    log::trace!(
                        "✓ Cache hit: {:?} {} -> {} => {:?}",
                        key.protocol,
                        key.local_addr,
                        key.remote_addr,
                        process_info
                    );
                    return Some(process_info.clone());
                }
                // Exact match missed — try wildcard fallback before declaring a miss
                if let Some(result) = Self::fallback_lookup(&cache.lookup, &key) {
                    log::trace!("✓ Fallback hit (cache): {:?} => {:?}", key, result);
                    return Some(result);
                }
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

        if table_is_fresh {
            // The current table has no row for this tuple, so the socket is
            // already gone — exactly the case the ETW cache exists for.
            return self.etw_cache.lookup(&key);
        }

        // Serving an ETW hit here skips the refresh syscalls entirely, but
        // only a real name is worth that: for a placeholder the table may
        // still do better.
        let etw_process = self.etw_cache.lookup(&key);
        if let Some(process) = &etw_process
            && process.1 != UNKNOWN_PROCESS_NAME
        {
            return etw_process;
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
            let result = cache
                .lookup
                .get(&key)
                .cloned()
                .or_else(|| Self::fallback_lookup(&cache.lookup, &key));
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
            result.or(etw_process)
        } else {
            etw_process
        }
    }

    fn refresh(&self) -> Result<()> {
        let mut new_cache = HashMap::new();
        let mut process_names = HashMap::new();

        self.refresh_tcp_processes(&mut new_cache, &mut process_names)?;
        self.refresh_udp_processes(&mut new_cache, &mut process_names)?;

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
        if self._etw.is_some() {
            "windows-etw+iphlpapi"
        } else {
            "windows-iphlpapi"
        }
    }

    fn get_degradation_reason(&self) -> DegradationReason {
        if self._etw.is_some() {
            DegradationReason::None
        } else {
            DegradationReason::EtwUnavailable
        }
    }
}

fn cache_process(
    cache: &mut ProcessMap,
    process_names: &mut ProcessNameCache,
    key: ConnectionKey,
    pid: u32,
) {
    // PID 0 is used for TCP rows whose owner is no longer available (for
    // example TIME_WAIT), so treating it as a process would create false
    // attribution. The same applies when the owning process has already
    // exited. Access-denied is different: the process is alive, so preserve
    // the kernel-provided owner PID even without a name.
    if pid == 0 {
        return;
    }

    let resolved = process_names
        .entry(pid)
        .or_insert_with(|| match query_process_name(pid) {
            ProcessNameLookup::Named(name) => Some(name),
            ProcessNameLookup::Denied => Some(UNKNOWN_PROCESS_NAME.to_string()),
            ProcessNameLookup::Gone => None,
        });
    let Some(process_name) = resolved.clone() else {
        return;
    };

    log::trace!(
        "Cached: {:?} {} -> {} (PID: {}, {})",
        key.protocol,
        key.local_addr,
        key.remote_addr,
        pid,
        process_name
    );
    cache.insert(key, (pid, process_name));
}

pub(super) fn get_process_name_from_pid(pid: u32) -> Option<String> {
    match query_process_name(pid) {
        ProcessNameLookup::Named(name) => Some(name),
        ProcessNameLookup::Denied | ProcessNameLookup::Gone => None,
    }
}

fn query_process_name(pid: u32) -> ProcessNameLookup {
    unsafe {
        // Open process with query information access
        let handle = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(error) => {
                return if error.code() == ERROR_ACCESS_DENIED.to_hresult() {
                    ProcessNameLookup::Denied
                } else {
                    ProcessNameLookup::Gone
                };
            }
        };

        // Query process image name
        // QueryFullProcessImageNameW supports extended-length paths. A MAX_PATH
        // buffer silently loses attribution for executables installed below a
        // long path, so allocate the documented maximum Windows path instead.
        let mut size: u32 = 32_768;
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
                return ProcessNameLookup::Named(filename.to_string());
            }
        }

        // The open succeeded, so the process is alive; only the name query
        // failed.
        ProcessNameLookup::Denied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnet_core::network::types::ProtocolState;
    use std::net::UdpSocket;

    #[test]
    fn skips_rows_whose_owner_no_longer_exists() {
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            local_addr: "127.0.0.1:12345".parse().unwrap(),
            remote_addr: "0.0.0.0:0".parse().unwrap(),
        };
        let mut cache = ProcessMap::new();
        let mut process_names = ProcessNameCache::new();

        cache_process(&mut cache, &mut process_names, key.clone(), u32::MAX);

        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn preserves_pid_when_process_name_is_unavailable() {
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            local_addr: "127.0.0.1:12346".parse().unwrap(),
            remote_addr: "0.0.0.0:0".parse().unwrap(),
        };
        let mut cache = ProcessMap::new();
        let mut process_names = ProcessNameCache::new();

        // PID 4 is the System process: always alive, but its image name is
        // not queryable via QueryFullProcessImageNameW.
        cache_process(&mut cache, &mut process_names, key.clone(), 4);

        assert_eq!(
            cache.get(&key),
            Some(&(4, UNKNOWN_PROCESS_NAME.to_string()))
        );
    }

    #[test]
    fn attributes_ipv6_udp_socket_to_current_process() {
        let socket = UdpSocket::bind("[::1]:0").expect("bind IPv6 UDP socket");
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let conn = Connection::new(Protocol::Udp, local_addr, remote_addr, ProtocolState::Udp);
        let lookup = WindowsProcessLookup::new().unwrap();

        let process = lookup
            .get_process_for_connection(&conn)
            .expect("IPv6 UDP socket should have an owner");

        assert_eq!(process.0, std::process::id());
        assert_ne!(process.1, UNKNOWN_PROCESS_NAME);
    }
}
