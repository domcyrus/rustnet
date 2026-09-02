// Windows ETW process attribution with an IP Helper API fallback.

use super::etw::{EtwAttribution, EtwProcessCache};
use super::{read_recovering, write_recovering};
use crate::{
    ConnectionKey, DegradationReason, HostSocket, HostSocketState, HostTcpState, MatchQuality,
    ProcessAncestor, ProcessAttribution, ProcessLineage, ProcessLookup, SocketOwner,
    SocketSnapshot, collect_process_lineage, relaxed_lookup, remote_if_present,
};
use anyhow::{Context, Result};
use rustnet_core::network::types::{Connection, Protocol, UNKNOWN_PROCESS_NAME};
use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

const CACHE_LOCK: &str = "Process cache";

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

pub(super) struct WindowsProcessLookup {
    cache: RwLock<ProcessCache>,
    process_details: RwLock<HashMap<u32, WindowsProcessDetails>>,
    socket_snapshot: RwLock<SocketSnapshot>,
    etw_cache: Arc<EtwProcessCache>,
    _etw: Option<EtwAttribution>,
}

struct ProcessCache {
    lookup: HashMap<ConnectionKey, (u32, String)>,
    last_refresh: Instant,
}

#[derive(Debug, Clone)]
struct WindowsProcessDetails {
    ppid: u32,
    name: String,
    executable: Option<PathBuf>,
    started_at_unix_ms: Option<u64>,
    runtime_resolved: bool,
}

#[derive(Debug)]
struct WindowsRuntimeDetails {
    executable: Option<PathBuf>,
    started_at_unix_ms: Option<u64>,
}

// The four IP Helper table refreshes share the same unsafe two-call dance:
// size probe, ERROR_INSUFFICIENT_BUFFER check, size sanity check, allocate,
// fetch, header and entry bounds checks, then a row loop ending in
// cache_process. A macro rather than a generic function keeps the exact
// Windows API types of each expansion intact; only the API function, address
// family, table class, table and row types, log labels, and per-row key
// construction vary.
macro_rules! refresh_table {
    (
        $fn_name:ident,
        $api:ident,
        $family:expr,
        $table_class:expr,
        $table_ty:ty,
        $row_ty:ty,
        $api_label:literal,
        $table_label:literal,
        $processing_label:literal,
        |$row:ident| $key:expr,
        |$state_row:ident| $state:expr $(,)?
    ) => {
        fn $fn_name(
            &self,
            cache: &mut ProcessMap,
            process_names: &mut ProcessNameCache,
            sockets: &mut Vec<HostSocket>,
        ) -> Result<()> {
            unsafe {
                let mut size: u32 = 0;

                // First call to get buffer size
                let result = $api(None, &mut size, false, $family, $table_class, 0);

                if WIN32_ERROR(result) != ERROR_INSUFFICIENT_BUFFER {
                    log::debug!(
                        concat!($api_label, " returned no data or error: {}"),
                        result
                    );
                    return Ok(()); // No connections or error
                }

                if size == 0 || size > 100_000_000 {
                    // Sanity check: reject unreasonably large sizes (100MB limit)
                    log::warn!(concat!($api_label, " returned invalid size: {}"), size);
                    return Ok(());
                }

                // Allocate buffer and get actual data
                let mut table = allocate_table_buffer(size);
                let result = $api(
                    Some(table.as_mut_ptr() as *mut _),
                    &mut size,
                    false,
                    $family,
                    $table_class,
                    0,
                );

                if result != 0 {
                    log::debug!(concat!($api_label, " second call failed: {}"), result);
                    return Ok(()); // Error getting table
                }

                // Verify we have enough data for the header
                if table_buffer_len(&table) < std::mem::size_of::<u32>() {
                    log::warn!(concat!($table_label, " table buffer too small for header"));
                    return Ok(());
                }

                // Parse the table
                let parsed_table = &*(table.as_ptr() as *const $table_ty);
                let num_entries = parsed_table.dwNumEntries as usize;

                // Bounds check: ensure we have enough space for all entries
                let required_size =
                    std::mem::size_of::<u32>() + num_entries * std::mem::size_of::<$row_ty>();
                if table_buffer_len(&table) < required_size {
                    log::warn!(
                        concat!(
                            $table_label,
                            " table buffer too small: got {} bytes, need {} for {} entries"
                        ),
                        table_buffer_len(&table),
                        required_size,
                        num_entries
                    );
                    return Ok(());
                }

                log::debug!(
                    concat!("Processing {} ", $processing_label, " connections"),
                    num_entries
                );

                // Get pointer to the first entry
                let rows_ptr = &parsed_table.table[0] as *const $row_ty;

                for i in 0..num_entries {
                    let $row = &*rows_ptr.add(i);
                    let key = $key;
                    if key.protocol == Protocol::Udp && key.local_addr.port() == 0 {
                        continue;
                    }
                    let $state_row = $row;
                    let state = $state;
                    let owner = cache_process(cache, process_names, key, $row.dwOwningPid);
                    sockets.push(HostSocket {
                        protocol: key.protocol,
                        local_addr: key.local_addr,
                        remote_addr: remote_if_present(key.remote_addr),
                        state,
                        owner,
                        native_id: None,
                    });
                }
            }

            Ok(())
        }
    };
}

impl WindowsProcessLookup {
    pub(super) fn new() -> Result<Self> {
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

        let lookup = Self {
            cache: RwLock::new(ProcessCache {
                lookup: HashMap::new(),
                last_refresh: initial_refresh,
            }),
            process_details: RwLock::new(HashMap::new()),
            socket_snapshot: RwLock::new(SocketSnapshot::default()),
            etw_cache,
            _etw: etw,
        };
        lookup.refresh()?;
        Ok(lookup)
    }

    fn snapshot_processes() -> Result<HashMap<u32, WindowsProcessDetails>> {
        // SAFETY: the Tool Help APIs receive an initialized structure with the
        // documented size. The snapshot handle is closed on every path.
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .context("failed to snapshot Windows processes")?;
            let result = (|| {
                let mut processes = HashMap::new();
                let mut entry = PROCESSENTRY32W {
                    dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
                        .expect("PROCESSENTRY32W size fits in u32"),
                    ..Default::default()
                };

                Process32FirstW(snapshot, &mut entry)
                    .context("failed to enumerate Windows processes")?;
                loop {
                    let name = decode_wide_string(&entry.szExeFile);
                    processes.insert(
                        entry.th32ProcessID,
                        WindowsProcessDetails {
                            ppid: entry.th32ParentProcessID,
                            name,
                            executable: None,
                            started_at_unix_ms: None,
                            runtime_resolved: false,
                        },
                    );
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
                Ok(processes)
            })();
            let _ = CloseHandle(snapshot);
            result
        }
    }

    fn process_details(&self, pid: u32) -> Option<WindowsProcessDetails> {
        let mut details = self
            .process_details
            .read()
            .expect("process details lock poisoned")
            .get(&pid)
            .cloned();

        if details.is_none() {
            let snapshot = Self::snapshot_processes().ok()?;
            details = snapshot.get(&pid).cloned();
            *self
                .process_details
                .write()
                .expect("process details lock poisoned") = snapshot;
        }

        let mut details = details?;
        if details.runtime_resolved {
            return Some(details);
        }

        if let Some(runtime) = query_process_runtime(pid) {
            details.executable = runtime.executable;
            details.started_at_unix_ms = runtime.started_at_unix_ms;
        }
        details.runtime_resolved = true;
        self.process_details
            .write()
            .expect("process details lock poisoned")
            .insert(pid, details.clone());
        Some(details)
    }

    fn process_lineage(&self, pid: u32, ppid: u32) -> Option<ProcessLineage> {
        // Windows never rewrites a child's parent PID when the parent exits,
        // and dead PIDs are recycled. A real ancestor always started no later
        // than its descendant, so a "parent" younger than the youngest child
        // seen so far is a recycled PID and ends the walk. The bound carries
        // across entries with unknown start times.
        let mut newest_descendant_start = self
            .process_details(pid)
            .and_then(|details| details.started_at_unix_ms);
        collect_process_lineage(pid, ppid, |ancestor_pid| {
            let details = self.process_details(ancestor_pid)?;
            if let (Some(descendant_start), Some(ancestor_start)) =
                (newest_descendant_start, details.started_at_unix_ms)
                && ancestor_start > descendant_start
            {
                return None;
            }
            if details.started_at_unix_ms.is_some() {
                newest_descendant_start = details.started_at_unix_ms;
            }
            Some((
                ProcessAncestor {
                    pid: ancestor_pid,
                    name: details.name,
                    executable: details.executable,
                    started_at_unix_ms: details.started_at_unix_ms,
                },
                details.ppid,
            ))
        })
    }

    fn refresh_tcp_processes(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
        sockets: &mut Vec<HostSocket>,
    ) -> Result<()> {
        // IPv4 TCP connections
        self.refresh_tcp_table_v4(cache, process_names, sockets)?;
        // IPv6 TCP connections
        self.refresh_tcp_table_v6(cache, process_names, sockets)?;
        Ok(())
    }

    refresh_table!(
        refresh_tcp_table_v4,
        GetExtendedTcpTable,
        AF_INET.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        MIB_TCPTABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID,
        "GetExtendedTcpTable (IPv4)",
        "TCP",
        "TCP IPv4",
        |row| ConnectionKey {
            protocol: Protocol::Tcp,
            local_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
                u16::from_be(row.dwRemotePort as u16),
            ),
        },
        |row| HostSocketState::Tcp(windows_tcp_state(row.dwState))
    );

    refresh_table!(
        refresh_tcp_table_v6,
        GetExtendedTcpTable,
        AF_INET6.0 as u32,
        TCP_TABLE_OWNER_PID_ALL,
        MIB_TCP6TABLE_OWNER_PID,
        MIB_TCP6ROW_OWNER_PID,
        "GetExtendedTcpTable (IPv6)",
        "TCP IPv6",
        "TCP IPv6",
        |row| ConnectionKey {
            protocol: Protocol::Tcp,
            local_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                u16::from_be(row.dwLocalPort as u16),
            ),
            remote_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
                u16::from_be(row.dwRemotePort as u16),
            ),
        },
        |row| HostSocketState::Tcp(windows_tcp_state(row.dwState))
    );

    fn refresh_udp_processes(
        &self,
        cache: &mut ProcessMap,
        process_names: &mut ProcessNameCache,
        sockets: &mut Vec<HostSocket>,
    ) -> Result<()> {
        // IPv4 UDP connections
        self.refresh_udp_table_v4(cache, process_names, sockets)?;
        // IPv6 UDP connections
        self.refresh_udp_table_v6(cache, process_names, sockets)?;
        Ok(())
    }

    refresh_table!(
        refresh_udp_table_v4,
        GetExtendedUdpTable,
        AF_INET.0 as u32,
        UDP_TABLE_OWNER_PID,
        MIB_UDPTABLE_OWNER_PID,
        MIB_UDPROW_OWNER_PID,
        "GetExtendedUdpTable (IPv4)",
        "UDP",
        "UDP IPv4",
        |row| ConnectionKey {
            protocol: Protocol::Udp,
            local_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
                u16::from_be(row.dwLocalPort as u16),
            ),
            // UDP doesn't have remote address in the table
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        },
        |_row| HostSocketState::UdpBound
    );

    refresh_table!(
        refresh_udp_table_v6,
        GetExtendedUdpTable,
        AF_INET6.0 as u32,
        UDP_TABLE_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID,
        MIB_UDP6ROW_OWNER_PID,
        "GetExtendedUdpTable (IPv6)",
        "UDP IPv6",
        "UDP IPv6",
        |row| ConnectionKey {
            protocol: Protocol::Udp,
            local_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
                u16::from_be(row.dwLocalPort as u16),
            ),
            // UDP doesn't have remote address in the table
            remote_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        },
        |_row| HostSocketState::UdpBound
    );
}

impl WindowsProcessLookup {
    fn lookup_process(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);

        // A fresh IP Helper snapshot reflects the kernel's current socket
        // owner and takes precedence over the ETW tuple cache, whose entries
        // can be up to ENTRY_TTL old and outlive a port reuse. ETW wins when
        // the table has no row: processes that exited between refreshes.
        let mut table_is_fresh = false;
        {
            let cache = read_recovering(&self.cache, CACHE_LOCK);

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
                if let Some(result) =
                    relaxed_lookup(&cache.lookup, &key).map(|(process, _quality)| process.clone())
                {
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
            let cache = read_recovering(&self.cache, CACHE_LOCK);
            let result = cache.lookup.get(&key).cloned().or_else(|| {
                relaxed_lookup(&cache.lookup, &key).map(|(process, _quality)| process.clone())
            });
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
}

impl ProcessLookup for WindowsProcessLookup {
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let (pid, name) = self.lookup_process(conn)?;
        let mut attribution = ProcessAttribution::new(pid, name, MatchQuality::Unspecified);
        if let Some(details) = self.process_details(pid) {
            let lineage = self.process_lineage(pid, details.ppid);
            attribution = attribution.with_details(details.ppid, None, details.executable, lineage);
        }
        Some(attribution)
    }

    fn refresh(&self) -> Result<()> {
        let mut new_cache = HashMap::new();
        let mut process_names = HashMap::new();
        let mut sockets = Vec::new();

        self.refresh_tcp_processes(&mut new_cache, &mut process_names, &mut sockets)?;
        self.refresh_udp_processes(&mut new_cache, &mut process_names, &mut sockets)?;

        match Self::snapshot_processes() {
            Ok(processes) => {
                *self
                    .process_details
                    .write()
                    .expect("process details lock poisoned") = processes;
            }
            Err(error) => log::debug!("Windows process snapshot failed: {}", error),
        }

        let mut cache = write_recovering(&self.cache, CACHE_LOCK);

        let total_entries = new_cache.len();
        cache.lookup = new_cache;
        cache.last_refresh = Instant::now();
        *self
            .socket_snapshot
            .write()
            .expect("socket snapshot lock poisoned") = SocketSnapshot::new(sockets);

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

    fn socket_snapshot(&self) -> SocketSnapshot {
        self.socket_snapshot
            .read()
            .expect("socket snapshot lock poisoned")
            .clone()
    }
}

fn windows_tcp_state(state: u32) -> HostTcpState {
    match state {
        1 => HostTcpState::Closed,
        2 => HostTcpState::Listen,
        3 => HostTcpState::SynSent,
        4 => HostTcpState::SynReceived,
        5 => HostTcpState::Established,
        6 => HostTcpState::FinWait1,
        7 => HostTcpState::FinWait2,
        8 => HostTcpState::CloseWait,
        9 => HostTcpState::Closing,
        10 => HostTcpState::LastAck,
        11 => HostTcpState::TimeWait,
        12 => HostTcpState::DeleteTcb,
        _ => HostTcpState::Unknown,
    }
}

fn decode_wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    OsString::from_wide(&buffer[..length])
        .to_string_lossy()
        .into_owned()
}

fn filetime_to_unix_ms(time: FILETIME) -> Option<u64> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
    let ticks = (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    ticks
        .checked_sub(WINDOWS_TO_UNIX_EPOCH_100NS)
        .map(|unix_ticks| unix_ticks / 10_000)
}

/// The full image path of the process behind `handle`, or `None` when the
/// query fails or returns an empty path.
///
/// # Safety
///
/// `handle` must be an open process handle with at least
/// `PROCESS_QUERY_LIMITED_INFORMATION` access.
unsafe fn query_image_path(handle: HANDLE) -> Option<PathBuf> {
    // QueryFullProcessImageNameW supports extended-length paths. A MAX_PATH
    // buffer silently loses attribution for executables installed below a
    // long path, so allocate the documented maximum Windows path instead.
    let mut size: u32 = 32_768;
    let mut buffer: Vec<u16> = vec![0; size as usize];

    // SAFETY: the buffer has exactly `size` elements and the caller
    // guarantees a valid process handle.
    let result = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    };
    (result.is_ok() && size > 0)
        .then(|| PathBuf::from(OsString::from_wide(&buffer[..size as usize])))
}

fn query_process_runtime(pid: u32) -> Option<WindowsRuntimeDetails> {
    // SAFETY: the process handle is valid after `OpenProcess`, all buffers
    // have their exact lengths, and the handle is closed before returning.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let executable = query_image_path(handle);

        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let started_at_unix_ms =
            GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
                .is_ok()
                .then(|| filetime_to_unix_ms(creation))
                .flatten();

        let _ = CloseHandle(handle);
        Some(WindowsRuntimeDetails {
            executable,
            started_at_unix_ms,
        })
    }
}

fn cache_process(
    cache: &mut ProcessMap,
    process_names: &mut ProcessNameCache,
    key: ConnectionKey,
    pid: u32,
) -> Option<SocketOwner> {
    // PID 0 is used for TCP rows whose owner is no longer available (for
    // example TIME_WAIT), so treating it as a process would create false
    // attribution. The same applies when the owning process has already
    // exited. Access-denied is different: the process is alive, so preserve
    // the kernel-provided owner PID even without a name.
    if pid == 0 {
        return None;
    }

    let resolved = process_names
        .entry(pid)
        .or_insert_with(|| match query_process_name(pid) {
            ProcessNameLookup::Named(name) => Some(name),
            ProcessNameLookup::Denied => Some(UNKNOWN_PROCESS_NAME.to_string()),
            ProcessNameLookup::Gone => None,
        });
    let Some(process_name) = resolved.clone() else {
        return None;
    };

    log::trace!(
        "Cached: {:?} {} -> {} (PID: {}, {})",
        key.protocol,
        key.local_addr,
        key.remote_addr,
        pid,
        process_name
    );
    cache.insert(key, (pid, process_name.clone()));
    Some(SocketOwner {
        pid,
        name: process_name,
        uid: None,
    })
}

pub(super) fn get_process_name_from_pid(pid: u32) -> Option<String> {
    match query_process_name(pid) {
        ProcessNameLookup::Named(name) => Some(name),
        ProcessNameLookup::Denied | ProcessNameLookup::Gone => None,
    }
}

fn query_process_name(pid: u32) -> ProcessNameLookup {
    // PID 4 is the kernel's System process, fixed since Windows XP. It owns
    // real sockets (NetBIOS name service, SMB) but has no image to query —
    // QueryFullProcessImageNameW has nothing to return — so without this it
    // surfaces as the "Unknown" placeholder in every process list.
    if pid == 4 {
        return ProcessNameLookup::Named("System".to_string());
    }
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

        let image_path = query_image_path(handle);

        let _ = CloseHandle(handle);

        // Only the file name is wanted
        if let Some(filename) = image_path.as_deref().and_then(Path::file_name) {
            return ProcessNameLookup::Named(filename.to_string_lossy().into_owned());
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

        let _ = cache_process(&mut cache, &mut process_names, key, u32::MAX);

        assert_eq!(cache.get(&key), None);
    }

    #[test]
    fn names_the_kernel_system_process() {
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            local_addr: "127.0.0.1:12346".parse().unwrap(),
            remote_addr: "0.0.0.0:0".parse().unwrap(),
        };
        let mut cache = ProcessMap::new();
        let mut process_names = ProcessNameCache::new();

        // PID 4 is the System process: always alive, but its image name is
        // not queryable via QueryFullProcessImageNameW, so it is named
        // directly rather than cached as the Unknown placeholder.
        let _ = cache_process(&mut cache, &mut process_names, key, 4);

        assert_eq!(cache.get(&key), Some(&(4, "System".to_string())));
    }

    #[test]
    fn attributes_ipv6_udp_socket_to_current_process() {
        let socket = UdpSocket::bind("[::1]:0").expect("bind IPv6 UDP socket");
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let conn = Connection::new(Protocol::Udp, local_addr, remote_addr, ProtocolState::Udp);
        let lookup = WindowsProcessLookup::new().unwrap();

        let attribution = lookup
            .get_process_attribution(&conn)
            .expect("IPv6 UDP socket should have an owner");

        assert_eq!(attribution.tgid, std::process::id());
        assert_ne!(attribution.name, UNKNOWN_PROCESS_NAME);
        assert!(attribution.executable.is_some());
        assert_eq!(
            attribution
                .lineage
                .as_ref()
                .and_then(|lineage| lineage.ancestors.last())
                .map(|ancestor| ancestor.pid),
            attribution.ppid
        );
    }

    #[test]
    fn converts_windows_filetime_epoch_to_unix_milliseconds() {
        const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;
        let time = FILETIME {
            dwLowDateTime: WINDOWS_TO_UNIX_EPOCH_100NS as u32,
            dwHighDateTime: (WINDOWS_TO_UNIX_EPOCH_100NS >> 32) as u32,
        };

        assert_eq!(filetime_to_unix_ms(time), Some(0));
    }

    #[test]
    fn maps_ip_helper_tcp_states() {
        assert_eq!(windows_tcp_state(2), HostTcpState::Listen);
        assert_eq!(windows_tcp_state(5), HostTcpState::Established);
        assert_eq!(windows_tcp_state(11), HostTcpState::TimeWait);
        assert_eq!(windows_tcp_state(12), HostTcpState::DeleteTcb);
        assert_eq!(windows_tcp_state(u32::MAX), HostTcpState::Unknown);
    }
}
