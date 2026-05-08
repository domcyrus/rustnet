//! eBPF program loader with comprehensive error handling

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, info, warn};
use std::io::Read as _;

use crate::network::platform::DegradationReason;
use super::maps_libbpf::TcpStats;

mod socket_tracker {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker.skel.rs"));
}

use socket_tracker::*;

pub struct EbpfLoader {
    skel: Box<SocketTrackerSkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
    tcp_iter_link: Option<libbpf_rs::Link>,
}

impl EbpfLoader {
    /// Attempt to load eBPF programs with graceful error handling
    /// Returns (Option<Self>, DegradationReason) - the reason explains why eBPF is unavailable
    pub fn try_load() -> Result<(Option<Self>, DegradationReason)> {
        // First check if we have necessary capabilities
        let cap_result = Self::check_capabilities_detailed();
        if cap_result != DegradationReason::None {
            info!(
                "eBPF: Insufficient capabilities ({}), falling back to procfs",
                cap_result.description()
            );
            return Ok((None, cap_result));
        }

        info!("eBPF: Sufficient capabilities detected, attempting to load program");

        match Self::load_program() {
            Ok(loader) => {
                info!("eBPF: Socket tracker loaded and attached successfully");
                Ok((Some(loader), DegradationReason::None))
            }
            Err(e) => {
                warn!(
                    "eBPF: Failed to load program: {}, falling back to procfs",
                    e
                );
                Ok((None, DegradationReason::KernelUnsupported))
            }
        }
    }

    fn load_program() -> Result<Self> {
        debug!("eBPF: Opening eBPF skeleton");
        let skel_builder = SocketTrackerSkelBuilder::default();

        // Heap allocate the object to avoid lifetime issues
        let mut open_object = Box::new(std::mem::MaybeUninit::uninit());
        let open_skel = skel_builder.open(&mut open_object).map_err(|e| {
            warn!("eBPF: Failed to open skeleton: {}", e);
            e
        })?;

        debug!("eBPF: Loading program into kernel");
        let mut skel = open_skel.load().map_err(|e| {
            warn!("eBPF: Failed to load program into kernel: {}", e);
            e
        })?;

        debug!("eBPF: Attaching all programs");
        match skel.attach() {
            Ok(_) => {
                info!("eBPF: Programs attached successfully");
                let prog_names = [
                    "trace_tcp_connect",
                    "trace_tcp_accept",
                    "trace_udp_sendmsg",
                    "trace_tcp_v6_connect",
                    "trace_udp_v6_sendmsg",
                    "dump_tcp_sockets",
                ];
                for (i, prog_name) in prog_names.iter().enumerate() {
                    debug!("eBPF: Checking attachment for program {}: {}", i, prog_name);
                }
                info!("eBPF: All programs loaded and attached successfully");
            }
            Err(e) => {
                warn!("eBPF: Failed to attach programs: {}", e);
                return Err(e.into());
            }
        }

        // Take the iter/tcp link out before transmuting skel.
        // Keeping it alive is what keeps dump_tcp_sockets attached; dropping it
        // detaches the iter. The other kprobe links remain owned by skel.links.
        let tcp_iter_link = skel.links.dump_tcp_sockets.take();
        if tcp_iter_link.is_none() {
            warn!("eBPF: dump_tcp_sockets iter/tcp did not attach — TCP stats will be unavailable");
        } else {
            info!("eBPF: iter/tcp attached, TCP stats scan available");
        }

        // SAFETY: SocketTrackerSkel borrows from open_object via the reference
        // passed to skel_builder.open(). We extend the lifetime to 'static because
        // _open_object is stored alongside skel in EbpfLoader and will not be
        // dropped before skel. The Box ensures a stable address.
        let skel_static: SocketTrackerSkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel: Box::new(skel_static),
            _open_object: open_object,
            tcp_iter_link,
        })
    }

    /// Check if we have the necessary capabilities for eBPF
    /// Returns DegradationReason::None if sufficient, otherwise the specific reason
    fn check_capabilities_detailed() -> DegradationReason {
        use std::fs;

        // Check if we're running as root
        if unsafe { libc::geteuid() } == 0 {
            debug!("eBPF: Running as root - all capabilities available");
            return DegradationReason::None;
        }

        // Check for required capabilities via /proc/self/status
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            // Parse CapEff (effective capabilities) line
            if let Some(cap_line) = status.lines().find(|line| line.starts_with("CapEff:"))
                && let Some(cap_hex) = cap_line.split_whitespace().nth(1)
                && let Ok(cap_value) = u64::from_str_radix(cap_hex, 16)
            {
                debug!("eBPF: Current effective capabilities: 0x{:x}", cap_value);

                // Capability bit positions
                const CAP_NET_RAW: u64 = 13;
                const CAP_SYS_ADMIN: u64 = 21;
                const CAP_BPF: u64 = 39;
                const CAP_PERFMON: u64 = 38;

                // Check CAP_NET_RAW (required for read-only packet capture)
                let has_net_raw = (cap_value & (1u64 << CAP_NET_RAW)) != 0;

                debug!(
                    "eBPF: Capability CAP_NET_RAW (bit {}): {}",
                    CAP_NET_RAW,
                    if has_net_raw { "present" } else { "missing" }
                );

                // Must have CAP_NET_RAW for packet capture - but this is checked elsewhere
                // Here we focus on eBPF-specific capabilities

                // Check modern capabilities (Linux 5.8+)
                let has_bpf = (cap_value & (1u64 << CAP_BPF)) != 0;
                let has_perfmon = (cap_value & (1u64 << CAP_PERFMON)) != 0;

                debug!(
                    "eBPF: Modern capability CAP_BPF (bit {}): {}",
                    CAP_BPF,
                    if has_bpf { "present" } else { "missing" }
                );
                debug!(
                    "eBPF: Modern capability CAP_PERFMON (bit {}): {}",
                    CAP_PERFMON,
                    if has_perfmon { "present" } else { "missing" }
                );

                // Check legacy capability
                let has_sys_admin = (cap_value & (1u64 << CAP_SYS_ADMIN)) != 0;

                debug!(
                    "eBPF: Capability CAP_SYS_ADMIN (bit {}): {}",
                    CAP_SYS_ADMIN,
                    if has_sys_admin { "present" } else { "missing" }
                );

                // Accept either modern capabilities OR legacy capability
                if has_bpf && has_perfmon {
                    info!("eBPF: Using modern capabilities (CAP_BPF + CAP_PERFMON)");
                    return DegradationReason::None;
                } else if has_sys_admin {
                    info!("eBPF: Using legacy capability (CAP_SYS_ADMIN)");
                    return DegradationReason::None;
                } else {
                    // Return specific missing capability
                    debug!("eBPF: Missing required capabilities");
                    if !has_bpf && !has_perfmon {
                        return DegradationReason::MissingBpfCapabilities;
                    } else if !has_bpf {
                        return DegradationReason::MissingCapBpf;
                    } else {
                        return DegradationReason::MissingCapPerfmon;
                    }
                }
            }
        }

        debug!(
            "eBPF: Insufficient capabilities - need either (CAP_BPF+CAP_PERFMON) or CAP_SYS_ADMIN for eBPF"
        );
        DegradationReason::MissingBpfCapabilities
    }

    /// Get the socket map for lookups
    pub fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        &self.skel.maps.socket_map
    }

    /// Walk every tcp_sock in the kernel and return stats for each.
    /// Triggers the iter/tcp BPF program by opening a new iterator fd and
    /// reading from it — zero trap overhead, purely pull-based.
    pub fn scan_tcp_stats(&self) -> Result<Vec<TcpStats>> {
        let link = match &self.tcp_iter_link {
            Some(l) => l,
            None => return Ok(Vec::new()),
        };

        let mut iter = libbpf_rs::Iter::new(link)?;
        let mut buf = Vec::new();
        iter.read_to_end(&mut buf)?;

        let entry_size = std::mem::size_of::<TcpStats>();
        if buf.is_empty() {
            return Ok(Vec::new());
        }
        if buf.len() % entry_size != 0 {
            return Err(anyhow::anyhow!(
                "iter/tcp read {} bytes — not a multiple of {} (TcpStats size); possible struct layout mismatch",
                buf.len(),
                entry_size
            ));
        }

        let result = buf
            .chunks_exact(entry_size)
            .map(|chunk| {
                // SAFETY: TcpStats is #[repr(C, packed)]; all bit patterns are valid
                // for every field type (integers). Chunk is exactly entry_size bytes.
                unsafe {
                    let mut s = std::mem::MaybeUninit::<TcpStats>::uninit();
                    std::ptr::copy_nonoverlapping(
                        chunk.as_ptr(),
                        s.as_mut_ptr() as *mut u8,
                        entry_size,
                    );
                    s.assume_init()
                }
            })
            .collect();

        Ok(result)
    }
}
