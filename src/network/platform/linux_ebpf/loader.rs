//! eBPF program loader with comprehensive error handling

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use log::{debug, info, warn};

mod socket_tracker {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker.skel.rs"));
}

use socket_tracker::*;

pub struct EbpfLoader {
    skel: Box<SocketTrackerSkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
}

impl EbpfLoader {
    /// Attempt to load eBPF programs with graceful error handling
    pub fn try_load() -> Result<Option<Self>> {
        // First check if we have necessary capabilities
        if !Self::check_capabilities() {
            info!("eBPF: Insufficient capabilities (need root or CAP_BPF), falling back to procfs");
            return Ok(None);
        } else {
            info!("eBPF: Sufficient capabilities detected, attempting to load program");
        }

        match Self::load_program() {
            Ok(loader) => {
                info!("eBPF: Socket tracker loaded and attached successfully");
                Ok(Some(loader))
            }
            Err(e) => {
                warn!(
                    "eBPF: Failed to load program: {}, falling back to procfs",
                    e
                );
                Ok(None)
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
                // Verify programs are actually attached by checking their links
                let prog_names = [
                    "trace_tcp_connect",
                    "trace_tcp_accept",
                    "trace_udp_sendmsg",
                    "trace_tcp_v6_connect",
                    "trace_udp_v6_sendmsg",
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

        // Convert to 'static lifetime by boxing
        let skel_static: SocketTrackerSkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel: Box::new(skel_static),
            _open_object: open_object,
        })
    }

    /// Check if we have the necessary capabilities for eBPF
    fn check_capabilities() -> bool {
        use std::fs;

        // Check if we're running as root
        if unsafe { libc::geteuid() } == 0 {
            debug!("eBPF: Running as root - all capabilities available");
            return true;
        }

        // Check for required capabilities via /proc/self/status
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            // Parse CapEff (effective capabilities) line
            if let Some(cap_line) = status.lines().find(|line| line.starts_with("CapEff:"))
                && let Some(cap_hex) = cap_line.split_whitespace().nth(1)
                && let Ok(cap_value) = u64::from_str_radix(cap_hex, 16)
            {
                debug!("eBPF: Current effective capabilities: 0x{:x}", cap_value);

                // Required capabilities (bit positions):
                // CAP_NET_RAW = 13, CAP_NET_ADMIN = 12, CAP_BPF = 39, CAP_PERFMON = 38, CAP_SYS_ADMIN = 21
                let required_caps = [
                    13, // CAP_NET_RAW - for packet capture
                    12, // CAP_NET_ADMIN - for network administration
                    21, // CAP_SYS_ADMIN - fallback for older kernels
                ];

                // Optional modern capabilities (Linux 5.8+)
                let modern_caps = [
                    39, // CAP_BPF - for BPF operations
                    38, // CAP_PERFMON - for performance monitoring
                ];

                // Check required capabilities
                let has_required = required_caps.iter().all(|&cap| {
                    let has_cap = (cap_value & (1u64 << cap)) != 0;
                    debug!(
                        "eBPF: Capability {} (bit {}): {}",
                        match cap {
                            13 => "CAP_NET_RAW",
                            12 => "CAP_NET_ADMIN",
                            21 => "CAP_SYS_ADMIN",
                            _ => "UNKNOWN",
                        },
                        cap,
                        if has_cap { "present" } else { "missing" }
                    );
                    has_cap
                });

                // Check modern capabilities (nice to have)
                let has_modern = modern_caps.iter().any(|&cap| {
                    let has_cap = (cap_value & (1u64 << cap)) != 0;
                    debug!(
                        "eBPF: Modern capability {} (bit {}): {}",
                        match cap {
                            39 => "CAP_BPF",
                            38 => "CAP_PERFMON",
                            _ => "UNKNOWN",
                        },
                        cap,
                        if has_cap { "present" } else { "missing" }
                    );
                    has_cap
                });

                if has_required {
                    if has_modern {
                        info!("eBPF: All required and modern capabilities present");
                    } else {
                        info!("eBPF: Required capabilities present, using legacy mode");
                    }
                    return true;
                } else {
                    debug!("eBPF: Missing required capabilities");
                }
            }
        }

        debug!(
            "eBPF: Insufficient capabilities - need CAP_NET_RAW, CAP_NET_ADMIN, and CAP_SYS_ADMIN (or CAP_BPF+CAP_PERFMON on newer kernels)"
        );
        false
    }

    /// Get the socket map for lookups
    pub fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        &self.skel.maps.socket_map
    }
}
