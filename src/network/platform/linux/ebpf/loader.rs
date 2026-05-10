//! eBPF program loader with comprehensive error handling

use anyhow::Result;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use log::{debug, info, warn};

use crate::network::platform::DegradationReason;

mod socket_tracker {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker.skel.rs"));
}

use socket_tracker::*;

pub struct EbpfLoader {
    skel: Box<SocketTrackerSkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
    // Per-program Link handles. Dropping a Link detaches the kprobe, so the
    // links must outlive the loader. They are never read after attach.
    _links: Vec<libbpf_rs::Link>,
}

impl EbpfLoader {
    /// Attempt to load eBPF programs with graceful error handling
    /// Returns (Option<Self>, DegradationReason) - the reason explains why eBPF is unavailable
    pub fn try_load() -> Result<(Option<Self>, DegradationReason)> {
        // First check if we have necessary capabilities
        let cap_result = Self::check_capabilities_detailed();
        if cap_result != DegradationReason::None {
            // If caps are missing AND the binary lives on a nosuid mount, that
            // is almost certainly the real cause: the kernel silently ignores
            // file capabilities for binaries on `nosuid` filesystems, so any
            // setcap the user applied was effectively a no-op. Surface that
            // specific reason instead of the generic "needs CAP_X" message.
            if matches!(
                cap_result,
                DegradationReason::MissingCapBpf
                    | DegradationReason::MissingCapPerfmon
                    | DegradationReason::MissingBpfCapabilities
            ) && Self::executable_on_nosuid_mount()
            {
                warn!(
                    "eBPF: rustnet binary lives on a nosuid mount; file capabilities are ignored at exec"
                );
                return Ok((None, DegradationReason::BinaryOnNosuidMount));
            }
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
                Ok((None, classify_libbpf_error(&e)))
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

        // Attach each kprobe individually so a single missing kernel symbol
        // yields a "kprobe attach failed: <name>" message instead of a generic
        // failure with no symbol context.
        debug!("eBPF: Attaching kprobes individually");
        type AttachFn = dyn Fn(&mut SocketTrackerSkel<'_>) -> libbpf_rs::Result<libbpf_rs::Link>;
        let attachments: [(&str, &AttachFn); 7] = [
            ("trace_tcp_connect", &|s| s.progs.trace_tcp_connect.attach()),
            ("trace_tcp_accept", &|s| s.progs.trace_tcp_accept.attach()),
            ("trace_udp_sendmsg", &|s| s.progs.trace_udp_sendmsg.attach()),
            ("trace_tcp_v6_connect", &|s| {
                s.progs.trace_tcp_v6_connect.attach()
            }),
            ("trace_udp_v6_sendmsg", &|s| {
                s.progs.trace_udp_v6_sendmsg.attach()
            }),
            ("trace_ping_v4_sendmsg", &|s| {
                s.progs.trace_ping_v4_sendmsg.attach()
            }),
            ("trace_ping_v6_sendmsg", &|s| {
                s.progs.trace_ping_v6_sendmsg.attach()
            }),
        ];

        let mut links: Vec<libbpf_rs::Link> = Vec::with_capacity(attachments.len());
        for (name, attach_fn) in attachments.iter() {
            match attach_fn(&mut skel) {
                Ok(link) => {
                    debug!("eBPF: Attached kprobe {}", name);
                    links.push(link);
                }
                Err(e) => {
                    warn!("eBPF: Failed to attach kprobe {}: {}", name, e);
                    return Err(anyhow::Error::new(e).context(format!("attach kprobe {name}")));
                }
            }
        }
        info!("eBPF: All {} kprobes attached successfully", links.len());

        // SAFETY: SocketTrackerSkel borrows from open_object via the reference
        // passed to skel_builder.open(). We extend the lifetime to 'static because
        // _open_object is stored alongside skel in EbpfLoader and will not be
        // dropped before skel. The Box ensures a stable address.
        let skel_static: SocketTrackerSkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel: Box::new(skel_static),
            _open_object: open_object,
            _links: links,
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

    /// Detect whether the running binary lives on a filesystem mounted with
    /// `nosuid`. When that is the case, the kernel silently ignores file
    /// capabilities applied via `setcap`, so any caps the user granted are
    /// effectively no-ops at exec time.
    ///
    /// Resolves `/proc/self/exe` to its canonical path, then walks
    /// `/proc/self/mountinfo` looking for the longest mount-point prefix that
    /// contains the binary. The mount options field is parsed for `nosuid`.
    fn executable_on_nosuid_mount() -> bool {
        use std::fs;
        use std::path::Path;

        let exe = match fs::read_link("/proc/self/exe") {
            Ok(p) => p,
            Err(e) => {
                debug!("nosuid check: failed to resolve /proc/self/exe: {}", e);
                return false;
            }
        };

        let mountinfo = match fs::read_to_string("/proc/self/mountinfo") {
            Ok(s) => s,
            Err(e) => {
                debug!("nosuid check: failed to read /proc/self/mountinfo: {}", e);
                return false;
            }
        };

        // /proc/self/mountinfo line layout (see man 5 proc, "mountinfo"):
        //   id parent major:minor root mountpoint options - fstype source super_options
        //   [0]  [1]    [2]      [3]    [4]       [5]   [6]
        // Field 5 is the mount point and field 6 is the per-mount options.
        let mut best: Option<(usize, &str)> = None;
        for line in mountinfo.lines() {
            let mut fields = line.split_whitespace();
            let mountpoint = match fields.nth(4) {
                Some(mp) => mp,
                None => continue,
            };
            let options = match fields.next() {
                Some(o) => o,
                None => continue,
            };
            if Path::new(mountpoint).is_ancestor_of_or_equal(&exe) {
                let len = mountpoint.len();
                if best.map(|(l, _)| len > l).unwrap_or(true) {
                    best = Some((len, options));
                }
            }
        }

        match best {
            Some((_, options)) => {
                let nosuid = options.split(',').any(|opt| opt == "nosuid");
                if nosuid {
                    debug!("nosuid check: binary {:?} is on a nosuid mount", exe);
                }
                nosuid
            }
            None => false,
        }
    }
}

/// Stable Rust does not expose `Path::is_ancestor_of`; do the prefix match
/// component-by-component so `/foo` does not match `/foobar`.
trait PathAncestorExt {
    fn is_ancestor_of_or_equal(&self, other: &std::path::Path) -> bool;
}

impl PathAncestorExt for std::path::Path {
    fn is_ancestor_of_or_equal(&self, other: &std::path::Path) -> bool {
        let mut a = self.components();
        let mut b = other.components();
        loop {
            match (a.next(), b.next()) {
                (Some(x), Some(y)) if x == y => continue,
                (None, _) => return true,
                _ => return false,
            }
        }
    }
}

/// Classify a libbpf error into a `DegradationReason` so the TUI can surface
/// an actionable hint instead of a generic "kernel unsupported" message.
///
/// Walks the full error chain (libbpf-rs uses `anyhow::Context`) and matches
/// the lower-cased text against well-known failure modes in priority order.
fn classify_libbpf_error(err: &anyhow::Error) -> DegradationReason {
    // Collect every link in the chain into a single lower-cased blob to avoid
    // brittleness around which level wraps which.
    let mut blob = String::new();
    for cause in err.chain() {
        blob.push_str(&cause.to_string().to_lowercase());
        blob.push('\n');
    }

    if blob.contains("btf") || blob.contains("vmlinux") || blob.contains("co-re") {
        return DegradationReason::BtfUnavailable;
    }

    // ENOSYS from bpf(2) means the syscall isn't implemented at all.
    if blob.contains("function not implemented") || blob.contains("enosys") {
        return DegradationReason::KernelUnsupported;
    }

    // Permission errors after the cap pre-check has already passed imply an
    // LSM (AppArmor / lockdown), `kernel.unprivileged_bpf_disabled`, or —
    // for kprobe attach via `perf_event_open(2)` — `kernel.perf_event_paranoid`
    // being too restrictive even for CAP_PERFMON. libbpf surfaces these as
    // either EPERM ("Operation not permitted") or EACCES ("Permission
    // denied" / "-EACCES"). Both must be matched.
    let permission_denied = blob.contains("operation not permitted")
        || blob.contains("permission denied")
        || blob.contains("eperm")
        || blob.contains("eacces")
        || blob.contains("-eacces");
    if permission_denied {
        return DegradationReason::BpfPermissionDenied;
    }

    // Genuine kprobe attach failure that isn't a permission issue — usually
    // a missing kernel symbol. Carry the symbol name where libbpf gave us
    // one so the user can confirm whether the kernel exposes it.
    let mentions_attach =
        blob.contains("attach") || blob.contains("kprobe") || blob.contains("perf_event_open");
    if mentions_attach {
        let sym = extract_kprobe_symbol(&blob).unwrap_or_default();
        return DegradationReason::KprobeAttachFailed(sym);
    }

    // Cap the text so the TUI's right-column reason line wraps to at most
    // ~2 rows on typical terminal widths. Full text is always available in
    // the rustnet log file via the `warn!("eBPF: Failed to load program: …")`
    // emitted at the call site.
    let mut text = err.to_string();
    const MAX_LEN: usize = 100;
    if text.len() > MAX_LEN {
        text.truncate(MAX_LEN);
        text.push('…');
    }
    DegradationReason::EbpfLoadFailed(text)
}

fn extract_kprobe_symbol(blob: &str) -> Option<String> {
    // Look for "attach kprobe <name>" or "kprobe/<name>" first - both forms
    // appear in libbpf error text.
    for prefix in ["attach kprobe ", "kprobe/", "kprobe '"] {
        if let Some(rest) = blob.split(prefix).nth(1) {
            let sym: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !sym.is_empty() {
                return Some(sym);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn classifies_btf_error() {
        let e = anyhow!("failed to load: BTF type 42 missing");
        assert_eq!(classify_libbpf_error(&e), DegradationReason::BtfUnavailable);
    }

    #[test]
    fn classifies_eperm_as_apparmor_hint() {
        let e = anyhow!("bpf(BPF_PROG_LOAD): Operation not permitted");
        assert_eq!(
            classify_libbpf_error(&e),
            DegradationReason::BpfPermissionDenied
        );
    }

    #[test]
    fn classifies_eacces_from_perf_event_open() {
        // Exact wording observed on Debian 13 / kernel 6.12 (issue #255):
        // libbpf returns -EACCES from perf_event_open() when attaching kprobe.
        // This must classify as a permission issue (perf_event_paranoid /
        // AppArmor) — NOT as a missing-kprobe-symbol failure.
        let e = anyhow!(
            "libbpf: prog 'trace_tcp_connect': failed to create kprobe \
             'tcp_connect+0x0' perf event: -EACCES"
        );
        assert_eq!(
            classify_libbpf_error(&e),
            DegradationReason::BpfPermissionDenied
        );
    }

    #[test]
    fn classifies_kprobe_attach_with_symbol() {
        let e = anyhow!("failed to attach kprobe ping_v6_sendmsg: No such file or directory");
        match classify_libbpf_error(&e) {
            DegradationReason::KprobeAttachFailed(sym) => assert_eq!(sym, "ping_v6_sendmsg"),
            other => panic!("expected KprobeAttachFailed, got {:?}", other),
        }
    }

    #[test]
    fn classifies_enosys_as_kernel_unsupported() {
        let e = anyhow!("bpf syscall: Function not implemented");
        assert_eq!(
            classify_libbpf_error(&e),
            DegradationReason::KernelUnsupported
        );
    }

    #[test]
    fn falls_back_to_ebpf_load_failed_with_truncation() {
        let long = "x".repeat(500);
        let e = anyhow!("{}", long);
        match classify_libbpf_error(&e) {
            DegradationReason::EbpfLoadFailed(s) => {
                // 100 ASCII chars + "…" sentinel
                assert!(
                    s.chars().count() <= 101,
                    "expected truncation, got {} chars",
                    s.chars().count()
                );
                assert!(s.ends_with('…'), "expected ellipsis suffix, got {:?}", s);
            }
            other => panic!("expected EbpfLoadFailed, got {:?}", other),
        }
    }

    #[test]
    fn extracts_symbol_from_quoted_form() {
        let sym = extract_kprobe_symbol("could not attach kprobe 'tcp_v6_connect' on cpu 0");
        assert_eq!(sym.as_deref(), Some("tcp_v6_connect"));
    }
}
