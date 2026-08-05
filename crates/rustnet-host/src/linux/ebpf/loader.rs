//! Linux eBPF backend negotiation and program loading.

use anyhow::{Context, Result, ensure};
use libbpf_rs::btf::{
    Btf, BtfKind, BtfType, HasSize, ReferencesType,
    types::{Func, FuncProto, Int, IntEncoding},
};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use log::{debug, info, warn};

use super::maps_libbpf::{CONN_INFO_SIZE, CONN_KEY_SIZE};
use crate::{AttributionBackend, AttributionCapabilities, DegradationReason};

mod socket_tracker_fentry {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker_fentry.skel.rs"));
}

mod socket_tracker_kprobe {
    include!(concat!(env!("OUT_DIR"), "/socket_tracker_kprobe.skel.rs"));
}

use socket_tracker_fentry::*;
use socket_tracker_kprobe::*;

pub(crate) const CORE_CAPABILITIES: AttributionCapabilities =
    AttributionCapabilities::from_bits_retain(
        AttributionCapabilities::TCP_V4_CONNECT.bits()
            | AttributionCapabilities::TCP_V6_CONNECT.bits()
            | AttributionCapabilities::TCP_ACCEPT.bits()
            | AttributionCapabilities::UDP_V4_SEND.bits()
            | AttributionCapabilities::UDP_V6_SEND.bits(),
    );

#[derive(Debug, PartialEq, Eq)]
enum BackendSelection<T, E> {
    Selected { loader: T, fentry_error: Option<E> },
    TargetBtfUnavailable(E),
    BackendsFailed { fentry_error: E, kprobe_error: E },
}

/// Loaded eBPF backend. Each object owns a private socket map.
pub enum EbpfLoader {
    Fentry(FentryLoader),
    Kprobe(KprobeLoader),
}

impl EbpfLoader {
    /// Load the best backend supported by the running kernel.
    ///
    /// Capability and target-BTF checks happen once. Both kernel backends use
    /// CO-RE socket field reads, so missing target BTF falls safely to procfs.
    /// With BTF available, backend support is determined from actual program
    /// load and attachment results rather than uname.
    pub fn try_load() -> Result<(Option<Self>, DegradationReason)> {
        let cap_result = check_capabilities_detailed();
        if cap_result != DegradationReason::None {
            if matches!(
                cap_result,
                DegradationReason::MissingCapBpf
                    | DegradationReason::MissingCapPerfmon
                    | DegradationReason::MissingBpfCapabilities
            ) && executable_on_nosuid_mount()
            {
                warn!(
                    "eBPF: rustnet binary lives on a nosuid mount; file capabilities are ignored at exec"
                );
                return Ok((None, DegradationReason::BinaryOnNosuidMount));
            }
            info!(
                "eBPF: insufficient capabilities ({}), using procfs",
                cap_result.description()
            );
            return Ok((None, cap_result));
        }

        info!("eBPF: checking target BTF and attempting fentry/fexit backend");
        match select_backend_with_target_btf(
            Btf::from_vmlinux()
                .map_err(anyhow::Error::from)
                .context("load running kernel BTF"),
            |kernel_btf| FentryLoader::load_program(kernel_btf).map(Self::Fentry),
            |_| KprobeLoader::load_program().map(Self::Kprobe),
        ) {
            BackendSelection::Selected {
                loader,
                fentry_error: None,
            } => {
                info!(
                    "eBPF: selected {} backend with capabilities {:?}",
                    loader.backend(),
                    loader.capabilities()
                );
                Ok((Some(loader), DegradationReason::None))
            }
            BackendSelection::Selected {
                loader,
                fentry_error: Some(fentry_error),
            } => {
                // The legacy backend attaches the same probe set and reports
                // the same capabilities, so falling back to it is not a
                // degradation of attribution — only of probe overhead. The
                // active backend is already named by the detection method, so
                // the fentry error belongs in the log, not in the TUI.
                warn!(
                    "eBPF: fentry/fexit unavailable: {}; selected legacy kprobe backend with capabilities {:?}",
                    error_chain_text(&fentry_error),
                    loader.capabilities()
                );
                Ok((Some(loader), DegradationReason::None))
            }
            BackendSelection::TargetBtfUnavailable(error) => {
                warn!(
                    "eBPF: target BTF unavailable: {}; both CO-RE backends require target BTF, using procfs",
                    error_chain_text(&error)
                );
                Ok((None, DegradationReason::BtfUnavailable))
            }
            BackendSelection::BackendsFailed {
                fentry_error,
                kprobe_error,
            } => {
                warn!(
                    "eBPF: all kernel backends failed; fentry/fexit: {}; kprobe: {}; using procfs",
                    error_chain_text(&fentry_error),
                    error_chain_text(&kprobe_error)
                );
                // Both complete chains are in the log above. The reason shown
                // in the TUI is classified from the legacy backend's failure —
                // it is the last one attempted and the one whose EPERM/EACCES
                // and missing-symbol cases have actionable fixes.
                Ok((None, classify_libbpf_error(&kprobe_error)))
            }
        }
    }

    pub fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        match self {
            Self::Fentry(loader) => loader.socket_map(),
            Self::Kprobe(loader) => loader.socket_map(),
        }
    }

    pub fn backend(&self) -> AttributionBackend {
        match self {
            Self::Fentry(_) => AttributionBackend::EbpfFentry,
            Self::Kprobe(_) => AttributionBackend::EbpfKprobe,
        }
    }

    pub fn capabilities(&self) -> AttributionCapabilities {
        match self {
            Self::Fentry(loader) => loader.capabilities,
            Self::Kprobe(loader) => loader.capabilities,
        }
    }

    #[cfg(test)]
    pub(crate) fn load_backend_for_test(backend: AttributionBackend) -> Result<Self> {
        match backend {
            AttributionBackend::EbpfFentry => {
                let kernel_btf =
                    Btf::from_vmlinux().context("load running kernel BTF for fentry test")?;
                FentryLoader::load_program(&kernel_btf).map(Self::Fentry)
            }
            AttributionBackend::EbpfKprobe => KprobeLoader::load_program().map(Self::Kprobe),
            other => Err(anyhow::anyhow!("{other} is not an eBPF backend")),
        }
    }
}

pub struct FentryLoader {
    skel: Box<SocketTrackerFentrySkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
    _links: Vec<libbpf_rs::Link>,
    capabilities: AttributionCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptSignature {
    LegacyFourArguments,
    ProtoAcceptArgument,
}

impl FentryLoader {
    fn load_program(kernel_btf: &Btf<'_>) -> Result<Self> {
        let accept_signature = detect_accept_signature(kernel_btf)?;
        let ping_v4 = optional_sendmsg_compatibility(kernel_btf, "ping_v4_sendmsg");
        let ping_v6 = optional_sendmsg_compatibility(kernel_btf, "ping_v6_sendmsg");

        debug!(
            "eBPF fentry: accept signature {:?}, ping_v4={:?}, ping_v6={:?}",
            accept_signature, ping_v4, ping_v6
        );
        warn_if_optional_incompatible("ping_v4_sendmsg", ping_v4);
        warn_if_optional_incompatible("ping_v6_sendmsg", ping_v6);

        let skel_builder = SocketTrackerFentrySkelBuilder::default();
        let mut open_object = Box::new(std::mem::MaybeUninit::uninit());
        let mut open_skel = skel_builder
            .open(&mut open_object)
            .context("open fentry skeleton")?;
        validate_socket_map(&open_skel.maps.socket_map)?;

        match accept_signature {
            AcceptSignature::LegacyFourArguments => open_skel
                .progs
                .trace_tcp_accept_proto_arg
                .set_autoload(false),
            AcceptSignature::ProtoAcceptArgument => open_skel
                .progs
                .trace_tcp_accept_legacy_signature
                .set_autoload(false),
        }
        if ping_v4 != OptionalProgramCompatibility::Compatible {
            open_skel.progs.trace_ping_v4_sendmsg.set_autoload(false);
        }
        if ping_v6 != OptionalProgramCompatibility::Compatible {
            open_skel.progs.trace_ping_v6_sendmsg.set_autoload(false);
        }

        let skel = open_skel.load().context("load fentry BPF object")?;
        let mut links = Vec::with_capacity(7);
        let mut capabilities = AttributionCapabilities::empty();

        macro_rules! attach_required {
            ($program:expr, $name:literal, $capability:expr) => {{
                let link = $program
                    .attach()
                    .with_context(|| format!("attach fentry/fexit {}", $name))?;
                links.push(link);
                capabilities.insert($capability);
            }};
        }

        attach_required!(
            skel.progs.trace_tcp_connect,
            "tcp_connect",
            AttributionCapabilities::TCP_V4_CONNECT
        );
        attach_required!(
            skel.progs.trace_tcp_v6_connect,
            "tcp_v6_connect",
            AttributionCapabilities::TCP_V6_CONNECT
        );
        attach_required!(
            skel.progs.trace_udp_sendmsg,
            "udp_sendmsg",
            AttributionCapabilities::UDP_V4_SEND
        );
        attach_required!(
            skel.progs.trace_udp_v6_sendmsg,
            "udpv6_sendmsg",
            AttributionCapabilities::UDP_V6_SEND
        );
        match accept_signature {
            AcceptSignature::LegacyFourArguments => attach_required!(
                skel.progs.trace_tcp_accept_legacy_signature,
                "inet_csk_accept (legacy signature)",
                AttributionCapabilities::TCP_ACCEPT
            ),
            AcceptSignature::ProtoAcceptArgument => attach_required!(
                skel.progs.trace_tcp_accept_proto_arg,
                "inet_csk_accept (proto_accept_arg signature)",
                AttributionCapabilities::TCP_ACCEPT
            ),
        }

        if ping_v4 == OptionalProgramCompatibility::Compatible {
            attach_optional(
                skel.progs.trace_ping_v4_sendmsg.attach(),
                "fentry/ping_v4_sendmsg",
                AttributionCapabilities::ICMP_V4_SEND,
                &mut links,
                &mut capabilities,
            );
        }
        if ping_v6 == OptionalProgramCompatibility::Compatible {
            attach_optional(
                skel.progs.trace_ping_v6_sendmsg.attach(),
                "fentry/ping_v6_sendmsg",
                AttributionCapabilities::ICMP_V6_SEND,
                &mut links,
                &mut capabilities,
            );
        }

        debug_assert!(capabilities.contains(CORE_CAPABILITIES));

        // SAFETY: The skeleton borrows from open_object. Both are stored in
        // this loader, open_object has a stable Box address, and skel is
        // declared first so it is dropped before open_object.
        let skel_static: SocketTrackerFentrySkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel: Box::new(skel_static),
            _open_object: open_object,
            _links: links,
            capabilities,
        })
    }

    fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        &self.skel.maps.socket_map
    }
}

pub struct KprobeLoader {
    skel: Box<SocketTrackerKprobeSkel<'static>>,
    _open_object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
    _links: Vec<libbpf_rs::Link>,
    capabilities: AttributionCapabilities,
}

impl KprobeLoader {
    fn load_program() -> Result<Self> {
        debug!("eBPF kprobe: opening legacy skeleton");
        let skel_builder = SocketTrackerKprobeSkelBuilder::default();
        let mut open_object = Box::new(std::mem::MaybeUninit::uninit());
        let open_skel = skel_builder
            .open(&mut open_object)
            .context("open kprobe skeleton")?;
        validate_socket_map(&open_skel.maps.socket_map)?;
        let skel = open_skel.load().context("load kprobe BPF object")?;

        let mut links = Vec::with_capacity(6);
        let mut capabilities = AttributionCapabilities::empty();

        macro_rules! attach_required {
            ($program:expr, $name:literal, $capability:expr) => {{
                let link = $program
                    .attach()
                    .with_context(|| format!("attach legacy probe {}", $name))?;
                links.push(link);
                capabilities.insert($capability);
            }};
        }

        // tcp_connect is the common tail of both address families, so one
        // probe covers IPv4, IPv6, and dual-stack connects.
        attach_required!(
            skel.progs.trace_tcp_connect,
            "kprobe/tcp_connect",
            AttributionCapabilities::TCP_V4_CONNECT | AttributionCapabilities::TCP_V6_CONNECT
        );
        attach_required!(
            skel.progs.trace_udp_sendmsg,
            "kprobe/udp_sendmsg",
            AttributionCapabilities::UDP_V4_SEND
        );
        attach_required!(
            skel.progs.trace_udp_v6_sendmsg,
            "kprobe/udpv6_sendmsg",
            AttributionCapabilities::UDP_V6_SEND
        );
        attach_required!(
            skel.progs.trace_tcp_accept,
            "kretprobe/inet_csk_accept",
            AttributionCapabilities::TCP_ACCEPT
        );

        attach_optional(
            skel.progs.trace_ping_v4_sendmsg.attach(),
            "kprobe/ping_v4_sendmsg",
            AttributionCapabilities::ICMP_V4_SEND,
            &mut links,
            &mut capabilities,
        );
        attach_optional(
            skel.progs.trace_ping_v6_sendmsg.attach(),
            "kprobe/ping_v6_sendmsg",
            AttributionCapabilities::ICMP_V6_SEND,
            &mut links,
            &mut capabilities,
        );

        debug_assert!(capabilities.contains(CORE_CAPABILITIES));

        // SAFETY: See the corresponding FentryLoader safety comment.
        let skel_static: SocketTrackerKprobeSkel<'static> = unsafe { std::mem::transmute(skel) };

        Ok(Self {
            skel: Box::new(skel_static),
            _open_object: open_object,
            _links: links,
            capabilities,
        })
    }

    fn socket_map(&self) -> &libbpf_rs::Map<'_> {
        &self.skel.maps.socket_map
    }
}

fn validate_socket_map(map: &libbpf_rs::OpenMap<'_>) -> Result<()> {
    validate_socket_map_layout(map.key_size(), map.value_size())
}

fn validate_socket_map_layout(key_size: u32, value_size: u32) -> Result<()> {
    ensure!(
        key_size as usize == CONN_KEY_SIZE,
        "socket_map key size mismatch: BPF object uses {key_size} bytes, Rust expects {CONN_KEY_SIZE}"
    );
    ensure!(
        value_size as usize == CONN_INFO_SIZE,
        "socket_map value size mismatch: BPF object uses {value_size} bytes, Rust expects {CONN_INFO_SIZE}"
    );
    Ok(())
}

fn attach_optional(
    result: libbpf_rs::Result<libbpf_rs::Link>,
    name: &str,
    capability: AttributionCapabilities,
    links: &mut Vec<libbpf_rs::Link>,
    capabilities: &mut AttributionCapabilities,
) {
    match result {
        Ok(link) => {
            debug!("eBPF: attached optional probe {name}");
            links.push(link);
            capabilities.insert(capability);
        }
        Err(error) => {
            warn!(
                "eBPF: optional probe {name} unavailable: {error}; continuing with partial coverage"
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OptionalProgramCompatibility {
    Missing,
    Compatible,
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BtfTypeShape {
    SignedInteger(usize),
    UnsignedInteger(usize),
    PointerTo(String),
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSignature {
    return_type: BtfTypeShape,
    parameters: Vec<BtfTypeShape>,
}

fn optional_sendmsg_compatibility(btf: &Btf<'_>, name: &str) -> OptionalProgramCompatibility {
    let Some(func) = btf.type_by_name::<Func<'_>>(name) else {
        return OptionalProgramCompatibility::Missing;
    };
    let Ok(proto) = FuncProto::try_from(func.referenced_type()) else {
        return OptionalProgramCompatibility::Incompatible;
    };
    let Some(pointer_size) = btf.ptr_size().ok().map(|size| size.get()) else {
        return OptionalProgramCompatibility::Incompatible;
    };
    let Some(signature) = function_signature(btf, &proto) else {
        return OptionalProgramCompatibility::Incompatible;
    };

    if is_expected_sendmsg_signature(&signature, pointer_size) {
        OptionalProgramCompatibility::Compatible
    } else {
        OptionalProgramCompatibility::Incompatible
    }
}

fn function_signature(btf: &Btf<'_>, proto: &FuncProto<'_>) -> Option<FunctionSignature> {
    let return_type = btf_type_shape(btf, proto.referenced_type_id())?;
    let parameters = proto
        .iter()
        .map(|parameter| btf_type_shape(btf, parameter.ty))
        .collect::<Option<Vec<_>>>()?;

    Some(FunctionSignature {
        return_type,
        parameters,
    })
}

fn btf_type_shape(btf: &Btf<'_>, type_id: libbpf_rs::btf::TypeId) -> Option<BtfTypeShape> {
    let raw_type = btf.type_by_id::<BtfType<'_>>(type_id)?;
    let canonical_type = raw_type.skip_mods_and_typedefs();

    match canonical_type.kind() {
        BtfKind::Int => {
            let int = Int::try_from(canonical_type).ok()?;
            let size = int.size();
            match int.encoding {
                IntEncoding::Signed => Some(BtfTypeShape::SignedInteger(size)),
                IntEncoding::None => Some(BtfTypeShape::UnsignedInteger(size)),
                IntEncoding::Char | IntEncoding::Bool => Some(BtfTypeShape::Other),
            }
        }
        BtfKind::Ptr => {
            let pointed_to = canonical_type.next_type()?.skip_mods_and_typedefs();
            let name = pointed_to.name()?.to_str()?.to_string();
            Some(BtfTypeShape::PointerTo(name))
        }
        _ => Some(BtfTypeShape::Other),
    }
}

fn expected_sendmsg_signature(pointer_size: usize) -> FunctionSignature {
    FunctionSignature {
        return_type: BtfTypeShape::SignedInteger(4),
        parameters: vec![
            BtfTypeShape::PointerTo("sock".to_string()),
            BtfTypeShape::PointerTo("msghdr".to_string()),
            BtfTypeShape::UnsignedInteger(pointer_size),
        ],
    }
}

fn is_expected_sendmsg_signature(signature: &FunctionSignature, pointer_size: usize) -> bool {
    signature == &expected_sendmsg_signature(pointer_size)
}

fn warn_if_optional_incompatible(name: &str, compatibility: OptionalProgramCompatibility) {
    if compatibility == OptionalProgramCompatibility::Incompatible {
        warn!(
            "eBPF fentry: optional probe {name} has an incompatible BTF prototype; disabling it before object load"
        );
    }
}

fn detect_accept_signature(btf: &Btf<'_>) -> Result<AcceptSignature> {
    let func: Func<'_> = btf
        .type_by_name("inet_csk_accept")
        .context("inet_csk_accept is absent from kernel BTF")?;
    let proto = FuncProto::try_from(func.referenced_type())
        .map_err(|_| anyhow::anyhow!("inet_csk_accept BTF entry has no function prototype"))?;

    match proto.iter().len() {
        4 => Ok(AcceptSignature::LegacyFourArguments),
        2 => Ok(AcceptSignature::ProtoAcceptArgument),
        count => Err(anyhow::anyhow!(
            "unsupported inet_csk_accept BTF signature with {count} arguments"
        )),
    }
}

fn select_backend_with_target_btf<B, T, E>(
    target_btf: std::result::Result<B, E>,
    fentry: impl FnOnce(&B) -> std::result::Result<T, E>,
    kprobe: impl FnOnce(&B) -> std::result::Result<T, E>,
) -> BackendSelection<T, E> {
    let target_btf = match target_btf {
        Ok(target_btf) => target_btf,
        Err(error) => return BackendSelection::TargetBtfUnavailable(error),
    };

    match fentry(&target_btf) {
        Ok(loader) => BackendSelection::Selected {
            loader,
            fentry_error: None,
        },
        Err(fentry_error) => match kprobe(&target_btf) {
            Ok(loader) => BackendSelection::Selected {
                loader,
                fentry_error: Some(fentry_error),
            },
            Err(kprobe_error) => BackendSelection::BackendsFailed {
                fentry_error,
                kprobe_error,
            },
        },
    }
}

fn error_chain_text(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn check_capabilities_detailed() -> DegradationReason {
    use std::fs;

    // Root holds every capability. Check that first so an unreadable or
    // unparsable /proc/self/status (minimal container images, a namespace
    // without /proc mounted) cannot downgrade a privileged run to procfs.
    // SAFETY: geteuid never fails and touches no memory.
    if unsafe { libc::geteuid() } == 0 {
        debug!("eBPF: running as root, all capabilities available");
        return DegradationReason::None;
    }

    if let Ok(status) = fs::read_to_string("/proc/self/status")
        && let Some(cap_line) = status.lines().find(|line| line.starts_with("CapEff:"))
        && let Some(cap_hex) = cap_line.split_whitespace().nth(1)
        && let Ok(cap_value) = u64::from_str_radix(cap_hex, 16)
    {
        const CAP_SYS_ADMIN: u64 = 21;
        const CAP_PERFMON: u64 = 38;
        const CAP_BPF: u64 = 39;

        let has_bpf = (cap_value & (1u64 << CAP_BPF)) != 0;
        let has_perfmon = (cap_value & (1u64 << CAP_PERFMON)) != 0;
        let has_sys_admin = (cap_value & (1u64 << CAP_SYS_ADMIN)) != 0;

        if has_bpf && has_perfmon || has_sys_admin {
            return DegradationReason::None;
        }
        if !has_bpf && !has_perfmon {
            return DegradationReason::MissingBpfCapabilities;
        }
        if !has_bpf {
            return DegradationReason::MissingCapBpf;
        }
        return DegradationReason::MissingCapPerfmon;
    }

    DegradationReason::MissingBpfCapabilities
}

/// Detect whether file capabilities are ignored because the executable is on
/// a filesystem mounted with `nosuid`.
fn executable_on_nosuid_mount() -> bool {
    use std::fs;
    use std::path::Path;

    let exe = match fs::read_link("/proc/self/exe") {
        Ok(path) => path,
        Err(error) => {
            debug!("nosuid check: failed to resolve /proc/self/exe: {error}");
            return false;
        }
    };
    let mountinfo = match fs::read_to_string("/proc/self/mountinfo") {
        Ok(contents) => contents,
        Err(error) => {
            debug!("nosuid check: failed to read /proc/self/mountinfo: {error}");
            return false;
        }
    };

    let mut best: Option<(usize, &str)> = None;
    for line in mountinfo.lines() {
        let mut fields = line.split_whitespace();
        let mountpoint = match fields.nth(4) {
            Some(mountpoint) => mountpoint,
            None => continue,
        };
        let options = match fields.next() {
            Some(options) => options,
            None => continue,
        };
        if Path::new(mountpoint).is_ancestor_of_or_equal(&exe) {
            let len = mountpoint.len();
            if best.map(|(current, _)| len > current).unwrap_or(true) {
                best = Some((len, options));
            }
        }
    }

    best.map(|(_, options)| options.split(',').any(|option| option == "nosuid"))
        .unwrap_or(false)
}

trait PathAncestorExt {
    fn is_ancestor_of_or_equal(&self, other: &std::path::Path) -> bool;
}

impl PathAncestorExt for std::path::Path {
    fn is_ancestor_of_or_equal(&self, other: &std::path::Path) -> bool {
        let mut ancestor = self.components();
        let mut descendant = other.components();
        loop {
            match (ancestor.next(), descendant.next()) {
                (Some(left), Some(right)) if left == right => continue,
                (None, _) => return true,
                _ => return false,
            }
        }
    }
}

/// Map a libbpf failure onto the most actionable degradation reason.
///
/// The returned text is capped so the TUI's indented reason line stays within
/// the two rows the Statistics pane budgets for it.
fn classify_libbpf_error(err: &anyhow::Error) -> DegradationReason {
    let blob = error_chain_text(err).to_lowercase();

    if blob.contains("btf") || blob.contains("vmlinux") || blob.contains("co-re") {
        return DegradationReason::BtfUnavailable;
    }
    if blob.contains("function not implemented") || blob.contains("enosys") {
        return DegradationReason::KernelUnsupported;
    }
    if blob.contains("operation not permitted")
        || blob.contains("permission denied")
        || blob.contains("eperm")
        || blob.contains("eacces")
        || blob.contains("-eacces")
    {
        return DegradationReason::BpfPermissionDenied;
    }
    if blob.contains("attach") || blob.contains("kprobe") || blob.contains("perf_event_open") {
        return DegradationReason::KprobeAttachFailed(
            extract_kprobe_symbol(&blob).unwrap_or_default(),
        );
    }

    let mut text = err.to_string();
    const MAX_LEN: usize = 100;
    if text.len() > MAX_LEN {
        text.truncate(MAX_LEN);
        text.push('…');
    }
    DegradationReason::EbpfLoadFailed(text)
}

fn extract_kprobe_symbol(blob: &str) -> Option<String> {
    for prefix in ["attach kprobe ", "kprobe/", "kprobe '"] {
        if let Some(rest) = blob.split(prefix).nth(1) {
            let symbol: String = rest
                .chars()
                .take_while(|character| character.is_alphanumeric() || *character == '_')
                .collect();
            if !symbol.is_empty() {
                return Some(symbol);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::cell::Cell;

    #[test]
    fn socket_map_layout_matches_rust_types() {
        assert!(validate_socket_map_layout(CONN_KEY_SIZE as u32, CONN_INFO_SIZE as u32).is_ok());
    }

    #[test]
    fn socket_map_layout_rejects_key_size_mismatch() {
        let error = validate_socket_map_layout(CONN_KEY_SIZE as u32 + 1, CONN_INFO_SIZE as u32)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "socket_map key size mismatch: BPF object uses 41 bytes, Rust expects 40"
        );
    }

    #[test]
    fn socket_map_layout_rejects_value_size_mismatch() {
        let error = validate_socket_map_layout(CONN_KEY_SIZE as u32, CONN_INFO_SIZE as u32 + 1)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "socket_map value size mismatch: BPF object uses 41 bytes, Rust expects 40"
        );
    }

    #[test]
    fn backend_selection_prefers_fentry_without_trying_kprobe() {
        let kprobe_called = Cell::new(false);
        let selected = select_backend_with_target_btf(
            Ok::<_, &'static str>(()),
            |_| Ok::<_, &'static str>("fentry"),
            |_| {
                kprobe_called.set(true);
                Ok("kprobe")
            },
        );

        assert_eq!(
            selected,
            BackendSelection::Selected {
                loader: "fentry",
                fentry_error: None
            }
        );
        assert!(!kprobe_called.get());
    }

    #[test]
    fn backend_selection_falls_back_to_kprobe() {
        let selected =
            select_backend_with_target_btf(Ok(()), |_| Err("fentry failed"), |_| Ok("kprobe"));
        assert_eq!(
            selected,
            BackendSelection::Selected {
                loader: "kprobe",
                fentry_error: Some("fentry failed")
            }
        );
    }

    #[test]
    fn backend_selection_retains_both_failures() {
        let selected = select_backend_with_target_btf::<(), (), _>(
            Ok(()),
            |_| Err("fentry failed"),
            |_| Err("kprobe failed"),
        );
        assert_eq!(
            selected,
            BackendSelection::BackendsFailed {
                fentry_error: "fentry failed",
                kprobe_error: "kprobe failed"
            }
        );
    }

    #[test]
    fn missing_target_btf_skips_both_kernel_backends() {
        let fentry_called = Cell::new(false);
        let kprobe_called = Cell::new(false);
        let selected = select_backend_with_target_btf::<(), (), _>(
            Err("target BTF missing"),
            |_| {
                fentry_called.set(true);
                Ok(())
            },
            |_| {
                kprobe_called.set(true);
                Ok(())
            },
        );

        assert_eq!(
            selected,
            BackendSelection::TargetBtfUnavailable("target BTF missing")
        );
        assert!(!fentry_called.get());
        assert!(!kprobe_called.get());
    }

    #[test]
    fn optional_sendmsg_signature_requires_expected_argument_types() {
        let expected = expected_sendmsg_signature(8);
        assert!(is_expected_sendmsg_signature(&expected, 8));
        assert!(!is_expected_sendmsg_signature(&expected, 4));

        let wrong_message_type = FunctionSignature {
            return_type: BtfTypeShape::SignedInteger(4),
            parameters: vec![
                BtfTypeShape::PointerTo("sock".to_string()),
                BtfTypeShape::PointerTo("mmsghdr".to_string()),
                BtfTypeShape::UnsignedInteger(8),
            ],
        };
        assert!(!is_expected_sendmsg_signature(&wrong_message_type, 8));

        let missing_length = FunctionSignature {
            return_type: BtfTypeShape::SignedInteger(4),
            parameters: vec![
                BtfTypeShape::PointerTo("sock".to_string()),
                BtfTypeShape::PointerTo("msghdr".to_string()),
            ],
        };
        assert!(!is_expected_sendmsg_signature(&missing_length, 8));
    }

    #[test]
    fn optional_probe_failure_represents_partial_capabilities() {
        let mut capabilities = CORE_CAPABILITIES;
        capabilities.insert(AttributionCapabilities::ICMP_V4_SEND);

        assert!(capabilities.contains(CORE_CAPABILITIES));
        assert!(capabilities.contains(AttributionCapabilities::ICMP_V4_SEND));
        assert!(!capabilities.contains(AttributionCapabilities::ICMP_V6_SEND));
    }

    #[test]
    fn classifies_btf_error() {
        let error = anyhow!("failed to load: BTF type 42 missing");
        assert_eq!(
            classify_libbpf_error(&error),
            DegradationReason::BtfUnavailable
        );
    }

    #[test]
    fn classifies_eperm_as_permission_denied() {
        let error = anyhow!("bpf(BPF_PROG_LOAD): Operation not permitted");
        assert_eq!(
            classify_libbpf_error(&error),
            DegradationReason::BpfPermissionDenied
        );
    }

    #[test]
    fn classifies_eacces_from_perf_event_open() {
        let error = anyhow!(
            "libbpf: prog 'trace_tcp_connect': failed to create kprobe \
             'tcp_connect+0x0' perf event: -EACCES"
        );
        assert_eq!(
            classify_libbpf_error(&error),
            DegradationReason::BpfPermissionDenied
        );
    }

    #[test]
    fn classifies_kprobe_attach_with_symbol() {
        let error = anyhow!("failed to attach kprobe ping_v6_sendmsg: No such file or directory");
        assert_eq!(
            classify_libbpf_error(&error),
            DegradationReason::KprobeAttachFailed("ping_v6_sendmsg".to_string())
        );
    }

    #[test]
    fn classifies_enosys_as_kernel_unsupported() {
        let error = anyhow!("bpf syscall: Function not implemented");
        assert_eq!(
            classify_libbpf_error(&error),
            DegradationReason::KernelUnsupported
        );
    }

    #[test]
    fn falls_back_to_ebpf_load_failed_with_truncation() {
        let error = anyhow!("{}", "x".repeat(500));
        match classify_libbpf_error(&error) {
            DegradationReason::EbpfLoadFailed(text) => {
                assert!(text.chars().count() <= 101);
                assert!(text.ends_with('…'));
            }
            other => panic!("expected EbpfLoadFailed, got {other:?}"),
        }
    }
}
