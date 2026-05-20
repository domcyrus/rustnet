// network/kubernetes.rs - Kubernetes pod/container resolution
//
// Parses `/proc/<pid>/cgroup` to recover the pod UID and container ID of the
// process owning a connection. The pure parser (`parse_cgroup`) is
// cross-platform so it stays unit-testable on non-Linux developer machines;
// the procfs reader (`lookup_for_pid`) is Linux-only.
//
// Recognised cgroup layouts:
//   - cgroup v1 systemd:
//     `.../kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<UID>.slice/<runtime>-<CID>.scope`
//   - cgroup v2 unified:
//     `0::/kubepods/<qos>/pod<UID>/<CID>` or `.../pod<UID>/<runtime>-<CID>.scope`
//   - Runtime prefixes stripped from the container ID: `cri-containerd-`,
//     `crio-`, `docker-`. Bare 64-hex IDs are also accepted.
//
// Pod UID normalisation: Kubernetes pod UIDs are UUIDs (8-4-4-4-12 hex). systemd
// encodes them with underscores instead of hyphens. The parser yields the
// hyphenated, lowercase canonical form so callers can compare against
// `kubectl get pod ... metadata.uid` directly.

/// Raw data recovered from a process's cgroup membership before pairing with
/// pod metadata (which lives in `K8sInfo`). The parser only runs on Linux at
/// runtime, but the pure logic is also compiled in tests so it stays
/// exercisable on developer machines.
#[cfg(any(test, target_os = "linux"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupInfo {
    pub pod_uid: Option<String>,
    pub container_id: Option<String>,
    pub cgroup_path: String,
}

/// Parse the contents of a `/proc/<pid>/cgroup` file and return the
/// kubepods-related info if any line refers to a Kubernetes pod. Returns
/// `None` for processes that aren't part of a pod cgroup.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_cgroup(contents: &str) -> Option<CgroupInfo> {
    let path = contents
        .lines()
        .map(extract_path)
        .find(|p| p.contains("kubepods"))?;

    let pod_uid = path.split('/').find_map(extract_pod_uid);
    let container_id = path.rsplit('/').find_map(extract_container_id);

    Some(CgroupInfo {
        pod_uid,
        container_id,
        cgroup_path: path.to_string(),
    })
}

/// Read `/proc/<pid>/cgroup` and parse it. Returns `None` if the file is
/// unreadable (PID gone, permissions) or the process isn't in a pod cgroup.
#[cfg(target_os = "linux")]
pub fn lookup_for_pid(pid: u32) -> Option<CgroupInfo> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup(&contents)
}

/// Runtime control for Kubernetes pod/container attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KubernetesMode {
    /// Enable only when rustnet is itself running inside a pod (the common
    /// `kubectl rustnet` case). A no-op on ordinary hosts, so there is no
    /// wasted `/proc` scanning when not in Kubernetes.
    #[default]
    Auto,
    /// Always attempt attribution (e.g. running directly on a node).
    On,
    /// Never attempt attribution.
    Off,
}

impl KubernetesMode {
    /// Parse the `--kubernetes` flag value. Returns `None` for unknown input.
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    /// Whether attribution should run, resolving `Auto` by pod detection.
    pub fn enabled(self) -> bool {
        match self {
            Self::On => true,
            Self::Off => false,
            Self::Auto => running_in_pod(),
        }
    }
}

/// Whether the current process is running inside a Kubernetes pod. Uses the
/// `KUBERNETES_SERVICE_HOST` env var, which the kubelet injects into every pod
/// (the same signal client-go uses for in-cluster detection). This is reliable
/// regardless of cgroup namespacing, unlike inspecting `/proc/self/cgroup`,
/// which a namespaced pod sees as just `/`.
pub fn running_in_pod() -> bool {
    std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

/// Resolves a PID to its pod and container metadata.
///
/// The cgroup-derived part (pod UID, container ID, cgroup path) is cached per
/// PID since cgroup membership is stable for the life of a PID. Human-readable
/// names come from a separately-refreshed [`PodMetadata`] table and are merged
/// in on every lookup, so a pod's name appears as soon as the next metadata
/// refresh observes it.
pub struct KubernetesResolver {
    cache: dashmap::DashMap<u32, crate::network::types::K8sInfo>,
    metadata: std::sync::RwLock<PodMetadata>,
}

impl KubernetesResolver {
    pub fn new() -> Self {
        Self {
            cache: dashmap::DashMap::new(),
            metadata: std::sync::RwLock::new(PodMetadata::load()),
        }
    }

    /// Look up pod and container info for a process. On non-Linux platforms
    /// always returns `None` so callers can stay platform-agnostic.
    pub fn enrich(&self, pid: u32) -> Option<crate::network::types::K8sInfo> {
        let mut info = if let Some(cached) = self.cache.get(&pid) {
            cached.clone()
        } else {
            let base = self.fetch(pid)?;
            self.cache.insert(pid, base.clone());
            base
        };
        if let Ok(meta) = self.metadata.read() {
            meta.apply(&mut info);
        }
        Some(info)
    }

    /// Reload the on-disk pod metadata table. Cheap (a directory read) and
    /// safe to call on the enrichment refresh tick.
    pub fn refresh_metadata(&self) {
        if let Ok(mut meta) = self.metadata.write() {
            *meta = PodMetadata::load();
        }
    }

    #[cfg(target_os = "linux")]
    fn fetch(&self, pid: u32) -> Option<crate::network::types::K8sInfo> {
        let cg = lookup_for_pid(pid)?;
        Some(crate::network::types::K8sInfo {
            pod_uid: cg.pod_uid,
            container_id: cg.container_id,
            cgroup_path: Some(cg.cgroup_path),
            pod_name: None,
            pod_namespace: None,
            container_name: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn fetch(&self, _pid: u32) -> Option<crate::network::types::K8sInfo> {
        None
    }
}

impl Default for KubernetesResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Pod and container names indexed for enrichment, sourced from the
/// kubelet-managed log directories (runtime-agnostic, no auth, no gRPC):
///
///   - `/var/log/containers/<pod>_<namespace>_<container>-<cid>.log` symlinks
///     give container ID -> (pod name, namespace, container name).
///   - `/var/log/pods/<namespace>_<pod>_<uid>/` directories give pod UID ->
///     (pod name, namespace), used as a fallback when a connection is
///     attributed to a pod's sandbox container (which has no log symlink).
#[derive(Debug, Default)]
pub struct PodMetadata {
    by_container_id: std::collections::HashMap<String, ContainerMeta>,
    by_pod_uid: std::collections::HashMap<String, PodMeta>,
}

#[derive(Debug, Clone)]
struct ContainerMeta {
    pod_name: String,
    namespace: String,
    container_name: String,
}

#[derive(Debug, Clone)]
struct PodMeta {
    pod_name: String,
    namespace: String,
}

impl PodMetadata {
    /// Load the metadata table from the kubelet log directories. Linux-only;
    /// returns an empty table on other platforms or when the directories are
    /// not present (e.g. not running on a node, or the mount is missing).
    #[cfg(target_os = "linux")]
    pub fn load() -> Self {
        let mut by_container_id = std::collections::HashMap::new();
        if let Ok(dir) = std::fs::read_dir("/var/log/containers") {
            for entry in dir.flatten() {
                let name = entry.file_name();
                let name = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if let Some((cid, meta)) = parse_container_log_name(name) {
                    by_container_id.insert(cid, meta);
                }
            }
        }

        let mut by_pod_uid = std::collections::HashMap::new();
        if let Ok(dir) = std::fs::read_dir("/var/log/pods") {
            for entry in dir.flatten() {
                let name = entry.file_name();
                let name = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if let Some((uid, meta)) = parse_pod_dir_name(name) {
                    by_pod_uid.insert(uid, meta);
                }
            }
        }

        Self {
            by_container_id,
            by_pod_uid,
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load() -> Self {
        Self::default()
    }

    /// Fill in the human-readable name fields of a [`K8sInfo`] from the table.
    /// Container-ID match (precise) is preferred; pod-UID match is the fallback
    /// for connections attributed to a pod's sandbox container.
    fn apply(&self, info: &mut crate::network::types::K8sInfo) {
        if let Some(cid) = &info.container_id
            && let Some(meta) = self.by_container_id.get(cid)
        {
            info.pod_name = Some(meta.pod_name.clone());
            info.pod_namespace = Some(meta.namespace.clone());
            info.container_name = Some(meta.container_name.clone());
            return;
        }
        if info.pod_name.is_none()
            && let Some(uid) = &info.pod_uid
            && let Some(meta) = self.by_pod_uid.get(uid)
        {
            info.pod_name = Some(meta.pod_name.clone());
            info.pod_namespace = Some(meta.namespace.clone());
        }
    }
}

/// Parse a `/var/log/containers/` symlink filename of the form
/// `<pod-name>_<namespace>_<container-name>-<container-id>.log`. Pod,
/// namespace, and container names are RFC 1123 labels (no underscores), so the
/// first two `_` delimit pod and namespace; the trailing 64-hex container ID is
/// split off the remainder. Returns `(container_id, ContainerMeta)`.
#[cfg(any(test, target_os = "linux"))]
fn parse_container_log_name(filename: &str) -> Option<(String, ContainerMeta)> {
    let stem = filename.strip_suffix(".log")?;
    let mut parts = stem.splitn(3, '_');
    let pod_name = parts.next()?;
    let namespace = parts.next()?;
    let rest = parts.next()?; // "<container-name>-<container-id>"
    let dash = rest.rfind('-')?;
    let container_name = &rest[..dash];
    let container_id = &rest[dash + 1..];
    if container_id.len() != 64 || !container_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    if pod_name.is_empty() || namespace.is_empty() || container_name.is_empty() {
        return None;
    }
    Some((
        container_id.to_string(),
        ContainerMeta {
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
            container_name: container_name.to_string(),
        },
    ))
}

/// Parse a `/var/log/pods/` directory name of the form
/// `<namespace>_<pod-name>_<pod-uid>`. Returns `(pod_uid, PodMeta)`.
#[cfg(any(test, target_os = "linux"))]
fn parse_pod_dir_name(name: &str) -> Option<(String, PodMeta)> {
    let mut parts = name.splitn(3, '_');
    let namespace = parts.next()?;
    let pod_name = parts.next()?;
    let uid = parts.next()?;
    if namespace.is_empty() || pod_name.is_empty() || uid.is_empty() {
        return None;
    }
    Some((
        uid.to_string(),
        PodMeta {
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
        },
    ))
}

// ---------------------------------------------------------------------------
// Per-PID procfs socket table for cross-namespace attribution.
//
// Under `hostNetwork: true`, the standard procfs path reads `/proc/net/tcp`
// from the host network namespace, so it cannot see sockets owned by pods in
// their own netns. The per-PID file `/proc/<pid>/net/tcp` IS netns-aware: it
// shows the TCP table from the PID's network namespace. By walking
// `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` for every PID known to live in a
// kubepods cgroup, we get a netns-aware view of all pod sockets on the node.
//
// Cost is modest: a node typically runs a few dozen kubepods PIDs, the files
// are tiny (one line per active socket), and the table is rebuilt only on the
// enrichment refresh tick.
// ---------------------------------------------------------------------------

/// IP protocol distinction for the socket table key. We track TCP and UDP
/// separately because the same 4-tuple can be reused across protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketProtocol {
    Tcp,
    Udp,
}

/// Lookup key matching what `network::types::ConnectionKey` would produce:
/// the connection's 4-tuple plus its transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketKey {
    pub protocol: SocketProtocol,
    pub local: std::net::SocketAddr,
    pub remote: std::net::SocketAddr,
}

/// Built from a sweep of `/proc/*/net/{tcp,tcp6,udp,udp6}` for kubepods PIDs.
/// Provides O(1) lookup by socket 4-tuple to (pid, K8sInfo).
pub struct KubernetesSocketTable {
    by_key: std::collections::HashMap<SocketKey, (u32, crate::network::types::K8sInfo)>,
}

impl KubernetesSocketTable {
    pub fn empty() -> Self {
        Self {
            by_key: std::collections::HashMap::new(),
        }
    }

    /// Rebuild the table by walking `/proc/*/cgroup` to find kubepods PIDs and
    /// then reading each one's per-PID network tables. Linux-only; the no-op
    /// stub on other platforms returns an empty table.
    #[cfg(target_os = "linux")]
    pub fn build(resolver: &KubernetesResolver) -> Self {
        let mut by_key = std::collections::HashMap::new();
        for pid in discover_kubepods_pids() {
            let k8s = match resolver.enrich(pid) {
                Some(info) => info,
                None => continue,
            };
            for file in ["tcp", "tcp6", "udp", "udp6"] {
                let path = format!("/proc/{pid}/net/{file}");
                let contents = match std::fs::read_to_string(&path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let proto = if file.starts_with("tcp") {
                    SocketProtocol::Tcp
                } else {
                    SocketProtocol::Udp
                };
                let is_v6 = file.ends_with('6');
                for line in contents.lines().skip(1) {
                    if let Some(key) = parse_proc_net_line(line, proto, is_v6) {
                        by_key.entry(key).or_insert_with(|| (pid, k8s.clone()));
                    }
                }
            }
        }
        Self { by_key }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn build(_resolver: &KubernetesResolver) -> Self {
        Self::empty()
    }

    /// Look up a (pid, K8sInfo) for the given socket 4-tuple. Returns `None`
    /// when the tuple isn't owned by any kubepods PID.
    pub fn lookup(&self, key: &SocketKey) -> Option<&(u32, crate::network::types::K8sInfo)> {
        self.by_key.get(key)
    }

    /// Look up by a rustnet `Connection`, trying both 4-tuple orderings.
    /// rustnet's local/remote orientation is derived from observed packet
    /// direction and may not match the socket's local/remote orientation, so
    /// we probe both. Non-TCP/UDP protocols never have socket-table entries.
    pub fn lookup_connection(
        &self,
        conn: &crate::network::types::Connection,
    ) -> Option<(u32, crate::network::types::K8sInfo)> {
        use crate::network::types::Protocol;
        let protocol = match conn.protocol {
            Protocol::Tcp => SocketProtocol::Tcp,
            Protocol::Udp => SocketProtocol::Udp,
            _ => return None,
        };
        let forward = SocketKey {
            protocol,
            local: conn.local_addr,
            remote: conn.remote_addr,
        };
        let reverse = SocketKey {
            protocol,
            local: conn.remote_addr,
            remote: conn.local_addr,
        };
        self.lookup(&forward)
            .or_else(|| self.lookup(&reverse))
            .cloned()
    }
}

/// Read a process's short name from `/proc/<pid>/comm`. Used to fill in a
/// process name for connections attributed via the socket table (which yields
/// a PID but not a name). Linux-only; returns `None` elsewhere.
#[cfg(target_os = "linux")]
pub fn read_process_name(pid: u32) -> Option<String> {
    let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn read_process_name(_pid: u32) -> Option<String> {
    None
}

/// Enumerate numeric `/proc/<pid>` entries and return those whose
/// `/proc/<pid>/cgroup` mentions `kubepods`.
#[cfg(target_os = "linux")]
fn discover_kubepods_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return pids,
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s,
            None => continue,
        };
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Avoid an extra fs::metadata call; rely on /proc/<pid>/cgroup being
        // readable as proof the PID exists and is accessible to us.
        if let Ok(cg) = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            && cg.contains("kubepods")
        {
            pids.push(pid);
        }
    }
    pids
}

/// Parse a single line of `/proc/<pid>/net/{tcp,tcp6,udp,udp6}`. The format
/// looks like:
///
///   sl  local_address rem_address  st  tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
///
/// Address columns are hex-encoded. IPv4 is 8 hex chars representing a u32 in
/// host byte order (the kernel printed the `__be32` value with `%08X`, so on
/// little-endian boxes the byte order is reversed). IPv6 is 32 hex chars
/// representing four u32s, each printed in host byte order.
#[cfg(any(test, target_os = "linux"))]
pub fn parse_proc_net_line(line: &str, protocol: SocketProtocol, is_v6: bool) -> Option<SocketKey> {
    let mut fields = line.split_whitespace();
    // Skip the "sl" column.
    fields.next()?;
    let local_raw = fields.next()?;
    let remote_raw = fields.next()?;
    let local = parse_addr_port(local_raw, is_v6)?;
    let remote = parse_addr_port(remote_raw, is_v6)?;
    Some(SocketKey {
        protocol,
        local,
        remote,
    })
}

#[cfg(any(test, target_os = "linux"))]
fn parse_addr_port(field: &str, is_v6: bool) -> Option<std::net::SocketAddr> {
    let (ip_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if is_v6 {
        let ip = parse_ipv6_hex(ip_hex)?;
        // Sockets bound to v6 may carry IPv4-mapped addresses (`::ffff:1.2.3.4`)
        // for incoming v4 traffic. Normalise so the caller's 4-tuple match
        // works whether the wire frame was v4 or v6.
        let v4: Option<std::net::Ipv4Addr> = ip.to_ipv4_mapped();
        let addr = match v4 {
            Some(v4) => std::net::IpAddr::V4(v4),
            None => std::net::IpAddr::V6(ip),
        };
        Some(std::net::SocketAddr::new(addr, port))
    } else {
        let ip = parse_ipv4_hex(ip_hex)?;
        Some(std::net::SocketAddr::new(std::net::IpAddr::V4(ip), port))
    }
}

#[cfg(any(test, target_os = "linux"))]
fn parse_ipv4_hex(s: &str) -> Option<std::net::Ipv4Addr> {
    if s.len() != 8 {
        return None;
    }
    let val = u32::from_str_radix(s, 16).ok()?;
    // The 8-hex-char field is `printf("%08X", be32)` on the wire. On a
    // little-endian host that means the byte order is reversed relative to the
    // network-order IP. Recover the original 4 bytes via `to_le_bytes`.
    Some(std::net::Ipv4Addr::from(val.to_le_bytes()))
}

#[cfg(any(test, target_os = "linux"))]
fn parse_ipv6_hex(s: &str) -> Option<std::net::Ipv6Addr> {
    if s.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for i in 0..4 {
        let chunk = &s[i * 8..(i + 1) * 8];
        let val = u32::from_str_radix(chunk, 16).ok()?;
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }
    Some(std::net::Ipv6Addr::from(bytes))
}

/// `/proc/<pid>/cgroup` lines look like `12:cpu,cpuacct:/some/path` for v1
/// and `0::/some/path` for v2. Return just the path.
#[cfg(any(test, target_os = "linux"))]
fn extract_path(line: &str) -> &str {
    // Skip the first two colon-separated fields.
    line.splitn(3, ':').nth(2).unwrap_or(line)
}

/// Extract a pod UID from a single path segment. Accepts:
///   - `pod<UID>` (raw, e.g. v2 layout)
///   - `kubepods-<qos>-pod<UID>.slice` and similar systemd-encoded forms
#[cfg(any(test, target_os = "linux"))]
fn extract_pod_uid(segment: &str) -> Option<String> {
    // The systemd-encoded slice form ("kubepods-besteffort-pod<UID>.slice")
    // contains two occurrences of "pod" — the one inside "kubepods" and the
    // marker before the UID. The UID always follows the last occurrence.
    let after_pod = &segment[segment.rfind("pod")? + 3..];
    let candidate = after_pod
        .trim_end_matches(".slice")
        .trim_end_matches(".scope");
    canonicalize_uid(candidate)
}

/// Normalise `123e4567_e89b_12d3_a456_426614174000` or
/// `123e4567-e89b-12d3-a456-426614174000` to the canonical hyphenated form.
/// Returns `None` if the input isn't a recognisable UUID.
#[cfg(any(test, target_os = "linux"))]
fn canonicalize_uid(raw: &str) -> Option<String> {
    let normalised: String = raw
        .chars()
        .map(|c| if c == '_' { '-' } else { c })
        .collect();
    let lower = normalised.to_ascii_lowercase();

    // Standard UUID form: 8-4-4-4-12 hex with hyphens.
    if lower.len() == 36 && is_canonical_uuid(&lower) {
        return Some(lower);
    }

    // Bare 32-hex form without separators: re-insert hyphens.
    if lower.len() == 32 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(format!(
            "{}-{}-{}-{}-{}",
            &lower[0..8],
            &lower[8..12],
            &lower[12..16],
            &lower[16..20],
            &lower[20..32],
        ));
    }

    None
}

#[cfg(any(test, target_os = "linux"))]
fn is_canonical_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Extract the container ID from the last segment of a cgroup path.
#[cfg(any(test, target_os = "linux"))]
fn extract_container_id(segment: &str) -> Option<String> {
    let trimmed = segment.trim_end_matches(".scope");
    // Strip well-known runtime prefixes.
    let candidate = trimmed
        .strip_prefix("cri-containerd-")
        .or_else(|| trimmed.strip_prefix("containerd-"))
        .or_else(|| trimmed.strip_prefix("crio-"))
        .or_else(|| trimmed.strip_prefix("docker-"))
        .unwrap_or(trimmed);

    let candidate = candidate.to_ascii_lowercase();
    if candidate.len() >= 32 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(candidate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1. cgroup v1 systemd, containerd runtime (typical EKS / kind)
    #[test]
    fn parses_cgroup_v1_systemd_containerd() {
        let line = "12:cpu,cpuacct:/kubepods.slice/kubepods-besteffort.slice/\
                    kubepods-besteffort-pod123e4567_e89b_12d3_a456_426614174000.slice/\
                    cri-containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let info = parse_cgroup(line).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(
            info.container_id.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    // 2. cgroup v2 unified containerd
    #[test]
    fn parses_cgroup_v2_unified_containerd() {
        let line = "0::/kubepods/burstable/pod123e4567-e89b-12d3-a456-426614174000/\
             abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let info = parse_cgroup(line).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(
            info.container_id.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    // 3. cri-o runtime
    #[test]
    fn parses_crio_scope() {
        let line = "0::/kubepods.slice/kubepods-besteffort.slice/\
                    kubepods-besteffort-pod123e4567_e89b_12d3_a456_426614174000.slice/\
                    crio-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let info = parse_cgroup(line).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(
            info.container_id.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    // 4. legacy docker shim
    #[test]
    fn parses_docker_shim_legacy() {
        let line = "11:devices:/kubepods/burstable/\
                    pod123e4567-e89b-12d3-a456-426614174000/\
                    docker-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope";
        let info = parse_cgroup(line).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
        assert_eq!(
            info.container_id.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    // 5. non-Kubernetes host returns None
    #[test]
    fn non_k8s_host_returns_none() {
        let contents = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.scope\n";
        assert!(parse_cgroup(contents).is_none());
    }

    // 6. pod UID normalisation: underscored -> hyphenated, also handles bare 32-hex
    #[test]
    fn normalises_pod_uid_variants() {
        // underscores
        assert_eq!(
            canonicalize_uid("123e4567_e89b_12d3_a456_426614174000"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );
        // already hyphenated
        assert_eq!(
            canonicalize_uid("123E4567-E89B-12D3-A456-426614174000"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );
        // bare 32-hex (rare, but seen in some pod-keyed cgroup forms)
        assert_eq!(
            canonicalize_uid("123e4567e89b12d3a456426614174000"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );
        // garbage
        assert_eq!(canonicalize_uid("not-a-uuid"), None);
    }

    // 7. kind / kubelet-prefixed cgroup as seen from inside a hostPID:true pod
    //    with a different cgroup namespace. Path is relative (begins with `../`)
    //    but the kubepods segment is preserved.
    #[test]
    fn parses_kubelet_prefixed_relative_path() {
        let line = "0::/../../kubelet-kubepods-besteffort.slice/\
                    kubelet-kubepods-besteffort-podc3b4d893_473e_43c2_8013_8ee2955a4630.slice/\
                    cri-containerd-c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b.scope";
        let info = parse_cgroup(line).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("c3b4d893-473e-43c2-8013-8ee2955a4630")
        );
        assert_eq!(
            info.container_id.as_deref(),
            Some("c16c7605305c854d8582a1db3d5bb3c4b6c89a08e914223e9d500682b3fb0b1b")
        );
    }

    // Multi-line /proc/<pid>/cgroup picks the kubepods line.
    #[test]
    fn picks_kubepods_line_among_many() {
        let contents = "13:misc:/\n\
                        12:perf_event:/\n\
                        11:cpu,cpuacct:/kubepods.slice/kubepods-besteffort.slice/\
                        kubepods-besteffort-pod123e4567_e89b_12d3_a456_426614174000.slice/\
                        cri-containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope\n\
                        0::/system.slice/garbage.scope\n";
        let info = parse_cgroup(contents).expect("recognised");
        assert_eq!(
            info.pod_uid.as_deref(),
            Some("123e4567-e89b-12d3-a456-426614174000")
        );
    }

    // --- /proc/<pid>/net/* line parsing ----------------------------------

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn ipv4_hex_is_little_endian() {
        // 0100007F => 127.0.0.1 (kernel printed the be32 with %08X on LE host)
        assert_eq!(
            parse_ipv4_hex("0100007F"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
        // 0F02000A => 10.0.2.15
        assert_eq!(
            parse_ipv4_hex("0F02000A"),
            Some(Ipv4Addr::new(10, 0, 2, 15))
        );
        // 00000000 => 0.0.0.0 (listening wildcard)
        assert_eq!(parse_ipv4_hex("00000000"), Some(Ipv4Addr::UNSPECIFIED));
        // wrong length
        assert_eq!(parse_ipv4_hex("0100"), None);
    }

    #[test]
    fn ipv6_hex_chunked_little_endian() {
        // ::1 loopback
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000001000000"),
            Some(Ipv6Addr::LOCALHOST)
        );
        // all zeros => ::
        assert_eq!(
            parse_ipv6_hex("00000000000000000000000000000000"),
            Some(Ipv6Addr::UNSPECIFIED)
        );
        // wrong length
        assert_eq!(parse_ipv6_hex("00"), None);
    }

    #[test]
    fn parses_tcp_v4_line() {
        // Real-shape line: listening on 0.0.0.0:8080 (1F90), no remote.
        let line = "  0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 12345 1 ...";
        let key = parse_proc_net_line(line, SocketProtocol::Tcp, false).expect("parsed");
        assert_eq!(key.protocol, SocketProtocol::Tcp);
        assert_eq!(
            key.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0x1F90)
        );
        assert_eq!(
            key.remote,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        );
    }

    #[test]
    fn parses_tcp_v4_established_line() {
        // 127.0.0.1:51000 -> 127.0.0.1:443
        let line = "  1: 0100007F:C738 0100007F:01BB 01 00000000:00000000 00:00000000 00000000  1000 0 99999 1 ...";
        let key = parse_proc_net_line(line, SocketProtocol::Tcp, false).expect("parsed");
        assert_eq!(
            key.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0xC738)
        );
        assert_eq!(
            key.remote,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443)
        );
    }

    #[test]
    fn parses_udp_v4_line() {
        let line = "  2: 0F02000A:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   101 0 54321 2 ...";
        let key = parse_proc_net_line(line, SocketProtocol::Udp, false).expect("parsed");
        assert_eq!(key.protocol, SocketProtocol::Udp);
        assert_eq!(
            key.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 0x35)
        );
    }

    #[test]
    fn parses_tcp_v6_line() {
        // ::1:8080 listening
        let line = "  0: 00000000000000000000000001000000:1F90 \
                    00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 12345 1 ...";
        let key = parse_proc_net_line(line, SocketProtocol::Tcp, true).expect("parsed");
        assert_eq!(
            key.local,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0x1F90)
        );
    }

    #[test]
    fn v6_line_with_ipv4_mapped_address_normalises_to_v4() {
        // ::ffff:10.0.2.15 — an IPv4-mapped v6 socket. s6_addr32 = [0,0,0xFFFF0000,
        // 0x0F02000A] printed in host order: 00000000 00000000 0000FFFF 0F02000A
        let line = "  0: 0000000000000000FFFF00000F02000A:0050 \
                    00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1 ...";
        let key = parse_proc_net_line(line, SocketProtocol::Tcp, true).expect("parsed");
        assert_eq!(
            key.local,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 80)
        );
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(parse_proc_net_line("garbage", SocketProtocol::Tcp, false).is_none());
        assert!(
            parse_proc_net_line("  0: nocolon 00000000:0000", SocketProtocol::Tcp, false).is_none()
        );
        assert!(parse_proc_net_line("", SocketProtocol::Tcp, false).is_none());
    }

    // --- kubelet log directory metadata parsing --------------------------

    #[test]
    fn parses_container_log_symlink_name() {
        let name = "coredns-7d764666f9-c9hxr_kube-system_coredns-\
                    2212d876c8edeb3216424f078dc37475050b23a09c601bdcf6e55bc06f1e0bbc.log";
        let (cid, meta) = parse_container_log_name(name).expect("parsed");
        assert_eq!(
            cid,
            "2212d876c8edeb3216424f078dc37475050b23a09c601bdcf6e55bc06f1e0bbc"
        );
        assert_eq!(meta.pod_name, "coredns-7d764666f9-c9hxr");
        assert_eq!(meta.namespace, "kube-system");
        assert_eq!(meta.container_name, "coredns");
    }

    #[test]
    fn parses_container_log_with_dashed_container_name() {
        // Container names may contain dashes; the 64-hex ID is split off last.
        let name = "my-app-7d764666f9-abcde_default_side-car-\
                    abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.log";
        let (cid, meta) = parse_container_log_name(name).expect("parsed");
        assert_eq!(
            cid,
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
        assert_eq!(meta.pod_name, "my-app-7d764666f9-abcde");
        assert_eq!(meta.namespace, "default");
        assert_eq!(meta.container_name, "side-car");
    }

    #[test]
    fn rejects_bad_container_log_names() {
        // Missing .log
        assert!(parse_container_log_name("foo_bar_baz-deadbeef").is_none());
        // Container ID not 64 hex
        assert!(parse_container_log_name("pod_ns_ctr-shortid.log").is_none());
        // Too few underscore-separated fields
        assert!(parse_container_log_name("podonly.log").is_none());
    }

    #[test]
    fn parses_pod_dir_name() {
        let (uid, meta) = super::parse_pod_dir_name(
            "demo-traffic_nginx-86644db9cc-mf5lx_c3b4d893-473e-43c2-8013-8ee2955a4630",
        )
        .expect("parsed");
        assert_eq!(uid, "c3b4d893-473e-43c2-8013-8ee2955a4630");
        assert_eq!(meta.pod_name, "nginx-86644db9cc-mf5lx");
        assert_eq!(meta.namespace, "demo-traffic");
    }

    #[test]
    fn metadata_apply_prefers_container_id_then_pod_uid() {
        use crate::network::types::K8sInfo;
        let mut meta = PodMetadata::default();
        meta.by_container_id.insert(
            "cid64".to_string(),
            ContainerMeta {
                pod_name: "web-1".to_string(),
                namespace: "shop".to_string(),
                container_name: "nginx".to_string(),
            },
        );
        meta.by_pod_uid.insert(
            "uid-1".to_string(),
            PodMeta {
                pod_name: "web-1".to_string(),
                namespace: "shop".to_string(),
            },
        );

        // Container-ID hit fills all three name fields.
        let mut info = K8sInfo {
            container_id: Some("cid64".to_string()),
            pod_uid: Some("uid-1".to_string()),
            ..Default::default()
        };
        meta.apply(&mut info);
        assert_eq!(info.pod_name.as_deref(), Some("web-1"));
        assert_eq!(info.pod_namespace.as_deref(), Some("shop"));
        assert_eq!(info.container_name.as_deref(), Some("nginx"));

        // Sandbox container (no container-ID match) falls back to pod UID;
        // container name stays None.
        let mut sandbox = K8sInfo {
            container_id: Some("unknown-sandbox-id".to_string()),
            pod_uid: Some("uid-1".to_string()),
            ..Default::default()
        };
        meta.apply(&mut sandbox);
        assert_eq!(sandbox.pod_name.as_deref(), Some("web-1"));
        assert_eq!(sandbox.pod_namespace.as_deref(), Some("shop"));
        assert_eq!(sandbox.container_name, None);
    }
}
