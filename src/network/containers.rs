//! Socket and procfs container identity without access to a runtime daemon.

use crate::network::types::{ContainerInfo, ContainerRuntime};
use rustnet_host::SocketCgroup;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

fn hex_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

fn lxc_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
        && name != "."
        && name != ".."
}

/// Recognize explicit manager layouts, never infer a manager from a bare hash.
/// Scan from the leaf so nested containers retain the innermost identity.
fn parse_path(path: &str) -> Option<ContainerInfo> {
    let parts: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();
    // Keep pod identity in the Kubernetes resolver, including nested kind hosts.
    if parts
        .iter()
        .any(|p| *p == "kubepods" || p.starts_with("kubepods-") || *p == "kubepods.slice")
    {
        return None;
    }
    for (i, part) in parts.iter().enumerate().rev() {
        let trimmed = part.strip_suffix(".scope").unwrap_or(part);
        let candidate = trimmed
            .strip_prefix("docker-")
            .map(|id| (ContainerRuntime::Docker, id))
            .or_else(|| {
                trimmed
                    .strip_prefix("libpod-")
                    .map(|id| (ContainerRuntime::Podman, id))
            })
            .or_else(|| {
                (i > 0 && parts[i - 1] == "docker").then_some((ContainerRuntime::Docker, *part))
            });
        if let Some((runtime, id)) = candidate
            && hex_id(id)
        {
            return Some(ContainerInfo {
                runtime,
                id: id.to_ascii_lowercase(),
                name: None,
                cgroup_path: Some(path.into()),
            });
        }
        let name = part.strip_prefix("lxc.payload.").or_else(|| {
            (i > 0 && (parts[i - 1] == "lxc" || parts[i - 1] == "lxc.payload")).then_some(*part)
        });
        if let Some(name) = name
            && lxc_name(name)
        {
            return Some(ContainerInfo {
                runtime: ContainerRuntime::Lxc,
                id: name.into(),
                name: Some(name.into()),
                cgroup_path: Some(path.into()),
            });
        }
    }
    None
}

/// Parse cgroup v1 or v2 procfs text. Unknown and namespaced-away paths stay unknown.
pub fn parse_cgroup(contents: &str) -> Option<ContainerInfo> {
    contents
        .lines()
        .filter_map(|line| line.splitn(3, ':').nth(2))
        .find_map(parse_path)
}

/// The retained kernel record contains names, not a full cgroup path.
fn from_socket(cgroup: &SocketCgroup) -> Option<ContainerInfo> {
    // The kernel buffers hold 128 bytes including NUL. Reject possibly
    // truncated LXC names instead of exporting a partial name as an ID.
    if cgroup.name.len() >= 127 || cgroup.parent.len() >= 127 {
        return None;
    }
    let mut info = parse_path(&format!("{}/{}", cgroup.parent, cgroup.name))?;
    info.cgroup_path = None;
    Some(info)
}

/// Names are cached before privilege drop. A missing or inaccessible metadata
/// file never prevents cgroup identification. No runtime commands or sockets.
#[derive(Default)]
pub struct ContainerResolver {
    names: HashMap<(ContainerRuntime, String), String>,
}

impl ContainerResolver {
    pub fn new() -> Self {
        let mut resolver = Self::default();
        if cfg!(target_os = "linux") {
            resolver.load_docker(Path::new("/var/lib/docker/containers"));
            resolver.load_podman(Path::new("/var/lib/containers/storage"));
            let data = std::env::var_os("XDG_DATA_HOME")
                .map(std::path::PathBuf::from)
                .or_else(|| {
                    std::env::var_os("HOME").map(|home| Path::new(&home).join(".local/share"))
                });
            if let Some(data) = data {
                resolver.load_docker(&data.join("docker/containers"));
                resolver.load_podman(&data.join("containers/storage"));
            }
        }
        resolver
    }

    /// Prefer retained identity. Never pair it with metadata from a possibly
    /// reused PID. The fallback reads cgroups afresh, with no PID-only cache.
    pub fn enrich(&self, pid: u32, socket: Option<&SocketCgroup>) -> Option<ContainerInfo> {
        let mut info = match socket {
            Some(cgroup) => from_socket(cgroup).or_else(|| {
                // For a live process in a deeper container subtree, require
                // its current leaf and parent to agree with the socket record.
                let info = self.lookup_pid(pid)?;
                let suffix = format!("/{}/{}", cgroup.parent, cgroup.name);
                info.cgroup_path
                    .as_deref()?
                    .ends_with(&suffix)
                    .then_some(info)
            })?,
            None => self.lookup_pid(pid)?,
        };
        if let Some(name) = self.names.get(&(info.runtime, info.id.clone())) {
            info.name = Some(name.clone());
        }
        Some(info)
    }

    #[cfg(target_os = "linux")]
    fn lookup_pid(&self, pid: u32) -> Option<ContainerInfo> {
        // Open the process directory first so reuse cannot redirect later reads
        // to another process. procfs entries on a dead process fail to open.
        let dir = std::fs::File::open(format!("/proc/{pid}")).ok()?;
        use std::os::fd::AsRawFd;
        let text =
            std::fs::read_to_string(format!("/proc/self/fd/{}/cgroup", dir.as_raw_fd())).ok()?;
        parse_cgroup(&text)
    }

    #[cfg(not(target_os = "linux"))]
    fn lookup_pid(&self, _pid: u32) -> Option<ContainerInfo> {
        None
    }

    fn load_docker(&mut self, root: &Path) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return;
        };
        for entry in entries.flatten().take(4096) {
            let id = entry.file_name().to_string_lossy().into_owned();
            if !hex_id(&id) {
                continue;
            }
            if let Some(value) = read_json(&entry.path().join("config.v2.json"))
                && let Some(name) = value.get("Name").and_then(|v| v.as_str())
                && !name.trim_start_matches('/').is_empty()
            {
                self.names.insert(
                    (ContainerRuntime::Docker, id.to_ascii_lowercase()),
                    name.trim_start_matches('/').into(),
                );
            }
        }
    }

    fn load_podman(&mut self, root: &Path) {
        for driver in ["overlay", "vfs", "btrfs"] {
            let Some(value) = read_json(&root.join(format!("{driver}-containers/containers.json")))
            else {
                continue;
            };
            let Some(rows) = value.as_array() else {
                continue;
            };
            for row in rows.iter().take(4096) {
                if let Some(id) = row.get("id").and_then(|v| v.as_str())
                    && hex_id(id)
                    && let Some(name) = row
                        .get("names")
                        .and_then(|v| v.as_array())
                        .and_then(|v| v.first())
                        .and_then(|v| v.as_str())
                    && !name.is_empty()
                {
                    self.names.insert(
                        (ContainerRuntime::Podman, id.to_ascii_lowercase()),
                        name.into(),
                    );
                }
            }
        }
    }
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    const LIMIT: u64 = 4 * 1024 * 1024;
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut data = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut data).ok()?;
    if data.len() > LIMIT as usize {
        return None;
    }
    serde_json::from_slice(&data).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn parses_managers_v1_v2_and_nested_scopes() {
        for (path, runtime) in [
            (format!("/docker/{ID}"), ContainerRuntime::Docker),
            (
                format!("/system.slice/docker-{ID}.scope"),
                ContainerRuntime::Docker,
            ),
            (
                format!("/user.slice/user-1000.slice/user@1000.service/libpod-{ID}.scope"),
                ContainerRuntime::Podman,
            ),
            (
                format!("/machine.slice/libpod-{ID}/init.scope"),
                ContainerRuntime::Podman,
            ),
            ("/lxc/web/init.scope".into(), ContainerRuntime::Lxc),
            ("/lxc.payload/web".into(), ContainerRuntime::Lxc),
            (
                "/lxc.payload.web/system.slice/sshd.service".into(),
                ContainerRuntime::Lxc,
            ),
        ] {
            for prefix in ["0::", "5:cpu,cpuacct:"] {
                let info = parse_cgroup(&format!("{prefix}{path}\n")).unwrap();
                assert_eq!(info.runtime, runtime);
                assert_eq!(
                    info.id,
                    if runtime == ContainerRuntime::Lxc {
                        "web"
                    } else {
                        ID
                    }
                );
            }
        }
    }

    #[test]
    fn rejects_host_monitor_and_incomplete_identities() {
        for path in [
            "/",
            "/system.slice/docker.service",
            "/lxc.monitor.web",
            "/libpod-conmon-deadbeef.scope",
            "/docker/abc",
            "/lxc/..",
            "/lxc.payload.",
            "/system.slice/sshd.service",
        ] {
            assert!(parse_cgroup(&format!("0::{path}")).is_none(), "{path}");
        }
        assert!(parse_cgroup(&format!("0::/{ID}")).is_none());
        assert!(parse_cgroup(&format!("0::/docker/{ID}/kubepods/pod123/{ID}")).is_none());
    }

    #[test]
    fn retained_identity_works_after_pid_exit_and_never_uses_unrelated_pid() {
        let resolver = ContainerResolver::default();
        let socket = SocketCgroup {
            name: format!("libpod-{ID}.scope"),
            parent: "user.slice".into(),
        };
        let info = resolver.enrich(u32::MAX, Some(&socket)).unwrap();
        assert_eq!(info.runtime, ContainerRuntime::Podman);
        assert_eq!(info.id, ID);
        assert_eq!(info.cgroup_path, None);
        assert!(resolver.enrich(u32::MAX, None).is_none());
    }

    #[test]
    fn nested_containers_choose_inner_identity_and_reject_truncated_names() {
        let info = parse_cgroup(&format!("0::/docker/{ID}/lxc.payload.web")).unwrap();
        assert_eq!(info.runtime, ContainerRuntime::Lxc);
        assert_eq!(info.id, "web");
        let info = from_socket(&SocketCgroup {
            name: "init.scope".into(),
            parent: format!("libpod-{ID}.scope"),
        })
        .unwrap();
        assert_eq!(info.runtime, ContainerRuntime::Podman);
        assert_eq!(info.id, ID);
        assert!(
            from_socket(&SocketCgroup {
                name: format!("lxc.payload.{}", "x".repeat(115)),
                parent: "root".into()
            })
            .is_none()
        );
        assert!(parse_cgroup("malformed\n0::/lxc.payload.web").is_some());
    }

    #[test]
    fn metadata_names_are_optional_and_scoped_to_runtime() {
        let root = std::env::temp_dir().join(format!(
            "rustnet-container-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let docker = root.as_path().join(ID);
        std::fs::create_dir(&docker).unwrap();
        std::fs::write(docker.join("config.v2.json"), r#"{"Name":"/web"}"#).unwrap();
        let podman = root.as_path().join("overlay-containers");
        std::fs::create_dir(&podman).unwrap();
        std::fs::write(
            podman.join("containers.json"),
            format!(r#"[{{"id":"{ID}","names":["worker"]}}]"#),
        )
        .unwrap();
        let mut resolver = ContainerResolver::default();
        resolver.load_docker(root.as_path());
        resolver.load_podman(root.as_path());
        for (prefix, name) in [("docker", "web"), ("libpod", "worker")] {
            let socket = SocketCgroup {
                name: format!("{prefix}-{ID}.scope"),
                parent: "system.slice".into(),
            };
            assert_eq!(
                resolver
                    .enrich(u32::MAX, Some(&socket))
                    .unwrap()
                    .name
                    .as_deref(),
                Some(name)
            );
        }
        resolver.load_docker(&root.as_path().join("missing"));
        std::fs::write(podman.join("containers.json"), "invalid").unwrap();
        resolver.load_podman(root.as_path());
        std::fs::remove_dir_all(root).unwrap();
    }
}
