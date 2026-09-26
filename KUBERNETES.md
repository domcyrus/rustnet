# Kubernetes and container capture

[简体中文](KUBERNETES.zh-CN.md) | [日本語](KUBERNETES.ja.md)

## Docker, Podman and LXC (unreleased)

On Linux, container attribution works without the `kubernetes` feature or daemon sockets. It uses process cgroups and retained eBPF socket identity; host PID/cgroup and network visibility are required. Unknown layouts stay unknown, and procfs fallback cannot recover exited processes.

Details shows runtime, ID and available names. Filter with `runtime:docker`, `runtime:podman`, `runtime:lxc` or `container:web` (`cont:` also matches names or IDs, including Kubernetes containers). Use `-i any` for bridge/veth traffic.

Docker and Podman names come from readable local metadata collected before privilege drop; LXC uses its cgroup name as its ID and name. Names may be missing or stale until restart, especially with custom storage paths or another user's rootless containers.

Headless JSON, JSONL logs and PCAP sidecars expose `container` with `runtime`, `id`, `name` and `cgroup_path`; the last two may be null. PCAPNG comments include `runtime=`, `container_id=` and available `container=` names. Events reflect metadata known when written; PCAP sidecars include final metadata for connections still tracked at shutdown.

## Short flows (unreleased)

With Linux eBPF and cgroup v2, RustNet retains the container and parent pod cgroup names at each socket event. Standard systemd and cgroupfs Kubernetes layouts can therefore be attributed after the process exits, even when the flow starts and ends between the five-second namespace scans. Lookup tries the observed endpoint orientation first, including wildcard source addresses, then the reverse orientation, so host capture can match sockets in a pod network namespace. Pod and container names are resolved from the existing kubelet log metadata. The recorded pod UID and container ID take precedence over cached PID metadata.

The socket map holds up to 32,768 tuples and evicts older records under pressure. Existing cleanup removes records more than 60 seconds old on a 30-second cleanup cadence. A newer event for the same tuple replaces its owner. Retained events supply attribution for captured packets; they do not reconstruct packets missed by capture. The event contains two cgroup names, so `cgroup_path` is omitted when enrichment uses this source.

Cgroup v1, nested cgroups below the container, unavailable eBPF, and unreadable or truncated cgroup names still rely on procfs discovery and can miss processes that exit between scans. Human-readable names require the kubelet log metadata to remain available.

## Using kubectl-rustnet

[kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet) provides host PID/network access and eBPF capabilities. Use `--image` to select a RustNet image containing this change; generic attribution needs no additional plugin flag. The default pod mounts kubelet logs, but not Docker/Podman metadata, so standalone container names may be unavailable. Kubernetes workloads keep their existing pod/container fields and filters.

With a plugin version containing [PR #21](https://github.com/domcyrus/kubectl-rustnet/pull/21), `--output-dir ./captures` saves and verifies exports before deleting the debug pod; copy failures retain it with recovery instructions. RustNet flags follow `--`, for example: `kubectl rustnet --image YOUR_IMAGE --output-dir ./captures -- --filter 'container:web'`. Older plugin versions require copying files with `kubectl cp` before quitting. See the [usage guide](USAGE.md#--kubernetes-mode-optional-feature) for Kubernetes setup.
