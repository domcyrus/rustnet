# Container attribution (unreleased)

[简体中文](CONTAINERS.zh-CN.md) | [日本語](CONTAINERS.ja.md)

On Linux, development builds identify Docker, Podman and LXC connections from
process cgroups and retained eBPF socket cgroup names. This works independently
of the `kubernetes` feature and does not connect to Docker, Podman or LXC daemon
sockets. Kubernetes pod attribution keeps its existing fields and behavior.

## Identity and names

- Docker: `/docker/<64-hex-ID>` and `docker-<ID>.scope`.
- Podman: `libpod-<64-hex-ID>` and `libpod-<ID>.scope`, including rootless
  user slices and cgroupfs layouts.
- LXC: `/lxc/<name>`, `/lxc.payload/<name>` and `lxc.payload.<name>`.
  The LXC name is both its identifier and display name. Monitor cgroups are
  excluded.

The innermost recognized container wins. A bare hash, an unknown layout or a
hidden cgroup stays unknown. Basic identification requires process/cgroup
visibility; it does not require access to runtime metadata or a daemon socket.
With eBPF and cgroup v2, retained leaf/parent names can identify sockets after
process exit. Deeper subtrees need a live process when those two names do not
identify the container. Procfs fallback cannot recover a process already gone.

Before privilege drop, RustNet reads a bounded snapshot of names from readable
Docker `config.v2.json` files under `/var/lib/docker/containers` and Podman
`{overlay,vfs,btrfs}-containers/containers.json` under
`/var/lib/containers/storage`. It also checks `docker/containers` and
`containers/storage` under the launching user's `XDG_DATA_HOME` (or
`$HOME/.local/share`). LXC names come directly from cgroups.

Names are optional. Custom storage roots, metadata hidden by permissions,
containers created or renamed after startup, and another user's rootless
storage may leave a name unavailable or unchanged until restart. Runtime and ID
remain useful. No credentials or full runtime configuration are exported.

## Details, filters and exports

Details adds a **Container** section with runtime, ID, optional name and cgroup
path. These filters support the same substring and regex syntax as other text
filters:

```bash
sudo rustnet --filter 'runtime:docker'
sudo rustnet --filter 'runtime:podman container:web'
sudo rustnet --headless --duration 10 --output json --filter 'runtime:lxc'
```

`container:` (alias `cont:`) matches name or ID and continues to match Kubernetes
container metadata. `runtime:` matches `docker`, `podman` or `lxc`.

Headless snapshots add a nullable `container` object. JSONL event logs and PCAP
JSONL sidecars include the object when attributed:

```json
{"container":{"runtime":"lxc","id":"web","name":"web","cgroup_path":"/lxc.payload.web"}}
```

`name` and `cgroup_path` may be null. Retained socket names do not provide a full
path. PCAPNG packet comments include `runtime=`, `container_id=` and, when
available, `container=`. Events and packet comments reflect metadata known when
written; a PCAP sidecar includes final metadata for connections still tracked at
shutdown.

Run on the Linux host, or provide host PID/cgroup and network visibility to a
monitor container. Capture on `-i any` to include bridge/veth traffic. Visibility
inside an isolated container or a macOS Docker client does not expose the Linux
host's other containers. No runtime socket mount is needed.
