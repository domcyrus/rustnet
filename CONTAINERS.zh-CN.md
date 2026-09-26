# 容器归属识别（未发布）

[English](CONTAINERS.md) | [日本語](CONTAINERS.ja.md)

Linux 开发版本通过进程 cgroup 和 eBPF 保留的套接字 cgroup 名称，识别 Docker、
Podman 和 LXC 连接。此功能独立于 `kubernetes` 特性，不连接任何运行时守护进程
套接字。Kubernetes Pod 归属的现有字段和行为保持不变。

## 标识与名称

- Docker：`/docker/<64 位十六进制 ID>`、`docker-<ID>.scope`。
- Podman：`libpod-<64 位十六进制 ID>`、`libpod-<ID>.scope`，包括 rootless
  用户 slice 和 cgroupfs 布局。
- LXC：`/lxc/<名称>`、`/lxc.payload/<名称>`、`lxc.payload.<名称>`。
  LXC 名称同时作为标识和显示名称。监控进程的 cgroup 不纳入识别。

优先识别最内层容器。纯哈希、未知布局或不可见的 cgroup 保持未知。
基本识别需要进程和 cgroup 可见，但不需要运行时元数据或守护进程套接字。
eBPF 与 cgroup v2 可在进程退出后使用保留的叶节点和父节点名称识别套接字。
若这两个名称不足以确定容器，较深的子树需要仍存活的进程。
procfs 回退无法恢复已退出的进程。

RustNet 在降低权限之前读取有大小限制的名称快照：Docker 的
`/var/lib/docker/containers` 下的 `config.v2.json`，以及 Podman 的
`/var/lib/containers/storage` 下的 `{overlay,vfs,btrfs}-containers/containers.json`。
同时检查启动用户的 `XDG_DATA_HOME`（默认 `$HOME/.local/share`）下的
`docker/containers` 和 `containers/storage`。LXC 名称直接来自 cgroup。

名称是可选信息。自定义存储目录、权限限制、启动后创建或重命名的容器，以及其他
用户的 rootless 存储，可能导致名称缺失或直到重启才更新。运行时和 ID 仍可使用。
不导出凭据或完整运行时配置。

## 详情、过滤与导出

Details 增加 **Container** 区域，显示运行时、ID、可选名称和 cgroup 路径。
过滤支持与其他文本字段相同的子串和正则语法：

```bash
sudo rustnet --filter 'runtime:docker'
sudo rustnet --filter 'runtime:podman container:web'
sudo rustnet --headless --duration 10 --output json --filter 'runtime:lxc'
```

`container:`（别名 `cont:`）匹配名称或 ID，并继续支持 Kubernetes 容器元数据。
`runtime:` 匹配 `docker`、`podman` 或 `lxc`。

无界面快照新增可为空的 `container` 对象。JSONL 事件日志和 PCAP JSONL 附属文件
在归属已知时包含该对象：

```json
{"container":{"runtime":"lxc","id":"web","name":"web","cgroup_path":"/lxc.payload.web"}}
```

`name` 和 `cgroup_path` 可为 null。保留的套接字名称不能提供完整路径。
PCAPNG 数据包注释包含 `runtime=`、`container_id=` 和可用时的 `container=`。
事件和数据包注释反映写入时已知的元数据；PCAP 附属文件包含关闭时仍被跟踪连接的
最终元数据。

请在 Linux 主机上运行，或为监控容器提供主机 PID、cgroup 和网络可见性。
使用 `-i any` 捕获 bridge/veth 流量。隔离容器或 macOS Docker 客户端无法直接看到
Linux 主机的其他容器。无需挂载运行时套接字。
