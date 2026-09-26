# Kubernetes 与容器抓包

[English](KUBERNETES.md) | [日本語](KUBERNETES.ja.md)

## Docker、Podman 和 LXC（未发布）

Linux 容器归属识别不依赖 `kubernetes` 特性或守护进程套接字，通过进程 cgroup 和 eBPF 保留的套接字标识工作，需要主机 PID、cgroup 和网络可见性。未知布局保持未知，procfs 回退无法恢复已退出的进程。

Details 显示运行时、ID 和可用名称。可使用 `runtime:docker`、`runtime:podman`、`runtime:lxc` 或 `container:web` 过滤；`cont:` 同样匹配名称或 ID，包括 Kubernetes 容器。使用 `-i any` 捕获 bridge/veth 流量。

Docker 和 Podman 名称来自降低权限前读取的本地元数据；LXC 的 cgroup 名称同时作为 ID 和名称。自定义存储目录、其他用户的 rootless 容器等情况可能导致名称缺失或直到重启才更新。

无界面 JSON、JSONL 日志和 PCAP 附属文件中的 `container` 包含 `runtime`、`id`、`name` 和 `cgroup_path`，后两项可为 null。PCAPNG 注释包含 `runtime=`、`container_id=` 和可用时的 `container=` 名称。事件反映写入时已知的元数据；PCAP 附属文件包含关闭时仍被跟踪连接的最终元数据。

## 短连接（尚未发布）

在启用 Linux eBPF 和 cgroup v2 时，RustNet 会在 socket 事件发生时保留容器及其父 pod 的 cgroup 名称。因此，对于标准 systemd 和 cgroupfs Kubernetes 布局，即使连接在间隔五秒的两次命名空间扫描之间建立并结束，进程退出后仍可识别归属。查询先尝试观测到的端点方向（包括源地址通配匹配），再尝试反向匹配，因此主机上的抓包也能匹配 pod 网络命名空间内的 socket。Pod 和容器名称通过现有的 kubelet 日志元数据解析。事件中的 pod UID 和容器 ID 优先于按 PID 缓存的元数据。

Socket 映射最多保留 32,768 个连接元组，容量不足时淘汰较旧记录。现有清理机制每 30 秒清理超过 60 秒的记录。同一元组的新事件会替换其所有者。保留的事件用于为已捕获的数据包补充归属信息，不能重建漏抓的数据包。事件只包含两个 cgroup 名称，因此使用该来源时不提供 `cgroup_path`。

Cgroup v1、容器下的嵌套 cgroup、eBPF 不可用，以及无法读取或被截断的 cgroup 名称仍依赖 procfs 扫描，可能遗漏在两次扫描之间退出的进程。解析可读名称需要相应的 kubelet 日志元数据仍然存在。

## 配合 kubectl-rustnet 使用

[kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet) 提供主机 PID、网络访问及 eBPF 权限。通过 `--image` 选择包含此修改的 RustNet 镜像，通用容器识别不需要其他插件参数。默认 Pod 挂载 kubelet 日志，但不挂载 Docker/Podman 元数据，因此独立容器的名称可能缺失。Kubernetes 工作负载继续使用现有的 Pod/容器字段和过滤器。

包含 [PR #21](https://github.com/domcyrus/kubectl-rustnet/pull/21) 的插件版本支持 `--output-dir ./captures`，先保存并验证文件，再删除调试 Pod；复制失败时保留 Pod 并提供恢复说明。RustNet 参数放在 `--` 之后，例如：`kubectl rustnet --image YOUR_IMAGE --output-dir ./captures -- --filter 'container:web'`。旧版插件需要在退出前使用 `kubectl cp` 复制文件。Kubernetes 配置见[使用指南](USAGE.zh-CN.md#--kubernetes-mode-optional-feature)。
