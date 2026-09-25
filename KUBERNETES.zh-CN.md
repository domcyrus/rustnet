# Kubernetes 抓包与证据导出

[English](KUBERNETES.md) | [日本語](KUBERNETES.ja.md)

## 短连接（尚未发布）

在启用 Linux eBPF 和 cgroup v2 时，RustNet 会在 socket 事件发生时保留容器及其父 pod 的 cgroup 名称。因此，对于标准 systemd 和 cgroupfs Kubernetes 布局，即使连接在间隔五秒的两次命名空间扫描之间建立并结束，进程退出后仍可识别归属。查询先尝试观测到的端点方向（包括源地址通配匹配），再尝试反向匹配，因此主机上的抓包也能匹配 pod 网络命名空间内的 socket。Pod 和容器名称通过现有的 kubelet 日志元数据解析。事件中的 pod UID 和容器 ID 优先于按 PID 缓存的元数据。

Socket 映射最多保留 32,768 个连接元组，容量不足时淘汰较旧记录。现有清理机制每 30 秒清理超过 60 秒的记录。同一元组的新事件会替换其所有者。保留的事件用于为已捕获的数据包补充归属信息，不能重建漏抓的数据包。事件只包含两个 cgroup 名称，因此使用该来源时不提供 `cgroup_path`。

Cgroup v1、容器下的嵌套 cgroup、eBPF 不可用，以及无法读取或被截断的 cgroup 名称仍依赖 procfs 扫描，可能遗漏在两次扫描之间退出的进程。解析可读名称需要相应的 kubelet 日志元数据仍然存在。

## 导出后续工作

kubectl 插件位于独立仓库：[domcyrus/kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet)。配套的 [`--output-dir` 后续任务](https://github.com/domcyrus/kubectl-rustnet/issues/20) 要求先正常停止抓包，刷新并复制 JSONL 或 PCAPNG 证据（包括 sidecar），然后才能删除调试 pod。如果复制失败，必须保留 pod 并提供恢复说明。

该参数属于插件的计划功能，本次 RustNet 修改尚未实现。在插件支持该功能之前，请在调试 pod 仍运行时、退出会话之前使用 `kubectl cp` 复制文件。Kubernetes 配置见[使用指南](USAGE.zh-CN.md#--kubernetes-mode-optional-feature)。
