<p align="center"><a href="SECURITY.md">English</a> | <strong>简体中文</strong></p>

# 安全

RustNet 处理不受信任的网络数据，因此纵深防御至关重要。本文档描述了已实现的安全措施。

## 目录

- [Landlock 沙箱（Linux）](#landlock-sandboxing-linux)
- [Seatbelt 沙箱（macOS）](#seatbelt-sandboxing-macos)
- [FreeBSD 沙箱](#freebsd-sandboxing)
- [权限剥离与 Job Object 沙箱（Windows）](#privilege-drop-and-job-object-sandboxing-windows)
- [权限需求](#privilege-requirements)
- [只读操作](#read-only-operation)
- [不主动对外通信](#no-external-communication)
- [日志文件隐私](#log-file-privacy)
- [eBPF 安全](#ebpf-security)
- [威胁模型](#threat-model)
- [供应链安全](#supply-chain-security)
- [审计与合规](#audit-and-compliance)
- [报告安全问题](#reporting-security-issues)

## Landlock 沙箱（Linux）<a id="landlock-sandboxing-linux"></a>

在 Linux 5.13+ 上，RustNet 使用 [Landlock](https://landlock.io/) 在初始化后限制自身的 Linux capabilities。这样即使包解析存在漏洞被利用，也能限制损害范围。

### 受限制的内容

| 限制项 | 内核版本 | 描述 |
|--------|----------|------|
| 文件系统 | 5.13+ | 仅 `/proc` 可读（用于进程识别） |
| 网络 | 6.4+ | 禁止 TCP bind/connect（RustNet 为被动模式） |
| Linux capabilities | 任意 | pcap socket 打开后丢弃 `CAP_NET_RAW` |
| Linux capabilities | 任意 | eBPF 程序加载后丢弃 `CAP_BPF`、`CAP_PERFMON` |
| 特权 | 任意 | `PR_SET_NO_NEW_PRIVS` 防止通过 setuid 二进制文件提升特权 |

### 工作原理

1. **初始化阶段**：RustNet 加载 eBPF 程序、打开包捕获句柄、创建日志文件
2. **Linux capabilities 剥离**：移除 `CAP_NET_RAW`、`CAP_BPF` 和 `CAP_PERFMON`
3. **Landlock**：限制文件系统和网络访问

### 安全收益

如果攻击者利用 DPI/包解析中的漏洞：
- 无法读取任意文件（凭据、配置等）
- 无法写入文件系统（除配置的日志路径外）
- 无法建立出站 TCP 连接（阻止数据外泄）
- 无法绑定 TCP 端口（阻止反向 shell）
- 无法创建新的 raw socket（Linux capabilities 已剥离）
- 无法通过 setuid 二进制文件提升特权（`PR_SET_NO_NEW_PRIVS`）

### CLI 选项

```
--no-sandbox        禁用 Landlock 沙箱和 Linux capabilities 剥离
--sandbox-strict    要求完整沙箱强制生效，否则退出
```

### 优雅降级

- **Kernel < 5.13**：跳过沙箱，记录警告
- **Kernel 5.13-6.3**：仅文件系统限制
- **Kernel 6.4+**：完整的文件系统 + 网络限制
- **Docker**：Landlock 可能受限；应用正常运行

## Seatbelt 沙箱（macOS）<a id="seatbelt-sandboxing-macos"></a>

在 macOS 10.5+ 上，RustNet 使用 [Seatbelt](https://theapplewiki.com/wiki/Dev:Seatbelt)（`sandbox_init_with_parameters`）在初始化后限制自身能力。这样即使包解析存在漏洞被利用，也能限制损害范围。

### 受限制的内容

| 限制项 | 描述 |
|--------|------|
| 出站网络 | TCP/UDP 出站被阻止；Unix socket（Mach IPC）允许 |
| 文件系统读取 | 禁止读取用户主目录（`/Users`、`/var/root`）；GeoIP 路径显式允许 |
| 文件系统写入 | 禁止写入所有用户主目录（`/Users`、`/var/root`） |
| 文件系统写入 | 仅配置的日志和 PCAP 导出路径可写 |
| 进程执行 | 除 `/usr/sbin/lsof` 外，禁止执行所有二进制文件 |

### 工作原理

1. **初始化阶段**：RustNet 打开包捕获句柄（BPF/PKTAP）并创建日志文件
2. **预创建**：PCAP sidecar 文件（`.connections.jsonl`）在沙箱应用前创建，因此其路径已经是有效的允许目标
3. **沙箱应用**：调用 `sandbox_init_with_parameters` — 已打开的文件描述符保持不变，仅限制未来的操作

### 配置文件策略

RustNet 使用 **默认允许** 的 SBPL 配置文件配合针对性拒绝。拒绝默认的配置文件需要显式将所有系统库、Mach 端口、区域设置数据、字体和其他 OS 内部组件加入白名单——脆弱且容易出错。默认允许配合针对性拒绝覆盖了主要威胁（凭据窃取、数据外泄、shell 逃逸），同时避免操作风险。具体的拒绝规则阻止对用户主目录下的文件读/写、出站网络连接，以及除 `/usr/sbin/lsof` 外所有二进制文件的执行。

### 输出文件支持

`--json-log` 和 `--pcap-export` 路径通过运行时参数（`JSON_LOG_PATH`、`PCAP_PATH`、`PCAP_JSONL_PATH`）传递给 SBPL 配置文件。配置文件为每个路径授予显式的 `allow file-write*` 规则，该规则通过 SBPL 的特异性优先于更宽泛的 `/Users` 拒绝规则。未使用的参数默认为 `/dev/null`。

两个标志在沙箱内均可正常工作。

### 安全收益

如果攻击者利用 DPI/包解析中的漏洞：
- 无法读取 `/Users` 下的 SSH 密钥、AWS 凭据、浏览器配置文件或其他凭据文件
- 无法写入 `/Users` 下的 SSH 密钥、AWS 凭据、浏览器配置文件或其他凭据文件
- 无法建立出站 TCP/UDP 连接（阻止数据外泄）
- 无法打开新的 raw network socket
- 无法执行二进制文件（不能通过 `/bin/sh`、`/usr/bin/curl` 等逃逸 shell）

### CLI 选项

```
--no-sandbox        禁用 Seatbelt 沙箱
--sandbox-strict    要求完整沙箱强制生效，否则退出
```

### 为什么默认使用 BestEffort

`sandbox_init_with_parameters` 是 macOS 的私有（未公开）API。自 macOS 10.5 以来一直保持稳定，Chromium、Firefox 和 Safari 都使用它进行进程沙箱，但理论上可能在没有通知的情况下发生变化。BestEffort 在 API 行为异常时优雅降级，而不是阻止应用运行。使用 `--sandbox-strict` 可要求沙箱生效，否则中止。

### 剪贴板行为

与 Linux Landlock 不同，在 Seatbelt 下剪贴板复制（`c` 键）正常工作。macOS 剪贴板使用 NSPasteboard，通过 Mach IPC 在 Unix domain socket 上通信——SBPL 配置文件显式允许 `(network-outbound (remote unix-socket))`。

在 Linux 上，剪贴板需要访问 Wayland socket（`/run/user/UID/wayland-0`）或 X11 socket（`/tmp/.X11-unix/`）。Landlock 的拒绝默认模型会阻止这些，因为它们不在写路径的允许列表中，因此当 Landlock 激活时剪贴板不可用。

## FreeBSD 沙箱<a id="freebsd-sandboxing"></a>

FreeBSD 当前未启用沙箱。计划使用 `cap_enter()` 配合 `libcasper` 实现完整的 Capsicum 沙箱，用于特权进程查找——详见 [ROADMAP.md](ROADMAP.md)。

## 权限剥离与 Job Object 沙箱（Windows）<a id="privilege-drop-and-job-object-sandboxing-windows"></a>

在 Windows 上，RustNet 在初始化后从进程令牌中移除危险特权，并应用 Job Object 阻止子进程创建。

### 受限制的内容

| 限制项 | 描述 |
|--------|------|
| 特权移除 | 永久移除 SeDebugPrivilege、SeTakeOwnershipPrivilege、SeBackupPrivilege、SeRestorePrivilege 等危险特权 |
| 子进程 | Job Object 阻止创建子进程（反向 shell、基于 exec 的数据外泄） |

### 工作原理

1. **初始化阶段**：RustNet 打开 Npcap 句柄并创建日志文件
2. **特权移除**：`AdjustTokenPrivileges` 配合 `SE_PRIVILEGE_REMOVED` 永久从进程令牌中剥离危险特权
3. **Job Object**：应用 `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` 的 Job Object，阻止任何子进程创建

### 安全收益

如果攻击者利用 DPI/包解析中的漏洞：
- 无法调试其他进程（SeDebugPrivilege 已移除）
- 无法取得任意文件的所有权（SeTakeOwnershipPrivilege 已移除）
- 无法通过 ACL 绕过读取文件（SeBackupPrivilege 已移除）
- 无法生成子进程（cmd.exe、powershell.exe、curl.exe —— 被 Job Object 阻止）
- 无法加载内核驱动（SeLoadDriverPrivilege 已移除）

### 局限性

Windows 沙箱弱于 Linux/macOS/FreeBSD：
- 无文件系统限制 —— Windows 缺少与 Landlock 或 Seatbelt 等效的进程级文件系统沙箱
- 无网络限制 —— 阻止出站会中断 Npcap 包捕获
- 特权移除仅影响提升进程已拥有的特权

### CLI 选项

```
--no-sandbox        禁用特权移除和 Job Object
--sandbox-strict    要求完整沙箱强制生效，否则退出
```

## 权限需求<a id="privilege-requirements"></a>

RustNet 需要特权访问来捕获网络数据包：

| 平台 | 需求 |
|------|------|
| Linux | `CAP_NET_RAW` 这项 Linux capability 或 root |
| macOS | Root 或 BPF 组成员（`access_bpf` 组） |
| Windows | Administrator（用于 Npcap） |
| FreeBSD | Root 或 BPF 设备访问 |

### 为什么需要特权

- **Raw socket 访问** —— 在低层拦截网络流量（只读、非混杂模式）
- **BPF 设备访问** —— 将包过滤器加载到内核
- **eBPF 程序** —— 可选的内核探针，用于增强进程追踪（仅限 Linux）

### 推荐：基于 Linux capabilities 的执行（Linux）

与其以 root 运行，不如仅授予所需的 Linux capabilities：

```bash
# 现代 Linux（5.8+）：包捕获 + eBPF
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(which rustnet)

# 旧版 Linux（pre-5.8）：包捕获 + eBPF
sudo setcap 'cap_net_raw,cap_sys_admin+eip' $(which rustnet)

# 仅包捕获（无 eBPF 进程检测）
sudo setcap cap_net_raw+eip $(which rustnet)
```

沙箱应用后，`CAP_NET_RAW` 会被丢弃——进程仅保留所需的最小特权。

## 只读操作<a id="read-only-operation"></a>

RustNet 仅监控流量，不会：
- 修改数据包
- 阻断连接
- 注入流量
- 更改路由表
- 更改防火墙规则

包捕获以非混杂、只读模式打开。

## 不主动对外通信<a id="no-external-communication"></a>

RustNet 完全在本地运行：
- 无遥测或分析
- 无网络请求（除监控的流量外）
- 无云服务或远程 API
- 所有数据保留在你的系统上

## 日志文件隐私<a id="log-file-privacy"></a>

日志文件可能包含敏感信息：
- IP 地址和端口
- 主机名和 SNI 数据
- 进程名和 PID
- DNS 查询和响应

**最佳实践：**
- 默认禁用日志记录（不使用 `--log-level` 标志）
- 保护日志目录权限
- 实施日志轮转和保留策略
- 分享前检查日志中的敏感数据

## eBPF 安全<a id="ebpf-security"></a>

使用 eBPF 进行增强型进程检测时（Linux 默认）：

- 需要额外的 Linux capabilities（`CAP_BPF`、`CAP_PERFMON`）
- eBPF 程序在加载前由内核验证
- 仅限只读操作（不修改数据包）
- 如果 eBPF 失败，自动回退到 procfs

## 威胁模型<a id="threat-model"></a>

**RustNet 防护的内容：**
- 未经授权的用户无法在没有适当权限的情况下捕获数据包
- 基于 Linux capabilities 的权限限制了被入侵后的影响范围
- Landlock（Linux）和 Seatbelt（macOS）沙箱限制潜在的漏洞利用

**RustNet 不防护的内容：**
- 拥有包捕获权限的用户可以看到所有未加密的流量
- Root/Administrator 用户可以直接修改 RustNet 或捕获数据包
- 对机器的物理访问可以捕获数据包
- 网络级攻击（RustNet 是监控工具，不是安全设备）

### 以 Root 身份运行时的沙箱

Landlock（Linux）和 Seatbelt（macOS）即使在 RustNet 以 root（UID 0）运行时也会强制执行限制。沙箱一旦应用就无法从进程内部撤销——Landlock 设置了 `PR_SET_NO_NEW_PRIVS`，每个进程该设置不可逆。

然而，沙箱**不能**防护供应链攻击。被入侵的二进制文件可以直接不应用沙箱。Root 也可以：
- 传递 `--no-sandbox` 完全跳过沙箱
- 卸载 Landlock LSM 内核模块
- 在 macOS 上禁用 SIP（控制沙箱强制执行）
- 使用 `ptrace` 修改运行中的进程

因此，强烈建议使用细粒度 Linux capabilities（`setcap cap_net_raw=eip`）运行，而不是以 root 运行。

## 供应链安全<a id="supply-chain-security"></a>

RustNet 采取以下措施防护供应链攻击：

- **依赖锁文件**：`Cargo.lock` 已提交到仓库，固定所有传递依赖版本并记录源校验和。这防止静默版本升级。
- **安全审计**：`cargo audit` 在每次 push 和 pull request 时于 CI 中运行，对照 RustSec Advisory Database 检查依赖。
- **CI action 固定**：所有 GitHub Actions 均通过 commit SHA（而非标签）固定，防止对上游 action 的标签重写攻击。
- **保守的依赖策略**：新依赖需要说明理由，并审查其维护状态和安全记录（参见 [CONTRIBUTING.zh-CN.md](CONTRIBUTING.zh-CN.md)）。
- **构建时完整性**：Windows Npcap SDK 下载在 `build.rs` 中对照硬编码的 SHA256 校验和进行验证。
- **代码签名**：macOS 发布版本使用 Apple Developer 证书签名并进行公证。
- **校验和验证**：所有打包工作流（Homebrew、Chocolatey、AUR）在发布前计算并双重验证 SHA256 校验和。

### 局限性

- `cargo install rustnet` 从 crates.io 获取最新兼容版本，并**不**使用 `Cargo.lock`。从源码构建的用户应验证源 tarball 校验和。
- 构建脚本（`build.rs`）和 proc-macros 在编译时执行任意代码。虽然所有当前依赖都是久经考验的 crate，但这是 Rust 构建模型的固有风险。

## 审计与合规<a id="audit-and-compliance"></a>

对于生产环境：
- 审计记录谁以包捕获权限运行 RustNet
- 网络监控策略和数据保护法规合规
- 对特权网络访问进行用户访问审查
- 通过配置管理系统实现自动化 Linux capabilities 管理

## 报告安全问题<a id="reporting-security-issues"></a>

请通过 GitHub Issues 报告安全漏洞，或直接与维护者联系。
