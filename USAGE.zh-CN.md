<p align="center"><a href="USAGE.md">English</a> | <strong>简体中文</strong></p>

# 使用指南

本文档涵盖 RustNet 的详细使用说明，包括命令行选项、键盘控制、过滤、排序以及理解连接生命周期。

## 目录

- [运行 RustNet](#running-rustnet)
- [命令行选项](#command-line-options)
- [键盘控制](#keyboard-controls)
- [鼠标控制](#mouse-controls)
- [过滤](#filtering)
- [排序](#sorting)
- [进程分组](#process-grouping)
- [网络统计面板](#network-statistics-panel)
- [接口统计](#interface-statistics)
- [连接生命周期与视觉指示器](#connection-lifecycle--visual-indicators)
- [日志](#logging)

## 运行 RustNet<a id="running-rustnet"></a>

在大多数系统上，数据包捕获需要提升的特权。详细的权限配置说明参见 [INSTALL.zh-CN.md](INSTALL.zh-CN.md)。

**快速开始：**

```bash
# 使用 sudo 运行（适用于所有平台）
sudo rustnet

# 或授予 Linux capabilities 以无需 sudo 运行（详情参见 INSTALL.md）
# Linux 示例（现代内核 5.8+）：
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /path/to/rustnet
rustnet
```

**基本使用示例：**

```bash
# 使用默认设置运行
# macOS：使用 PKTAP 获取进程元数据
# Linux/其他：自动检测活动接口
rustnet

# 指定网络接口
rustnet -i eth0
rustnet --interface wlan0

# Linux：同时监控所有接口
rustnet -i any

# 过滤掉 localhost 连接（默认已过滤）
rustnet --no-localhost

# 显示 localhost 连接（覆盖默认过滤）
rustnet --show-localhost

# 设置 UI 刷新间隔（毫秒）
rustnet -r 500
rustnet --refresh-interval 2000

# 禁用深度包检测
rustnet --no-dpi

# 禁用反向 DNS 查找（默认启用）
rustnet --no-resolve-dns

# 使用指定级别启用日志（选项：error、warn、info、debug、trace）
rustnet -l debug
rustnet --log-level info

# 查看帮助和所有选项
rustnet --help
```

## 命令行选项<a id="command-line-options"></a>

```
Usage: rustnet [OPTIONS]

Options:
  -i, --interface <INTERFACE>            要监控的网络接口
      --no-localhost                     过滤掉 localhost 连接（默认：已过滤）
      --show-localhost                   显示 localhost 连接（覆盖默认过滤）
  -r, --refresh-interval <MILLISECONDS>  UI 刷新间隔，单位为毫秒 [默认：1000]
      --no-dpi                           禁用深度包检测
      --no-resolve-dns                   禁用反向 DNS 查找（默认启用）
      --show-ptr-lookups                 显示 PTR 查找连接（默认隐藏）
  -l, --log-level <LEVEL>                设置日志级别（如果未提供，则不启用日志）
      --json-log <FILE>                  将连接事件以 JSON 格式记录到指定文件
      --pcap-export <FILE>               将捕获的数据包导出到 PCAP 文件供 Wireshark 分析
      --no-color                         禁用 UI 中的所有颜色（同时尊重 NO_COLOR 环境变量）
      --geoip-country <PATH>             GeoLite2-Country.mmdb 的路径（未指定时自动发现）
      --geoip-asn <PATH>                 GeoLite2-ASN.mmdb 的路径（未指定时自动发现）
      --geoip-city <PATH>                GeoLite2-City.mmdb 的路径（未指定时自动发现）
      --no-geoip                         完全禁用 GeoIP 查询
  -f, --bpf-filter <FILTER>              用于数据包捕获的 BPF 过滤器表达式
      --no-sandbox                       禁用 Landlock 沙箱（仅限 Linux）
      --sandbox-strict                   要求完整沙箱强制执行，否则退出（仅限 Linux）
  -h, --help                             打印帮助
  -V, --version                          打印版本
```

### 选项详情<a id="option-details"></a>

#### `-i, --interface <INTERFACE>`<a id="-i---interface-interface"></a>

指定要监控的网络接口。

**默认行为（无 `-i` 标志）：**
- **macOS**：自动使用 PKTAP 获取增强型进程元数据（需要 sudo）
- **Linux/其他**：自动检测第一个可用的非回环接口

**示例：**
```bash
# 默认：自动检测接口（macOS 上使用 PKTAP）
rustnet

# Linux：使用特殊的 "any" 伪接口监控所有接口
rustnet -i any

# 监控特定接口
rustnet -i eth0          # 监控以太网接口
rustnet -i wlan0         # 监控 WiFi 接口
rustnet -i en0           # 监控 macOS 主接口

# 监控 VPN 和隧道接口（TUN/TAP 支持）
rustnet -i utun0         # macOS VPN 隧道（TUN，Layer 3）
rustnet -i tun0          # Linux/BSD VPN 隧道（TUN，Layer 3）
rustnet -i tap0          # TAP 接口（Layer 2，包含 Ethernet）
```

**TUN/TAP 接口支持：**

RustNet 完全支持监控 VPN 和虚拟网络接口：

- **TUN 接口**（Layer 3）：直接承载 IP 数据包，不含 Ethernet 头部
  - VPN 常见：WireGuard、OpenVPN（tun 模式）、Tailscale
  - 示例：`utun0-utun9`（macOS）、`tun0-tun9`（Linux/BSD）

- **TAP 接口**（Layer 2）：包含完整的 Ethernet 帧
  - 用于：OpenVPN（tap 模式）、QEMU/KVM 虚拟网络、Docker
  - 示例：`tap0-tap9`（Linux/BSD）

RustNet 自动检测 TUN/TAP 接口并相应调整数据包解析。接口类型显示在 UI 状态区域。

**平台特定说明：**
- **macOS**：不使用 `-i` 时自动使用 PKTAP 以获得更好的进程检测。使用 `-i <interface>` 来监控特定接口
- **Linux**：使用 `-i any` 同时在所有接口上捕获（其他平台不可用）
- **TUN/TAP**：所有平台均完全支持 —— RustNet 通过名称检测接口类型并调整解析
- **所有平台**：如果指定了不存在的接口，会显示错误并列出可用接口

**查找你的接口：**
- Linux：`ip link show` 或 `ifconfig`
- macOS：`ifconfig` 或 `networksetup -listallhardwareports`
- Windows：`ipconfig /all`

#### `--no-localhost` / `--show-localhost`<a id="--no-localhost--show-localhost"></a>

控制是否显示 localhost（127.0.0.1/::1）连接。

- **默认**：过滤掉 localhost 连接（`--no-localhost`）
- **覆盖**：使用 `--show-localhost` 查看 localhost 连接

这对于减少连接列表中的噪音很有用，因为大多数用户不需要监控本地 IPC 连接。

#### `-r, --refresh-interval <MILLISECONDS>`<a id="-r---refresh-interval-milliseconds"></a>

以毫秒为单位设置 UI 刷新率。较低的值提供更灵敏的更新，但会增加 CPU 使用率。

**建议：**
- **默认（1000ms）**：大多数用户的良好平衡
- **高流量网络（2000ms）**：在繁忙网络上降低 CPU 使用率
- **实时监控（500ms）**：更灵敏的更新，适合快速分析
- **低端系统（2000-3000ms）**：降低资源受限机器上的负载

#### `--no-dpi`<a id="--no-dpi"></a>

禁用深度包检测（DPI）。这在高流量网络上可降低 20-40% 的 CPU 使用率，但会禁用：
- HTTP 主机检测
- HTTPS/TLS SNI 提取
- DNS 查询/响应检测
- SSH 版本识别
- QUIC 协议检测

适用于性能受限的环境或不需要应用层详细信息时。

#### `--no-resolve-dns` / `--show-ptr-lookups`<a id="--no-resolve-dns--show-ptr-lookups"></a>

反向 DNS 查找**默认启用**：IP 地址在后台解析为主机名，并显示在连接列表中（按 `d` 键切换）和详情标签页中。

- **`--no-resolve-dns`**：完全禁用反向 DNS 解析。连接列表仅显示 IP 地址，不发起 PTR 查询。
- **`--show-ptr-lookups`**：PTR 查找流量默认隐藏。使用此标志显示解析器生成的 DNS PTR 查询。

**注意**：解析后的主机名也包含在 JSON 日志中（`destination_hostname`、`source_hostname` 字段）。

#### `-f, --bpf-filter <FILTER>`<a id="-f---bpf-filter-filter"></a>

应用 BPF（Berkeley Packet Filter）表达式在捕获时过滤数据包。这比应用层过滤更高效，因为数据包在到达 RustNet 之前在内核中被过滤。

**常见过滤器表达式：**

```bash
# 按端口过滤（匹配源 OR 目的）
rustnet --bpf-filter "port 443"
rustnet --bpf-filter "port 80 or port 8080"

# 按目的端口过滤
rustnet --bpf-filter "dst port 443"
rustnet --bpf-filter "tcp dst port 80"

# 按源端口过滤
rustnet --bpf-filter "src port 443"

# 按主机过滤
rustnet --bpf-filter "host 192.168.1.1"
rustnet --bpf-filter "net 10.0.0.0/8"

# 按协议过滤
rustnet --bpf-filter "tcp"
rustnet --bpf-filter "udp port 53"

# 组合过滤器
rustnet --bpf-filter "tcp port 443 and host github.com"

# 排除流量
rustnet --bpf-filter "not port 22"
```

**注意：**
- BPF 过滤器语法遵循 pcap-filter(7) 格式。无效过滤器会导致 RustNet 退出并报错。使用 `man pcap-filter` 查看完整语法文档。
- **macOS 限制：** BPF 过滤器与 PKTAP（linktype 149）不兼容。在 macOS 上指定 BPF 过滤器时，RustNet 自动回退到常规接口捕获。这意味着进程识别使用 `lsof` 而非 PKTAP 的直接进程元数据，对于短寿命连接可能略不准确。

#### `-l, --log-level <LEVEL>`<a id="-l---log-level-level"></a>

使用指定级别启用日志。**默认禁用**日志。

**可用级别：**
- `error` —— 仅错误（最小日志）
- `warn` —— 警告和错误
- `info` —— 一般信息（建议用于常规调试）
- `debug` —— 详细的调试信息
- `trace` —— 非常详细的输出（包含数据包级详情）

日志文件创建于 `logs/` 目录，带时间戳：`rustnet_YYYY-MM-DD_HH-MM-SS.log`

## 键盘控制<a id="keyboard-controls"></a>

### 导航<a id="navigation"></a>

- `↑` 或 `k` —— 在连接列表中向上导航
- `↓` 或 `j` —— 在连接列表中向下导航
- `g` —— 跳转到第一个连接（vim 风格）
- `G`（Shift+g）—— 跳转到最后一个连接（vim 风格）
- `PageUp` 或 `Ctrl+B` —— 向上翻一页
- `PageDown` 或 `Ctrl+F` —— 向下翻一页

### 视图与标签页<a id="views-and-tabs"></a>

- `Tab` —— 在标签页之间切换（概览、详情、接口、图表、帮助）
- `Shift+Tab` —— 反向切换标签页
- `i` —— 切换接口统计视图
- `Enter` —— 查看所选连接的详细信息
- `Esc` —— 返回上一个视图或清除活动过滤器
- `h` —— 切换帮助屏幕

### 操作<a id="actions"></a>

- `c` —— 将远程地址复制到剪贴板
- `p` —— 在服务名和端口号之间切换
- `d` —— 在主机名和 IP 地址之间切换（由 `--no-resolve-dns` 禁用）
- `/` —— 进入过滤模式（vim 风格搜索，实时结果）
- `x` —— 清除所有连接并重置统计（按两次确认）
- `t` —— 切换历史（已关闭）连接的显示
- `r` —— 将视图重置为默认值（清除分组、排序、过滤和历史）

### 进程分组<a id="process-grouping-1"></a>

- `a` —— 切换进程分组模式（按进程聚合连接）
- `Space` —— 展开/折叠所选进程分组
- `←` 或 `h` —— 折叠所选分组
- `→` 或 `l` —— 展开所选分组

### 排序<a id="sorting-1"></a>

- `s` —— 在可排序列之间循环切换（从左到右顺序）
- `S`（Shift+s）—— 切换排序方向（升序/降序）

### 退出<a id="exit"></a>

- `q` —— 退出应用（按两次确认）
- `Ctrl+C` —— 立即退出

## 鼠标控制<a id="mouse-controls"></a>

RustNet 具有完整的鼠标支持。鼠标捕获自动启用 —— 以下描述的所有交互均可开箱即用。

### 概览标签页<a id="overview-tab"></a>

| 操作 | 效果 |
|------|------|
| **单击** 连接行 | 选择该连接 |
| **双击** 连接行 | 打开该连接的详情标签页 |
| **滚轮** 在连接列表上 | 在连接中上下导航 |
| **单击** 标签页名称 | 切换到该标签页 |

### 分组视图（按 `a` 启用）<a id="grouped-view-press-a-to-enable"></a>

| 操作 | 效果 |
|------|------|
| **单击** 分组头部（`[+]`/`[-]`） | 选择该分组 |
| **双击** 分组头部 | 展开或折叠进程分组 |
| **单击** 展开分组内的连接 | 选择该连接 |
| **双击** 展开分组内的连接 | 打开该连接的详情标签页 |
| **滚轮** | 在分组和连接中导航 |

### 详情标签页<a id="details-tab"></a>

| 操作 | 效果 |
|------|------|
| **单击** 任意字段行 | 将字段值复制到系统剪贴板 |

单击字段仅复制值（不包括标签）。例如，单击 "Remote Address: 142.250.80.46:443" 行会将 `142.250.80.46:443` 复制到剪贴板。状态栏会显示 3 秒的确认消息。

"Connection Information" 和 "Traffic Statistics" 两个面板都支持点击复制。

## 过滤<a id="filtering"></a>

按 `/` 进入过滤模式。输入以实时过滤连接，输入时可用方向键导航。

### 基本搜索<a id="basic-search"></a>

直接输入任意文本即可在所有连接字段中搜索：

```
/google        # 查找包含 "google" 的连接
/firefox       # 查找 Firefox 连接
/192.168       # 查找 IP 以 192.168 开头的连接
```

### 关键字过滤器<a id="keyword-filters"></a>

使用关键字过滤器进行定向搜索：

| 关键字 | 别名 | 描述 | 示例 |
|---------|---------|-------------|---------|
| `port:` | | 精确端口匹配；使用 `/pattern/` 进行正则 | `port:22` 仅匹配 22；`port:/22/` 匹配 22、220、5522 |
| `sport:` | `srcport:`、`source-port:` | 源端口（精确或正则） | `sport:80` 仅匹配源端口 80 |
| `dport:` | `dstport:`、`dest-port:`、`destination-port:` | 目的端口（精确或正则） | `dport:443` 仅匹配目的端口 443 |
| `src:` | `source:` | 源 IP/主机名 | `src:192.168` 匹配 192.168.x.x |
| `dst:` | `dest:`、`destination:` | 目的地址 | `dst:github.com` 匹配 github.com |
| `process:` | `proc:` | 进程名 | `process:ssh` 匹配 ssh、sshd |
| `sni:` | `host:`、`hostname:` | SNI 主机名（HTTPS） | `sni:api` 匹配 api.example.com |
| `service:` | `svc:` | 服务名 | `service:https` 匹配 HTTPS 服务 |
| `app:` | `application:` | 检测到的应用协议 | `app:ssh` 匹配 SSH 连接 |
| `state:` | | 协议状态 | `state:established` 匹配已建立的连接 |
| `proto:` | `protocol:` | 协议类型 | `proto:tcp` 匹配 TCP 连接 |

### 状态过滤<a id="state-filtering"></a>

按当前协议状态过滤连接（不区分大小写）：

⚠️ **注意：** 状态追踪的准确性因协议而异。TCP 状态最可靠，而 UDP、QUIC 和其他协议的状态来自数据包检测，可能并不总是反映真实的连接状态。

**示例：**
```
state:syn_recv       # 显示半开连接（可用于检测 SYN flood）
state:established    # 仅显示已建立的连接
state:fin_wait       # 显示处于关闭状态的连接
state:quic_handshake # 显示握手期间的 QUIC 连接
state:dns_query      # 显示 DNS 查询连接
state:udp_active     # 显示活跃的 UDP 连接
```

**可用状态：**

| 协议 | 状态 |
|----------|--------|
| **TCP** | `SYN_SENT`、`SYN_RECV`、`ESTABLISHED`、`FIN_WAIT1`、`FIN_WAIT2`、`TIME_WAIT`、`CLOSE_WAIT`、`LAST_ACK`、`CLOSING`、`CLOSED` |
| **QUIC** | `QUIC_INITIAL`、`QUIC_HANDSHAKE`、`QUIC_CONNECTED`、`QUIC_DRAINING`、`QUIC_CLOSED` ⚠️ *注意：可能不完整，因为握手已加密* |
| **UDP** | `UDP_ACTIVE`、`UDP_IDLE`、`UDP_STALE` |
| **DNS** | `DNS_QUERY`、`DNS_RESPONSE` |
| **SSH** | `BANNER`、`KEYEXCHANGE`、`AUTHENTICATION`、`ESTABLISHED` ⚠️ *注意：基于数据包检测* |
| **Other** | `ECHO_REQUEST`、`ECHO_REPLY`、`ARP_REQUEST`、`ARP_REPLY` |

### 正则过滤器<a id="regex-filters"></a>

将任何过滤值包裹在 `/pattern/` 中以使用正则表达式（不区分大小写）。正则使用 `regex-lite` crate 支持的标准语法。

```
/192\.168\.[0-9]+/         # 在所有字段中通用正则
port:/22/                  # 端口包含 "22"（22、220、2200、5522 …）
sni:/.*github\..*/         # SNI 匹配 github.com、api.github.com 等
process:/chrom(e|ium)/     # Chrome 或 Chromium
```

> **端口匹配**：`port:443` 是**精确**匹配（仅端口 443）。如需子串/正则行为，请使用 `port:/443/`。

### 组合过滤器<a id="combining-filters"></a>

用空格组合多个过滤器（隐式 AND）：

```
sport:80 process:nginx              # Nginx 从 80 端口发出的连接
dport:443 sni:google.com            # 到 Google 的 HTTPS 连接
sport:443 state:syn_recv            # 到 443 端口的半开连接（SYN flood 检测）
proto:tcp state:established         # 所有已建立的 TCP 连接
process:firefox state:quic_connected # Firefox 的活跃 QUIC 连接
dport:22 app:openssh                # 使用 OpenSSH 的 SSH 连接
state:established app:ssh           # 已建立的 SSH 连接
```

### 清除过滤器<a id="clearing-filters"></a>

按 `Esc` 清除活动过滤器并返回完整连接列表。

## 排序<a id="sorting"></a>

RustNet 提供强大的表格排序功能来帮助你分析网络连接。按 `s` 按从左到右的视觉顺序在可排序列之间循环切换，按 `S`（Shift+s）在升序和降序之间切换。

### 快速开始<a id="quick-start"></a>

**找出带宽大户（上下行合计流量）：**
```
反复按 's' 直到看到：Down/Up ↓
总带宽最高的连接显示在顶部
```

**按进程名排序：**
```
反复按 's' 直到看到：Process ↑
连接按进程名字母顺序排序
```

### 可排序列<a id="sortable-columns"></a>

按 `s` 按从左到右顺序在列之间循环切换：

| 列 | 默认方向 | 描述 |
|--------|-------------------|-------------|
| **Protocol** | ↑ 升序 | 按协议类型排序（TCP、UDP、ICMP 等） |
| **Local Address** | ↑ 升序 | 按本地 IP:port 排序（适用于多接口系统） |
| **Remote Address** | ↑ 升序 | 按远程 IP:port 排序 |
| **Location** | ↑ 升序 | 按国家代码排序（需要 GeoIP 数据库） |
| **State** | ↑ 升序 | 按连接状态排序（ESTABLISHED 等） |
| **Service** | ↑ 升序 | 按服务名或端口号排序 |
| **Application** | ↑ 升序 | 按检测到的应用协议排序（HTTP、DNS 等） |
| **Bandwidth (Down/Up)** | ↓ 降序 | 按**上下行合计**带宽排序（默认最高优先） |
| **Process** | ↑ 升序 | 按进程名字母顺序排序 |

### 排序指示器<a id="sort-indicators"></a>

活动排序列通过以下方式高亮：
- **青色**和**下划线**样式
- 显示排序方向的**箭头符号**（↑ 或 ↓）
- 显示当前排序状态的**表格标题**

**视觉指示器：**
```
活动列头部以青色和下划线显示：
Pro │ Local Address │ Remote Address ↑│ State │ ...
                      ^^^^^^^^^^^^^^^^
                      （青色、下划线、带箭头）

表格标题显示当前排序：
┌─ Active Connections (Sort: Remote Addr ↑) ──┐
```

### 排序行为<a id="sort-behavior"></a>

**按 `s`（小写）—— 循环列：**
- 移动到从左到右视觉顺序的下一列
- **重置为该列的默认方向**
- 带宽列默认降序（↓）以优先显示最高值
- 文本列默认升序（↑）以按字母顺序排列

**按 `S`（Shift+s）—— 切换方向：**
- **保持在当前列**
- 在升序（↑）和降序（↓）之间切换
- 可用于反转排序顺序（例如找出带宽最小的用户）

**多次按 `s` 返回默认：**
- 循环浏览所有列后返回默认按时间排序（按连接创建时间）
- 默认模式下不显示排序指示器

### 过滤时排序<a id="sorting-with-filtering"></a>

排序与过滤无缝配合：
1. **先过滤**：按 `/` 输入过滤条件
2. **再排序**：按 `s` 对过滤结果排序
3. **排序持续**：更改过滤器时保持排序顺序活动

示例工作流：
```
1. 按 '/' 并输入 'firefox' 过滤 Firefox 连接
2. 按 's' 直到看到 "Down/Up ↓"
3. 现在查看按总带宽（上下行合计）排序的 Firefox 连接
```

### 示例<a id="examples"></a>

**找出哪个进程使用最多带宽：**
```
1. 按 's' 直到出现 "Down/Up ↓"
2. 顶部连接显示最高总带宽（上下行合计）
3. 查看 "Process" 列以确定是哪个应用
```

**按远程目的地排序连接：**
```
1. 按 's' 直到出现 "Remote Address ↑"
2. 连接按远程 IP 地址分组
3. 如需，按 'S' 反转顺序
```

**找出空闲连接（最低带宽）：**
```
1. 按 's' 循环到 "Down/Up ↓"
2. 按 'S' 切换到 "Down/Up ↑"（升序）
3. 总带宽最低的连接显示在最前面
```

**按应用协议排序：**
```
1. 按 's' 直到出现 "Application / Host ↑"
2. 所有 HTTPS 连接分组在一起，DNS 查询分组在一起，等等
3. 适合查找特定类型的所有连接
```

## 进程分组<a id="process-grouping"></a>

RustNet 可以按进程名分组连接，提供聚合视图，让你更容易看到哪些应用正在使用你的网络。

### 启用进程分组<a id="enabling-process-grouping"></a>

按 `a` 切换进程分组模式。启用时：
- 连接按进程名分组（按字母顺序排序）
- 每个分组显示聚合统计
- 分组可以展开/折叠以显示单个连接

再次按 `a` 返回扁平（未分组）连接列表。

### 分组视图显示<a id="grouped-view-display"></a>

启用分组时，连接列表显示进程分组：

```
[+] firefox (12)              TCP: 10 UDP: 2     12.5K↓/1.2K↑
[-] chrome (8)                TCP: 8  UDP: 0     45.2K↓/5.1K↑
  ├── TCP  192.168.1.10:54321  142.250.80.78:443    ESTABLISHED  HTTPS
  ├── TCP  192.168.1.10:54322  142.250.80.78:443    ESTABLISHED  HTTPS
  └── UDP  192.168.1.10:54323  8.8.8.8:53           -            DNS
[+] systemd-resolved (3)      TCP: 0  UDP: 3     0.2K↓/0.1K↑
[+] <unknown> (5)             TCP: 2  UDP: 3     0.5K↓/0.2K↑
```

**分组头部格式：**
- `[+]` / `[-]` —— 折叠/展开指示器
- 进程名和连接数
- 协议细分（TCP/UDP 计数）
- 总带宽（下载↓/上传↑）

**展开的连接：**
- 树形前缀（`├──` / `└──`）显示层级
- 单个连接详情（协议、地址、状态、应用）

### 展开和折叠分组<a id="expanding-and-collapsing-groups"></a>

| 按键 | 操作 |
|-----|--------|
| `Space` | 切换所选分组的展开/折叠 |
| `→` 或 `l` | 展开所选分组 |
| `←` 或 `h` | 折叠所选分组 |

### 分组视图中的导航<a id="navigation-in-grouped-view"></a>

导航方式与扁平视图相同：
- `↑`/`k` 和 `↓`/`j` 在可见行（分组和展开的连接）之间移动
- `g` 跳转到第一行
- `G` 跳转到最后一行
- `Enter` 在连接上打开详情视图

### 未知进程<a id="unknown-processes"></a>

没有进程信息的连接被分组到单个 `<unknown>` 分组中。这通常包括：
- 在进程查找完成前就已关闭的短寿命连接
- 某些平台上的系统级连接
- 来自受限进程的连接

### 分组时过滤<a id="filtering-with-grouping"></a>

过滤与分组无缝配合：
1. 按 `/` 输入你的过滤条件
2. 仅显示包含匹配连接的分组
3. 展开分组以查看哪些连接匹配

### 分组时排序<a id="sorting-in-grouped-view"></a>

启用分组时：
- 分组按进程名字母顺序排序（A-Z）
- 排序列指示器显示分组内连接的排序方式
- 按 `s` 更改展开分组内连接的排序方式

### 重置视图<a id="reset-view"></a>

按 `r` 一次性重置所有视图设置：
- 禁用进程分组
- 清除任何活动过滤器
- 将排序重置为默认（按时间顺序）

## 网络统计面板<a id="network-statistics-panel"></a>

网络统计面板显示在界面右侧，位于流量面板下方。它提供直接从数据包捕获分析中得出的实时 TCP 连接质量指标，使其在 Linux、macOS、Windows 和 FreeBSD 上跨平台一致。

### 可用指标<a id="available-metrics"></a>

**TCP 重传**
检测由于数据包丢失或超时而重新传输的 TCP 段。RustNet 通过分析 TCP 序列号来识别重传：当到达的数据包序列号低于预期时，表示原始数据包已丢失并正在重发。

**乱序包**
追踪到达顺序错误的入站 TCP 数据包，通常由网络拥塞或多条路由路径导致。这些数据包最终会到达，但顺序错误，需要接收方缓冲并重新排序。

**快速重传**
识别由收到三个重复确认（RFC 2581）触发的 TCP 快速重传事件。这种机制允许 TCP 比等待超时更快地从数据包丢失中恢复，从而提高连接性能。

### 统计显示格式<a id="statistics-display-format"></a>

面板为每个指标显示**活动**和**总计**计数：

```
TCP Retransmits: 5 / 142 total
Out-of-Order: 2 / 89 total
Fast Retransmits: 1 / 23 total
Active TCP Flows: 18
```

- **活动计数**（左侧数字）：当前追踪连接的各事件总和。这个数字随着连接的建立和清理而上下波动。
- **总计计数**（右侧数字）：自 RustNet 启动以来的累积计数。这个数字只增不减，提供历史背景。
- **Active TCP Flows**：具有分析数据的活跃 TCP 连接数。

### 逐连接统计<a id="per-connection-statistics"></a>

查看连接详情时（在连接上按 `Enter`），显示该特定连接的 TCP 分析：

```
TCP Retransmits: 3
Out-of-Order: 1
Fast Retransmits: 0
```

这些计数器独立追踪每个连接，允许你识别遇到数据包丢失或网络问题的有问题连接。

### 使用场景<a id="use-cases"></a>

**网络质量监控**
重传或乱序包的突然增加表明网络拥塞、数据包丢失或路由问题。

**连接故障排查**
特定连接上的高重传计数可以识别：
- 到某些目的地的不可靠网络路径
- 带宽受限的链路
- 故障的网络硬件或驱动

**性能分析**
快速重传频率表明 TCP 在不等待超时的情况下从数据包丢失中恢复的情况。

### 技术说明<a id="technical-notes"></a>

- 统计源自 TCP 序列号分析，不需要数据包时间戳
- 分析适用于出站和入站数据包
- SYN 和 FIN 标志在序列号追踪中被正确计算（每个消耗 1 个序列号）
- 仅 TCP 连接显示分析指标；UDP、ICMP 和其他协议没有这些指标

## 接口统计<a id="interface-statistics"></a>

RustNet 在所有支持的平台上（Linux、macOS、FreeBSD、Windows）提供实时网络接口统计。接口统计显示在两个位置：

### 访问接口统计<a id="accessing-interface-statistics"></a>

**概览标签页（主屏幕）：**
- 接口统计出现在右侧面板，位于网络统计下方
- 显示最多 3 个活跃接口及当前速率
- 显示：`InterfaceName: X KB/s ↓ / Y KB/s ↑`
- 显示累计总数：`Errors (Total): N  Drops (Total): M`

**接口标签页（详细视图）：**
- 按 `i` 切换接口统计视图
- 显示所有网络接口的详细表格
- 显示每个接口的综合指标

### 显示的统计<a id="statistics-displayed"></a>

| 指标 | 描述 | 说明 |
|--------|-------------|-------|
| **RX Rate** | 当前接收速率（字节/秒） | 根据近期活动计算 |
| **TX Rate** | 当前发送速率（字节/秒） | 根据近期活动计算 |
| **RX Packets** | 接收的总数据包数 | 自启动/接口上线以来累计 |
| **TX Packets** | 发送的总数据包数 | 自启动/接口上线以来累计 |
| **RX Err** | 接收错误 | 累计总数（非近期） |
| **TX Err** | 发送错误 | 累计总数（非近期） |
| **RX Drop** | 丢弃的入站数据包 | 累计总数（非近期） |
| **TX Drop** | 丢弃的出站数据包 | 累计总数（非近期） |
| **Collisions** | 网络冲突 | 平台相关的可用性 |

**重要**：错误和丢弃计数器是**自系统启动或接口上线以来的累计总数**，不是近期活动。这些有助于识别长期接口可靠性，但不会显示即时问题。

### 平台特定行为<a id="platform-specific-behavior"></a>

**所有平台：**
- 所有计数器（字节、数据包、错误、丢弃）自启动/接口上线以来累计
- 速率（字节/秒）根据每 2 秒采集的快照计算
- 包含回环接口用于监控本地流量

**Windows：**
- 过滤掉虚拟/过滤适配器，仅显示物理接口：
  - 排除：`-Npcap`、`-WFP`、`-QoS`、`-Native`、`-Virtual`、`-Packet` 变体
  - 排除：`Lightweight Filter`、`MAC Layer` 接口
  - 排除：已断开的 "Local Area Connection" 适配器
- 使用基于 LUID 的去重防止重复的接口条目
- Collisions：始终为 0（现代 Windows 接口上不可用）

**macOS：**
- 包含数据验证以检测虚拟接口上的损坏计数器
- TX Drops：始终为 0（macOS 上可用性有限）
- 如果错误/丢弃计数器值看起来损坏（>2^31 或 errors>packets），则进行清理

**FreeBSD：**
- TX Drops：始终为 0（FreeBSD 上通常不可用）
- 使用 BSD getifaddrs API 配合 AF_LINK 过滤

**Linux：**
- 从 `/sys/class/net/{interface}/statistics` 读取统计
- 所有计数器通常可用且可靠

### 解读统计<a id="interpreting-the-statistics"></a>

**健康的接口：**
```
Ethernet: 2.40 KB/s ↓ / 1.96 KB/s ↑
  Errors (Total): 0  Drops (Total): 0
```
零或极低的错误/丢弃计数表明可靠的网络连接。

**有问题的接口：**
```
WiFi: 150 KB/s ↓ / 45 KB/s ↑
  Errors (Total): 1089  Drops (Total): 2178
```
高错误/丢弃计数可能表明：
- 信号干扰（WiFi）
- 线缆问题（Ethernet）
- 网络拥塞
- 驱动或硬件问题

**注意**：由于错误/丢弃计数器是累计的，请相对于总数据包数来评估它们。数百万数据包中有少量错误是正常的；数据包数低但有数千错误则表明有问题。

### 接口过滤<a id="interface-filtering"></a>

**显示哪些接口：**
- 接口必须在操作上 "up" OR 拥有流量统计
- 包含回环接口（用于监控本地连接）
- Windows 上排除虚拟/过滤适配器（它们镜像物理接口）

**概览标签页过滤：**
- Windows：显示所有活跃接口（NPF 设备路径自动检测）
- macOS/Linux：显示有近期流量的接口（`rx_bytes > 0 || tx_bytes > 0 || rx_packets > 0 || tx_packets > 0`）
- 特殊接口（`any`、`pktap`）：显示有任何活动的所有接口

**接口标签页：**
- 显示通过平台特定过滤的所有检测到的接口
- 排序将当前捕获的接口排在最前面（高亮）
- 其他接口按字母顺序出现

### 使用场景<a id="use-cases-1"></a>

**带宽监控：**
监控所有网络接口的实时带宽使用情况以识别：
- 哪个接口承载最多流量
- WiFi 与 Ethernet 之间的带宽分布
- 本地流量体积（回环接口）

**可靠性分析：**
检查累计错误和丢弃计数器以：
- 识别不可靠的网络接口
- 检测硬件或驱动问题
- 随时间比较接口质量

**多接口系统：**
在具有多个网络接口的系统上：
- 跨接口比较性能
- 监控 VPN 隧道统计
- 追踪接口故障转移行为

## 连接生命周期与视觉指示器<a id="connection-lifecycle--visual-indicators"></a>

RustNet 使用智能超时管理自动清理不活跃的连接，同时在移除前提供视觉警告。

### 视觉陈旧度指示器<a id="visual-staleness-indicators"></a>

连接根据距离被清理的接近程度改变颜色：

| 颜色 | 含义 | 陈旧度 |
|-------|---------|-----------|
| **白色**（默认） | 活跃连接 | < 75% 的超时时间 |
| **黄色** | 陈旧 - 接近超时 | 75-90% 的超时时间 |
| **红色** | 严重 - 即将被移除 | > 90% 的超时时间 |

**示例**：一条超时为 10 分钟的 HTTP 连接会：
- 前 7.5 分钟保持**白色**
- 7.5 到 9 分钟变为**黄色**（警告）
- 9 分钟后变为**红色**（严重）
- 10 分钟时被移除

这让你在连接即将从列表中消失前得到预警。

### 智能协议感知超时<a id="smart-protocol-aware-timeouts"></a>

RustNet 根据协议和检测到的应用调整连接超时：

#### TCP 连接<a id="tcp-connections"></a>
- **HTTP/HTTPS**（通过 DPI 检测）：**10 分钟** —— 支持 HTTP keep-alive
- **SSH**（通过 DPI 检测）：**30 分钟** —— 适应长交互会话
- **活跃已建立**（< 1 分钟空闲）：**10 分钟**
- **空闲已建立**（> 1 分钟空闲）：**5 分钟**
- **TIME_WAIT**：30 秒 —— 标准 TCP 超时
- **CLOSED**：5 秒 —— 快速清理
- **SYN_SENT、FIN_WAIT 等**：30-60 秒

#### UDP 连接<a id="udp-connections"></a>
- **基于 UDP 的 SSH**：**30 分钟** —— 长会话
- **DNS**：**30 秒** —— 短查询
- **普通 UDP**：**60 秒** —— 标准超时

#### QUIC 连接（检测到的状态）<a id="quic-connections-detected-state"></a>
- **已连接**：**3 分钟** 默认（或当可用时使用来自传输参数的 idle timeout）
- **带 CONNECTION_CLOSE 帧**：1-10 秒（基于关闭类型）
- **Initial/Handshaking**：60 秒 —— 允许连接建立
- **Draining**：10 秒 —— RFC 9000 draining 周期

### 基于活动的调整<a id="activity-based-adjustment"></a>

显示近期数据包活动的连接获得更长的超时：
- **最近数据包 < 60 秒前**：使用"活跃"超时（更长）
- **最近数据包 > 60 秒前**：使用"空闲"超时（更短）

这确保活跃连接保持可见，而空闲连接更快被清理。

### 连接为什么消失<a id="why-connections-disappear"></a>

连接在以下情况下被移除：
1. **在超时期间内未收到数据包**
2. 连接进入**关闭状态**（TCP CLOSED、QUIC CLOSED）
3. 检测到**显式关闭帧**（QUIC CONNECTION_CLOSE）

**注意**：速率指示器（带宽显示）基于近期活动显示*衰减*的流量。连接可能显示带宽下降（黄色条），但在超过空闲超时前仍保留在列表中。这是有意设计的 —— 视觉衰减让你在连接被移除前有时间看到它逐渐结束。

### 历史连接<a id="historic-connections"></a>

默认情况下，连接在超时或关闭后从列表中消失。按 `t` 切换**历史连接**模式，使已关闭的连接与活跃连接一起保持可见。

**工作原理：**

当连接被清理时，它被归档到历史连接池中（最多 5,000 条；最旧的先被逐出）。按 `t` 切换它们的可见性：

- **活跃连接**以标准颜色指示器正常显示
- **历史连接**以**暗灰色**显示，以清楚区分于活跃连接
- 启用历史模式时，表格标题变为 **"Active + Historic Connections"**

**详情视图：**

选择历史连接并按 `Enter` 显示通常的连接详情，外加一个**Status**字段显示连接关闭多久前（例如 "Closed (5m ago)"）。

**统计面板：**

当存在历史连接时，统计面板在总活跃连接数下方显示一个单独的 **"Historic: N"** 计数。

**分组视图：**

在进程分组模式（`a`）中，当启用历史模式时，分组头部将历史连接数与活跃计数分开显示。

**图表标签页：**

图表标签页始终只显示活跃连接，即使历史模式开启。

**重置：**

- 按 `r` 重置所有视图设置，这也会隐藏历史连接
- 按 `x` 两次清除所有连接，这也会清除历史池

## 日志<a id="logging"></a>

日志**默认禁用**。使用 `--log-level` 选项启用时，RustNet 在 `logs/` 目录中创建带时间戳的日志文件。每个会话生成一个新日志文件，格式为 `rustnet_YYYY-MM-DD_HH-MM-SS.log`。

### 日志文件内容<a id="log-file-contents"></a>

日志文件包含：
- 应用启动和关闭事件
- 网络接口信息
- 数据包捕获统计
- 连接状态变更
- 错误诊断
- DPI 检测结果（debug/trace 级别）
- 性能指标（trace 级别）

### 启用日志<a id="enabling-logging"></a>

使用 `--log-level` 选项启用日志：

```bash
# Info 级别日志（建议常规使用）
sudo rustnet --log-level info

# Debug 级别日志（详细故障排查）
sudo rustnet --log-level debug

# Trace 级别日志（非常详细，包含数据包级详情）
sudo rustnet --log-level trace

# 仅 Error 级别日志（最小日志）
sudo rustnet --log-level error
```

### 日志级别说明<a id="log-levels-explained"></a>

| 级别 | 记录内容 | 使用场景 |
|-------|------------------|----------|
| `error` | 仅错误和关键问题 | 生产监控 |
| `warn` | 警告和错误 | 带警告的正常运行 |
| `info` | 一般信息、启动/关闭 | 标准调试 |
| `debug` | 详细的调试信息 | 故障排查 |
| `trace` | 数据包级详情，非常详细 | 深度调试 |

### 管理日志文件<a id="managing-log-files"></a>

**日志清理脚本：**

提供了 `scripts/clear_old_logs.sh` 脚本用于日志清理：

```bash
# 删除 7 天前的日志
./scripts/clear_old_logs.sh

# 通过编辑脚本自定义保留期
```

**手动清理：**

```bash
# 删除所有日志
rm -rf logs/

# 删除 7 天前的日志（Linux/macOS）
find logs/ -name "rustnet_*.log" -mtime +7 -delete

# 查看日志文件大小
du -sh logs/
```

### 日志文件隐私<a id="log-file-privacy"></a>

⚠️ **警告**：日志文件可能包含敏感信息：
- IP 地址和端口
- 主机名和 SNI 数据（HTTPS）
- DNS 查询和响应
- 进程名和 PID
- 数据包内容（trace 级别）

**最佳实践：**
- 仅在需要调试时启用日志
- 保护日志目录权限：`chmod 700 logs/`
- 分享前检查日志中的敏感数据
- 实施日志轮转和保留策略
- 不再需要时删除日志

### 使用日志故障排查<a id="troubleshooting-with-logs"></a>

报告问题时：
1. 启用 debug 日志：`rustnet --log-level debug`
2. 重现问题
3. 在 `logs/` 中找到最新的日志文件
4. 查看错误或异常行为
5. 分享前脱敏敏感信息

对于性能问题，trace 级别日志提供最详细的细节，但会快速生成大量日志文件。

### JSON 日志<a id="json-logging"></a>

`--json-log` 选项启用将连接事件以结构化 JSON 格式记录到文件。每行是一个独立的 JSON 对象（JSONL 格式）。

```bash
# 启用 JSON 日志
sudo rustnet --json-log /tmp/connections.json

# 与其他选项组合
sudo rustnet -i eth0 --json-log ~/network-events.json
```

**事件类型：**<a id="event-types"></a>
- `new_connection` —— 首次检测到新连接时记录
- `connection_closed` —— 连接在变为不活跃后被清理时记录

**JSON 字段：**<a id="json-fields"></a>

| 字段 | 类型 | 描述 |
|-------|------|-------------|
| `timestamp` | string | RFC3339 UTC 时间戳 |
| `event` | string | 事件类型（`new_connection` 或 `connection_closed`） |
| `protocol` | string | 协议（TCP、UDP 等） |
| `source_ip` | string | 本地 IP 地址 |
| `source_port` | number | 本地端口号 |
| `destination_ip` | string | 远程 IP 地址 |
| `destination_port` | number | 远程端口号 |
| `pid` | number | 进程 ID（如果可用） |
| `process_name` | string | 进程名（如果可用） |
| `service_name` | string | 端口查找的服务名（如果可用） |
| `direction` | string | 连接方向（`outgoing` 或 `incoming`），仅当观察到 TCP 握手时 |
| `dpi_protocol` | string | 检测到的应用协议（如果启用 DPI） |
| `dpi_domain` | string | 提取的域名/主机名（如果可用） |
| `bytes_sent` | number | 发送的总字节数（仅 connection_closed） |
| `bytes_received` | number | 接收的总字节数（仅 connection_closed） |
| `duration_secs` | number | 连接持续时间，单位为秒（仅 connection_closed） |

**示例输出：**<a id="example-output"></a>

```json
{"timestamp":"2025-01-15T10:30:00Z","event":"new_connection","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","dpi_protocol":"HTTPS","dpi_domain":"example.com"}
{"timestamp":"2025-01-15T10:30:05Z","event":"connection_closed","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","bytes_sent":1024,"bytes_received":4096,"duration_secs":5}
```

**处理 JSON 日志：**<a id="processing-json-logs"></a>

```bash
# 漂亮打印最新事件
tail -f /tmp/connections.json | jq .

# 按进程过滤
cat /tmp/connections.json | jq 'select(.process_name == "firefox")'

# 按目的地统计连接数
cat /tmp/connections.json | jq -s 'group_by(.destination_ip) | map({ip: .[0].destination_ip, count: length})'
```

### PCAP 导出<a id="pcap-export"></a>

`--pcap-export` 选项将原始数据包捕获到标准 PCAP 文件，供 Wireshark、tcpdump 或其他工具分析。

```bash
# 导出所有捕获的数据包
sudo rustnet -i eth0 --pcap-export capture.pcap

# 与 BPF 过滤器组合
sudo rustnet -i eth0 --bpf-filter "tcp port 443" --pcap-export https.pcap
```

**输出文件：**<a id="output-files"></a>

| 文件 | 描述 |
|------|-------------|
| `capture.pcap` | 标准 PCAP 格式的原始数据包 |
| `capture.pcap.connections.jsonl` | 流式连接元数据，带进程信息 |

**Sidecar JSONL 格式**（每行一个 JSON 对象，连接关闭时写入）：<a id="sidecar-jsonl-format"></a>

```json
{"timestamp":"2026-01-17T10:30:00Z","protocol":"TCP","local_addr":"192.168.1.100:54321","remote_addr":"142.250.80.46:443","pid":1234,"process_name":"firefox","first_seen":"...","last_seen":"...","bytes_sent":1024,"bytes_received":8192,"state":"ESTABLISHED"}
```

| 字段 | 描述 |
|-------|-------------|
| `timestamp` | 连接记录写入时间 |
| `protocol` | TCP、UDP、ICMP 等 |
| `local_addr` / `remote_addr` | 连接端点 |
| `pid` / `process_name` | 进程信息（如果已识别） |
| `first_seen` / `last_seen` | 连接时间戳 |
| `bytes_sent` / `bytes_received` | 流量总计 |
| `state` | 最终连接状态 |

#### 用进程信息富化 PCAP<a id="enriching-pcap-with-process-information"></a>

标准 PCAP 文件不包含进程信息。使用附带的 `scripts/pcap_enrich.py` 脚本将数据包与进程关联：

```bash
# 安装 scapy（必需）
pip install scapy

# 显示带进程信息的数据包
python scripts/pcap_enrich.py capture.pcap

# 输出为 TSV 以便进一步处理
python scripts/pcap_enrich.py capture.pcap --format tsv > report.tsv

# 创建带进程注释的注释 PCAPNG（需要 Wireshark 的 editcap）
python scripts/pcap_enrich.py capture.pcap -o annotated.pcapng
```

注释 PCAPNG 将进程信息嵌入为数据包注释，在 Wireshark 的数据包详情中可见。

**手动关联：**

```bash
# 查看数据包
wireshark capture.pcap

# 查看进程映射
cat capture.pcap.connections.jsonl | jq -r '[.protocol, .local_addr, .remote_addr, .pid, .process_name] | @tsv'

# 在 Wireshark 中按连接元组过滤
# ip.addr == 142.250.80.46 && tcp.port == 443
```
