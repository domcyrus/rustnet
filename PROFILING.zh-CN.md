<p align="center"><a href="PROFILING.md">English</a> | <strong>简体中文</strong></p>

# RustNet 性能分析指南

本指南介绍如何对 RustNet 进行性能分析，以定位性能瓶颈。

## 快速开始<a id="quick-start"></a>

### 使用 perf + flamegraph 进行 CPU 分析<a id="cpu-profiling-with-perf--flamegraph"></a>

在 Linux 上分析 CPU 占用最简单的方式：

```bash
# 1. 安装 flamegraph 工具
cargo install flamegraph

# 2. 构建带调试符号的 release 二进制
# 重要：要生成有意义的火焰图，必须包含调试符号！
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release

# 或临时在 Cargo.toml 中加入：
# [profile.release]
# debug = true

# 3. 在性能分析下运行（perf 需要 sudo）
# 注意：使用 flamegraph 的完整路径，因为 sudo 不会带上你用户的 PATH
# 重要：在要分析的命令前加 --
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet

# 或在二进制之后指定接口及其他参数
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet -i eth0

# 或者保留 PATH 以使用更简洁的命令：
sudo env "PATH=$PATH" flamegraph -- ./target/release/rustnet

# 4. 在浏览器中打开生成的 flamegraph.svg
firefox flamegraph.svg
```

### 备选方案：直接使用 perf<a id="alternative-using-perf-directly"></a>

如果你更习惯直接使用 `perf`：

```bash
# 构建带调试符号的版本
cargo build --release

# 记录性能数据（运行 30-60 秒，然后按 Ctrl+C 停止）
sudo perf record -F 99 -g ./target/release/rustnet -i eth0

# 生成火焰图（需要 FlameGraph 脚本）
# 从以下地址安装：https://github.com/brendangregg/FlameGraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg

# 或在 perf 的 TUI 中查看
sudo perf report
```

### 分析正在运行的实例<a id="profiling-a-running-instance"></a>

如果 RustNet 已经在运行：

```bash
# 查找 PID
ps aux | grep rustnet

# 对运行中的进程分析 60 秒
sudo -E ~/.cargo/bin/flamegraph -p <PID> --output rustnet-live.svg

# 或直接使用 perf
sudo perf record -F 99 -g -p <PID> sleep 60
sudo perf report
```

## 解读火焰图<a id="interpreting-flamegraphs"></a>

重点关注：
- **底部的宽条**：消耗大量总 CPU 时间的函数
- **高耸的栈**：很深的调用链（潜在的优化目标）
- **热点**：采样次数很多的函数（在某些查看器中显示为鲜亮的颜色）

常见热点：
- `packet_parser::parse_packet`：正常——这是核心的数据包处理
- `DashMap::iter` 或 `iter_mut`：如果占比很大，考虑降低迭代频率
- `clone`：如果过多，减少不必要的克隆
- 系统调用（`read`、`write`、`ioctl`）：文件系统或网络 I/O 开销

## Criterion 基准测试<a id="criterion-benchmarks"></a>

核心操作的微基准测试位于 `benches/`。运行方式：

| 基准测试 | 命令 |
|-----------|---------|
| 数据包解析 | `cargo bench --bench packet_parsing` |
| 连接合并 | `cargo bench --bench connection_merge` |
| 快照创建 | `cargo bench --bench snapshot` |
| 全部基准测试 | `cargo bench` |
| 结构体大小 | `cargo test --lib struct_sizes -- --nocapture` |

Criterion 会在 `target/criterion/` 中生成 HTML 报告，并对多次运行结果进行统计比较。

## 临时基准测试<a id="ad-hoc-benchmarking"></a>

要获得稳定一致的基准测试：

```bash
# 在稳定的流量下运行
sudo ./target/release/rustnet --interface eth0 &
PID=$!

# 监控 CPU 占用
top -p $PID

# 或使用 perf stat 获取详细指标
sudo perf stat -p $PID sleep 60

# 停止应用
sudo kill $PID
```

## 性能回归测试<a id="performance-regression-testing"></a>

在改动之后，对比改动前后：

```bash
# 基线（改动前）
sudo perf stat -r 3 timeout 60s ./target/release/rustnet-before > /dev/null

# 改动后
sudo perf stat -r 3 timeout 60s ./target/release/rustnet > /dev/null
```

需要对比的关键指标：
- CPU 周期数
- 每周期指令数（IPC）
- 缓存未命中
- 上下文切换

## 火焰图问题排查<a id="troubleshooting-flamegraphs"></a>

### 火焰图为空或只有单个条目<a id="empty-or-single-entry-flamegraph"></a>

如果你的火焰图只显示 “rustnet (100%)” 而没有任何细节：

**问题**：release 构建缺少调试符号。

**解决方案**：
```bash
# 带调试符号重新构建
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release

# 或在 Cargo.toml 中加入：
[profile.release]
debug = true

# 然后重新分析
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

### 火焰图只显示内核函数<a id="flamegraph-shows-only-kernel-functions"></a>

**问题**：运行权限不足，或 perf 无法访问用户态符号。

**解决方案**：
```bash
# 检查 perf_event_paranoid 设置
cat /proc/sys/kernel/perf_event_paranoid

# 如果它大于 1，临时调低（需要 root）：
sudo sysctl kernel.perf_event_paranoid=1

# 或以 root 运行
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

### 火焰图过短（采样少于 1000 个）<a id="very-short-flamegraph--1000-samples"></a>

**问题**：分析会话太短，采集的数据不足。

**解决方案**：
```bash
# 在停止前，让 rustnet 至少运行 30-60 秒
# 网络流量越多，分析结果越好

# 如需更长时间的分析：
timeout 60 sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

## 排查 TUI 卡顿<a id="debugging-slow-tui"></a>

如果 TUI 感觉迟钝：

1. **检查刷新频率**：默认是 1000ms，可通过 `--refresh-interval` 调整
2. **检查连接数量**：连接数过高会增加排序开销
3. **分析 UI 循环**：在 `run_ui_loop`、`draw` 或 `sort_connections` 中查找热点
4. **监控线程争用**：检查数据包处理线程是否阻塞了快照提供者
