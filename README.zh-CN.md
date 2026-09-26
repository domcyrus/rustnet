<p align="center">
  <img src="https://raw.githubusercontent.com/domcyrus/rustnet/main/assets/rustnet.svg" alt="RustNet 标志" width="96" height="96">
</p>

<h1 align="center">RustNet</h1>

<p align="center">
  <a href="https://ratatui.rs/"><img src="https://ratatui.rs/built-with-ratatui/badge.svg" alt="基于 Ratatui 构建"></a>
  <a href="https://github.com/domcyrus/rustnet/actions"><img src="https://github.com/domcyrus/rustnet/workflows/Rust/badge.svg" alt="构建状态"></a>
  <a href="https://crates.io/crates/rustnet-monitor"><img src="https://img.shields.io/crates/v/rustnet-monitor.svg" alt="Crates.io 版本"></a>
  <a href="https://github.com/domcyrus/rustnet/releases"><img src="https://img.shields.io/github/v/release/domcyrus/rustnet.svg" alt="最新版本"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache 2.0 许可证"></a>
</p>

<p align="center"><a href="README.md">English</a> | <strong>简体中文</strong> | <a href="README.ja.md">日本語</a></p>

RustNet 是一款终端网络监控工具，可实时显示 TCP、UDP 和 QUIC 连接及其所属进程。支持 Linux、macOS、Windows 和 FreeBSD。

## 安装

在 macOS 或 Linux 上使用 Homebrew：

```bash
brew install rustnet
```

抓包需要按平台配置权限。Linux capabilities、macOS 的 PKTAP 和 BPF 访问权限、其他包管理器及故障排查见[安装指南](INSTALL.zh-CN.md)。

> **发布状态：** 下文的功能亮点、GIF 和截图对应 v1.6.0。`main` 分支链接的指南还可能介绍[尚未发布的变更](CHANGELOG.md#unreleased)。使用已发布版本时，请参阅 [v1.6.0 文档](https://github.com/domcyrus/rustnet/blob/v1.6.0/README.zh-CN.md)，并运行 `rustnet --version` 和 `rustnet --help` 确认版本及选项。

## 演示

<p align="center">
  <img src="./assets/rustnet.gif" alt="RustNet 演示" width="800">
</p>

## 功能亮点

- 在可通过 SSH 使用的终端界面中，显示每条连接的所属进程、状态、流量和应用层协议。
- 通过数据包检测识别 HTTP、TLS/SNI、DNS、SSH、QUIC 等协议。
- 按进程、地址、端口、协议等条件过滤连接。
- 导出 PCAP 或带注释的 PCAPNG，供 Wireshark 分析。
- 启动后降低权限，并在支持的平台上启用沙箱。

功能详情见[使用指南](USAGE.zh-CN.md)、[架构指南](ARCHITECTURE.zh-CN.md)和[安全指南](SECURITY.zh-CN.md)。

## 截图

<table>
  <tr>
    <td align="center"><strong>概览</strong><br>实时连接与流量<br><img src="./assets/screenshots/overview.png" width="400" alt="RustNet 概览"></td>
    <td align="center"><strong>详情</strong><br>进程、协议与远端信息<br><img src="./assets/screenshots/details.png" width="400" alt="RustNet 详情"></td>
  </tr>
  <tr>
    <td align="center"><strong>图表</strong><br>流量与应用图表<br><img src="./assets/screenshots/graph.png" width="400" alt="RustNet 图表"></td>
    <td align="center"><strong>活动</strong><br>按进程查看流量<br><img src="./assets/screenshots/interfaces.png" width="400" alt="RustNet 活动"></td>
  </tr>
</table>

## 其他安装方式

| 平台 | 命令 |
| --- | --- |
| Ubuntu 22.04+ / Linux Mint 21+ | `sudo add-apt-repository ppa:domcyrus/rustnet`<br>`sudo apt update && sudo apt install rustnet` |
| Fedora 42+ | `sudo dnf copr enable domcyrus/rustnet`<br>`sudo dnf install rustnet` |
| Arch Linux | `sudo pacman -S rustnet` |
| Windows | `choco install rustnet` 或 `scoop install rustnet` |
| Cargo | `cargo install rustnet-monitor` |
| Nix / NixOS | `nix-shell -p rustnet` |

Windows 还需要安装 [Npcap](https://npcap.com)。使用 v1.6.0 时，请启用“WinPcap API compatible mode”。openSUSE、Pop!_OS、FreeBSD、Docker 和源码构建的说明见[安装指南](INSTALL.zh-CN.md)。

## 运行

在 Linux 上配置好 capabilities 后：

```bash
rustnet
```

在 macOS 上，使用 PKTAP 需要 `sudo`。配置 BPF 访问权限后也可不使用 sudo 运行，但 RustNet 会通过 `lsof` 检测进程。

按 `/` 过滤连接，按 `Enter` 查看详情，按 `q` 退出。接口选择、其他选项、键盘操作、过滤和导出方法见[使用指南](USAGE.zh-CN.md)。

## 文档

- [安装](INSTALL.zh-CN.md)：平台支持、权限配置与故障排查
- [使用](USAGE.zh-CN.md)：操作、过滤、自动化与抓包导出
- [安全](SECURITY.zh-CN.md)：沙箱与权限管理
- [架构](ARCHITECTURE.zh-CN.md)：各平台后端与性能
- [Kubernetes 抓包](KUBERNETES.zh-CN.md)：归属识别限制及证据导出后续工作
- [更新日志](CHANGELOG.md)：已发布和即将发布的变更
- [参与贡献](CONTRIBUTING.zh-CN.md)：贡献指南

RustNet 使用 [ratatui](https://github.com/ratatui-org/ratatui) 构建终端界面，使用 [libpcap](https://www.tcpdump.org/) 抓包。项目贡献者见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

本项目采用 [Apache License 2.0](LICENSE) 许可证。
