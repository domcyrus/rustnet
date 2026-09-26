<p align="center">
  <img src="https://raw.githubusercontent.com/domcyrus/rustnet/main/assets/rustnet.svg" alt="RustNet logo" width="96" height="96">
</p>

<h1 align="center">RustNet</h1>

<p align="center">
  <a href="https://ratatui.rs/"><img src="https://ratatui.rs/built-with-ratatui/badge.svg" alt="Built with Ratatui"></a>
  <a href="https://github.com/domcyrus/rustnet/actions"><img src="https://github.com/domcyrus/rustnet/workflows/Rust/badge.svg" alt="Build status"></a>
  <a href="https://crates.io/crates/rustnet-monitor"><img src="https://img.shields.io/crates/v/rustnet-monitor.svg" alt="Crates.io version"></a>
  <a href="https://github.com/domcyrus/rustnet/releases"><img src="https://img.shields.io/github/v/release/domcyrus/rustnet.svg" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache 2.0 license"></a>
</p>

<p align="center"><strong>English</strong> | <a href="README.zh-CN.md">简体中文</a> | <a href="README.ja.md">日本語</a></p>

RustNet is a terminal network monitor that shows live TCP, UDP, and QUIC connections with process attribution when available. It runs on Linux, macOS, Windows, and FreeBSD.

## Install

On macOS or Linux with Homebrew:

```bash
brew install rustnet
```

Packet capture needs platform-specific permissions. See the [installation guide](INSTALL.md) for Linux capabilities, macOS PKTAP and BPF access, other package managers, and troubleshooting.

> **Release status:** The highlights, GIF, and screenshots below reflect v1.6.0. The guides linked from `main` may also describe [unreleased changes](CHANGELOG.md#unreleased). For the installed release, use the [v1.6.0 documentation](https://github.com/domcyrus/rustnet/blob/v1.6.0/README.md) and check `rustnet --version` and `rustnet --help`.

## Demo

<p align="center">
  <img src="./assets/rustnet.gif" alt="RustNet demo" width="800">
</p>

## Highlights

- Shows connection state, traffic, application protocol, and available process information in a terminal UI that works over SSH.
- Identifies protocols such as HTTP, TLS/SNI, DNS, SSH, and QUIC through packet inspection.
- Filters connections by process, address, port, protocol, and more.
- Exports captures as PCAP or PCAPNG with best-effort annotations for analysis in Wireshark.
- Reduces privileges after startup and uses platform sandboxing where supported.

See the [usage guide](USAGE.md), [architecture guide](ARCHITECTURE.md), and [security guide](SECURITY.md) for feature details.

## Screenshots

<table>
  <tr>
    <td align="center"><strong>Overview</strong><br>Live connections and traffic<br><img src="./assets/screenshots/overview.png" width="400" alt="RustNet Overview"></td>
    <td align="center"><strong>Details</strong><br>Process, protocol, and peer information<br><img src="./assets/screenshots/details.png" width="400" alt="RustNet Details"></td>
  </tr>
  <tr>
    <td align="center"><strong>Graph</strong><br>Traffic and application charts<br><img src="./assets/screenshots/graph.png" width="400" alt="RustNet Graph"></td>
    <td align="center"><strong>Activity</strong><br>Traffic by process<br><img src="./assets/screenshots/interfaces.png" width="400" alt="RustNet Activity"></td>
  </tr>
</table>

## Other installation methods

| Platform | Command |
| --- | --- |
| Ubuntu 22.04+ / Linux Mint 21+ | `sudo add-apt-repository ppa:domcyrus/rustnet`<br>`sudo apt update && sudo apt install rustnet` |
| Fedora 42+ | `sudo dnf copr enable domcyrus/rustnet`<br>`sudo dnf install rustnet` |
| Arch Linux | `sudo pacman -S rustnet` |
| Windows | `choco install rustnet` or `scoop install rustnet` |
| Cargo | `cargo install rustnet-monitor` |
| Nix / NixOS | `nix-shell -p rustnet` |

Windows also requires [Npcap](https://npcap.com). For v1.6.0, enable its "WinPcap API compatible mode". For openSUSE, Pop!_OS, FreeBSD, Docker, and source builds, see the [installation guide](INSTALL.md).

## Run

On Linux, after configuring capabilities:

```bash
rustnet
```

On macOS, PKTAP requires `sudo`. With BPF access configured, RustNet can run without it but uses `lsof` for process detection.

Press `/` to filter connections, `Enter` to inspect one, and `q` to quit. See the [usage guide](USAGE.md) for interface selection, options, controls, filters, and exports.

## Documentation

- [Installation](INSTALL.md): platforms, permissions, and troubleshooting
- [Usage](USAGE.md): controls, filtering, automation, and capture exports
- [Security](SECURITY.md): sandboxing and privilege management
- [Architecture](ARCHITECTURE.md): platform backends and performance
- [Changelog](CHANGELOG.md): releases and upcoming changes
- [Contributing](CONTRIBUTING.md): how to contribute

RustNet uses [ratatui](https://github.com/ratatui-org/ratatui) for its terminal UI and [libpcap](https://www.tcpdump.org/)/[Npcap](https://npcap.com/) for packet capture. See [CONTRIBUTORS.md](CONTRIBUTORS.md) for project contributors.

Licensed under [Apache License 2.0](LICENSE).
