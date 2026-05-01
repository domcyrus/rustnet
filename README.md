<p align="center">
  <h1 align="center">RustNet</h1>
  <p align="center">
    <strong>Per-process network monitoring for your terminal: live TCP, UDP, and QUIC connections with deep packet inspection, sandboxed by default.</strong>
  </p>
  <p align="center">
    <a href="https://ratatui.rs/"><img src="https://ratatui.rs/built-with-ratatui/badge.svg" alt="Built With Ratatui"></a>
    <a href="https://github.com/domcyrus/rustnet/actions"><img src="https://github.com/domcyrus/rustnet/workflows/Rust/badge.svg" alt="Build Status"></a>
    <a href="https://crates.io/crates/rustnet-monitor"><img src="https://img.shields.io/crates/v/rustnet-monitor.svg" alt="Crates.io"></a>
    <a href="https://github.com/domcyrus/rustnet/stargazers"><img src="https://img.shields.io/github/stars/domcyrus/rustnet?style=flat&logo=github" alt="GitHub Stars"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
    <a href="https://github.com/domcyrus/rustnet/releases"><img src="https://img.shields.io/github/v/release/domcyrus/rustnet.svg" alt="GitHub release"></a>
    <a href="https://github.com/domcyrus/rustnet/pkgs/container/rustnet"><img src="https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker" alt="Docker Image"></a>
  </p>
</p>

<p align="center">
  <img src="./assets/rustnet.gif" alt="RustNet demo" width="800">
</p>

<p align="center">
  <em>Real-time visibility into every connection your machine makes, who owns it, and what protocol it's speaking. No tcpdump, X11 forwarding, or root piping.</em>
</p>

## Features

- **Per-process attribution**: Every TCP, UDP, and QUIC connection mapped to its owning process, via eBPF on Linux, PKTAP on macOS, native APIs on Windows and FreeBSD. Wireshark and tcpdump can't do this; `netstat` / `ss` can't show live state.
- **Deep packet inspection**: Identify HTTP, HTTPS/TLS with SNI, DNS, SSH, QUIC, NTP, mDNS, LLMNR, DHCP, SNMP, SSDP, and NetBIOS, without external dissectors.
- **Security sandboxing**: Landlock (Linux 5.13+), Seatbelt (macOS), token privilege drop + job-object child-process block (Windows). Drops privileges immediately after libpcap initializes. See [SECURITY.md](SECURITY.md).
- **TCP network analytics**: Real-time retransmissions, out-of-order packets, and fast-retransmit detection, per-connection and aggregate.
- **Smart connection lifecycle**: Protocol-aware timeouts with white → yellow → red staleness indicators. Toggle `t` to keep historic (closed) connections visible for forensics.
- **Vim/fzf-style filtering**: `port:`, `src:`, `dst:`, `sni:`, `process:`, `state:`, `proto:`, plus regex via `/(?i)pattern/`.
- **GeoIP enrichment**: Country lookups via local MaxMind GeoLite2. No network calls.
- **Cross-platform**: Linux, macOS, Windows, FreeBSD.

## Why RustNet?

RustNet fills the gap between simple connection tools (`netstat`, `ss`) and packet analyzers (`Wireshark`, `tcpdump`):

- **Process attribution**: See which application owns each connection. Wireshark cannot provide this because it only sees packets, not sockets.
- **Connection-centric view**: Track states, bandwidth, and protocols per connection in real-time
- **SSH-friendly**: TUI works over SSH so you can quickly see what's happening on a remote server without forwarding X11 or capturing traffic

RustNet complements packet capture tools. Use RustNet to see *what's making connections*. For deep forensic analysis, use `--pcap-export` to capture packets with process attribution, then enrich with `scripts/pcap_enrich.py` and analyze in Wireshark with full PID/process context. See [PCAP Export](USAGE.md#pcap-export) and [Comparison with Similar Tools](ARCHITECTURE.md#comparison-with-similar-tools) for details.

Built on ratatui, libpcap, eBPF (libbpf-rs), DashMap, crossbeam, ring, MaxMind GeoLite2, and Landlock. See [ARCHITECTURE.md](ARCHITECTURE.md#dependencies) for the full dependency breakdown.

<details>
<summary><b>eBPF Enhanced Process Identification (Linux Default)</b></summary>

RustNet uses kernel eBPF programs by default on Linux for enhanced performance and lower overhead process identification. However, this comes with important limitations:

**Process Name Limitations:**
- eBPF uses the kernel's `comm` field, which is limited to 16 characters
- Shows the task/thread command name, not the full executable path
- Multi-threaded applications often show thread names instead of the main process name

**Real-world Examples:**
- **Firefox**: May appear as "Socket Thread", "Web Content", "Isolated Web Co", or "MainThread"
- **Chrome**: May appear as "ThreadPoolForeg", "Chrome_IOThread", "BrokerProcess", or "SandboxHelper"
- **Electron apps**: Often show as "electron", "node", or internal thread names
- **System processes**: Show truncated names like "systemd-resolve" → "systemd-resolve"

**Fallback Behavior:**
- When eBPF fails to load or lacks sufficient permissions, RustNet automatically falls back to standard procfs-based process identification
- Standard mode provides full process names but with higher CPU overhead
- eBPF is enabled by default; no special build flags needed

To disable eBPF and use procfs-only mode, build with:
```bash
cargo build --release --no-default-features
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for technical information.

</details>

<details>
<summary><b>Interface Statistics Monitoring</b></summary>

RustNet provides real-time network interface statistics across all supported platforms:

- **Overview Tab**: Shows active interfaces with current rates, errors, and drops
- **Interfaces Tab** (press `i`): Detailed table with comprehensive metrics for all interfaces
- **Cross-Platform**: Linux (sysfs), macOS/FreeBSD (getifaddrs), Windows (GetIfTable2 API)
- **Smart Filtering**: Windows automatically excludes virtual/filter adapters

See [USAGE.md](USAGE.md#interface-statistics) for detailed documentation on interpreting interface statistics and platform-specific behavior.

**Metrics Available:**
- Total bytes and packets (RX/TX)
- Error counters (receive and transmit)
- Packet drops (queue overflows)
- Collisions (legacy, rarely used on modern networks)

Stats are collected every 2 seconds in a background thread with minimal performance impact.

</details>

## Quick Start

### Installation

**Homebrew (macOS / Linux):**
```bash
brew tap domcyrus/rustnet
brew install rustnet
```

**Ubuntu (25.10+):**
```bash
sudo add-apt-repository ppa:domcyrus/rustnet
sudo apt update && sudo apt install rustnet
```

**Fedora (42+):**
```bash
sudo dnf copr enable domcyrus/rustnet
sudo dnf install rustnet
```

**Arch Linux:**
```bash
sudo pacman -S rustnet
```

**From crates.io:**
```bash
cargo install rustnet-monitor
```

**Windows (Chocolatey):**
```powershell
# Run in Administrator PowerShell
# Requires Npcap (https://npcap.com) installed with "WinPcap API-compatible Mode" enabled
choco install rustnet
```

**Other platforms:**
- **FreeBSD**: Download from [rustnet-bsd releases](https://github.com/domcyrus/rustnet-bsd/releases)
- **Docker, source builds, other Linux distros**: See [INSTALL.md](INSTALL.md) for detailed instructions

### Running RustNet

Packet capture requires elevated privileges:

```bash
# Quick start (all platforms)
sudo rustnet

# Linux: Grant capabilities to run without sudo (recommended)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(which rustnet)
rustnet
```

**Common options:**
```bash
rustnet -i eth0              # Specify network interface
rustnet --show-localhost     # Show localhost connections
rustnet --no-resolve-dns     # Disable reverse DNS lookups (enabled by default)
rustnet -r 500               # Set refresh interval (ms)
```

See [INSTALL.md](INSTALL.md) for detailed permission setup and [USAGE.md](USAGE.md) for complete options.

## Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit (press twice to confirm) |
| `Ctrl+C` | Quit immediately |
| `x` | Clear all connections (press twice to confirm) |
| `Tab` | Switch between tabs |
| `i` | Toggle interface statistics view |
| `↑/k` `↓/j` | Navigate up/down |
| `g` `G` | Jump to first/last connection |
| `Enter` | View connection details |
| `Esc` | Go back or clear filter |
| `c` | Copy remote address |
| `p` | Toggle service names/ports |
| `d` | Toggle hostnames/IPs |
| `s` `S` | Cycle sort columns / toggle direction |
| `a` | Toggle process grouping |
| `Space` | Expand/collapse process group |
| `←/→` or `h/l` | Collapse/expand group |
| `PageUp/PageDown` or `Ctrl+B/F` | Page navigation |
| `t` | Toggle historic (closed) connections |
| `r` | Reset view (grouping, sort, filter) |
| `/` | Enter filter mode |
| `h` | Toggle help |

See [USAGE.md](USAGE.md) for detailed keyboard controls and navigation tips.

## Filtering & Sorting

**Quick filtering examples:**
```
/google                        # Search for "google" anywhere
/port:443                      # Filter by port
/process:firefox               # Filter by process
/state:established             # Filter by connection state
/dport:443 sni:github.com      # Combine filters
```

**Sorting:**
- Press `s` to cycle through sortable columns (Protocol, Address, State, Service, Bandwidth, Process)
- Press `S` (Shift+s) to toggle sort direction
- Find bandwidth hogs: Press `s` until "Down/Up ↓" appears (sorts by combined up+down speed)

See [USAGE.md](USAGE.md) for complete filtering syntax and sorting guide.

<details>
<summary><b>Advanced Filtering Examples</b></summary>

**Keyword filters:**
- `port:44` - Ports containing "44" (443, 8080, 4433)
- `sport:80` - Source ports containing "80"
- `dport:443` - Destination ports containing "443"
- `src:192.168` - Source IPs containing "192.168"
- `dst:github.com` - Destinations containing "github.com"
- `process:ssh` - Process names containing "ssh"
- `sni:api` - SNI hostnames containing "api"
- `app:openssh` - SSH connections using OpenSSH
- `state:established` - Filter by protocol state
- `proto:tcp` - Filter by protocol type

**State filtering:**
- `state:syn_recv` - Half-open connections (SYN flood detection)
- `state:established` - Established connections only
- `state:quic_connected` - Active QUIC connections
- `state:dns_query` - DNS query connections

**Combined examples:**
- `sport:80 process:nginx` - Nginx connections from port 80
- `dport:443 sni:google.com` - HTTPS to Google
- `process:firefox state:quic_connected` - Firefox QUIC connections
- `dport:22 app:openssh state:established` - Established OpenSSH connections

</details>

<details>
<summary><b>Connection Lifecycle & Visual Indicators</b></summary>

RustNet uses smart timeouts and visual warnings before removing connections:

**Visual staleness indicators:**
- **White**: Active (< 75% of timeout)
- **Yellow**: Stale (75-90% of timeout)
- **Red**: Critical (> 90% of timeout)

**Protocol-aware timeouts:**
- **HTTP/HTTPS**: 10 minutes (supports keep-alive)
- **SSH**: 30 minutes (long sessions)
- **TCP active**: 10 minutes, idle: 5 minutes
- **QUIC connected**: 3 minutes (or peer's transport-param idle timeout, when present); `Initial`/`Handshaking`: 60 seconds
- **DNS**: 30 seconds
- **TCP CLOSED**: 5 seconds

Example: An HTTP connection turns yellow at 7.5 min, red at 9 min, and is removed at 10 min.

See [USAGE.md](USAGE.md) for complete timeout details.

</details>

## Documentation

- **[INSTALL.md](INSTALL.md)** - Detailed installation instructions for all platforms, permission setup, and troubleshooting
- **[USAGE.md](USAGE.md)** - Complete usage guide including command-line options, filtering, sorting, and logging
- **[SECURITY.md](SECURITY.md)** - Security features including Landlock sandboxing and privilege management
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical architecture, platform implementations, and performance details
- **[PROFILING.md](PROFILING.md)** - Performance profiling guide with flamegraph setup and optimization tips
- **[ROADMAP.md](ROADMAP.md)** - Planned features and future improvements
- **[RELEASE.md](RELEASE.md)** - Release process for maintainers

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to contribute.

See [CONTRIBUTORS.md](CONTRIBUTORS.md) for a list of people who have contributed to this project.

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI
- Packet capture powered by [libpcap](https://www.tcpdump.org/)
- Inspired by tools like `tshark/wireshark/tcpdump`, `sniffnet`, `netstat`, `ss`, `iftop`, and [bandwhich](https://github.com/imsnif/bandwhich)
- Some code is vibe coded (OMG) / may the LLM gods be with you

---

## Documentation Moved

Some sections have been moved to dedicated files for better organization:

- **Permissions Setup**: Now in [INSTALL.md - Permissions Setup](INSTALL.md#permissions-setup)
- **Installation Instructions**: Now in [INSTALL.md](INSTALL.md)
- **Detailed Usage**: Now in [USAGE.md](USAGE.md)
- **Architecture Details**: Now in [ARCHITECTURE.md](ARCHITECTURE.md)
