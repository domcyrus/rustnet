[![Built With Ratatui](https://ratatui.rs/built-with-ratatui/badge.svg)](https://ratatui.rs/)
[![Build Status](https://github.com/domcyrus/rustnet/workflows/Rust/badge.svg)](https://github.com/domcyrus/rustnet/actions)
[![Crates.io](https://img.shields.io/crates/v/rustnet-monitor.svg)](https://crates.io/crates/rustnet-monitor)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/domcyrus/rustnet.svg)](https://github.com/domcyrus/rustnet/releases)
[![Docker Image](https://img.shields.io/badge/docker-ghcr.io-blue?logo=docker)](https://github.com/domcyrus/rustnet/pkgs/container/rustnet)

# RustNet

A cross-platform network monitoring tool built with Rust. RustNet provides real-time visibility into network connections with detailed state information, connection lifecycle management, deep packet inspection, and a terminal user interface.

![RustNet Demo](./assets/rustnet.gif)

## Features

- **Real-time Network Monitoring**: Monitor active TCP, UDP, ICMP, and ARP connections with detailed state information
- **Connection States**: State display showing connection status:
  - **TCP States**: `ESTABLISHED`, `SYN_SENT`, `TIME_WAIT`, `CLOSED`, etc.
  - **QUIC States**: `QUIC_INITIAL`, `QUIC_HANDSHAKE`, `QUIC_CONNECTED`, `QUIC_DRAINING`
  - **DNS States**: `DNS_QUERY`, `DNS_RESPONSE`
  - **SSH States**: `BANNER`, `KEYEXCHANGE`, `AUTHENTICATION`, `ESTABLISHED` (for SSH protocol)
  - **Activity States**: `UDP_ACTIVE`, `UDP_IDLE`, `UDP_STALE` based on connection activity
- **Deep Packet Inspection (DPI)**: Detect application protocols:
  - HTTP with host information
  - HTTPS/TLS with SNI (Server Name Indication)
  - DNS queries and responses
  - **SSH connections** with version detection, software identification, and connection state tracking
  - **QUIC protocol with CONNECTION_CLOSE frame detection** and RFC 9000 compliance
- **Connection Lifecycle Management**:
  - **Smart protocol-aware timeouts** based on protocol, state, and activity level
  - **TCP connections**: 5-10 minutes for established (activity-based), with DPI-aware extensions
  - **HTTP/HTTPS keep-alive**: 10 minutes (both TCP and UDP/HTTP3)
  - **SSH sessions**: 30 minutes (both TCP and UDP)
  - **QUIC connections**: 5-10 minutes (activity-based)
  - **Fast cleanup**: DNS (30s), TCP closed (5s), QUIC draining (10s)
  - **Visual staleness indicators**: Connections turn yellow (75% timeout) then red (90% timeout) before cleanup
- **Process Identification**: Associate network connections with running processes
  - **Note**: With experimental eBPF support, process names are limited to 16 characters from the kernel's `comm` field and may show thread names instead of full executable names
- **Service Name Resolution**: Identify well-known services using port numbers
- **Cross-platform Support**: Works on Linux, macOS, Windows and potentially BSD systems
- **Advanced Filtering**: Real-time vim/fzf-style filtering with keyword support:
  - Navigate while typing filters
  - Fuzzy search across all connection fields including DPI data
  - Keyword filters: `port:44`, `src:192.168`, `dst:google.com`, `sni:github.com`, `process:firefox`
- **Terminal User Interface**: TUI built with ratatui with adjustable column widths for state visibility
- **Multi-threaded Processing**: Concurrent packet processing across multiple threads
- **Optional Logging**: Detailed logging with configurable log levels (disabled by default)

### eBPF Enhanced Process Identification (Experimental)

On Linux, RustNet uses kernel eBPF programs by default for enhanced performance and lower overhead process identification. However, this comes with important limitations:

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

## Installation

### Installing from Release Packages

Pre-built packages are available for each release on the [GitHub Releases](https://github.com/domcyrus/rustnet/releases) page.

#### macOS DMG Installation

> **Prefer Homebrew** If you have Homebrew installed, using `brew install` is easier and avoids Gatekeeper bypass steps. See [Homebrew Installation](#option-3-homebrew-installation) for instructions.

1. **Download** the appropriate DMG for your architecture:
   - `Rustnet_macOS_AppleSilicon.dmg` for Apple Silicon Macs (M1/M2/M3)
   - `Rustnet_macOS_Intel.dmg` for Intel-based Macs

2. **Open the DMG** and drag Rustnet.app to your Applications folder

3. **Bypass Gatekeeper** (for unsigned builds):
   - When you first try to open Rustnet, macOS will block it because the app is not signed
   - Go to **System Settings → Privacy & Security**
   - Scroll down to find the message about Rustnet being blocked
   - Click **"Open Anyway"** to allow the application to run
   - You may need to confirm this choice when launching the app again

4. **Run Rustnet**:
   - Double-click Rustnet.app to launch it in a Terminal window with sudo
   - Or run from command line: `sudo /Applications/Rustnet.app/Contents/MacOS/rustnet`

5. **Optional: Create a symlink for shell access**:
   ```bash
   # Create a symlink so you can run 'rustnet' from anywhere
   sudo ln -s /Applications/Rustnet.app/Contents/MacOS/rustnet /usr/local/bin/rustnet

   # Now you can run from any terminal:
   sudo rustnet
   ```

6. **Optional: Setup BPF permissions** (to avoid needing sudo):
   - Install Wireshark's BPF permission helper: `brew install --cask wireshark-chmodbpf`
   - Log out and back in for group changes to take effect
   - See the [Permissions](#permissions) section for detailed setup instructions

#### Windows MSI Installation

1. **Install Npcap Runtime** (required for packet capture):
   - Download from https://npcap.com/dist/
   - Run the installer and select **"WinPcap API compatible mode"**

2. **Download and install** the appropriate MSI package:
   - `Rustnet_Windows_64-bit.msi` for 64-bit Windows
   - `Rustnet_Windows_32-bit.msi` for 32-bit Windows

3. **Run the installer** and follow the installation wizard

4. **Run Rustnet**:
   - Open Command Prompt or PowerShell
   - Run: `rustnet.exe`
   - If Npcap is not installed or not in WinPcap compatible mode, RustNet will display a helpful error message with installation instructions
   - Note: Depending on your Npcap installation settings, you may or may not need Administrator privileges

#### Linux Package Installation

**Debian/Ubuntu (.deb packages):**

```bash
# Download the appropriate package for your architecture:
# - Rustnet_LinuxDEB_amd64.deb (x86_64)
# - Rustnet_LinuxDEB_arm64.deb (ARM64)
# - Rustnet_LinuxDEB_armhf.deb (ARMv7)

# Install the package
sudo dpkg -i Rustnet_LinuxDEB_amd64.deb

# Install dependencies if needed
sudo apt-get install -f

# Run with sudo
sudo rustnet

# Optional: Grant capabilities to run without sudo
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/rustnet
rustnet
```

**RedHat/Fedora/CentOS (.rpm packages):**

```bash
# Download the appropriate package for your architecture:
# - Rustnet_LinuxRPM_x86_64.rpm
# - Rustnet_LinuxRPM_aarch64.rpm

# Install the package
sudo rpm -i Rustnet_LinuxRPM_x86_64.rpm
# Or with dnf/yum:
sudo dnf install Rustnet_LinuxRPM_x86_64.rpm

# Run with sudo
sudo rustnet

# Optional: Grant capabilities to run without sudo
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/rustnet
rustnet
```

### Prerequisites

- Rust 2024 edition or later (install from [rustup.rs](https://rustup.rs/))
- libpcap or similar packet capture library:
  - **Linux**: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RedHat/CentOS)
  - **macOS**: Included by default
  - **Windows**: Install Npcap and Npcap SDK (see [Windows Build Setup](#windows-build-setup) below)
- **For eBPF support (enabled by default on Linux, experimental)**:
  - `sudo apt-get install libelf-dev clang llvm` (Debian/Ubuntu)
  - `sudo yum install elfutils-libelf-devel clang llvm` (RedHat/CentOS)
  - Linux kernel 4.19+ with BTF support recommended

### Windows Build Setup

Building RustNet on Windows requires the Npcap SDK and proper environment configuration:

#### Build Requirements

1. **Download and Install Npcap SDK**:
   - Download the Npcap SDK from https://npcap.com/dist/
   - Extract the SDK to a directory (e.g., `C:\npcap-sdk`)

2. **Set Environment Variables**:
   - Set the `LIB` environment variable to include the SDK's library path:
     ```cmd
     set LIB=%LIB%;C:\npcap-sdk\Lib\x64
     ```
   - For PowerShell:
     ```powershell
     $env:LIB = "$env:LIB;C:\npcap-sdk\Lib\x64"
     ```
   - For permanent setup, add this to your system environment variables

3. **Build RustNet**:
   ```cmd
   cargo build --release
   ```

#### Runtime Requirements

1. **Install Npcap Runtime**:
   - Download the Npcap installer from https://npcap.com/dist/
   - Run the installer and **select "WinPcap API compatible mode"** during installation
   - This ensures compatibility with the packet capture library

2. **Run RustNet**:
   ```cmd
   rustnet.exe
   ```

**Note**: Depending on your Npcap installation settings, you may or may not need Administrator privileges. If you didn't select the option to restrict packet capture to administrators during Npcap installation, RustNet can run with normal user privileges.

### Install via Cargo (Recommended)

```bash
# Install directly from crates.io
cargo install rustnet-monitor

# The binary will be installed to ~/.cargo/bin/rustnet
# Make sure ~/.cargo/bin is in your PATH
```

### Building from source

```bash
# Clone the repository
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Build in release mode (eBPF enabled by default on Linux)
cargo build --release

# Build without eBPF on Linux (if needed)
cargo build --release --no-default-features --features [other features if needed]

# The executable will be in target/release/rustnet
```

### Using Docker

RustNet is available as a Docker container from GitHub Container Registry:

```bash
# Pull the latest image
docker pull ghcr.io/domcyrus/rustnet:latest

# Or pull a specific version
docker pull ghcr.io/domcyrus/rustnet:0.7.0

# Run with required network capabilities (latest)
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --net=host \
  ghcr.io/domcyrus/rustnet:latest

# Run with specific version
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --net=host \
  ghcr.io/domcyrus/rustnet:0.7.0

# Run with specific interface
docker run --rm -it --cap-add=NET_RAW --cap-add=NET_ADMIN --net=host \
  ghcr.io/domcyrus/rustnet:latest -i eth0

# Run with process identification support (requires host /proc access)
# Note: Process identification in containers requires access to the host's /proc filesystem
# This allows RustNet to map network connections to host processes
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_PTRACE \
  --net=host \
  --pid=host \
  -v /proc:/host/proc:ro \
  ghcr.io/domcyrus/rustnet:latest

# Run with full eBPF support (requires additional kernel capabilities)
# Note: eBPF is enabled by default but requires kernel access to load BPF programs
# For modern kernels (5.8+):
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=BPF --cap-add=PERFMON --cap-add=SYS_PTRACE \
  --net=host \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  ghcr.io/domcyrus/rustnet:latest

# For older kernels (fallback to SYS_ADMIN):
docker run --rm -it \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=SYS_ADMIN --cap-add=SYS_PTRACE \
  --net=host \
  --pid=host \
  -v /proc:/host/proc:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  ghcr.io/domcyrus/rustnet:latest

# Alternative: Run with privileged mode (less secure but simpler)
docker run --rm -it --privileged --net=host \
  ghcr.io/domcyrus/rustnet:latest

# View available options
docker run --rm ghcr.io/domcyrus/rustnet:latest --help

# Or with specific version
docker run --rm ghcr.io/domcyrus/rustnet:0.7.0 --help
```

**Notes:**
- The container requires network capabilities (`NET_RAW` and `NET_ADMIN`) or privileged mode for packet capture
- Host networking (`--net=host`) is recommended for monitoring all network interfaces
- **Process identification in containers**: By default, Docker containers cannot see host processes. To enable process identification:
  - Use `--pid=host` to share the host's PID namespace
  - Mount host's `/proc` filesystem with `-v /proc:/host/proc:ro`
  - Add `--cap-add=SYS_PTRACE` capability for process inspection
  - Without these, RustNet will show network connections but cannot identify which host processes own them
- **eBPF support in containers**: eBPF is enabled by default on Linux but requires additional capabilities to load kernel programs:
  - **Modern kernels (5.8+)**: Add `--cap-add=BPF` and `--cap-add=PERFMON` capabilities
  - **Older kernels**: Use `--cap-add=SYS_ADMIN` as fallback (broader permissions)
  - Mount `/sys/kernel/debug` for BPF debugging information (optional but recommended)
  - Without eBPF capabilities, RustNet automatically falls back to procfs-only mode
  - To disable eBPF and use procfs-only mode explicitly, rebuild the container with `--no-default-features`

### Running RustNet

On Unix-like systems (Linux/macOS), packet capture typically requires elevated privileges:

#### When built from source:

```bash
# Run with sudo
sudo ./target/release/rustnet

# Or set capabilities on Linux (to avoid needing sudo)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rustnet
./target/release/rustnet
```

#### When installed via cargo:

```bash
# Option 1: Use full path with sudo
sudo $(which rustnet)

# Option 2: Set capabilities on the cargo-installed binary (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip ~/.cargo/bin/rustnet
rustnet  # Can now run without sudo

# Option 3: Create system-wide symlink
sudo ln -s ~/.cargo/bin/rustnet /usr/local/bin/rustnet
sudo rustnet  # Works from anywhere

# Option 4: Install globally with cargo (requires sudo)
sudo cargo install --root /usr/local rustnet-monitor
sudo rustnet  # Binary installed to /usr/local/bin/rustnet
```

## Usage

```bash
# Run with default settings (monitors default interface)
rustnet

# Specify network interface
rustnet -i eth0
rustnet --interface wlan0

# Filter out localhost connections (already filtered by default)
rustnet --no-localhost

# Show localhost connections (override default filtering)
rustnet --show-localhost

# Set UI refresh interval (in milliseconds)
rustnet -r 500
rustnet --refresh-interval 2000

# Disable deep packet inspection
rustnet --no-dpi

# Enable logging with specific level (options: error, warn, info, debug, trace)
rustnet -l debug
rustnet --log-level info

# View help and all options
rustnet --help
```

### Command-line Options

Usage: rustnet [OPTIONS]

Options:
  -i, --interface <INTERFACE>            Network interface to monitor
      --no-localhost                     Filter out localhost connections (default: filtered)
      --show-localhost                   Show localhost connections (overrides default filtering)
  -r, --refresh-interval <MILLISECONDS>  UI refresh interval in milliseconds [default: 1000]
      --no-dpi                           Disable deep packet inspection
  -l, --log-level <LEVEL>                Set the log level (if not provided, no logging will be enabled)
  -h, --help                             Print help
  -V, --version                          Print version

### Keyboard Controls

- `q`: Quit the application (press twice to confirm)
- `Ctrl+C`: Quit immediately
- `Tab`: Switch between tabs (Overview, Details, Help)
- `↑/k`: Navigate up in connection list
- `↓/j`: Navigate down in connection list
- `g`: Jump to first connection (vim-style)
- `G` (Shift+g): Jump to last connection (vim-style)
- `PageUp`: Move up by 10 items
- `PageDown`: Move down by 10 items
- `Enter`: View detailed information about selected connection
- `Esc`: Go back to previous view or clear active filter
- `c`: Copy remote address to clipboard
- `p`: Toggle between service names and port numbers
- `s`: Cycle through sort columns (left-to-right order)
- `S` (Shift+s): Toggle sort direction (ascending/descending)
- `h`: Toggle help screen
- `/`: Enter filter mode (vim-style search with real-time results)

## Connection Lifecycle & Visual Indicators

RustNet uses intelligent timeout management to automatically clean up inactive connections while providing visual warnings before removal.

### Visual Staleness Indicators

Connections change color based on how close they are to being cleaned up:

| Color | Meaning | Staleness |
|-------|---------|-----------|
| **White** (default) | Active connection | < 75% of timeout |
| **Yellow** | Stale - approaching timeout | 75-90% of timeout |
| **Red** | Critical - will be removed soon | > 90% of timeout |

**Example**: An HTTP connection with a 10-minute timeout will:
- Stay **white** for the first 7.5 minutes
- Turn **yellow** from 7.5 to 9 minutes (warning)
- Turn **red** after 9 minutes (critical)
- Be removed at 10 minutes

This gives you advance warning when a connection is about to disappear from the list.

### Smart Protocol-Aware Timeouts

RustNet adjusts connection timeouts based on the protocol and detected application:

#### TCP Connections
- **HTTP/HTTPS** (detected via DPI): **10 minutes** - supports HTTP keep-alive
- **SSH** (detected via DPI): **30 minutes** - accommodates long interactive sessions
- **Active established** (< 1 min idle): **10 minutes**
- **Idle established** (> 1 min idle): **5 minutes**
- **TIME_WAIT**: 30 seconds - standard TCP timeout
- **CLOSED**: 5 seconds - rapid cleanup
- **SYN_SENT, FIN_WAIT, etc.**: 30-60 seconds

#### UDP Connections
- **HTTP/3 (QUIC with HTTP)**: **10 minutes** - connection reuse
- **HTTPS/3 (QUIC with HTTPS)**: **10 minutes** - connection reuse
- **SSH over UDP**: **30 minutes** - long-lived sessions
- **DNS**: **30 seconds** - short-lived queries
- **Regular UDP**: **60 seconds** - standard timeout

#### QUIC Connections (Detected State)
- **Connected (active)** (< 1 min idle): **10 minutes**
- **Connected (idle)** (> 1 min idle): **5 minutes**
- **With CONNECTION_CLOSE frame**: 1-10 seconds (based on close type)
- **Initial/Handshaking**: 60 seconds - allow connection establishment
- **Draining**: 10 seconds - RFC 9000 draining period

### Activity-Based Adjustment

Connections showing recent packet activity get longer timeouts:
- **Last packet < 60 seconds ago**: Uses "active" timeout (longer)
- **Last packet > 60 seconds ago**: Uses "idle" timeout (shorter)

This ensures active connections stay visible while idle connections are cleaned up more quickly.

### Why Connections Disappear

A connection is removed when:
1. **No packets received** for the duration of its timeout period
2. The connection enters a **closed state** (TCP CLOSED, QUIC CLOSED)
3. **Explicit close frames** detected (QUIC CONNECTION_CLOSE)

**Note**: Rate indicators (bandwidth display) show *decaying* traffic based on recent activity. A connection may show declining bandwidth (yellow bars) but remain in the list until it exceeds its idle timeout. This is intentional - the visual decay gives you time to see the connection winding down before it's removed.

## Sorting

RustNet provides powerful table sorting to help you analyze network connections. Press `s` to cycle through sortable columns in left-to-right visual order, and press `S` (Shift+s) to toggle between ascending and descending order.

### Quick Start

**Find bandwidth hogs:**
```
Press 's' repeatedly until you see: Down↓/Up
The connections with highest download bandwidth appear at the top
```

**Find top uploaders:**
```
Press 's' repeatedly until you see: Down/Up↓
The connections with highest upload bandwidth appear at the top
```

**Sort by process name:**
```
Press 's' repeatedly until you see: Process ↑
Connections are sorted alphabetically by process name
```

### Sortable Columns

Press `s` to cycle through columns in left-to-right order:

| Column | Default Direction | Description |
|--------|-------------------|-------------|
| **Protocol** | ↑ Ascending | Sort by protocol type (TCP, UDP, ICMP, etc.) |
| **Local Address** | ↑ Ascending | Sort by local IP:port (useful for multi-interface systems) |
| **Remote Address** | ↑ Ascending | Sort by remote IP:port |
| **State** | ↑ Ascending | Sort by connection state (ESTABLISHED, etc.) |
| **Service** | ↑ Ascending | Sort by service name or port number |
| **Application** | ↑ Ascending | Sort by detected application protocol (HTTP, DNS, etc.) |
| **Bandwidth ↓** | ↓ Descending | Sort by **download** bandwidth (highest first by default) |
| **Bandwidth ↑** | ↓ Descending | Sort by **upload** bandwidth (highest first by default) |
| **Process** | ↑ Ascending | Sort by process name alphabetically |

### Sort Indicators

The active sort column is highlighted with:
- **Cyan color** and **underline** styling
- **Arrow symbol** (↑ or ↓) showing sort direction
- **Table title** showing current sort state

**Visual indicators:**
```
Active column header appears in cyan with underline:
Pro │ Local Address │ Remote Address ↑│ State │ ...
                      ^^^^^^^^^^^^^^^^
                      (cyan, underlined, with arrow)

Table title shows current sort:
┌─ Active Connections (Sort: Remote Addr ↑) ──┐
```

### Bandwidth Column Special Behavior

The bandwidth column shows **both download and upload** metrics. The arrow attaches to the specific metric being sorted:

| Display | Sorting By | Direction | Meaning |
|---------|------------|-----------|---------|
| `Down↓/Up` | Download | Descending (↓) | **Highest downloads first** (bandwidth hogs) |
| `Down↑/Up` | Download | Ascending (↑) | Lowest downloads first |
| `Down/Up↓` | Upload | Descending (↓) | **Highest uploads first** (top uploaders) |
| `Down/Up↑` | Upload | Ascending (↑) | Lowest uploads first |

**Key points:**
- The arrow (↑/↓) indicates **sort direction**, not bandwidth direction
- `↓` = Descending = Highest values at top (10MB → 5MB → 1MB)
- `↑` = Ascending = Lowest values at top (1MB → 5MB → 10MB)
- Press `s` once on bandwidth to sort by downloads, press `s` again for uploads
- Press `S` (Shift+s) to flip between high-to-low and low-to-high

### Sort Behavior

**Press `s` (lowercase) - Cycle Columns:**
- Moves to the next column in left-to-right visual order
- **Resets to default direction** for that column
- Bandwidth columns default to descending (↓) to show highest values first
- Text columns default to ascending (↑) for alphabetical order

**Press `S` (Shift+s) - Toggle Direction:**
- **Stays on current column**
- Flips between ascending (↑) and descending (↓)
- Useful for reversing sort order (e.g., finding smallest bandwidth users)

**Press `s` multiple times to return to default:**
- Cycling through all columns returns to the default chronological sort (by connection creation time)
- No sort indicator is shown when in default mode

### Sorting with Filtering

Sorting works seamlessly with filtering:
1. **Filter first**: Press `/` and enter your filter criteria
2. **Then sort**: Press `s` to sort the filtered results
3. **The sort persists**: Changing the filter keeps your sort order active

Example workflow:
```
1. Press '/' and type 'firefox' to filter Firefox connections
2. Press 's' until you see "Down↓/Up"
3. Now viewing Firefox connections sorted by download bandwidth
```

### Examples

**Find which process is downloading the most:**
```
1. Press 's' until "Down↓/Up" appears
2. Top connection shows the highest download rate
3. Look at the "Process" column to see which application
```

**Sort connections by remote destination:**
```
1. Press 's' until "Remote Address ↑" appears
2. Connections are grouped by remote IP address
3. Press 'S' to reverse order if needed
```

**Find idle connections (lowest bandwidth):**
```
1. Press 's' to cycle to "Down↓/Up"
2. Press 'S' to toggle to "Down↑/Up" (ascending)
3. Connections with lowest download bandwidth appear first
```

**Sort by application protocol:**
```
1. Press 's' until "Application / Host ↑" appears
2. All HTTPS connections group together, DNS queries together, etc.
3. Useful for finding all connections of a specific type
```

## Filtering

Press `/` to enter filter mode. Type to filter connections in real-time, navigate with arrow keys while typing.

**Basic search:**

- `/google` - Find connections containing "google"
- `/firefox` - Find Firefox connections

**Keyword filters:**

- `port:44` - Ports containing "44" (443, 8080, etc.)
- `sport:80` - Source ports containing "80"
- `dport:443` - Destination ports containing "443"
- `src:192.168` - Source IPs containing "192.168"
- `dst:github.com` - Destinations containing "github.com"
- `process:ssh` - Process names containing "ssh"
- `sni:api` - SNI hostnames containing "api"
- `ssh:openssh` - SSH connections using OpenSSH
- `state:established` - Filter connections by protocol state

**State filtering:**

Filter connections by their current protocol state (case-insensitive):

⚠️ **Note:** State tracking accuracy varies by protocol. TCP states are most reliable, while UDP, QUIC, and other protocol states are derived from packet inspection and internal lifecycle management, which may not always reflect the true connection state.

- `state:syn_recv` - Show half-open connections (useful for detecting SYN floods)
- `state:established` - Show only established connections
- `state:fin_wait` - Show connections in closing states
- `state:quic_handshake` - Show QUIC connections during handshake
- `state:dns_query` - Show DNS query connections
- `state:udp_active` - Show active UDP connections

**Available states:**
- **TCP**: `SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE_WAIT`, `LAST_ACK`, `CLOSING`, `CLOSED`
- **QUIC**: `QUIC_INITIAL`, `QUIC_HANDSHAKE`, `QUIC_CONNECTED`, `QUIC_DRAINING`, `QUIC_CLOSED` ⚠️ *Note: QUIC state tracking may be incomplete due to encrypted handshake packets and reassembly challenges*
- **UDP**: `UDP_ACTIVE`, `UDP_IDLE`, `UDP_STALE`  
- **DNS**: `DNS_QUERY`, `DNS_RESPONSE`
- **SSH**: `BANNER`, `KEYEXCHANGE`, `AUTHENTICATION`, `ESTABLISHED` ⚠️ *Note: SSH state tracking is based on packet inspection and may not always reflect the true connection state*
- **Other**: `ECHO_REQUEST`, `ECHO_REPLY`, `ARP_REQUEST`, `ARP_REPLY`

**Examples:**

- `sport:80 process:nginx` - Nginx connections from port 80
- `dport:443 sni:google.com` - HTTPS connections to Google
- `sport:443 state:syn_recv` - Half-open connections to port 443 (SYN flood detection)
- `proto:tcp state:established` - All established TCP connections
- `process:firefox state:quic_connected` - Active QUIC connections from Firefox
- `dport:22 ssh:openssh` - SSH connections using OpenSSH
- `state:established ssh:openssh` - Established SSH connections using OpenSSH

Press `Esc` to clear filter.

## Logging

Logging is disabled by default. When enabled with the `--log-level` option, RustNet creates timestamped log files in the `logs/` directory. Each session generates a new log file with the format `rustnet_YYYY-MM-DD_HH-MM-SS.log`.

Log files contain:

- Application startup and shutdown events
- Network interface information
- Packet capture statistics
- Connection state changes
- Error diagnostics

**To enable logging**, use the `--log-level` option:

```bash
# Enable info-level logging
sudo rustnet --log-level info

# Enable debug-level logging for troubleshooting
sudo rustnet --log-level debug
```

The `scripts/clear_old_logs.sh` script is provided for log cleanup.

## Architecture

RustNet uses a multi-threaded architecture for packet processing:

```
┌─────────────────┐
│ Packet Capture  │ ──packets──> Crossbeam Channel
│   (libpcap)     │                      │
└─────────────────┘                      │
                                         ├──> ┌──────────────────┐
                                         ├──> │ Packet Processor │ ──> DashMap
                                         ├──> │    (Thread 0)    │      │
                                         └──> │    (Thread N)    │      │
                                              └──────────────────┘      │
                                                                        │
┌─────────────────┐                                                     │
│Process Enrichment│ ────────────────────────────────────────────> DashMap
│  (Platform API) │                                                     │
└─────────────────┘                                                     │
                                                                        │
┌─────────────────┐                                                     │
│Snapshot Provider│ <─────────────────────────────────────────── DashMap
└─────────────────┘                                                     │
         │                                                              │
         └──> RwLock<Vec<Connection>> (for UI)                          │
                                                                        │
┌─────────────────┐                                                     │
│ Cleanup Thread  │ <─────────────────────────────────────────── DashMap
└─────────────────┘
```

### Key Components

1. **Packet Capture Thread**: Uses libpcap to capture raw packets from the network interface
2. **Packet Processors**: Multiple worker threads parse packets and perform DPI analysis
3. **Process Enrichment**: Platform-specific APIs to associate connections with processes
4. **Snapshot Provider**: Creates consistent snapshots for the UI at regular intervals
5. **Cleanup Thread**: Removes inactive connections using smart, protocol-aware timeouts:
   - **TCP Established**: 10 minutes (active) / 5 minutes (idle)
   - **HTTP/HTTPS**: 10 minutes (supports keep-alive)
   - **SSH**: 30 minutes (long-lived sessions)
   - **QUIC**: 10 minutes (active) / 5 minutes (idle)
   - **DNS**: 30 seconds (short-lived queries)
   - **TCP Closed**: 5 seconds (rapid cleanup)
6. **Rate Refresh Thread**: Updates bandwidth calculations every second with gentle decay
7. **DashMap**: Concurrent hashmap for storing connection state

## Dependencies

RustNet is built with the following key dependencies:

- **ratatui**: Terminal user interface framework with full widget support
- **crossterm**: Cross-platform terminal manipulation
- **pcap**: Packet capture library bindings
- **pnet_datalink**: Network interface enumeration
- **dashmap**: Concurrent hashmap
- **crossbeam**: Multi-threading utilities and channels
- **dns-lookup**: DNS resolution capabilities
- **clap**: Command-line argument parsing with derive features
- **simplelog**: Flexible logging framework
- **anyhow**: Error handling and context
- **arboard**: Clipboard access for copying addresses
- **log**: Logging facade
- **num_cpus**: CPU core detection for threading
- **simple-logging**: Additional logging utilities
- **chrono**: Date and time handling
- **ring**: Cryptographic operations
- **aes**: AES encryption support
- **procfs** (Linux): Process information from /proc filesystem

## Platform-Specific Implementation

### Process Lookup

RustNet uses platform-specific APIs to associate network connections with processes:

- **Linux**: Parses `/proc/net/tcp`, `/proc/net/udp`, and `/proc/<pid>/fd/` to find socket inodes
- **macOS**: Uses PKTAP (Packet Tap) headers when available for process identification from packet metadata, with fallback to `lsof` system commands for process-socket associations. PKTAP extracts process information directly from kernel packet headers when supported.
- **Windows**: Uses nothing so far :)

### Network Interfaces

The tool automatically detects and lists available network interfaces using platform-specific methods, falling back to pcap's device enumeration when native methods are unavailable.

## Performance Considerations

- **Multi-threaded Processing**: Packet processing is distributed across multiple threads (up to 4 by default)
- **Concurrent Data Structures**: Uses DashMap for concurrent access with fine-grained locking
- **Batch Processing**: Packets are processed in batches to improve cache efficiency
- **Selective DPI**: Deep packet inspection can be disabled with `--no-dpi` for lower overhead
- **Configurable Intervals**: Adjust refresh rates based on your needs

## Troubleshooting

### Common Issues

1. **Permission Denied**: Packet capture requires elevated privileges. Run with `sudo` or set capabilities.

2. **No Connections Shown**:
   - Check if the correct network interface is selected
   - Verify packet capture permissions
   - Try showing localhost connections with `--show-localhost` (filtered by default)

3. **High CPU Usage**:
   - Increase the refresh interval: `--refresh-interval 2000`
   - Disable DPI if not needed: `--no-dpi`
   - Check log files for excessive packet rates

4. **Process Names Not Showing**:
   - On Linux, ensure `/proc` is accessible
   - Some processes may require root privileges to identify

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
sudo rustnet --log-level debug
```

Check the generated log file in the `logs/` directory for detailed diagnostics. Note that logging is disabled by default, so you must explicitly enable it with the `--log-level` option.

## Security Considerations

- RustNet requires privileged access for packet capture
- The tool only monitors traffic; it does not modify or block connections
- Log files may contain sensitive connection information
- No data is transmitted outside your system

## Permissions

RustNet requires elevated privileges to capture network packets because accessing network interfaces for packet capture is a privileged operation on all modern operating systems. This section explains how to properly grant these permissions on different platforms.

### Why Permissions Are Required

Network packet capture requires access to:

- **Raw sockets** for low-level network access
- **Network interfaces** in promiscuous mode
- **BPF (Berkeley Packet Filter) devices** on macOS/BSD systems
- **Network namespaces** on some Linux configurations

These capabilities are restricted to prevent malicious software from intercepting network traffic.

### macOS Permission Setup

On macOS, packet capture requires access to BPF (Berkeley Packet Filter) devices located at `/dev/bpf*`.

#### Option 1: Run with sudo (Simplest)

```bash
# Build and run with sudo
cargo build --release
sudo ./target/release/rustnet
```

#### Option 2: BPF Group Access (Recommended)

Add your user to the `access_bpf` group for passwordless packet capture:

**Using Wireshark's ChmodBPF (Easiest):**

```bash
# Install Wireshark's BPF permission helper
brew install --cask wireshark-chmodbpf

# Log out and back in for group changes to take effect
# Then run rustnet without sudo:
rustnet
```

**Manual BPF Group Setup:**

```bash
# Create the access_bpf group (if it doesn't exist)
sudo dseditgroup -o create access_bpf

# Add your user to the group
sudo dseditgroup -o edit -a $USER -t user access_bpf

# Set permissions on BPF devices (this needs to be done after each reboot)
sudo chmod g+rw /dev/bpf*
sudo chgrp access_bpf /dev/bpf*

# Log out and back in for group membership to take effect
```

#### Option 3: Homebrew Installation

If installed via Homebrew, the formula will provide detailed setup instructions:

```bash
brew tap domcyrus/rustnet
brew install rustnet
# Follow the caveats displayed after installation
```

### Linux Permission Setup

On Linux, packet capture requires `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.

#### Option 1: Run with sudo (Simplest)

```bash
# Build and run with sudo
cargo build --release
sudo ./target/release/rustnet
```

#### Option 2: Grant Capabilities (Recommended)

Grant specific network capabilities to the binary without full root privileges:

**For source builds:**

```bash
# Build the binary first
cargo build --release

# Grant network capabilities to the binary
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rustnet

# Now run without sudo
./target/release/rustnet
```

**For cargo-installed binaries:**

```bash
# If installed via cargo install rustnet-monitor
sudo setcap cap_net_raw,cap_net_admin=eip ~/.cargo/bin/rustnet

# Now run without sudo
rustnet
```

**For eBPF-enabled builds (default on Linux, experimental):**

eBPF is enabled by default on Linux and requires additional capabilities for kernel program loading and performance monitoring:

```bash
# Build (eBPF is enabled by default on Linux)
cargo build --release

# Grant full capability set for eBPF (modern kernels with CAP_BPF support)
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+eip' ./target/release/rustnet

# OR for older kernels (fallback to CAP_SYS_ADMIN)
sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin+eip' ./target/release/rustnet

# Run without sudo - eBPF programs will load automatically if capabilities are sufficient
./target/release/rustnet
```

To disable eBPF and use procfs-only mode:
```bash
cargo build --release --no-default-features
```

**Capability requirements for eBPF:**
- `CAP_NET_RAW` - Raw socket access for packet capture
- `CAP_NET_ADMIN` - Network administration 
- `CAP_BPF` - BPF program loading (Linux 5.8+, preferred)
- `CAP_PERFMON` - Performance monitoring (Linux 5.8+, preferred)  
- `CAP_SYS_ADMIN` - System administration (fallback for older kernels)

The application will automatically detect available capabilities and fall back to procfs-only mode if eBPF cannot be loaded.

**Note:** eBPF support is enabled by default on Linux but is experimental and may have limitations with process name display (see [eBPF Enhanced Process Identification](#ebpf-enhanced-process-identification-experimental)).

**For system-wide installation:**

```bash
# If installed via package manager or copied to /usr/local/bin
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/rustnet
rustnet
```

#### Option 3: Homebrew on Linux

```bash
# Install via Homebrew
brew install domcyrus/rustnet/rustnet

# Grant capabilities to the Homebrew-installed binary
sudo setcap cap_net_raw,cap_net_admin=eip $(brew --prefix)/bin/rustnet

# Run without sudo
rustnet
```

### Windows Permission Setup

Windows support is currently limited, but when available:

- RustNet will require **Administrator privileges**
- Must install **WinPcap** or **Npcap** for packet capture
- Run Command Prompt or PowerShell "As Administrator"

### Verifying Permissions

To verify that permissions are set up correctly:

#### macOS

```bash
# Check BPF device permissions
ls -la /dev/bpf*

# Check group membership
groups | grep access_bpf

# Test without sudo
rustnet --help
```

#### Linux

```bash
# Check capabilities on the binary
# For source builds:
getcap ./target/release/rustnet

# For cargo-installed binaries:
getcap ~/.cargo/bin/rustnet

# For system-wide installations:
getcap $(which rustnet)

# Should show: cap_net_raw,cap_net_admin=eip

# Test without sudo
rustnet --help
```

### Troubleshooting Permission Issues

#### "Permission denied" errors

**On macOS:**

- Ensure you're in the `access_bpf` group: `groups | grep access_bpf`
- Check BPF device permissions: `ls -la /dev/bpf0`
- Try running with sudo to confirm it's a permission issue
- Log out and back in after group changes

**On Linux:**

- Check if capabilities are set: `getcap $(which rustnet)` or `getcap ~/.cargo/bin/rustnet`
- Verify libpcap is installed: `ldconfig -p | grep pcap`
- Try running with sudo to confirm it's a permission issue: `sudo $(which rustnet)`
- Some systems require `CAP_NET_BIND_SERVICE` as well

#### "No suitable capture interfaces found"

- Check available interfaces: `ip link show` (Linux) or `ifconfig` (macOS)
- Try specifying an interface explicitly: `rustnet -i eth0`
- Ensure the interface is up and has an IP address
- Some virtual interfaces may not support packet capture

#### "Operation not permitted" with capabilities set

- Capabilities may have been removed by system updates
- Re-apply capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which rustnet)`
- Some filesystems don't support extended attributes (capabilities)
- Try copying the binary to a different filesystem (e.g., from NFS to local disk)

### Security Best Practices

1. **Use capabilities instead of sudo** when possible (Linux)
2. **Use group-based access** instead of running as root (macOS)
3. **Regularly audit** which users have packet capture privileges
4. **Consider network segmentation** if running on production systems
5. **Monitor log files** for unauthorized usage
6. **Remove capabilities** when RustNet is no longer needed:

   ```bash
   # Linux: Remove capabilities
   sudo setcap -r /path/to/rustnet

   # macOS: Remove from group
   sudo dseditgroup -o edit -d $USER -t user access_bpf
   ```

### Integration with System Monitoring

For production environments, consider:

- **Audit logging** of packet capture access
- **Network monitoring policies** and compliance requirements
- **User access reviews** for privileged network access
- **Automated capability management** in configuration management systems

This permissions setup ensures RustNet can capture packets while maintaining security best practices and principle of least privilege.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## For Maintainers

For detailed information about the release process, see [RELEASE.md](RELEASE.md).

## Roadmap

For planned features and future improvements, see [ROADMAP.md](ROADMAP.md).

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI
- Packet capture powered by [libpcap](https://www.tcpdump.org/)
- Inspired by tools like `tshark/wireshark/tcpdump`, `sniffnet`, `netstat`, `ss`, and `iftop`
- Some code is vibe coded (OMG) / may the LLM gods be with you
