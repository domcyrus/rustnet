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
  - Configurable timeouts based on protocol, state, and activity (TCP closed: 5s, QUIC draining: 10s, SSH: 30min)
  - Protocol-specific cleanup (DNS: 30s, established TCP: 5min, QUIC with close frames: 1-10s)
  - Activity-based timeout adjustment for long-lived vs idle connections
- **Process Identification**: Associate network connections with running processes
- **Service Name Resolution**: Identify well-known services using port numbers
- **Cross-platform Support**: Works on Linux, macOS and potentially on Windows and BSD systems
- **Advanced Filtering**: Real-time vim/fzf-style filtering with keyword support:
  - Navigate while typing filters
  - Fuzzy search across all connection fields including DPI data
  - Keyword filters: `port:44`, `src:192.168`, `dst:google.com`, `sni:github.com`, `process:firefox`
- **Terminal User Interface**: TUI built with ratatui with adjustable column widths for state visibility
- **Multi-threaded Processing**: Concurrent packet processing across multiple threads
- **Optional Logging**: Detailed logging with configurable log levels (disabled by default)

## Installation

### Prerequisites

- Rust 2024 edition or later (install from [rustup.rs](https://rustup.rs/))
- libpcap or similar packet capture library:
  - **Linux**: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RedHat/CentOS)
  - **macOS**: Included by default
  - **Windows**: Install Npcap and Npcap SDK (see [Windows Build Setup](#windows-build-setup) below)

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

# Build in release mode
cargo build --release

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

# Alternative: Run with privileged mode (less secure but simpler)
docker run --rm -it --privileged --net=host \
  ghcr.io/domcyrus/rustnet:latest

# View available options
docker run --rm ghcr.io/domcyrus/rustnet:latest --help

# Or with specific version
docker run --rm ghcr.io/domcyrus/rustnet:0.7.0 --help
```

**Note:** The container requires network capabilities (`NET_RAW` and `NET_ADMIN`) or privileged mode for packet capture. Host networking (`--net=host`) is recommended for monitoring all network interfaces.

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

# Filter out localhost connections
rustnet --no-localhost

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
      --no-localhost                     Filter out localhost connections
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
- `PageUp`: Move up by 10 items
- `PageDown`: Move down by 10 items
- `Enter`: View detailed information about selected connection
- `Esc`: Go back to previous view or clear active filter
- `c`: Copy remote address to clipboard
- `h`: Toggle help screen
- `/`: Enter filter mode (vim-style search with real-time results)

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
5. **Cleanup Thread**: Removes connections using configurable timeouts based on protocol, state, and activity
6. **DashMap**: Concurrent hashmap for storing connection state

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
   - Try disabling localhost filtering with `--no-localhost`

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
