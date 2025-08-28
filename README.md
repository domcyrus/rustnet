# RustNet

A high-performance, cross-platform network monitoring tool built with Rust. RustNet provides real-time visibility into network connections with enhanced state display, intelligent connection lifecycle management, deep packet inspection capabilities, and a responsive terminal user interface.

## Features

- **Real-time Network Monitoring**: Monitor active TCP, UDP, ICMP, and ARP connections with **enhanced state visibility**
- **Intelligent Connection States**: Rich state display showing exactly what each connection is doing:
  - **TCP States**: `ESTABLISHED`, `SYN_SENT`, `TIME_WAIT`, `CLOSED`, etc.
  - **QUIC States**: `QUIC_INITIAL`, `QUIC_HANDSHAKE`, `QUIC_CONNECTED`, `QUIC_DRAINING`
  - **DNS States**: `DNS_QUERY`, `DNS_RESPONSE`
  - **Activity States**: `UDP_ACTIVE`, `UDP_IDLE`, `UDP_STALE` based on connection activity
- **Deep Packet Inspection (DPI)**: Automatically detect application protocols:
  - HTTP with host information
  - HTTPS/TLS with SNI (Server Name Indication)
  - DNS queries and responses
  - SSH connections
  - **QUIC protocol with CONNECTION_CLOSE frame detection** and proper RFC 9000 compliance
- **Smart Connection Lifecycle Management**:
  - **Dynamic timeouts** based on protocol, state, and activity (TCP closed: 5s, QUIC draining: 10s, SSH: 30min)
  - **Protocol-aware cleanup** (DNS: 30s, established TCP: 5min, QUIC with close frames: 1-10s)
  - **Activity-based timeout scaling** for long-lived vs idle connections
- **Process Identification**: Associate network connections with running processes
- **Service Name Resolution**: Identify well-known services using port numbers
- **Cross-platform Support**: Works on Linux, macOS and potentially on Windows and BSD systems
- **Terminal User Interface**: Clean, responsive TUI built with ratatui with **optimized column widths** for state visibility
- **Performance Optimized**: Multi-threaded packet processing with minimal overhead
- **Optional Logging**: Detailed logging with configurable log levels (disabled by default)

## Installation

### Prerequisites

- Rust 2024 edition or later (install from [rustup.rs](https://rustup.rs/))
- libpcap or similar packet capture library:
  - **Linux**: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RedHat/CentOS)
  - **macOS**: Included by default
  - **Windows**: Install WinPcap or Npcap

### Building from source

```bash
# Clone the repository
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Build in release mode
cargo build --release

# The executable will be in target/release/rustnet
```

### Running RustNet

On Unix-like systems (Linux/macOS), packet capture typically requires elevated privileges:

```bash
# Run with sudo
sudo ./target/release/rustnet

# Or set capabilities on Linux (to avoid needing sudo)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rustnet
./target/release/rustnet
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
- `Esc`: Go back to previous view
- `c`: Copy remote address to clipboard
- `h`: Toggle help screen

## Logging

Logging is **disabled by default** for better performance. When enabled with the `--log-level` option, RustNet creates timestamped log files in the `logs/` directory. Each session generates a new log file with the format `rustnet_YYYY-MM-DD_HH-MM-SS.log`.

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

RustNet employs a multi-threaded architecture for high-performance packet processing:

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
5. **Smart Cleanup Thread**: Removes connections using dynamic timeouts based on protocol, state, and activity
6. **DashMap**: Lock-free concurrent hashmap for storing connection state

## Dependencies

RustNet is built with the following key dependencies:

- **ratatui**: Terminal user interface framework with full widget support
- **crossterm**: Cross-platform terminal manipulation
- **pcap**: Packet capture library bindings
- **pnet_datalink**: Network interface enumeration
- **dashmap**: High-performance concurrent hashmap
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
- **macOS**: Uses **PKTAP (Packet Tap)** headers when available for direct process identification from packet metadata, with fallback to `lsof` system commands for process-socket associations. PKTAP provides more accurate and efficient process identification by extracting process information directly from the kernel packet headers.
- **Windows**: Uses nothing so far :)

### Network Interfaces

The tool automatically detects and lists available network interfaces using platform-specific methods, falling back to pcap's device enumeration when native methods are unavailable.

## Performance Considerations

- **Multi-threaded Processing**: Packet processing is distributed across multiple threads (up to 4 by default)
- **Lock-free Data Structures**: Uses DashMap for concurrent access without traditional locking
- **Batch Processing**: Packets are processed in batches to improve cache efficiency
- **Selective DPI**: Deep packet inspection can be disabled with `--no-dpi` for lower overhead
- **Configurable Intervals**: Adjust refresh rates and timeouts based on your needs

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

```bash
# Build the binary first
cargo build --release

# Grant network capabilities to the binary
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rustnet

# Now run without sudo
./target/release/rustnet
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
getcap ./target/release/rustnet
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

- Check if capabilities are set: `getcap $(which rustnet)`
- Verify libpcap is installed: `ldconfig -p | grep pcap`
- Try running with sudo to confirm it's a permission issue
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

## Release Process

This section is for maintainers releasing new versions of RustNet.

### Creating a New Release

#### 1. Prepare the Release

```bash
# Ensure you're on the main branch with latest changes
git checkout main
git pull origin main

# Update version in Cargo.toml if needed
# Update CHANGELOG.md with release notes

# Test the build
cargo build --release
cargo test
```

#### 2. Create and Push Git Tag

```bash
# Create an annotated tag with release notes
git tag -a v0.2.0 -m "Release v0.2.0

- Fixed process display stability issues on macOS
- Improved PKTAP header processing
- Enhanced process name normalization
- Added comprehensive debug logging
"

# Push the tag to trigger GitHub release
git push origin v0.2.0
```

#### 3. Create GitHub Release

1. Go to the [GitHub repository releases page](https://github.com/domcyrus/rustnet/releases)
2. Click "Create a new release"
3. Select the tag you just pushed (v0.2.0)
4. Set the release title (e.g., "RustNet v0.2.0")
5. Add release notes describing changes, fixes, and new features
6. Attach pre-built binaries if available
7. Click "Publish release"

Alternatively, use GitHub CLI:

```bash
# Install GitHub CLI if not already installed
# brew install gh

# Create release from tag
gh release create v0.2.0 \
  --title "RustNet v0.2.0" \
  --notes-file CHANGELOG.md \
  --target main
```

#### 4. Update Homebrew Formula

After creating the GitHub release, update the Homebrew formula:

```bash
# Calculate SHA256 of the source tarball
curl -L "https://github.com/domcyrus/rustnet/archive/v0.2.0.tar.gz" | shasum -a 256

# The output will be something like:
# a1b2c3d4e5f6... (64-character hash)
```

Update the Homebrew formula file (`rustnet.rb` in your tap repository):

```ruby
class Rustnet < Formula
  desc "High-performance network monitoring tool with TUI"
  homepage "https://github.com/domcyrus/homebrew-rustnet"
  url "https://github.com/domcyrus/rustnet/archive/v0.2.0.tar.gz"
  sha256 "a1b2c3d4e5f6..." # Replace with actual SHA256 from above
  license "Apache-2.0"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    system "#{bin}/rustnet", "--version"
  end
end
```

#### 5. Test and Submit Homebrew Update

```bash
# Clone or update your homebrew tap repository
git clone https://github.com/domcyrus/homebrew-rustnet.git
cd homebrew-rustnet

# Update the formula file with new version and SHA256
# Edit rustnet.rb with the values from step 4

# Test the formula locally
brew install --build-from-source ./rustnet.rb
brew test rustnet
brew audit --strict rustnet.rb

# Commit and push the updated formula
git add rustnet.rb
git commit -m "Update rustnet to v0.2.0"
git push origin main
```

#### 6. Verify the Release

```bash
# Test installation from Homebrew
brew uninstall rustnet
brew update
brew install domcyrus/rustnet/rustnet

# Verify the new version
rustnet --version
```

### Automated Release Workflow

For future releases, consider setting up GitHub Actions to automate parts of this process:

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build and Release
        run: |
          cargo build --release
          # Add steps to create release artifacts
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: target/release/rustnet
          generate_release_notes: true
```

### Release Checklist

Before each release, ensure:

- [ ] Version number updated in `Cargo.toml`
- [ ] `CHANGELOG.md` updated with release notes
- [ ] All tests pass (`cargo test`)
- [ ] Documentation is up to date
- [ ] Git tag created and pushed
- [ ] GitHub release created
- [ ] Homebrew formula updated with correct SHA256
- [ ] Formula tested locally
- [ ] Release announced (if applicable)

### Versioning

RustNet follows [Semantic Versioning (SemVer)](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for backward-compatible functionality additions
- **PATCH** version for backward-compatible bug fixes

Examples:

- `v0.1.0` → `v0.1.1` (bug fixes)
- `v0.1.1` → `v0.2.0` (new features)
- `v0.2.0` → `v1.0.0` (major changes, API stability)

## TODO

### Platform Support

- **macOS Support**: Basic features need testing and fixes for macOS compatibility
- **Windows Support**: Core functionality requires implementation and testing on Windows
- **BSD Support**: Add support for FreeBSD, OpenBSD, and NetBSD
- **Linux Process Identification Enhancement**: Investigate using **eBPF** (Extended Berkeley Packet Filter) for direct kernel-level process identification similar to macOS PKTAP. This would provide more accurate and efficient process-to-connection mapping than the current `/proc` filesystem approach, especially for high-throughput scenarios.

### Features

- **DPI Enhancements**: Improve deep packet inspection capabilities:
  - Support more protocols (e.g., FTP, SMTP, etc.)
  - More accurate SNI detection for QUIC/HTTPS
  - More information about SSH connections (e.g., key exchange algorithms)
- **DNS Reverse Lookup**: Add optional hostname resolution (toggle between IP and hostname display)
- **IPv6 Support**: Full IPv6 connection tracking and display, including DNS resolution, didn't test yet
- **Search/Filter**: Add real-time search and filtering capabilities:
  - Filter by process name
  - Filter by protocol
  - Filter by port range
  - Filter by IP/hostname
  - Filter by SNI (Server Name Indication)
  - Regular expression support
- **Internationalization (i18n)**: Support for multiple languages in the UI
- **Connection History**: Store and display historical connection data
- **Export Functionality**: Export connections to CSV/JSON formats
- **Configuration File**: Support for persistent configuration (filters, UI preferences)
- **Connection Alerts**: Notifications for new connections or suspicious activity
- **GeoIP Integration**: Maybe add geographical location of remote IPs
- **Protocol Statistics**: Summary view of protocol distribution
- **Rate Limiting Detection**: Identify connections with unusual traffic patterns

### UI Improvements

- **Resizable Columns**: Dynamic column width adjustment
- **Connection Grouping**: Group connections by process/service
- **Sortable Columns**: Click to sort by any column
- **Connection Details Popup**: Modal dialog for detailed connection info
- **ASCII Graphs**: Terminal-based graphs for bandwidth/packet visualization
- **Mouse Support**: Click to select connections
- **Split Pane View**: Show multiple views simultaneously

### Development

- **Unit Tests**: Comprehensive test coverage for all modules
- **Integration Tests**: End-to-end testing for different platforms
- **CI/CD Pipeline**: Automated builds and releases for all platforms
- **Documentation**: API documentation and developer guide
- **Packaging/Distribution**: Create packages for easy installation on Linux, macOS, and Windows

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI
- Packet capture powered by [libpcap](https://www.tcpdump.org/)
- Inspired by tools like `tshark/wireshark/tcpdump`, `sniffnet`, `netstat`, `ss`, and `iftop`
- Some code is vibe coded (OMG) / may the LLM gods be with you
