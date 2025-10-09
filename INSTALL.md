# Installation Guide

This guide covers all installation methods for RustNet across different platforms.

## Table of Contents

- [Installing from Release Packages](#installing-from-release-packages)
  - [macOS DMG Installation](#macos-dmg-installation)
  - [Windows MSI Installation](#windows-msi-installation)
  - [Linux Package Installation](#linux-package-installation)
- [Install via Cargo](#install-via-cargo)
- [Building from Source](#building-from-source)
- [Using Docker](#using-docker)
- [Prerequisites](#prerequisites)
- [Permissions Setup](#permissions-setup)
- [Troubleshooting](#troubleshooting)

## Installing from Release Packages

Pre-built packages are available for each release on the [GitHub Releases](https://github.com/domcyrus/rustnet/releases) page.

### macOS DMG Installation

> **💡 Prefer Homebrew?** If you have Homebrew installed, using `brew install` is easier and avoids Gatekeeper bypass steps. See [Homebrew Installation](#homebrew-installation) for instructions.

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
   - See the [Permissions Setup](#permissions-setup) section for detailed instructions

### Windows MSI Installation

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

### Linux Package Installation

#### Debian/Ubuntu (.deb packages)

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

# Optional: Grant capabilities to run without sudo (see Permissions section)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/rustnet
rustnet
```

#### RedHat/Fedora/CentOS (.rpm packages)

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

# Optional: Grant capabilities to run without sudo (see Permissions section)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/rustnet
rustnet
```

#### Arch Linux (AUR)

Two AUR packages are available:
- [`rustnet`](https://aur.archlinux.org/packages/rustnet) - Build from source (maintained by [@DeepChirp](https://github.com/DeepChirp))
- [`rustnet-bin`](https://aur.archlinux.org/packages/rustnet-bin) - Pre-compiled binary for faster installation

Install with your preferred AUR helper:
```bash
# Source build (optimized for your system)
yay -S rustnet

# OR pre-compiled binary (faster installation)
yay -S rustnet-bin
```

#### Fedora/RHEL/CentOS (COPR)

```bash
sudo dnf copr enable domcyrus/rustnet
sudo dnf install rustnet
```

#### Homebrew Installation

**On macOS:**
```bash
brew tap domcyrus/rustnet
brew install rustnet

# Follow the caveats displayed after installation for permission setup
```

**On Linux:**
```bash
brew install domcyrus/rustnet/rustnet

# Grant capabilities to the Homebrew-installed binary
sudo setcap cap_net_raw,cap_net_admin=eip $(brew --prefix)/bin/rustnet

# Run without sudo
rustnet
```

## Install via Cargo

```bash
# Install directly from crates.io
cargo install rustnet-monitor

# The binary will be installed to ~/.cargo/bin/rustnet
# Make sure ~/.cargo/bin is in your PATH
```

After installation, see the [Permissions Setup](#permissions-setup) section to configure permissions.

## Building from Source

### Prerequisites

- Rust 2024 edition or later (install from [rustup.rs](https://rustup.rs/))
- libpcap or similar packet capture library:
  - **Linux**: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RedHat/CentOS)
  - **macOS**: Included by default
  - **Windows**: Install Npcap and Npcap SDK (see [Windows Build Setup](#windows-build-setup) below)
- **For eBPF support (optional, experimental - Linux only)**:
  - `sudo apt-get install libelf-dev clang llvm` (Debian/Ubuntu)
  - `sudo yum install elfutils-libelf-devel clang llvm` (RedHat/CentOS)
  - Linux kernel 4.19+ with BTF support recommended

### Basic Build

```bash
# Clone the repository
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Build in release mode (basic functionality)
cargo build --release

# Build with experimental eBPF support for enhanced Linux performance (Linux only)
cargo build --release --features ebpf

# The executable will be in target/release/rustnet
```

See [EBPF_BUILD.md](EBPF_BUILD.md) for detailed eBPF build instructions.

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

## Using Docker

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
```

**Note:** The container requires network capabilities (`NET_RAW` and `NET_ADMIN`) or privileged mode for packet capture. Host networking (`--net=host`) is recommended for monitoring all network interfaces.

## Permissions Setup

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

**Using Wireshark's ChmodBPF (For basic packet capture):**

```bash
# Install Wireshark's BPF permission helper
brew install --cask wireshark-chmodbpf

# Log out and back in for group changes to take effect
# Then run rustnet without sudo:
rustnet  # Uses lsof for process detection (slower)

# For PKTAP support with process metadata from packet headers, use sudo:
sudo rustnet  # Uses PKTAP for faster process detection
```

**Note**: `wireshark-chmodbpf` grants access to `/dev/bpf*` for packet capture, but **PKTAP** is a separate privileged kernel interface that requires root privileges regardless of BPF permissions. The TUI will display which detection method is active ("pktap" with sudo, or "lsof" without).

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

**For experimental eBPF-enabled builds (enhanced Linux performance):**

eBPF is an experimental feature that provides lower-overhead process identification using kernel probes:

```bash
# Build with eBPF support
cargo build --release --features ebpf

# Try modern capabilities first (Linux 5.8+)
sudo setcap 'cap_net_raw,cap_net_admin,cap_bpf,cap_perfmon+eip' ./target/release/rustnet
./target/release/rustnet

# If eBPF fails to load, add CAP_SYS_ADMIN (may be required depending on kernel version)
sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon+eip' ./target/release/rustnet
./target/release/rustnet
# Check TUI Statistics panel - should show "Process Detection: eBPF + procfs"
```

**Capability requirements for eBPF:**

Base capabilities (always required):
- `CAP_NET_RAW` - Raw socket access for packet capture
- `CAP_NET_ADMIN` - Network administration

eBPF-specific capabilities (Linux 5.8+):
- `CAP_BPF` - BPF program loading and map operations
- `CAP_PERFMON` - Performance monitoring and tracing operations

Additional capability (may be required):
- `CAP_SYS_ADMIN` - Some kernel versions or configurations may still require this for kprobe attachment, even with CAP_BPF and CAP_PERFMON available. Requirements vary by kernel version and configuration.

**Fallback behavior**: If eBPF cannot load (e.g., insufficient capabilities, incompatible kernel), the application automatically uses procfs-only mode. The TUI Statistics panel displays which detection method is active:
- `Process Detection: eBPF + procfs` - eBPF successfully loaded
- `Process Detection: procfs` - Using procfs fallback

**Note:** eBPF support is experimental and may have limitations with process name display. See [ARCHITECTURE.md](ARCHITECTURE.md) for details on eBPF implementation.

**For system-wide installation:**

```bash
# If installed via package manager or copied to /usr/local/bin
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/rustnet
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

## Troubleshooting

### Common Installation Issues

#### Permission Denied Errors

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

#### No Suitable Capture Interfaces Found

- Check available interfaces: `ip link show` (Linux) or `ifconfig` (macOS)
- Try specifying an interface explicitly: `rustnet -i eth0`
- Ensure the interface is up and has an IP address
- Some virtual interfaces may not support packet capture

#### Operation Not Permitted (with capabilities set)

- Capabilities may have been removed by system updates
- Re-apply capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip $(which rustnet)`
- Some filesystems don't support extended attributes (capabilities)
- Try copying the binary to a different filesystem (e.g., from NFS to local disk)

#### Windows: Npcap Not Found

- Ensure Npcap is installed from https://npcap.com/dist/
- During Npcap installation, select **"WinPcap API compatible mode"**
- Verify Npcap service is running: `sc query npcap`
- Try reinstalling Npcap with administrator privileges

#### Build Errors

**Linux - Missing libpcap:**
```bash
# Debian/Ubuntu
sudo apt-get install libpcap-dev

# RedHat/CentOS/Fedora
sudo yum install libpcap-devel
```

**Windows - Npcap SDK not found:**
- Ensure the `LIB` environment variable includes the Npcap SDK path
- Check that the SDK is extracted to a directory without spaces
- Use the correct architecture (x64 vs x86) for your Rust toolchain

**eBPF build fails:**
```bash
# Install required dependencies
# Debian/Ubuntu
sudo apt-get install libelf-dev clang llvm

# RedHat/CentOS/Fedora
sudo yum install elfutils-libelf-devel clang llvm
```

### Getting Help

If you encounter issues not covered here:

1. Enable debug logging: `rustnet --log-level debug`
2. Check the log file in the `logs/` directory
3. Open an issue on [GitHub](https://github.com/domcyrus/rustnet/issues) with:
   - Your operating system and version
   - Installation method used
   - Error messages from logs
   - Output of permission verification commands

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
