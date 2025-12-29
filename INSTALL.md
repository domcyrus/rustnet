# Installation Guide

This guide covers all installation methods for RustNet across different platforms.

## Table of Contents

- [Installing from Release Packages](#installing-from-release-packages)
  - [macOS DMG Installation](#macos-dmg-installation)
  - [Windows MSI Installation](#windows-msi-installation)
  - [Windows Chocolatey Installation](#windows-chocolatey-installation)
  - [Linux Package Installation](#linux-package-installation)
  - [FreeBSD Installation](#freebsd-installation)
- [Install via Cargo](#install-via-cargo)
- [Building from Source](#building-from-source)
- [Using Docker](#using-docker)
- [Prerequisites](#prerequisites)
- [Permissions Setup](#permissions-setup)
- [Troubleshooting](#troubleshooting)

## Installing from Release Packages

Pre-built packages are available for each release on the [GitHub Releases](https://github.com/domcyrus/rustnet/releases) page.

### macOS DMG Installation

> ** Prefer Homebrew?** If you have Homebrew installed, using `brew install` is easier and avoids Gatekeeper bypass steps. See [Homebrew Installation](#homebrew-installation) for instructions.

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

### Windows Chocolatey Installation

The easiest way to install RustNet on Windows is via [Chocolatey](https://community.chocolatey.org/packages/rustnet):

```powershell
# Run in Administrator PowerShell
choco install rustnet
```

**Note:** You still need to install [Npcap](https://npcap.com) separately with "WinPcap API compatible mode" enabled.

### Linux Package Installation

#### Ubuntu PPA (Recommended for Ubuntu 25.10+)

The easiest way to install RustNet on Ubuntu is via the official PPA.

```bash
# Add the RustNet PPA
sudo add-apt-repository ppa:domcyrus/rustnet

# Update package list
sudo apt update

# Install rustnet
sudo apt install rustnet

# Run with sudo
sudo rustnet

# Optional: Grant capabilities to run without sudo (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' /usr/bin/rustnet
rustnet
```

**Important:** The PPA only supports Ubuntu 25.10+ due to the Rust 1.88+ requirement. Earlier Ubuntu versions don't have a recent enough Rust compiler in their repositories. For older Ubuntu versions, use the [.deb packages](#debianubuntu-deb-packages) from GitHub releases or [build from source](#building-from-source).

#### Debian/Ubuntu (.deb packages)

For manual installation or non-Ubuntu Debian-based distributions:

```bash
# Download the appropriate package for your architecture:
# - Rustnet_LinuxDEB_amd64.deb (x86_64)
# - Rustnet_LinuxDEB_arm64.deb (ARM64)
# - Rustnet_LinuxDEB_armhf.deb (ARMv7)

# Install the package (capabilities are automatically configured)
sudo dpkg -i Rustnet_LinuxDEB_amd64.deb

# Install dependencies if needed
sudo apt-get install -f

# Run without sudo (capabilities were set by post-install script)
rustnet

# Verify capabilities
getcap /usr/bin/rustnet
```

**Note:** The .deb package automatically sets Linux capabilities via post-install script, so you can run RustNet without sudo.

#### RedHat/Fedora/CentOS (.rpm packages)

For manual installation or distributions not using COPR:

```bash
# Download the appropriate package for your architecture:
# - Rustnet_LinuxRPM_x86_64.rpm
# - Rustnet_LinuxRPM_aarch64.rpm

# Install the package (capabilities are automatically configured)
sudo rpm -i Rustnet_LinuxRPM_x86_64.rpm
# Or with dnf/yum:
sudo dnf install Rustnet_LinuxRPM_x86_64.rpm

# Run without sudo (capabilities were set by post-install script)
rustnet

# Verify capabilities
getcap /usr/bin/rustnet
```

**Note:** The .rpm package automatically sets Linux capabilities via post-install script, so you can run RustNet without sudo.

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

#### Fedora (COPR - Recommended for Fedora 42+)

The easiest way to install RustNet on Fedora is via the official COPR repository.

```bash
# Enable the COPR repository
sudo dnf copr enable domcyrus/rustnet

# Install rustnet
sudo dnf install rustnet

# Run with sudo
sudo rustnet

# Optional: Grant capabilities to run without sudo (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' /usr/bin/rustnet
rustnet
```

**Important:** The COPR only supports Fedora 42 and 43 due to the Rust 1.88+ requirement. CentOS and RHEL don't have recent enough Rust compilers in their repositories. For those distributions, use the [.rpm packages](#redhatfedoracentos-rpm-packages) from GitHub releases or [build from source](#building-from-source).

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

# Grant capabilities to the Homebrew-installed binary (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' $(brew --prefix)/bin/rustnet

# Run without sudo
rustnet
```

#### Static Binary (Portable - Any Linux Distribution)

For maximum portability, static binaries are available that work on **any Linux distribution** regardless of GLIBC version. These are fully self-contained and require no system dependencies.

```bash
# Download the static binary for your architecture:
# - rustnet-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz (x86_64)
# - rustnet-vX.Y.Z-aarch64-unknown-linux-musl.tar.gz (ARM64)

# Extract the archive
tar xzf rustnet-vX.Y.Z-x86_64-unknown-linux-musl.tar.gz

# Move binary to PATH
sudo mv rustnet-vX.Y.Z-x86_64-unknown-linux-musl/rustnet /usr/local/bin/

# Grant capabilities (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' /usr/local/bin/rustnet

# Run without sudo
rustnet
```

**When to use static binaries:**
- Older distributions with outdated GLIBC (e.g., CentOS 7, older Ubuntu)
- Minimal/containerized environments
- Air-gapped systems where installing dependencies is difficult
- When you want a single portable binary

### FreeBSD Installation

FreeBSD support is available starting from version 0.15.0.

#### From Ports or Packages (Future)

Once available in FreeBSD ports:
```bash
# Using pkg (binary packages)
pkg install rustnet

# Or build from ports
cd /usr/ports/net/rustnet && make install clean
```

#### From GitHub Releases

Download the FreeBSD binary from the [rustnet-bsd releases](https://github.com/domcyrus/rustnet-bsd/releases):

```bash
# Download the appropriate package
fetch https://github.com/domcyrus/rustnet-bsd/releases/download/vX.Y.Z/rustnet-vX.Y.Z-x86_64-unknown-freebsd.tar.gz

# Extract the archive
tar xzf rustnet-vX.Y.Z-x86_64-unknown-freebsd.tar.gz

# Move binary to PATH
sudo mv rustnet-vX.Y.Z-x86_64-unknown-freebsd/rustnet /usr/local/bin/

# Make it executable
sudo chmod +x /usr/local/bin/rustnet

# Run with sudo
sudo rustnet
```

#### Building from Source on FreeBSD

```bash
# Install dependencies
pkg install rust libpcap

# Clone the repository
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Build in release mode
cargo build --release

# The executable will be in target/release/rustnet
sudo ./target/release/rustnet
```

#### Permission Setup for FreeBSD

FreeBSD requires access to BPF (Berkeley Packet Filter) devices for packet capture.

**Option 1: Run with sudo (Simplest)**
```bash
sudo rustnet
```

**Option 2: Add user to the bpf group (Recommended)**
```bash
# Add your user to the bpf group
sudo pw groupmod bpf -m $(whoami)

# Log out and back in for group changes to take effect

# Now run without sudo
rustnet
```

**Option 3: Change BPF device permissions (Temporary)**
```bash
# This will reset on reboot
sudo chmod o+rw /dev/bpf*

# Now run without sudo
rustnet
```

**Verifying FreeBSD Permissions:**
```bash
# Check if you're in the bpf group
groups | grep bpf

# Check BPF device permissions
ls -la /dev/bpf*

# Test without sudo
rustnet --help
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
- Platform-specific dependencies:
  - **Linux (Debian/Ubuntu)**:
    ```bash
    sudo apt-get install build-essential pkg-config libpcap-dev libelf-dev zlib1g-dev clang llvm
    ```
  - **Linux (RedHat/CentOS/Fedora)**:
    ```bash
    sudo yum install make pkgconfig libpcap-devel elfutils-libelf-devel zlib-devel clang llvm
    ```
  - **macOS**: Install Xcode Command Line Tools: `xcode-select --install`
  - **FreeBSD**: `pkg install rust libpcap`
  - **Windows**: Install Npcap and Npcap SDK (see [Windows Build Setup](#windows-build-setup) below)

### Basic Build

```bash
# Clone the repository
git clone https://github.com/domcyrus/rustnet.git
cd rustnet

# Build in release mode (eBPF is enabled by default on Linux)
cargo build --release

# To build WITHOUT eBPF support (procfs-only mode on Linux)
cargo build --release --no-default-features

# The executable will be in target/release/rustnet
```

To build without eBPF (procfs-only mode), use `cargo build --release --no-default-features`.

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

# Run with required capabilities for eBPF support (latest)
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:latest

# Run with specific version
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:0.7.0

# Run with specific interface
docker run --rm -it --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON --net=host \
  ghcr.io/domcyrus/rustnet:latest -i eth0

# Alternative: Run with privileged mode (less secure but simpler)
docker run --rm -it --privileged --net=host \
  ghcr.io/domcyrus/rustnet:latest

# View available options
docker run --rm ghcr.io/domcyrus/rustnet:latest --help
```

**Note:** The container requires capabilities (`NET_RAW`, `BPF`, and `PERFMON`) or privileged mode for packet capture with eBPF support. Host networking (`--net=host`) is recommended for monitoring all network interfaces.

## Permissions Setup

RustNet requires elevated privileges to capture network packets because accessing network interfaces for packet capture is a privileged operation on all modern operating systems. This section explains how to properly grant these permissions on different platforms.

> ### **Security Advantage: Read-Only Network Access on Linux**
>
> **RustNet uses read-only packet capture without promiscuous mode on all platforms.** This means:
>
> **Linux:** Requires only **`CAP_NET_RAW`** capability - **NOT** full root or `CAP_NET_ADMIN`
> **Principle of Least Privilege:** Minimal permissions needed for packet capture
> **No Promiscuous Mode:** Only captures packets to/from the host (not all network traffic)
> **Read-Only:** Cannot modify or inject packets
> **Enhanced Security:** Reduced attack surface compared to full root access
>
> **macOS Note:** PKTAP (for process metadata) requires root privileges, but you can run without sudo using the `lsof` fallback for basic packet capture.

### Why Permissions Are Required

Network packet capture requires access to:

- **Raw sockets** for low-level network access (read-only, non-promiscuous mode)
- **Network interfaces** for packet capture
- **BPF (Berkeley Packet Filter) devices** on macOS/BSD systems
- **Network namespaces** on some Linux configurations

These capabilities are restricted to prevent malicious software from intercepting network traffic.

### macOS Permission Setup

On macOS, packet capture requires access to BPF (Berkeley Packet Filter) devices located at `/dev/bpf*`.

**Note:** macOS PKTAP (for extracting process metadata from packets) requires **root/sudo** privileges. Without sudo, RustNet uses `lsof` as a fallback for process detection (slower but works without root).

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

### Linux Permission Setup (Read-Only Access - No Root Required!)

**Linux Advantage:** RustNet requires **only `CAP_NET_RAW`** for packet capture - far less than full root access!

On Linux, packet capture requires only the `CAP_NET_RAW` capability for read-only, non-promiscuous packet capture. For eBPF-enhanced process tracking, additional capabilities (`CAP_BPF` and `CAP_PERFMON`) are needed, but **`CAP_NET_ADMIN` is NOT required**.

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

# Grant capabilities to the binary (modern kernel 5.8+, with eBPF support)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' ./target/release/rustnet

# Now run without sudo
./target/release/rustnet
```

**For cargo-installed binaries:**

```bash
# If installed via cargo install rustnet-monitor (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' ~/.cargo/bin/rustnet

# Now run without sudo
rustnet
```

**For eBPF-enabled builds (enhanced Linux performance - enabled by default):**

eBPF is enabled by default on Linux and provides lower-overhead process identification using kernel probes:

```bash
# Build in release mode (eBPF is enabled by default)
cargo build --release

# Modern Linux (5.8+) - works with just these three capabilities:
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' ./target/release/rustnet
./target/release/rustnet

# Legacy Linux (older kernels without CAP_BPF) - use CAP_SYS_ADMIN as fallback:
sudo setcap 'cap_net_raw,cap_sys_admin=eip' ./target/release/rustnet
./target/release/rustnet

# Check TUI Statistics panel - should show "Process Detection: eBPF + procfs"
```

**Capability requirements:**

**Base capability (always required):**
- `CAP_NET_RAW` - Raw socket access for read-only packet capture (non-promiscuous mode)

**eBPF-specific capabilities (choose based on kernel version):**

**Modern Linux (5.8+):**
- `CAP_BPF` - BPF program loading and map operations
- `CAP_PERFMON` - Performance monitoring and tracing operations

**Legacy Linux (pre-5.8):**
- `CAP_SYS_ADMIN` - Required for BPF operations on older kernels without CAP_BPF support

**Note:** CAP_NET_ADMIN is NOT required. RustNet uses read-only packet capture without promiscuous mode.

**Fallback behavior**: If eBPF cannot load (e.g., insufficient capabilities, incompatible kernel), the application automatically uses procfs-only mode. The TUI Statistics panel displays which detection method is active:
- `Process Detection: eBPF + procfs` - eBPF successfully loaded
- `Process Detection: procfs` - Using procfs fallback

**Note:** eBPF is enabled by default on Linux builds and may have limitations with process name display. See [ARCHITECTURE.md](ARCHITECTURE.md) for details on eBPF implementation. To build without eBPF, use `cargo build --release --no-default-features`.

**For system-wide installation:**

```bash
# If installed via package manager or copied to /usr/local/bin (modern kernel 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' /usr/local/bin/rustnet
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

# Modern (5.8+): Should show cap_net_raw,cap_bpf,cap_perfmon=eip
# Legacy: Should show cap_net_raw,cap_sys_admin=eip

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
- Re-apply capabilities (modern): `sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' $(which rustnet)`
- Some filesystems don't support extended attributes (capabilities)
- Try copying the binary to a different filesystem (e.g., from NFS to local disk)

#### Windows: Npcap Not Found

- Ensure Npcap is installed from https://npcap.com/dist/
- During Npcap installation, select **"WinPcap API compatible mode"**
- Verify Npcap service is running: `sc query npcap`
- Try reinstalling Npcap with administrator privileges

#### Build Errors

**Windows - Npcap SDK not found:**
- Ensure the `LIB` environment variable includes the Npcap SDK path
- Check that the SDK is extracted to a directory without spaces
- Use the correct architecture (x64 vs x86) for your Rust toolchain

**Linux build fails:**
```bash
# Install all required dependencies
# Debian/Ubuntu
sudo apt-get install build-essential pkg-config libpcap-dev libelf-dev zlib1g-dev clang llvm

# RedHat/CentOS/Fedora
sudo yum install make pkgconfig libpcap-devel elfutils-libelf-devel zlib-devel clang llvm
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
