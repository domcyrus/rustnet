# eBPF Build Guide

This document explains how to work with eBPF kernel headers in this project.

## Current Setup

The project bundles **architecture-specific vmlinux.h files** from the [libbpf/vmlinux.h](https://github.com/libbpf/vmlinux.h) repository. This eliminates network dependencies during builds and ensures reproducible builds.

### Bundled vmlinux.h Files

Pre-downloaded vmlinux.h files (based on Linux kernel 6.14) are included in the repository at:
- `resources/ebpf/vmlinux/x86/vmlinux.h` (for x86_64, ~1.1MB)
- `resources/ebpf/vmlinux/aarch64/vmlinux.h` (for aarch64, ~1.0MB)
- `resources/ebpf/vmlinux/arm/vmlinux.h` (for armv7, ~981KB)

These files are automatically used during the build process based on the target architecture. **No network access is required** during compilation.

**Benefits:**
- **Zero network dependency**: Works in restricted build environments (COPR, Fedora build systems, etc.)
- **Reproducible builds**: Same headers every time, no external dependencies
- **Complete kernel definitions**: All kernel structures available, no missing types
- **No manual maintenance**: Auto-generated from kernel BTF
- **Cross-kernel compatibility**: CO-RE/BTF ensures portability across kernel versions

**Trade-offs:**
- Repository size: ~3MB total for all architectures (acceptable for modern git)
- Not immediately clear which kernel structures are actually used by the code

## Updating Bundled vmlinux.h Files

The bundled vmlinux.h files are based on kernel 6.14 from the libbpf repository. To update them to a newer kernel version:

```bash
# Update all architectures at once
for arch in x86 aarch64 arm; do
  # Get the symlink target (e.g., vmlinux_6.14.h)
  target=$(curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/${arch}/vmlinux.h")

  # Download the actual file
  curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/${arch}/${target}" \
    -o "resources/ebpf/vmlinux/${arch}/vmlinux.h"

  echo "Updated ${arch} to ${target}"
done
```

Or update a single architecture:

```bash
# Example: Update x86 only
arch="x86"
target=$(curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/${arch}/vmlinux.h")
curl -sL "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/${arch}/${target}" \
  -o "resources/ebpf/vmlinux/${arch}/vmlinux.h"
```

After updating, commit the changes to the repository.

## Building with eBPF Support

To build rustnet with eBPF support on Linux:

```bash
# Install build dependencies
sudo apt-get install libelf-dev clang llvm  # Debian/Ubuntu
sudo yum install elfutils-libelf-devel clang llvm  # RedHat/CentOS/Fedora

# Build with eBPF feature
cargo build --release --features ebpf

# The bundled vmlinux.h files will be used automatically
# No network access required!
```

## Testing eBPF Functionality

After building with eBPF support, test that it works correctly:

```bash
# Option 1: Run with sudo (always works)
sudo cargo run --features ebpf

# Option 2: Set capabilities (Linux only, see INSTALL.md Permissions section)
sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon+eip' ./target/release/rustnet
./target/release/rustnet

# Check the TUI Statistics panel to verify it shows "Process Detection: eBPF + procfs"
```

**Note**: eBPF kprobe programs require specific Linux capabilities. See [INSTALL.md - Permissions Setup](INSTALL.md#permissions-setup) for detailed capability requirements. The required capabilities may vary by kernel version.

## Generating vmlinux.h from Your Local Kernel (Optional)

If you need to generate a vmlinux.h file for your specific kernel (e.g., for debugging or custom kernel builds):

```bash
# Method 1: Using bpftool (requires root/CAP_BPF)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Method 2: Using pahole (if available)
pahole -J /boot/vmlinux-$(uname -r)
pahole --btf_encode_detached vmlinux.btf /boot/vmlinux-$(uname -r)
bpftool btf dump file vmlinux.btf format c > vmlinux.h

# Method 3: From kernel source
cd /path/to/kernel/source
make scripts_gdb
bpftool btf dump file vmlinux format c > vmlinux.h
```

This is typically not needed since the bundled headers work across kernel versions thanks to CO-RE/BTF.

## Troubleshooting

### Compilation Errors

**"Bundled vmlinux.h not found"**:
- Ensure the `resources/ebpf/vmlinux/` directory exists
- Verify you've cloned the full repository (not a partial checkout)
- Check that the vmlinux.h file exists for your target architecture

**Missing build dependencies**:
- Install clang, llvm, and libelf-dev
- Ensure rustfmt is installed: `rustup component add rustfmt`

### Runtime Errors

**"BTF verification failed"**:
- Your kernel may not have BTF support enabled
- Linux kernel 4.19+ with BTF support is recommended
- Check if BTF is available: `ls /sys/kernel/btf/vmlinux`

**"Permission denied" when loading eBPF**:
- See [INSTALL.md - Permissions Setup](INSTALL.md#permissions-setup) for capability setup
- Required capabilities: `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_BPF`, `CAP_PERFMON`
- Some kernels may also require `CAP_SYS_ADMIN`

**eBPF fails to load, falls back to procfs**:
- This is expected behavior when eBPF can't load
- Check the TUI Statistics panel to see which detection method is active
- Common reasons: insufficient capabilities, incompatible kernel, BTF not available
