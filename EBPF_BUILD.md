# eBPF Build Guide

This document explains how to work with eBPF kernel headers in this project.

## Current Setup

We use the **full vmlinux.h header** that is automatically downloaded at build time. The build process downloads architecture-specific kernel headers from the [libbpf/vmlinux.h](https://github.com/libbpf/vmlinux.h) repository.

**Benefits of this approach:**

- **Zero maintenance**: No manual header updates needed when adding new eBPF features
- **Complete definitions**: All kernel structures and types are available
- **Architecture-aware**: Downloads the correct header for your target architecture (x86, aarch64, arm)
- **Build-time download**: Headers are cached in `OUT_DIR`, reused between builds
- **Git-friendly**: Headers are not committed to the repository (gitignored)
- **Cross-compilation support**: Works seamlessly when cross-compiling for different architectures
- **crates.io compatible**: No git dependencies required

**How it works:**

1. During `cargo build`, the `build.rs` script detects the target architecture
2. It downloads the appropriate `vmlinux.h` from `https://github.com/libbpf/vmlinux.h`
3. The header is cached in the build output directory (`target/<profile>/build/<pkg>/out/vmlinux_headers/<arch>/`)
4. Subsequent builds reuse the cached header (no re-download needed)
5. The eBPF program is compiled with `-I` pointing to the cached header directory

## Automatic vmlinux.h Download

The build process automatically handles downloading the correct header. No manual steps required!

**Download process details:**

```rust
// In build.rs (simplified)
fn download_vmlinux_header(arch: &str) -> Result<PathBuf> {
    // 1. Check cache first
    let cache_dir = out_dir.join("vmlinux_headers").join(arch);
    if vmlinux_file.exists() {
        return Ok(cache_dir); // Use cached version
    }

    // 2. Download symlink to get versioned filename
    let symlink_url = format!(
        "https://raw.githubusercontent.com/libbpf/vmlinux.h/main/include/{}/vmlinux.h",
        arch
    );

    // 3. Follow symlink to actual file (e.g., vmlinux_6.14.h)
    // 4. Download and cache the full header
    // 5. Return path for clang include
}
```

**Manual generation (alternative for local kernel):**

If you want to generate a vmlinux.h from your running kernel instead:

```bash
# Using bpftool (requires root/CAP_BPF)
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## How to Create Minimal Headers from Full vmlinux.h

### 1. Identify Required Structures

First, analyze your eBPF program to find which kernel structures you access:

```bash
# Find all struct references in your eBPF code
grep -E "struct [a-zA-Z_]+" socket_tracker.bpf.c

# Find BPF_CORE_READ usage to see field accesses
grep -E "BPF_CORE_READ.*\\..*" socket_tracker.bpf.c

# Common structures for socket tracking:
# - struct sock (contains __sk_common)
# - struct sock_common (network fields)
# - struct msghdr (for sendmsg calls)
# - struct sockaddr_in (IPv4 addresses)
# - struct pt_regs (kprobe context)
```

### 2. Extract Definitions from Full vmlinux.h

Use these commands to extract specific structures:

```bash
# Extract a specific struct (e.g., sock_common)
awk '/^struct sock_common {/,/^}/' vmlinux.h

# Extract type definitions
grep "typedef.*__u[0-9]*\|typedef.*__be[0-9]*" vmlinux.h

# Extract multiple related structures
grep -A 50 "struct sock_common {" vmlinux.h
grep -A 20 "struct sock {" vmlinux.h
grep -A 10 "struct msghdr {" vmlinux.h
```

### 3. Create Minimal Header

Create a new header file with:

1. **Header guards and CO-RE pragma**:
   ```c
   #ifndef __VMLINUX_MIN_H__
   #define __VMLINUX_MIN_H__

   #ifndef BPF_NO_PRESERVE_ACCESS_INDEX
   #pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
   #endif
   ```

2. **Basic types** (only what you need):
   ```c
   typedef unsigned char __u8;
   typedef unsigned int __u32;
   typedef __u32 __be32;
   // etc.
   ```

3. **Required structures** with **only the fields you access**:
   ```c
   struct sock_common {
       // Only include fields accessed by BPF_CORE_READ
       __be32 skc_daddr;
       __be32 skc_rcv_saddr;
       __be16 skc_dport;
       __u16 skc_num;
       // ... other fields you actually use
   };
   ```

4. **Footer**:
   ```c
   #ifndef BPF_NO_PRESERVE_ACCESS_INDEX
   #pragma clang attribute pop
   #endif
   #endif
   ```

### 4. Automated Extraction Script

For complex projects, you can create a script to automate extraction:

```bash
#!/bin/bash
# extract_minimal_vmlinux.sh

FULL_VMLINUX="vmlinux.h"
OUTPUT="vmlinux_min.h"
BPF_SOURCE="socket_tracker.bpf.c"

# Find structs used in BPF program
STRUCTS=$(grep -oE "struct [a-zA-Z_]+" "$BPF_SOURCE" | sort -u | cut -d' ' -f2)

echo "Extracting structures: $STRUCTS"

# Start minimal header
cat > "$OUTPUT" << 'EOF'
#ifndef __VMLINUX_MIN_H__
#define __VMLINUX_MIN_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

/* Basic types */
EOF

# Extract basic types
grep "typedef.*__u[0-9]*\|typedef.*__be[0-9]*\|typedef.*__kernel" "$FULL_VMLINUX" | head -20 >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "/* Network structures */" >> "$OUTPUT"

# Extract each required struct
for struct in $STRUCTS; do
    echo "Extracting struct $struct..."
    awk "/^struct $struct \{/,/^}/" "$FULL_VMLINUX" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
done

# Close header
cat >> "$OUTPUT" << 'EOF'

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_MIN_H__ */
EOF

echo "Minimal vmlinux header created: $OUTPUT"
```

## Testing eBPF Compilation

To build and test eBPF programs:

```bash
# Build with eBPF support (downloads vmlinux.h if not cached)
cargo build --features ebpf

# Verify eBPF program loads and runs (requires root)
sudo cargo run --features ebpf

# Cross-compile for different architecture
cargo build --target aarch64-unknown-linux-gnu --features ebpf
```

## Best Practices

1. **Use CO-RE**: The full vmlinux.h works with CO-RE (Compile Once, Run Everywhere) for kernel portability
2. **Test across kernels**: Verify your program works on different kernel versions
3. **Trust the cache**: The downloaded headers are cached - you won't re-download on every build
4. **Cross-compilation**: The build process automatically downloads the correct arch-specific header

## Troubleshooting

### Compilation Errors

- **Missing struct definition**: Add the struct to your minimal header
- **Missing field**: Include the specific field in your struct definition
- **Type errors**: Ensure all referenced types are defined

### Runtime Errors

- **BTF verification failed**: Check that field names match kernel structures
- **Access violations**: Ensure you're accessing fields that exist in target kernel

### Field Access Issues

- **Wrong offset**: Make sure struct layout matches target kernel
- **Missing CO-RE relocations**: Verify preserve_access_index pragma is present

## Why Use Full vmlinux.h?

We chose the full vmlinux.h approach (downloaded at build time) because:

**Advantages:**
- **Architecture-specific**: Automatically downloads the correct header for x86, ARM64, ARM
- **Zero maintenance**: No need to manually update headers when adding eBPF features
- **Always complete**: Never missing kernel structure definitions
- **No git bloat**: The ~3-4MB header is cached in `target/` (gitignored), not committed
- **Fast builds**: Cached headers are reused across builds
- **crates.io ready**: No git dependencies blocking publication

**Why not minimal headers?**

The previous approach used a hand-crafted `vmlinux_min.h` (6.7KB). While smaller, it had a critical flaw:
- **Not architecture-specific**: Broke ARM64 builds due to architecture-dependent struct layouts
- Kernel structures have different layouts and sizes on different architectures
- A single minimal header can't work across x86_64, aarch64, and arm

By downloading architecture-specific full headers at build time, we ensure correct builds for all target platforms without git repository bloat.
