# eBPF Build Guide

This document explains how to work with eBPF kernel headers in this project.

## Current Setup

We use a **minimal vmlinux header** (`vmlinux_min.h`) instead of the full kernel headers. This approach has trade-offs that should be considered:

**Benefits of minimal vmlinux_min.h:**

- **Small size**: 5.5KB (203 lines) vs 3.4MB (100K+ lines) full vmlinux.h
- **Git-friendly**: Small file size, manageable diffs, easier to review
- **Portable**: Works across kernel versions with CO-RE/BTF
- **Clear dependencies**: Shows exactly which kernel structures we depend on

**Drawbacks of minimal vmlinux_min.h:**

- **Manual maintenance**: Need to update when adding new eBPF features that access different kernel structures
- **Potential for missing definitions**: Easy to forget required types when extending functionality
- **Development overhead**: Requires understanding of kernel internals to extract correct definitions

**Alternative approach (full vmlinux.h):**

- **Pros**: Complete kernel definitions, auto-generated, no manual maintenance, never missing types
- **Cons**: Very large file (3.4MB), but can be gitignored and generated during build process

## How to Generate Full vmlinux.h (if needed)

If you need to generate a complete vmlinux.h file for your kernel:

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

## Testing Your Minimal Header

After creating your minimal header:

```bash
# Test compilation
cargo build --features ebpf

# If compilation fails, check for missing definitions
# and add them to your minimal header

# Verify eBPF program loads
# Option 1: Run with sudo (always works)
sudo cargo run --features ebpf

# Option 2: Set capabilities (Linux only, see README.md Permissions section)
sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon+eip' ./target/debug/rustnet
cargo run --features ebpf

# Check the TUI Statistics panel to verify it shows "Process Detection: eBPF + procfs"
```

**Note**: eBPF kprobe programs require specific Linux capabilities. See the main [README.md Permissions section](README.md#permissions) for detailed capability requirements. The required capabilities may vary by kernel version.

## Best Practices

1. **Start minimal**: Only include structures and fields you actually access
2. **Use CO-RE**: Always include the preserve_access_index pragma for portability
3. **Document sources**: Note which kernel version/source your definitions came from
4. **Test across kernels**: Verify your program works on different kernel versions
5. **Keep synchronized**: Update minimal headers when your eBPF program changes

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

## Why Not Use Full vmlinux.h?

While using the full vmlinux.h works, it has downsides:

- **Huge file size** (3+ MB): Slows down compilation and git operations
- **Unclear dependencies**: Hard to see what your program actually needs
- **Kernel-specific**: Generated for one specific kernel version
- **Review complexity**: Impossible to review 100K+ lines in PRs

The minimal approach gives you the benefits of vmlinux.h (CO-RE support, exact field layouts) without the downsides.
