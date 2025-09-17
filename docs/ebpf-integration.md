# eBPF Socket Tracking Integration

## Overview

This document describes the eBPF socket tracking integration added to rustnet for enhanced process enrichment on Linux systems.

## Architecture

### Components

1. **eBPF Program** (`src/network/platform/linux_ebpf/programs/socket_tracker.c`)
   - Kernel-space eBPF program that hooks into socket operations
   - Tracks TCP connect, accept, UDP sendmsg, and socket close events
   - Stores process information in eBPF maps for userspace retrieval

2. **eBPF Loader** (`src/network/platform/linux_ebpf/loader.rs`)
   - Loads and attaches eBPF programs using the Aya framework
   - Handles capability checking and graceful failure
   - Manages kprobe attachments to kernel functions

3. **Map Interface** (`src/network/platform/linux_ebpf/maps.rs`)
   - Provides safe Rust interface to eBPF maps
   - Handles data structure conversion between C and Rust
   - Implements connection key matching

4. **Enhanced Process Lookup** (`src/network/platform/linux_enhanced.rs`)
   - Combines eBPF (fast path) with procfs (fallback)
   - Provides unified caching and statistics
   - Gracefully degrades when eBPF is unavailable

### Fallback Strategy

The implementation uses a layered approach:

1. **eBPF Fast Path**: For TCP/UDP connections, try eBPF lookup first
2. **procfs Fallback**: If eBPF fails or for other protocols (ICMP, ARP)
3. **Unified Caching**: Results from both sources are cached together

## Usage

### Building with eBPF Support

```bash
# Build with eBPF feature enabled
cargo build --features ebpf

# Build without eBPF (procfs only)
cargo build
```

### Runtime Requirements

- **For eBPF**: Requires root privileges or CAP_BPF/CAP_SYS_ADMIN capabilities
- **For procfs**: Works with regular user privileges

### Feature Detection

The system automatically detects eBPF availability at runtime:

```rust
let lookup = create_process_lookup_with_pktap_status(false)?;
// Will use enhanced lookup if possible, fall back to procfs-only
```

## Protocol Support

| Protocol | eBPF Support | procfs Support | Notes |
|----------|--------------|----------------|-------|
| TCP IPv4 | ✅           | ✅            | eBPF provides faster lookups |
| TCP IPv6 | ✅           | ✅            | Full IPv6 support added |
| UDP IPv4 | ✅           | ✅            | eBPF tracks sendmsg events |
| UDP IPv6 | ✅           | ✅            | Full IPv6 support added |
| ICMP     | ❌           | ✅            | eBPF doesn't handle ICMP |
| ARP      | ❌           | ✅            | eBPF doesn't handle ARP |

## Performance

The enhanced lookup provides several performance benefits:

- **Reduced procfs parsing**: eBPF eliminates need to parse `/proc/net/*` files for TCP/UDP
- **Real-time tracking**: eBPF captures connections as they're created
- **Lower CPU usage**: Less file system I/O and string parsing
- **Unified caching**: Single cache for all lookup sources

## Testing

### Unit Tests
- Basic functionality tests for all components
- Fallback behavior verification
- Cache and statistics testing

### Integration Tests
- Cross-compilation verification
- Feature flag testing
- Runtime capability detection

### Manual Testing

```bash
# Test with eBPF enabled (requires root)
sudo cargo test --features ebpf

# Test fallback behavior
cargo test

# Run rustnet with eBPF
sudo cargo run --features ebpf
```

## Limitations

1. **Privilege Requirements**: eBPF requires elevated privileges
2. **Kernel Version**: Requires modern Linux kernel with eBPF support
3. **Kernel Headers**: Requires kernel headers and BPF development tools (clang, llvm-strip)
4. **TCP/UDP Only**: eBPF doesn't track ICMP, ARP, or other protocols
5. **Kernel Structure Dependencies**: eBPF program depends on internal kernel structures which may vary between versions

## Enhanced Monitoring and Statistics

The eBPF integration now includes comprehensive statistics tracking:

- **Lookup Performance**: Cache hit rates, eBPF vs procfs usage
- **Protocol Breakdown**: IPv4/IPv6 and TCP/UDP connection counts  
- **Success Rates**: Failed lookup tracking
- **Cache Metrics**: Active cache entries and efficiency
- **Real-time Status**: eBPF availability and health monitoring

Access statistics via the `get_stats()` method on the enhanced lookup provider.

## Build Requirements

### Fedora/RHEL/CentOS
```bash
sudo dnf install clang llvm kernel-headers libbpf-devel
```

### Ubuntu/Debian  
```bash
sudo apt install clang llvm linux-headers-$(uname -r) libbpf-dev
```

## Future Enhancements

1. **Kernel Structure Compatibility**: Better handling of kernel version differences
2. **Additional Protocols**: Add support for other protocols in eBPF
3. **Connection State**: Track more detailed connection state information
4. **Security Context**: Capture additional process security information
5. **Performance Optimization**: Further reduce overhead and improve caching

## Security Considerations

- eBPF programs run in kernel space with restricted access
- Use of `bpf_probe_read_kernel()` for safe memory access
- Dual BSD/GPL license compatible with Apache 2.0 userspace code
- Graceful degradation ensures no security exposure on failure

## Dependencies

- `aya`: Pure Rust eBPF framework
- `aya-build`: Build-time eBPF compilation
- `bytes`: Efficient data handling
- `libc`: System call interfaces

All dependencies are optional and only included with the `ebpf` feature flag.