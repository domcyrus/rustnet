# musl Static Build Challenges

This document explains why RustNet currently does not provide musl static builds and the technical challenges encountered during implementation attempts.

## Background

musl is a lightweight C standard library designed for static linking. It would allow RustNet to produce fully static binaries that work on any Linux distribution regardless of GLIBC version.

## Why We Attempted musl Builds

GitHub issue #40 reported that pre-built packages required GLIBC 2.38/2.39, which wasn't available on PopOS 22.04 (GLIBC 2.35). musl builds would theoretically solve this by creating fully static binaries.

## Challenges Encountered

### libpcap Linking Issues

The primary challenge appears to be related to **libpcap** static linking with musl:

- Installing `libpcap-dev` in Ubuntu-based cross-rs containers provides glibc-linked libraries
- Attempting to statically link these with musl resulted in linker errors
- Errors included undefined references to pthread, math (exp), and dynamic loading functions (dladdr)

It's unclear whether this is due to:
- Fundamental glibc/musl incompatibility when statically linking
- Missing library specifications in the linker flags
- Issues with how cross-rs musl images are configured
- Something specific to our build configuration

### eBPF Complications

We initially attempted to include eBPF support, which required vendoring libelf and zlib. This was abandoned to simplify the problem, but even without eBPF the libpcap linking issues persisted.

## Current Solution

**We solved the original issue by pinning builds to ubuntu-22.04** (GLIBC 2.35), which ensures compatibility with PopOS 22.04 and similar distributions.

For users on older distributions, the `cargo install` workaround is documented:
```bash
cargo install rustnet-monitor
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' ~/.cargo/bin/rustnet
```

## Potential Future Approaches

If someone wants to tackle musl builds in the future, areas to investigate:

1. **Building libpcap from source** targeting musl in the pre-build step
2. **Using Alpine Linux-based images** which have native musl packages
3. **Custom linker flags** to properly link required libraries
4. **Alternative pure-Rust packet capture** libraries (if they exist)

We're uncertain which approach would work best, or if there are other issues we haven't discovered yet.

## Why We're Not Pursuing This Now

- The ubuntu-22.04 solution already addresses the reported issue
- The complexity-to-benefit ratio seems high
- `cargo install` provides a universal fallback for edge cases
- More investigation would be needed to understand the root causes

If you have experience with musl static linking and want to contribute, we'd welcome the help!

---

*Last updated: 2025-10-09*
*Status: Not currently pursuing due to linking complexity*
