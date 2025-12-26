# musl Static Build Guide

This document explains how to build fully static RustNet binaries using musl.

## Quick Start

```bash
# Build static binary with eBPF support (default, ~6.5MB)
docker build -f Dockerfile.static -t rustnet-static .

# Or build without eBPF (smaller, ~5.2MB)
docker build -f Dockerfile.static --build-arg FEATURES="--no-default-features" -t rustnet-static .

# Extract the binary
mkdir -p dist
docker run --rm -v $(pwd)/dist:/out rustnet-static cp /build/target/release/rustnet /out/

# Verify it's static
file dist/rustnet
# Output: ELF 64-bit LSB pie executable, x86-64, ..., static-pie linked

ldd dist/rustnet
# Output: statically linked
```

## Binary Characteristics

| Build | Size | eBPF | Process Detection | Compatibility |
|-------|------|------|-------------------|---------------|
| With eBPF | ~6.5MB | Yes | eBPF + procfs fallback | Any Linux |
| Without eBPF | ~5.2MB | No | procfs only | Any Linux |

## How It Works

The `Dockerfile.static` uses `rust:alpine` which provides:
- Native musl toolchain (no glibc/musl mixing issues)
- `libpcap-dev` package with static library (`/usr/lib/libpcap.a`)
- `elfutils-dev` with static libelf for eBPF
- All dependencies compiled against musl

### The zstd Fix

Alpine's elfutils 0.189+ has an undeclared dependency on zstd for ELF section compression. The Dockerfile includes a workaround:

```toml
# .cargo/config.toml
[target.x86_64-unknown-linux-musl]
rustflags = ["-C", "link-arg=-l:libzstd.a"]
```

This explicitly links the static zstd library, fixing the link order issue. See [libbpf/bpftool#152](https://github.com/libbpf/bpftool/issues/152) for details.

## Running the Static Binary

```bash
# Set capabilities for packet capture
sudo setcap 'cap_net_raw=eip' dist/rustnet

# For eBPF support (Linux 5.8+)
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' dist/rustnet

# Run
./dist/rustnet
```

## CI Integration

For GitHub Actions, use the native container approach (faster than Docker build):

```yaml
build-static:
  name: build-static-musl
  runs-on: ubuntu-latest
  container:
    image: rust:alpine
  steps:
    - uses: actions/checkout@v6

    - name: Install dependencies
      run: |
        apk add --no-cache \
          musl-dev libpcap-dev pkgconfig build-base perl \
          elfutils-dev zlib-dev zlib-static zstd-dev zstd-static \
          clang llvm linux-headers git
        rustup component add rustfmt

    - name: Configure static zstd linking
      run: |
        mkdir -p .cargo
        printf '[target.x86_64-unknown-linux-musl]\nrustflags = ["-C", "link-arg=-l:libzstd.a"]\n' > .cargo/config.toml

    - name: Build
      run: cargo build --release

    - name: Verify static linking
      run: |
        file target/release/rustnet
        ldd target/release/rustnet 2>&1 | grep -q "statically linked"
```

## Historical Context

### Previous Challenges (Resolved)

Earlier attempts using cross-rs with Ubuntu-based containers failed:
- Installing `libpcap-dev` in Ubuntu provides glibc-linked libraries
- Mixing glibc libraries with musl linking caused undefined references
- Errors included pthread, math (exp), and dladdr symbols

### Why Alpine Works

Alpine Linux uses musl as its system C library:
- All packages are compiled against musl
- Static libraries (`*.a`) are musl-compatible
- No glibc/musl mixing occurs

### The eBPF Challenge (Resolved)

Static eBPF builds initially failed due to elfutils → zstd dependency chain:
- elfutils 0.189+ added ZSTD compression for ELF sections
- libbpf-sys didn't propagate the zstd link dependency
- Fixed by explicitly linking `-l:libzstd.a` via cargo config

## References

- [libbpf/bpftool#152](https://github.com/libbpf/bpftool/issues/152) - zstd link fix
- [arachsys/libelf](https://github.com/arachsys/libelf) - Standalone libelf (alternative)
- [Alpine Static Linking](https://build-your-own.org/blog/20221229_alpine/) - General guidance

---

*Last updated: 2025-12-26*
*Status: Fully working with eBPF support*
