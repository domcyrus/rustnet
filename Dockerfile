# Multi-stage Docker build for RustNet
FROM rust:1.89-slim AS builder

# Install rustfmt component (required for eBPF compilation)
RUN rustup component add rustfmt

# Install build dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libelf-dev \
    zlib1g-dev \
    clang \
    llvm \
    make \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy build script for eBPF compilation
COPY build.rs ./

# Copy bundled eBPF vmlinux headers (required for eBPF compilation)
COPY resources/ebpf/vmlinux ./resources/ebpf/vmlinux

# Copy source code
COPY src ./src
COPY assets/services ./assets/services

# Build the application in release mode (eBPF is enabled by default on Linux)
RUN cargo build --release

# Runtime stage - use trixie-slim to match GLIBC version from builder
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libelf1 \
    zlib1g \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for general security practices
# Note: While this follows Docker security best practices, RustNet requires elevated
# privileges for packet capture (NET_RAW/NET_ADMIN capabilities or root access).
# The container will need to be run with --cap-add=NET_RAW --cap-add=NET_ADMIN
# or --privileged flag to function properly for network monitoring.
RUN useradd -r -s /bin/false rustnet

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rustnet /usr/local/bin/rustnet

# Copy assets/services only
COPY --from=builder /app/assets/services ./assets/services

# Create logs directory
RUN mkdir -p /app/logs && chown rustnet:rustnet /app/logs

# Set executable permissions
RUN chmod +x /usr/local/bin/rustnet

# Expose no ports by default (rustnet is for monitoring, not serving)
# Network access is handled via host networking or packet capture capabilities

# Add labels for better image metadata
LABEL org.opencontainers.image.title="RustNet"
LABEL org.opencontainers.image.description="A cross-platform network monitoring tool with deep packet inspection"
LABEL org.opencontainers.image.source="https://github.com/domcyrus/rustnet"
LABEL org.opencontainers.image.licenses="Apache License, Version 2.0"

# Important: RustNet requires elevated privileges for packet capture and eBPF functionality
# Modern kernels (5.8+): docker run --cap-add=NET_RAW --cap-add=BPF --cap-add=PERFMON rustnet
# Legacy kernels: docker run --cap-add=NET_RAW --cap-add=SYS_ADMIN rustnet
# Or with: docker run --privileged rustnet
# Note: CAP_NET_ADMIN is NOT required (uses read-only, non-promiscuous packet capture)
ENTRYPOINT ["rustnet"]
