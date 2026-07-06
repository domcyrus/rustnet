# Multi-stage Docker build for RustNet
# Base images are pinned by digest for reproducible, tamper-evident builds.
FROM rust:1.96-slim@sha256:31ee7fc65186be7e0e0ccb3f2ca305f14e4739e7642a1ae65753aa5d7b874523 AS builder

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

# Copy build script (manpage/completions; npcap on Windows)
COPY build.rs ./

# Copy source code
COPY src ./src
COPY benches ./benches
# Workspace member crates. rustnet-core holds the baked-in oui.gz / services
# assets (include_bytes!/include_str!); rustnet-host holds the eBPF programs and
# bundled vmlinux headers compiled by its own build.rs.
COPY crates ./crates

# Build the application in release mode (eBPF is enabled by default on Linux).
# Optional features can be added with --build-arg CARGO_FEATURES=kubernetes
# (additive: default features stay on). The CI Kubernetes image variant passes
# CARGO_FEATURES=kubernetes; the default image leaves it empty.
ARG CARGO_FEATURES=""
RUN if [ -n "$CARGO_FEATURES" ]; then \
        cargo build --release --features "$CARGO_FEATURES"; \
    else \
        cargo build --release; \
    fi

# Runtime stage - use trixie-slim to match GLIBC version from builder
# Pinned by digest for a reproducible, tamper-evident base image.
FROM debian:trixie-slim@sha256:28de0877c2189802884ccd20f15ee41c203573bd87bb6b883f5f46362d24c5c2

# Install runtime dependencies
# libcap2-bin provides setcap, used below to grant packet-capture capabilities
# to the binary so it can run as a non-root user.
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libelf1 \
    zlib1g \
    ca-certificates \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user. The container runs as this user (see USER below);
# packet-capture privileges are granted via file capabilities on the binary
# rather than by running as root.
RUN useradd -r -s /bin/false rustnet

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/target/release/rustnet /usr/local/bin/rustnet

# Copy the services asset for reference (the binary already embeds it at build time)
COPY --from=builder /app/crates/rustnet-core/assets/services ./assets/services

# Create logs directory
RUN mkdir -p /app/logs && chown rustnet:rustnet /app/logs

# Set executable permissions and grant CAP_NET_RAW as a file capability so the
# binary can capture packets as a non-root user. NET_RAW is in Docker's default
# capability bounding set, so `docker run rustnet` works without extra flags.
#
# Only NET_RAW is baked in on purpose: a file capability that is NOT also in the
# container's bounding set makes execve() fail with EPERM. BPF/PERFMON are not
# in Docker's default set, so eBPF is handled at runtime instead (see below).
RUN chmod +x /usr/local/bin/rustnet \
    && setcap 'cap_net_raw=ep' /usr/local/bin/rustnet

# Expose no ports by default (rustnet is for monitoring, not serving)
# Network access is handled via host networking or packet capture capabilities

# Add labels for better image metadata
LABEL org.opencontainers.image.title="RustNet"
LABEL org.opencontainers.image.description="A cross-platform network monitoring tool with deep packet inspection"
LABEL org.opencontainers.image.source="https://github.com/domcyrus/rustnet"
LABEL org.opencontainers.image.licenses="Apache License, Version 2.0"

# RustNet runs as the non-root 'rustnet' user. CAP_NET_RAW is baked into the
# binary as a file capability and is part of Docker's default bounding set, so
# basic packet capture works out of the box:
#   docker run rustnet
# eBPF-based process attribution needs BPF+PERFMON, which are NOT in the default
# bounding set and can't be granted to a non-root user via file capabilities.
# Enable eBPF by running as root with the extra caps (modern kernels 5.8+):
#   docker run --user root --cap-add=BPF --cap-add=PERFMON rustnet
# Legacy kernels require broad CAP_SYS_ADMIN for eBPF. RustNet does not
# recommend granting it by default; without eBPF caps, rustnet falls back to
# /proc-based process detection.
# CAP_NET_ADMIN is NOT required (read-only, non-promiscuous capture).
USER rustnet
ENTRYPOINT ["rustnet"]
