# Multi-stage Docker build for RustNet
# Base images are pinned by digest for reproducible, tamper-evident builds.
FROM rust:1.96-slim@sha256:082a5849a6870672b5f7a5bf4eddc71723fce38756fd834a0d734a5306a310ab AS builder

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

# Build the application in release mode (eBPF is enabled by default on Linux)
RUN cargo build --release

# Runtime stage - use trixie-slim to match GLIBC version from builder
# Pinned by digest for a reproducible, tamper-evident base image.
FROM debian:trixie-slim@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e

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
# Older kernels use CAP_SYS_ADMIN instead of BPF+PERFMON:
#   docker run --user root --cap-add=SYS_ADMIN rustnet
# Without those, rustnet falls back to /proc-based process detection.
# CAP_NET_ADMIN is NOT required (read-only, non-promiscuous capture).
USER rustnet
ENTRYPOINT ["rustnet"]
