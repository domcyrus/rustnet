# Architecture

This document describes the technical architecture and implementation details of RustNet.

## Table of Contents

- [Multi-threaded Architecture](#multi-threaded-architecture)
- [Key Components](#key-components)
- [Platform-Specific Implementations](#platform-specific-implementations)
- [Performance Considerations](#performance-considerations)
- [Dependencies](#dependencies)
- [Security](#security)

## Multi-threaded Architecture

RustNet uses a multi-threaded architecture for efficient packet processing:

```
┌─────────────────┐
│ Packet Capture  │ ──packets──> Crossbeam Channel
│   (libpcap)     │                      │
└─────────────────┘                      │
                                         ├──> ┌──────────────────┐
                                         ├──> │ Packet Processor │ ──> DashMap
                                         ├──> │    (Thread 0)    │      │
                                         └──> │    (Thread N)    │      │
                                              └──────────────────┘      │
                                                                        │
┌─────────────────┐                                                     │
│Process Enrichment│ ────────────────────────────────────────────> DashMap
│  (Platform API) │                                                     │
└─────────────────┘                                                     │
                                                                        │
┌─────────────────┐                                                     │
│Snapshot Provider│ <─────────────────────────────────────────── DashMap
└─────────────────┘                                                     │
         │                                                              │
         └──> RwLock<Vec<Connection>> (for UI)                          │
                                                                        │
┌─────────────────┐                                                     │
│ Cleanup Thread  │ <─────────────────────────────────────────── DashMap
└─────────────────┘
```

## Key Components

### 1. Packet Capture Thread

Uses libpcap to capture raw packets from the network interface. This thread runs independently and feeds packets into a Crossbeam channel for processing.

**Responsibilities:**
- Open network interface for packet capture (non-promiscuous, read-only mode)
- Apply BPF filters if needed
- Capture raw packets
- Send packets to processing queue

### 2. Packet Processors

Multiple worker threads (up to 4 by default, based on CPU cores) that parse packets and perform Deep Packet Inspection (DPI) analysis.

**Responsibilities:**
- Parse Ethernet, IP, TCP, UDP, ICMP, ARP headers
- Extract connection 5-tuple (protocol, src IP, src port, dst IP, dst port)
- Perform DPI to detect application protocols:
  - HTTP with host information
  - HTTPS/TLS with SNI (Server Name Indication)
  - DNS queries and responses
  - SSH connections with version detection
  - QUIC protocol with CONNECTION_CLOSE frame detection
- Track connection states and lifecycle
- Update connection metadata in DashMap
- Calculate bandwidth metrics

### 3. Process Enrichment

Platform-specific APIs to associate network connections with running processes. This component runs periodically to enrich connection data with process information.

**Responsibilities:**
- Map socket inodes to process IDs
- Resolve process names and command lines
- Update connection records with process information
- Handle permission-related fallbacks

See [Platform-Specific Implementations](#platform-specific-implementations) for details on each platform.

### 4. Snapshot Provider

Creates consistent snapshots of connection data for the UI at regular intervals (default: 1 second). This ensures the UI has a stable view of connections without race conditions.

**Responsibilities:**
- Read from DashMap at configured intervals
- Apply filtering based on user criteria (localhost, etc.)
- Sort connections based on user-selected column
- Create immutable snapshot for UI rendering
- Provide RwLock-protected Vec<Connection> for UI thread

### 5. Cleanup Thread

Removes inactive connections using smart, protocol-aware timeouts. This prevents memory leaks and keeps the connection list relevant.

**Timeout Strategy:**

#### TCP Connections
- **HTTP/HTTPS** (detected via DPI): **10 minutes** - supports HTTP keep-alive
- **SSH** (detected via DPI): **30 minutes** - accommodates long interactive sessions
- **Active established** (< 1 min idle): **10 minutes**
- **Idle established** (> 1 min idle): **5 minutes**
- **TIME_WAIT**: 30 seconds - standard TCP timeout
- **CLOSED**: 5 seconds - rapid cleanup
- **SYN_SENT, FIN_WAIT, etc.**: 30-60 seconds

#### UDP Connections
- **HTTP/3 (QUIC with HTTP)**: **10 minutes** - connection reuse
- **HTTPS/3 (QUIC with HTTPS)**: **10 minutes** - connection reuse
- **SSH over UDP**: **30 minutes** - long-lived sessions
- **DNS**: **30 seconds** - short-lived queries
- **Regular UDP**: **60 seconds** - standard timeout

#### QUIC Connections (Detected State)
- **Connected (active)** (< 1 min idle): **10 minutes**
- **Connected (idle)** (> 1 min idle): **5 minutes**
- **With CONNECTION_CLOSE frame**: 1-10 seconds (based on close type)
- **Initial/Handshaking**: 60 seconds - allow connection establishment
- **Draining**: 10 seconds - RFC 9000 draining period

**Visual Staleness Indicators:**

Connections change color based on proximity to timeout:
- **White** (default): < 75% of timeout
- **Yellow**: 75-90% of timeout (warning)
- **Red**: > 90% of timeout (critical)

### 6. Rate Refresh Thread

Updates bandwidth calculations every second with gentle decay. This provides smooth bandwidth visualization without abrupt changes.

**Responsibilities:**
- Calculate bytes/second for download and upload
- Apply exponential decay to older measurements
- Update visual bandwidth indicators
- Maintain rolling window of packet rates

### 7. DashMap

Concurrent hashmap (`DashMap<ConnectionKey, Connection>`) for storing connection state. This lock-free data structure enables efficient concurrent access from multiple threads.

**Key Features:**
- Fine-grained locking (per-shard)
- No global lock contention
- Safe concurrent reads and writes
- High performance under concurrent load

## Platform-Specific Implementations

### Process Lookup

RustNet uses platform-specific APIs to associate network connections with processes:

#### Linux

**Standard Mode (procfs):**
- Parses `/proc/net/tcp` and `/proc/net/udp` to get socket inodes
- Iterates through `/proc/<pid>/fd/` to find socket file descriptors
- Maps inodes to process IDs and resolves process names from `/proc/<pid>/cmdline`

**eBPF Mode (Default on Linux):**
- Uses kernel eBPF programs attached to socket syscalls
- Captures socket creation events with process context
- Provides lower overhead than procfs scanning
- **Limitations:**
  - Process names limited to 16 characters (kernel `comm` field)
  - May show thread names instead of full executable names
  - Multi-threaded applications show internal thread names
- **Capability requirements:**
  - Modern Linux (5.8+): `CAP_NET_RAW` (packet capture), `CAP_BPF`, `CAP_PERFMON` (eBPF)
  - Legacy Linux (pre-5.8): `CAP_NET_RAW` (packet capture), `CAP_SYS_ADMIN` (eBPF)
  - Note: CAP_NET_ADMIN is NOT required (uses read-only, non-promiscuous packet capture)

**Fallback Behavior:**
- If eBPF fails to load (permissions, kernel compatibility), automatically falls back to procfs mode
- TUI Statistics panel shows active detection method

#### macOS

**PKTAP Mode (with sudo):**
- Uses PKTAP (Packet Tap) kernel interface
- Extracts process information directly from packet metadata
- Requires root privileges (privileged kernel interface)
- Faster and more accurate than lsof

**lsof Mode (without sudo or fallback):**
- Uses `lsof -i -n -P` to list network connections
- Parses output to associate sockets with processes
- Higher CPU overhead but works without root
- Used automatically when PKTAP is unavailable

**Detection:**
- TUI Statistics panel shows "pktap" or "lsof" based on active method
- Automatically selects best available method

#### Windows

**IP Helper API:**
- Uses `GetExtendedTcpTable` and `GetExtendedUdpTable` from Windows IP Helper API
- Retrieves connection tables with process IDs
- Supports both IPv4 and IPv6 connections
- Resolves process names using `OpenProcess` and `QueryFullProcessImageNameW`

**Requirements:**
- May require Administrator privileges depending on system configuration
- Requires Npcap or WinPcap for packet capture

### Network Interfaces

The tool automatically detects and lists available network interfaces using platform-specific methods:

- **Linux**: Uses `netlink` or falls back to `/sys/class/net/`
- **macOS**: Uses `getifaddrs()` system call
- **Windows**: Uses `GetAdaptersInfo()` from IP Helper API
- **All platforms**: Falls back to pcap's `pcap_findalldevs()` when native methods fail

## Performance Considerations

### Multi-threaded Processing

Packet processing is distributed across multiple threads (up to 4 by default, based on CPU cores). This enables:
- Parallel packet parsing and DPI analysis
- Better utilization of multi-core systems
- Reduced latency for high packet rates

### Concurrent Data Structures

**DashMap** provides lock-free concurrent access with:
- Per-shard locking (16 shards by default)
- No global lock contention
- Read-heavy workload optimization
- Safe concurrent modifications

### Batch Processing

Packets are processed in batches to improve cache efficiency:
- Multiple packets processed before context switching
- Reduced system call overhead
- Better CPU cache utilization

### Selective DPI

Deep packet inspection can be disabled with `--no-dpi` for lower overhead:
- Reduces CPU usage by 20-40% on high-traffic networks
- Still tracks basic connection information
- Useful for performance-constrained environments

### Configurable Intervals

Adjust refresh rates based on your needs:
- **UI refresh**: Default 1000ms (adjustable with `--refresh-interval`)
- **Process enrichment**: Every 2 seconds
- **Cleanup check**: Every 5 seconds
- **Rate calculation**: Every 1 second

### Memory Management

**Connection cleanup** prevents unbounded memory growth:
- Protocol-aware timeouts remove stale connections
- Visual staleness warnings before removal
- Configurable timeout thresholds

**Snapshot isolation** prevents UI blocking:
- UI reads from immutable snapshots
- Background threads update DashMap concurrently
- No lock contention between UI and packet processing

## Dependencies

RustNet is built with the following key dependencies:

### Core Dependencies

- **ratatui** - Terminal user interface framework with full widget support
- **crossterm** - Cross-platform terminal manipulation
- **pcap** - Packet capture library bindings for libpcap/Npcap
- **pnet_datalink** - Network interface enumeration and low-level networking

### Concurrency & Threading

- **dashmap** - Concurrent hashmap with fine-grained locking
- **crossbeam** - Multi-threading utilities and lock-free channels
- **parking_lot** - Efficient synchronization primitives (RwLock, Mutex)

### Networking & Protocols

- **dns-lookup** - DNS resolution capabilities
- **etherparse** - Ethernet, IP, TCP, UDP packet parsing
- **trust-dns-proto** - DNS protocol parsing (for DPI)

### Command-line & Logging

- **clap** - Command-line argument parsing with derive features
- **simplelog** - Flexible logging framework
- **log** - Logging facade
- **anyhow** - Error handling and context

### Platform-Specific

- **procfs** (Linux) - Process information from /proc filesystem (runtime fallback)
- **libbpf-rs** (Linux) - eBPF program loading and management
- **libbpf-sys** (Linux) - Low-level libbpf bindings for eBPF
- **windows-sys** (Windows) - Windows API bindings for IP Helper API

### Utilities

- **arboard** - Clipboard access for copying addresses
- **num_cpus** - CPU core detection for threading
- **chrono** - Date and time handling
- **ring** - Cryptographic operations (for TLS/SNI parsing)
- **aes** - AES encryption support (for protocol detection)

## Security

For security documentation including Landlock sandboxing, privilege requirements, and threat model, see [SECURITY.md](SECURITY.md).
