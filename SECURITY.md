# Security

RustNet processes untrusted network data, making defense-in-depth security critical. This document describes the security measures implemented.

## Table of Contents

- [Landlock Sandboxing (Linux)](#landlock-sandboxing-linux)
- [Privilege Requirements](#privilege-requirements)
- [Read-Only Operation](#read-only-operation)
- [No External Communication](#no-external-communication)
- [Log File Privacy](#log-file-privacy)
- [eBPF Security](#ebpf-security)
- [Threat Model](#threat-model)
- [Audit and Compliance](#audit-and-compliance)
- [Reporting Security Issues](#reporting-security-issues)

## Landlock Sandboxing (Linux)

On Linux 5.13+, RustNet uses [Landlock](https://landlock.io/) to restrict its own capabilities after initialization. This limits the damage if a vulnerability in packet parsing is exploited.

### What Gets Restricted

| Restriction | Kernel Version | Description |
|-------------|----------------|-------------|
| Filesystem | 5.13+ | Only `/proc` readable (for process identification) |
| Network | 6.4+ | TCP bind/connect blocked (RustNet is passive) |
| Capabilities | Any | `CAP_NET_RAW` dropped after pcap socket opened |

### How It Works

1. **Initialization phase**: RustNet loads eBPF programs, opens packet capture handles, and creates log files
2. **Sandbox application**: After init, Landlock restricts filesystem and network access
3. **Capability drop**: `CAP_NET_RAW` is removed from the process (existing pcap socket remains valid)

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot read arbitrary files (credentials, configs, etc.)
- Cannot write to filesystem (except configured log paths)
- Cannot make outbound TCP connections (data exfiltration blocked)
- Cannot bind TCP ports (reverse shell blocked)
- Cannot create new raw sockets (capability dropped)

### CLI Options

```
--no-sandbox        Disable Landlock sandboxing
--sandbox-strict    Require full sandbox enforcement or exit
```

### Graceful Degradation

- **Kernel < 5.13**: Sandboxing skipped, warning logged
- **Kernel 5.13-6.3**: Filesystem restrictions only
- **Kernel 6.4+**: Full filesystem + network restrictions
- **Docker**: May be blocked by seccomp; app continues normally

## Privilege Requirements

RustNet requires privileged access for packet capture:

| Platform | Requirement |
|----------|-------------|
| Linux | `CAP_NET_RAW` capability or root |
| macOS | Root or BPF group membership (`access_bpf` group) |
| Windows | Administrator (for Npcap) |
| FreeBSD | Root or BPF device access |

### Why Privileges Are Needed

- **Raw socket access** - Intercept network traffic at low level (read-only, non-promiscuous mode)
- **BPF device access** - Load packet filters into kernel
- **eBPF programs** - Optional kernel probes for enhanced process tracking (Linux only)

### Recommended: Capability-based Execution (Linux)

Instead of running as root, grant only the required capabilities:

```bash
# Modern Linux (5.8+): packet capture + eBPF
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' $(which rustnet)

# Legacy Linux (pre-5.8): packet capture + eBPF
sudo setcap 'cap_net_raw,cap_sys_admin=eip' $(which rustnet)

# Packet capture only (no eBPF process detection)
sudo setcap cap_net_raw=eip $(which rustnet)
```

After sandbox application, `CAP_NET_RAW` is dropped - the process retains only the minimum privileges needed.

## Read-Only Operation

RustNet only monitors traffic; it does not:
- Modify packets
- Block connections
- Inject traffic
- Alter routing tables
- Change firewall rules

The packet capture is opened in non-promiscuous, read-only mode.

## No External Communication

RustNet operates entirely locally:
- No telemetry or analytics
- No network requests (except monitored traffic)
- No cloud services or remote APIs
- All data stays on your system

## Log File Privacy

Log files may contain sensitive information:
- IP addresses and ports
- Hostnames and SNI data
- Process names and PIDs
- DNS queries and responses

**Best Practices:**
- Disable logging by default (no `--log-level` flag)
- Secure log directory permissions
- Implement log rotation and retention policies
- Review logs for sensitive data before sharing

## eBPF Security

When using eBPF for enhanced process detection (default on Linux):

- Requires additional kernel capabilities (`CAP_BPF`, `CAP_PERFMON`)
- eBPF programs are verified by kernel before loading
- Limited to read-only operations (no packet modification)
- Automatically falls back to procfs if eBPF fails

## Threat Model

**What RustNet protects against:**
- Unauthorized users cannot capture packets without proper permissions
- Capability-based permissions limit blast radius of compromise
- Landlock sandbox contains potential exploitation

**What RustNet does NOT protect against:**
- Users with packet capture permissions can see all unencrypted traffic
- Root/Administrator users can modify RustNet or capture packets directly
- Physical access to the machine enables packet capture
- Network-level attacks (RustNet is a monitoring tool, not a security appliance)

## Audit and Compliance

For production environments:
- **Audit logging** of who runs RustNet with packet capture privileges
- **Network monitoring policies** and compliance with data protection regulations
- **User access reviews** for privileged network access
- **Automated capability management** via configuration management systems

## Reporting Security Issues

Please report security vulnerabilities via GitHub Issues or contact the maintainers directly.
