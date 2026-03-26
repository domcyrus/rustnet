# Security

RustNet processes untrusted network data, making defense-in-depth security critical. This document describes the security measures implemented.

## Table of Contents

- [Landlock Sandboxing (Linux)](#landlock-sandboxing-linux)
- [Seatbelt Sandboxing (macOS)](#seatbelt-sandboxing-macos)
- [Capsicum Sandboxing (FreeBSD)](#capsicum-sandboxing-freebsd)
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

## Seatbelt Sandboxing (macOS)

On macOS 10.5+, RustNet uses [Seatbelt](https://theapplewiki.com/wiki/Dev:Seatbelt) (`sandbox_init_with_parameters`) to restrict its own capabilities after initialization. This limits the damage if a vulnerability in packet parsing is exploited.

### What Gets Restricted

| Restriction | Description |
|-------------|-------------|
| Outbound network | TCP/UDP outbound blocked; Unix sockets (Mach IPC) allowed |
| Filesystem writes | All user home directories blocked (`/Users`, `/var/root`) |
| Filesystem writes | Only configured log and PCAP export paths writable |

### How It Works

1. **Initialization phase**: RustNet opens packet capture handles (BPF/PKTAP) and creates log files
2. **Pre-create**: PCAP sidecar file (`.connections.jsonl`) is created before the sandbox so its path is already a valid allow target
3. **Sandbox application**: `sandbox_init_with_parameters` is called — already-open file descriptors survive unchanged, only future operations are restricted

### Profile Strategy

RustNet uses an **allow-default** SBPL profile with targeted denies. A deny-default profile would require explicitly whitelisting all system libraries, Mach ports, locale data, fonts, and other OS internals — fragile and error-prone. Allow-default covers the primary threats (outbound exfiltration, credential theft) without operational risk.

### Output File Support

`--json-log` and `--pcap-export` paths are passed to the SBPL profile as runtime parameters (`JSON_LOG_PATH`, `PCAP_PATH`, `PCAP_JSONL_PATH`). The profile grants an explicit `allow file-write*` rule on each path, which takes precedence over the broader `/Users` deny rule via SBPL specificity. Unused parameters default to `/dev/null`.

Both flags work normally within the sandbox.

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot write to SSH keys, AWS credentials, browser profiles, or other credential files
- Cannot make outbound TCP/UDP connections (data exfiltration blocked)
- Cannot open new raw network sockets

### CLI Options

```
--no-sandbox        Disable Seatbelt sandboxing
--sandbox-strict    Require full sandbox enforcement or exit
```

### Why BestEffort is Default

`sandbox_init_with_parameters` is a private (undocumented) macOS API. It has been stable since macOS 10.5 and is used by Chromium, Firefox, and Safari for process sandboxing, but it could theoretically change without notice. BestEffort degrades gracefully if the API behaves unexpectedly rather than preventing the app from running. Use `--sandbox-strict` to require sandboxing or abort.

### Clipboard Behavior

Unlike Linux Landlock, clipboard copy (`c` key) works normally under Seatbelt. macOS clipboard uses NSPasteboard, which communicates via Mach IPC over Unix domain sockets — the SBPL profile explicitly allows `(network-outbound (remote unix-socket))`.

On Linux, clipboard requires access to Wayland sockets (`/run/user/UID/wayland-0`) or X11 sockets (`/tmp/.X11-unix/`). Landlock's deny-default model blocks these because they are not in the write-path allowlist, so clipboard is unavailable when Landlock is active.

## Capsicum Sandboxing (FreeBSD)

On FreeBSD, RustNet uses [Capsicum](https://wiki.freebsd.org/Capsicum) to restrict file descriptor capabilities after initialization. This limits the damage if a vulnerability in packet parsing is exploited.

### What Gets Restricted

| Restriction | Description |
|-------------|-------------|
| Output FDs | Log and PCAP export file descriptors restricted to write-only |
| Read prevention | Output FDs cannot be repurposed for reading sensitive data |

### How It Works

1. **Initialization phase**: RustNet opens packet capture handles, creates log files, and starts the process lookup subsystem
2. **FD restriction**: `cap_rights_limit()` restricts each output file FD to write/seek/fstat only
3. **Runtime**: Process identification via `sockstat` subprocess continues working (not affected by per-FD restrictions)

### Why cap_rights_limit Instead of cap_enter

RustNet on FreeBSD uses `sockstat` subprocess calls for process-to-connection mapping. `cap_enter()` would block `fork()`/`execve()`, breaking this functionality. Using `cap_rights_limit()` on individual FDs provides meaningful hardening without disrupting runtime behavior.

> **Known limitation:** Without `cap_enter()`, a compromised process can still `open()` new files, `socket()` new connections, and `execve()` arbitrary programs. The per-FD restrictions only prevent misuse of the *specific restricted FDs*. A future improvement is to switch from the `sockstat` subprocess to `libprocstat(3)` library calls, which would eliminate the fork/exec dependency and allow full capability mode via `cap_enter()`.

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot repurpose output file descriptors to read sensitive data
- Output FDs are locked to write/append operations only

### CLI Options

```
--no-sandbox        Disable Capsicum sandboxing
--sandbox-strict    Require full sandbox enforcement or exit
```

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
- Landlock (Linux) and Seatbelt (macOS) sandboxes contain potential exploitation

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
