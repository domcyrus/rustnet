<p align="center"><strong>English</strong> | <a href="SECURITY.zh-CN.md">简体中文</a></p>

# Security

RustNet processes untrusted network data, making defense-in-depth security critical. This document describes the security measures implemented.

## Table of Contents

- [Landlock Sandboxing (Linux)](#landlock-sandboxing-linux)
- [Fedora SELinux Policy](#fedora-selinux-policy)
- [Seatbelt Sandboxing (macOS)](#seatbelt-sandboxing-macos)
- [FreeBSD Sandboxing](#freebsd-sandboxing)
- [Privilege Drop and Job Object Sandboxing (Windows)](#privilege-drop-and-job-object-sandboxing-windows)
- [Privilege Requirements](#privilege-requirements)
- [Read-Only Operation](#read-only-operation)
- [No External Communication](#no-external-communication)
- [Log File Privacy](#log-file-privacy)
- [eBPF Security](#ebpf-security)
- [Threat Model](#threat-model)
- [Supply Chain Security](#supply-chain-security)
- [Audit and Compliance](#audit-and-compliance)
- [Reporting Security Issues](#reporting-security-issues)

## Landlock Sandboxing (Linux)

On Linux 5.13+, RustNet uses [Landlock](https://landlock.io/) to restrict its own capabilities after initialization. This limits the damage if a vulnerability in packet parsing is exploited.

### What Gets Restricted

| Restriction | Kernel Version | Description |
|-------------|----------------|-------------|
| Filesystem | 5.13+ | Only `/proc` readable (for process identification) |
| Network | 6.7+ | TCP bind/connect blocked (RustNet is passive) |
| Capabilities | Any | `CAP_NET_RAW` dropped after pcap socket opened |
| Capabilities | Any | `CAP_BPF`, `CAP_PERFMON` dropped after eBPF programs loaded |
| Privileges | 3.5+ | `PR_SET_NO_NEW_PRIVS` set by RustNet itself — always, even with `--no-sandbox` — prevents privilege escalation via setuid binaries |

### How It Works

1. **Initialization phase**: RustNet loads eBPF programs, opens packet capture handles, and creates log files
2. **Privilege lock**: `PR_SET_NO_NEW_PRIVS` is set (applied even when the sandbox is disabled)
3. **Capability drop**: `CAP_NET_RAW`, `CAP_BPF`, and `CAP_PERFMON` are removed from the process
4. **Landlock**: Restricts filesystem and network access

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot read arbitrary files (credentials, configs, etc.)
- Cannot write to filesystem (except configured log paths)
- Cannot make outbound TCP connections (TCP exfiltration blocked)
- Cannot bind TCP ports (reverse shell blocked)
- Cannot create new raw sockets (capability dropped)
- Cannot escalate privileges via setuid binaries (`PR_SET_NO_NEW_PRIVS`, set even with `--no-sandbox`)

### CLI Options

```
--no-sandbox        Disable Landlock sandboxing and capability dropping
                    (PR_SET_NO_NEW_PRIVS is still set)
--sandbox-strict    Require full sandbox enforcement or exit
```

### Graceful Degradation

- **Kernel < 5.13**: Sandboxing skipped, warning logged
- **Kernel 5.13-6.3**: Filesystem restrictions only
- **Kernel 6.7+**: Filesystem + TCP bind/connect restrictions
- **Docker**: Landlock may be restricted; app continues normally

## Fedora SELinux Policy

The Fedora COPR RPM ships a `rustnet` SELinux policy module for modern Fedora
systems. Fedora enables SELinux by default, so the RPM installs the module and
restores the label on `/usr/bin/rustnet` during package installation.

The first shipped policy is intentionally **permissive** for `rustnet_t`. This
lets maintainers collect AVCs from real capture sessions without breaking users.
After the policy is validated on supported Fedora releases, a follow-up change
can remove the permissive rule and make the domain enforcing.

### Policy Coverage

| Restriction | Description |
|-------------|-------------|
| Domain transition | Normal Fedora interactive launches of `/usr/bin/rustnet` transition into `rustnet_t` |
| Capabilities | Allows only the packet-capture/eBPF capabilities rustnet needs |
| DNS | Allows reverse DNS through the configured resolver |
| Filesystem | Labels `/usr/bin/rustnet` and supports a labelled `/var/log/rustnet` output directory |
| Firewall | The RPM does **not** modify firewalld or nftables rules |

Because the first policy is permissive, these rules are initially audit coverage,
not hard denials. Enforced confinement comes after AVC review.

### AVC Review

```bash
semodule -l | grep rustnet
ls -Z /usr/bin/rustnet
sudo ausearch -m avc -ts recent
```

Subnet-level egress policy, such as "allow RFC1918 but deny public IPs", is left
to administrator-managed firewall or network policy. The RustNet RPM does not
install host firewall rules because those can affect unrelated traffic when the
tool is run as the invoking user or with sudo.

## Seatbelt Sandboxing (macOS)

On macOS 10.5+, RustNet uses [Seatbelt](https://theapplewiki.com/wiki/Dev:Seatbelt) (`sandbox_init_with_parameters`) to restrict its own capabilities after initialization. This limits the damage if a vulnerability in packet parsing is exploited.

### What Gets Restricted

| Restriction | Description |
|-------------|-------------|
| Outbound network | TCP/UDP outbound blocked; Unix sockets (Mach IPC) allowed |
| Filesystem reads | User home directories blocked (`/Users`, `/var/root`); GeoIP paths explicitly allowed |
| Filesystem writes | All user home directories blocked (`/Users`, `/var/root`) |
| Filesystem writes | Only configured log and PCAP export paths writable |
| Process execution | All binaries blocked except `/usr/sbin/lsof` |

### How It Works

1. **Initialization phase**: RustNet opens packet capture handles (BPF/PKTAP) and creates log files
2. **Pre-create**: PCAP sidecar file (`.connections.jsonl`) is created before the sandbox so its path is already a valid allow target
3. **Sandbox application**: `sandbox_init_with_parameters` is called — already-open file descriptors survive unchanged, only future operations are restricted

### Profile Strategy

RustNet uses an **allow-default** SBPL profile with targeted denies. A deny-default profile would require explicitly whitelisting all system libraries, Mach ports, locale data, fonts, and other OS internals — fragile and error-prone. Allow-default with targeted denies covers the primary threats (credential theft, data exfiltration, shell escapes) without operational risk. Specific deny rules block file reads/writes under user home directories, outbound network connections, and execution of all binaries except `/usr/sbin/lsof`.

### Output File Support

`--json-log` and `--pcap-export` paths are passed to the SBPL profile as runtime parameters (`JSON_LOG_PATH`, `PCAP_PATH`, `PCAP_JSONL_PATH`). The profile grants an explicit `allow file-write*` rule on each path, which takes precedence over the broader `/Users` deny rule via SBPL specificity. Unused parameters default to `/dev/null`.

Both flags work normally within the sandbox.

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot read SSH keys, AWS credentials, browser profiles, or other credential files under `/Users`
- Cannot write to SSH keys, AWS credentials, browser profiles, or other credential files
- Cannot make outbound TCP/UDP connections (data exfiltration blocked)
- Cannot open new raw network sockets
- Cannot execute binaries (no shell escapes via `/bin/sh`, `/usr/bin/curl`, etc.)

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

## FreeBSD Sandboxing

FreeBSD does not currently have sandboxing enabled. A full Capsicum sandbox using `cap_enter()` with `libcasper` for privileged process lookup is planned — see [ROADMAP.md](ROADMAP.md) for details.

## Privilege Drop and Job Object Sandboxing (Windows)

On Windows, RustNet removes dangerous privileges from the process token and applies a Job Object to prevent child process creation after initialization.

### What Gets Restricted

| Restriction | Description |
|-------------|-------------|
| Privilege removal | SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege, and other dangerous privileges permanently removed |
| Child processes | Job Object blocks creation of child processes (reverse shell, exec-based exfiltration) |

### How It Works

1. **Initialization phase**: RustNet opens Npcap handles and creates log files
2. **Privilege removal**: `AdjustTokenPrivileges` with `SE_PRIVILEGE_REMOVED` permanently strips dangerous privileges from the process token
3. **Job Object**: A Job Object with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` is applied, preventing any child process creation

### Security Benefits

If an attacker exploits a vulnerability in DPI/packet parsing:
- Cannot debug other processes (SeDebugPrivilege removed)
- Cannot take ownership of arbitrary files (SeTakeOwnershipPrivilege removed)
- Cannot bypass ACLs to read files (SeBackupPrivilege removed)
- Cannot spawn child processes (cmd.exe, powershell.exe, curl.exe — blocked by Job Object)
- Cannot load kernel drivers (SeLoadDriverPrivilege removed)

### Limitations

Windows sandboxing is weaker than Linux/macOS/FreeBSD:
- No filesystem restriction — Windows lacks a process-wide filesystem sandbox equivalent to Landlock or Seatbelt
- No network restriction — blocking outbound would break Npcap packet capture
- Privilege removal only affects privileges the elevated process held

### CLI Options

```
--no-sandbox        Disable privilege removal and job object
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
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' $(which rustnet)

# Legacy Linux (pre-5.8): packet capture + eBPF
sudo setcap 'cap_net_raw,cap_sys_admin+eip' $(which rustnet)

# Packet capture only (no eBPF process detection)
sudo setcap cap_net_raw+eip $(which rustnet)
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

RustNet has no telemetry or cloud backend:
- No telemetry or analytics
- No cloud services or remote APIs
- GeoIP lookups use local MaxMind databases only

By default, RustNet does perform reverse DNS (PTR) lookups for captured IP
addresses through the system resolver. Disable those active DNS requests with:

```bash
rustnet --no-resolve-dns
```

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

### Sandboxing as Root

Both Landlock (Linux) and Seatbelt (macOS) enforce restrictions even when RustNet runs as root (UID 0). Once applied, the sandbox cannot be reversed from within the process — on Linux, RustNet sets `PR_SET_NO_NEW_PRIVS` directly before applying any restrictions (Landlock requires and would set it as well), which is irreversible per-process and applied even with `--no-sandbox`.

However, sandboxing does **not** protect against supply chain attacks. A compromised binary would simply not apply the sandbox. Root can also:
- Pass `--no-sandbox` to skip sandboxing entirely (except `PR_SET_NO_NEW_PRIVS`)
- Unload the Landlock LSM kernel module
- Disable SIP on macOS (which controls sandbox enforcement)
- Use `ptrace` to modify a running process

For this reason, running with fine-grained capabilities (`setcap cap_net_raw=eip`) is strongly preferred over running as root.

## Supply Chain Security

RustNet takes the following measures to protect against supply chain attacks:

- **Dependency lockfile**: `Cargo.lock` is committed to the repository, pinning all transitive dependency versions and recording source checksums. This prevents silent version upgrades.
- **Security audit**: `cargo deny check` runs in CI on every push and pull request, checking dependencies against the RustSec Advisory Database and enforcing license, source, and wildcard-version policies (`deny.toml`). A scheduled daily workflow re-checks advisories against the committed `Cargo.lock`, so newly published advisories surface without requiring a push.
- **CI action pinning**: All GitHub Actions are pinned by commit SHA (not tags), preventing tag-rewriting attacks on upstream actions.
- **Conservative dependency policy**: New dependencies require justification and are reviewed for maintenance status and security track record (see `CONTRIBUTING.md`).
- **Build-time integrity**: The Windows Npcap SDK download in `build.rs` is verified against a hardcoded SHA256 checksum.
- **Code signing**: macOS releases are signed with an Apple Developer certificate and notarized.
- **Checksum verification**: All packaging workflows (Homebrew, Chocolatey, AUR) calculate and double-verify SHA256 checksums before publishing.

### Limitations

- `cargo install rustnet` fetches the latest compatible versions from crates.io and does **not** use `Cargo.lock`. Users building from source should verify the source tarball checksum.
- Build scripts (`build.rs`) and proc-macros execute arbitrary code at compile time. While all current dependencies are well-established crates, this is an inherent risk of the Rust build model.

## Audit and Compliance

For production environments:
- **Audit logging** of who runs RustNet with packet capture privileges
- **Network monitoring policies** and compliance with data protection regulations
- **User access reviews** for privileged network access
- **Automated capability management** via configuration management systems

## Reporting Security Issues

Please report security vulnerabilities via GitHub Issues or contact the maintainers directly.
