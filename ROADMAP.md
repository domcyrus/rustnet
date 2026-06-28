# RustNet Roadmap

This document outlines the planned features and improvements for RustNet.

## Platform Support

- [x] **macOS Support**: Full support including:
  - BPF device access and permissions setup
  - PKTAP (Packet Tap) headers for process identification from packet metadata
  - Fallback to `lsof` system commands for process-socket associations
  - DMG installation packages for Apple Silicon and Intel
  - Homebrew installation support
- [x] **Windows Support**: Full functionality working with:
  - Npcap SDK and runtime integration
  - MSI installation packages for 64-bit and 32-bit
  - Process identification via Windows IP Helper API (GetExtendedTcpTable/GetExtendedUdpTable)
- [x] **FreeBSD Support**: Full support including:
  - Process identification via `sockstat` command parsing
  - BPF device access and permissions setup
  - Native libpcap packet capture
  - Cross-compilation support from Linux
- [ ] **FreeBSD Capsicum Full Sandbox** (`cap_enter()`): Replace per-FD `cap_rights_limit()` with full capability mode to prevent file access and data exfiltration. Requires:
  - Switch from `sockstat` subprocess to `libprocstat(3)` library calls for process lookup (eliminates `fork()`/`execve()` dependency)
  - Integrate `libcasper` for privileged sysctl access from inside capability mode (`kern.proc.filedesc` is blocked in `cap_enter()`)
  - Architecture: pre-fork a Casper service before `cap_enter()`, communicate over socket pair at runtime
  - Write FFI bindings for `libprocstat` and `libcasper` (no Rust crate exists)
  - Link against `-lprocstat -lcasper -lcap_sysctl` (system libraries on FreeBSD 10+)
- [ ] **Windows Sandbox Hardening**: Strengthen the current privilege-drop + Job Object setup with process mitigation policies (`SetProcessMitigationPolicy`), low-integrity execution, and evaluation of `CreateRestrictedToken` / AppContainer.
- [ ] **macOS Seatbelt Hardening**: The current Seatbelt profile is allow-default with targeted denies (user homes, system credential stores, outbound TCP/UDP, `process-exec` except `lsof`). Tighten further:
  - **Deny-by-default writes**: rustnet only writes its log/PCAP/JSONL output, so flip `file-write*` to deny-by-default with a small allowlist. This blocks root-level persistence (`/Library/LaunchDaemons`, `/Library/LaunchAgents`, `/private/etc` cron/launchd, etc.) that the current allow-default write policy leaves open. Needs on-host validation that the TUI's writes to the already-open tty and the `lsof` child still work.
  - **More credential read denies**: system TCC database (`/Library/Application Support/com.apple.TCC`), Kerberos keytabs, `master.passwd`/`sudoers`, saved network/Wi-Fi configuration (`/Library/Preferences/SystemConfiguration`).
  - **Eventual deny-by-default reads**: whitelist the dyld shared cache, system frameworks, `/dev/bpf*`, resolver/locale/timezone data, and the GeoIP paths. Strongest containment, but fragile across macOS releases — requires a multi-version on-host test pass before shipping.
- [ ] **Linux Sandbox Hardening (capabilities + Landlock network)**: Landlock already enforces deny-by-default filesystem access on the post-sandbox worker threads, but two gaps remain when rustnet runs as root:
  - **Drop all non-essential capabilities** (or clear the bounding set via `PR_CAPBSET_DROP`) before spawning the worker threads. Today only `CAP_NET_RAW`/`CAP_BPF`/`CAP_PERFMON` are dropped, so a root-launched process retains `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, etc. — which Landlock does not cover (non-filesystem/non-TCP abuse such as loading kernel modules). Running non-root with a `cap_net_raw` file capability already avoids this; the hardening is for the common `sudo rustnet` case.
  - **UDP egress is not blocked**: Landlock ABI v4 only governs TCP `bind`/`connect`, so UDP exfiltration remains possible (accepted as low risk today, since filesystem reads are tightly contained). Revisit when a newer Landlock ABI adds UDP support. Note macOS Seatbelt already blocks both TCP and UDP.
- [ ] **OpenBSD and NetBSD Support**: Future platforms to support
- [x] **Linux Process Identification**: **Experimental eBPF Support Implemented** - Basic eBPF-based process identification now available with `--features ebpf`. Provides efficient kernel-level process-to-connection mapping with lower overhead than procfs. Currently has limitations (see eBPF Improvements section below).

## eBPF Improvements (Linux)

The experimental eBPF support provides efficient process identification but has several areas for improvement:

### Current Limitations
- **Process Names Limited to 16 Characters**: Uses kernel `comm` field, causing truncation (e.g., "Firefox" → "Socket Thread")
- **Thread Names vs Process Names**: Shows thread command names instead of full executable names

### Planned Improvements
- **Hybrid eBPF + Procfs Approach**: Use eBPF for connection tracking, selectively lookup full process names via procfs for better accuracy
- **Full Executable Path Resolution**: Investigate accessing full process executable path from eBPF programs
- **Better Process-Thread Mapping**: Improve mapping from thread IDs to parent process information
- **Enhanced BTF Support**: Better compatibility across different kernel versions and distributions
- **Performance Optimizations**: Reduce eBPF map lookups and improve connection-to-process matching efficiency
- **Switch from kprobes to fentry/fexit or kprobe.multi**: Today we attach 7 kprobes via `perf_event_open(2)`, which is gated by `kernel.perf_event_paranoid`. On Debian 13 the default is `=3` (an out-of-tree patch that predates CAP_PERFMON and only honors CAP_SYS_ADMIN), so even with `cap_bpf,cap_perfmon+ep` set via `setcap`, attach fails with `-EACCES` until the user lowers the sysctl globally (issue #255). Debian bug #994044 was archived in 2025 without a fix, so this is unlikely to change in Forky (Debian 14, ~2027) without renewed pressure. Ubuntu has a parallel patch at `=4` that *was* updated to honor CAP_PERFMON in late 2025 (Jammy 5.15.0-165+, Noble 6.8.0-91+, Plucky 6.14.0-37+, Questing 6.17.0-14+, Resolute 6.18.0-8+), so Ubuntu users already work out of the box — Debian is the laggard. Both `BPF_PROG_TYPE_TRACING` (fentry/fexit, kernel ≥ 5.5) and `kprobe.multi` (fprobe-based, kernel ≥ 5.18) attach via `BPF_LINK_CREATE` and never call `perf_event_open` — they're gated only by CAP_BPF + CAP_PERFMON, so they would work out of the box on Debian regardless of the broken patch. fentry also gives entry args + return value in a single program (cleaner than kprobe + kretprobe). Mainline / Fedora / Arch / RHEL all default to paranoid=2 and the upstream direction (CAP_PERFMON, fprobe, BTF trampolines) is toward more privilege separation, not less, so this conversion is also future-aligned. Trade-off: raises minimum supported kernel from current (kprobes work back to ~4.x) to 5.5+ for fentry or 5.18+ for kprobe.multi — need to decide whether to keep a kprobe fallback for older kernels.

### Future Enhancements
- **Real-time Process Updates**: Track process name changes and executable updates
- **Container Support**: Better process identification within containerized environments
- **Security Context**: Include process security attributes (capabilities, SELinux context, etc.)

## Features

### Monitoring & Protocol Support

- [x] **Real-time Network Monitoring**: Monitor active TCP, UDP, ICMP, and ARP connections
- [x] **Connection States**: Comprehensive state tracking for:
  - TCP states (ESTABLISHED, SYN_SENT, TIME_WAIT, CLOSED, etc.)
  - QUIC states (QUIC_INITIAL, QUIC_HANDSHAKE, QUIC_CONNECTED, QUIC_DRAINING)
  - DNS states (DNS_QUERY, DNS_RESPONSE)
  - SSH states (BANNER, KEYEXCHANGE, AUTHENTICATION, ESTABLISHED)
  - Activity states (UDP_ACTIVE, UDP_IDLE, UDP_STALE)
- [x] **Deep Packet Inspection (DPI)**: Application protocol detection:
  - HTTP with host information
  - HTTPS/TLS with SNI (Server Name Indication)
  - DNS queries and responses
  - SSH connections with version detection, software identification, and state tracking
  - QUIC protocol with CONNECTION_CLOSE frame detection and RFC 9000 compliance
- [ ] **DPI Enhancements**: Improve deep packet inspection capabilities:
  - Support more protocols (e.g. FTP, SMTP, IMAP, etc.)
  - CDP/LLDP (network device discovery protocols)
  - LACP (Link Aggregation Control Protocol)
  - More accurate SNI detection for QUIC/HTTPS
- [x] **Connection Lifecycle Management**: Smart protocol-aware timeouts with visual staleness indicators (yellow at 75%, red at 90%)
- [x] **Process Identification**: Associate network connections with running processes (with experimental eBPF support on Linux)
- [x] **Service Name Resolution**: Identify well-known services using port numbers
- [x] **Cross-platform Support**: Works on Linux, macOS, Windows, and FreeBSD
- [x] **DNS Reverse Lookup**: Add optional hostname resolution (toggle between IP and hostname display) - `--resolve-dns` flag with `d` key toggle
- [ ] **IPv6 Support**: Full IPv6 connection tracking and display, including DNS resolution (needs testing)
- [ ] **VLAN Tag Detection**: Parse 802.1Q VLAN tags from packet headers to identify VLAN configurations
- [ ] **Passive Host Discovery**: Infer local network hosts from observed ARP requests/replies and other broadcast traffic without active scanning
- [ ] **MAC Vendor Lookup (OUI)**: Resolve MAC addresses to hardware vendor names using a local OUI database (e.g. "Apple", "Intel", "Ubiquiti")

### Filtering & Search

- [x] **Advanced Filtering**: Real-time vim/fzf-style filtering with:
  - Navigate while typing filters
  - Fuzzy search across all connection fields including DPI data
  - Keyword filters: `port:`, `src:`, `dst:`, `sni:`, `process:`, `sport:`, `dport:`, `ssh:`, `state:`
  - State filtering for all protocol states
  - Exact port matching by default (`port:22` matches only port 22)
  - Regular expression support via `/pattern/` syntax on any filter value

### Sorting & Display

- [x] **Sorting**: Comprehensive table sorting with:
  - Sort by all columns: Protocol, Local/Remote Address, State, Service, Application, Bandwidth (Down/Up), Process
  - Intuitive left-to-right column cycling with `s` key
  - Direction toggle with `S` (Shift+s) for ascending/descending
  - Visual indicators: cyan/underlined active column, arrows showing direction
  - Smart defaults: bandwidth descending (show hogs), text ascending (alphabetical)
  - Bandwidth sorting: sorts by combined up+down bandwidth total
  - Seamless integration with filtering

### Performance & Architecture

- [x] **Multi-threaded Processing**: Concurrent packet processing across multiple threads
- [x] **Optional Logging**: Detailed logging with configurable log levels (disabled by default)

### Packaging & Distribution

- [x] **Package Distribution**: Pre-built packages available:
  - [x] **macOS DMG packages**: Apple Silicon and Intel (via GitHub Actions release workflow)
  - [x] **Windows MSI packages**: 64-bit and 32-bit (via cargo-wix)
  - [x] **Linux DEB packages**: amd64, arm64, armhf (via cargo-deb)
  - [x] **Linux RPM packages**: x86_64, aarch64 (via cargo-generate-rpm)
  - [x] **Cargo crates.io**: Published as `rustnet-monitor` (version 0.10.0+)
  - [x] **Docker images**: Available on GitHub Container Registry with eBPF support
  - [x] **Homebrew formula**: Available in separate tap repository (domcyrus/rustnet)

### Future Enhancements

- [ ] **Internationalization (i18n)**: Support for multiple languages in the UI
- [x] **Connection History**: Store and display historical connection data (toggle with `t` key, up to 5,000 archived connections)
- [x] **PCAP Export**: Export packets to PCAP file with process attribution sidecar (`--pcap-export`)
  - Standard PCAP format compatible with Wireshark/tcpdump
  - Streaming JSONL sidecar with PID, process name, timestamps
  - Python enrichment script to create annotated PCAPNG
- [x] **Native Annotated PCAPNG Export**: Export a Wireshark-ready PCAPNG file with live best-effort RustNet packet comments (`--pcapng-export`)
  - Per-packet comments include process/PID, direction, DPI/SNI, and GeoIP/ASN when available
  - Uses true capture timestamps and bounded attribution retry
- [ ] **Enhanced PCAP Metadata**: Richer process information in sidecar file
  - Process executable full path (not just name)
  - Command line arguments
  - Working directory
  - User/UID information
  - Parent process information
- [ ] **Configuration File**: Support for persistent configuration:
  - Custom color themes and UI styling
  - Default filters and sort preferences
  - Default process grouping (start with `group: true` in config)
  - Color mode preference (disable colors via config, complementing `--no-color` flag)
  - Per-interface settings
  - Keybinding customization
- [ ] **Connection Alerts**: Notifications for new connections or suspicious activity
- [x] **GeoIP Integration**: Geographical location of remote IPs
- [x] **GeoIP City-Level Resolution**: Extend GeoIP to include city-level location data using GeoLite2-City database
- [ ] **Protocol Statistics**: Summary view of protocol distribution
- [ ] **Rate Limiting Detection**: Identify connections with unusual traffic patterns
- [ ] **Bufferbloat Detection**: Measure latency under load to identify bufferbloat issues on the network
- [ ] **PCAP Import/Replay**: Load a PCAP file (with optional JSON process attribution sidecar) and replay it in the TUI for offline analysis. Enables remote monitoring workflows: capture on a remote host with `--pcap-export`, transfer files, and replay locally with full process-attributed view
- [ ] **Route Table Display**: Show the system routing table in a user-friendly view within the TUI
- [ ] **Privacy/Redact Mode**: Obfuscate sensitive information (IPs, MACs, hostnames) in the TUI for safe screenshots and sharing. Include option to export connection details from the details view to a text file with privacy redaction applied

## UI Improvements

- [x] **Terminal User Interface**: TUI built with ratatui with adjustable column widths
- [x] **Sortable Columns**: Keyboard-based sorting by all table columns
- [x] **Keyboard Controls**: Comprehensive keyboard navigation (q, Ctrl+C, x, Tab, arrows, j/k, g/G, PageUp/Down, Enter, Esc, c, p, s, S, h, /, a, r, Space)
- [x] **Connection Details View**: Detailed information about selected connections (Enter key)
- [x] **Help Screen**: Toggle help screen with keyboard shortcuts (h key)
- [x] **Clipboard Support**: Copy remote address to clipboard (c key)
- [x] **Service/Port Toggle**: Toggle between service names and port numbers (p key)
- [x] **Platform-Specific CLI Help**: Show only relevant options per platform (hide Linux sandbox options on macOS, hide PKTAP notes on Linux)
- [x] **Connection Grouping**: Group connections by process with expandable tree view (press `a` to toggle, aggregated stats, Space/arrows to expand/collapse)
- [x] **Reset View**: Reset all view settings (grouping, sort, filter) with `r` key
- [ ] **Resizable Columns**: Dynamic column width adjustment
- [ ] **ASCII Graphs**: Terminal-based graphs for bandwidth/packet visualization
- [ ] **Mouse Support**: Click to select connections
- [ ] **Split Pane View**: Show multiple views simultaneously

## Architecture

### Workspace Split

Restructure the single crate into a Cargo workspace (same GitHub repo) with clear separation of concerns:

- [x] **rustnet-monitor** (binary, bin name `rustnet`): CLI, TUI, app event
  loop, sandboxing (Landlock/Seatbelt), and interface statistics -- the
  user-facing application; process attribution is delegated to `rustnet-host`.
  (Package stays `rustnet-monitor` because the `rustnet` crate name is taken on
  crates.io; the installed binary is `rustnet`.)
- [x] **rustnet-core** (library): Packet parsing, protocol types, DPI,
  link-layer parsers, connection merging, and DNS/GeoIP/OUI lookups -- the
  reusable, platform-independent, capture-independent analysis core. Lives at
  `crates/rustnet-core`. (Named `rustnet-core` rather than `rustnet-net` to
  avoid the redundant "net-net"; verified available on crates.io.)
- [x] **rustnet-capture** (library): the libpcap/Npcap-based capture backend --
  device selection, BPF filters, macOS PKTAP, TUN/TAP, and a raw-frame
  `PacketReader`. Lives at `crates/rustnet-capture`. This is the **existing**
  pcap code moved into its own crate (not a libpcap-free rewrite): the point of
  the split is composability — a headless front-end (e.g. a Prometheus exporter)
  can pair `rustnet-capture` + `rustnet-core` without the TUI, and a platform
  wanting a bespoke capture path (e.g. the macOS pktap helper) can swap it out.
  The macOS `DegradationReason` coupling was untangled by giving capture its own
  `PktapUnavailable` enum, which the binary maps to its UI `DegradationReason`.
- [x] **rustnet-host** (library): Per-connection process attribution behind one
  `ProcessLookup` trait -- eBPF/procfs on Linux, PKTAP/lsof on macOS, the IP
  Helper API on Windows, and `sockstat` on FreeBSD. Lives at `crates/rustnet-host`
  and owns the eBPF build tooling (the `socket_tracker.bpf.c` program and bundled
  `vmlinux.h`). The binary injects PKTAP availability via `report_pktap_degradation`,
  so the crate needs no dependency on `rustnet-capture`.
- [ ] **rustnet-helper** (binary): Minimal suid helper for macOS pktap privilege
  separation (~100 lines, zero C deps — just `libc`). **Future work, not yet a
  crate.** The root-gated pktap interface creation (`SIOCIFCREATE`) can only be
  written and validated on real macOS hardware, so this is deferred until it can
  be done for real rather than scaffolded. See "macOS Privilege Separation" below.

Benefits:
- Clean dependency boundaries (helper has zero C dependencies)
- `rustnet-core` becomes independently useful as a Rust network analysis library
- Compile times improve (parallel crate compilation)
- `cargo install rustnet-monitor` continues to work unchanged

**Status:** The workspace exists with `rustnet-monitor` (binary) depending on
`rustnet-core`, `rustnet-capture`, and `rustnet-host`. The binary's `src/network`
module re-exports `rustnet_core::network::*` and `rustnet_capture` (as `capture`)
so existing `crate::network::*` paths, integration tests, and benches are
unchanged. Net-only dependencies (`dns-lookup`, `ring`, `aes`, `flate2`,
`maxminddb`, `pnet_datalink`) and the baked-in `oui.gz` / `services` assets live
in `rustnet-core`; all pcap usage lives in `rustnet-capture`; and `procfs` /
`libbpf-rs` plus the eBPF programs and `vmlinux.h` live in `rustnet-host`.
`rustnet-core` also exposes a `ConnectionTracker` so headless tools can fold
captured packets into a live, lifecycle-managed connection table without the
TUI. Remaining work: the `rustnet-helper` macOS pktap suid helper (needs real
hardware).

### macOS Privilege Separation (pktap without root)

Currently pktap requires root because the macOS kernel enforces a root check (`SIOCIFCREATE` ioctl) when creating the pktap pseudo-interface. This is independent of BPF device permissions (ChmodBPF). The goal is to run the main RustNet process as a regular user while only the minimal helper runs privileged.

**Approach**: Small suid helper binary that:
1. Opens `/dev/bpf*` and creates the pktap interface (requires root)
2. Configures BPF device (bind interface, set buffer size, immediate mode)
3. Locks the device with `BIOCLOCK` (prevents further configuration changes)
4. Passes the BPF file descriptor to the unprivileged RustNet process via Unix socket (`SCM_RIGHTS`)
5. Drops privileges and exits

The main RustNet process reads packets directly from the received BPF fd using `read()` -- no libpcap needed on this path. The existing pktap header parser (`link_layer/pktap.rs`) already handles the packet format. BPF filter compilation is not needed since BPF filters are already incompatible with pktap.

On Linux/Windows/FreeBSD, nothing changes -- libpcap is used as today, with the existing capability-based privilege model on Linux.

Security properties:
- Helper is tiny (~100 lines of Rust, no C code) -- minimal attack surface as root
- `BIOCLOCK` prevents the unprivileged process from reconfiguring the capture device
- Seatbelt sandbox can still be applied to the main process after fd handoff
- Similar pattern to Wireshark's `dumpcap` but with a smaller privileged surface (no libpcap in the helper)

## Development

- [x] **Unit Tests**: Basic unit tests in 12+ source modules (DPI protocols, filtering, services, network capture, etc.)
- [x] **Integration Tests**: Platform-specific integration tests for Linux and macOS (tests/integration_tests.rs)
- [ ] **Comprehensive Test Coverage**: Expand test coverage across all modules
- [x] **CI/CD Pipeline**: Automated builds and releases for all platforms (GitHub Actions)
  - [x] **Release workflow**: Multi-platform builds with cross-compilation
  - [x] **Docker workflow**: Automated Docker image builds
  - [x] **Rust workflow**: Basic CI checks
- [x] **Documentation**: Comprehensive README with usage guides, architecture overview, and troubleshooting
- [x] **Packaging/Distribution**: Create packages for easy installation on Linux, macOS, and Windows
  - DMG packages with code signing
  - MSI packages with code signing for Windows
