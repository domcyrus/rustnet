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
- [ ] **BSD Support**: Add support for FreeBSD, OpenBSD, and NetBSD
- [x] **Linux Process Identification**: **Experimental eBPF Support Implemented** - Basic eBPF-based process identification now available with `--features ebpf`. Provides efficient kernel-level process-to-connection mapping with lower overhead than procfs. Currently has limitations (see eBPF Improvements section below).

## eBPF Improvements (Linux)

The experimental eBPF support provides efficient process identification but has several areas for improvement:

### Current Limitations
- **Process Names Limited to 16 Characters**: Uses kernel `comm` field, causing truncation (e.g., "Firefox" → "Socket Thread")
- **Thread Names vs Process Names**: Shows thread command names instead of full executable names
- **Minimal vmlinux.h Maintenance**: Current approach requires manual updates when adding new kernel structure access

### Planned Improvements
- **Hybrid eBPF + Procfs Approach**: Use eBPF for connection tracking, selectively lookup full process names via procfs for better accuracy
- **Full Executable Path Resolution**: Investigate accessing full process executable path from eBPF programs
- **Better Process-Thread Mapping**: Improve mapping from thread IDs to parent process information
- **vmlinux.h Strategy**: Consider switching to full auto-generated vmlinux.h for easier maintenance vs current minimal approach
- **Enhanced BTF Support**: Better compatibility across different kernel versions and distributions
- **Performance Optimizations**: Reduce eBPF map lookups and improve connection-to-process matching efficiency

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
  - More accurate SNI detection for QUIC/HTTPS
- [x] **Connection Lifecycle Management**: Smart protocol-aware timeouts with visual staleness indicators (yellow at 75%, red at 90%)
- [x] **Process Identification**: Associate network connections with running processes (with experimental eBPF support on Linux)
- [x] **Service Name Resolution**: Identify well-known services using port numbers
- [x] **Cross-platform Support**: Works on Linux, macOS, Windows
- [ ] **DNS Reverse Lookup**: Add optional hostname resolution (toggle between IP and hostname display)
- [ ] **IPv6 Support**: Full IPv6 connection tracking and display, including DNS resolution (needs testing)

### Filtering & Search

- [x] **Advanced Filtering**: Real-time vim/fzf-style filtering with:
  - Navigate while typing filters
  - Fuzzy search across all connection fields including DPI data
  - Keyword filters: `port:`, `src:`, `dst:`, `sni:`, `process:`, `sport:`, `dport:`, `ssh:`, `state:`
  - State filtering for all protocol states
- [ ] **Search/Filter Enhancements**:
  - Regular expression support

### Sorting & Display

- [x] **Sorting**: Comprehensive table sorting with:
  - Sort by all columns: Protocol, Local/Remote Address, State, Service, Application, Bandwidth (Down/Up), Process
  - Intuitive left-to-right column cycling with `s` key
  - Direction toggle with `S` (Shift+s) for ascending/descending
  - Visual indicators: cyan/underlined active column, arrows showing direction
  - Smart defaults: bandwidth descending (show hogs), text ascending (alphabetical)
  - Special bandwidth handling: arrows attach to specific metric (Down↓/Up or Down/Up↓)
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
- [ ] **Connection History**: Store and display historical connection data
- [ ] **Export Functionality**: Export connections to CSV/JSON formats
- [ ] **Configuration File**: Support for persistent configuration (filters, UI preferences)
- [ ] **Connection Alerts**: Notifications for new connections or suspicious activity
- [ ] **GeoIP Integration**: Maybe add geographical location of remote IPs
- [ ] **Protocol Statistics**: Summary view of protocol distribution
- [ ] **Rate Limiting Detection**: Identify connections with unusual traffic patterns

## UI Improvements

- [x] **Terminal User Interface**: TUI built with ratatui with adjustable column widths
- [x] **Sortable Columns**: Keyboard-based sorting by all table columns
- [x] **Keyboard Controls**: Comprehensive keyboard navigation (q, Ctrl+C, Tab, arrows, j/k, PageUp/Down, Enter, Esc, c, p, s, S, h, /)
- [x] **Connection Details View**: Detailed information about selected connections (Enter key)
- [x] **Help Screen**: Toggle help screen with keyboard shortcuts (h key)
- [x] **Clipboard Support**: Copy remote address to clipboard (c key)
- [x] **Service/Port Toggle**: Toggle between service names and port numbers (p key)
- [ ] **Resizable Columns**: Dynamic column width adjustment
- [ ] **Connection Grouping**: Group connections by process/service
- [ ] **ASCII Graphs**: Terminal-based graphs for bandwidth/packet visualization
- [ ] **Mouse Support**: Click to select connections
- [ ] **Split Pane View**: Show multiple views simultaneously

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
