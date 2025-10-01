# RustNet Roadmap

This document outlines the planned features and improvements for RustNet.

## Platform Support

- **macOS Support**: Basic features need testing and fixes for macOS compatibility
- **Windows Support**: Basic functionality working with Npcap SDK and runtime. Process identification not yet implemented for Windows
- **BSD Support**: Add support for FreeBSD, OpenBSD, and NetBSD
- **Linux Process Identification**: **Experimental eBPF Support Implemented** - Basic eBPF-based process identification now available with `--features ebpf`. Provides efficient kernel-level process-to-connection mapping with lower overhead than procfs. Currently has limitations (see eBPF Improvements section below).

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

- **✅ Sorting** (Completed): Comprehensive table sorting with:
  - Sort by all columns: Protocol, Local/Remote Address, State, Service, Application, Bandwidth (Down/Up), Process
  - Intuitive left-to-right column cycling with `s` key
  - Direction toggle with `S` (Shift+s) for ascending/descending
  - Visual indicators: cyan/underlined active column, arrows showing direction
  - Smart defaults: bandwidth descending (show hogs), text ascending (alphabetical)
  - Special bandwidth handling: arrows attach to specific metric (Down↓/Up or Down/Up↓)
  - Seamless integration with filtering
- **DPI Enhancements**: Improve deep packet inspection capabilities:
  - Support more protocols (e.g. FTP, SMTP, etc.)
  - More accurate SNI detection for QUIC/HTTPS
- **DNS Reverse Lookup**: Add optional hostname resolution (toggle between IP and hostname display)
- **IPv6 Support**: Full IPv6 connection tracking and display, including DNS resolution, didn't test yet
- **Search/Filter**: 
  - Regular expression support (future enhancement)
- **Internationalization (i18n)**: Support for multiple languages in the UI
- **Connection History**: Store and display historical connection data
- **Export Functionality**: Export connections to CSV/JSON formats
- **Configuration File**: Support for persistent configuration (filters, UI preferences)
- **Connection Alerts**: Notifications for new connections or suspicious activity
- **GeoIP Integration**: Maybe add geographical location of remote IPs
- **Protocol Statistics**: Summary view of protocol distribution
- **Rate Limiting Detection**: Identify connections with unusual traffic patterns

## UI Improvements

- **✅ Sortable Columns** (Completed): Keyboard-based sorting by all table columns
- **Resizable Columns**: Dynamic column width adjustment
- **Connection Grouping**: Group connections by process/service
- **Connection Details Popup**: Modal dialog for detailed connection info
- **ASCII Graphs**: Terminal-based graphs for bandwidth/packet visualization
- **Mouse Support**: Click to select connections
- **Split Pane View**: Show multiple views simultaneously

## Development

- **Unit Tests**: Comprehensive test coverage for all modules
- **Integration Tests**: End-to-end testing for different platforms
- **CI/CD Pipeline**: Automated builds and releases for all platforms
- **Documentation**: API documentation and developer guide
- **Packaging/Distribution**: Create packages for easy installation on Linux, macOS, and Windows
