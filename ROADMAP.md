# RustNet Roadmap

This document outlines the planned features and improvements for RustNet.

## Platform Support

- **macOS Support**: Basic features need testing and fixes for macOS compatibility
- **Windows Support**: ✅ Basic functionality working with Npcap SDK and runtime. Process identification not yet implemented for Windows
- **BSD Support**: Add support for FreeBSD, OpenBSD, and NetBSD
- **Linux Process Identification Enhancement**: Investigate using **eBPF** (Extended Berkeley Packet Filter) for direct kernel-level process identification similar to macOS PKTAP. This would provide more accurate and efficient process-to-connection mapping than the current `/proc` filesystem approach, especially for high-throughput scenarios.

## Features

- **Sorting**: Sort by name, bandwidth utilization, etc.
- **DPI Enhancements**: Improve deep packet inspection capabilities:
  - Support more protocols (e.g. FTP, SMTP, etc.)
  - More accurate SNI detection for QUIC/HTTPS
- **DNS Reverse Lookup**: Add optional hostname resolution (toggle between IP and hostname display)
- **IPv6 Support**: Full IPv6 connection tracking and display, including DNS resolution, didn't test yet
- **Search/Filter**: 
  - 🔄 Regular expression support (future enhancement)
- **Internationalization (i18n)**: Support for multiple languages in the UI
- **Connection History**: Store and display historical connection data
- **Export Functionality**: Export connections to CSV/JSON formats
- **Configuration File**: Support for persistent configuration (filters, UI preferences)
- **Connection Alerts**: Notifications for new connections or suspicious activity
- **GeoIP Integration**: Maybe add geographical location of remote IPs
- **Protocol Statistics**: Summary view of protocol distribution
- **Rate Limiting Detection**: Identify connections with unusual traffic patterns

## UI Improvements

- **Resizable Columns**: Dynamic column width adjustment
- **Connection Grouping**: Group connections by process/service
- **Sortable Columns**: Click to sort by any column
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
