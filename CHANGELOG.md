# Changelog

All notable changes to RustNet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.0] - 2025-09-30

### Added
- **Docker Support with eBPF**: Docker images now include eBPF support for enhanced performance
  - Multi-architecture Docker builds (amd64, arm64, armv7)
  - eBPF-enabled images for advanced socket tracking on Linux
  - Optimized container builds with proper dependency management
- **Cross-Platform Packaging and Release Automation**: Comprehensive automated release workflow
  - Automated DEB, RPM, DMG, and MSI package generation
  - Cross-platform CI/CD improvements

### Fixed
- **RPM Package Dependencies**: Corrected libelf dependency specification in RPM packages
- **Windows MSI Packaging**: Fixed MSI installer generation issues
- **Release Workflow**: Resolved various release automation issues

## [0.10.0] - 2025-09-28

### Added
- **Rust Version Requirements**: Added minimum Rust version requirement (1.88.0+) for let-chains support

### Changed
- **Build Requirements**: Now requires Rust 1.88.0 or later for advanced language features

## [0.9.0] - 2025-09-18

### Added
- **Experimental eBPF Support for Linux**: Enhanced socket tracking with optional eBPF backend
  - eBPF-based socket tracker with CO-RE (Compile Once - Run Everywhere) support
  - Minimal vmlinux header (5.5KB instead of full 3.4MB file)
  - Graceful fallback mechanism to procfs when eBPF unavailable
  - Support for both IPv4 and IPv6 socket tracking
  - Optional feature disabled by default (enable with `--features=ebpf`)
  - Comprehensive capability checking for required permissions
- **Windows Platform Support**: Network monitoring capability on Windows (without process identification)

## [0.8.0] - 2025-09-11

### Added
- **SSH Deep Packet Inspection (DPI)**: Comprehensive SSH protocol analysis including:
  - SSH version detection (SSH-1.x, SSH-2.0)
  - Client and server software identification (OpenSSH, PuTTY, libssh, etc.)
  - Connection state tracking: Banner, KeyExchange, Authentication, Established
  - Algorithm detection and negotiation monitoring
  - SSH-specific filtering with `ssh:` prefix in connection filters
- **Enhanced Filtering**: SSH connections now support detailed filtering by software name and connection state

### Improved
- **CI/CD**: Enhanced GitHub Actions with path-based triggers for more efficient workflows
- **Documentation**: Updated README with SSH DPI examples and state descriptions

## [0.7.0] - 2025-09-11

### Fixed
- SecureCRT backspace handling issue

## [0.6.0] - 2025-09-10

### Added
- Connection state filtering (ESTABLISHED, TIME_WAIT, etc.)

## [0.5.0] - 2025-01-09

### Added
- **Connection Filtering System**: New comprehensive filtering capability allowing users to filter connections by:
  - Protocol type (TCP, UDP, ICMP)
  - Local and remote IP addresses
  - Local and remote ports
  - Process names
  - Service names
  - Customizable filter expressions with intuitive UI
- **Enhanced Documentation**: Added asciinema demo recording for better user onboarding
- **Visual Demonstrations**: Added animated GIF showcasing RustNet functionality

### Fixed
- **README Improvements**: Fixed image syntax and formatting issues for better GitHub display

### Changed
- **User Interface**: Enhanced TUI to support dynamic filtering with keyboard shortcuts
- **Documentation**: Improved project presentation with visual aids and demonstrations

## [0.4.0] - 2025-01-29

### Improved
- Enhanced traffic monitoring with better rate tracking and byte counters
- Fixed Linux platform build warnings for improved compilation stability
- Corrected version display to use dynamic version from Cargo.toml instead of hardcoded value

## [0.3.0] - 2024-12-28

### Added
- Created `RELEASE.md` and `ROADMAP.md` for better project organization
- Enhanced memory efficiency through enum variant boxing

### Fixed
- Major clippy warning cleanup (97% reduction from 38 to 1 warnings)
- Refactored functions using `TransportParams` struct to reduce complexity
- Fixed collapsible if patterns and improved code readability
- Eliminated needless borrows and manual implementations

### Changed
- Moved release documentation to dedicated files
- Streamlined README to focus on user information
- Improved code organization and Rust best practices

## [0.2.0] - 2024-12-19

### Added
- **Enhanced PKTAP Support on macOS**: Comprehensive process identification using macOS PKTAP (Packet Tap) headers
  - Direct extraction of process names and PIDs from kernel packet metadata
  - Robust handling of 20-byte PKTAP process name fields with proper normalization
  - Support for both `pth_comm` and `pth_e_comm` (effective command name) fields
  - Fallback to `lsof` system commands when PKTAP data is unavailable
- **Process Data Immutability System**: Once process information is set from any source, it becomes immutable to prevent display inconsistencies
- **Advanced Process Name Normalization**: Handles all types of whitespace, control characters, and padding in process names
- **Comprehensive Debug Logging**: Extensive logging for PKTAP header processing, process name extraction, and data flow tracking

### Fixed
- **Process Display Stability on macOS**: Fixed issue where process names would change format during UI scrolling (e.g., "firefox              (123)" → "firefox (123)")
- **PKTAP Header Processing**: Improved parsing of raw PKTAP packet headers with better error handling and validation
- **Process Name Consistency**: Eliminated race conditions and data inconsistencies in process name display
- **Whitespace Normalization**: Fixed handling of tabs, multiple spaces, unicode whitespace, and control characters in process names

### Changed
- **Process Enrichment Logic**: Modified to respect existing PKTAP data and only fill in missing information from `lsof`
- **UI Rendering Optimization**: Simplified process name rendering to use pre-normalized data from sources
- **Error Handling**: Enhanced error reporting for PKTAP processing and process lookup failures

### Technical Details
- Implemented `extract_process_name_from_bytes()` function for robust PKTAP process name extraction
- Added immutability enforcement in connection merge logic with violation detection
- Enhanced macOS process lookup with `normalize_process_name_robust()` function
- Improved byte-level debugging and logging for process identification troubleshooting

### Platform-Specific Improvements
- **macOS**: PKTAP now provides primary process identification with significant performance and accuracy improvements over `lsof`-only approach
- **Linux**: Process enrichment logic updated to work consistently with new immutability system

## [0.1.0] - 2024-XX-XX

### Added
- Initial release of RustNet
- Real-time network connection monitoring
- Deep packet inspection (DPI) for HTTP, HTTPS, DNS, SSH, and QUIC
- Cross-platform support (Linux, macOS, Windows)
- Terminal user interface with ratatui
- Multi-threaded packet processing
- Process identification using platform-specific APIs
- Service name resolution
- Configurable refresh intervals and filtering options
- Optional logging with multiple log levels

[Unreleased]: https://github.com/domcyrus/rustnet/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/domcyrus/rustnet/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/domcyrus/rustnet/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/domcyrus/rustnet/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/domcyrus/rustnet/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/domcyrus/rustnet/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/domcyrus/rustnet/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/domcyrus/rustnet/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/domcyrus/rustnet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/domcyrus/rustnet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/domcyrus/rustnet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/domcyrus/rustnet/releases/tag/v0.1.0