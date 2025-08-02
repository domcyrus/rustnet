# RustNet

A high-performance, cross-platform network monitoring tool built with Rust. RustNet provides real-time visibility into network connections with deep packet inspection capabilities and a responsive terminal user interface.

## Features

- **Real-time Network Monitoring**: Monitor active TCP, UDP, ICMP, and ARP connections
- **Deep Packet Inspection (DPI)**: Automatically detect application protocols:
  - HTTP with host information
  - HTTPS/TLS with SNI (Server Name Indication)
  - DNS queries and responses
  - SSH connections
  - QUIC protocol
- **Process Identification**: Associate network connections with running processes
- **Service Name Resolution**: Identify well-known services using port numbers
- **Cross-platform Support**: Works on Linux, Windows, and macOS
- **Terminal User Interface**: Clean, responsive TUI built with ratatui
- **Performance Optimized**: Multi-threaded packet processing with minimal overhead
- **Configurable Logging**: Detailed logging with configurable log levels

## Installation

### Prerequisites

- Rust 2024 edition or later (install from [rustup.rs](https://rustup.rs/))
- libpcap or similar packet capture library:
  - **Linux**: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (RedHat/CentOS)
  - **macOS**: Included by default
  - **Windows**: Install WinPcap or Npcap

### Building from source

```bash
# Clone the repository
git clone https://github.com/yourusername/rustnet.git
cd rustnet

# Build in release mode
cargo build --release

# The executable will be in target/release/rustnet
```

### Running RustNet

On Unix-like systems (Linux/macOS), packet capture typically requires elevated privileges:

```bash
# Run with sudo
sudo ./target/release/rustnet

# Or set capabilities on Linux (to avoid needing sudo)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rustnet
./target/release/rustnet
```

## Usage

```bash
# Run with default settings (monitors default interface)
rustnet

# Specify network interface
rustnet -i eth0
rustnet --interface wlan0

# Filter out localhost connections
rustnet --no-localhost

# Set UI refresh interval (in milliseconds)
rustnet -r 500
rustnet --refresh-interval 2000

# Disable deep packet inspection
rustnet --no-dpi

# Set log level (options: error, warn, info, debug, trace)
rustnet -l debug
rustnet --log-level trace

# View help and all options
rustnet --help
```

### Command-line Options

- `-i, --interface <INTERFACE>`: Network interface to monitor
- `--no-localhost`: Filter out localhost connections
- `-r, --refresh-interval <MS>`: UI refresh interval in milliseconds (default: 1000)
- `--no-dpi`: Disable deep packet inspection
- `-l, --log-level <LEVEL>`: Set the log level (default: info)

### Keyboard Controls

- `q`: Quit the application (press twice to confirm)
- `Ctrl+C`: Quit immediately
- `Tab`: Switch between tabs (Overview, Details, Help)
- `↑/k`: Navigate up in connection list
- `↓/j`: Navigate down in connection list
- `PageUp`: Move up by 10 items
- `PageDown`: Move down by 10 items
- `Enter`: View detailed information about selected connection
- `Esc`: Go back to previous view
- `c`: Copy remote address to clipboard
- `h`: Toggle help screen

## Logging

RustNet creates timestamped log files in the `logs/` directory. Each session generates a new log file with the format `rustnet_YYYY-MM-DD_HH-MM-SS.log`. 

Log files contain:
- Application startup and shutdown events
- Network interface information
- Packet capture statistics
- Connection state changes
- Error diagnostics

Use the `--log-level` option to control verbosity. The `scripts/clear_old_logs.sh` script is provided for log cleanup.

## Architecture

RustNet employs a multi-threaded architecture for high-performance packet processing:

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

### Key Components

1. **Packet Capture Thread**: Uses libpcap to capture raw packets from the network interface
2. **Packet Processors**: Multiple worker threads parse packets and perform DPI analysis
3. **Process Enrichment**: Platform-specific APIs to associate connections with processes
4. **Snapshot Provider**: Creates consistent snapshots for the UI at regular intervals
5. **Cleanup Thread**: Removes stale connections based on timeout settings
6. **DashMap**: Lock-free concurrent hashmap for storing connection state

## Dependencies

RustNet is built with the following key dependencies:

- **ratatui**: Terminal user interface framework
- **crossterm**: Cross-platform terminal manipulation
- **pcap**: Packet capture library bindings
- **pnet_datalink**: Network interface enumeration
- **dashmap**: High-performance concurrent hashmap
- **crossbeam**: Multi-threading utilities
- **dns-lookup**: DNS resolution
- **clap**: Command-line argument parsing
- **simplelog**: Flexible logging framework
- **procfs** (Linux): Process information from /proc filesystem

## Platform-Specific Implementation

### Process Lookup

RustNet uses platform-specific APIs to associate network connections with processes:

- **Linux**: Parses `/proc/net/tcp`, `/proc/net/udp`, and `/proc/<pid>/fd/` to find socket inodes
- **Windows**: Uses Windows API calls to enumerate processes and their network connections
- **macOS**: Uses system commands like `lsof` to query process-socket associations

### Network Interfaces

The tool automatically detects and lists available network interfaces using platform-specific methods, falling back to pcap's device enumeration when native methods are unavailable.

## Performance Considerations

- **Multi-threaded Processing**: Packet processing is distributed across multiple threads (up to 4 by default)
- **Lock-free Data Structures**: Uses DashMap for concurrent access without traditional locking
- **Batch Processing**: Packets are processed in batches to improve cache efficiency
- **Selective DPI**: Deep packet inspection can be disabled with `--no-dpi` for lower overhead
- **Configurable Intervals**: Adjust refresh rates and timeouts based on your needs

## Troubleshooting

### Common Issues

1. **Permission Denied**: Packet capture requires elevated privileges. Run with `sudo` or set capabilities.

2. **No Connections Shown**: 
   - Check if the correct network interface is selected
   - Verify packet capture permissions
   - Try disabling localhost filtering with `--no-localhost`

3. **High CPU Usage**:
   - Increase the refresh interval: `--refresh-interval 2000`
   - Disable DPI if not needed: `--no-dpi`
   - Check log files for excessive packet rates

4. **Process Names Not Showing**:
   - On Linux, ensure `/proc` is accessible
   - Some processes may require root privileges to identify

### Debug Mode

Enable debug logging to troubleshoot issues:

```bash
rustnet --log-level debug
```

Check the generated log file in the `logs/` directory for detailed diagnostics.

## Security Considerations

- RustNet requires privileged access for packet capture
- The tool only monitors traffic; it does not modify or block connections
- Log files may contain sensitive connection information
- No data is transmitted outside your system

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [ratatui](https://github.com/ratatui-org/ratatui) for the terminal UI
- Packet capture powered by [libpcap](https://www.tcpdump.org/)
- Inspired by tools like `sniffnet`, `netstat`, `ss`, and `iftop`
