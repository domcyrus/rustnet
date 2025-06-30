# RustNet

A cross-platform network monitoring tool built with Rust and TUI interface.

## Features

- Monitor active network connections (TCP, UDP)
- View connection details (state, traffic, age)
- Identify processes associated with connections
- Display geographical information about remote IPs
- Cross-platform support (Linux, Windows, macOS)
- Terminal user interface with keyboard navigation
- Internationalization support

## Installation

### Prerequisites

- Rust and Cargo (install from [rustup.rs](https://rustup.rs/))

### Building from source

```bash
# Clone the repository
git clone https://github.com/yourusername/rustnet.git
cd rustnet

# Build in release mode
cargo build --release

# The executable will be in target/release/rustnet
```

## Usage

```bash
# Run with default settings
rustnet

# Specify network interface
rustnet -i eth0

# Use a custom configuration file
rustnet -c /path/to/config.yml

# Set interface language
rustnet -l fr
```

### Keyboard Controls

- `q` or `Ctrl+C`: Quit the application
- `r`: Refresh connections
- `↑/k`, `↓/j`: Navigate up/down
- `Enter`: View detailed information about a connection
- `Esc`: Go back to previous view
- `p`: View process details (when viewing connection details)
- `l`: Toggle IP location display
- `h`: Toggle help screen

## Configuration

RustNet can be configured using a YAML configuration file. The application searches for the configuration file in the following locations:

1. Path specified with `-c` or `--config`
2. `$XDG_CONFIG_HOME/rustnet/config.yml`
3. `~/.config/rustnet/config.yml`
4. `./config.yml` (current directory)

Example configuration:

```yaml
# Network interface to monitor (leave empty for default)
interface: eth0

# Interface language (ISO code: en, fr, ...)
language: en

# Path to MaxMind GeoIP database
geoip_db_path: /usr/share/GeoIP/GeoLite2-City.mmdb

# Refresh interval in milliseconds
refresh_interval: 1000

# Show IP locations (requires MaxMind DB)
show_locations: true
```

## Architecture

┌─────────────────┐
│ Packet Capture  │ ──packets──> channel
└─────────────────┘                  │
                                     ├──> ┌──────────────────┐
                                     ├──> │ Packet Processor │ ──> DashMap
                                     ├──> │    (Thread 0)    │      │
                                     └──> │    (Thread N)    │      │
                                          └──────────────────┘      │
                                                                    │
┌─────────────────-┐                                                │
│Process Enrichment│ ──────────────────────────────────────────> DashMap
└─────────────────-┘                                                │
                                                                    │
┌─────────────────┐                                                 │
│Snapshot Provider│ <────────────────────────────────────────── DashMap
└─────────────────┘                                                │
         │                                                         │
         └──> RwLock<Vec<Connection>> (for UI)                     │
                                                                   │
┌─────────────────┐                                                │
│ Cleanup Thread  │ <────────────────────────────────────────── DashMap
└─────────────────┘

## Internationalization

RustNet supports multiple languages. The application looks for language files in the following locations:

1. `./i18n/[language].yml` (current directory)
2. `$XDG_DATA_HOME/rustnet/i18n/[language].yml`
3. `~/.local/share/rustnet/i18n/[language].yml`
4. `/usr/share/rustnet/i18n/[language].yml`

Currently supported languages:

- English (en)
- French (fr)

To add a new language, create a copy of `i18n/en.yml`, translate the values, and save it with the appropriate language code (e.g., `de.yml` for German).

## Advanced Usage

### Finding Process Information

RustNet attempts to identify the process associated with each network connection using different methods depending on the operating system:

- **Linux**: Uses `ss` command, `netstat`, or parses `/proc` directly
- **Windows**: Uses `netstat` command or Windows API
- **macOS**: Uses `lsof` command or `netstat`

## TODOs

### GeoIP Lookup

For GeoIP lookup: MaxMind GeoLite2 City database (place `GeoLite2-City.mmdb` in the application directory)

When a MaxMind GeoLite2 City database is available, RustNet can display geographical information about remote IP addresses. To use this feature:

1. Download the GeoLite2 City database from MaxMind (requires free account)
2. Place the `GeoLite2-City.mmdb` file in one of the search paths (see configuration)
3. Enable IP location display with the `l` key

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
