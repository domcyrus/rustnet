# Usage Guide

This guide covers detailed usage of RustNet, including command-line options, keyboard controls, filtering, sorting, and understanding connection lifecycle.

## Table of Contents

- [Running RustNet](#running-rustnet)
- [Command-line Options](#command-line-options)
- [Keyboard Controls](#keyboard-controls)
- [Filtering](#filtering)
- [Sorting](#sorting)
- [Connection Lifecycle & Visual Indicators](#connection-lifecycle--visual-indicators)
- [Logging](#logging)

## Running RustNet

Packet capture requires elevated privileges on most systems. See [INSTALL.md](INSTALL.md) for detailed permission setup instructions.

**Quick start:**

```bash
# Run with sudo (works on all platforms)
sudo rustnet

# Or grant capabilities to run without sudo (see INSTALL.md for details)
# Linux example:
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/rustnet
rustnet
```

**Basic usage examples:**

```bash
# Run with default settings (monitors default interface)
rustnet

# Specify network interface
rustnet -i eth0
rustnet --interface wlan0

# Filter out localhost connections (already filtered by default)
rustnet --no-localhost

# Show localhost connections (override default filtering)
rustnet --show-localhost

# Set UI refresh interval (in milliseconds)
rustnet -r 500
rustnet --refresh-interval 2000

# Disable deep packet inspection
rustnet --no-dpi

# Enable logging with specific level (options: error, warn, info, debug, trace)
rustnet -l debug
rustnet --log-level info

# View help and all options
rustnet --help
```

## Command-line Options

```
Usage: rustnet [OPTIONS]

Options:
  -i, --interface <INTERFACE>            Network interface to monitor
      --no-localhost                     Filter out localhost connections (default: filtered)
      --show-localhost                   Show localhost connections (overrides default filtering)
  -r, --refresh-interval <MILLISECONDS>  UI refresh interval in milliseconds [default: 1000]
      --no-dpi                           Disable deep packet inspection
  -l, --log-level <LEVEL>                Set the log level (if not provided, no logging will be enabled)
  -h, --help                             Print help
  -V, --version                          Print version
```

### Option Details

#### `-i, --interface <INTERFACE>`

Specify which network interface to monitor. If not provided, RustNet will use the first available non-loopback interface.

**Examples:**
```bash
rustnet -i eth0          # Monitor Ethernet interface
rustnet -i wlan0         # Monitor WiFi interface
rustnet -i en0           # Monitor macOS primary interface
```

**Finding your interfaces:**
- Linux: `ip link show` or `ifconfig`
- macOS: `ifconfig` or `networksetup -listallhardwareports`
- Windows: `ipconfig /all`

#### `--no-localhost` / `--show-localhost`

Control whether localhost (127.0.0.1/::1) connections are displayed.

- **Default**: Localhost connections are filtered out (`--no-localhost`)
- **Override**: Use `--show-localhost` to see localhost connections

This is useful for reducing noise in the connection list, as most users don't need to monitor local IPC connections.

#### `-r, --refresh-interval <MILLISECONDS>`

Set the UI refresh rate in milliseconds. Lower values provide more responsive updates but increase CPU usage.

**Recommendations:**
- **Default (1000ms)**: Good balance for most users
- **High-traffic networks (2000ms)**: Reduce CPU usage on busy networks
- **Real-time monitoring (500ms)**: More responsive updates for quick analysis
- **Low-end systems (2000-3000ms)**: Reduce load on resource-constrained machines

#### `--no-dpi`

Disable Deep Packet Inspection (DPI). This reduces CPU usage by 20-40% on high-traffic networks but disables:
- HTTP host detection
- HTTPS/TLS SNI extraction
- DNS query/response detection
- SSH version identification
- QUIC protocol detection

Useful for performance-constrained environments or when application-level details aren't needed.

#### `-l, --log-level <LEVEL>`

Enable logging with the specified level. Logging is **disabled by default**.

**Available levels:**
- `error` - Only errors (minimal logging)
- `warn` - Warnings and errors
- `info` - General information (recommended for normal debugging)
- `debug` - Detailed debugging information
- `trace` - Very verbose output (includes packet-level details)

Log files are created in the `logs/` directory with timestamp: `rustnet_YYYY-MM-DD_HH-MM-SS.log`

## Keyboard Controls

### Navigation

- `↑` or `k` - Navigate up in connection list
- `↓` or `j` - Navigate down in connection list
- `g` - Jump to first connection (vim-style)
- `G` (Shift+g) - Jump to last connection (vim-style)
- `PageUp` - Move up by 10 items
- `PageDown` - Move down by 10 items

### Views and Tabs

- `Tab` - Switch between tabs (Overview, Details, Help)
- `Enter` - View detailed information about selected connection
- `Esc` - Go back to previous view or clear active filter
- `h` - Toggle help screen

### Actions

- `c` - Copy remote address to clipboard
- `p` - Toggle between service names and port numbers
- `/` - Enter filter mode (vim-style search with real-time results)

### Sorting

- `s` - Cycle through sort columns (left-to-right order)
- `S` (Shift+s) - Toggle sort direction (ascending/descending)

### Exit

- `q` - Quit the application (press twice to confirm)
- `Ctrl+C` - Quit immediately

## Filtering

Press `/` to enter filter mode. Type to filter connections in real-time, navigate with arrow keys while typing.

### Basic Search

Simply type any text to search across all connection fields:

```
/google        # Find connections containing "google"
/firefox       # Find Firefox connections
/192.168       # Find connections with IP starting with 192.168
```

### Keyword Filters

Use keyword filters for targeted searches:

| Keyword | Description | Example |
|---------|-------------|---------|
| `port:` | Ports containing pattern | `port:44` matches 443, 8080, 4433 |
| `sport:` | Source ports | `sport:80` matches source port 80 |
| `dport:` | Destination ports | `dport:443` matches destination port 443 |
| `src:` | Source IPs/hostnames | `src:192.168` matches 192.168.x.x |
| `dst:` | Destinations | `dst:github.com` matches github.com |
| `process:` | Process names | `process:ssh` matches ssh, sshd |
| `sni:` | SNI hostnames (HTTPS) | `sni:api` matches api.example.com |
| `ssh:` | SSH version/software | `ssh:openssh` matches OpenSSH connections |
| `state:` | Protocol states | `state:established` matches established connections |
| `proto:` | Protocol type | `proto:tcp` matches TCP connections |

### State Filtering

Filter connections by their current protocol state (case-insensitive):

⚠️ **Note:** State tracking accuracy varies by protocol. TCP states are most reliable, while UDP, QUIC, and other protocol states are derived from packet inspection and may not always reflect the true connection state.

**Examples:**
```
state:syn_recv       # Show half-open connections (useful for detecting SYN floods)
state:established    # Show only established connections
state:fin_wait       # Show connections in closing states
state:quic_handshake # Show QUIC connections during handshake
state:dns_query      # Show DNS query connections
state:udp_active     # Show active UDP connections
```

**Available states:**

| Protocol | States |
|----------|--------|
| **TCP** | `SYN_SENT`, `SYN_RECV`, `ESTABLISHED`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE_WAIT`, `LAST_ACK`, `CLOSING`, `CLOSED` |
| **QUIC** | `QUIC_INITIAL`, `QUIC_HANDSHAKE`, `QUIC_CONNECTED`, `QUIC_DRAINING`, `QUIC_CLOSED` ⚠️ *Note: May be incomplete due to encrypted handshakes* |
| **UDP** | `UDP_ACTIVE`, `UDP_IDLE`, `UDP_STALE` |
| **DNS** | `DNS_QUERY`, `DNS_RESPONSE` |
| **SSH** | `BANNER`, `KEYEXCHANGE`, `AUTHENTICATION`, `ESTABLISHED` ⚠️ *Note: Based on packet inspection* |
| **Other** | `ECHO_REQUEST`, `ECHO_REPLY`, `ARP_REQUEST`, `ARP_REPLY` |

### Combining Filters

Combine multiple filters with spaces (implicit AND):

```
sport:80 process:nginx              # Nginx connections from port 80
dport:443 sni:google.com            # HTTPS connections to Google
sport:443 state:syn_recv            # Half-open connections to port 443 (SYN flood detection)
proto:tcp state:established         # All established TCP connections
process:firefox state:quic_connected # Active QUIC connections from Firefox
dport:22 ssh:openssh                # SSH connections using OpenSSH
state:established ssh:openssh       # Established SSH connections using OpenSSH
```

### Clearing Filters

Press `Esc` to clear the active filter and return to the full connection list.

## Sorting

RustNet provides powerful table sorting to help you analyze network connections. Press `s` to cycle through sortable columns in left-to-right visual order, and press `S` (Shift+s) to toggle between ascending and descending order.

### Quick Start

**Find bandwidth hogs:**
```
Press 's' repeatedly until you see: Down↓/Up
The connections with highest download bandwidth appear at the top
```

**Find top uploaders:**
```
Press 's' repeatedly until you see: Down/Up↓
The connections with highest upload bandwidth appear at the top
```

**Sort by process name:**
```
Press 's' repeatedly until you see: Process ↑
Connections are sorted alphabetically by process name
```

### Sortable Columns

Press `s` to cycle through columns in left-to-right order:

| Column | Default Direction | Description |
|--------|-------------------|-------------|
| **Protocol** | ↑ Ascending | Sort by protocol type (TCP, UDP, ICMP, etc.) |
| **Local Address** | ↑ Ascending | Sort by local IP:port (useful for multi-interface systems) |
| **Remote Address** | ↑ Ascending | Sort by remote IP:port |
| **State** | ↑ Ascending | Sort by connection state (ESTABLISHED, etc.) |
| **Service** | ↑ Ascending | Sort by service name or port number |
| **Application** | ↑ Ascending | Sort by detected application protocol (HTTP, DNS, etc.) |
| **Bandwidth ↓** | ↓ Descending | Sort by **download** bandwidth (highest first by default) |
| **Bandwidth ↑** | ↓ Descending | Sort by **upload** bandwidth (highest first by default) |
| **Process** | ↑ Ascending | Sort by process name alphabetically |

### Sort Indicators

The active sort column is highlighted with:
- **Cyan color** and **underline** styling
- **Arrow symbol** (↑ or ↓) showing sort direction
- **Table title** showing current sort state

**Visual indicators:**
```
Active column header appears in cyan with underline:
Pro │ Local Address │ Remote Address ↑│ State │ ...
                      ^^^^^^^^^^^^^^^^
                      (cyan, underlined, with arrow)

Table title shows current sort:
┌─ Active Connections (Sort: Remote Addr ↑) ──┐
```

### Bandwidth Column Special Behavior

The bandwidth column shows **both download and upload** metrics. The arrow attaches to the specific metric being sorted:

| Display | Sorting By | Direction | Meaning |
|---------|------------|-----------|---------|
| `Down↓/Up` | Download | Descending (↓) | **Highest downloads first** (bandwidth hogs) |
| `Down↑/Up` | Download | Ascending (↑) | Lowest downloads first |
| `Down/Up↓` | Upload | Descending (↓) | **Highest uploads first** (top uploaders) |
| `Down/Up↑` | Upload | Ascending (↑) | Lowest uploads first |

**Key points:**
- The arrow (↑/↓) indicates **sort direction**, not bandwidth direction
- `↓` = Descending = Highest values at top (10MB → 5MB → 1MB)
- `↑` = Ascending = Lowest values at top (1MB → 5MB → 10MB)
- Press `s` once on bandwidth to sort by downloads, press `s` again for uploads
- Press `S` (Shift+s) to flip between high-to-low and low-to-high

### Sort Behavior

**Press `s` (lowercase) - Cycle Columns:**
- Moves to the next column in left-to-right visual order
- **Resets to default direction** for that column
- Bandwidth columns default to descending (↓) to show highest values first
- Text columns default to ascending (↑) for alphabetical order

**Press `S` (Shift+s) - Toggle Direction:**
- **Stays on current column**
- Flips between ascending (↑) and descending (↓)
- Useful for reversing sort order (e.g., finding smallest bandwidth users)

**Press `s` multiple times to return to default:**
- Cycling through all columns returns to the default chronological sort (by connection creation time)
- No sort indicator is shown when in default mode

### Sorting with Filtering

Sorting works seamlessly with filtering:
1. **Filter first**: Press `/` and enter your filter criteria
2. **Then sort**: Press `s` to sort the filtered results
3. **The sort persists**: Changing the filter keeps your sort order active

Example workflow:
```
1. Press '/' and type 'firefox' to filter Firefox connections
2. Press 's' until you see "Down↓/Up"
3. Now viewing Firefox connections sorted by download bandwidth
```

### Examples

**Find which process is downloading the most:**
```
1. Press 's' until "Down↓/Up" appears
2. Top connection shows the highest download rate
3. Look at the "Process" column to see which application
```

**Sort connections by remote destination:**
```
1. Press 's' until "Remote Address ↑" appears
2. Connections are grouped by remote IP address
3. Press 'S' to reverse order if needed
```

**Find idle connections (lowest bandwidth):**
```
1. Press 's' to cycle to "Down↓/Up"
2. Press 'S' to toggle to "Down↑/Up" (ascending)
3. Connections with lowest download bandwidth appear first
```

**Sort by application protocol:**
```
1. Press 's' until "Application / Host ↑" appears
2. All HTTPS connections group together, DNS queries together, etc.
3. Useful for finding all connections of a specific type
```

## Connection Lifecycle & Visual Indicators

RustNet uses intelligent timeout management to automatically clean up inactive connections while providing visual warnings before removal.

### Visual Staleness Indicators

Connections change color based on how close they are to being cleaned up:

| Color | Meaning | Staleness |
|-------|---------|-----------|
| **White** (default) | Active connection | < 75% of timeout |
| **Yellow** | Stale - approaching timeout | 75-90% of timeout |
| **Red** | Critical - will be removed soon | > 90% of timeout |

**Example**: An HTTP connection with a 10-minute timeout will:
- Stay **white** for the first 7.5 minutes
- Turn **yellow** from 7.5 to 9 minutes (warning)
- Turn **red** after 9 minutes (critical)
- Be removed at 10 minutes

This gives you advance warning when a connection is about to disappear from the list.

### Smart Protocol-Aware Timeouts

RustNet adjusts connection timeouts based on the protocol and detected application:

#### TCP Connections
- **HTTP/HTTPS** (detected via DPI): **10 minutes** - supports HTTP keep-alive
- **SSH** (detected via DPI): **30 minutes** - accommodates long interactive sessions
- **Active established** (< 1 min idle): **10 minutes**
- **Idle established** (> 1 min idle): **5 minutes**
- **TIME_WAIT**: 30 seconds - standard TCP timeout
- **CLOSED**: 5 seconds - rapid cleanup
- **SYN_SENT, FIN_WAIT, etc.**: 30-60 seconds

#### UDP Connections
- **HTTP/3 (QUIC with HTTP)**: **10 minutes** - connection reuse
- **HTTPS/3 (QUIC with HTTPS)**: **10 minutes** - connection reuse
- **SSH over UDP**: **30 minutes** - long-lived sessions
- **DNS**: **30 seconds** - short-lived queries
- **Regular UDP**: **60 seconds** - standard timeout

#### QUIC Connections (Detected State)
- **Connected (active)** (< 1 min idle): **10 minutes**
- **Connected (idle)** (> 1 min idle): **5 minutes**
- **With CONNECTION_CLOSE frame**: 1-10 seconds (based on close type)
- **Initial/Handshaking**: 60 seconds - allow connection establishment
- **Draining**: 10 seconds - RFC 9000 draining period

### Activity-Based Adjustment

Connections showing recent packet activity get longer timeouts:
- **Last packet < 60 seconds ago**: Uses "active" timeout (longer)
- **Last packet > 60 seconds ago**: Uses "idle" timeout (shorter)

This ensures active connections stay visible while idle connections are cleaned up more quickly.

### Why Connections Disappear

A connection is removed when:
1. **No packets received** for the duration of its timeout period
2. The connection enters a **closed state** (TCP CLOSED, QUIC CLOSED)
3. **Explicit close frames** detected (QUIC CONNECTION_CLOSE)

**Note**: Rate indicators (bandwidth display) show *decaying* traffic based on recent activity. A connection may show declining bandwidth (yellow bars) but remain in the list until it exceeds its idle timeout. This is intentional - the visual decay gives you time to see the connection winding down before it's removed.

## Logging

Logging is **disabled by default**. When enabled with the `--log-level` option, RustNet creates timestamped log files in the `logs/` directory. Each session generates a new log file with the format `rustnet_YYYY-MM-DD_HH-MM-SS.log`.

### Log File Contents

Log files contain:
- Application startup and shutdown events
- Network interface information
- Packet capture statistics
- Connection state changes
- Error diagnostics
- DPI detection results (at debug/trace levels)
- Performance metrics (at trace level)

### Enabling Logging

Use the `--log-level` option to enable logging:

```bash
# Info-level logging (recommended for general use)
sudo rustnet --log-level info

# Debug-level logging (detailed troubleshooting)
sudo rustnet --log-level debug

# Trace-level logging (very verbose, includes packet-level details)
sudo rustnet --log-level trace

# Error-only logging (minimal logging)
sudo rustnet --log-level error
```

### Log Levels Explained

| Level | What Gets Logged | Use Case |
|-------|------------------|----------|
| `error` | Only errors and critical issues | Production monitoring |
| `warn` | Warnings and errors | Normal operation with warnings |
| `info` | General information, startup/shutdown | Standard debugging |
| `debug` | Detailed debugging information | Troubleshooting issues |
| `trace` | Packet-level details, very verbose | Deep debugging |

### Managing Log Files

**Log cleanup script:**

The `scripts/clear_old_logs.sh` script is provided for log cleanup:

```bash
# Remove logs older than 7 days
./scripts/clear_old_logs.sh

# Customize retention period by editing the script
```

**Manual cleanup:**

```bash
# Remove all logs
rm -rf logs/

# Remove logs older than 7 days (Linux/macOS)
find logs/ -name "rustnet_*.log" -mtime +7 -delete

# View log file size
du -sh logs/
```

### Log File Privacy

⚠️ **Warning**: Log files may contain sensitive information:
- IP addresses and ports
- Hostnames and SNI data (HTTPS)
- DNS queries and responses
- Process names and PIDs
- Packet contents (at trace level)

**Best practices:**
- Only enable logging when needed for debugging
- Secure log directory permissions: `chmod 700 logs/`
- Review logs for sensitive data before sharing
- Implement log rotation and retention policies
- Delete logs when no longer needed

### Troubleshooting with Logs

When reporting issues:
1. Enable debug logging: `rustnet --log-level debug`
2. Reproduce the issue
3. Find the latest log file in `logs/`
4. Review for errors or unexpected behavior
5. Redact sensitive information before sharing

For performance issues, trace-level logging provides the most detail but generates large log files quickly.
