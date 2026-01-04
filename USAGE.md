# Usage Guide

This guide covers detailed usage of RustNet, including command-line options, keyboard controls, filtering, sorting, and understanding connection lifecycle.

## Table of Contents

- [Running RustNet](#running-rustnet)
- [Command-line Options](#command-line-options)
- [Keyboard Controls](#keyboard-controls)
- [Filtering](#filtering)
- [Sorting](#sorting)
- [Process Grouping](#process-grouping)
- [Network Statistics Panel](#network-statistics-panel)
- [Interface Statistics](#interface-statistics)
- [Connection Lifecycle & Visual Indicators](#connection-lifecycle--visual-indicators)
- [Logging](#logging)

## Running RustNet

Packet capture requires elevated privileges on most systems. See [INSTALL.md](INSTALL.md) for detailed permission setup instructions.

**Quick start:**

```bash
# Run with sudo (works on all platforms)
sudo rustnet

# Or grant capabilities to run without sudo (see INSTALL.md for details)
# Linux example (modern kernel 5.8+):
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon=eip' /path/to/rustnet
rustnet
```

**Basic usage examples:**

```bash
# Run with default settings
# macOS: Uses PKTAP for process metadata
# Linux/Other: Auto-detects active interface
rustnet

# Specify network interface
rustnet -i eth0
rustnet --interface wlan0

# Linux: Monitor all interfaces simultaneously
rustnet -i any

# Filter out localhost connections (already filtered by default)
rustnet --no-localhost

# Show localhost connections (override default filtering)
rustnet --show-localhost

# Set UI refresh interval (in milliseconds)
rustnet -r 500
rustnet --refresh-interval 2000

# Disable deep packet inspection
rustnet --no-dpi

# Enable reverse DNS lookups to show hostnames
rustnet --resolve-dns

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
      --resolve-dns                      Enable reverse DNS lookups to show hostnames
      --show-ptr-lookups                 Show PTR lookup connections (hidden by default with --resolve-dns)
  -l, --log-level <LEVEL>                Set the log level (if not provided, no logging will be enabled)
      --json-log <FILE>                  Enable JSON logging of connection events to specified file
  -f, --bpf-filter <FILTER>              BPF filter expression for packet capture
      --no-sandbox                       Disable Landlock sandboxing (Linux only)
      --sandbox-strict                   Require full sandbox enforcement or exit (Linux only)
  -h, --help                             Print help
  -V, --version                          Print version
```

### Option Details

#### `-i, --interface <INTERFACE>`

Specify which network interface to monitor.

**Default behavior (no `-i` flag):**
- **macOS**: Automatically uses PKTAP for enhanced process metadata (requires sudo)
- **Linux/Other**: Auto-detects the first available non-loopback interface

**Examples:**
```bash
# Default: Auto-detect interface (PKTAP on macOS)
rustnet

# Linux: Monitor all interfaces using the special "any" pseudo-interface
rustnet -i any

# Monitor specific interfaces
rustnet -i eth0          # Monitor Ethernet interface
rustnet -i wlan0         # Monitor WiFi interface
rustnet -i en0           # Monitor macOS primary interface

# Monitor VPN and tunnel interfaces (TUN/TAP support)
rustnet -i utun0         # macOS VPN tunnel (TUN, Layer 3)
rustnet -i tun0          # Linux/BSD VPN tunnel (TUN, Layer 3)
rustnet -i tap0          # TAP interface (Layer 2, includes Ethernet)
```

**TUN/TAP Interface Support:**

RustNet fully supports monitoring VPN and virtual network interfaces:

- **TUN interfaces** (Layer 3): Carry IP packets directly without Ethernet headers
  - Common on VPNs: WireGuard, OpenVPN (tun mode), Tailscale
  - Examples: `utun0-utun9` (macOS), `tun0-tun9` (Linux/BSD)

- **TAP interfaces** (Layer 2): Include full Ethernet frames
  - Used by: OpenVPN (tap mode), QEMU/KVM virtual networks, Docker
  - Examples: `tap0-tap9` (Linux/BSD)

RustNet automatically detects TUN/TAP interfaces and adjusts packet parsing accordingly. The interface type is displayed in the UI status area.

**Platform-specific notes:**
- **macOS**: Without `-i`, PKTAP is used automatically for better process detection. Use `-i <interface>` to monitor a specific interface instead
- **Linux**: Use `-i any` to capture on all interfaces simultaneously (not available on other platforms)
- **TUN/TAP**: Fully supported on all platforms - RustNet detects interface type by name and adjusts parsing
- **All platforms**: If you specify a non-existent interface, an error will show available interfaces

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

#### `--resolve-dns` / `--show-ptr-lookups`

Enable reverse DNS lookups to display hostnames instead of IP addresses.

- **`--resolve-dns`**: Resolves IP addresses to hostnames in the background. Hostnames appear in the connection list (toggle with `d` key) and in the Details tab.
- **`--show-ptr-lookups`**: By default, PTR lookup traffic is hidden when `--resolve-dns` is enabled. Use this flag to show the DNS PTR queries.

**Note**: Resolved hostnames are also included in JSON logs (`destination_hostname`, `source_hostname` fields).

#### `-f, --bpf-filter <FILTER>`

Apply a BPF (Berkeley Packet Filter) expression to filter packets at capture time. This is more efficient than application-level filtering as packets are filtered in the kernel before reaching RustNet.

**Common filter expressions:**

```bash
# Filter by port (matches source OR destination)
rustnet --bpf-filter "port 443"
rustnet --bpf-filter "port 80 or port 8080"

# Filter by destination port specifically
rustnet --bpf-filter "dst port 443"
rustnet --bpf-filter "tcp dst port 80"

# Filter by source port specifically
rustnet --bpf-filter "src port 443"

# Filter by host
rustnet --bpf-filter "host 192.168.1.1"
rustnet --bpf-filter "net 10.0.0.0/8"

# Filter by protocol
rustnet --bpf-filter "tcp"
rustnet --bpf-filter "udp port 53"

# Combine filters
rustnet --bpf-filter "tcp port 443 and host github.com"

# Exclude traffic
rustnet --bpf-filter "not port 22"
```

**Notes:**
- BPF filter syntax follows the pcap-filter(7) format. Invalid filters will cause RustNet to exit with an error. Use `man pcap-filter` for complete syntax documentation.
- **macOS limitation:** BPF filters are incompatible with PKTAP (linktype 149). When you specify a BPF filter on macOS, RustNet automatically falls back to regular interface capture. This means process identification uses `lsof` instead of PKTAP's direct process metadata, which may be slightly less accurate for short-lived connections.

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
- `i` - Toggle Interface Statistics view
- `Enter` - View detailed information about selected connection
- `Esc` - Go back to previous view or clear active filter
- `h` - Toggle help screen

### Actions

- `c` - Copy remote address to clipboard
- `p` - Toggle between service names and port numbers
- `d` - Toggle between hostnames and IP addresses (requires `--resolve-dns`)
- `/` - Enter filter mode (vim-style search with real-time results)
- `x` - Clear all connections and reset statistics (press twice to confirm)
- `r` - Reset view to defaults (clears grouping, sort, and filter)

### Process Grouping

- `a` - Toggle process grouping mode (aggregate connections by process)
- `Space` - Expand/collapse selected process group
- `←` or `h` - Collapse selected group
- `→` or `l` - Expand selected group

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

**Find bandwidth hogs (combined up+down traffic):**
```
Press 's' repeatedly until you see: Down/Up ↓
The connections with highest total bandwidth appear at the top
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
| **Bandwidth (Down/Up)** | ↓ Descending | Sort by **combined up+down** bandwidth (highest first by default) |
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

### Sort Behavior

**Press `s` (lowercase) - Cycle Columns:**
- Moves to the next column in left-to-right visual order
- **Resets to default direction** for that column
- Bandwidth column defaults to descending (↓) to show highest values first
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
2. Press 's' until you see "Down/Up ↓"
3. Now viewing Firefox connections sorted by total bandwidth (up+down combined)
```

### Examples

**Find which process is using the most bandwidth:**
```
1. Press 's' until "Down/Up ↓" appears
2. Top connection shows the highest total bandwidth (up+down combined)
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
1. Press 's' to cycle to "Down/Up ↓"
2. Press 'S' to toggle to "Down/Up ↑" (ascending)
3. Connections with lowest total bandwidth appear first
```

**Sort by application protocol:**
```
1. Press 's' until "Application / Host ↑" appears
2. All HTTPS connections group together, DNS queries together, etc.
3. Useful for finding all connections of a specific type
```

## Process Grouping

RustNet can group connections by process name, providing an aggregated view that makes it easier to see which applications are using your network.

### Enabling Process Grouping

Press `a` to toggle process grouping mode. When enabled:
- Connections are grouped by process name (sorted alphabetically)
- Each group shows aggregated statistics
- Groups can be expanded/collapsed to show individual connections

Press `a` again to return to the flat (ungrouped) connection list.

### Grouped View Display

When grouping is enabled, the connection list shows process groups:

```
[+] firefox (12)              TCP: 10 UDP: 2     12.5K↓/1.2K↑
[-] chrome (8)                TCP: 8  UDP: 0     45.2K↓/5.1K↑
  ├── TCP  192.168.1.10:54321  142.250.80.78:443    ESTABLISHED  HTTPS
  ├── TCP  192.168.1.10:54322  142.250.80.78:443    ESTABLISHED  HTTPS
  └── UDP  192.168.1.10:54323  8.8.8.8:53           -            DNS
[+] systemd-resolved (3)      TCP: 0  UDP: 3     0.2K↓/0.1K↑
[+] <unknown> (5)             TCP: 2  UDP: 3     0.5K↓/0.2K↑
```

**Group header format:**
- `[+]` / `[-]` - Collapsed/expanded indicator
- Process name and connection count
- Protocol breakdown (TCP/UDP counts)
- Total bandwidth (download↓/upload↑)

**Expanded connections:**
- Tree-style prefixes (`├──` / `└──`) show hierarchy
- Individual connection details (protocol, addresses, state, application)

### Expanding and Collapsing Groups

| Key | Action |
|-----|--------|
| `Space` | Toggle expand/collapse on selected group |
| `→` or `l` | Expand selected group |
| `←` or `h` | Collapse selected group |

### Navigation in Grouped View

Navigation works the same as in flat view:
- `↑`/`k` and `↓`/`j` move through visible rows (groups and expanded connections)
- `g` jumps to the first row
- `G` jumps to the last row
- `Enter` on a connection opens the Details view

### Unknown Processes

Connections without process information are grouped into a single `<unknown>` group. This typically includes:
- Short-lived connections that closed before process lookup completed
- System-level connections on some platforms
- Connections from restricted processes

### Filtering with Grouping

Filtering works seamlessly with grouping:
1. Press `/` and enter your filter
2. Only groups containing matching connections are shown
3. Expand groups to see which connections matched

### Sorting in Grouped View

When grouping is enabled:
- Groups are sorted alphabetically by process name (A-Z)
- The sort column indicator shows how connections within groups are sorted
- Press `s` to change how connections are sorted within expanded groups

### Reset View

Press `r` to reset all view settings at once:
- Disables process grouping
- Clears any active filter
- Resets sort to default (chronological order)

## Network Statistics Panel

The Network Statistics panel appears on the right side of the interface, below the Traffic panel. It provides real-time TCP connection quality metrics derived directly from packet capture analysis, making it platform-independent across Linux, macOS, Windows, and FreeBSD.

### Available Metrics

**TCP Retransmits**
Detects when a TCP segment is retransmitted due to packet loss or timeout. RustNet identifies retransmissions by analyzing TCP sequence numbers: when a packet arrives with a sequence number lower than expected, it indicates the original packet was lost and is being resent.

**Out-of-Order Packets**
Tracks inbound TCP packets that arrive out of sequence, typically caused by network congestion or multiple routing paths. These packets eventually arrive but in the wrong order, requiring the receiver to buffer and reorder them.

**Fast Retransmits**
Identifies TCP fast retransmit events triggered by receiving three duplicate acknowledgments (RFC 2581). This mechanism allows TCP to detect and recover from packet loss more quickly than waiting for a timeout, improving connection performance.

### Statistics Display Format

The panel shows both **active** and **total** counts for each metric:

```
TCP Retransmits: 5 / 142 total
Out-of-Order: 2 / 89 total
Fast Retransmits: 1 / 23 total
Active TCP Flows: 18
```

- **Active count** (left number): Sum of events from currently tracked connections. This number goes up and down as connections are established and cleaned up.
- **Total count** (right number): Cumulative count since RustNet started. This number only increases and provides historical context.
- **Active TCP Flows**: Number of active TCP connections with analytics data.

### Per-Connection Statistics

When viewing connection details (press `Enter` on a connection), TCP analytics are shown for that specific connection:

```
TCP Retransmits: 3
Out-of-Order: 1
Fast Retransmits: 0
```

These counters are tracked independently for each connection, allowing you to identify problematic connections experiencing packet loss or network issues.

### Use Cases

**Network Quality Monitoring**
A sudden increase in retransmissions or out-of-order packets indicates network congestion, packet loss, or routing issues.

**Connection Troubleshooting**
High retransmit counts on specific connections can identify:
- Unreliable network paths to certain destinations
- Bandwidth-constrained links
- Faulty network hardware or drivers

**Performance Analysis**
Fast retransmit frequency indicates how well TCP is recovering from packet loss without waiting for timeouts.

### Technical Notes

- Statistics are derived from TCP sequence number analysis without requiring packet timestamps
- Analysis works on both outbound and inbound packets
- SYN and FIN flags are properly accounted for in sequence number tracking (each consumes 1 sequence number)
- Only TCP connections show analytics; UDP, ICMP, and other protocols do not have these metrics

## Interface Statistics

RustNet provides real-time network interface statistics across all supported platforms (Linux, macOS, FreeBSD, Windows). Interface stats are displayed in two locations:

### Accessing Interface Statistics

**Overview Tab (Main Screen):**
- Interface stats appear in the right panel below Network Stats
- Shows up to 3 active interfaces with current rates
- Displays: `InterfaceName: X KB/s ↓ / Y KB/s ↑`
- Shows cumulative totals: `Errors (Total): N  Drops (Total): M`

**Interfaces Tab (Detailed View):**
- Press `i` to toggle the Interface Statistics view
- Shows a detailed table of all network interfaces
- Displays comprehensive metrics for each interface

### Statistics Displayed

| Metric | Description | Notes |
|--------|-------------|-------|
| **RX Rate** | Current receive rate (bytes/sec) | Calculated from recent activity |
| **TX Rate** | Current transmit rate (bytes/sec) | Calculated from recent activity |
| **RX Packets** | Total packets received | Cumulative since boot/interface up |
| **TX Packets** | Total packets transmitted | Cumulative since boot/interface up |
| **RX Err** | Receive errors | Cumulative total (not recent) |
| **TX Err** | Transmit errors | Cumulative total (not recent) |
| **RX Drop** | Dropped incoming packets | Cumulative total (not recent) |
| **TX Drop** | Dropped outgoing packets | Cumulative total (not recent) |
| **Collisions** | Network collisions | Platform-dependent availability |

**Important**: Error and drop counters are **cumulative totals** since the system booted or the interface came up, not recent activity. These help identify long-term interface reliability but won't show immediate issues.

### Platform-Specific Behavior

**All Platforms:**
- All counters (bytes, packets, errors, drops) are cumulative from boot/interface up
- Rates (bytes/sec) are calculated from snapshots taken every 2 seconds
- Loopback interface is included for monitoring local traffic

**Windows:**
- Filters out virtual/filter adapters to show only physical interfaces:
  - Excludes: `-Npcap`, `-WFP`, `-QoS`, `-Native`, `-Virtual`, `-Packet` variants
  - Excludes: `Lightweight Filter`, `MAC Layer` interfaces
  - Excludes: Disconnected "Local Area Connection" adapters
- Uses LUID-based deduplication to prevent duplicate interface entries
- Collisions: Always 0 (not available on modern Windows interfaces)

**macOS:**
- Includes data validation to detect corrupt counters on virtual interfaces
- TX Drops: Always 0 (limited availability on macOS)
- Sanitizes error/drop counters if values appear corrupted (>2^31 or errors>packets)

**FreeBSD:**
- TX Drops: Always 0 (not typically available on FreeBSD)
- Uses BSD getifaddrs API with AF_LINK filtering

**Linux:**
- Reads statistics from `/sys/class/net/{interface}/statistics`
- All counters typically available and reliable

### Interpreting the Statistics

**Healthy Interface:**
```
Ethernet: 2.40 KB/s ↓ / 1.96 KB/s ↑
  Errors (Total): 0  Drops (Total): 0
```
Zero or very low error/drop counts indicate a reliable network connection.

**Problematic Interface:**
```
WiFi: 150 KB/s ↓ / 45 KB/s ↑
  Errors (Total): 1089  Drops (Total): 2178
```
High error/drop counts may indicate:
- Signal interference (WiFi)
- Cable issues (Ethernet)
- Network congestion
- Driver or hardware problems

**Note**: Since error/drop counters are cumulative, evaluate them relative to total packets. A few errors out of millions of packets is normal; thousands of errors with low packet counts indicates problems.

### Interface Filtering

**Which Interfaces Are Shown:**
- Interfaces must be operationally "up" OR have traffic statistics
- Loopback interface is included (useful for monitoring local connections)
- Virtual/filter adapters are excluded on Windows (they mirror physical interfaces)

**Overview Tab Filtering:**
- Windows: Shows all active interfaces (NPF device path detected automatically)
- macOS/Linux: Shows interfaces with recent traffic (`rx_bytes > 0 || tx_bytes > 0 || rx_packets > 0 || tx_packets > 0`)
- Special interfaces (`any`, `pktap`): Shows all interfaces with any activity

**Interfaces Tab:**
- Shows all detected interfaces that pass the platform-specific filters
- Sorts to show the currently captured interface first (highlighted)
- Other interfaces appear in alphabetical order

### Use Cases

**Bandwidth Monitoring:**
Monitor real-time bandwidth usage across all network interfaces to identify:
- Which interface is carrying the most traffic
- Bandwidth distribution across WiFi vs Ethernet
- Local traffic volume (loopback interface)

**Reliability Analysis:**
Check cumulative error and drop counters to:
- Identify unreliable network interfaces
- Detect hardware or driver issues
- Compare interface quality over time

**Multi-Interface Systems:**
On systems with multiple network interfaces:
- Compare performance across interfaces
- Monitor VPN tunnel statistics
- Track interface failover behavior

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

### JSON Logging

The `--json-log` option enables structured JSON logging of connection events to a file. Each line is a separate JSON object (JSONL format).

```bash
# Enable JSON logging
sudo rustnet --json-log /tmp/connections.json

# Combine with other options
sudo rustnet -i eth0 --json-log ~/network-events.json
```

**Event types:**
- `new_connection` - Logged when a new connection is first detected
- `connection_closed` - Logged when a connection is cleaned up after becoming inactive

**JSON fields:**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | RFC3339 UTC timestamp |
| `event` | string | Event type (`new_connection` or `connection_closed`) |
| `protocol` | string | Protocol (TCP, UDP, etc.) |
| `source_ip` | string | Local IP address |
| `source_port` | number | Local port number |
| `destination_ip` | string | Remote IP address |
| `destination_port` | number | Remote port number |
| `pid` | number | Process ID (if available) |
| `process_name` | string | Process name (if available) |
| `service_name` | string | Service name from port lookup (if available) |
| `direction` | string | Connection direction (`outgoing` or `incoming`), TCP only when handshake observed |
| `dpi_protocol` | string | Detected application protocol (if DPI enabled) |
| `dpi_domain` | string | Extracted domain/hostname (if available) |
| `bytes_sent` | number | Total bytes sent (connection_closed only) |
| `bytes_received` | number | Total bytes received (connection_closed only) |
| `duration_secs` | number | Connection duration in seconds (connection_closed only) |

**Example output:**

```json
{"timestamp":"2025-01-15T10:30:00Z","event":"new_connection","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","dpi_protocol":"HTTPS","dpi_domain":"example.com"}
{"timestamp":"2025-01-15T10:30:05Z","event":"connection_closed","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","bytes_sent":1024,"bytes_received":4096,"duration_secs":5}
```

**Processing JSON logs:**

```bash
# Pretty-print latest events
tail -f /tmp/connections.json | jq .

# Filter by process
cat /tmp/connections.json | jq 'select(.process_name == "firefox")'

# Count connections by destination
cat /tmp/connections.json | jq -s 'group_by(.destination_ip) | map({ip: .[0].destination_ip, count: length})'
```
