<p align="center"><strong>English</strong> | <a href="USAGE.zh-CN.md">简体中文</a></p>

# Usage Guide

This guide covers detailed usage of RustNet, including command-line options, keyboard controls, filtering, sorting, and understanding connection lifecycle.

## Table of Contents

- [Running RustNet](#running-rustnet)
- [Command-line Options](#command-line-options)
- [Keyboard Controls](#keyboard-controls)
- [Mouse Controls](#mouse-controls)
- [Filtering](#filtering)
- [Sorting](#sorting)
- [Process Grouping](#process-grouping)
- [Network Statistics Panel](#network-statistics-panel)
- [Process Activity](#process-activity)
- [Host Socket Inventory](#host-socket-inventory)
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
sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' /path/to/rustnet
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

# Pick a color theme (muted, vivid, catppuccin-mocha, tokyo-night, gruvbox, nord)
rustnet --theme tokyo-night

# Disable reverse DNS lookups (enabled by default)
rustnet --no-resolve-dns

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
  -i, --interface <INTERFACE>
          Network interface to monitor
      --no-localhost
          Filter out localhost connections
      --show-localhost
          Show localhost connections (overrides default filtering)
  -r, --refresh-interval <MILLISECONDS>
          UI refresh interval in milliseconds [default: 500]
      --no-dpi
          Disable deep packet inspection
  -l, --log-level <LEVEL>
          Set the log level (if not provided, no logging will be enabled)
      --json-log <FILE>
          Enable JSON logging of connection events to specified file
      --headless
          Run without the terminal UI and stream connection events as JSON lines to stdout (log output goes to stderr)
      --snapshot-interval <SECONDS>
          Emit a snapshot event with the full connection table every SECONDS seconds (headless only)
      --filter <QUERY>
          Only stream connections matching QUERY, using the same syntax as the interactive / filter (headless only)
      --pcap-export <FILE>
          Export captured packets to PCAP file for Wireshark analysis
      --pcapng-export <FILE>
          Export captured packets to annotated PCAPNG file for Wireshark analysis
  -f, --bpf-filter <FILTER>
          BPF filter expression for packet capture (e.g., "tcp port 443"). Note: Using a BPF filter disables PKTAP (process info falls back to lsof)
      --no-resolve-dns
          Disable reverse DNS resolution for IP addresses (enabled by default; shows hostnames instead of IPs)
      --show-ptr-lookups
          Show PTR lookup connections in UI (hidden by default when DNS resolution is enabled)
      --no-color
          Disable all colors in the UI (also respects NO_COLOR env var)
      --theme <PRESET>
          Color theme: muted (default), vivid, catppuccin-mocha, tokyo-night, gruvbox, nord. Overrides the theme set in the config file (~/.config/rustnet/config.toml) [possible values: muted, vivid, catppuccin-mocha, tokyo-night, gruvbox, nord]
      --geoip-country <PATH>
          Path to GeoLite2-Country.mmdb database. Auto-discovered from: ./resources/geoip2, $XDG_DATA_HOME/rustnet/geoip, ~/.local/share/rustnet/geoip, /usr/share/GeoIP, /usr/local/share/GeoIP, /opt/homebrew/share/GeoIP, /var/lib/GeoIP
      --geoip-asn <PATH>
          Path to GeoLite2-ASN.mmdb database (same search paths as --geoip-country)
      --geoip-city <PATH>
          Path to GeoLite2-City.mmdb database (same search paths as --geoip-country; superset of Country: provides city name and postal code in addition to country)
      --no-geoip
          Disable GeoIP lookups entirely
      --no-sandbox
          Disable sandboxing (on Linux, PR_SET_NO_NEW_PRIVS is still set)
      --sandbox-strict
          Require full sandbox enforcement or exit
      --no-uid-drop
          Keep running as root instead of dropping to SUDO_UID/SUDO_GID (or nobody) after initialization. Keeping root lets the lsof fallback attribute other users' processes when PKTAP is unavailable
  -h, --help
          Print help
  -V, --version
          Print version
```

Builds compiled with the optional `kubernetes` feature (including the official Docker image) additionally expose `--kubernetes <MODE>`. See [`--kubernetes`](#--kubernetes-mode-optional-feature) below.

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

# Windows: use the adapter's friendly name; it is resolved to the
# \Device\NPF_{GUID} device automatically
rustnet -i Ethernet
rustnet -i "Wi-Fi"

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
- **Default (500ms)**: Smooth live graphs and responsive updates
- **High-traffic networks (1000-2000ms)**: Reduce CPU usage on busy networks
- **Low-end systems (2000-3000ms)**: Reduce load on resource-constrained machines

#### `--no-dpi`

Disable Deep Packet Inspection (DPI). This reduces CPU usage by 20-40% on high-traffic networks but disables:
- HTTP host detection
- HTTPS/TLS SNI extraction
- DNS query/response detection
- SSH version identification
- QUIC protocol detection

Useful for performance-constrained environments or when application-level details aren't needed.

#### `--no-resolve-dns` / `--show-ptr-lookups`

Reverse DNS lookups are **enabled by default**: IP addresses are resolved to hostnames in the background and shown in the connection list (toggle with the `d` key) and in the Details tab.

- **`--no-resolve-dns`**: Disable reverse DNS resolution entirely. The connection list shows IP addresses only and no PTR queries are issued.
- **`--show-ptr-lookups`**: PTR lookup traffic is hidden by default. Use this flag to show the DNS PTR queries generated by the resolver.

**Note**: Resolved hostnames are also included in JSON logs (`destination_hostname`, `source_hostname` fields).

#### `--theme <PRESET>`

Select the color theme preset:

- **`muted`** (default): A restrained palette with one cyan accent. Addresses
  keep calm colors (remote = blue, local = cyan); everything else uses color
  only for *signals*: transitional connection states, staleness (a removal
  stripe and countdown running yellow to red while the row softens to gray),
  and live bandwidth.
- **`vivid`**: The same ANSI-16 palette as `muted`, but the chrome itself takes
  color: yellow headings and keys, magenta borders, and a distinct color per
  column.
- **`catppuccin-mocha`**, **`tokyo-night`**, **`gruvbox`**, **`nord`**:
  Truecolor renditions of the popular palettes. On terminals without truecolor
  support they fall back to the nearest ANSI-16 colors.

```bash
# Color the chrome too, with a distinct color per column
rustnet --theme vivid

# Use a truecolor theme
rustnet --theme tokyo-night
```

The theme can also be set in an optional config file at
`~/.config/rustnet/config.toml` (`$XDG_CONFIG_HOME/rustnet/config.toml` when
set; `%APPDATA%\rustnet\config.toml` on Windows), so the flag is not needed on
every run. The `[theme.overrides]` table optionally replaces individual colors:

```toml
[theme]
name = "tokyo-night"

[theme.overrides]
accent = "#ff9e64"
border = "darkgray"
```

Override values are ANSI color names (`red`, `lightblue`, `darkgray`, ...) or
`#rrggbb` hex. Valid keys: `accent`, `ok`, `warn`, `err`, `info`, `special`,
`muted`, `faint`, `text`, `heading`, `label`, `key`, `border`, `rx`, `tx`,
`rx_wave`, `tx_wave`, `selection_bg`, `selection_fg`, `status_bg`.

Precedence: `--theme` on the command line overrides the config file, which
overrides the `muted` default. A missing config file is fine; an unreadable or
invalid file, or a bad override value, prints a warning at startup and falls
back to the defaults. Overrides that leave a foreground/background pair below
3:1 contrast also print a startup warning, though the colors are used as
given. Under `sudo rustnet`, the config of the user who ran sudo is read
rather than root's, and the file must be owned by that user.

On light terminal backgrounds, ANSI Gray (the muted/label text tier of the
`muted` and `vivid` presets) is nearly unreadable, so at startup rustnet asks
the terminal for its background color (an OSC 11 query, Unix only) and darkens
those gray tiers to ANSI DarkGray when the background reports as light; the
per-process name tints darken likewise. Terminals that do not answer the query
keep the theme as-is, and explicit `[theme.overrides]` values are never
touched.

Related: `--no-color` disables all colors entirely (also honors the `NO_COLOR`
environment variable).

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

Log files are created in the `logs/` directory with timestamp: `rustnet_YYYY-MM-DD_HH-MM-SS.log`. In [headless mode](#headless-mode) the log goes to stderr instead.

#### `--headless`

Run without the terminal UI and stream connection events as JSON lines to stdout. Startup, sandboxing, uid drop, and enrichment are the same as in the TUI; only the output differs. With `--log-level`, log lines go to stderr instead of a file under `logs/`. See [Headless Mode](#headless-mode) for the event format.

```bash
# Stream every connection event, pretty-printed
sudo rustnet --headless | jq .
```

#### `--snapshot-interval <SECONDS>`

Headless only. Emit a `snapshot` event with the full connection table every `SECONDS` seconds (a positive integer), in addition to the per-connection events. The first snapshot is written after one full interval. Requires `--headless`.

```bash
sudo rustnet --headless --snapshot-interval 10
```

#### `--filter <QUERY>`

Headless only. Stream only the connections matching `QUERY`, using the same syntax as the interactive `/` filter (see [Filtering](#filtering)): keyword terms such as `port:443` or `process:curl`, free text, and `/regex/` values, combined with spaces (AND). The query is checked before capture starts; a keyword with no value (`port:`) or an invalid regex exits with an error. Requires `--headless`.

```bash
sudo rustnet --headless --filter 'port:443'
sudo rustnet --headless --filter 'proto:udp dport:53'
```

#### `--kubernetes <MODE>` (optional feature)

Attribute connections to their owning Kubernetes pod and container. This flag only exists in builds compiled with the `kubernetes` cargo feature: the official Docker image (`ghcr.io/domcyrus/rustnet`) ships with it enabled, while native installs (cargo, Homebrew, deb/rpm) leave it off.

**Modes:**

- `auto` (default): Enable attribution only when RustNet itself is running inside a pod
- `on`: Always enable (e.g. when running directly on a node)
- `off`: Disable attribution

When active, RustNet maps each connection's PID to its pod UID and container ID via cgroups (`/proc/<pid>/cgroup`) and resolves human-readable pod and container names from the kubelet log directories (`/var/log/containers`, `/var/log/pods`). This is runtime-agnostic and needs no CRI socket or kubelet credentials. Pod-owned sockets are attributed even when RustNet runs with `hostNetwork: true`, because the per-PID socket tables are network-namespace aware.

Attribution is surfaced in:

- The **Details tab**, as a "Kubernetes" section showing pod name, namespace, pod UID, container name, and container ID
- **JSON logs** (`--json-log`), the `--headless` event stream and its `snapshot` records, and the `--pcap-export` sidecar JSONL, as a `kubernetes` object per connection event
- **PCAPNG packet comments** (`--pcapng-export`), as `pod=`, `ns=`, `pod_uid=`, `container=`, and `container_id=` fields
- The `pod:`, `ns:`, and `container:` [filter keywords](#keyword-filters)

**Running on a cluster:** the easiest way to use this is the [kubectl-rustnet](https://github.com/domcyrus/kubectl-rustnet) plugin (`kubectl krew install rustnet`). It launches RustNet as an ephemeral debug pod on a node using the official image, mounts the kubelet log directories read-only for name resolution, and cleans up the pod on exit. Since the plugin runs RustNet inside a pod, the default `auto` mode enables attribution without any flags.

```bash
# On a Kubernetes cluster: run as an ephemeral debug pod via the plugin
kubectl rustnet --node worker-3

# Native build with the feature enabled
cargo build --release --features kubernetes

# Force attribution on outside a pod (e.g. directly on a node)
rustnet --kubernetes on
```

## Keyboard Controls

### Navigation

- `↑` or `k` - Navigate up in connection list
- `↓` or `j` - Navigate down in connection list
- `g` - Jump to first connection (vim-style)
- `G` (Shift+g) - Jump to last connection (vim-style)
- `PageUp` or `Ctrl+B` - Move up by one page
- `PageDown` or `Ctrl+F` - Move down by one page

### Views and Tabs

- `Tab` or `]` - Next tab
- `Shift+Tab` or `[` - Previous tab
- `1` / `2` / `3` / `4` / `5` - Jump directly to Overview / Details / Activity / Graph / Host
- `Enter` - View detailed information about selected connection
- `Esc` - Go back to previous view or clear active filter
- `h` - Toggle a help overlay containing controls for the active tab

The help overlay keeps the active tab visible underneath it and only lists
controls and concepts that apply to that tab. Tab navigation (`Tab`,
`Shift+Tab`, `1`-`5`) stays available while the overlay is open, and a mouse
click anywhere dismisses it.

### Actions

- `c` - Copy remote address to clipboard
- `p` - Toggle between service names and port numbers
- `d` - Toggle hostnames/IPs on Overview or Egress (TX)/Ingress (RX) on Activity
- `/` - Enter filter mode (vim-style search with real-time results)
- `x` - Clear all connections and reset statistics (press twice to confirm)
- `t` - Toggle display of historic (closed) connections
- `i` - Toggle the System info sidebar on Overview or open interface details on Host
- `r` - Reset view to defaults (clears grouping, sort, filter, and historic)

### Process Grouping

- `a` - Toggle process grouping mode (aggregate connections by process)
- `Space` - Expand/collapse selected process group
- `←` - Collapse selected group
- `→` or `l` - Expand selected group

### Sorting

- `s` - Cycle through sort columns (left-to-right order)
- `S` (Shift+s) - Toggle sort direction (ascending/descending)

### Exit

- `q` - Quit the application (press twice to confirm)
- `Ctrl+C` - Quit immediately

## Mouse Controls

RustNet has full mouse support. Mouse capture is enabled automatically — all interactions described below work out of the box.

### Overview Tab

| Action | Effect |
|--------|--------|
| **Click** on a connection row | Select that connection |
| **Double-click** a connection row | Open the Details tab for that connection |
| **Scroll wheel** over the connection list | Navigate up/down through connections |
| **Click** on a tab name | Switch to that tab |

### Grouped View (press `a` to enable)

| Action | Effect |
|--------|--------|
| **Click** on a group header (`▸`/`▾`) | Select the group |
| **Double-click** a group header | Expand or collapse the process group |
| **Click** on a connection within an expanded group | Select that connection |
| **Double-click** a connection within an expanded group | Open the Details tab for that connection |
| **Scroll wheel** | Navigate through groups and connections |

### Details Tab

| Action | Effect |
|--------|--------|
| **Click** on any field line | Copy the field value to the system clipboard |

Clicking a field copies just the value (not the label). For example, clicking the "Remote Address: 142.250.80.46:443" line copies `142.250.80.46:443` to your clipboard. A confirmation message appears in the status bar for 3 seconds.

Both the "Connection Information" and "Traffic Statistics" panels support click-to-copy.

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

| Keyword | Aliases | Description | Example |
|---------|---------|-------------|---------|
| `port:` | | Exact port match; use `/pattern/` for regex | `port:22` matches only 22; `port:/22/` matches 22, 220, 5522 |
| `sport:` | `srcport:`, `source-port:` | Source port (exact or regex) | `sport:80` matches only source port 80 |
| `dport:` | `dstport:`, `dest-port:`, `destination-port:` | Destination port (exact or regex) | `dport:443` matches only destination port 443 |
| `src:` | `source:` | Source IPs/hostnames | `src:192.168` matches 192.168.x.x |
| `dst:` | `dest:`, `destination:` | Destinations | `dst:github.com` matches github.com |
| `process:` | `proc:` | Process names | `process:ssh` matches ssh, sshd |
| `sni:` | `host:`, `hostname:` | SNI hostnames (HTTPS) and DNS-attributed hostnames | `sni:api` matches api.example.com |
| `service:` | `svc:` | Service names | `service:https` matches HTTPS service |
| `app:` | `application:` | Detected application protocol | `app:ssh` matches SSH connections |
| `state:` | | Protocol states | `state:established` matches established connections |
| `proto:` | `protocol:` | Protocol type | `proto:tcp` matches TCP connections |
| `pod:` | | Kubernetes pod name or UID * | `pod:nginx` matches nginx-86644db9cc-mf5lx |
| `ns:` | `namespace:` | Kubernetes pod namespace * | `ns:kube-system` matches pods in kube-system |
| `container:` | `cont:` | Kubernetes container name or ID * | `container:nginx` matches the nginx container |

\* Requires a build with the `kubernetes` feature and active pod attribution. See [`--kubernetes`](#--kubernetes-mode-optional-feature).

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

### Regex Filters

Wrap any filter value in `/pattern/` to use a regular expression (case-insensitive). Regexes use standard syntax supported by the `regex-lite` crate.

```
/192\.168\.[0-9]+/         # General regex across all fields
port:/22/                  # Ports containing "22" (22, 220, 2200, 5522 …)
sni:/.*github\..*/         # SNI matching github.com, api.github.com, etc.
process:/chrom(e|ium)/     # Chrome or Chromium
```

> **Port matching**: `port:443` is an **exact** match (only port 443). Use `port:/443/` if you want substring/regex behaviour.

### Combining Filters

Combine multiple filters with spaces (implicit AND):

```
sport:80 process:nginx              # Nginx connections from port 80
dport:443 sni:google.com            # HTTPS connections to Google
sport:443 state:syn_recv            # Half-open connections to port 443 (SYN flood detection)
proto:tcp state:established         # All established TCP connections
process:firefox state:quic_connected # Active QUIC connections from Firefox
dport:22 app:openssh                # SSH connections using OpenSSH
state:established app:ssh           # Established SSH connections
```

### Clearing Filters

Press `Esc` to clear the active filter and return to the full connection list.

## Sorting

RustNet provides powerful table sorting to help you analyze network connections. Press `s` to cycle through sortable columns in left-to-right visual order, and press `S` (Shift+s) to toggle between ascending and descending order.

### Quick Start

**Find bandwidth hogs (combined up+down traffic):**
```
Press 's' repeatedly until you see: Bandwidth Total ↓
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
| **Process** | ↑ Ascending | Sort by process name alphabetically |
| **Remote Address** | ↑ Ascending | Sort by remote IP:port |
| **Local Address** | ↑ Ascending | Sort by local IP:port (useful for multi-interface systems) |
| **Location** | ↑ Ascending | Sort by country code (requires GeoIP database) |
| **Service** | ↑ Ascending | Sort by service name or port number |
| **Application** | ↑ Ascending | Sort by detected application protocol (HTTP, DNS, etc.), with TCP/UDP as tie-break |
| **State** | ↑ Ascending | Sort by connection state (ESTABLISHED, etc.) |
| **RTT** | ↓ Descending | Sort by round-trip time (slowest connections first by default) |
| **Health** | ↓ Descending | Sort protocol-aware health signals by severity, then event count |
| **Bandwidth (Rx/Tx)** | ↓ Descending | Sort by **combined up+down** bandwidth (highest first by default) |

Columns hidden at narrow terminal widths stay in the cycle — the active sort is always named in the table's section title.

### Sort Indicators

The active sort column is highlighted with:
- **Cyan color** and **underline** styling
- **Arrow symbol** (↑ or ↓) showing sort direction
- **Table title** showing current sort state

**Visual indicators:**
```
Active column header appears in cyan with underline:
Process │ Remote ↑ │ Local │ Service │ App │ ...
          ^^^^^^^^
          (cyan, underlined, with arrow)

Section title shows current sort:
▎ Active Connections · 42 shown · sort Remote Addr ↑
```

### Sort Behavior

**Press `s` (lowercase) - Cycle Columns:**
- Moves to the next column in left-to-right visual order
- **Resets to default direction** for that column
- Bandwidth, RTT, and Health default to descending (↓) to show the most significant values first
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
2. Press 's' until you see "Bandwidth Total ↓"
3. Now viewing Firefox connections sorted by total bandwidth (up+down combined)
```

### Examples

**Find which process is using the most bandwidth:**
```
1. Press 's' until "Bandwidth Total ↓" appears
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
1. Press 's' to cycle to "Bandwidth Total ↓"
2. Press 'S' to toggle to "Bandwidth Total ↑" (ascending)
3. Connections with lowest total bandwidth appear first
```

**Sort by application protocol:**
```
1. Press 's' until "Application ↑" appears
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

The Overview status bar highlights `a grouped` while this mode is active. It
also promotes the selected group's immediate action to `space expand` or
`space collapse`, including while an individual connection inside that group
is selected.

### Grouped View Display

When grouping is enabled, the connection list shows process groups:

```
▸ firefox (12)                                       TCP:10 UDP:2  12.5K/1.2K
▾ chrome (8)                                         TCP:8 UDP:0   45.2K/5.1K
  ├─ 4101   142.250.80.78:443  192.168.1.10:54321   ESTABLISHED   1.2K/0.3K
  ├─ 4101   142.250.80.78:443  192.168.1.10:54322   ESTABLISHED   0.8K/0.1K
  └─ 4102   8.8.8.8:53         192.168.1.10:54323   UDP_ACTIVE    0.2K/0.1K
▸ systemd-resolved (3)                               TCP:0 UDP:3   0.2K/0.1K
▸ <unknown> (5)                                      TCP:2 UDP:3   0.5K/0.2K
```

**Group header format:**
- `▸` / `▾` - Collapsed/expanded indicator
- Process name and connection count
- Protocol breakdown (TCP/UDP counts)
- Total bandwidth (rx/tx, in the Bandwidth column)

**Expanded connections:**
- Tree-style prefixes (`├─` / `└─`) with the PID (the group header carries the process name)
- The same columns as the flat view (addresses, state, application, bandwidth)

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

The Overview table shows observable connection quality in the **Health**
column. The badge adapts to the protocol:

- `R3/O1` for TCP means three retransmits and one out-of-order packet.
- `R1/V0` for QUIC means one explicit Retry and no Version Negotiation packet.
- `R2/T1` for outgoing DNS, LLMNR, NetBIOS, STUN, or NTP transactions means
  two repeated request IDs and one request that expired unanswered. NTP polls
  carry a fresh transmit timestamp each time, so NTP surfaces timeouts rather
  than retries.

Clean, gradable connections show `ok`. Generic UDP, unsupported protocols, and
transaction rows where no outgoing request was observed show `-`. Double-digit
counts are displayed as `+`, while Details retains the exact counters. The
Details Transport Health card marks the two counters behind the badge with
their letters (`TCP Retransmits (R)`, `Out-of-Order (O)`), so the compact badge
maps back to exact numbers. Health
sorting is severity-first: TCP retransmits and request timeouts rank above
warning-only out-of-order, retry, and version events, then higher counts rank
first.

When viewing connection details (press `Enter` on a connection), TCP analytics are shown for that specific connection:

```
TCP Retransmits: 3
Out-of-Order: 1
Fast Retransmits: 0
```

These counters are tracked independently for each connection, allowing you to identify problematic connections experiencing packet loss or network issues.

**Window Size**
The same card reports each end's last advertised receive window as a pair:
`↓` is the window this host advertised, which bounds inbound data, and `↑` the
one the remote advertised, which bounds outbound data.

```
Window Size  ↓ 137.50 KB · ↑ 1.00 KB
```

Window scaling is negotiated only in the SYN handshake (RFC 7323), so a
connection that was already open when RustNet started reads
`unknown (no handshake)`. The 16-bit header field on its own stands for
anything up to 16384 times its value, so it is reported as unknown rather than
as a size that cannot be acted on. Connections opened while RustNet is running
show byte counts.

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

## Process Activity

The Activity tab derives bounded process traffic totals from active connections and RustNet's existing pool of up to 5,000 retained historic connections. A short-lived uploader remains visible after its socket closes, until its historic connection is evicted or the connections are cleared. Press `3` to open it.

The main process table switches between Egress (TX) and Ingress (RX) and shows:

- Current and peak rates, plus the process share of captured traffic in the selected direction over the rolling 60-second window
- Retained bytes in the selected direction, including active and retained historic connections
- Active and total connection counts
- Unique remote destinations and the highest-volume remote peer
- Process attribution coverage, with unresolved traffic grouped as `Unknown`
- Rolling 60-second process traffic as a percentage of interface traffic in the selected direction

The table adapts to the available terminal width, so narrower terminals hide some columns. Its columns mean:

| Column | Meaning |
|---|---|
| **Process** | Process name and PID. Traffic without process attribution is grouped as `Unknown`. |
| **Pulse** | Relative share of the selected direction's rolling 60-second captured traffic. |
| **TX now / RX now** | Current traffic rate for the process in the selected direction. |
| **Peak TX / Peak RX** | Highest observed current rate while the process remains in the retained Activity view. |
| **60s %** | Process share of all captured process traffic in the selected direction over the rolling 60-second window. |
| **Iface 60s** | Process traffic over 60 seconds as a percentage of the matching interface traffic. A `~` prefix indicates an approximate host-wide comparison for multi-interface capture. |
| **TX 60s / RX 60s** | Captured bytes attributed to the process in the selected direction over the rolling 60-second window. |
| **Retained** | Total bytes across the process's active and retained historic connections in the selected direction. This is bounded retained data, not a lifetime counter. |
| **Conns** | `active/total`, for example `41/66` means 41 active connections and 66 retained connections in total. The total includes active plus recently completed historic connections. |
| **Remote** | Number of unique remote socket endpoints across the retained connections. An endpoint is an IP address plus port, so one host contacted on two ports counts as two remotes. Repeated connections to the same endpoint count once. A `+` suffix means the count exceeded the 256-destination display cap. |
| **Top remote peer** | Remote endpoint with the most retained traffic in the selected direction. |

Traffic Pulse shows the current captured rate, but calculates coverage from captured bytes and interface-counter bytes over the same rolling 60-second window. This avoids the large fluctuations caused by comparing independently sampled instantaneous rates. Coverage divides the captured total by the interface total and caps the displayed percentage at 100%, because slightly different window endpoints or counter visibility can otherwise produce small overages. Both raw totals remain visible for diagnosis. When RustNet captures one named interface, it compares directly with that interface. With multi-interface capture, RustNet compares against a host-wide interface aggregate and prefixes the value with `~` because VPN and virtual interface counters can overlap.

Press `d` to switch between Egress (TX, blue) and Ingress (RX, green), `s` to cycle the Activity sort metric, and `S` to reverse its order. The detailed interface table lives on the Host tab (press `5`, then `i`).

For a quick security review, sort Egress by the rolling or retained byte count, look for an unexpected high-volume process, and inspect its top remote peer. Retained traffic keeps a short-lived uploader visible after its socket closes.

## Host Socket Inventory

Press `5` to open the Host tab. Unlike the Overview connection list, this view reads the operating system's socket table and does not require a packet to have been captured for a row to appear.

The Sockets view includes:

- Counts for TCP LISTEN, ESTABLISHED, opening, closing, and TIME_WAIT states
- The total number of UDP BOUND endpoints
- Average and maximum RTT from connections observed by packet capture
- A table of TCP LISTEN sockets and UDP BOUND endpoints with local address, optional peer, service, PID, and process name

UDP does not have a LISTEN state. Every UDP row represents a local bound endpoint, including endpoints that were bound implicitly by their first send. A connected UDP endpoint may also have a peer.

The inventory refreshes every 5 seconds. Process ownership is best effort because a process can exit during a scan or permissions can hide its details. The socket row remains visible when ownership is unavailable.

| Platform | Socket source |
|---|---|
| Linux | `/proc/net/tcp`, `tcp6`, `udp`, and `udp6`, joined to socket inodes in `/proc/<pid>/fd` |
| macOS | Numeric `lsof` socket inventory, also used for this view while PKTAP supplies packet process metadata |
| FreeBSD | `sockstat -s` for native TCP states plus UDP socket rows |
| Windows | IP Helper owner tables from `GetExtendedTcpTable` and `GetExtendedUdpTable` |

Press `i` for Interfaces and `s` to return to Sockets. Left and right arrow keys switch between the two views.

## Interface Statistics

RustNet provides real-time network interface statistics across all supported platforms (Linux, macOS, FreeBSD, Windows). Interface stats are displayed in two locations:

### Accessing Interface Statistics

**Overview Tab (Main Screen):**
- Interface stats appear in the right panel below Network Stats
- Shows up to 3 active interfaces with current rates
- Displays: `InterfaceName: X KB/s ↓ / Y KB/s ↑`
- Shows cumulative totals: `Errors (Total): N  Drops (Total): M`

**Host Tab (Detailed View):**
- Press `5` for Host, then `i` to open the Interface Statistics view
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
- Rates (bytes/sec) are calculated from snapshots taken every 500ms
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

**Host Interface Details:**
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

### Hostname Display

Hostnames extracted from the connection itself (TLS SNI from HTTPS or QUIC, the HTTP `Host:` header) are shown in the **App** column. The name in the **Remote** column is chosen by priority (toggle hostnames with the `d` key):

1. **DNS-attributed hostname**: rendered as `~name:port` in a dim color when the connection carries no SNI / Host header but a DNS resolution to this IP was observed within the last **10 seconds**
2. **Reverse DNS** (system resolver, unless disabled with `--no-resolve-dns`)
3. **Raw IP address**

The leading `~` glyph signals that the hostname was *inferred* from a DNS response seen on the wire, not extracted from the connection. This is most useful for QUIC sessions after the handshake (where SNI is encrypted) and for plain TCP/UDP connections that carry no hostname-bearing payload. Attribution needs no active lookups, so it works even with `--no-resolve-dns`. The Details tab shows a separate **Attributed Name** row with the full inferred hostname, plus an **Attributed Via** row with the source and observation age (`Captured DNS, 5s ago`) so the provenance is explicit. Attributed names are searchable like any other hostname: both the `sni:` / `host:` / `hostname:` keyword filter and the free-text search match them.

**Caveats** (RustNet learns names by sniffing DNS on the wire):

- **DoH / DoT** (encrypted DNS): no plaintext to observe, no attribution.
- **`/etc/hosts`, NSCD cache, `systemd-resolved` D-Bus API** (`org.freedesktop.resolve1`): no DNS packet is emitted, so attribution is impossible regardless of capture method.
- **Local stub resolvers** (e.g. `systemd-resolved` on `127.0.0.53`): if you only capture a physical interface, you see the stub's upstream queries but not which app talked to the stub. Capture on `lo` as well to see the application side.
- **VPN/WireGuard tunnels**: capture on the tunnel interface (e.g. `utun0`, `wg0`) rather than the underlay so you see plaintext DNS.

### Visual Staleness Indicators

Idle rows announce their cleanup with a stripe and a countdown instead of recoloring the whole row:

| Look | Meaning | Staleness |
|------|---------|-----------|
| **Full color** | Active connection | < 50% of timeout |
| **Stripe + countdown** | Idle, approaching timeout; a `▎` stripe at the left edge of the row and the time left in the ↓/↑ column, e.g. `45s left`, run yellow through orange to red (bold for the final stretch), while Process, Remote, Local, Loc, Service, and App soften toward gray | 50-100% of timeout |
| **Gray** | Historic, closed and archived; `closed` in State, `n/a` in ↓/↑ | after timeout (toggle `t`) |

State, RTT, and Health never fade, so a red retransmit counter on an idle row
is still a real problem. The stripe and the countdown are the only lifecycle
cells that use yellow and red, and the countdown's text says what the color
means, so those hues never recolor a whole row. The fade stops at the muted tier: the faint gray of
historic rows is reserved for closed connections, so on dark and light
terminals alike an idle row keeps its colored stripe, its countdown, and its colored
signal cells while a historic row is uniformly gray.

**Example**: An HTTP connection with a 10-minute timeout will:
- Keep **full color** for the first 5 minutes
- Show a `▎` **stripe** at its left edge and a **countdown** in the ↓/↑ column from 5 to 10 minutes, both turning from yellow to red, while its identifying columns soften
- Be removed at 10 minutes, becoming a gray historic row marked `closed`

This gives you advance warning when a connection is about to disappear from the list.

### Smart Protocol-Aware Timeouts

RustNet adjusts connection timeouts based on the protocol and detected application:

#### TCP Connections
- **HTTP/HTTPS** (detected via DPI): **10 minutes** - supports HTTP keep-alive
- **SSH** (detected via DPI): **30 minutes** - accommodates long interactive sessions
- **Generic established**: **5 minutes**
- **TIME_WAIT**: 30 seconds - standard TCP timeout
- **CLOSED**: 15 seconds - terminal archival grace
- **SYN_SENT, FIN_WAIT, etc.**: 30-60 seconds

#### UDP Connections
- **SSH over UDP**: **30 minutes** - long-lived sessions
- **DNS**: **30 seconds** - short-lived queries
- **Regular UDP**: **60 seconds** - standard timeout

#### QUIC Connections (Detected State)
- **Connected**: **3 minutes** default (or uses idle timeout from transport parameters if available)
- **With CONNECTION_CLOSE frame**: 15 seconds
- **Initial/Handshaking**: 60 seconds - allow connection establishment
- **Draining/Closed**: 15 seconds - terminal archival grace

Every packet resets the idle timer for nonterminal connections. Terminal TCP
and QUIC connections use the time when they first entered their terminal state,
so repeated FIN, ACK, RST, or close packets do not postpone archival.

A new TCP SYN observed against a closing connection starts a new live
generation and archives the previous generation as an immutable historic
record. Delayed teardown-only TCP packets matching a recently archived
terminal connection are ignored for 30 seconds rather than creating a phantom
established row.

### Why Connections Disappear

A connection is removed when:
1. **No packets received** for the duration of its timeout period
2. The connection enters a **closed state** (TCP CLOSED, QUIC CLOSED)
3. **Explicit close frames** detected (QUIC CONNECTION_CLOSE)

**Note**: Rate indicators show decaying traffic based on recent activity. A
connection may show declining bandwidth while it approaches its idle or
terminal timeout. Historic rows show `n/a` for current bandwidth because a
closed connection has no live rate; final byte and packet totals remain
available in Details.

### Historic Connections

By default, connections disappear from the list once they time out or close. Press `t` to toggle **historic connections** mode, which keeps closed connections visible alongside active ones.

While historic connections are visible, the Overview status bar highlights
`t history`. This indicator can be active alongside the process-grouping
indicator.

**How it works:**

When a connection is cleaned up, it is archived into a historic connections pool (up to 5,000 entries; oldest are evicted first). Pressing `t` toggles their visibility:

- **Active connections** display normally with standard color indicators
- **Historic connections** appear in **dim gray** to clearly distinguish them from active connections
- **Historic bandwidth** displays as `n/a`; final byte and packet totals remain available
- The table title changes to **"Active + Historic Connections"** when historic mode is on

**Details view:**

Selecting a historic connection and pressing `Enter` shows the usual connection details, plus a **Status** field displaying how long ago the connection was closed (e.g., "Closed (5m ago)").

**Stats panel:**

When historic connections are present, the stats panel shows a separate **"Historic: N"** count below the total active connections.

**Grouped view:**

In process grouping mode (`a`), group headers show the historic connection count separately from the active count when historic mode is enabled.

**Graph tab:**

The graph tab always shows only active connections, even when historic mode is on.

**Resetting:**

- Press `r` to reset all view settings, which also hides historic connections
- Press `x` twice to clear all connections, which also clears the historic pool

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

### Headless Mode

`--headless` runs the capture pipeline without the terminal UI and streams connection events to stdout as JSON lines (JSONL, one object per line). It is meant for piping into `jq` or a log shipper, and for running under a service manager or in a container where there is no TTY.

```bash
# Pretty-print every event
sudo rustnet --headless | jq .

# Destination IPs of HTTPS connections only
sudo rustnet --headless --filter 'port:443' | jq -r '.destination_ip'

# Process and bytes sent for every closed connection, log output discarded
sudo rustnet --headless 2>/dev/null | jq -c 'select(.event=="connection_closed") | {process_name,bytes_sent}'
```

**Startup:** headless mode goes through the same startup sequence as the TUI: privilege check, capture and eBPF initialization, sandboxing, and the root uid drop, followed by the same process attribution, DPI, DNS, and GeoIP enrichment. No terminal is touched. stdout carries only events; the privilege banner and, with `--log-level`, the log lines go to stderr instead of a file under `logs/`, so `rustnet --headless 2>/dev/null` is a clean JSONL stream. Options that only affect the UI (`--theme`, `--no-color`) have no effect.

**Event types:**

| Event | When | Fields |
|-------|------|--------|
| `startup` | Once, as the first line, after the capture device is open and the sandbox is applied | See below |
| `new_connection` | A connection is first seen | Same as [JSON Logging](#json-logging) |
| `connection_closed` | A connection is cleaned up after becoming inactive | Same as [JSON Logging](#json-logging), including `bytes_sent`, `bytes_received`, and `duration_secs` |
| `snapshot` | Every `--snapshot-interval` seconds | See below |

Every line has `timestamp` (RFC3339 UTC) and `event`. The `new_connection` and `connection_closed` lines are the same as the ones `--json-log` writes; their fields are documented under [JSON Logging](#json-logging). A `new_connection` line is emitted when the first packet of a connection is seen, before process attribution, GeoIP, or DPI details are usually available, so consumers that need `pid` or `process_name` should use `connection_closed` or `snapshot` events, or match the lines on their 5-tuple (`protocol`, `source_ip`, `source_port`, `destination_ip`, `destination_port`).

`startup` fields:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | RFC3339 UTC timestamp |
| `event` | string | `startup` |
| `version` | string | RustNet version |
| `pid` | number | Process ID of this RustNet instance |
| `interface` | string | Capture interface (omitted if unknown) |
| `link_type` | string | Link layer of the capture: `Ethernet`, `RawIp`, `LinuxSll`, `LinuxSll2`, `Pktap`, `Tun`, `Tap`, or `Unknown` |
| `sandbox` | string | Sandbox status: `Fully enforced`, `Partially enforced`, `Not applied`, or `Error` (Linux, Windows, and macOS builds with the `macos-sandbox` feature) |
| `process_detection` | string | Process attribution method in use: `eBPF fentry/fexit + procfs`, `eBPF kprobe + procfs`, or `procfs` on Linux; `pktap` or `lsof` on macOS; `windows-etw+iphlpapi` or `windows-iphlpapi` on Windows; `sockstat` on FreeBSD. The value is the one reported at startup, so it can be `initializing...` if attribution was not ready within the startup wait |
| `filter` | string | The `--filter` query (omitted when none) |
| `snapshot_interval_secs` | number | The `--snapshot-interval` value (omitted when none) |

`snapshot` fields:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | RFC3339 UTC timestamp |
| `event` | string | `snapshot` |
| `connections` | array | One object per connection currently in the table, with the same fields as a `new_connection` line minus `timestamp` and `event` |

The snapshot table is the one the TUI shows: localhost connections are excluded unless `--show-localhost` is given, DNS PTR lookups are hidden unless `--show-ptr-lookups` is given, and it is refreshed every `--refresh-interval` milliseconds. The first snapshot is written after one full interval so it reflects real traffic rather than an empty table.

**Filtering:** `--filter QUERY` restricts `new_connection`, `connection_closed`, and the `snapshot` table to connections matching `QUERY`; the `startup` line is always written. The syntax is that of the interactive `/` filter (see [Filtering](#filtering)): keyword terms, free text, and `/regex/` values, combined with spaces (AND). The query is checked before capture starts, so a keyword with no value (`port:`) or an invalid regex fails immediately with an error on stderr.

```bash
# DNS traffic from any process
sudo rustnet --headless --filter 'proto:udp dport:53'

# Firefox connections to any github.com host
sudo rustnet --headless --filter 'process:firefox sni:/github\.com$/'
```

**Backpressure:** stdout is written by a dedicated thread through a queue of 10,000 lines. If the consumer falls behind, events are dropped rather than stalling packet processing; the number of dropped lines is logged as a warning (visible with `--log-level warn` or higher).

**Exiting:**

- `SIGINT` (Ctrl+C), `SIGTERM`, or `SIGHUP` stops the stream, writes out the queued lines, and exits with status 0. On Windows the console control handler is not wired yet, so Ctrl+C or closing the console ends the process without draining the queued lines.
- When the consumer closes the pipe (for example `rustnet --headless | head -n 20`), the next write fails and RustNet exits with status 0.
- A packet capture failure exits with status 1 with the error on stderr.
- An unknown option, a `--snapshot-interval` or `--filter` without `--headless`, or an invalid `--filter` query exits with an error before capture starts.

**Combining with other outputs:** `--json-log FILE` still works alongside `--headless` and receives every `new_connection` and `connection_closed` event, unfiltered; `--filter` only applies to stdout. `--pcap-export` and `--pcapng-export` work as in the TUI.

### JSON Logging

The `--json-log` option enables structured JSON logging of connection events to a file. Each line is a separate JSON object (JSONL format). To stream the same events to stdout instead of a file, see [Headless Mode](#headless-mode).

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
{"timestamp":"2025-01-15T10:30:00Z","event":"new_connection","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","dpi_protocol":"HTTPS (example.com)","dpi_domain":"example.com"}
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

### PCAP Export

The `--pcap-export` option captures raw packets to a standard PCAP file for analysis in Wireshark, tcpdump, or other tools.

```bash
# Export all captured packets
sudo rustnet -i eth0 --pcap-export capture.pcap

# Combine with BPF filter
sudo rustnet -i eth0 --bpf-filter "tcp port 443" --pcap-export https.pcap
```

**Output files:**

| File | Description |
|------|-------------|
| `capture.pcap` | Raw packet data in standard PCAP format |
| `capture.pcap.connections.jsonl` | Streaming connection metadata with process info |

**Sidecar JSONL format** (one JSON object per line, written as connections close):

```json
{"timestamp":"2026-01-17T10:30:00Z","protocol":"TCP","local_addr":"192.168.1.100:54321","remote_addr":"142.250.80.46:443","pid":1234,"process_name":"firefox","first_seen":"...","last_seen":"...","bytes_sent":1024,"bytes_received":8192,"state":"ESTABLISHED"}
```

| Field | Description |
|-------|-------------|
| `timestamp` | When the connection record was written |
| `protocol` | TCP, UDP, ICMP, etc. |
| `local_addr` / `remote_addr` | Connection endpoints |
| `pid` / `process_name` | Process info (if identified) |
| `first_seen` / `last_seen` | Connection timestamps |
| `bytes_sent` / `bytes_received` | Traffic totals |
| `state` | Final connection state |

#### Enriching PCAP with Process Information

Standard PCAP files don't include process information. Use the included `scripts/pcap_enrich.py` script to correlate packets with processes:

```bash
# Install scapy (required)
pip install scapy

# Show packets with process info
python scripts/pcap_enrich.py capture.pcap

# Output as TSV for further processing
python scripts/pcap_enrich.py capture.pcap --format tsv > report.tsv

# Create annotated PCAPNG with process comments (requires Wireshark's editcap)
python scripts/pcap_enrich.py capture.pcap -o annotated.pcapng
```

The annotated PCAPNG embeds process information as packet comments, visible in Wireshark's packet details.

#### Native Annotated PCAPNG Export

The `--pcapng-export` option writes a PCAPNG file directly with RustNet packet comments. This avoids the Python enrichment step when you want to open the capture in Wireshark immediately:

```bash
sudo rustnet -i eth0 --pcapng-export capture.pcapng
```

Packet comments are live best-effort annotations. RustNet waits briefly for process and GeoIP enrichment, then writes the packet even if attribution is still unavailable; packets may still have DPI/SNI, direction, or GeoIP comments without `process=`/`pid=` fields. Under heavy load, packets dropped before the processor stage or dropped by the bounded PCAPNG export queue will not appear in the PCAPNG, so a simultaneous `--pcap-export` file can contain packets missing from the PCAPNG. Packet blocks may be written out of capture order, but they keep their true capture timestamps and Wireshark can sort/display them by time.

Use `--pcap-export` plus `capture.pcap.connections.jsonl` when cleanup-time metadata completeness matters more than a single annotated file.

**Manual correlation:**

```bash
# View packets
wireshark capture.pcap

# View process mappings
cat capture.pcap.connections.jsonl | jq -r '[.protocol, .local_addr, .remote_addr, .pid, .process_name] | @tsv'

# Filter in Wireshark by connection tuple
# ip.addr == 142.250.80.46 && tcp.port == 443
```
