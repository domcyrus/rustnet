# Changelog

All notable changes to RustNet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Headless Mode**: `--headless` runs without the TUI, with optional
  `--duration` and shared `--filter` syntax. Versioned snapshots stream as
  JSONL by default, while `--output json` emits one final snapshot. Stdout is
  reserved for machine-readable output. A bounded asynchronous writer prevents
  blocked consumers from delaying shutdown, while runtime capture and critical
  worker failures emit terminal error state and return a nonzero status.
  Connection IDs remain stable through archival and distinguish reused
  endpoints, traffic rates have explicit bytes-per-second field names, and
  timed-out workers retain a `stopping` terminal status
- **Reusable Connection Filters**: the complete filter language now lives in
  `rustnet-core`, with the existing TUI path retained as a compatibility
  re-export for future headless frontends
- **Inline Connection Health**: connection rows now show compact TCP
  retransmit/out-of-order, QUIC Retry/version, and transactional UDP
  retry/timeout badges, with a severity-first Health sort. The Details
  Transport Health card marks the counters behind the badge with their
  letters, e.g. `TCP Retransmits (R)` and `Out-of-Order (O)` (#583)
- **VPN Traffic Detection**: identify WireGuard and OpenVPN connections through
  packet signatures, including OpenVPN over UDP and TCP (#581)
- **Host Socket Inventory**: the new Host tab shows TCP LISTEN sockets, UDP
  BOUND endpoints, TCP state totals, observed RTT, process owners, and the
  detailed interface table on Linux, macOS, FreeBSD, and Windows
- **State-Aware Status Bar**: the Overview footer highlights active process
  grouping and history modes and shows whether Space will expand or collapse
  the selected process group

### Changed
- **Frontend Modules**: startup and the TUI loop now live in library modules;
  headless orchestration, schema projection, and output handling are separate
  modules. Overlapping JSON, PCAP, sidecar, and PCAPNG destinations are rejected
  before existing output data can be truncated
- **Runtime Lifecycle Foundation**: privileged capture and process attribution
  are prepared synchronously before sandboxing, while all long-lived workers
  start through a typed post-sandbox handoff and stop under one owned,
  bounded supervisor
- **Staleness Cue**: idle connection rows now show a stripe at their left
  edge and a removal countdown in the bandwidth column from halfway through
  their timeout (previously 75%), both running yellow to red as cleanup
  nears, while the rest of the row softens toward gray
  instead of recoloring whole rows, so Health, RTT, and State keep their
  colors and stale rows stay distinct from gray historic rows on dark
  terminals
- **Responsive System Sidebar**: Traffic now appears before the static Security
  details, which collapse to the sandbox status when terminal height is limited
- **Contextual Help Overlay**: Help now opens above the active tab and only
  shows controls and concepts relevant to that view. The tab bar now contains
  the five application views, with direct shortcuts `1` through `5`
- **Internal Deduplication**: duplicated helpers, fixtures, and workflow steps
  were consolidated across the workspace, removing about 2,000 lines with no
  intended change in behaviour. Small visible differences: truncated names in
  the connection table, Activity tab, and filter chip no longer leave a space
  before the ellipsis, GeoIP lookups also skip multicast, reserved,
  benchmarking, documentation, and discard addresses, hostnames stuck in a
  pending DNS state are retried after 30 seconds, a connection superseded by
  a new SYN is archived with its cached rates zeroed like an expired one, the
  sandbox report uses one wording for a failed root uid drop on every
  platform and, on builds without Landlock, for the success case as well, the
  standalone aarch64 and Android static build workflows are removed since the
  release workflow already produces those binaries, and dispatching the
  release workflow with `skip_downstream` now also skips the crates.io,
  Docker, COPR, PPA, and OBS publish jobs so a backfill cannot republish
- **Release Backfills**: a re-run of the release workflow no longer overwrites
  assets that are already on the release unless `overwrite_assets` is set,
  since Chocolatey, Scoop, and the AUR binary package pin checksums of the
  published files

- **Acronym Casing**: the Details header chip reads `RTT` instead of `rtt`
  and PCAPNG export errors spell the format in uppercase

### Fixed
- **Windows Address Discovery**: collect IPv4, IPv6, and subnet broadcasts
  through IP Helper without loading the Npcap capture driver
- **Loss and Export Accounting**: queue backpressure drops are reported
  separately from libpcap and interface drops, partial batches drain during
  shutdown, and classic PCAP output remains bound to its securely pre-opened
  file descriptor
- **macOS Host Tab SYN_RCVD**: sockets that `lsof` reports as `SYN_RCVD` now
  show as SYN received instead of an unknown state

- **Bogus "unknown" Process Group on Linux**: a process that exited while
  RustNet scanned `/proc` was recorded under the literal name `unknown`, which
  showed up as its own process group next to the real `<unknown>` bucket and,
  with eBPF attribution, overrode the correct name the kernel had captured at
  socket creation. Such a process is now skipped instead (#590)
- **TCP Window Size Per Direction**: the Details Transport Health card kept a
  single window slot that every segment overwrote, so the value flipped
  between the local and remote advertised windows. Both are now shown (`↓`
  local, `↑` remote), in bytes only when the captured handshake proved the
  window scale. Without it the scale is unknowable from the wire, so the row
  reads `unknown (no handshake)` rather than a raw header field that stands
  for anything up to 16384 times its value; the Details help and USAGE explain
  it (#589)
- **TCP Analytics for a Connection's First Packet**: the packet that creates a
  connection now reaches the TCP analytics. For a connection this host
  initiates that packet is its own SYN, the only carrier of the local
  window-scale option, so windows could never be reported in bytes even with
  the whole handshake captured (#589)
- **Duplicate ACK False Positives**: a repeated ACK only counts as a duplicate
  when this host has data outstanding and the advertised window is unchanged
  (RFC 5681), so an idle connection's keepalives and the peer's window updates
  no longer inflate the counter or report a fast retransmit on a connection
  that never retransmitted. A RST no longer overwrites the last advertised
  window with its meaningless zero (#589)
- **Default Npcap Installations on Windows**: RustNet now finds Npcap in its
  standard `System32\Npcap` directory, so WinPcap API-compatible mode is no
  longer required. `--help` and `--version` also work without Npcap installed
- **Attribution of Pre-Existing Connections on Linux**: connections that were
  already open before RustNet started keep their process name after privilege
  reduction, including root services when RustNet runs with file capabilities
  on Linux 5.11 and newer. A one-shot BPF task-file inventory and the
  privileged procfs scan feed a validated fallback shown as the "startup
  snapshot" match quality (#575)

### Removed
- **Ubuntu 25.10 (Questing) PPA**: the series reached end of life and
  Launchpad rejects new uploads for it, so the PPA build matrix and install
  docs drop it. Already-published questing packages stay in the PPA archive

## [1.6.0] - 2026-08-20

### Added
- **Light Background Detection**: at startup rustnet asks the terminal for its
  background color (OSC 11, Unix only) and, on a light background, darkens the
  ANSI Gray muted/label text tiers to DarkGray, which were nearly unreadable on
  white; the per-process identity tints darken likewise. Terminals that stay
  silent past a 150 ms timeout keep the theme unchanged, and explicit
  `[theme.overrides]` values are never touched (#563)
- **Theme Contrast Warning**: config file color overrides that leave a
  foreground/background pair below 3:1 contrast now print a startup warning.
  Only pairs the override touches are judged, so the built-in palettes are
  never second-guessed, and the colors are never altered. Body text is the
  terminal's own foreground, so pairs involving it cannot be measured (#563)
- **Truecolor Detection on Direct-Color Terminals**: `TERM=*-direct` entries
  advertise 24-bit color without setting `COLORTERM`, and are no longer
  downgraded to ANSI-16 (#563)
- **Config File Under sudo**: `sudo rustnet` now reads the invoking user's
  config rather than root's, resolving their home from the passwd database
  the same way the privilege drop resolves `SUDO_UID`. A config not owned by
  that user is refused, since the read happens with root privileges (#563)
- **New Theme Presets**: `--theme` gains `catppuccin-mocha`, `tokyo-night`,
  `gruvbox`, and `nord` truecolor themes with ANSI fallback (#563)
- **Config File**: optional `~/.config/rustnet/config.toml` sets the theme and
  per-color overrides; `--theme` takes precedence (#563)
- **Passive DNS Attribution**: connections without an SNI or HTTP Host header
  (encrypted QUIC, plain TCP/UDP) are now tagged with a hostname inferred from
  DNS responses observed on the wire within the last 10 seconds, shown as a
  dimmed `~name` in the Remote column and as an Attributed Name row with source
  and age in the Details tab; attributed names match the hostname filters and
  free-text search. Event-driven cache in `rustnet-core`, no per-packet
  lookups; works without reverse DNS (#553)
- **LLMNR Response Time**: UDP LLMNR lookups now show their query-to-first-
  response time in the Details Transport Health card. Pairing reuses the DNS
  transaction tracker, scoped to the local socket so multicast queries match
  unicast replies, and stamps the timing on both connection rows. Pending
  queries share the existing 10s expiry and hard cap. `rustnet-core` API note:
  `LlmnrInfo` gained `txid`, while `Connection` and `IngestOutcome` gained
  `llmnr_response_time` (#552)
- **Headless Example**: `examples/headless.rs` shows the library-crate
  pairing without the TUI: capture, parsing, connection tracking, process
  attribution, interface stats, and sandboxing, printing connection
  summaries to stdout. ROADMAP.md documents the remaining headless
  workstream (#550)
- **NetBIOS Response Time**: UDP Name Service and Datagram Service requests now
  show response time and the latest response status in Details. Pairing uses the
  16-bit transaction ID plus the local socket and service, so broadcast requests
  match replies from individual hosts, and the round trip is shown on both the
  broadcast request row and the responder's connection. WACK packets keep the
  request pending until its final response, and pending requests have a 10s
  expiry and hard cap (#538)
- **Ubuntu 22.04 LTS (Jammy) PPA**: The PPA now also builds for Ubuntu 22.04
  LTS using its backported `rustc-1.89` toolchain, covering Linux Mint 21.x
  and Pop!_OS 22.04. Install docs now list the supported derivatives and the
  Pop!_OS `apt-manage` command (#534)
- **Ubuntu 24.04 LTS (Noble) PPA**: The PPA now also builds for Ubuntu 24.04
  LTS using its backported `rustc-1.89` toolchain, which makes the documented
  `add-apt-repository` install work on Ubuntu 24.04 and Linux Mint 22.x.
  Install docs updated accordingly (#533)
- **DNS Query Name in Details**: The Details tab's DNS card now shows the
  queried domain as `DNS Query` alongside the query type and response IPs.
  The name was already parsed from query and response packets but only used
  for filtering and the Overview protocol column. The card also flags NODATA
  answers: a NOERROR response whose answer section holds no record of the
  queried type (e.g. an HTTPS-type lookup for a name with only A/AAAA
  records) shows `DNS Answer: no data` instead of silently omitting the
  response rows. The claim follows RFC 2308: truncated (TC) responses,
  referrals (NS-without-SOA authority), and answer sections that do not
  parse completely leave the flag unset rather than reporting a false
  "no data". `rustnet-core` API note: `DnsInfo` gained a `nodata` field,
  a breaking change for code constructing that struct with a literal (#532)
- **LAN Device Identification**: The Details tab's Network Context card shows
  Local MAC and Remote MAC rows with the OUI vendor (e.g. "Apple, Inc.") for
  addresses the neighbor cache has resolved, learned passively from observed
  ARP (IPv4) and NDP (IPv6) traffic. NDP messages are trusted only at hop
  limit 255 (RFC 4861), fragmented NDP is ignored (RFC 6980), and messages
  carrying any malformed option are discarded whole (RFC 4861 §7.1.1). Since
  neither protocol crosses routers, normally only on-link addresses (LAN
  devices and the gateway) populate; randomized MACs are labeled "locally
  administered". The cache holds up to 4096 neighbors — when full, entries
  idle for 30+ minutes are swept out to make room — and the clear-connections
  action resets it. `rustnet-core` API note: `ProtocolState::Icmp` gained an
  `ndp_neighbor` field, a breaking change for code constructing or
  exhaustively matching that variant (#530, #531)
- **Default Gateway Marker**: Connections whose remote endpoint is the host's
  default gateway (the local router) are now marked. The Overview Remote
  column appends `(gw)` when it fits, the Details tab annotates the remote
  address with `(gateway)`, and JSONL logs gain `remote_is_gateway` (sidecar)
  and `destination_is_gateway` (event log) keys, emitted only when true.
  Gateways are read from the OS routing table (`/proc/net/route` and
  `/proc/net/ipv6_route` on Linux, a `PF_ROUTE` sysctl dump on macOS/FreeBSD,
  `GetIpForwardTable2` on Windows) and refreshed with the local-address
  snapshot, so VPN or network changes are picked up (#529)
- **NTP RTT**: NTP client connections now show the latest request→response
  round trip in the Details Transport Health card, along with the server
  stratum. Polls pair with responses through the originate timestamp echo
  (RFC 5905), so daemons polling several servers stay distinct. Pending
  requests are bounded (hard cap plus 10s expiry) like DNS queries (#527)
- **STUN RTT**: STUN connections now show the latest request→response round
  trip in the Details Transport Health card, paired by the 96-bit transaction
  ID that retransmits reuse. Pending requests are bounded (hard cap plus 10s
  expiry) like DNS queries (#526)
- **Ping RTT**: ICMPv4 and ICMPv6 echo connections now show their latest RTT
  in the Overview RTT column and the Details Transport Health card. Requests
  and replies are paired by identifier and sequence number using per-packet
  capture timestamps, so overlapping or reordered exchanges from commands such
  as `ping 8.8.8.8 -i .2` remain distinct. Loopback pings are timed too, and
  inbound echo flows skip the RTT row since only the remote sender can measure
  it. Pending requests expire after 10 seconds and have a hard cap (#525)
- **DNS Response Time**: Unicast UDP DNS connections now show a transport
  metric in the Details Transport Health card instead of "No transport metrics
  for this protocol". Queries and responses are paired by their 16-bit
  transaction ID using capture timestamps, the latest completed round trip is
  shown as `DNS Response Time`, and the card also surfaces the last response
  code (NOERROR, NXDOMAIN, SERVFAIL, ...). Pending queries are bounded (hard
  cap plus 10s expiry), so floods cost samples, not memory. mDNS/LLMNR
  first-response timing is a possible follow-up (#523)
- **Cross-Platform Process Lineage**: The Details tab shows up to four parent
  processes for each attributed connection on Linux, macOS, Windows, and
  FreeBSD. JSONL exports include each ancestor's PID, name, executable path,
  start time, and whether the chain was truncated (#520)
- **Per-Connection RTT**: Every TCP connection now carries a live round-trip
  estimate for its whole lifetime, not just a one-shot handshake RTT. An
  outbound data segment is timed until the ACK that covers it, with Karn's
  algorithm discarding samples around retransmissions, and the samples feed an
  RFC 6298 style smoothed value. The Overview table gains a sortable RTT
  column (descending by default, so the slowest connections surface first),
  the Details Transport Health card shows `Live RTT` next to `Initial RTT`,
  and JSON event logs plus the PCAP sidecar gain `rtt_ms`. QUIC connections
  keep their handshake RTT, since QUIC ACKs are encrypted on the wire. Data
  round trips also feed the Graph tab's aggregate RTT, which previously only
  saw new-connection handshakes (#515)
- **Capture Failure Reporting**: Capture startup and runtime failures are retained in
  application state and shown as a persistent status-bar error with restart and quit
  guidance, instead of the TUI running on silently after capture stopped. The status
  bar grows a second row when the message and hint do not fit on one (#497)
- **Rich Process Attribution**: `ProcessLookup::get_process_attribution()` returns a
  `ProcessAttribution` carrying TGID, PPID, effective UID/GID, executable path,
  process lineage, and match quality instead of only `(pid, name)`. `MatchQuality`
  records how a connection was matched, so a relaxed wildcard or listener guess is
  no longer indistinguishable from a proven 4-tuple hit. On Linux the eBPF backends
  carry the kernel-recorded identity through unchanged and resolve process metadata
  in user space; the enhanced cache stores the full result, so metadata and match
  quality survive the first lookup. Every platform implements the rich lookup
  directly (#505, #513)
- **Process Identity, User, and Match Quality in the UI and Exports**: Connections now
  carry the owning process's PPID, executable path, effective UID/GID, and how
  confidently the attribution matched. The Attribution card in the Details pane
  repeats PID, shows PPID, and resolves user/group names with numeric fallbacks. It
  appears only when a backend actually resolved something, so platforms that cannot
  supply a field show nothing rather than a permanent placeholder. A relaxed
  wildcard or listener match renders in the warning color instead of passing for a
  proven one. The JSONL sidecar gains `process_ppid`, `process_executable`,
  `process_uid`, `process_gid`, and `attribution_match`; PCAPNG packet comments gain
  `ppid=`, `uid=`, and `attr=` but deliberately omit the executable path, which would
  repeat in every packet block. Executable paths are interned behind an `Arc`, so
  bulk connection snapshots stay allocation-free. Long paths shorten from the middle at render time
  (`/nix/store/…/bin/hello`), keeping the location prefix and the basename visible,
  and a leading `$HOME` renders as `~`; click-to-copy still yields the full
  path (#506, #511, #512, #513)
- **Rich macOS Process Attribution**: PKTAP keeps its kernel-provided per-packet PID
  and process name, marks the result as an exact PKTAP attribution, and uses libproc
  to add the PPID, executable path, and effective UID/GID. The lsof fallback
  requests and parses numeric UIDs, resolves executable paths through libproc, and
  reports exact, wildcard-address, or listener match quality. Packet-seeded PKTAP connections now
  receive one rich-enrichment pass without making permanently unavailable optional
  fields hot-loop retries (#510, #513)
- **Rich FreeBSD Process Attribution**: `sockstat` ownership is enriched through
  native `KERN_PROC_PID` and `KERN_PROC_PATHNAME` sysctl queries with PPID,
  effective UID/GID, and executable path. Process details are cached by PID for
  each socket-table refresh (#513)

### Changed
- **Library Crates 0.5.0**: the workspace library crates are released as
  0.5.0: `rustnet-core`, `rustnet-capture`, `rustnet-host`, and the new
  `rustnet-sandbox`, carrying the breaking API changes noted in this
  section's entries
- **Scrollbar**: the thumb is now a thin accent-colored bar on the outer edge
  of its column instead of a full block in the terminal foreground, and the
  track rule is gone, so the bar reads as a cue rather than a second vertical
  line beside the data (#563)
- **`--theme classic` Renamed to `vivid`**: the name now describes the colors
  rather than the provenance. It is the same ANSI-16 palette as `muted` with
  the chrome colored: yellow headings and keys, magenta borders. `classic` is
  no longer accepted (#563)
- **Status Bar Rebuilt Around Priority**: the footer now shows the active
  tab's context actions on the left and a fixed `h help  q quit` cluster
  pinned right. The cluster is reserved before any context action is placed,
  so quit never falls off the edge; when the terminal is too narrow to spell
  the actions out, the labels go first and the keys stand alone. Tab
  navigation hints are gone, since the numbered tab bar already advertises
  them, and the exhaustive keymap lives on the Help tab. Trailing actions
  are dropped one at a time to keep the remaining labels readable, and only
  a very narrow terminal falls back to bare keys. Keys are bright text on
  the terminal background rather than a reverse-video band, and Details
  only offers `ctrl-d/u` when the record outgrows its pane (#563)
- **Status Bar Alerts Match the Chrome**: the quit prompt, copy feedback,
  and capture errors now carry their meaning in a bold signal color instead
  of filling the row with a solid yellow, green, or red band. `NO_COLOR`
  keeps the reverse-video band, where it is the only cue available (#563)
- **Copy Hints Follow the Sandbox**: on Linux under the default sandbox the
  clipboard cannot be reached, so the `c copy` hints and the Details
  "click a field to copy" affordance are hidden rather than offering a key
  that can only report an error. `--no-sandbox` restores them (#563)
- **Filtering Is a Mode, Not Four Notices**: the filter input row now shows
  only while a query is being typed. Once confirmed it collapses, leaving the
  query chip in the Connections title and the activity dot on the Overview
  tab, and the status bar returns to actions with `esc clear filter` first.
  While typing, the footer offers only what the filter editor handles, since
  every other key types a character into the query (#563)
- **Connection Table Cues**: the selected row now leads with an accent bar,
  and process names get a stable per-name tint (#563)
- **Tab Bar Status Cues**: the tab row right-aligns the capture interface and
  its link type, with a dot that turns red while capture is failing, and marks
  Overview with a `•` while a filter is active. The active filter query also
  shows next to the connection count in the Connections title. The capture
  cluster drops its link type, then itself, when the tab row gets tight (#563)
- **Details Header Badges**: the Details header shows the connection state as a
  colored pill plus chips for the current rates and RTT, dropping chips
  right to left as the terminal narrows. Scrolled Details and Help panes dim the
  line where the content continues, and long process paths now truncate from the
  left so the binary name stays visible (#563)
- **Loading Shimmer**: the loading screen text shimmers across the accent color
  on truecolor terminals and stays static everywhere else (#563)
- **TUI Restyle**: keycap-style status bar, realigned Help tab, and refined
  bar, scrollbar, and selection styling (#563)
- **Details Tab Application Card Alignment**: every protocol's Application
  card now renders a fixed row set with `-` placeholders instead of rows that
  appear and disappear with data availability; HTTPS shows its four rows even
  before the TLS handshake is parsed, and QUIC's SNI/ALPN rows are no longer
  hidden behind it. ICMP/ICMPv6 and IGMP gain their own cards (message name,
  echo ID/sequence, NDP neighbor, group address), HTTP gains Version, Host,
  and User-Agent rows, and ARP gains an Operation row plus the same
  protocol-colored heading as DPI protocols. SSH version/state and DNS, mDNS,
  and LLMNR response IPs render human-readable instead of Rust debug output,
  and FTP's response code and message merge into one row. DNS, LLMNR, and
  NetBIOS expose their transaction IDs like STUN already did. Transport Health
  drops its duplicate NTP Stratum and STUN Last Message rows; those now live
  only in the Application card (#557)
- **Library Internals Deduplicated and Narrowed**: Removed remaining dead code
  and test-only public API from the workspace crates, narrowed public items
  with no external consumers to crate or module visibility (including
  cfg-gated macOS and Windows internals the Linux lint pass could not see),
  and deduplicated repeated logic: the four Windows socket-table refreshes,
  the macOS/FreeBSD BPF privilege probe, PKTAP and lsof process-name
  normalization, `ParsedPacket` construction, and the Details tab field
  rendering (#556)
- **Dead Library-Crate API Removed**: The workspace crates dropped public API
  nothing in the workspace uses: a never-compiling procfs-only module and
  write-only lookup statistics in `rustnet-host`, the unused thread-id and
  monotonic-timestamp attribution fields, and assorted unused methods and
  write-only fields in `rustnet-core` (including the crate-root flat
  re-exports and the `psh`/`urg` TCP flags) (#551)
- **Interface Stats Moved to rustnet-core**: The per-platform interface
  statistics providers (sysfs on Linux, getifaddrs on macOS/FreeBSD, IP
  Helper on Windows) moved from the binary into `rustnet-core` behind a new
  `interface_stats::create_stats_provider()` composition point, and the
  macOS/FreeBSD getifaddrs walkers now share one implementation (#549)
- **Sandboxing Moved to rustnet-sandbox**: Sandboxing and the root uid drop
  now live in the new dependency-free `rustnet-sandbox` crate with one
  `apply_sandbox` entry point per platform. `--no-sandbox` and
  `--sandbox-strict` now exist on all platforms: FreeBSD honors them for the
  uid drop (previously ignored), macOS builds without Seatbelt honor them
  too, and macOS now reports partial enforcement (e.g. Seatbelt applied but
  uid drop failed) instead of only fully-enforced/not-applied (#548)
- **Unified TLS Handshake Parser**: The HTTPS (TCP) and QUIC DPI paths now
  share one TLS handshake parser. TCP SNI values are validated with the same
  strict hostname rules as QUIC (values containing characters like `/ @ : ?`
  or single-label names are no longer shown), ClientHellos larger than 16 KB
  (e.g. post-quantum key shares) are now parsed on TCP, and the 100-extension
  parsing cap now also applies to QUIC. Invalid older supported-version values
  cannot cause QUIC handshakes to be reported below TLS 1.3 (#546)
- **Shared OUI Database**: The OUI vendor table is now shared between
  packet-processor threads via `Arc` instead of being cloned per thread,
  saving roughly 10 MB of memory (#542)
- **Modern Linux eBPF Attribution Backend**: Process attribution now prefers BPF
  trampoline programs (fentry/fexit) and falls back to legacy kprobes and then procfs,
  choosing the backend from actual BTF, load, and attach results rather than the
  reported kernel version. The preferred backend avoids `perf_event_open(2)`, so
  Debian's `kernel.perf_event_paranoid=3` default no longer blocks eBPF attribution.
  Both BPF backends use CO-RE socket reads and fall through to procfs when target BTF
  is unavailable rather than risking misattribution with fixed offsets. The Statistics
  panel reports the selected backend, a missing optional ICMP hook now degrades only
  ICMP coverage instead of disabling TCP/UDP attribution, and BPF capabilities are
  dropped on the capture workers after privileged initialization (#498)

### Fixed
- **Linux Aggregate Capture Recovery**: Capturing with `-i any` now retries
  transient libpcap "interface disappeared" errors during VPN or other
  interface removal instead of stopping immediately. Named-interface failures
  and persistent errors remain fatal (#559)
- **Details Tab ARP Layout**: ARP connections were exempt from the fixed
  Details layout and dropped the Network Context MAC/attribution rows and the
  whole Attribution card, so Traffic Statistics and the cards below jumped
  when moving between ARP and non-ARP entries. ARP now renders the same
  left-column row set with `-` placeholders, and its MAC rows resolve from
  the neighbor cache like any other on-link connection. The Status and
  Attributed Via ages now share one formatter, so connections closed or idle
  for over an hour show `2h ago` instead of a large minute count (#555)
- **Details Tab Layout Stability**: rows in the Details tab no longer appear
  or disappear with data availability. MAC, Attributed Name/Via, the
  Attribution card's process fields, the Kubernetes card's fields, and the
  inbound Ping RTT row now always render for their connection class, showing
  `-` when unresolved, so labels and the cards below keep fixed positions
  while navigating between connections. Placeholder rows are not
  click-to-copy targets (#554)
- **macOS lsof Attribution UID**: When libproc details resolve, lsof-based
  attribution now reports the process's live effective UID from libproc
  instead of the UID captured in the earlier lsof scan, matching the other
  platforms (#545)
- **Broadcast/Multicast Endpoint Display**: A broadcast or multicast datagram
  sent by a peer (e.g. NetBIOS to 192.168.0.255) used to render its
  destination as a normal-looking Local address. Such endpoints now render as
  `bcast:PORT` / `mcast:PORT` in the Overview table, the Details tab annotates
  the full address with `(broadcast)` / `(multicast)`, and the Scope field
  reports BROADCAST for subnet-directed broadcasts instead of PRIVATE.
  Interface prefixes are now collected alongside local addresses to recognize
  each subnet's broadcast address; recognized broadcasts no longer trigger
  ambiguous-endpoint interface re-enumeration. JSONL logs gain
  `local_addr_kind`/`remote_addr_kind` (sidecar) and
  `source_addr_kind`/`destination_addr_kind` (event log) keys, emitted only
  for non-unicast endpoints (#528)
- **FreeBSD User Names in Connection Details**: Numeric socket-owner UIDs from
  `sockstat` now survive process attribution, so Details can resolve user names
  even when live process metadata is unavailable (#522)
- **Linux User Names in Connection Details**: The Landlock profile now permits
  read-only access to the public NSS account files, so the Details tab resolves
  process UID/GID values to user/group names instead of showing numeric values
  such as `1000:1000` (#519)
- **Comm-Truncated Linux Process Names**: The kernel `comm` field holds at most
  15 bytes, so both the eBPF and procfs backends showed names like
  "chromium-browse". When a name sits at that limit and the resolved
  executable's file name strictly extends it, the executable name now wins
  ("chromium-browse" becomes "chromium-browser"). Shorter names and interpreter
  cases (comm "myscript", exe "python3") are left untouched, so deliberately
  renamed comms keep working (#514)
- **Initial RTT Measured Against The Wrong Clock**: `Initial RTT` in the Details
  pane reported round trips as `0.0ms`. RTT was timed with a clock read taken while
  processing a packet rather than from the packet's capture timestamp, and capture
  hands packets to processing in batches spanning up to 100 packets or 100ms — wide
  enough that a whole handshake usually lands in one batch and gets timed as the
  batch loop's own microseconds. Connections are now stamped with each packet's
  libpcap timestamp, which costs no extra clock reads and also makes RTTs correct
  when a saved pcap is replayed. Separately, RTT could be measured from an inbound
  packet to this host's own reply, which spans no network at all; the clock now
  starts only on a packet leaving this host. This affected TCP as well — any
  connection to a local listener reported a handshake RTT of roughly 60µs (#507)
- **Transport Health On QUIC Connections**: The Details pane labelled every
  connection's Transport Health card with TCP loss counters, so a QUIC flow showed
  `TCP Retransmits`, `Duplicate ACKs`, and `Window Size` sitting empty as if the
  measurement had failed. QUIC encrypts its ACK frames and protects its packet
  numbers, so those counters are unobservable on the wire rather than merely
  unmeasured. QUIC connections now get their own rows — `Idle Timeout` and
  `Connection Close` from the transport parameters and CONNECTION\_CLOSE frame,
  plus a note about the encrypted counters — and `Initial RTT` is filled in from
  the long-header handshake exchange, the QUIC analogue of SYN/SYN-ACK timing.
  Other UDP flows say so instead of showing six blank TCP fields. All variants keep
  the card's height so the dashboard doesn't resize between connections (#507)
- **TCP Transport Health Counters**: `TCP Retransmits` in the Details pane stayed
  at 0 for the life of a connection while `Fast Retransmits` climbed into the
  dozens. Outbound sequence tracking desynchronized permanently the first time a
  segment was missed, so no later retransmission was counted; it now tracks a
  high-water mark that resyncs across gaps. Duplicate-ACK detection also counted
  inbound data segments, which repeat the same ack number throughout any download
  and inflated `Fast Retransmits` on healthy connections. `Duplicate ACKs` now
  reports a lifetime total rather than the length of the run in progress, and
  sequence comparisons use RFC 1982 serial arithmetic so they survive the 32-bit
  wraparound (#501)
- **JSON Outputs After Privilege Drop**: JSON event logs and PCAP sidecars are opened
  before sandboxing and the UID drop and written through retained descriptors, so
  logging no longer stops silently when the target path lives under a directory the
  unprivileged user cannot traverse (for example `/root`). Unopenable outputs now fail
  before terminal setup instead of failing quietly at runtime (#486)
- **eBPF Attribution Correctness**: Fixed TCP accept attribution and UID/GID
  extraction, stored dual-stack `AF_INET6` sockets with IPv4-mapped peers under the
  `AF_INET` key that matches the wire packets, removed a per-thread handoff map that
  leaked on missed kretprobes, and made socket-map cleanup skip unreadable entries
  instead of aborting the sweep and letting the map fill (#498)

### Documentation
- **Roadmap Audit**: Synced completed capabilities and clarified remaining DPI,
  platform, and analysis work (#547)
- **eBPF Install and Troubleshooting**: Documented the fentry/kprobe/procfs backend
  order, BTF and `RLIMIT_MEMLOCK` requirements, and reworked the BPF-denied
  troubleshooting steps now that `perf_event_paranoid` affects only the legacy
  backend (#498)
- **Localized Docs**: Added a Japanese README and synchronized the Simplified Chinese
  README, install, and usage docs (#484)

## [1.5.0] - 2026-07-21

This release makes RustNet Kubernetes-aware: connections can be attributed to their
owning pod and container, and the new native PCAPNG export writes Wireshark-ready
captures with process, DPI, GeoIP, and pod annotations. A new Activity view ranks
processes by traffic, the graphs got a gradient braille overhaul, Windows process
attribution went event-driven with ETW, and rustnet now drops root privileges after
initialization on Linux, macOS, and FreeBSD.

### Added
- **Kubernetes Pod/Container Attribution**: New optional `kubernetes` feature
  (off by default, no extra dependencies) that attributes connections to their
  owning pod and container on a node, including `hostNetwork` pods. Pod, namespace,
  and container appear in the Details pane, JSONL/PCAPNG exports, and the new
  `pod:`, `ns:`, and `container:` filter keywords. The container image enables the
  feature by default (#299, #450)
- **Native Annotated PCAPNG Export**: New `--pcapng-export FILE` writes a
  Wireshark-ready PCAPNG file whose packet comments carry best-effort process, PID,
  direction, DPI/SNI, and GeoIP metadata, preserving libpcap timestamps and original
  packet lengths. The Overview panel reports export progress and annotation stats (#432)
- **Process Activity View**: The Interfaces tab is now a process-focused Activity
  view (key `3`) ranking egress and ingress traffic with 60-second share bars,
  retained totals, connection counts, and top remote peers; `d` flips direction,
  `s` changes the sort metric, and `i` opens the detailed interface table (#465)
- **Gradient Braille Graphs and Adaptive Rendering**: Flow-inspired braille area
  graphs with gradient ramps across the Graph tab, Overview mini graphs, and
  per-connection Details waves, plus a draw-on-demand main loop with event
  coalescing that roughly halves terminal-emulator CPU (#459)
- **Pane Scrolling and Filled Traffic Chart**: Details, Help, and Interfaces tabs
  scroll with mouse wheel and vim keys instead of silently clipping, and the
  traffic chart renders RX/TX as filled areas (#452)
- **Event-driven Windows Process Attribution**: Use kernel network and process ETW
  events to retain connection ownership for short-lived processes, with IP Helper
  polling as reconciliation and fallback. IPv6 UDP ownership is now included (#474)

### Security
- **Drop Root Privileges After Initialization**: Under sudo, rustnet now drops to
  `SUDO_UID`/`SUDO_GID` (or `nobody` for plain root) once capture and eBPF are
  initialized on Linux, macOS, and FreeBSD, so a DPI compromise no longer runs as
  root. Opt out with the new `--no-uid-drop` flag; `--sandbox-strict` fails hard if
  the drop fails. Trade-offs are documented in SECURITY.md (#456, #457, #458)
- **No More `CAP_SYS_ADMIN` Auto-Grant**: DEB/RPM installs no longer grant the
  broad `cap_sys_admin` eBPF fallback capability; on pre-5.8 kernels process
  detection degrades to procfs instead (#431)
- **Hardened File Writes**: Log and capture files are created atomically with
  `O_NOFOLLOW` and mode `0600`, and `lsof`/`sockstat` are invoked by absolute path
  to prevent symlink and `$PATH` attacks (#430)

### Fixed
- **Dynamic local-address detection**: Refresh endpoint-orientation addresses after
  network changes and retry ambiguous unicast packets once. On Windows, supplement
  the IPv4-only adapter data with `GetAdaptersAddresses()` so IPv6 traffic is not
  shown with reversed local and remote endpoints (#475)
- **Transport Payload Length**: Trim the transport slice to the IP datagram length,
  so Ethernet frame padding no longer produces phantom 6-byte payloads, false
  retransmission counts, resurrected closed connections, or DPI misclassification
  from trailing bytes (#479, thanks @0xghost42)
- **Connection Lifecycle**: Reused connection tuples no longer inherit their
  predecessor's process/DPI metadata in PCAPNG annotations or rate history in
  Details; immutable history is preserved across tuple reuse; UI-side expiry no
  longer hides tracked connections; rows stay yellow through the whole warning
  window; and the recently-closed tombstone table keeps a capacity floor for tiny
  archive configs (#469, #470, #473)
- **Grouped Overview Navigation**: Space collapses or expands a process group from
  a child row, and `g`/`G` jump to the first and last visible rows in grouped
  mode (#471)
- **Live Graph Rendering**: Graphs sample and redraw more frequently with stable
  scaling, so waves no longer wobble or flatten after spikes, and the connection
  count graph now shows opened/closed lifecycle activity (#472)
- **Overview Status Polish**: Clarified filtered result counts, kept Statistics
  totals unfiltered with process counts, and added an expiry color gradient with a
  matching Help legend (#466)
- **Stable Details Layout**: The Details tab uses fixed Connection, Network
  Context, Application, and Transport Health cards with placeholder rows, so
  sections no longer shift while navigating (#462)
- **Help Scrollbar**: Restored the inset Help scrollbar and the `Help · ↑/↓ scroll`
  title hint (#460)
- **QUIC DPI**: Parse Retry and Version Negotiation packets correctly, merge CRYPTO
  fragments across coalesced Initial packets (restoring SNI for large ClientHellos),
  and use the right Initial salts for draft/mvfst versions (#453)
- **Protocol Detection Switches**: Correct DPI misclassifications (SIP/RTSP as
  HTTP, SMTP as FTP, WireGuard as BitTorrent uTP), add MQTT QoS 2/AUTH types and
  structural SNMPv3 parsing, fix NetBIOS datagram offsets, and drop non-first IP
  fragments at the parser (#454)
- **DNS Label Parsing**: Reject RFC 1035 reserved label top-bits in
  `parse_question`, matching `skip_dns_name` (#434, thanks @0xghost42)
- **SSH State Detection**: Inspect the final 6-byte packet window, so signatures at
  the end of the payload are no longer missed (#406, thanks @0xghost42)
- **TLS Cipher Names**: Correct six mislabeled ARIA and Camellia cipher-suite
  names (#404, thanks @0xghost42)
- **macOS PKTAP PIDs**: Accept PIDs up to Darwin's 99999 ceiling instead of
  dropping attribution for PIDs at or above 65535 (#415, thanks @0xghost42)
- **eBPF Map Cleanup**: Compare map timestamps against `CLOCK_MONOTONIC` instead of
  wall-clock time, so cleanup no longer flushes the entire map and attribution no
  longer silently falls back to procfs (#451)

### Performance
- **Ratatui Hot Paths**: Cache selected row positions, aggregate Graph tab metrics
  in one borrowed pass, and select only the top process rows instead of sorting
  every process (#461)
- **HTTP Parser**: Drop the per-packet `Vec` allocation in the HTTP start-line
  parser (#402, thanks @0xghost42)

### Internal
- **Library Crates 0.4.0**: `rustnet-core`, `rustnet-capture`, and `rustnet-host`
  are released as 0.4.0 with the new Kubernetes, PCAPNG, and parser APIs
- **CI Auditing**: Replaced cargo-deny with RustSec cargo-audit for CI and
  scheduled supply-chain checks (#464)
- **OUI Database**: Monthly vendor database refresh (#439)
- **Dependencies**: Routine dependency and GitHub Actions updates across the cycle
  (Dependabot)

### Contributors

Special thanks to the contributors in this release:
- [@0xghost42](https://github.com/0xghost42): the transport payload-length fix,
  TLS cipher-suite corrections, SSH and DNS DPI fixes, the PKTAP PID ceiling fix,
  and HTTP parser performance (#402, #404, #406, #415, #434, #479)

## [1.4.0] - 2026-06-16

This release redesigns the TUI around a calmer visual hierarchy and, under the hood,
splits RustNet into a Cargo workspace of reusable library crates. Many of the TUI ideas
came from a detailed UI review by [@joshka](https://github.com/joshka) (Ratatui
maintainer) on our showcase submission
([ratatui/ratatui-website#1118](https://github.com/ratatui/ratatui-website/pull/1118)) —
thanks for the thoughtful feedback!

### Added
- **Theme Presets**: New `--theme` flag. The default `muted` preset keeps a single
  cyan accent and reserves color for signals (state changes, staleness, live
  bandwidth) and addresses; `--theme classic` restores the previous full-color palette (#377)
- **System Sidebar Toggle**: The System panel now has a fixed width and can be
  hidden with the `i` key (auto-hidden on narrow terminals) (#377)
- **Details Continuity Strip**: The Details tab opens with a mini connection table
  of the selected row and its neighbors; `j`/`k` flips through them without leaving
  the tab, following the grouped order when process grouping is enabled (#377)
- **Direct-Jump Tab Shortcuts**: Jump straight to a tab with keys `1`-`5`, with
  bracket cycle aliases (#318, thanks @obchain)
- **Connection List Scrollbar**: A scrollbar appears on the connection list when it
  overflows the viewport (#365)
- **FTP Deep Packet Inspection**: Detect the FTP control channel and extract command
  and response metadata (#266, thanks @0xghost42)
- **DNS / mDNS / LLMNR Response IPs**: Populate `response_ips` from A/AAAA answer
  records and extend the extraction to mDNS and LLMNR responses (#319, #333, #341, thanks @0xghost42)
- **Log Identity Banner**: Emit a program identity banner and the module target on
  every log line for easier diagnostics (#320, thanks @0xghost42)
- **Landlock v6 IPC Scoping** (Linux): Best-effort Landlock that scopes abstract-socket
  and signal IPC on kernels that support it, falling back gracefully on older ABIs (#363)
- **`no_new_privs` Always Set + cargo-deny**: Always set `no_new_privs` at startup, and
  adopt `cargo-deny` for supply-chain and license auditing in CI (#382)
- **openSUSE OBS Release Pipeline**: Automated openSUSE Build Service releases (#356)

### Changed
- **Stable Column Layout**: Column widths depend only on the terminal width — they
  no longer shift while scrolling. Narrow terminals hide low-priority columns
  instead of truncating cells; wide terminals distribute the spare width so the
  table spans the full screen with the bandwidth column flush right (#377)
- **Merged Proto/App Column**: The Protocol column is merged into Application
  ("TCP·HTTPS"), and the status-dot column is gone — staleness now lives entirely
  in the row styling (#377)
- **Custom Tab Bar and Borderless Sections**: Numbered tab bar with an accent
  underline, a single-line filter prompt, and section headers in place of the
  border-box-around-everything look (#377)
- **Dependencies**: Routine dependency and GitHub Actions updates across the cycle
  (Dependabot, ~18 PRs)

### Fixed
- **Process attribution for short-lived and multithreaded processes** (Linux):
  eBPF socket tracking now records the process name (thread-group leader)
  instead of the calling thread's name, so connections from e.g. firefox or dig
  no longer show up as "Socket Thread" or "isc-net-0000"; PID-to-name
  resolution reads `/proc/<pid>/comm` on demand instead of waiting for the
  periodic scan; and new connections are enriched on a fast 250ms tick, so
  process names appear almost immediately instead of after up to 2 seconds (#376)
- **DLT_NULL Link Layer**: Strip the 4-byte address-family header before parsing
  DLT_NULL/loopback captures (#394, thanks @0xghost42)
- **Terminal Restore on Panic**: Restore the terminal via a chained panic hook so a
  panic no longer leaves the terminal in raw mode (#364)
- **Scrollbar Thumb**: The scrollbar thumb now reaches the bottom at max scroll (#366)
- **Landlock `/sys` Access**: Allow read access to `/sys` so interface statistics work
  under the Landlock sandbox (#370)
- **Filter Mode Backspace**: Handle raw backspace characters in filter mode (#335, thanks @iccccccccccccc)
- **eBPF Error Surfacing**: Classify libbpf errors and surface them in the TUI (#255, #258)
- **Native Builds**: Skip cross-compile library paths on native builds (#259)
- **RPM Packaging**: Own the directories and hicolor icon dirs the package creates, and
  require `libcap-progs` on openSUSE so the `%post` `setcap` runs (#357, #358, #359, #360)

### Performance
- **Per-Packet Allocations**: Cut per-packet allocations and snapshot copy-on-write
  copies on the hot path (#380)
- **Core Types**: Add `Protocol::as_str()` and drop per-row/per-filter `to_string`
  allocations (#392, thanks @obchain)
- **Connection Table**: Borrow the process name in `process_text` instead of cloning (#390, thanks @obchain)
- **Sparklines / Parsers**: Single-allocation sparkline getters, fewer redundant
  collects in the HTTP and SSH parsers, and removed redundant clones in the render path
  and sandbox init (#339, #345, #355, thanks @obchain)

### Internal
- **Cargo Workspace Split**: RustNet is now a four-crate workspace — `rustnet-core`
  (packet parsing, protocol/DPI types, link-layer, connection merging, DNS/GeoIP/OUI
  lookups), `rustnet-capture` (libpcap/Npcap capture backend), `rustnet-host`
  (per-connection process attribution), and the `rustnet-monitor` binary. The three
  libraries are now published to crates.io alongside the binary (#367)

### Documentation
- **Simplified Chinese**: Added a Simplified Chinese README translation and translated
  the rest of the docs, plus zh-CN openSUSE Tumbleweed install instructions
  (#263 thanks @whtis, #277 thanks @luojiyin1987, #361)
- **Install / Packaging Docs**: Nix and NixOS instructions and nixpkgs/NixOS-module
  notes, Homebrew core formula pointer, Repology packaging overview, a Mermaid
  architecture diagram, and a PR template with tightened contributor guidelines
  (#264, #270, #281, #285, #286, #311, #332, #369)
- **Ubuntu 26.04 (Resolute) PPA**: Added the Resolute PPA build (#254, #256)

### Contributors

Special thanks to the contributors in this release:
- [@0xghost42](https://github.com/0xghost42) — FTP DPI, DNS/mDNS/LLMNR response-IP
  extraction, the log identity banner, the DLT_NULL fix, and many DPI/eBPF refactors
  (#266, #278, #279, #289, #290, #307, #309, #319, #320, #333, #341, #394)
- [@obchain](https://github.com/obchain) — performance and allocation cleanups across
  the DPI parsers, render path, and core types, plus direct-jump tab shortcuts
  (#292, #294, #296, #301, #303, #317, #318, #327, #339, #345, #355, #390, #392)
- [@iccccccccccccc](https://github.com/iccccccccccccc) — raw backspace handling in filter mode (#335)
- [@whtis](https://github.com/whtis) (HaiTao Wu) — Simplified Chinese README translation (#263)
- [@luojiyin1987](https://github.com/luojiyin1987) (luo jiyin) — Simplified Chinese documentation translation (#277)

## [1.3.0] - 2026-05-05

The headline of this release is a major TUI refresh. The tabs, stats panel, and details view have all been redesigned, with new per-field colors, a status dot, and address scope labels making it easier to read connections at a glance.

### Added
- **TUI Revamp**: Redesigned tabs, stats panel, and details view (#239)
- **Per-field Colors and Status Dot**: New per-field colors, status dot, and magenta panel borders for at-a-glance readability (#241)
- **Address Scope Labels**: Remote addresses are tagged PUBLIC, PRIVATE, etc. in the connection list (#251)
- **Reverse DNS Resolution by Default**: Reverse DNS resolution is now enabled by default. Use the new `--no-resolve-dns` flag to opt out (#245)

### Fixed
- **Sandbox Info on Overview**: Show the full sandbox details on the overview tab (#250)
- **Search Scope and Status Bars**: Scope the `/` search to Overview and tidy the status bars (#229, #230)
- **QUIC Initial Packet Parser**: Bounds-check `token_len` in the Initial packet parser (#244)
- **QUIC Varint Parser**: Bounds-check varint lengths and isolate parser panics (#232)
- **Release Pipeline**: Fix the downstream trigger race and AUR token permissions (#223)

### Changed
- **Demo Recording Automation**: Automate VHS recording for the demo GIF and README screenshots (#247)
- **OUI Vendor Database**: Refreshed IEEE OUI vendor database (#242)
- **Dependencies**: Bumped `rand` (0.8.5 to 0.8.6), `openssl` (0.10.75 to 0.10.78), `zip`, `libbpf-cargo`, and other rust-dependencies and actions group updates (#224, #225, #226, #227, #231, #233, #234, #238, #240, #243)

### Documentation
- **Windows Sandbox Terminology**: Accurate Windows sandbox terminology and roadmap entry (#237)
- **README Polish**: README hero polish, metadata tune-up, and accuracy fixes (#236)
- **Crate and Module Docs**: Expanded crate and module docs and tuned metadata for discoverability (#235)

## [1.2.0] - 2026-04-09

### Added
- **Windows Restricted Token Sandbox**: Drop privileges at startup on Windows using a restricted process token (#206)
- **macOS Seatbelt Sandboxing**: Apply a Seatbelt sandbox profile at startup on macOS, later tightened to restrict filesystem and IPC access (#196, #203)
- **Linux Sandbox Hardening**: Drop Linux capabilities and clear the ambient capability set after startup (#208)
- **Process Privilege in UI**: Show whether a process is privileged in the security section of the TUI (#197)
- **Filter: Exact Port Matching and Regex Support**: Filter syntax supports exact port matches and regex patterns (#195)
- **VLAN Support in PKTAP and SLL/SLL2**: Parse VLAN tags in PKTAP and SLL/SLL2 capture formats (#202)
- **VLAN Header in Layer 3 Extraction**: Account for VLAN headers when extracting layer 3 data (#199, thanks @deepakpjose)
- **IGMP Protocol Parsing**: Recognize and parse IGMP traffic (#209, thanks @deepakpjose)
- **Process Name for Wildcard /proc/net/ Entries**: Resolve process names for wildcard (`0.0.0.0`/`::`) entries in `/proc/net/` (#218, thanks @deepakpjose)
- **CI Supply-Chain Hardening**: Pin GitHub Actions to commit SHAs and verify Npcap installer checksums (#210)
- **Architecture Roadmap**: Added workspace split and macOS privilege separation roadmap docs (#211)

### Fixed
- **Default Interface Selection**: Use the active routing table to pick the default interface (#194, thanks @l1a)
- **Root Detection on Unix**: Use `geteuid()` instead of `getuid()` to detect root (#192, thanks @DeepChirp)
- **Release Pipeline Reliability**: Improved release workflow reliability, gated downstream jobs on `publish-release`, added checksum verification to AUR updates, and documented the no-retag policy (2a38f2d, 795f7a1, 002eb55, 8403a0f)
- **FreeBSD CI Dispatch**: Restrict FreeBSD dispatch to manual triggers only (#201)

### Changed
- **CPU Efficiency Improvements**: Substantial reductions in CPU usage across hot paths — rate calculation moved from per-update to per-refresh (#220), timeouts avoided to improve CPU performance (#213), threads given meaningful names to aid profiling (#212), and allocations reduced in sorting and snapshot paths (#222). Big thanks to [@deepakpjose](https://github.com/deepakpjose) for driving the CPU-efficiency work (#213, #220, #212) — these changes make RustNet noticeably lighter on the CPU.
- **FreeBSD Platform Cleanup**: Refactored FreeBSD platform support code (#205)
- **Dependencies**: Bumped `zip` (8.2.0 → 8.3.0 → 8.5.0), `clap_mangen`, `docker/login-action`, and other rust-dependencies group updates (#198, #200, #214, #216, #219, #221)
- **OUI Vendor Database**: Refreshed IEEE OUI vendor database (#215)

### Contributors

Special thanks to the external contributors in this release:
- [@deepakpjose](https://github.com/deepakpjose) — CPU-efficiency improvements and additional features (#199, #209, #212, #213, #218, #220)
- [@l1a](https://github.com/l1a) — default interface selection via active routing table (#194)
- [@DeepChirp](https://github.com/DeepChirp) — Unix root detection via `geteuid()` (#192)

## [1.1.0] - 2026-03-16

### Added
- **OUI Vendor Lookup for ARP**: Display MAC vendor names for ARP connections using IEEE OUI database (#183)
- **Historic Connections Toggle**: Toggle to show/hide historic (closed) connections (#184)
- **Mouse Support**: Mouse interaction support for TUI navigation (#170)
- **Security Hardening & Packet Stats**: Enhanced security hardening and packet statistics display in TUI (#169)
- **GeoIP City Lookup**: Show city-level geolocation for remote IPs using GeoLite2 City database (#168)
- **Android Build Support**: Native Android builds with static musl linking (#167)
- **Multi-Arch Android Builds**: Added armv7, x86_64, and x86 Android static build targets
- **MQTT Protocol Detection**: Deep packet inspection for MQTT protocol traffic (#161)
- **STUN Traffic Detection**: Detect STUN protocol traffic per RFC 5389/8489 (#160)
- **BitTorrent Traffic Detection**: Detect BitTorrent protocol traffic (#159)
- **ARP Performance Benchmarks**: Added criterion benchmarks for ARP-related operations (#188)

### Fixed
- **Undefined Behavior Fix**: Fix UB issues, remove clippy suppressions, add safety documentation (#187)
- **Light Terminal Readability**: Fix selection highlight unreadable on light terminal themes (#182)
- **Clipboard Warning**: Fix unused variable warning in copy_to_clipboard across platforms (#178)
- **Android Cross-Compilation**: Fix cross-compilation and release upload issues for Android targets (#174)
- **MQTT Detection Accuracy**: Restrict MQTT signature detection to CONNECT packets only (#164)

### Changed
- **Documentation**: Synced docs with implementation, added missing keyboard shortcuts (#190, #157)
- **CI/CD**: Staged release pipeline so downstream jobs wait for builds (#154), added FreeBSD coverage to PR builds (#158)
- **Dependencies**: Bumped chrono, http_req, zip, and various rust-dependencies groups

## [1.0.0] - 2026-02-09

### Added
- **GeoIP Location Support**: Show country codes for remote IPs using GeoLite2 databases with auto-discovery (#151)
- **PCAP Export with Process Attribution**: Export captured packets to PCAP files with a process attribution JSONL sidecar for Wireshark enrichment (#137)
- **eBPF-based ICMP PID Tracking**: Track process IDs for ICMP connections using eBPF on Linux (#136)
- **Process Detection Degradation Warnings**: Show warnings in the UI when process detection falls back to a less accurate method (#128)
- **ARM64 Musl Static Builds**: CI now produces arm64 musl static Linux builds with eBPF support

### Fixed
- **Service Name Precedence**: Corrected ordering when multiple service name sources conflict (#150)
- **Pointer Dereference Safety**: Use `as_ref()` for safer pointer dereference in macOS/FreeBSD interface stats (#147)
- **Clippy Warnings**: Resolve `unnecessary_unwrap` errors flagged by clippy (#144)
- **ICMP Dead Code**: Remove dead code warning in ICMP handling (#138)
- **GitHub Actions Permissions**: Add explicit permissions to all GitHub Actions workflows (#131)
- **Logging Initialization**: Set up logging level before privileges check for earlier diagnostic output (#143)

### Changed
- **SSH Heuristic Tightened**: Tighten SSH packet structure heuristic to reduce false positives (#135)
- **CI Reusable Workflows**: Share build logic via reusable workflow, remove redundant test-static-builds workflow
- **Chocolatey Automation**: Trigger Chocolatey package publish on release automatically
- **Code Alignment**: Refactoring and code alignment improvements (#149)
- **Dependencies**: Updated libbpf-rs to 0.26, bumped clap, time, zip, lru, and libc
- **Documentation**: Clarified RustNet vs Wireshark positioning, added PowerShell font troubleshooting, added JSON logging to feature comparison, added bandwhich to acknowledgments (#129, #130, #132, #133)

## [0.18.0] - 2026-01-07

### Added
- **Process Grouping**: Expandable tree view to group connections by process (`a` to toggle grouping, `Space` to expand/collapse)
- **Traffic Visualization Graph Tab**: New Graph tab with real-time network traffic graphs and bandwidth visualization (press `Tab` to cycle through tabs)
- **Network Health Visualization**: Health indicators in Graph tab showing connection quality metrics
- **Reverse DNS Hostnames**: Display reverse DNS names in Details tab and filter PTR traffic (`--resolve-dns` to enable, `d` to toggle display)
- **BPF Filter Support**: New `--bpf-filter` option for custom packet capture filtering (e.g., `--bpf-filter "port 443"`)
- **Clear All Connections**: New hotkey (`x`) to clear all tracked connections
- **Enhanced JSON Logging**: Added pid, process_name, service_name fields to JSON log output
- **New DPI Protocols**: NTP, mDNS, LLMNR, DHCP, SNMP, SSDP, NetBIOS protocol detection with enhanced ARP display
- **Static Musl Builds**: Linux static binary builds using musl for better portability
- **Platform-Specific Help**: CLI help now shows platform-specific options

### Fixed
- **macOS BPF Filter**: Skip PKTAP when BPF filter is specified to avoid conflicts
- **Linux Clipboard**: Handle clipboard access blocked by Landlock sandbox gracefully
- **Interface Stats**: Use safer pointer dereference in interface statistics

### Changed
- **FreeBSD Builds**: Moved to separate rustnet-bsd repository for native builds
- **CI Improvements**: Homebrew formula auto-update on release, AUR workflow on publish
- **Dependencies**: Updated ratatui to 0.30.0, various dependency updates
- **Documentation**: Added contribution guidelines, Chocolatey and Arch Linux installation instructions

## [0.17.0] - 2025-12-07

### Added
- **Landlock Sandbox for Linux**: Filesystem and network sandboxing for enhanced security
  - Restricts filesystem access to `/proc` only after initialization
  - Network sandbox blocks TCP bind/connect on kernel 6.4+
  - Drops `CAP_NET_RAW` capability after pcap handle is opened
  - New CLI options: `--no-sandbox` and `--sandbox-strict`
  - Comprehensive security documentation in SECURITY.md
- **eBPF Thread Name Resolution**: Resolve eBPF thread names (e.g., 'Socket Thread') to main process names (e.g., 'firefox')
  - Uses periodic procfs PID cache for resolution
  - Falls back to eBPF name for short-lived processes
- **AUR Package Automation**: Automated Arch Linux AUR package publishing workflow

### Changed
- **Platform Code Reorganization**: Restructured platform-specific code into cleaner module hierarchy
  - `src/network/platform/linux/` - Linux-specific code with eBPF and sandbox subdirectories
  - `src/network/platform/macos/` - macOS-specific code
  - `src/network/platform/freebsd/` - FreeBSD-specific code
  - `src/network/platform/windows/` - Windows-specific code
- **QUIC DPI Simplification**: Unified SNI extraction helpers and simplified QUIC protocol handling

### Fixed
- **Test Determinism**: Made RateTracker tests deterministic with injectable timestamps

## [0.16.1] - 2025-11-22

### Fixed
- **Cross-Compilation**: Fixed eBPF build issues when cross-compiling to non-Linux platforms
  - Made `libbpf-cargo` an optional build dependency
  - Fixed `build.rs` to check TARGET environment variable instead of host platform
  - Prevents Linux-specific dependencies from being built for FreeBSD, macOS, and Windows
- **FreeBSD Build**: Switched from cross-compilation to native FreeBSD VM builds
  - Uses `vmactions/freebsd-vm` for native FreeBSD compilation
  - Eliminates cross-compilation sysroot and library linking issues
  - Ensures FreeBSD builds work reliably with native package manager

## [0.16.0] - 2025-11-22

### Added
- **Network Interface Statistics**: Real-time monitoring of network interface statistics across all platforms
  - Cross-platform support for Linux, macOS, Windows, and FreeBSD
  - Display of interface-level metrics including packets sent/received, bytes transferred, and errors
  - Platform-specific implementations optimized for each operating system
  - New interface statistics module with dedicated platform handlers

### Changed
- **Link Layer Parsing**: Refactored link layer parsing into modular components
  - Separated link layer types (Ethernet, Linux SLL, Raw IP, TUN/TAP, PKTAP)
  - Improved packet parsing architecture for better maintainability
  - Enhanced support for various network interface types

### Fixed
- **Windows Interface Stats**: Fixed interface statistics collection on Windows platforms
  - Improved reliability of Windows network adapter statistics
  - Better handling of Windows-specific network interfaces
- **macOS Interface Stats**: Platform-specific improvements for macOS interface statistics
  - Enhanced accuracy of macOS network interface metrics
  - Better integration with macOS network stack

## [0.15.0] - 2025-10-25

### Added
- **Ubuntu PPA Packaging**: Official Ubuntu PPA repository for easy installation on Ubuntu/Debian-based distributions
  - Automated GitHub Actions workflow for PPA releases
  - Support for multiple Ubuntu versions

### Changed
- **Bandwidth Sorting**: Changed bandwidth sorting to use combined up+down total instead of separate up/down sorting
  - Simpler sorting behavior: press `s` once to sort by total bandwidth
  - Display still shows "Down/Up" with individual values
  - Arrow indicator shows when sorting by combined bandwidth total
- **Packet Capture Permissions**: Removed CAP_NET_ADMIN and CAP_SYS_ADMIN requirements
  - Uses read-only packet capture (non-promiscuous mode)
  - Reduced security footprint with minimal required capabilities

### Fixed
- **Bandwidth Rate Tracking**: Improved accuracy and stability of bandwidth rate calculations
  - More consistent rate measurements
  - Better handling of network traffic bursts

## [0.14.0] - 2025-10-12

### Added
- **eBPF Enabled by Default on Linux**: eBPF support is now enabled by default on Linux builds for enhanced performance
  - Provides faster socket tracking with reduced overhead
  - Includes CO-RE (Compile Once - Run Everywhere) support
  - Graceful fallback to procfs when eBPF is unavailable
- **JSON Logging for SIEM Integration**: New JSON-structured logging output for security information and event management systems
  - Enables integration with enterprise monitoring and security platforms
  - Structured log format for easier parsing and analysis
- **TUN/TAP Interface Support**: Added support for TUN/TAP virtual network interfaces
  - Enables monitoring of VPN connections and virtual network devices
  - Expands interface compatibility for complex network setups
- **Fedora COPR RPM Packaging**: Official Fedora COPR repository for easy installation on Fedora/RHEL-based distributions

### Fixed
- **High CPU Usage on Linux**: Eliminated excessive procfs scanning causing high CPU utilization
  - Optimized process lookup frequency and caching strategy
  - Significantly reduced system resource consumption during monitoring

### Changed
- **Build Dependencies**: Bundled vmlinux.h files to eliminate network dependency during builds
  - Improves build reliability and offline build capability
  - Reduces external dependencies for compilation
- **Documentation**: Restructured documentation into focused files with improved musl static build documentation

## [0.13.0] - 2025-10-04

### Added
- **Windows Process Identification**: Implemented full process lookup using Windows IP Helper API
  - Uses GetExtendedTcpTable and GetExtendedUdpTable for connection-to-process mapping
  - Resolves process names via OpenProcess and QueryFullProcessImageNameW
  - Supports both TCP/UDP and IPv4/IPv6 connections
  - Implements time-based caching with 2-second TTL for performance
  - Migrated from winapi to windows crate (v0.59) for better maintainability
- **Privilege Detection**: Pre-flight privilege checking before network interface access
  - Detects insufficient privileges on Linux, macOS, and Windows
  - Provides platform-specific instructions (sudo, setcap, Docker flags)
  - Shows errors before TUI initialization for better visibility
  - Detects container environments with Docker-specific guidance

### Fixed
- **Packet Length Calculation**: Use actual packet length from IP headers instead of captured length
  - Extracts Total Length field from IP headers for accurate byte counting
  - Fixes severe undercounting for large packets (NFS, jumbo frames)
  - Resolves issues with snaplen-limited capture buffers

### Changed
- **Documentation**: Updated ROADMAP.md and README.md with Windows process identification status and Arch Linux installation instructions

## [0.12.1] - 2025-10-02

### Changed
- **Build Configuration**: Improved crate metadata for crates.io publishing
  - No functional changes to the binary or runtime behavior
  - Enhanced package configuration for better crate ecosystem integration

## [0.12.0] - 2025-10-01

### Added
- **Vim-style Navigation**: Jump to beginning of connection list with `g` and end with `G` (Shift+g)
- **Table Sorting**: Comprehensive sorting functionality for all connection table columns
  - Press `s` to cycle through sortable columns (Protocol, Local Address, Remote Address, State, Service, Application, Bandwidth ↓, Bandwidth ↑, Process)
  - Press `S` (Shift+s) to toggle sort direction (ascending/descending)
  - Visual indicators with arrows and cyan highlighting on active sort column
  - Sort by download/upload bandwidth to find bandwidth hogs
  - Alphabetical sorting for text columns
- **Port Display Toggle**: Press `p` to switch between service names and port numbers display
- **Connection Navigation Improvements**: Enhanced navigation with better visual cleanup indication
- **Localhost Filtering Control**: New `--show-localhost` command-line flag to override default localhost filtering

### Fixed
- **Windows Double Key Issue**: Fixed duplicate key event handling on Windows platforms
- **Windows MSI Runtime Dependencies**: Added startup check for missing Npcap/WinPcap DLLs
  - Displays helpful error message with installation instructions when DLLs are missing
  - Added winapi dependency for Windows DLL detection
  - Updated README with runtime dependency information
- **Linux Interface Selection**: Fixed "any" interface selection on Linux
  - Improved interface detection and validation
  - Better error handling for interface configuration
- **Package Dependencies**: Removed unnecessary runtime dependencies (clang, llvm) from RPM and DEB packages
  - Reduces installation footprint and dependency conflicts
- **Docker Build**: Removed armv7 architecture from Docker builds for improved stability

### Changed
- **Documentation**: Updated roadmap and README with new features and keyboard shortcuts

## [0.11.0] - 2025-09-30

### Added
- **Docker Support with eBPF**: Docker images now include eBPF support for enhanced performance
  - Multi-architecture Docker builds (amd64, arm64)
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

[Unreleased]: https://github.com/domcyrus/rustnet/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/domcyrus/rustnet/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/domcyrus/rustnet/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/domcyrus/rustnet/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/domcyrus/rustnet/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/domcyrus/rustnet/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/domcyrus/rustnet/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/domcyrus/rustnet/compare/v0.18.0...v1.0.0
[0.18.0]: https://github.com/domcyrus/rustnet/compare/v0.17.0...v0.18.0
[0.17.0]: https://github.com/domcyrus/rustnet/compare/v0.16.1...v0.17.0
[0.16.1]: https://github.com/domcyrus/rustnet/compare/v0.15.0...v0.16.1
[0.15.0]: https://github.com/domcyrus/rustnet/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/domcyrus/rustnet/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/domcyrus/rustnet/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/domcyrus/rustnet/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/domcyrus/rustnet/compare/v0.11.0...v0.12.0
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
