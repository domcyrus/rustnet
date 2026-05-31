# rustnet-capture

The packet-capture backend of [RustNet](https://github.com/domcyrus/rustnet),
built on `libpcap` / `Npcap` via the [`pcap`](https://crates.io/crates/pcap)
crate.

This crate owns all of RustNet's pcap-based capture:

- network device selection (with sensible defaults that skip virtual/loopback
  adapters),
- BPF-filter setup,
- the macOS **PKTAP** fast path that attaches process metadata to packets,
- TUN/TAP interface handling,
- and a simple [`PacketReader`] that yields raw link-layer frames plus the
  libpcap data-link type (DLT).

## Why a separate crate?

It is intentionally decoupled from the analysis core (`rustnet-core`) and the
`rustnet` application so you can compose them differently:

- pair `rustnet-capture` + `rustnet-core` to build a **headless** tool (e.g. a
  Prometheus exporter) with no terminal UI;
- or swap `rustnet-capture` out for a **bespoke capture path** (for example a
  root-free macOS pktap helper) while still using `rustnet-core` for parsing.

Capture produces bytes; turning those bytes into connections, DPI results, and
GeoIP/DNS lookups is `rustnet-core`'s job.

## License

Apache-2.0
