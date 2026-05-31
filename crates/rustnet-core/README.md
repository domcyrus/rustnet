# rustnet-core

The reusable network-analysis core of [RustNet](https://github.com/domcyrus/rustnet).

`rustnet-core` is the platform-independent, capture-independent layer that
turns bytes into meaningful network information. It has **no dependency on
libpcap, raw sockets, or OS process tables** — it operates on byte slices and
parsed structures, so it can be embedded in any tool that already has packets
to analyze.

## Features

- **Packet parsing** for Ethernet, Linux SLL/SLL2, PKTAP, raw IP, and TUN/TAP
  link layers, plus IPv4/IPv6, TCP, UDP, ICMP, and IGMP.
- **Deep packet inspection** for HTTP, HTTPS/TLS (SNI extraction), DNS, SSH,
  QUIC, NTP, mDNS, LLMNR, DHCP, SNMP, SSDP, NetBIOS, and more.
- **Connection merging** — fold parsed packets into long-lived connection
  state with protocol-aware lifecycle tracking and TCP analytics
  (retransmissions, out-of-order, fast-retransmit).
- **GeoIP** lookups against MaxMind GeoLite2 databases.
- **Reverse DNS** with background async resolution and caching.
- **OUI vendor** and **service-name** resolution from baked-in datasets (no
  runtime files required — the data is embedded at compile time).

## Layout

Everything lives under the [`network`] module and is re-exported at the crate
root, so both `rustnet_core::network::types` and `rustnet_core::types` resolve
to the same place.

## Status

The public API is currently `0.x` and may change between minor versions while
the workspace split stabilizes.

## License

Apache-2.0
