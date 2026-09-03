//! # rustnet-core
//!
//! The reusable network-analysis core of [RustNet](https://github.com/domcyrus/rustnet):
//! packet parsing, protocol types, deep packet inspection (DPI), link-layer
//! parsers, connection merging, and DNS / GeoIP / OUI lookups.
//!
//! This crate is platform-independent and capture-independent: it operates on
//! byte slices and parsed structures, with no dependency on `libpcap`, raw
//! sockets, or OS process tables. Raw packet capture and platform-specific
//! process attribution live in the `rustnet` binary crate.
//!
//! ## Capabilities
//!
//! - **Packet parsing** for Ethernet, Linux SLL/SLL2, PKTAP, raw IP, and
//!   TUN/TAP link layers, plus IPv4/IPv6, TCP, UDP, ICMP, and IGMP.
//! - **Deep packet inspection** for HTTP, HTTPS/TLS with SNI extraction,
//!   DNS, SSH, QUIC, NTP, mDNS, LLMNR, DHCP, SNMP, SSDP, NetBIOS, and more.
//! - **Connection merging**: fold parsed packets into long-lived connection
//!   state with protocol-aware lifecycle tracking and TCP analytics.
//! - **GeoIP** lookups against MaxMind GeoLite2 databases.
//! - **Reverse DNS** with background async resolution and caching.
//! - **OUI** vendor resolution and **service** name resolution (baked-in
//!   datasets).
//!
//! ## Layout
//!
//! All modules live under [`network`].

pub mod network;
