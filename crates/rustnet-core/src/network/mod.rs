//! Networking core: link-layer/IP/transport parsers, deep packet inspection
//! (HTTP, TLS SNI, DNS, SSH, QUIC, NTP, mDNS, LLMNR, DHCP, SNMP, SSDP,
//! NetBIOS), connection merging, GeoIP lookups, OUI vendor resolution,
//! interface-statistics traits, and the shared connection/protocol types.
//!
//! This is the platform-independent, capture-independent analysis layer.
//! Raw packet capture and platform-specific process attribution live in the
//! `rustnet` binary crate (and, in future, dedicated `rustnet-capture` /
//! `rustnet-helper` crates).

pub mod bogon;
pub mod dns;
pub mod dpi;
pub mod geoip;
pub mod interface_stats;
pub mod link_layer;
pub mod merge;
pub mod oui;
pub mod parser;
pub mod protocol;
pub mod services;
pub mod tracker;
pub mod types;
