//! Networking core: libpcap-based packet capture, link-layer/IP/transport
//! parsers, deep packet inspection (HTTP, TLS SNI, DNS, SSH, QUIC, NTP,
//! mDNS, LLMNR, DHCP, SNMP, SSDP, NetBIOS), connection merging, GeoIP
//! lookups, OUI vendor resolution, interface statistics, and
//! platform-specific process attribution (procfs / eBPF on Linux, native
//! APIs on macOS, Windows, and FreeBSD).

pub mod bogon;
pub mod capture;
pub mod dns;
pub mod dpi;
pub mod geoip;
pub mod interface_stats;
pub mod link_layer;
pub mod merge;
pub mod oui;
pub mod parser;
pub mod platform;
pub mod privileges;
pub mod protocol;
pub mod services;
pub mod types;
