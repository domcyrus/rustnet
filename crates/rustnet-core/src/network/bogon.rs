//! Classification of an IP address into a routing/usage scope: globally
//! routable ("public"), or one of the RFC-reserved ranges (private, loopback,
//! link-local, multicast, documentation, etc.).
//!
//! Used to label remote endpoints in the UI so internal traffic is visually
//! distinguishable from public-Internet traffic. Pure passive classification:
//! no lookups, no I/O.
//!
//! The set of non-public categories is intentionally small but covers the
//! ranges users care about when scanning a connection list. Stable-Rust
//! `is_*` helpers on `Ipv4Addr` / `Ipv6Addr` only cover a subset, so the
//! checks here are done with explicit bit-mask comparisons to avoid relying
//! on unstable APIs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    Multicast,
    Broadcast,
    Documentation,
    Benchmarking,
    Unspecified,
    Reserved,
    UniqueLocal,
    Discard,
    Ipv4Mapped,
}

impl Scope {
    /// Short, all-caps tag suitable for inline display in a detail panel.
    pub fn label(self) -> &'static str {
        match self {
            Scope::Public => "PUBLIC",
            Scope::Loopback => "LOOPBACK",
            Scope::Private => "PRIVATE",
            Scope::LinkLocal => "LINK-LOCAL",
            Scope::Cgnat => "CGNAT",
            Scope::Multicast => "MULTICAST",
            Scope::Broadcast => "BROADCAST",
            Scope::Documentation => "DOCUMENTATION",
            Scope::Benchmarking => "BENCHMARKING",
            Scope::Unspecified => "UNSPECIFIED",
            Scope::Reserved => "RESERVED",
            Scope::UniqueLocal => "UNIQUE-LOCAL",
            Scope::Discard => "DISCARD",
            Scope::Ipv4Mapped => "IPV4-MAPPED",
        }
    }
}

pub fn classify(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Scope {
    let octets = ip.octets();
    let [a, b, _, _] = octets;

    if ip.is_unspecified() {
        return Scope::Unspecified;
    }
    if a == 127 {
        return Scope::Loopback;
    }
    // RFC 1918
    if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        return Scope::Private;
    }
    if a == 169 && b == 254 {
        return Scope::LinkLocal;
    }
    // RFC 6598 carrier-grade NAT: 100.64.0.0/10
    if a == 100 && (64..=127).contains(&b) {
        return Scope::Cgnat;
    }
    // Documentation: 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2),
    // 203.0.113.0/24 (TEST-NET-3).
    if (a == 192 && b == 0 && octets[2] == 2)
        || (a == 198 && b == 51 && octets[2] == 100)
        || (a == 203 && b == 0 && octets[2] == 113)
    {
        return Scope::Documentation;
    }
    // RFC 2544 benchmarking: 198.18.0.0/15
    if a == 198 && (b == 18 || b == 19) {
        return Scope::Benchmarking;
    }
    if octets == [255, 255, 255, 255] {
        return Scope::Broadcast;
    }
    // 224.0.0.0/4 multicast
    if (224..=239).contains(&a) {
        return Scope::Multicast;
    }
    // 240.0.0.0/4 reserved (excluding the 255.255.255.255 broadcast above)
    if a >= 240 {
        return Scope::Reserved;
    }
    Scope::Public
}

fn classify_v6(ip: Ipv6Addr) -> Scope {
    if ip.is_unspecified() {
        return Scope::Unspecified;
    }
    if ip.is_loopback() {
        return Scope::Loopback;
    }
    let segs = ip.segments();
    // ::ffff:0:0/96 IPv4-mapped
    if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xffff {
        return Scope::Ipv4Mapped;
    }
    // 100::/64 discard prefix (RFC 6666)
    if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
        return Scope::Discard;
    }
    // 2001:db8::/32 documentation
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return Scope::Documentation;
    }
    // ff00::/8 multicast
    if (segs[0] >> 8) == 0xff {
        return Scope::Multicast;
    }
    // fe80::/10 link-local
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Scope::LinkLocal;
    }
    // fc00::/7 unique-local
    if (segs[0] & 0xfe00) == 0xfc00 {
        return Scope::UniqueLocal;
    }
    Scope::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    // The three cases the user explicitly asked for.

    #[test]
    fn rfc1918_10_slash_8_is_private() {
        assert_eq!(classify(v4("10.0.0.1")), Scope::Private);
        assert_eq!(classify(v4("10.255.255.254")), Scope::Private);
        assert_eq!(classify(v4("10.0.0.0")), Scope::Private);
        assert_eq!(classify(v4("10.0.0.0")).label(), "PRIVATE");
    }

    #[test]
    fn ipv4_169_254_slash_16_is_link_local() {
        assert_eq!(classify(v4("169.254.1.1")), Scope::LinkLocal);
        assert_eq!(classify(v4("169.254.255.255")), Scope::LinkLocal);
        assert_eq!(classify(v4("169.254.0.0")).label(), "LINK-LOCAL");
        // Sibling /16 must not match.
        assert_eq!(classify(v4("169.253.1.1")), Scope::Public);
    }

    #[test]
    fn ipv6_fe80_slash_10_is_link_local() {
        assert_eq!(classify(v6("fe80::1")), Scope::LinkLocal);
        assert_eq!(
            classify(v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")),
            Scope::LinkLocal
        );
        assert_eq!(classify(v6("fe80::1")).label(), "LINK-LOCAL");
        // fec0::/10 site-local is deprecated and outside fe80::/10.
        assert_eq!(classify(v6("fec0::1")), Scope::Public);
    }

    // One representative per remaining category.

    #[test]
    fn ipv4_other_categories() {
        assert_eq!(classify(v4("172.16.0.1")), Scope::Private);
        assert_eq!(classify(v4("192.168.1.1")), Scope::Private);
        assert_eq!(classify(v4("172.32.0.1")), Scope::Public); // outside 172.16/12
        assert_eq!(classify(v4("127.0.0.1")), Scope::Loopback);
        assert_eq!(classify(v4("0.0.0.0")), Scope::Unspecified);
        assert_eq!(classify(v4("100.64.0.1")), Scope::Cgnat);
        assert_eq!(classify(v4("100.128.0.1")), Scope::Public); // outside 100.64/10
        assert_eq!(classify(v4("224.0.0.251")), Scope::Multicast); // mDNS
        assert_eq!(classify(v4("239.255.255.250")), Scope::Multicast);
        assert_eq!(classify(v4("255.255.255.255")), Scope::Broadcast);
        assert_eq!(classify(v4("192.0.2.1")), Scope::Documentation);
        assert_eq!(classify(v4("198.51.100.5")), Scope::Documentation);
        assert_eq!(classify(v4("203.0.113.7")), Scope::Documentation);
        assert_eq!(classify(v4("198.18.0.1")), Scope::Benchmarking);
        assert_eq!(classify(v4("240.0.0.1")), Scope::Reserved);
    }

    #[test]
    fn ipv6_other_categories() {
        assert_eq!(classify(v6("::")), Scope::Unspecified);
        assert_eq!(classify(v6("::1")), Scope::Loopback);
        assert_eq!(classify(v6("ff02::1")), Scope::Multicast);
        assert_eq!(classify(v6("fc00::1")), Scope::UniqueLocal);
        assert_eq!(classify(v6("fd00::1")), Scope::UniqueLocal);
        assert_eq!(classify(v6("2001:db8::1")), Scope::Documentation);
        assert_eq!(classify(v6("100::1")), Scope::Discard);
        assert_eq!(classify(v6("::ffff:1.2.3.4")), Scope::Ipv4Mapped);
    }

    #[test]
    fn public_ips_are_classified_public() {
        assert_eq!(classify(v4("1.1.1.1")), Scope::Public);
        assert_eq!(classify(v4("8.8.8.8")), Scope::Public);
        assert_eq!(classify(v4("93.184.216.34")), Scope::Public);
        assert_eq!(classify(v6("2606:4700:4700::1111")), Scope::Public);
        assert_eq!(classify(v4("1.1.1.1")).label(), "PUBLIC");
    }
}
