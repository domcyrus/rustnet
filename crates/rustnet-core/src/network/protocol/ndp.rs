//! NDP (IPv6 Neighbor Discovery, RFC 4861) link-layer address extraction.
//!
//! NDP rides ICMPv6, so its messages already reach the ICMPv6 parse path;
//! this module only pulls the IP-to-MAC mapping out of the source/target
//! link-layer address options so the tracker's neighbor cache can learn IPv6
//! neighbors the same way it learns IPv4 ones from ARP.

use crate::network::oui::OuiLookup;
use crate::network::types::NdpNeighbor;
use std::net::{IpAddr, Ipv6Addr};

/// Extract the IP-to-MAC mapping from one NDP message, if it is one and
/// carries the relevant link-layer address option. `icmpv6_data` starts at
/// the ICMPv6 header.
///
/// The caller must verify the enclosing IPv6 hop limit is 255 before calling:
/// RFC 4861 receivers require it, and it proves the packet was not routed —
/// the on-link property ARP gets for free from not being routable.
pub fn extract_neighbor(
    icmpv6_data: &[u8],
    src_ip: IpAddr,
    oui_lookup: Option<&OuiLookup>,
) -> Option<NdpNeighbor> {
    // ICMPv6 header plus at least one 8-byte option; NDP messages use code 0.
    if icmpv6_data.len() < 8 || icmpv6_data[1] != 0 {
        return None;
    }

    // Per message type: where the options start, which link-layer option
    // carries the mapping, and which IP address that option describes.
    let (options_offset, wanted_option, ip) = match icmpv6_data[0] {
        // Router Solicitation / Router Advertisement / Neighbor Solicitation:
        // the source link-layer option (type 1) describes the sender. A DAD
        // solicitation has an unspecified source; the cache rejects those.
        133 => (8, 1, src_ip),
        134 => (16, 1, src_ip),
        135 => (24, 1, src_ip),
        // Neighbor Advertisement / Redirect: the target link-layer option
        // (type 2) describes the target address field, i.e. the advertised
        // host or the redirected-to next hop.
        136 => (24, 2, target_address(icmpv6_data)?),
        137 => (40, 2, target_address(icmpv6_data)?),
        _ => return None,
    };

    let mac = find_link_layer_option(icmpv6_data.get(options_offset..)?, wanted_option)?;
    let vendor = oui_lookup.and_then(|oui| oui.lookup(&mac).map(String::from));
    Some(NdpNeighbor { ip, mac, vendor })
}

/// The target address field NA and Redirect share (bytes 8..24).
fn target_address(icmpv6_data: &[u8]) -> Option<IpAddr> {
    let bytes: [u8; 16] = icmpv6_data.get(8..24)?.try_into().ok()?;
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

/// Walk the TLV option list for a source (1) or target (2) link-layer
/// address option and format its MAC. Option lengths count 8-octet units; a
/// zero length is malformed and aborts the walk (RFC 4861 §4.6). A matching
/// option is used only at length 1 (2 header bytes + 6 address bytes), the
/// Ethernet form — other link layers use other sizes.
fn find_link_layer_option(mut options: &[u8], wanted: u8) -> Option<String> {
    while options.len() >= 8 {
        let length = options[1] as usize * 8;
        if length == 0 {
            return None;
        }
        if options[0] == wanted && length == 8 {
            let mac = &options[2..8];
            return Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            ));
        }
        options = options.get(length..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x68, 0x5e, 0xdd, 0x09, 0x15, 0x5e];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn option(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut opt = vec![kind, ((payload.len() + 2).div_ceil(8)) as u8];
        opt.extend_from_slice(payload);
        while opt.len() % 8 != 0 {
            opt.push(0);
        }
        opt
    }

    /// ICMPv6 header + body for a neighbor solicitation of `target`.
    fn solicitation(target: &str) -> Vec<u8> {
        let mut msg = vec![135, 0, 0, 0, 0, 0, 0, 0];
        match ip(target) {
            IpAddr::V6(v6) => msg.extend_from_slice(&v6.octets()),
            IpAddr::V4(_) => unreachable!(),
        }
        msg
    }

    /// ICMPv6 header + body for a neighbor advertisement of `target`.
    fn advertisement(target: &str) -> Vec<u8> {
        let mut msg = vec![136, 0, 0, 0, 0x60, 0, 0, 0]; // solicited+override
        match ip(target) {
            IpAddr::V6(v6) => msg.extend_from_slice(&v6.octets()),
            IpAddr::V4(_) => unreachable!(),
        }
        msg
    }

    #[test]
    fn solicitation_learns_source_from_its_option() {
        let mut msg = solicitation("fe80::1");
        msg.extend_from_slice(&option(1, &MAC));

        let neighbor = extract_neighbor(&msg, ip("fe80::2"), None).unwrap();
        assert_eq!(neighbor.ip, ip("fe80::2"));
        assert_eq!(neighbor.mac, "68:5e:dd:09:15:5e");
        assert_eq!(neighbor.vendor, None);
    }

    #[test]
    fn advertisement_learns_target_address_not_source() {
        let mut msg = advertisement("2001:db8::10");
        msg.extend_from_slice(&option(2, &MAC));

        let neighbor = extract_neighbor(&msg, ip("fe80::2"), None).unwrap();
        assert_eq!(neighbor.ip, ip("2001:db8::10"));
        assert_eq!(neighbor.mac, "68:5e:dd:09:15:5e");
    }

    #[test]
    fn option_walk_skips_unrelated_options() {
        // Router advertisement: MTU option (type 5) then prefix information
        // (type 3, 32 bytes) before the source link-layer option.
        let mut msg = vec![134, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        msg.extend_from_slice(&option(5, &[0, 0, 0, 0, 0x05, 0xdc]));
        msg.extend_from_slice(&option(3, &[0u8; 30]));
        msg.extend_from_slice(&option(1, &MAC));

        let neighbor = extract_neighbor(&msg, ip("fe80::1"), None).unwrap();
        assert_eq!(neighbor.ip, ip("fe80::1"));
        assert_eq!(neighbor.mac, "68:5e:dd:09:15:5e");
    }

    #[test]
    fn wrong_option_kind_is_not_learned() {
        // A solicitation's mapping comes from the source option, not target.
        let mut msg = solicitation("fe80::1");
        msg.extend_from_slice(&option(2, &MAC));
        assert!(extract_neighbor(&msg, ip("fe80::2"), None).is_none());
    }

    #[test]
    fn malformed_zero_length_option_aborts() {
        let mut msg = solicitation("fe80::1");
        msg.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // length 0
        assert!(extract_neighbor(&msg, ip("fe80::2"), None).is_none());
    }

    #[test]
    fn non_ndp_and_nonzero_code_are_ignored() {
        // Echo request.
        assert!(extract_neighbor(&[128, 0, 0, 0, 0, 1, 0, 1], ip("fe80::2"), None).is_none());
        // NDP type with a nonzero code is invalid per RFC 4861.
        let mut msg = solicitation("fe80::1");
        msg[1] = 1;
        msg.extend_from_slice(&option(1, &MAC));
        assert!(extract_neighbor(&msg, ip("fe80::2"), None).is_none());
    }

    #[test]
    fn truncated_advertisement_is_rejected() {
        // Type/code/checksum only — no target address, no options.
        assert!(extract_neighbor(&[136, 0, 0, 0], ip("fe80::2"), None).is_none());
    }
}
