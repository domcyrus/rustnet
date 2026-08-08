//! Passive neighbor cache: IP address -> MAC address + OUI vendor, learned
//! from ARP (IPv4) and NDP (IPv6) traffic.
//!
//! Populated from ARP and NDP packets the parser already decodes, so it costs
//! nothing on the per-frame hot path. An entry exists only after such a frame
//! was observed on the local segment, which normally keeps the cache to
//! on-link addresses (ARP never crosses a router; NDP messages are only
//! accepted at hop limit 255, which proves they were not routed). The frames
//! themselves are trusted, though: under proxy ARP/NDP or spoofing an
//! off-link address can appear mapped to a local MAC — the entry then names
//! the L2 hop actually answering for that IP on this segment, not the remote
//! host itself.

use crate::network::types::{ArpInfo, ArpOperation, NdpNeighbor};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::time::SystemTime;

/// Bound against ARP-spoof floods and subnet scans. A real LAN segment holds
/// at most a few hundred neighbors; when full, new keys are dropped rather
/// than evicting: an eviction policy would let a flood of forged sender IPs
/// push out the legitimate neighbors (which are always the stalest entries
/// relative to the attacker's constantly-fresh junk), while dropping keeps
/// them intact and still lets them refresh.
const MAX_ENTRIES: usize = 4096;

/// One learned neighbor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighborEntry {
    /// Colon-separated lowercase MAC, as formatted by the ARP parser.
    pub mac: String,
    /// OUI vendor, resolved by the ARP parse path when the database is loaded.
    pub vendor: Option<String>,
    /// Capture timestamp of the ARP packet this entry was learned from.
    pub last_seen: SystemTime,
}

/// IP -> [`NeighborEntry`] table with interior mutability, safe to share
/// behind an `Arc` between packet-processor threads and UI readers.
#[derive(Debug, Default)]
pub struct NeighborCache {
    entries: DashMap<IpAddr, NeighborEntry, FxBuildHasher>,
}

impl NeighborCache {
    /// Fold one decoded ARP packet into the table.
    ///
    /// The sender fields are authoritative in both operations: in a request
    /// the sender describes itself (this also covers gratuitous ARP), in a
    /// reply the sender is the answering host. A reply's target additionally
    /// echoes the original requester, so it is learned too; a request's
    /// target MAC is unspecified and ignored.
    pub fn learn_from_arp(&self, arp: &ArpInfo, now: SystemTime) {
        self.learn(arp.sender_ip, &arp.sender_mac, &arp.sender_vendor, now);
        if arp.operation == ArpOperation::Reply {
            self.learn(arp.target_ip, &arp.target_mac, &arp.target_vendor, now);
        }
    }

    /// Fold one NDP-carried mapping into the table. The parser extracts these
    /// only from messages that passed the hop-limit-255 check (RFC 4861), the
    /// IPv6 equivalent of ARP's on-link guarantee.
    pub fn learn_from_ndp(&self, neighbor: &NdpNeighbor, now: SystemTime) {
        self.learn(neighbor.ip, &neighbor.mac, &neighbor.vendor, now);
    }

    /// The learned entry for `ip`, if any.
    pub fn get(&self, ip: &IpAddr) -> Option<NeighborEntry> {
        self.entries.get(ip).map(|entry| entry.clone())
    }

    fn learn(&self, ip: IpAddr, mac: &str, vendor: &Option<String>, now: SystemTime) {
        // Unspecified covers ARP probes and DAD solicitations; a multicast IP
        // never names a neighbor (possible in a forged NA target field).
        if ip.is_unspecified() || ip.is_multicast() || !is_unicast_hardware_mac(mac) {
            return;
        }

        // The cap only gates brand-new keys; refreshing a known neighbor is
        // always allowed (see MAX_ENTRIES). Both checks run before the shard
        // lock below, so racing processor threads can overshoot the cap by at
        // most a thread count's worth of entries — harmless. `len()` must not
        // be called while the entry guard is held: it read-locks every shard.
        if !self.entries.contains_key(&ip) && self.entries.len() >= MAX_ENTRIES {
            return;
        }

        match self.entries.entry(ip) {
            dashmap::Entry::Occupied(mut entry) => {
                // Packet batches fan out across processor threads, so two ARP
                // frames for the same IP can arrive here out of capture order;
                // never let the older observation overwrite the newer one.
                if entry.get().last_seen <= now {
                    entry.insert(NeighborEntry {
                        mac: mac.to_string(),
                        vendor: vendor.clone(),
                        last_seen: now,
                    });
                }
            }
            dashmap::Entry::Vacant(entry) => {
                entry.insert(NeighborEntry {
                    mac: mac.to_string(),
                    vendor: vendor.clone(),
                    last_seen: now,
                });
            }
        }
    }
}

/// Whether `mac` is a real device address worth learning: rejects the all-zero
/// placeholder (ARP probes, unfilled reply targets) and group addresses
/// (broadcast `ff:ff:...` and multicast, i.e. the first octet's I/G bit set).
fn is_unicast_hardware_mac(mac: &str) -> bool {
    match crate::network::oui::mac_first_octet(mac) {
        Some(first) => first & 0x01 == 0 && !is_zero_mac(mac),
        None => false,
    }
}

/// All-zero MAC in any separator format the OUI parser accepts, so the check
/// does not silently depend on the ARP parser's colon-lowercase formatting.
fn is_zero_mac(mac: &str) -> bool {
    let mut zero_digits = 0usize;
    for c in mac.trim().chars() {
        match c {
            '0' => zero_digits += 1,
            ':' | '-' => {}
            _ => return false,
        }
    }
    zero_digits == 12
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arp(operation: ArpOperation, sender: (&str, &str), target: (&str, &str)) -> ArpInfo {
        ArpInfo {
            operation,
            sender_mac: sender.1.to_string(),
            sender_ip: sender.0.parse().unwrap(),
            target_mac: target.1.to_string(),
            target_ip: target.0.parse().unwrap(),
            sender_vendor: Some("Sender Corp".to_string()),
            target_vendor: None,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn request_learns_sender_only() {
        let cache = NeighborCache::default();
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.132", "68:5e:dd:09:15:5e"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            SystemTime::now(),
        );

        let entry = cache.get(&ip("192.168.0.132")).unwrap();
        assert_eq!(entry.mac, "68:5e:dd:09:15:5e");
        assert_eq!(entry.vendor.as_deref(), Some("Sender Corp"));
        assert!(cache.get(&ip("192.168.0.1")).is_none());
    }

    #[test]
    fn reply_learns_sender_and_target() {
        let cache = NeighborCache::default();
        cache.learn_from_arp(
            &arp(
                ArpOperation::Reply,
                ("192.168.0.1", "04:d9:f5:c5:ed:e8"),
                ("192.168.0.132", "68:5e:dd:09:15:5e"),
            ),
            SystemTime::now(),
        );

        assert_eq!(
            cache.get(&ip("192.168.0.1")).unwrap().mac,
            "04:d9:f5:c5:ed:e8"
        );
        assert_eq!(
            cache.get(&ip("192.168.0.132")).unwrap().mac,
            "68:5e:dd:09:15:5e"
        );
    }

    #[test]
    fn probe_and_group_macs_are_rejected() {
        let cache = NeighborCache::default();
        // ARP probe: unspecified sender IP.
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("0.0.0.0", "68:5e:dd:09:15:5e"),
                ("192.168.0.7", "00:00:00:00:00:00"),
            ),
            SystemTime::now(),
        );
        // Zero and broadcast/multicast sender MACs.
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.9", "00:00:00:00:00:00"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            SystemTime::now(),
        );
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.10", "ff:ff:ff:ff:ff:ff"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            SystemTime::now(),
        );
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.11", "01:00:5e:00:00:fb"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            SystemTime::now(),
        );

        assert!(cache.get(&ip("0.0.0.0")).is_none());
        assert!(cache.get(&ip("192.168.0.9")).is_none());
        assert!(cache.get(&ip("192.168.0.10")).is_none());
        assert!(cache.get(&ip("192.168.0.11")).is_none());
    }

    #[test]
    fn newer_arp_overwrites_same_ip() {
        let cache = NeighborCache::default();
        let when = SystemTime::now();
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.50", "aa:aa:aa:00:00:01"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            when,
        );
        cache.learn_from_arp(
            &arp(
                ArpOperation::Request,
                ("192.168.0.50", "ce:ce:ce:00:00:02"),
                ("192.168.0.1", "00:00:00:00:00:00"),
            ),
            when,
        );

        assert_eq!(
            cache.get(&ip("192.168.0.50")).unwrap().mac,
            "ce:ce:ce:00:00:02"
        );
    }

    #[test]
    fn stale_arp_does_not_overwrite_newer_entry() {
        let cache = NeighborCache::default();
        let newer = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);
        let older = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(5);
        cache.learn(ip("192.168.0.50"), "aa:aa:aa:00:00:01", &None, newer);
        // Delivered late by another processor thread.
        cache.learn(ip("192.168.0.50"), "ce:ce:ce:00:00:02", &None, older);

        let entry = cache.get(&ip("192.168.0.50")).unwrap();
        assert_eq!(entry.mac, "aa:aa:aa:00:00:01");
        assert_eq!(entry.last_seen, newer);
    }

    #[test]
    fn cap_drops_new_keys_but_still_refreshes_known_ones() {
        let cache = NeighborCache::default();
        let base = SystemTime::UNIX_EPOCH;
        for i in 0..MAX_ENTRIES {
            let octets = [10u8, (i >> 16) as u8, (i >> 8) as u8, i as u8];
            cache.learn(
                IpAddr::from(octets),
                "aa:bb:cc:00:00:01",
                &None,
                base + std::time::Duration::from_secs(i as u64 + 1),
            );
        }
        assert_eq!(cache.entries.len(), MAX_ENTRIES);

        // A brand-new key is dropped; nothing already learned is evicted.
        cache.learn(
            ip("192.168.0.200"),
            "aa:bb:cc:00:00:02",
            &None,
            base + std::time::Duration::from_secs(MAX_ENTRIES as u64 + 10),
        );
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert!(cache.get(&ip("192.168.0.200")).is_none());
        assert!(cache.get(&ip("10.0.0.0")).is_some());

        // A known neighbor still refreshes at cap.
        cache.learn(
            ip("10.0.0.0"),
            "aa:bb:cc:00:00:03",
            &None,
            base + std::time::Duration::from_secs(MAX_ENTRIES as u64 + 20),
        );
        assert_eq!(cache.get(&ip("10.0.0.0")).unwrap().mac, "aa:bb:cc:00:00:03");
    }

    #[test]
    fn multicast_ip_is_rejected() {
        // A forged NA can advertise a multicast target; it never names a
        // neighbor.
        let cache = NeighborCache::default();
        cache.learn(ip("ff02::1"), "68:5e:dd:09:15:5e", &None, SystemTime::now());
        cache.learn(ip("224.0.0.251"), "68:5e:dd:09:15:5e", &None, SystemTime::now());
        assert!(cache.get(&ip("ff02::1")).is_none());
        assert!(cache.get(&ip("224.0.0.251")).is_none());
    }

    #[test]
    fn zero_mac_is_rejected_in_any_format() {
        assert!(is_zero_mac("00:00:00:00:00:00"));
        assert!(is_zero_mac("00-00-00-00-00-00"));
        assert!(is_zero_mac("000000000000"));
        assert!(!is_zero_mac("00:00:00:00:00:01"));
        assert!(!is_zero_mac("68:5e:dd:09:15:5e"));
    }
}
