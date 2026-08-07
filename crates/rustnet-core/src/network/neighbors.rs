//! Passive ARP-learned neighbor cache: IP address -> MAC address + OUI vendor.
//!
//! Populated from ARP packets the parser already decodes, so it costs nothing
//! on the per-frame hot path. An entry exists only after an ARP exchange was
//! observed on the wire, which also guarantees the mapped IP is on-link: ARP
//! never crosses a router, so the cache cannot mislabel an off-link private
//! address (e.g. a VPN peer) with a LAN device's identity.

use crate::network::types::{ArpInfo, ArpOperation};
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::time::SystemTime;

/// Bound against ARP-spoof floods and subnet scans. A real LAN segment holds
/// at most a few hundred neighbors; when full, the stalest entry is evicted.
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

    /// The learned entry for `ip`, if any.
    pub fn get(&self, ip: &IpAddr) -> Option<NeighborEntry> {
        self.entries.get(ip).map(|entry| entry.clone())
    }

    fn learn(&self, ip: IpAddr, mac: &str, vendor: &Option<String>, now: SystemTime) {
        if ip.is_unspecified() || !is_unicast_hardware_mac(mac) {
            return;
        }

        // The cap only gates brand-new keys; refreshing a known neighbor is
        // always allowed. `len()` read-locks every shard, but this path runs
        // only for ARP packets, which are rare.
        if !self.entries.contains_key(&ip) && self.entries.len() >= MAX_ENTRIES {
            self.evict_stalest();
        }

        self.entries.insert(
            ip,
            NeighborEntry {
                mac: mac.to_string(),
                vendor: vendor.clone(),
                last_seen: now,
            },
        );
    }

    fn evict_stalest(&self) {
        let stalest = self
            .entries
            .iter()
            .min_by_key(|entry| entry.last_seen)
            .map(|entry| *entry.key());
        if let Some(ip) = stalest {
            self.entries.remove(&ip);
        }
    }
}

/// Whether `mac` is a real device address worth learning: rejects the all-zero
/// placeholder (ARP probes, unfilled reply targets) and group addresses
/// (broadcast `ff:ff:...` and multicast, i.e. the first octet's I/G bit set).
fn is_unicast_hardware_mac(mac: &str) -> bool {
    match crate::network::oui::mac_first_octet(mac) {
        Some(first) => first & 0x01 == 0 && mac != "00:00:00:00:00:00",
        None => false,
    }
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
    fn cap_evicts_stalest_entry() {
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

        // The first (stalest) entry makes room for the newcomer.
        cache.learn(
            ip("192.168.0.200"),
            "aa:bb:cc:00:00:02",
            &None,
            base + std::time::Duration::from_secs(MAX_ENTRIES as u64 + 10),
        );
        assert_eq!(cache.entries.len(), MAX_ENTRIES);
        assert!(cache.get(&ip("10.0.0.0")).is_none());
        assert!(cache.get(&ip("192.168.0.200")).is_some());
    }
}
