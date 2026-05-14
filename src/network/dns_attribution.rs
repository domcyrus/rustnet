//! DNS-based hostname attribution cache.
//!
//! Builds an IP -> domain map from DNS responses observed on the wire and
//! lets callers tag connections with the most recently resolved hostname
//! for that IP. This is how a QUIC or plain-TCP connection gets a
//! human-readable hostname even when no SNI / Host header is visible:
//! when the user resolved `foo.com -> 1.2.3.4` a moment before opening
//! the connection, we can attribute that connection to `foo.com`.
//!
//! Conceptually equivalent to what Little Snitch's eBPF DNS cache does on
//! Linux, but driven from pcap. CNAME chains are handled implicitly
//! because the DNS DPI parser already records the original *question*
//! name; the IPs in the answer section map directly to that.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::network::types::{
    ApplicationProtocol, AttributedHostname, AttributionSource, Connection, Protocol,
};

/// Entries kept per IP. CDN / load-balanced IPs may be claimed by several
/// names within the retention window; a small bound prevents pathological
/// growth.
const MAX_DOMAINS_PER_IP: usize = 4;

/// Default freshness window: the time horizon over which a DNS
/// observation and a connection are considered to belong to the same
/// user action. Used symmetrically — a cached IP→domain entry is
/// trusted within this window, and a pending enrollment is kept while
/// it waits for matching DNS for at most this long. 10s matches Little
/// Snitch's `MAX_QUERY_AGE` and is tight enough to keep CDN-IP
/// collisions rare.
pub const DEFAULT_FRESH_WINDOW: Duration = Duration::from_secs(10);

/// Default retention window: entries past this are eligible for
/// pruning. Kept longer than `fresh_window` so debug accessors / detail
/// views can show recently-seen-but-not-fresh names if we ever want
/// them; lookups won't return these for attribution.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(600);

/// Default cap on tracked IPs.
pub const DEFAULT_MAX_ENTRIES: usize = 8192;

/// Cap on the number of connection keys that may wait on the same IP
/// for attribution. Bounds memory if many simultaneous connections to a
/// CDN IP all happen to predate any DNS observation.
const MAX_PENDING_PER_IP: usize = 256;

/// One observed (domain, when, source) tuple for an IP.
#[derive(Debug, Clone)]
pub struct AttributedDomain {
    pub domain: String,
    pub observed_at: Instant,
    pub source: AttributionSource,
}

/// One waiting connection key plus when it was enrolled.
#[derive(Debug, Clone)]
struct PendingEntry {
    conn_key: String,
    enrolled_at: Instant,
}

/// IP -> recent domains cache, populated from captured DNS responses.
///
/// In addition to the main IP -> domains map, the cache maintains a side
/// index of *pending attributions*: connections that have been observed
/// but couldn't be tagged yet because no fresh DNS for their remote IP
/// is in cache. When a DNS response later arrives for one of those IPs,
/// the cache surfaces the waiting connection keys so the caller can
/// attribute them in batch — no per-packet polling required.
///
/// Cheap to clone via `Arc`. All access is concurrent (DashMap), no outer
/// lock required.
#[derive(Debug)]
pub struct DnsAttributionCache {
    map: DashMap<IpAddr, Vec<AttributedDomain>>,
    /// IP -> connection keys waiting on a DNS resolution for that IP.
    /// Entries are added by `attribute()` on a cache miss and drained
    /// by `record_and_drain_pending()` when the matching DNS response
    /// arrives. Connection cleanup calls `forget_pending()` so dead
    /// keys don't accumulate.
    pending: DashMap<IpAddr, Vec<PendingEntry>>,
    max_entries: usize,
    fresh_window: Duration,
    retention: Duration,
}

impl Default for DnsAttributionCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_FRESH_WINDOW, DEFAULT_RETENTION)
    }
}

impl DnsAttributionCache {
    pub fn new(max_entries: usize, fresh_window: Duration, retention: Duration) -> Self {
        Self {
            map: DashMap::new(),
            pending: DashMap::new(),
            max_entries,
            fresh_window,
            retention,
        }
    }

    /// Wrap in an `Arc` for sharing with the packet pipeline.
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Record a DNS resolution: `query_name` resolved to `ips`.
    ///
    /// Empty inputs are ignored. Existing entries for an IP are updated
    /// in place: if the same domain is already present its timestamp is
    /// refreshed, otherwise the new entry is pushed and the per-IP list
    /// is trimmed to `MAX_DOMAINS_PER_IP` keeping the most recent.
    pub fn record(&self, query_name: &str, ips: &[IpAddr], source: AttributionSource) {
        let domain = query_name.trim().trim_end_matches('.');
        if domain.is_empty() || ips.is_empty() {
            return;
        }
        let now = Instant::now();

        for ip in ips {
            // Skip useless mappings.
            if ip.is_unspecified() || ip.is_loopback() {
                continue;
            }

            self.map
                .entry(*ip)
                .and_modify(|entries| {
                    if let Some(existing) = entries.iter_mut().find(|d| d.domain == domain) {
                        existing.observed_at = now;
                        existing.source = source;
                    } else {
                        entries.push(AttributedDomain {
                            domain: domain.to_string(),
                            observed_at: now,
                            source,
                        });
                    }
                    // Keep only the freshest MAX_DOMAINS_PER_IP entries.
                    if entries.len() > MAX_DOMAINS_PER_IP {
                        entries.sort_by_key(|d| std::cmp::Reverse(d.observed_at));
                        entries.truncate(MAX_DOMAINS_PER_IP);
                    }
                })
                .or_insert_with(|| {
                    vec![AttributedDomain {
                        domain: domain.to_string(),
                        observed_at: now,
                        source,
                    }]
                });
        }

        if self.map.len() > self.max_entries {
            self.prune(now);
        }
    }

    /// Look up the freshest domain known for `ip`.
    ///
    /// Returns `None` when the IP is unknown or all known entries are
    /// older than `retention`. The boolean is `true` when the freshest
    /// entry is within `fresh_window` (and therefore trustworthy enough
    /// to attribute a new connection to).
    pub fn lookup(&self, ip: IpAddr) -> Option<(AttributedDomain, bool)> {
        let entries = self.map.get(&ip)?;
        let now = Instant::now();
        let freshest = entries
            .iter()
            .filter(|d| now.saturating_duration_since(d.observed_at) <= self.retention)
            .max_by_key(|d| d.observed_at)?
            .clone();
        let fresh = now.saturating_duration_since(freshest.observed_at) <= self.fresh_window;
        Some((freshest, fresh))
    }

    /// Tag `conn` with a hostname inferred from the freshest DNS
    /// resolution observed for its remote IP, if any.
    ///
    /// On a cache miss the connection's key is **enrolled in the
    /// pending index** so the next matching DNS response can attribute
    /// it without further work from the packet hot path. Callers
    /// therefore call this once at connection creation and rely on
    /// `record_and_drain_pending()` to do the eventual tagging.
    ///
    /// Short-circuits (no enrollment, no lookup) when attribution is
    /// unnecessary or impossible:
    ///
    /// * `attributed_hostname` is already set (first-write-wins).
    /// * Connection already has an *authoritative* hostname from DPI
    ///   (TLS SNI on HTTPS / QUIC, or HTTP `Host:`). The UI prefers
    ///   those over attribution.
    /// * Protocol is ARP or the connection carries a name-resolution
    ///   / local-discovery protocol (DNS, mDNS, LLMNR, DHCP, SSDP,
    ///   NetBIOS). Attribution is either nonsensical (the protocol
    ///   *is* the name lookup) or useless (broadcast / multicast).
    pub fn attribute(&self, conn: &mut Connection) {
        if conn.protocol == Protocol::Arp || conn.attributed_hostname.is_some() {
            return;
        }
        if has_authoritative_hostname(conn) {
            return;
        }
        if is_unattributable_protocol(conn) {
            return;
        }
        let ip = conn.remote_addr.ip();
        if let Some((att, fresh)) = self.lookup(ip)
            && fresh
        {
            conn.attributed_hostname = Some(AttributedHostname {
                name: att.domain,
                source: att.source,
                observed_at: SystemTime::now(),
            });
            return;
        }

        // Cache miss: enroll for the next matching DNS response.
        self.enroll_pending(ip, conn.key());

        // Race-safe double-check: a concurrent `record()` may have
        // populated the cache (and possibly drained pending) between
        // our lookup and our enroll. If so, attribute now and let the
        // stale enrollment be cleaned up on connection close — a
        // future `record_and_drain_pending` for this IP will short-
        // circuit on `attributed_hostname.is_some()`.
        if let Some((att, fresh)) = self.lookup(ip)
            && fresh
        {
            conn.attributed_hostname = Some(AttributedHostname {
                name: att.domain,
                source: att.source,
                observed_at: SystemTime::now(),
            });
        }
    }

    /// Enroll `conn_key` to be attributed when the next DNS response
    /// for `ip` arrives. Bounded per-IP and deduplicated; each
    /// enrollment is timestamped so stale waits get pruned.
    fn enroll_pending(&self, ip: IpAddr, conn_key: String) {
        let now = Instant::now();
        self.pending
            .entry(ip)
            .and_modify(|v| {
                if v.iter().all(|e| e.conn_key != conn_key) && v.len() < MAX_PENDING_PER_IP {
                    v.push(PendingEntry {
                        conn_key: conn_key.clone(),
                        enrolled_at: now,
                    });
                }
            })
            .or_insert_with(|| {
                vec![PendingEntry {
                    conn_key,
                    enrolled_at: now,
                }]
            });
    }

    /// Remove a connection key from the pending index. Called on
    /// connection cleanup so dead keys don't linger when the connection
    /// dies before any DNS response arrives.
    pub fn forget_pending(&self, ip: IpAddr, conn_key: &str) {
        let now_empty = self.pending.get_mut(&ip).map(|mut entry| {
            entry.retain(|e| e.conn_key != conn_key);
            entry.is_empty()
        });
        if matches!(now_empty, Some(true)) {
            self.pending.remove(&ip);
        }
    }

    /// Record a DNS response into the cache **and** return the
    /// connection keys (those still within `fresh_window`) that were
    /// waiting on any of those IPs. Stale enrollments are dropped on
    /// the floor so a brand-new DNS resolution can't retroactively
    /// label a long-running connection.
    pub fn record_and_drain_pending(
        &self,
        query_name: &str,
        ips: &[IpAddr],
        source: AttributionSource,
    ) -> Vec<String> {
        self.record(query_name, ips, source);
        let now = Instant::now();
        let mut keys = Vec::new();
        for ip in ips {
            if ip.is_unspecified() || ip.is_loopback() {
                continue;
            }
            if let Some((_, waiters)) = self.pending.remove(ip) {
                for entry in waiters {
                    if now.saturating_duration_since(entry.enrolled_at) <= self.fresh_window {
                        keys.push(entry.conn_key);
                    }
                }
            }
        }
        keys
    }

    /// Drop pending enrollments older than `fresh_window`. Intended to
    /// be called from a periodic cleanup tick so memory doesn't
    /// accumulate when DNS for an enrolled IP never arrives.
    pub fn prune_pending(&self, now: Instant) {
        self.pending.retain(|_ip, entries| {
            entries.retain(|e| now.saturating_duration_since(e.enrolled_at) <= self.fresh_window);
            !entries.is_empty()
        });
    }

    /// Combined periodic maintenance: prune the IP→domain map and the
    /// pending index. Cheap; intended to be called once per cleanup
    /// thread tick.
    pub fn cleanup_tick(&self, now: Instant) {
        self.prune(now);
        self.prune_pending(now);
    }

    /// Drop entries older than `retention`. If the cache is still over
    /// `max_entries` after pruning, drop the oldest IPs until under cap.
    pub fn prune(&self, now: Instant) {
        // First, drop expired domains within each IP, and IPs that end up empty.
        self.map.retain(|_ip, entries| {
            entries.retain(|d| now.saturating_duration_since(d.observed_at) <= self.retention);
            !entries.is_empty()
        });

        if self.map.len() <= self.max_entries {
            return;
        }

        // Hard cap: collect the freshest timestamp per IP, sort ascending,
        // drop the oldest until under the cap.
        let mut ages: Vec<(IpAddr, Instant)> = self
            .map
            .iter()
            .map(|kv| {
                let freshest = kv
                    .value()
                    .iter()
                    .map(|d| d.observed_at)
                    .max()
                    .unwrap_or(now);
                (*kv.key(), freshest)
            })
            .collect();
        ages.sort_by_key(|(_, t)| *t);

        let to_drop = self.map.len().saturating_sub(self.max_entries);
        for (ip, _) in ages.into_iter().take(to_drop) {
            self.map.remove(&ip);
        }
    }
}

/// True when `conn` carries a protocol for which DNS-based hostname
/// attribution is meaningless: name-resolution protocols themselves
/// (DNS / mDNS / LLMNR), or local-network discovery / broadcast
/// protocols whose remote address is multicast or otherwise not a
/// resolvable host (DHCP / SSDP / NetBIOS).
fn is_unattributable_protocol(conn: &Connection) -> bool {
    let Some(dpi) = &conn.dpi_info else {
        return false;
    };
    matches!(
        dpi.application,
        ApplicationProtocol::Dns(_)
            | ApplicationProtocol::Mdns(_)
            | ApplicationProtocol::Llmnr(_)
            | ApplicationProtocol::Dhcp(_)
            | ApplicationProtocol::Ssdp(_)
            | ApplicationProtocol::NetBios(_)
    )
}

/// True when `conn`'s DPI info already provides an authoritative
/// hostname (TLS SNI or HTTP `Host:`), making attribution unnecessary.
/// `[PARTIAL]` SNI strings (truncated during ClientHello parsing) are
/// rejected so we keep trying until a full SNI lands or attribution
/// fills in.
fn has_authoritative_hostname(conn: &Connection) -> bool {
    let Some(dpi) = &conn.dpi_info else {
        return false;
    };
    match &dpi.application {
        ApplicationProtocol::Https(h) => h
            .tls_info
            .as_ref()
            .and_then(|t| t.sni.as_ref())
            .is_some_and(|s| !s.contains("[PARTIAL]")),
        ApplicationProtocol::Quic(q) => q
            .tls_info
            .as_ref()
            .and_then(|t| t.sni.as_ref())
            .is_some_and(|s| !s.contains("[PARTIAL]")),
        ApplicationProtocol::Http(h) => h.host.is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::thread::sleep;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn fresh_lookup_after_record() {
        let cache = DnsAttributionCache::default();
        cache.record("foo.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);

        let (att, fresh) = cache.lookup(ip(1, 2, 3, 4)).expect("hit");
        assert_eq!(att.domain, "foo.com");
        assert!(fresh);
    }

    #[test]
    fn lookup_past_fresh_window_is_not_fresh() {
        let cache = DnsAttributionCache::new(
            DEFAULT_MAX_ENTRIES,
            Duration::from_millis(20),
            Duration::from_secs(60),
        );
        cache.record("foo.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        sleep(Duration::from_millis(40));

        let (att, fresh) = cache.lookup(ip(1, 2, 3, 4)).expect("hit");
        assert_eq!(att.domain, "foo.com");
        assert!(!fresh, "should be stale");
    }

    #[test]
    fn lookup_past_retention_is_miss() {
        let cache = DnsAttributionCache::new(
            DEFAULT_MAX_ENTRIES,
            Duration::from_millis(5),
            Duration::from_millis(20),
        );
        cache.record("foo.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        sleep(Duration::from_millis(40));

        assert!(cache.lookup(ip(1, 2, 3, 4)).is_none());
    }

    #[test]
    fn most_recent_wins_for_shared_ip() {
        let cache = DnsAttributionCache::default();
        cache.record(
            "first.com",
            &[ip(1, 1, 1, 1)],
            AttributionSource::CapturedDns,
        );
        sleep(Duration::from_millis(5));
        cache.record(
            "second.com",
            &[ip(1, 1, 1, 1)],
            AttributionSource::CapturedDns,
        );

        let (att, _fresh) = cache.lookup(ip(1, 1, 1, 1)).expect("hit");
        assert_eq!(att.domain, "second.com");
    }

    #[test]
    fn record_dedupes_same_domain() {
        let cache = DnsAttributionCache::default();
        for _ in 0..10 {
            cache.record("foo.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        }
        // single domain entry, even after repeated records
        let entries = cache.map.get(&ip(1, 2, 3, 4)).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn ipv6_path() {
        let cache = DnsAttributionCache::default();
        let v6 = "2606:4700:4700::1111".parse::<IpAddr>().unwrap();
        cache.record("dns.cloudflare.com", &[v6], AttributionSource::CapturedDns);
        let (att, fresh) = cache.lookup(v6).expect("hit");
        assert_eq!(att.domain, "dns.cloudflare.com");
        assert!(fresh);
    }

    #[test]
    fn loopback_and_unspecified_ignored() {
        let cache = DnsAttributionCache::default();
        cache.record(
            "lo.example",
            &[ip(127, 0, 0, 1), ip(0, 0, 0, 0), ip(8, 8, 8, 8)],
            AttributionSource::CapturedDns,
        );
        assert!(cache.lookup(ip(127, 0, 0, 1)).is_none());
        assert!(cache.lookup(ip(0, 0, 0, 0)).is_none());
        assert!(cache.lookup(ip(8, 8, 8, 8)).is_some());
    }

    #[test]
    fn cap_enforced_via_prune() {
        let cache = DnsAttributionCache::new(16, Duration::from_secs(60), Duration::from_secs(60));
        for i in 0..200u32 {
            let octets = i.to_be_bytes();
            cache.record(
                "name.example",
                &[ip(10, octets[1], octets[2], octets[3])],
                AttributionSource::CapturedDns,
            );
        }
        assert!(
            cache.map.len() <= 16,
            "cache exceeded cap: {}",
            cache.map.len()
        );
    }

    #[test]
    fn attribute_tags_fresh_connection() {
        use crate::network::types::{Protocol, ProtocolState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();
        cache.record(
            "youtube.com",
            &[ip(142, 250, 1, 1)],
            AttributionSource::CapturedDns,
        );

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "142.250.1.1:443".parse().unwrap();
        let mut conn = Connection::new(Protocol::Udp, local, remote, ProtocolState::Udp);

        cache.attribute(&mut conn);
        let att = conn.attributed_hostname.expect("attribution applied");
        assert_eq!(att.name, "youtube.com");
        assert_eq!(att.source, AttributionSource::CapturedDns);
    }

    #[test]
    fn attribute_first_write_wins() {
        use crate::network::types::{Protocol, ProtocolState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();
        cache.record("a.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(crate::network::types::TcpState::Established),
        );

        cache.attribute(&mut conn);
        // A second resolution to the same IP shouldn't overwrite the
        // already-applied attribution on this connection.
        cache.record("b.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        cache.attribute(&mut conn);
        assert_eq!(conn.attributed_hostname.unwrap().name, "a.com");
    }

    #[test]
    fn attribute_skips_dns_self_attribution() {
        use crate::network::types::{
            ApplicationProtocol, DnsInfo, DpiInfo, Protocol, ProtocolState,
        };
        use std::net::SocketAddr;
        use std::time::Instant;

        let cache = DnsAttributionCache::default();
        cache.record(
            "resolver.example",
            &[ip(8, 8, 8, 8)],
            AttributionSource::CapturedDns,
        );

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let mut conn = Connection::new(Protocol::Udp, local, remote, ProtocolState::Udp);
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(DnsInfo {
                query_name: Some("foo.com".into()),
                query_type: None,
                response_ips: vec![],
                is_response: false,
            }),
            last_update_time: Instant::now(),
        });

        cache.attribute(&mut conn);
        assert!(
            conn.attributed_hostname.is_none(),
            "DNS connection must not be self-attributed"
        );
    }

    #[test]
    fn attribute_skips_local_discovery_protocols() {
        use crate::network::types::{
            ApplicationProtocol, DhcpInfo, DhcpMessageType, DpiInfo, LlmnrInfo, MdnsInfo,
            NetBiosInfo, NetBiosOpcode, NetBiosService, Protocol, ProtocolState, SsdpInfo,
            SsdpMethod,
        };
        use std::net::SocketAddr;
        use std::time::Instant;

        let cache = DnsAttributionCache::default();
        cache.record(
            "should-not-be-applied.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );

        let local: SocketAddr = "192.168.1.10:5353".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:5353".parse().unwrap();
        let make_conn = |app: ApplicationProtocol| {
            let mut c = Connection::new(Protocol::Udp, local, remote, ProtocolState::Udp);
            c.dpi_info = Some(DpiInfo {
                application: app,
                last_update_time: Instant::now(),
            });
            c
        };

        let cases: Vec<(&str, ApplicationProtocol)> = vec![
            (
                "mdns",
                ApplicationProtocol::Mdns(MdnsInfo {
                    query_name: None,
                    query_type: None,
                    is_response: false,
                }),
            ),
            (
                "llmnr",
                ApplicationProtocol::Llmnr(LlmnrInfo {
                    query_name: None,
                    query_type: None,
                    is_response: false,
                }),
            ),
            (
                "dhcp",
                ApplicationProtocol::Dhcp(DhcpInfo {
                    message_type: DhcpMessageType::Discover,
                    hostname: None,
                    client_mac: None,
                }),
            ),
            (
                "ssdp",
                ApplicationProtocol::Ssdp(SsdpInfo {
                    method: SsdpMethod::MSearch,
                    service_type: None,
                }),
            ),
            (
                "netbios",
                ApplicationProtocol::NetBios(NetBiosInfo {
                    service: NetBiosService::NameService,
                    opcode: NetBiosOpcode::Query,
                    name: None,
                }),
            ),
        ];

        for (label, app) in cases {
            let mut conn = make_conn(app);
            cache.attribute(&mut conn);
            assert!(
                conn.attributed_hostname.is_none(),
                "{} connections must not be attributed",
                label
            );
        }
    }

    #[test]
    fn attribute_skips_when_sni_present() {
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, HttpsInfo, Protocol, ProtocolState, TcpState, TlsInfo,
        };
        use std::net::SocketAddr;
        use std::time::Instant;

        let cache = DnsAttributionCache::default();
        cache.record(
            "attribution.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    version: None,
                    sni: Some("sni.example".into()),
                    alpn: vec![],
                    cipher_suite: None,
                }),
            }),
            last_update_time: Instant::now(),
        });

        cache.attribute(&mut conn);
        assert!(
            conn.attributed_hostname.is_none(),
            "SNI-bearing connections should short-circuit attribution"
        );
    }

    #[test]
    fn attribute_proceeds_when_sni_partial() {
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, HttpsInfo, Protocol, ProtocolState, TcpState, TlsInfo,
        };
        use std::net::SocketAddr;
        use std::time::Instant;

        let cache = DnsAttributionCache::default();
        cache.record(
            "real.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    version: None,
                    sni: Some("partial[PARTIAL]".into()),
                    alpn: vec![],
                    cipher_suite: None,
                }),
            }),
            last_update_time: Instant::now(),
        });

        cache.attribute(&mut conn);
        assert_eq!(
            conn.attributed_hostname.as_ref().map(|a| a.name.as_str()),
            Some("real.example"),
            "[PARTIAL] SNI is not authoritative; attribution should still apply"
        );
    }

    #[test]
    fn attribute_skips_when_not_fresh() {
        use crate::network::types::{Protocol, ProtocolState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::new(
            DEFAULT_MAX_ENTRIES,
            Duration::from_millis(10),
            Duration::from_secs(60),
        );
        cache.record("foo.com", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        sleep(Duration::from_millis(40));

        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(crate::network::types::TcpState::Established),
        );

        cache.attribute(&mut conn);
        assert!(
            conn.attributed_hostname.is_none(),
            "stale entry must not be applied"
        );
    }

    #[test]
    fn attribute_enrolls_on_miss_then_drain_attributes() {
        use crate::network::types::{Protocol, ProtocolState, TcpState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();

        // Connection happens first; cache is empty → enroll in pending.
        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        cache.attribute(&mut conn);
        assert!(conn.attributed_hostname.is_none());
        assert_eq!(cache.pending.len(), 1);

        // DNS response for that IP arrives → drain returns the waiter.
        let drained = cache.record_and_drain_pending(
            "late.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], conn.key());
        assert!(
            cache.pending.is_empty(),
            "pending entry should be removed on drain"
        );

        // Caller now applies attribute() to the drained connection;
        // this time it hits the freshly recorded entry.
        cache.attribute(&mut conn);
        assert_eq!(
            conn.attributed_hostname.as_ref().map(|a| a.name.as_str()),
            Some("late.example")
        );
    }

    #[test]
    fn forget_pending_clears_dead_keys() {
        use crate::network::types::{Protocol, ProtocolState, TcpState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();
        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        cache.attribute(&mut conn);
        assert_eq!(cache.pending.len(), 1);

        cache.forget_pending(conn.remote_addr.ip(), &conn.key());
        assert!(
            cache.pending.is_empty(),
            "forget_pending should drop the IP entry once empty"
        );

        // Subsequent DNS for that IP should not surface a stale waiter.
        let drained = cache.record_and_drain_pending(
            "x.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );
        assert!(drained.is_empty());
    }

    #[test]
    fn pending_ttl_drops_expired_enrollments_on_drain() {
        use crate::network::types::{Protocol, ProtocolState, TcpState};
        use std::net::SocketAddr;

        // Backdate the enrollment via direct field surgery so we don't
        // have to actually sleep for `fresh_window`.
        let cache = DnsAttributionCache::default();
        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        cache.attribute(&mut conn);
        // Backdate the enrollment past `fresh_window`.
        if let Some(mut entry) = cache.pending.get_mut(&conn.remote_addr.ip()) {
            for e in entry.iter_mut() {
                e.enrolled_at = Instant::now() - cache.fresh_window - Duration::from_secs(1);
            }
        }

        let drained = cache.record_and_drain_pending(
            "stale.example",
            &[ip(1, 2, 3, 4)],
            AttributionSource::CapturedDns,
        );
        assert!(drained.is_empty(), "stale enrollments must not be surfaced");
    }

    #[test]
    fn prune_pending_drops_expired_enrollments() {
        use crate::network::types::{Protocol, ProtocolState, TcpState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();
        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        cache.attribute(&mut conn);
        assert_eq!(cache.pending.len(), 1);

        if let Some(mut entry) = cache.pending.get_mut(&conn.remote_addr.ip()) {
            for e in entry.iter_mut() {
                e.enrolled_at = Instant::now() - cache.fresh_window - Duration::from_secs(1);
            }
        }
        cache.prune_pending(Instant::now());
        assert!(cache.pending.is_empty());
    }

    #[test]
    fn enroll_pending_dedupes_same_key() {
        use crate::network::types::{Protocol, ProtocolState, TcpState};
        use std::net::SocketAddr;

        let cache = DnsAttributionCache::default();
        let local: SocketAddr = "192.168.1.10:54321".parse().unwrap();
        let remote: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        for _ in 0..5 {
            cache.attribute(&mut conn);
        }
        let entry = cache.pending.get(&conn.remote_addr.ip()).unwrap();
        assert_eq!(entry.len(), 1);
    }

    #[test]
    fn empty_inputs_are_noops() {
        let cache = DnsAttributionCache::default();
        cache.record("", &[ip(1, 2, 3, 4)], AttributionSource::CapturedDns);
        cache.record("foo.com", &[], AttributionSource::CapturedDns);
        assert!(cache.map.is_empty());
    }
}
