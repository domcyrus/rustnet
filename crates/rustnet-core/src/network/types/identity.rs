use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

/// How closely a process attribution matched the connection it was asked about.
///
/// Attribution backends record sockets under the tuple they saw at creation
/// time, which is not always the tuple the capture side observes on the wire. A
/// lookup may therefore have to relax the key, and the caller deserves to know
/// that it did: a relaxed hit is a plausible owner, not a proven one.
///
/// Defined here rather than in `rustnet-host` because
/// [`Connection`](crate::network::types::Connection) carries it
/// and `rustnet-host` depends on this crate, not the other way round.
///
/// Marked `#[non_exhaustive]` so new relaxation shapes can be added without
/// breaking downstream `match` arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MatchQuality {
    /// Attribution is tied to the observed flow without relaxation, either by
    /// an exact 4-tuple match or by per-packet process metadata.
    ExactTuple,
    /// Matched only after zeroing the local address, i.e. the socket was
    /// recorded while bound to a wildcard address.
    WildcardLocalAddress,
    /// Matched a listening socket (the recorded entry has no remote peer).
    ListenerSocket,
    /// Exact 4-tuple match in the procfs socket table.
    ProcfsExact,
    /// procfs match that needed a relaxed key.
    ProcfsRelaxed,
    /// The backend reported an owner but could not report match provenance.
    Unspecified,
}

impl MatchQuality {
    /// Whether the connection's exact 4-tuple was found, with no relaxation.
    pub fn is_exact(self) -> bool {
        matches!(self, Self::ExactTuple | Self::ProcfsExact)
    }

    /// Human-readable label, for display to a person.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ExactTuple => "exact tuple",
            Self::WildcardLocalAddress => "wildcard local address",
            Self::ListenerSocket => "listener socket",
            Self::ProcfsExact => "procfs exact",
            Self::ProcfsRelaxed => "procfs relaxed",
            Self::Unspecified => "unspecified",
        }
    }

    /// Stable machine-readable token for exports.
    ///
    /// Separate from [`MatchQuality::as_str`] on purpose: the prose there is
    /// free to be reworded for readability, while anything a user greps or
    /// filters on must not change under them. It also contains no whitespace,
    /// which matters for the space-delimited PCAPNG packet comment.
    pub fn as_token(self) -> &'static str {
        match self {
            Self::ExactTuple => "exact-tuple",
            Self::WildcardLocalAddress => "wildcard-local-address",
            Self::ListenerSocket => "listener-socket",
            Self::ProcfsExact => "procfs-exact",
            Self::ProcfsRelaxed => "procfs-relaxed",
            Self::Unspecified => "unspecified",
        }
    }
}

impl fmt::Display for MatchQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Maximum number of parent processes retained for one attribution.
pub const MAX_PROCESS_ANCESTORS: usize = 4;

/// One parent in an owning process's ancestry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessAncestor {
    pub pid: u32,
    pub name: String,
    pub executable: Option<PathBuf>,
    /// Process creation time as milliseconds since the Unix epoch.
    pub started_at_unix_ms: Option<u64>,
}

/// Best-effort ancestry for an owning process.
///
/// Entries are ordered from the oldest retained ancestor to the direct
/// parent. `truncated` is true when an older ancestor was omitted by
/// [`MAX_PROCESS_ANCESTORS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessLineage {
    pub ancestors: Vec<ProcessAncestor>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Igmp,
    Arp,
}

impl Protocol {
    /// The protocol's display name as a `&'static str`. Hot paths (the
    /// connection-table render and the filter matcher) want the name as a
    /// borrowed string; going through `Display`/`to_string` there allocates a
    /// fresh `String` per row / per connection for no reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Igmp => "IGMP",
            Protocol::Arp => "ARP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Closing,
    Closed,
    Unknown,
}

impl TcpState {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
            Self::Unknown => "TCP_UNKNOWN",
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a TCP state is terminal. Closing states that can still carry
/// legitimate shutdown traffic are intentionally not included until they
/// reach TIME_WAIT or CLOSED.
pub(super) fn tcp_state_is_terminal(state: &TcpState) -> bool {
    matches!(state, TcpState::TimeWait | TcpState::Closed)
}

#[derive(Debug, Clone)]
pub enum ProtocolState {
    Tcp(TcpState),
    Udp,
    Icmp {
        icmp_type: u8,
        icmp_id: Option<u16>,
        icmp_sequence: Option<u16>,
        /// IP-to-MAC mapping carried by an NDP message's link-layer address
        /// option (ICMPv6 only), extracted by the parser when the enclosing
        /// IPv6 header proved on-link origin (hop limit 255, no Fragment
        /// Header — RFC 4861, RFC 6980). Feeds the tracker's neighbor cache,
        /// the IPv6 analogue of [`ProtocolState::Arp`].
        ndp_neighbor: Option<NdpNeighbor>,
    },
    Igmp {
        igmp_type: u8,
        group_addr: Option<std::net::Ipv4Addr>,
    },
    Arp(ArpInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpInfo {
    pub operation: ArpOperation,
    pub sender_mac: String,
    pub sender_ip: std::net::IpAddr,
    pub target_mac: String,
    pub target_ip: std::net::IpAddr,
    pub sender_vendor: Option<String>,
    pub target_vendor: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

/// One IP-to-MAC mapping extracted from an NDP (IPv6 Neighbor Discovery,
/// RFC 4861) message's link-layer address option — the IPv6 analogue of what
/// [`ArpInfo`] carries for IPv4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpNeighbor {
    /// The IPv6 address the option maps: the packet's source address for a
    /// source link-layer option (RS/RA/NS), the advertised target address for
    /// a target link-layer option (NA/Redirect).
    pub ip: std::net::IpAddr,
    /// Colon-separated lowercase MAC, as formatted by the parser.
    pub mac: String,
    /// OUI vendor, resolved at parse time when the database is loaded.
    pub vendor: Option<String>,
}

// ============================================================================
// Connection Key
// ============================================================================

/// Compact identity of a flow: protocol plus local/remote socket addresses.
///
/// Used as the connection-table key (and for matching pending TCP SYNs in RTT
/// tracking). `Copy` and fixed-size, so per-packet key construction, hashing,
/// and map lookups involve no heap allocation. The `Display` form matches the
/// historical string key format (`"TCP:1.2.3.4:80-TCP:5.6.7.8:443"`) so log
/// output is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl ConnectionKey {
    pub fn new(protocol: Protocol, local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            protocol,
            local_addr,
            remote_addr,
        }
    }
}

impl std::fmt::Display for ConnectionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}-{}:{}",
            self.protocol, self.local_addr, self.protocol, self.remote_addr
        )
    }
}

/// Classification of a connection endpoint address. `Broadcast` covers both
/// the limited broadcast (255.255.255.255) and subnet-directed broadcasts
/// (e.g. 192.168.0.255 on a /24), which require interface prefix knowledge
/// and are therefore computed by the packet parser, not derivable from the
/// address alone. IPv6 has no broadcast, only multicast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddrKind {
    #[default]
    Unicast,
    Broadcast,
    Multicast,
}

impl AddrKind {
    /// Stable lowercase token for JSON log output.
    pub fn as_token(self) -> &'static str {
        match self {
            AddrKind::Unicast => "unicast",
            AddrKind::Broadcast => "broadcast",
            AddrKind::Multicast => "multicast",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_as_str_matches_display() {
        for p in [
            Protocol::Tcp,
            Protocol::Udp,
            Protocol::Icmp,
            Protocol::Igmp,
            Protocol::Arp,
        ] {
            // Display now delegates to as_str — they must stay identical so
            // nothing reading protocol names (UI cells, filter, JSON) shifts.
            assert_eq!(p.as_str(), p.to_string());
        }
        assert_eq!(Protocol::Tcp.as_str(), "TCP");
        assert_eq!(Protocol::Arp.as_str(), "ARP");
    }

    /// Export tokens are what users grep and filter on, so they are pinned
    /// here: the prose in `as_str` may be reworded, these may not.
    #[test]
    fn match_quality_export_tokens_are_stable_and_whitespace_free() {
        let all = [
            (MatchQuality::ExactTuple, "exact-tuple"),
            (MatchQuality::WildcardLocalAddress, "wildcard-local-address"),
            (MatchQuality::ListenerSocket, "listener-socket"),
            (MatchQuality::ProcfsExact, "procfs-exact"),
            (MatchQuality::ProcfsRelaxed, "procfs-relaxed"),
            (MatchQuality::Unspecified, "unspecified"),
        ];

        for (quality, token) in all {
            assert_eq!(quality.as_token(), token);
            // The PCAPNG packet comment is space-delimited `key=value`.
            assert!(!token.contains(char::is_whitespace));
        }

        assert!(MatchQuality::ExactTuple.is_exact());
        assert!(MatchQuality::ProcfsExact.is_exact());
        assert!(!MatchQuality::ProcfsRelaxed.is_exact());
        assert!(!MatchQuality::Unspecified.is_exact());
    }

    #[test]
    fn test_tcp_state_display() {
        assert_eq!(TcpState::SynSent.to_string(), "SYN_SENT");
        assert_eq!(TcpState::SynReceived.to_string(), "SYN_RECV");
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::FinWait1.to_string(), "FIN_WAIT1");
        assert_eq!(TcpState::FinWait2.to_string(), "FIN_WAIT2");
        assert_eq!(TcpState::CloseWait.to_string(), "CLOSE_WAIT");
        assert_eq!(TcpState::LastAck.to_string(), "LAST_ACK");
        assert_eq!(TcpState::TimeWait.to_string(), "TIME_WAIT");
        assert_eq!(TcpState::Closing.to_string(), "CLOSING");
        assert_eq!(TcpState::Closed.to_string(), "CLOSED");
        assert_eq!(TcpState::Unknown.to_string(), "TCP_UNKNOWN");
    }
}
