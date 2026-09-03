use std::net::SocketAddr;
use std::path::PathBuf;

use super::connection::Connection;

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
    /// Matched the validated socket-table snapshot taken at startup. The
    /// owner came from BPF or a privileged procfs scan, and both the socket
    /// inode and process identity still match their startup values.
    StartupSnapshot,
    /// The backend reported an owner but could not report match provenance.
    Unspecified,
}

impl MatchQuality {
    /// Whether the connection's exact 4-tuple was found, with no relaxation.
    pub fn is_exact(self) -> bool {
        matches!(self, Self::ExactTuple | Self::ProcfsExact)
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
            Self::StartupSnapshot => "startup-snapshot",
            Self::Unspecified => "unspecified",
        }
    }
}

static_names! {
    /// Human-readable label, for display to a person.
    MatchQuality {
        ExactTuple => "exact tuple",
        WildcardLocalAddress => "wildcard local address",
        ListenerSocket => "listener socket",
        ProcfsExact => "procfs exact",
        ProcfsRelaxed => "procfs relaxed",
        StartupSnapshot => "startup snapshot",
        Unspecified => "unspecified",
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

static_names! {
    /// The protocol's display name as a `&'static str`. Hot paths (the
    /// connection-table render and the filter matcher) want the name as a
    /// borrowed string; going through `Display`/`to_string` there allocates a
    /// fresh `String` per row / per connection for no reason.
    Protocol {
        Tcp => "TCP",
        Udp => "UDP",
        Icmp => "ICMP",
        Igmp => "IGMP",
        Arp => "ARP",
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

static_names! {
    TcpState {
        SynSent => "SYN_SENT",
        SynReceived => "SYN_RECV",
        Established => "ESTABLISHED",
        FinWait1 => "FIN_WAIT1",
        FinWait2 => "FIN_WAIT2",
        CloseWait => "CLOSE_WAIT",
        LastAck => "LAST_ACK",
        TimeWait => "TIME_WAIT",
        Closing => "CLOSING",
        Closed => "CLOSED",
        Unknown => "TCP_UNKNOWN",
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
        /// Header; RFC 4861, RFC 6980). Feeds the tracker's neighbor cache,
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

/// Human-readable name for an ICMP (or ICMPv6) message type, for display in
/// the Details tab's Application card. Unknown types render as `Type N`.
///
/// This is a different display register from [`Connection::state`]'s compact
/// codes (`ECHO_REQ(id)`, `DEST_UNREACH`); a unit test keeps the two
/// special-cased type sets from drifting apart.
///
/// [`Connection::state`]: crate::network::types::Connection::state
pub fn icmp_message_name(icmp_type: u8, is_ipv6: bool) -> std::borrow::Cow<'static, str> {
    let name = if is_ipv6 {
        match icmp_type {
            128 => Some("Echo Request"),
            129 => Some("Echo Reply"),
            133 => Some("Router Solicitation"),
            134 => Some("Router Advertisement"),
            135 => Some("Neighbor Solicitation"),
            136 => Some("Neighbor Advertisement"),
            137 => Some("Redirect"),
            _ => None,
        }
    } else {
        match icmp_type {
            0 => Some("Echo Reply"),
            3 => Some("Destination Unreachable"),
            5 => Some("Redirect"),
            8 => Some("Echo Request"),
            11 => Some("Time Exceeded"),
            _ => None,
        }
    };
    match name {
        Some(name) => name.into(),
        None => format!("Type {}", icmp_type).into(),
    }
}

/// Human-readable name for an IGMP message type, for display in the Details
/// tab's Application card. Unknown types render as `Type 0xNN`.
///
/// Same display-register note as [`icmp_message_name`]: the compact codes in
/// [`Connection::state`] stay as they are, and a unit test keeps the two
/// special-cased type sets in sync.
///
/// [`Connection::state`]: crate::network::types::Connection::state
pub fn igmp_message_name(igmp_type: u8) -> std::borrow::Cow<'static, str> {
    match igmp_type {
        0x11 => "Membership Query".into(),
        0x12 => "Membership Report v1".into(),
        0x16 => "Membership Report v2".into(),
        0x22 => "Membership Report v3".into(),
        0x17 => "Leave Group".into(),
        other => format!("Type 0x{:02x}", other).into(),
    }
}

/// One IP-to-MAC mapping extracted from an NDP (IPv6 Neighbor Discovery,
/// RFC 4861) message's link-layer address option, the IPv6 analogue of what
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

    /// The key a connection is tracked under: its protocol and 4-tuple as
    /// observed, without the historic disambiguation of
    /// [`Connection::key`].
    pub fn from_connection(conn: &Connection) -> Self {
        Self::new(conn.protocol, conn.local_addr, conn.remote_addr)
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
            (MatchQuality::StartupSnapshot, "startup-snapshot"),
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
        assert!(!MatchQuality::StartupSnapshot.is_exact());
        assert!(!MatchQuality::Unspecified.is_exact());
    }

    #[test]
    fn icmp_message_names_are_family_aware() {
        assert_eq!(icmp_message_name(0, false), "Echo Reply");
        assert_eq!(icmp_message_name(3, false), "Destination Unreachable");
        assert_eq!(icmp_message_name(5, false), "Redirect");
        assert_eq!(icmp_message_name(8, false), "Echo Request");
        assert_eq!(icmp_message_name(11, false), "Time Exceeded");
        assert_eq!(icmp_message_name(128, false), "Type 128");

        assert_eq!(icmp_message_name(128, true), "Echo Request");
        assert_eq!(icmp_message_name(129, true), "Echo Reply");
        assert_eq!(icmp_message_name(133, true), "Router Solicitation");
        assert_eq!(icmp_message_name(134, true), "Router Advertisement");
        assert_eq!(icmp_message_name(135, true), "Neighbor Solicitation");
        assert_eq!(icmp_message_name(136, true), "Neighbor Advertisement");
        assert_eq!(icmp_message_name(137, true), "Redirect");
        assert_eq!(icmp_message_name(8, true), "Type 8");
    }

    #[test]
    fn igmp_message_names_cover_the_known_types() {
        assert_eq!(igmp_message_name(0x11), "Membership Query");
        assert_eq!(igmp_message_name(0x12), "Membership Report v1");
        assert_eq!(igmp_message_name(0x16), "Membership Report v2");
        assert_eq!(igmp_message_name(0x22), "Membership Report v3");
        assert_eq!(igmp_message_name(0x17), "Leave Group");
        assert_eq!(igmp_message_name(0x42), "Type 0x42");
    }

    /// `Connection::state()` renders compact codes (`ECHO_REQ`, `QUERY`) while
    /// the `*_message_name` helpers render prose for the Details Application
    /// card. The two must not drift: every type `state()` recognizes must
    /// also get a friendly name from the helper, and for IGMP the two sets
    /// are identical.
    #[test]
    fn message_name_helpers_cover_the_state_special_cases() {
        use crate::network::types::Connection;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 0);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20)), 0);

        for icmp_type in 0..=u8::MAX {
            let conn = Connection::new(
                Protocol::Icmp,
                local,
                remote,
                ProtocolState::Icmp {
                    icmp_type,
                    icmp_id: None,
                    icmp_sequence: None,
                    ndp_neighbor: None,
                },
            );
            let state_names_it = conn.state() != "ICMP_OTHER";
            let helper_names_it = !icmp_message_name(icmp_type, false).starts_with("Type ")
                || !icmp_message_name(icmp_type, true).starts_with("Type ");
            assert!(
                !state_names_it || helper_names_it,
                "state() names ICMP type {icmp_type} but icmp_message_name does not"
            );
        }

        for igmp_type in 0..=u8::MAX {
            let conn = Connection::new(
                Protocol::Igmp,
                local,
                remote,
                ProtocolState::Igmp {
                    igmp_type,
                    group_addr: None,
                },
            );
            let state_names_it = conn.state() != "IGMP_OTHER";
            let helper_names_it = !igmp_message_name(igmp_type).starts_with("Type ");
            assert_eq!(
                state_names_it, helper_names_it,
                "state() and igmp_message_name disagree on IGMP type 0x{igmp_type:02x}"
            );
        }
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
