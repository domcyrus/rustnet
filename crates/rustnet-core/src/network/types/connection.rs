use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::identity::{
    AddrKind, ArpOperation, MatchQuality, ProcessLineage, Protocol, ProtocolState, TcpState,
    tcp_state_is_terminal,
};
use super::protocol_info::{
    ApplicationProtocol, DpiInfo, QuicConnectionState, QuicInfo, QuicPacketType,
};
use super::rates::{RateTracker, TERMINAL_ARCHIVE_GRACE, TcpAnalytics, smooth_rate};

/// Distribution of connections by application protocol (from DPI)
#[derive(Debug, Clone, Default)]
pub struct AppProtocolDistribution {
    pub https_count: usize,
    pub http_count: usize,
    pub quic_count: usize,
    pub dns_count: usize,
    pub ssh_count: usize,
    pub other_count: usize,
}

impl AppProtocolDistribution {
    /// Add one connection to the distribution.
    pub fn record_connection(&mut self, conn: &Connection) {
        if let Some(dpi_info) = &conn.dpi_info {
            match &dpi_info.application {
                ApplicationProtocol::Https(_) => self.https_count += 1,
                ApplicationProtocol::Http(_) => self.http_count += 1,
                ApplicationProtocol::Quic(_) => self.quic_count += 1,
                ApplicationProtocol::Dns(_) => self.dns_count += 1,
                ApplicationProtocol::Ssh(_) => self.ssh_count += 1,
                ApplicationProtocol::Ntp(_)
                | ApplicationProtocol::Mdns(_)
                | ApplicationProtocol::Llmnr(_)
                | ApplicationProtocol::Dhcp(_)
                | ApplicationProtocol::Snmp(_)
                | ApplicationProtocol::Ssdp(_)
                | ApplicationProtocol::NetBios(_)
                | ApplicationProtocol::BitTorrent(_)
                | ApplicationProtocol::Stun(_)
                | ApplicationProtocol::Mqtt(_)
                | ApplicationProtocol::Ftp(_) => self.other_count += 1,
            }
        } else {
            self.other_count += 1;
        }
    }

    /// Calculate distribution from a list of connections
    pub fn from_connections(connections: &[Connection]) -> Self {
        let mut dist = Self::default();

        for conn in connections {
            dist.record_connection(conn);
        }

        dist
    }

    /// Get total connection count
    pub fn total(&self) -> usize {
        self.https_count
            + self.http_count
            + self.quic_count
            + self.dns_count
            + self.ssh_count
            + self.other_count
    }

    /// Get distribution as percentages (label, count, percentage)
    pub fn as_percentages(&self) -> Vec<(&'static str, usize, f64)> {
        let total = self.total().max(1) as f64;
        [
            ("HTTPS", self.https_count),
            ("QUIC", self.quic_count),
            ("HTTP", self.http_count),
            ("DNS", self.dns_count),
            ("SSH", self.ssh_count),
            ("Other", self.other_count),
        ]
        .into_iter()
        .map(|(label, count)| (label, count, count as f64 / total * 100.0))
        .collect()
    }
}

/// Kubernetes pod and container metadata attached to a connection when the
/// owning process is part of a pod on the current node. Populated by the
/// resolver in `network::kubernetes`; `None` when rustnet is not running
/// inside (or with visibility into) a Kubernetes node.
///
/// `pod_uid`, `container_id`, and `cgroup_path` come from `/proc/<pid>/cgroup`.
/// The human-readable `pod_name`, `pod_namespace`, and `container_name` are
/// resolved from the on-disk kubelet pods directory when available.
#[cfg(feature = "kubernetes")]
#[derive(Debug, Clone, Default)]
pub struct K8sInfo {
    pub pod_uid: Option<String>,
    pub pod_name: Option<String>,
    pub pod_namespace: Option<String>,
    pub container_id: Option<String>,
    pub container_name: Option<String>,
    pub cgroup_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Connection {
    // Core identification
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    /// Kind of the local endpoint address. Broadcast/multicast flows keep the
    /// group/broadcast address on the local side when the sender is a peer;
    /// this field lets the UI render that intentionally.
    pub local_addr_kind: AddrKind,
    pub remote_addr_kind: AddrKind,
    /// Whether the remote endpoint is a default-gateway address from the
    /// host's routing table at the time the last packet was observed.
    pub remote_is_gateway: bool,

    // Protocol state
    pub protocol_state: ProtocolState,

    // Process information
    pub pid: Option<u32>,
    /// Parent process id of the owning process, when it was still available
    /// during attribution.
    pub process_ppid: Option<u32>,
    pub process_name: Option<String>,
    /// Absolute path of the owning process's executable, when the platform can
    /// resolve it.
    ///
    /// `Arc<Path>` rather than `PathBuf`: every connection of a process shares
    /// one executable path, and `Connection` is cloned in bulk on every
    /// snapshot tick (see `snapshot_clone`). Interning keeps that clone from
    /// allocating per connection.
    pub executable: Option<Arc<Path>>,
    /// Effective user id of the owning process, when the platform reports it.
    pub process_uid: Option<u32>,
    /// Effective group id of the owning process, when the platform reports it.
    pub process_gid: Option<u32>,
    /// How confidently the attribution was matched to this connection. `None`
    /// until the connection is attributed.
    pub attribution_quality: Option<MatchQuality>,
    /// Parent processes, ordered from the oldest retained ancestor to the
    /// direct parent. Shared because connection snapshots are cloned in bulk.
    pub process_lineage: Option<Arc<ProcessLineage>>,

    // Kubernetes attribution (pod/container), populated on K8s nodes
    #[cfg(feature = "kubernetes")]
    pub k8s_info: Option<K8sInfo>,

    // Connection direction: true = outgoing (local initiated), false = incoming (remote initiated)
    // Only set for TCP when we observe the handshake (SYN/SYN+ACK), None otherwise
    pub connection_direction: Option<bool>,

    // Traffic statistics
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,

    // Timing
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
    /// First observation that placed the connection in a terminal state.
    /// Later teardown retransmissions may update `last_activity`, but they do
    /// not move this deadline and therefore cannot postpone archival.
    pub terminal_since: Option<SystemTime>,

    // Service identification
    pub service_name: Option<String>,

    // Deep packet inspection
    pub dpi_info: Option<DpiInfo>,

    // Performance metrics
    pub rate_tracker: RateTracker,

    // Backward compatibility fields - updated by rate_tracker
    pub current_incoming_rate_bps: f64,
    pub current_outgoing_rate_bps: f64,

    // TCP analytics (only for TCP connections)
    pub tcp_analytics: Option<TcpAnalytics>,

    // Initial RTT measurement: TCP SYN/SYN-ACK timing, or the QUIC long-header
    // handshake exchange. Set once, from the first round trip observed.
    pub initial_rtt: Option<std::time::Duration>,

    // Latest DNS query→response time, paired by transaction ID. Updated on
    // every completed query; includes resolver processing, so it is kept
    // separate from the transport-level `initial_rtt`.
    pub dns_response_time: Option<std::time::Duration>,

    // Latest NetBIOS request-to-response time, paired by transaction ID.
    // Kept separate from transport RTT because it includes service processing.
    pub netbios_response_time: Option<std::time::Duration>,

    // Latest ICMP echo round trip, paired by identifier and sequence number.
    // Updated on every completed outgoing request and incoming reply pair.
    pub icmp_echo_rtt: Option<std::time::Duration>,

    // Latest STUN request→response round trip, paired by transaction ID.
    // Like `dns_response_time`, kept separate from the transport-level RTT.
    pub stun_rtt: Option<std::time::Duration>,

    // Latest NTP request→response round trip, paired by the originate
    // timestamp echo. Kept separate from the transport-level RTT.
    pub ntp_rtt: Option<std::time::Duration>,

    // GeoIP information for remote address
    pub geoip_info: Option<crate::network::geoip::GeoIpInfo>,

    // Hostname inferred from a recently observed DNS resolution, populated
    // when no authoritative source like SNI/Host is available.
    pub attributed_hostname: Option<AttributedHostname>,

    // Historic connection tracking
    pub is_historic: bool,
    pub closed_at: Option<SystemTime>,
}

/// Source of an attributed hostname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributionSource {
    /// Learned from a DNS response captured on the wire.
    CapturedDns,
}

/// Hostname attributed to a connection from a separate signal (e.g. an
/// observed DNS response), as opposed to extracted from the connection
/// itself (SNI / Host header / reverse DNS).
#[derive(Debug, Clone)]
pub struct AttributedHostname {
    pub name: String,
    pub source: AttributionSource,
    pub observed_at: SystemTime,
}

impl Connection {
    /// Create a new connection
    pub fn new(
        protocol: Protocol,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: ProtocolState,
    ) -> Self {
        let now = SystemTime::now();
        // Initialize TCP analytics for TCP connections
        let tcp_analytics = if protocol == Protocol::Tcp {
            Some(TcpAnalytics::new())
        } else {
            None
        };
        let terminal_since =
            matches!(&state, ProtocolState::Tcp(tcp) if tcp_state_is_terminal(tcp)).then_some(now);

        Self {
            protocol,
            local_addr,
            remote_addr,
            local_addr_kind: AddrKind::default(),
            remote_addr_kind: AddrKind::default(),
            remote_is_gateway: false,
            protocol_state: state,
            pid: None,
            process_ppid: None,
            process_name: None,
            executable: None,
            process_uid: None,
            process_gid: None,
            attribution_quality: None,
            process_lineage: None,
            #[cfg(feature = "kubernetes")]
            k8s_info: None,
            connection_direction: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            created_at: now,
            last_activity: now,
            terminal_since,
            service_name: None,
            dpi_info: None,
            rate_tracker: RateTracker::new(),
            current_incoming_rate_bps: 0.0,
            current_outgoing_rate_bps: 0.0,
            tcp_analytics,
            initial_rtt: None,
            dns_response_time: None,
            netbios_response_time: None,
            icmp_echo_rtt: None,
            stun_rtt: None,
            ntp_rtt: None,
            geoip_info: None,
            attributed_hostname: None,
            is_historic: false,
            closed_at: None,
        }
    }

    /// Generate a unique key for this connection.
    /// Historic connections include `created_at` to disambiguate multiple
    /// closed connections that shared the same 4-tuple.
    pub fn key(&self) -> String {
        if self.is_historic {
            let created_nanos = self
                .created_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!(
                "{:?}:{}-{:?}:{}:h:{}",
                self.protocol, self.local_addr, self.protocol, self.remote_addr, created_nanos
            )
        } else {
            format!(
                "{:?}:{}-{:?}:{}",
                self.protocol, self.local_addr, self.protocol, self.remote_addr
            )
        }
    }

    /// Cheap clone for read-only snapshots (UI, historic archive).
    ///
    /// Identical to `clone()` except the rate-tracker sample buffer is
    /// dropped, so the live connection stays the unique owner of its
    /// samples and the next per-packet rate update avoids a copy-on-write
    /// deep copy. Consumers must read the cached `current_*_rate_bps`
    /// fields rather than recompute rates from samples.
    pub fn snapshot_clone(&self) -> Self {
        Self {
            rate_tracker: self.rate_tracker.clone_without_samples(),
            ..self.clone()
        }
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed().unwrap_or_default()
    }

    /// Whether the observed transport state is terminal. Closing TCP states
    /// that can still carry legitimate shutdown traffic are intentionally not
    /// included until they reach TIME_WAIT or CLOSED.
    pub fn is_terminal(&self) -> bool {
        match &self.protocol_state {
            ProtocolState::Tcp(state) => tcp_state_is_terminal(state),
            ProtocolState::Udp => self.dpi_info.as_ref().is_some_and(|dpi| {
                matches!(
                    &dpi.application,
                    ApplicationProtocol::Quic(quic)
                        if quic.connection_close.is_some()
                            || matches!(
                                quic.connection_state,
                                QuicConnectionState::Draining | QuicConnectionState::Closed
                            )
                )
            }),
            _ => false,
        }
    }

    /// Whether a strong new-session signal should start a fresh generation
    /// instead of being merged into this connection.
    pub fn is_closing_or_terminal(&self) -> bool {
        match &self.protocol_state {
            ProtocolState::Tcp(state) => matches!(
                state,
                TcpState::FinWait1
                    | TcpState::FinWait2
                    | TcpState::CloseWait
                    | TcpState::LastAck
                    | TcpState::TimeWait
                    | TcpState::Closing
                    | TcpState::Closed
            ),
            ProtocolState::Udp => self.is_terminal(),
            _ => false,
        }
    }

    /// Timestamp used to determine cleanup eligibility and staleness color.
    /// Terminal connections use their first terminal observation so duplicate
    /// FIN, ACK, RST, or close traffic cannot keep them live indefinitely.
    fn cleanup_reference_time(&self) -> SystemTime {
        if self.is_terminal() {
            self.terminal_since.unwrap_or(self.last_activity)
        } else {
            self.last_activity
        }
    }

    /// Time elapsed on the cleanup clock at a supplied timestamp.
    pub fn cleanup_age(&self, now: SystemTime) -> Duration {
        now.duration_since(self.cleanup_reference_time())
            .unwrap_or_default()
    }

    /// Get display state with enhanced UDP/QUIC visibility
    pub fn state(&self) -> Cow<'_, str> {
        match &self.protocol_state {
            ProtocolState::Tcp(tcp_state) => {
                let name = match tcp_state {
                    TcpState::SynSent => "SYN_SENT",
                    TcpState::SynReceived => "SYN_RECV",
                    TcpState::Established => "ESTABLISHED",
                    TcpState::FinWait1 => "FIN_WAIT1",
                    TcpState::FinWait2 => "FIN_WAIT2",
                    TcpState::CloseWait => "CLOSE_WAIT",
                    TcpState::LastAck => "LAST_ACK",
                    TcpState::TimeWait => "TIME_WAIT",
                    TcpState::Closing => "CLOSING",
                    TcpState::Closed => "CLOSED",
                    TcpState::Unknown => "TCP_UNKNOWN",
                };
                Cow::Borrowed(name)
            }
            ProtocolState::Udp => {
                // Check if it's a DPI-identified protocol
                if let Some(dpi_info) = &self.dpi_info {
                    match &dpi_info.application {
                        ApplicationProtocol::Quic(quic) => {
                            // Enhanced QUIC state display
                            Cow::Borrowed(match quic.connection_state {
                                QuicConnectionState::Initial => "QUIC_INITIAL",
                                QuicConnectionState::Handshaking => "QUIC_HANDSHAKE",
                                QuicConnectionState::Connected => "QUIC_CONNECTED",
                                QuicConnectionState::Draining => "QUIC_DRAINING",
                                QuicConnectionState::Closed => "QUIC_CLOSED",
                                QuicConnectionState::Unknown => match quic.packet_type {
                                    QuicPacketType::ZeroRtt => "QUIC_0RTT",
                                    QuicPacketType::Retry => "QUIC_RETRY",
                                    QuicPacketType::VersionNegotiation => "QUIC_VERSION_NEG",
                                    _ => "QUIC_UNKNOWN",
                                },
                            })
                        }
                        ApplicationProtocol::Dns(dns) => Cow::Borrowed(if dns.is_response {
                            "DNS_RESPONSE"
                        } else {
                            "DNS_QUERY"
                        }),
                        ApplicationProtocol::Http(_) => Cow::Borrowed("HTTP_UDP"),
                        ApplicationProtocol::Https(_) => Cow::Borrowed("HTTPS_UDP"),
                        ApplicationProtocol::Ssh(_) => Cow::Borrowed("SSH_UDP"),
                        ApplicationProtocol::Ntp(_) => Cow::Borrowed("NTP"),
                        ApplicationProtocol::Mdns(info) => Cow::Borrowed(if info.is_response {
                            "MDNS_RESPONSE"
                        } else {
                            "MDNS_QUERY"
                        }),
                        ApplicationProtocol::Llmnr(info) => Cow::Borrowed(if info.is_response {
                            "LLMNR_RESPONSE"
                        } else {
                            "LLMNR_QUERY"
                        }),
                        ApplicationProtocol::Dhcp(info) => {
                            Cow::Owned(format!("DHCP_{}", info.message_type))
                        }
                        ApplicationProtocol::Snmp(info) => {
                            Cow::Owned(format!("SNMP_{}", info.pdu_type))
                        }
                        ApplicationProtocol::Ssdp(info) => {
                            Cow::Owned(format!("SSDP_{}", info.method))
                        }
                        ApplicationProtocol::NetBios(info) => {
                            Cow::Owned(format!("NETBIOS_{}", info.service))
                        }
                        ApplicationProtocol::BitTorrent(_) => Cow::Borrowed("BT_UDP"),
                        ApplicationProtocol::Stun(info) => {
                            Cow::Owned(format!("STUN_{}", info.message_class))
                        }
                        ApplicationProtocol::Mqtt(_) => Cow::Borrowed("MQTT_UDP"),
                        ApplicationProtocol::Ftp(_) => Cow::Borrowed("FTP_UDP"),
                    }
                } else {
                    // Regular UDP without DPI classification
                    // Check activity level to provide more meaningful states
                    let idle_time = self.idle_time();
                    Cow::Borrowed(if idle_time > Duration::from_secs(60) {
                        "UDP_STALE"
                    } else if idle_time > Duration::from_secs(30) {
                        "UDP_IDLE"
                    } else {
                        "UDP_ACTIVE"
                    })
                }
            }
            ProtocolState::Icmp {
                icmp_type, icmp_id, ..
            } => match icmp_type {
                8 | 128 => match icmp_id {
                    Some(id) => Cow::Owned(format!("ECHO_REQ({})", id)),
                    None => Cow::Borrowed("ECHO_REQUEST"),
                },
                0 | 129 => match icmp_id {
                    Some(id) => Cow::Owned(format!("ECHO_REP({})", id)),
                    None => Cow::Borrowed("ECHO_REPLY"),
                },
                3 => Cow::Borrowed("DEST_UNREACH"),
                11 => Cow::Borrowed("TIME_EXCEEDED"),
                _ => Cow::Borrowed("ICMP_OTHER"),
            },
            ProtocolState::Igmp {
                igmp_type,
                group_addr,
            } => {
                let type_str = match igmp_type {
                    0x11 => "QUERY",
                    0x12 => "REPORT_V1",
                    0x16 => "REPORT_V2",
                    0x22 => "REPORT_V3",
                    0x17 => "LEAVE_GROUP",
                    _ => "IGMP_OTHER",
                };
                if let Some(addr) = group_addr {
                    Cow::Owned(format!("{}({})", type_str, addr))
                } else {
                    Cow::Borrowed(type_str)
                }
            }
            ProtocolState::Arp(info) => match info.operation {
                ArpOperation::Request => {
                    if let Some(ref vendor) = info.sender_vendor {
                        Cow::Owned(format!("ARP_WHO_HAS {} ({})", info.target_ip, vendor))
                    } else {
                        Cow::Owned(format!("ARP_WHO_HAS {}", info.target_ip))
                    }
                }
                ArpOperation::Reply => {
                    if let Some(ref vendor) = info.sender_vendor {
                        Cow::Owned(format!("ARP_IS_AT {} ({})", info.sender_mac, vendor))
                    } else {
                        Cow::Owned(format!("ARP_IS_AT {}", info.sender_mac))
                    }
                }
            },
        }
    }

    /// Push a rate sample for the current byte counts (called per-packet).
    /// Pruning and rate recalculation are deferred to `refresh_rates`.
    pub fn update_rates(&mut self) {
        self.rate_tracker
            .update(self.bytes_sent, self.bytes_received);
    }

    /// Prune stale samples and recalculate cached rates.
    /// Called periodically (e.g. every 1s). Pushing new samples happens per-packet
    /// via `update_rates`, keeping the hot path free of pruning/recalculation.
    ///
    /// Smooths only **falling** rates to prevent the bandwidth sort from jumping
    /// when traffic is bursty. Rising rates are reflected immediately.
    /// When the raw rate hits zero (traffic stopped), decay is aggressive (~3s
    /// to reach zero). When rates merely fluctuate, decay is gentler.
    pub fn refresh_rates(&mut self) {
        self.rate_tracker.prune();
        let raw_in = self.rate_tracker.get_incoming_rate_bps();
        let raw_out = self.rate_tracker.get_outgoing_rate_bps();

        self.current_incoming_rate_bps = smooth_rate(raw_in, self.current_incoming_rate_bps);
        self.current_outgoing_rate_bps = smooth_rate(raw_out, self.current_outgoing_rate_bps);
    }

    /// Whether either cached rate is still non-zero (i.e. smoothing hasn't
    /// decayed to zero yet). Used to decide if `refresh_rates` can be skipped.
    pub fn has_nonzero_rates(&self) -> bool {
        self.current_incoming_rate_bps != 0.0 || self.current_outgoing_rate_bps != 0.0
    }

    /// Get dynamic timeout for this connection based on protocol and state
    pub fn get_timeout(&self) -> Duration {
        match &self.protocol_state {
            ProtocolState::Tcp(tcp_state) => self.get_tcp_timeout(tcp_state),
            ProtocolState::Udp => {
                if let Some(dpi_info) = &self.dpi_info {
                    match &dpi_info.application {
                        ApplicationProtocol::Quic(quic) => self.get_quic_timeout(quic),
                        ApplicationProtocol::Dns(_) => Duration::from_secs(30),
                        // HTTP/3 connections need longer timeouts for connection reuse
                        ApplicationProtocol::Http(_) => Duration::from_secs(600), // 10 minutes (was 3 min)
                        ApplicationProtocol::Https(_) => Duration::from_secs(600), // 10 minutes (was 3 min)
                        ApplicationProtocol::Ssh(_) => Duration::from_secs(1800), // SSH can be very long-lived (30 min)
                        // New UDP protocols - use reasonable timeouts
                        ApplicationProtocol::Ntp(_) => Duration::from_secs(30),
                        ApplicationProtocol::Mdns(_) => Duration::from_secs(30),
                        ApplicationProtocol::Llmnr(_) => Duration::from_secs(30),
                        ApplicationProtocol::Dhcp(_) => Duration::from_secs(60),
                        ApplicationProtocol::Snmp(_) => Duration::from_secs(60),
                        ApplicationProtocol::Ssdp(_) => Duration::from_secs(30),
                        ApplicationProtocol::NetBios(_) => Duration::from_secs(60),
                        ApplicationProtocol::BitTorrent(_) => Duration::from_secs(60),
                        ApplicationProtocol::Stun(_) => Duration::from_secs(30),
                        ApplicationProtocol::Mqtt(_) => Duration::from_secs(120),
                        ApplicationProtocol::Ftp(_) => Duration::from_secs(60),
                    }
                } else {
                    // Regular UDP without DPI classification
                    Duration::from_secs(60)
                }
            }
            ProtocolState::Icmp { .. } => Duration::from_secs(10),
            ProtocolState::Igmp { .. } => Duration::from_secs(10),
            ProtocolState::Arp(_) => Duration::from_secs(30),
        }
    }

    /// Get TCP-specific timeout based on connection state and application protocol
    fn get_tcp_timeout(&self, tcp_state: &TcpState) -> Duration {
        match tcp_state {
            TcpState::Established => {
                // Check if we have DPI info for protocol-specific timeouts
                if let Some(dpi_info) = &self.dpi_info {
                    match &dpi_info.application {
                        // SSH connections need very long timeouts for interactive sessions
                        ApplicationProtocol::Ssh(_) => return Duration::from_secs(1800), // 30 minutes
                        // HTTP/HTTPS keep-alive connections
                        ApplicationProtocol::Http(_) | ApplicationProtocol::Https(_) => {
                            return Duration::from_secs(600); // 10 minutes
                        }
                        // Other protocols use default logic below
                        _ => {}
                    }
                }

                // Every packet already resets last_activity, so one explicit
                // generic idle timeout is clearer than changing the deadline
                // after the first minute of inactivity.
                Duration::from_secs(300)
            }
            TcpState::TimeWait => Duration::from_secs(30), // Standard TCP TIME_WAIT
            TcpState::Closed => TERMINAL_ARCHIVE_GRACE,
            TcpState::FinWait1 | TcpState::FinWait2 => Duration::from_secs(60), // Allow for proper close sequence
            TcpState::CloseWait | TcpState::LastAck => Duration::from_secs(60),
            TcpState::SynSent | TcpState::SynReceived => Duration::from_secs(60), // Connection establishment
            TcpState::Closing => Duration::from_secs(30),
            TcpState::Unknown => Duration::from_secs(120),
        }
    }

    /// Get QUIC-specific timeout based on connection state and close frames
    fn get_quic_timeout(&self, quic: &QuicInfo) -> Duration {
        // First check if we've detected a CONNECTION_CLOSE frame
        if quic.connection_close.is_some() {
            return TERMINAL_ARCHIVE_GRACE;
        }

        // Use state-based timeout if no close frame
        match quic.connection_state {
            QuicConnectionState::Initial => Duration::from_secs(60), // Allow handshake time
            QuicConnectionState::Handshaking => Duration::from_secs(60), // Crypto negotiation
            QuicConnectionState::Connected => {
                // Use idle timeout from transport params if available, otherwise default
                // Note: We cannot see CONNECTION_CLOSE frames (they're encrypted in 1-RTT packets)
                // so we must rely on timeouts to clean up closed connections
                if let Some(idle_timeout) = quic.idle_timeout {
                    idle_timeout
                } else {
                    // Use 3 minutes - matches typical browser idle timeouts
                    // and gives connections enough time to remain visible
                    Duration::from_secs(180)
                }
            }
            QuicConnectionState::Draining | QuicConnectionState::Closed => TERMINAL_ARCHIVE_GRACE,
            QuicConnectionState::Unknown => Duration::from_secs(120), // Conservative default
        }
    }

    /// Check if this connection should be cleaned up based on its timeout
    pub fn should_cleanup(&self, now: SystemTime) -> bool {
        let timeout = self.get_timeout();
        self.cleanup_age(now) > timeout
    }

    /// Get the staleness level as a percentage (0.0 to 1.0+)
    /// Returns how close the connection is to being cleaned up
    /// - 0.0 = just created
    /// - 0.75 = at warning threshold
    /// - 1.0 = will be cleaned up
    /// - >1.0 = should have been cleaned up already
    pub fn staleness_ratio(&self) -> f32 {
        let timeout = self.get_timeout();
        let idle = self.cleanup_reference_time().elapsed().unwrap_or_default();

        idle.as_secs_f32() / timeout.as_secs_f32()
    }

    /// Live round-trip estimate for display: the smoothed TCP data RTT once the
    /// continuous estimator has samples, otherwise a TCP/QUIC handshake RTT or
    /// the latest ICMP echo RTT.
    pub fn current_rtt(&self) -> Option<Duration> {
        self.tcp_analytics
            .as_ref()
            .and_then(|a| a.smoothed_rtt)
            .or(self.initial_rtt)
            .or(self.icmp_echo_rtt)
    }

    /// Hostname the connection itself vouches for: the TLS SNI (HTTPS /
    /// QUIC) or the HTTP `Host:` header, excluding SNI truncated during
    /// ClientHello parsing (`[PARTIAL]`). Shared by DNS attribution
    /// (which short-circuits when this is set) and the UI (which shows
    /// attributed names only in its absence) so the two predicates
    /// cannot drift.
    pub fn authoritative_hostname(&self) -> Option<&str> {
        self.dpi_info
            .as_ref()
            .and_then(|dpi| dpi.application.hostname())
            .filter(|name| !crate::network::dpi::is_partial_sni(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::rates::RateSample;
    use crate::network::types::{
        ArpInfo, CryptoFrameReassembler, DnsInfo, DnsQueryType, ProcessAncestor, QuicCloseInfo,
        TrafficHistory,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::Instant;

    fn create_test_connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn test_connection_snapshot_clone_preserves_cached_fields() {
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321);
        let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let mut conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.bytes_sent = 1234;
        conn.bytes_received = 5678;
        conn.update_rates();
        conn.current_incoming_rate_bps = 42.0;
        conn.current_outgoing_rate_bps = 24.0;

        let snap = conn.snapshot_clone();

        assert_eq!(snap.bytes_sent, 1234);
        assert_eq!(snap.bytes_received, 5678);
        assert_eq!(snap.current_incoming_rate_bps, 42.0);
        assert_eq!(snap.current_outgoing_rate_bps, 24.0);
        assert_eq!(snap.local_addr, conn.local_addr);
        assert_eq!(snap.remote_addr, conn.remote_addr);

        // The snapshot must not share the sample buffer with the original.
        assert_eq!(Arc::strong_count(&conn.rate_tracker.samples), 1);
        assert!(snap.rate_tracker.samples.is_empty());
    }

    /// The snapshot provider clones every connection on every tick, so process
    /// attribution allocations must be shared rather than copied per clone.
    #[test]
    fn snapshot_clone_shares_process_attribution_allocations() {
        use std::path::Path;

        let mut conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 54321),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            ProtocolState::Tcp(TcpState::Established),
        );
        let executable: Arc<Path> = Arc::from(Path::new("/usr/bin/curl"));
        conn.executable = Some(Arc::clone(&executable));
        conn.process_ppid = Some(999);
        conn.process_uid = Some(1000);
        conn.process_gid = Some(100);
        conn.attribution_quality = Some(MatchQuality::ExactTuple);
        let lineage = Arc::new(ProcessLineage {
            ancestors: vec![ProcessAncestor {
                pid: 1,
                name: "init".to_string(),
                executable: Some(PathBuf::from("/sbin/init")),
                started_at_unix_ms: Some(1_700_000_000_000),
            }],
            truncated: false,
        });
        conn.process_lineage = Some(Arc::clone(&lineage));

        let snap = conn.snapshot_clone();

        assert_eq!(snap.executable.as_deref(), Some(Path::new("/usr/bin/curl")));
        assert_eq!(snap.process_ppid, Some(999));
        assert_eq!(snap.process_uid, Some(1000));
        assert_eq!(snap.process_gid, Some(100));
        assert_eq!(snap.attribution_quality, Some(MatchQuality::ExactTuple));
        assert_eq!(snap.process_lineage.as_deref(), Some(lineage.as_ref()));
        assert!(
            Arc::ptr_eq(
                conn.executable.as_ref().unwrap(),
                snap.executable.as_ref().unwrap()
            ),
            "the clone must share the path allocation, not copy it"
        );
        assert!(Arc::ptr_eq(
            conn.process_lineage.as_ref().unwrap(),
            snap.process_lineage.as_ref().unwrap()
        ));
    }

    #[test]
    fn new_connections_carry_no_attribution() {
        let conn = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 2),
            ProtocolState::Tcp(TcpState::Established),
        );

        assert!(conn.executable.is_none());
        assert!(conn.process_ppid.is_none());
        assert!(conn.process_uid.is_none());
        assert!(conn.process_gid.is_none());
        assert!(conn.attribution_quality.is_none());
        assert!(conn.process_lineage.is_none());
    }

    #[test]
    fn test_connection_rate_integration() {
        let mut conn = create_test_connection();
        let start = Instant::now();

        // Simulate receiving packets - use internal rate_tracker directly for deterministic timing
        conn.bytes_sent = 1000;
        conn.bytes_received = 500;
        conn.rate_tracker
            .update_at_time(start, conn.bytes_sent, conn.bytes_received);

        conn.bytes_sent = 3000;
        conn.bytes_received = 1500;
        conn.rate_tracker.update_at_time(
            start + Duration::from_secs(1),
            conn.bytes_sent,
            conn.bytes_received,
        );

        // Update cached rate values
        conn.current_outgoing_rate_bps = conn
            .rate_tracker
            .get_outgoing_rate_at(start + Duration::from_secs(1));
        conn.current_incoming_rate_bps = conn
            .rate_tracker
            .get_incoming_rate_at(start + Duration::from_secs(1));

        // Verify backward compatibility fields are updated
        assert!(conn.current_outgoing_rate_bps >= 0.0);
        assert!(conn.current_incoming_rate_bps >= 0.0);
    }

    #[test]
    fn test_connection_refresh_rates() {
        // Test that refresh_rates() properly updates cached rate values
        let mut conn = create_test_connection();
        let start = Instant::now();

        // Initialize the rate tracker properly
        conn.rate_tracker.initialize_with_counts(0, 0);

        // Simulate first packet
        conn.bytes_sent = 50_000;
        conn.bytes_received = 25_000;
        conn.rate_tracker
            .update_at_time(start, conn.bytes_sent, conn.bytes_received);

        // Simulate more traffic after 1 second
        conn.bytes_sent = 100_000;
        conn.bytes_received = 50_000;
        conn.rate_tracker.update_at_time(
            start + Duration::from_secs(1),
            conn.bytes_sent,
            conn.bytes_received,
        );

        // Update cached rates at the 1-second mark
        let check_time = start + Duration::from_secs(1);
        conn.current_outgoing_rate_bps = conn.rate_tracker.get_outgoing_rate_at(check_time);
        conn.current_incoming_rate_bps = conn.rate_tracker.get_incoming_rate_at(check_time);

        // Should have non-zero rates after recent traffic (>= 1 second of data)
        assert!(
            conn.current_outgoing_rate_bps > 0.0,
            "Should have outgoing rate: {}",
            conn.current_outgoing_rate_bps
        );
        assert!(
            conn.current_incoming_rate_bps > 0.0,
            "Should have incoming rate: {}",
            conn.current_incoming_rate_bps
        );

        // Check rates at a time after samples become stale
        // Newest sample is at start+1s, window is 10s, threshold is 1.1x
        // So need to check at > start + 1s + 11s = start + 12.1s
        let idle_time = start + Duration::from_millis(12200);
        conn.current_outgoing_rate_bps = conn.rate_tracker.get_outgoing_rate_at(idle_time);
        conn.current_incoming_rate_bps = conn.rate_tracker.get_incoming_rate_at(idle_time);

        // Rates should be zero after long idle
        assert_eq!(
            conn.current_outgoing_rate_bps, 0.0,
            "Should be zero after 10+ seconds idle"
        );
        assert_eq!(
            conn.current_incoming_rate_bps, 0.0,
            "Should be zero after 10+ seconds idle"
        );
    }

    #[test]
    fn test_enhanced_state_display_tcp() {
        let mut conn = create_test_connection();

        // Test established TCP state
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);
        assert_eq!(conn.state(), "ESTABLISHED");

        // Test other TCP states
        conn.protocol_state = ProtocolState::Tcp(TcpState::SynSent);
        assert_eq!(conn.state(), "SYN_SENT");

        conn.protocol_state = ProtocolState::Tcp(TcpState::TimeWait);
        assert_eq!(conn.state(), "TIME_WAIT");

        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);
        assert_eq!(conn.state(), "CLOSED");
    }

    #[test]
    fn test_enhanced_state_display_quic() {
        let mut conn = Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            ProtocolState::Udp,
        );

        // Test QUIC with different states
        let mut quic_info = QuicInfo::new(0x00000001);
        quic_info.connection_state = QuicConnectionState::Initial;

        let dpi_info = DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_info.clone())),
            last_update_time: Instant::now(),
        };
        conn.dpi_info = Some(dpi_info);

        assert_eq!(conn.state(), "QUIC_INITIAL");

        // Test connected state
        let mut quic_connected = quic_info.clone();
        quic_connected.connection_state = QuicConnectionState::Connected;
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_connected)),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "QUIC_CONNECTED");

        // Test draining state
        let mut quic_draining = quic_info.clone();
        quic_draining.connection_state = QuicConnectionState::Draining;
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_draining)),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "QUIC_DRAINING");
    }

    #[test]
    fn test_enhanced_state_display_dns() {
        let mut conn = Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            ProtocolState::Udp,
        );

        // Test DNS query
        let dns_query = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: vec![],
            is_response: false,
            txid: 0x1234,
            rcode: None,
            nodata: None,
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_query),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "DNS_QUERY");

        // Test DNS response
        let dns_response = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: vec!["93.184.216.34".parse().unwrap()],
            is_response: true,
            txid: 0x1234,
            rcode: Some(0),
            nodata: Some(false),
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_response),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "DNS_RESPONSE");
    }

    #[test]
    fn test_enhanced_state_display_regular_udp() {
        let mut conn = Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
            ProtocolState::Udp,
        );

        // No DPI info - should show activity-based state
        assert_eq!(conn.state(), "UDP_ACTIVE"); // Fresh connection

        // Simulate aging the connection
        conn.last_activity = SystemTime::now() - Duration::from_secs(45);
        assert_eq!(conn.state(), "UDP_IDLE"); // Idle but not stale

        conn.last_activity = SystemTime::now() - Duration::from_secs(90);
        assert_eq!(conn.state(), "UDP_STALE"); // Stale connection
    }

    #[test]
    fn test_dynamic_timeout_tcp() {
        let mut conn = create_test_connection();

        // Generic established connections use one explicit idle timeout.
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);
        assert_eq!(conn.get_timeout(), Duration::from_secs(300));

        // The timeout no longer changes after the first minute.
        conn.last_activity = SystemTime::now() - Duration::from_secs(120);
        assert_eq!(conn.get_timeout(), Duration::from_secs(300));

        // Test TIME_WAIT
        conn.protocol_state = ProtocolState::Tcp(TcpState::TimeWait);
        assert_eq!(conn.get_timeout(), Duration::from_secs(30));

        // Test closed connections
        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);
        assert_eq!(conn.get_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn test_dynamic_timeout_quic() {
        let mut conn = Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            ProtocolState::Udp,
        );

        // Test QUIC with CONNECTION_CLOSE frame
        let mut quic_info = QuicInfo::new(0x00000001);
        quic_info.connection_close = Some(QuicCloseInfo {
            frame_type: 0x1c, // Transport close
            error_code: 0,    // NO_ERROR
        });

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_info)),
            last_update_time: Instant::now(),
        });

        assert_eq!(conn.get_timeout(), Duration::from_secs(15));

        // Test application close
        let mut quic_app_close = QuicInfo::new(0x00000001);
        quic_app_close.connection_close = Some(QuicCloseInfo {
            frame_type: 0x1d, // Application close
            error_code: 1,
        });

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_app_close)),
            last_update_time: Instant::now(),
        });

        assert_eq!(conn.get_timeout(), Duration::from_secs(15));
    }

    #[test]
    fn test_dynamic_timeout_dns() {
        let mut conn = Connection::new(
            Protocol::Udp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            ProtocolState::Udp,
        );

        let dns_info = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: vec![],
            is_response: false,
            txid: 0x1234,
            rcode: None,
            nodata: None,
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_info),
            last_update_time: Instant::now(),
        });

        assert_eq!(conn.get_timeout(), Duration::from_secs(30)); // Short timeout for DNS
    }

    #[test]
    fn test_should_cleanup() {
        let mut conn = create_test_connection();
        let now = SystemTime::now();

        // Fresh connection should not be cleaned up
        assert!(!conn.should_cleanup(now));

        // Test TCP closed connection cleanup
        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);
        conn.last_activity = now - Duration::from_secs(20); // Beyond terminal archive grace
        assert!(conn.should_cleanup(now));

        // Test established connection within timeout
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);
        conn.last_activity = now - Duration::from_secs(100); // Within 300s timeout
        assert!(!conn.should_cleanup(now));

        // Test established connection beyond timeout
        conn.last_activity = now - Duration::from_secs(350); // Beyond 300s timeout
        assert!(conn.should_cleanup(now));
    }

    #[test]
    fn test_staleness_ratio() {
        let mut conn = create_test_connection();
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);

        // Fresh connection - staleness ratio near 0
        let ratio = conn.staleness_ratio();
        assert!(
            ratio < 0.05,
            "Fresh connection should have low staleness ratio"
        );

        // At 50% of timeout (300s total for idle, 150s elapsed)
        conn.last_activity = SystemTime::now() - Duration::from_secs(150);
        let ratio = conn.staleness_ratio();
        assert!(
            (ratio - 0.5).abs() < 0.1,
            "Staleness ratio should be around 0.5, got {}",
            ratio
        );

        // At 75% of timeout (warning threshold) - 225s
        conn.last_activity = SystemTime::now() - Duration::from_secs(225);
        let ratio = conn.staleness_ratio();
        assert!(
            ratio >= 0.75,
            "Staleness ratio should be >= 0.75 at warning threshold, got {}",
            ratio
        );

        // At 90% of timeout (critical threshold) - 270s
        conn.last_activity = SystemTime::now() - Duration::from_secs(270);
        let ratio = conn.staleness_ratio();
        assert!(
            ratio >= 0.90,
            "Staleness ratio should be >= 0.90 at critical threshold, got {}",
            ratio
        );

        // Beyond timeout - 350s (beyond 300s timeout)
        conn.last_activity = SystemTime::now() - Duration::from_secs(350);
        let ratio = conn.staleness_ratio();
        assert!(
            ratio > 1.0,
            "Staleness ratio should exceed 1.0 beyond timeout, got {}",
            ratio
        );
    }

    #[test]
    fn test_staleness_with_different_timeouts() {
        // Test TIME_WAIT (30s timeout)
        let mut conn = create_test_connection();
        conn.protocol_state = ProtocolState::Tcp(TcpState::TimeWait);

        // At 75% of 30s = 22.5s
        conn.last_activity = SystemTime::now() - Duration::from_secs(23);
        let ratio = conn.staleness_ratio();
        assert!(
            ratio >= 0.75,
            "TIME_WAIT connection should be stale at 23s, ratio: {}",
            ratio
        );

        // Test CLOSED (15s terminal archive grace)
        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);

        // At 75% of 15s = 11.25s
        conn.last_activity = SystemTime::now() - Duration::from_secs(12);
        let ratio = conn.staleness_ratio();
        assert!(
            ratio >= 0.75,
            "CLOSED connection should be stale at 4s, ratio: {}",
            ratio
        );
    }

    #[test]
    fn test_icmp_and_arp_states() {
        // Test ICMP states
        let mut conn = Connection::new(
            Protocol::Icmp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0),
            ProtocolState::Icmp {
                icmp_type: 8,
                icmp_id: Some(1234),
                icmp_sequence: Some(7),
                ndp_neighbor: None,
            },
        );

        assert_eq!(conn.state(), "ECHO_REQ(1234)");
        assert_eq!(conn.get_timeout(), Duration::from_secs(10));

        conn.protocol_state = ProtocolState::Icmp {
            icmp_type: 129,
            icmp_id: Some(1234),
            icmp_sequence: Some(7),
            ndp_neighbor: None,
        };
        assert_eq!(conn.state(), "ECHO_REP(1234)");

        // Test ARP states
        conn.protocol = Protocol::Arp;
        conn.protocol_state = ProtocolState::Arp(ArpInfo {
            operation: ArpOperation::Request,
            sender_mac: "aa:bb:cc:dd:ee:ff".to_string(),
            sender_ip: "192.168.1.100".parse().unwrap(),
            target_mac: "00:00:00:00:00:00".to_string(),
            target_ip: "192.168.1.1".parse().unwrap(),
            sender_vendor: None,
            target_vendor: None,
        });
        assert_eq!(conn.state(), "ARP_WHO_HAS 192.168.1.1");
        assert_eq!(conn.get_timeout(), Duration::from_secs(30));
    }

    #[test]
    fn struct_sizes() {
        use crate::network::geoip::GeoIpInfo;
        use crate::network::parser::ParsedPacket;

        println!("=== Struct Size Report (stack-resident bytes) ===");
        println!(
            "Connection:            {} bytes",
            std::mem::size_of::<Connection>()
        );
        println!(
            "RateTracker:           {} bytes",
            std::mem::size_of::<RateTracker>()
        );
        println!(
            "RateSample:            {} bytes",
            std::mem::size_of::<RateSample>()
        );
        println!(
            "DpiInfo:               {} bytes",
            std::mem::size_of::<DpiInfo>()
        );
        println!(
            "ApplicationProtocol:   {} bytes",
            std::mem::size_of::<ApplicationProtocol>()
        );
        println!(
            "TcpAnalytics:          {} bytes",
            std::mem::size_of::<TcpAnalytics>()
        );
        println!(
            "ProtocolState:         {} bytes",
            std::mem::size_of::<ProtocolState>()
        );
        println!(
            "GeoIpInfo:             {} bytes",
            std::mem::size_of::<GeoIpInfo>()
        );
        println!(
            "ParsedPacket:          {} bytes",
            std::mem::size_of::<ParsedPacket>()
        );
        println!(
            "CryptoFrameReassembler:{} bytes",
            std::mem::size_of::<CryptoFrameReassembler>()
        );
        println!(
            "TrafficHistory:        {} bytes",
            std::mem::size_of::<TrafficHistory>()
        );
        println!(
            "Protocol:              {} bytes",
            std::mem::size_of::<Protocol>()
        );
        println!("=================================================");

        // Sanity: Connection should be reasonable (flag if it balloons)
        assert!(
            std::mem::size_of::<Connection>() < 2048,
            "Connection struct is unexpectedly large: {} bytes",
            std::mem::size_of::<Connection>()
        );
    }
}
