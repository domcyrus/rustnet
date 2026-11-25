//! Shared passive diagnostic findings engine.
//!
//! Evaluates bounded, evidence-first findings from `rustnet-core` snapshots.
//! Findings describe observed wire behavior, never causal verdicts, and never
//! retain credentials or application payloads.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::SystemTime;

use crate::network::dns_analytics::{DnsAnalyticsSnapshot, DnsHealth, DnsIssueKind};
use crate::network::interface_stats::InterfaceErrorCounts;
use crate::network::neighbors::NeighborChange;
use crate::network::tcp_attempts::TcpAttemptSnapshot;
use crate::network::time_window::TimeWindow;
use crate::network::types::{
    ApplicationProtocol, Connection, ConnectionKey, DhcpMessageType, NetworkEventKind,
    NetworkEventSnapshot, OpenVpnPacketType, Protocol, SnmpVersion, TlsAlertLevel, TlsInfo,
    TlsVersion, WireGuardPacketType,
};

const MAX_OBSERVATIONS: usize = 32;
const LOW_MSS_THRESHOLD: u16 = 1200;
const RETRANSMIT_WARN_COUNT: u64 = 5;
const RETRANSMIT_HIGH_COUNT: u64 = 10;
const OUT_OF_ORDER_WARN_COUNT: u64 = 10;
const ZERO_WINDOW_ERROR_COUNT: u64 = 5;
const NXDOMAIN_BURST_MIN_COUNT: usize = 10;
const NXDOMAIN_BURST_HIGH_COUNT: usize = 25;
const NXDOMAIN_BURST_PERCENT: usize = 25;
const TUNNEL_UNANSWERED_PACKETS: u64 = 3;
const MIDSTREAM_MIN_TCP_FLOWS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FindingSeverity {
    Error,
    Warning,
    Healthy,
    Muted,
}

impl FindingSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Healthy => "healthy",
            Self::Muted => "muted",
        }
    }

    pub const fn is_attention(self) -> bool {
        matches!(self, Self::Error | Self::Warning)
    }

    pub const fn observed(error: bool, warning: bool) -> Self {
        if error {
            Self::Error
        } else if warning {
            Self::Warning
        } else {
            Self::Muted
        }
    }

    fn escalate(&mut self, other: Self) {
        if other < *self {
            *self = other;
        }
    }

    const fn sort_rank(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
            Self::Healthy | Self::Muted => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    Tcp,
    Path,
    NameAndAddress,
    Application,
    Tunnel,
    Security,
    HostAndCapture,
}

impl FindingCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Path => "path",
            Self::NameAndAddress => "name_and_address",
            Self::Application => "application",
            Self::Tunnel => "tunnel",
            Self::Security => "security",
            Self::HostAndCapture => "host_and_capture",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingId {
    TcpHandshakes,
    TcpFlowQuality,
    ResetsAndIcmp,
    InterfaceDrops,
    DnsReplies,
    DnsNxdomainBurst,
    TlsHealth,
    HttpErrors,
    LanAndDhcp,
    TunnelHealth,
    CleartextProtocols,
    CaptureQuality,
}

struct FindingSpec {
    id: &'static str,
    title: &'static str,
    category: FindingCategory,
    hint: &'static str,
}

impl FindingId {
    const fn spec(self) -> FindingSpec {
        use FindingCategory as Cat;
        match self {
            Self::TcpHandshakes => FindingSpec {
                id: "tcp_handshakes",
                title: "TCP handshakes",
                category: Cat::Tcp,
                hint: "Resets often come from closed ports or middleboxes; unanswered SYNs can also reflect silent drops, routing issues, or capture gaps.",
            },
            Self::TcpFlowQuality => FindingSpec {
                id: "tcp_flow_quality",
                title: "TCP flow quality",
                category: Cat::Tcp,
                hint: "Inspect affected flows in Details for receive window, RTT, and retransmits; low MSS or repeated retransmits can signal MTU clamping or congestion.",
            },
            Self::ResetsAndIcmp => FindingSpec {
                id: "resets_and_icmp",
                title: "Resets and ICMP",
                category: Cat::Path,
                hint: "ICMP Packet Too Big points to path MTU limits; Administratively Prohibited or Port Unreachable indicates peer or router rejection.",
            },
            Self::InterfaceDrops => FindingSpec {
                id: "interface_drops",
                title: "Interface drops",
                category: Cat::HostAndCapture,
                hint: "OS interface drops/errors occur below the application layer; check NIC ring buffers, link errors, or saturation.",
            },
            Self::DnsReplies => FindingSpec {
                id: "dns_replies",
                title: "DNS replies",
                category: Cat::NameAndAddress,
                hint: "Timeouts or SERVFAIL/REFUSED point to unreachable or failing upstream resolvers; compare per-resolver latency and error counts.",
            },
            Self::DnsNxdomainBurst => FindingSpec {
                id: "dns_nxdomain_burst",
                title: "DNS NXDOMAIN bursts",
                category: Cat::NameAndAddress,
                hint: "High NXDOMAIN volume often comes from misconfigured search domains, stale service-discovery names, or client retry loops.",
            },
            Self::TlsHealth => FindingSpec {
                id: "tls_health",
                title: "TLS alerts & legacy versions",
                category: Cat::Application,
                hint: "Unencrypted TLS alerts pinpoint certificate, SNI, or version mismatches; upgrade legacy SSL 3.0 / TLS 1.0 / 1.1 endpoints.",
            },
            Self::HttpErrors => FindingSpec {
                id: "http_errors",
                title: "HTTP error responses",
                category: Cat::Application,
                hint: "Plaintext HTTP 5xx indicates upstream server errors; 4xx spikes typically indicate missing routes, bad requests, or rejected auth.",
            },
            Self::LanAndDhcp => FindingSpec {
                id: "lan_and_dhcp",
                title: "LAN & DHCP anomalies",
                category: Cat::NameAndAddress,
                hint: "DHCP NAK/DECLINE signals lease rejection or IP conflicts; IP-to-MAC changes can reflect failover, proxy ARP, duplicate IPs, or ARP spoofing.",
            },
            Self::TunnelHealth => FindingSpec {
                id: "tunnel_health",
                title: "VPN tunnel handshakes",
                category: Cat::Tunnel,
                hint: "Repeated unanswered WireGuard or OpenVPN handshakes usually indicate UDP filtering, stale endpoints, or mismatched keys.",
            },
            Self::CleartextProtocols => FindingSpec {
                id: "cleartext_protocols",
                title: "Cleartext & legacy protocols",
                category: Cat::Security,
                hint: "Plaintext credentials or legacy management traffic were observed; migrate the owning process to TLS, SFTP/FTPS, or SNMPv3.",
            },
            Self::CaptureQuality => FindingSpec {
                id: "capture_quality",
                title: "Capture quality",
                category: Cat::HostAndCapture,
                hint: "Dropped packets or mid-stream connections limit passive visibility; check capture buffers or filters before trusting missing-reply findings.",
            },
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.spec().id
    }
    pub const fn title(self) -> &'static str {
        self.spec().title
    }
    pub const fn category(self) -> FindingCategory {
        self.spec().category
    }
    pub const fn hint(self) -> &'static str {
        self.spec().hint
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRef {
    pub key: ConnectionKey,
    pub created_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingObservation {
    pub severity: FindingSeverity,
    pub subject: String,
    pub detail: String,
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub remote_addr: Option<SocketAddr>,
    pub connection: Option<ConnectionRef>,
}

impl FindingObservation {
    fn note(
        severity: FindingSeverity,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            subject: subject.into(),
            detail: detail.into(),
            process_name: None,
            pid: None,
            remote_addr: None,
            connection: None,
        }
    }

    fn for_conn(severity: FindingSeverity, conn: &Connection, detail: impl Into<String>) -> Self {
        let subject = match conn.authoritative_hostname() {
            Some(host) => format!("{host} ({})", conn.remote_addr),
            None => conn.remote_addr.to_string(),
        };
        Self {
            severity,
            subject,
            detail: detail.into(),
            process_name: conn.process_name.clone(),
            pid: conn.pid,
            remote_addr: Some(conn.remote_addr),
            connection: Some(ConnectionRef {
                key: ConnectionKey::from_connection(conn),
                created_at: conn.created_at,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingEntry {
    pub id: FindingId,
    pub severity: FindingSeverity,
    pub summary: String,
    pub window_label: &'static str,
    pub affected_count: usize,
    pub observations: Vec<FindingObservation>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FindingsSummary {
    pub errors: usize,
    pub warnings: usize,
}

impl FindingsSummary {
    pub const fn attention_count(self) -> usize {
        self.errors + self.warnings
    }
}

#[derive(Debug, Clone, Default)]
pub struct FindingsReport {
    pub summary: FindingsSummary,
    pub entries: Vec<FindingEntry>,
}

pub struct FindingsInput<'a> {
    pub connections: &'a [Connection],
    pub tcp_attempts: &'a TcpAttemptSnapshot,
    pub network_events: &'a NetworkEventSnapshot,
    pub dns: &'a DnsAnalyticsSnapshot,
    pub interfaces: &'a HashMap<String, InterfaceErrorCounts>,
    pub interfaces_since_clear: bool,
    pub neighbor_changes: &'a [NeighborChange],
    pub window: TimeWindow,
    pub capture_error: Option<&'a str>,
    pub capture_drops: u64,
    pub interface_drops: u64,
    pub queue_drops: u64,
}

struct FindingAcc {
    id: FindingId,
    severity: FindingSeverity,
    affected_count: usize,
    observations: Vec<FindingObservation>,
}

impl FindingAcc {
    fn new(id: FindingId) -> Self {
        Self {
            id,
            severity: FindingSeverity::Muted,
            affected_count: 0,
            observations: Vec::new(),
        }
    }

    fn push(&mut self, obs: FindingObservation) {
        self.severity.escalate(obs.severity);
        self.affected_count += 1;
        if self.observations.len() < MAX_OBSERVATIONS {
            self.observations.push(obs);
        }
    }

    fn finish(self, summary: impl Into<String>, window_label: &'static str) -> FindingEntry {
        FindingEntry {
            id: self.id,
            severity: self.severity,
            summary: summary.into(),
            window_label,
            affected_count: self.affected_count,
            observations: self.observations,
        }
    }
}

/// Evaluate all core and extended passive diagnostic detectors.
pub fn evaluate_findings(input: &FindingsInput<'_>) -> FindingsReport {
    let mut entries = vec![
        eval_tcp_handshakes(input),
        eval_resets_and_icmp(input),
        eval_interface_drops(input),
        eval_dns_replies(input),
        eval_capture_quality(input),
    ];
    entries.extend(evaluate_extended_findings(
        input.connections,
        input.dns,
        input.neighbor_changes,
    ));
    entries.sort_by_key(|e| e.severity.sort_rank());

    let mut summary = FindingsSummary::default();
    for entry in &entries {
        match entry.severity {
            FindingSeverity::Error => summary.errors += 1,
            FindingSeverity::Warning => summary.warnings += 1,
            FindingSeverity::Healthy | FindingSeverity::Muted => {}
        }
    }
    FindingsReport { summary, entries }
}

/// Single-pass evaluation of extended passive detectors (TCP flow quality,
/// TLS, HTTP, DNS NXDOMAIN bursts, LAN/DHCP, VPN tunnels, cleartext hygiene).
pub fn evaluate_extended_findings(
    connections: &[Connection],
    dns: &DnsAnalyticsSnapshot,
    neighbor_changes: &[NeighborChange],
) -> Vec<FindingEntry> {
    let mut tcp_flow = FindingAcc::new(FindingId::TcpFlowQuality);
    let mut tls = FindingAcc::new(FindingId::TlsHealth);
    let mut http = FindingAcc::new(FindingId::HttpErrors);
    let mut lan = FindingAcc::new(FindingId::LanAndDhcp);
    let mut tunnel = FindingAcc::new(FindingId::TunnelHealth);
    let mut cleartext = FindingAcc::new(FindingId::CleartextProtocols);

    let (mut zw_flows, mut loss_flows, mut low_mss_flows) = (0usize, 0usize, 0usize);
    let (mut tls_alerts, mut tls_legacy) = (0usize, 0usize);
    let (mut http_4xx, mut http_5xx) = (0usize, 0usize);
    let mut dhcp_errors = 0usize;
    let mut gateway_ips = HashSet::new();

    for conn in connections.iter().filter(|conn| !conn.is_historic) {
        if conn.remote_is_gateway {
            gateway_ips.insert(conn.remote_addr.ip());
        }
        inspect_tcp_flow(
            conn,
            &mut tcp_flow,
            &mut zw_flows,
            &mut loss_flows,
            &mut low_mss_flows,
        );
        if let Some(t) = tls_info_of(conn) {
            inspect_tls(conn, t, &mut tls, &mut tls_alerts, &mut tls_legacy);
        }
        let Some(app) = conn.dpi_info.as_ref().map(|d| &d.application) else {
            continue;
        };
        match app {
            ApplicationProtocol::Http(h) => {
                if let Some(code) = h.status_code.filter(|&c| c >= 400) {
                    let sev = if code >= 500 {
                        http_5xx += 1;
                        FindingSeverity::Error
                    } else {
                        http_4xx += 1;
                        FindingSeverity::Warning
                    };
                    let detail = match (&h.method, &h.path) {
                        (Some(m), Some(p)) => {
                            let short: String = p.chars().take(48).collect();
                            format!("HTTP {code} ({m} {short})")
                        }
                        (Some(m), None) => format!("HTTP {code} ({m})"),
                        _ => format!("HTTP {code}"),
                    };
                    http.push(FindingObservation::for_conn(sev, conn, detail));
                }
                if h.has_basic_auth {
                    cleartext.push(FindingObservation::for_conn(
                        FindingSeverity::Warning,
                        conn,
                        "HTTP Basic authorization over plaintext",
                    ));
                }
            }
            ApplicationProtocol::Dhcp(d)
                if matches!(
                    d.message_type,
                    DhcpMessageType::Nak | DhcpMessageType::Decline
                ) =>
            {
                dhcp_errors += 1;
                let host = d
                    .hostname
                    .as_deref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default();
                lan.push(FindingObservation::for_conn(
                    FindingSeverity::Error,
                    conn,
                    format!("DHCP {} observed{host}", d.message_type),
                ));
            }
            ApplicationProtocol::WireGuard(wg)
                if wg.packet_type == WireGuardPacketType::HandshakeInitiation
                    && conn.packets_sent >= TUNNEL_UNANSWERED_PACKETS
                    && conn.packets_received == 0 =>
            {
                tunnel.push(FindingObservation::for_conn(
                    FindingSeverity::Warning,
                    conn,
                    format!(
                        "WireGuard handshake unanswered ({} sent, 0 received)",
                        conn.packets_sent
                    ),
                ));
            }
            ApplicationProtocol::OpenVpn(ovpn)
                if matches!(
                    ovpn.packet_type,
                    OpenVpnPacketType::ControlHardResetClientV2
                        | OpenVpnPacketType::ControlHardResetClientV3
                ) && conn.packets_sent >= TUNNEL_UNANSWERED_PACKETS
                    && conn.packets_received == 0 =>
            {
                tunnel.push(FindingObservation::for_conn(
                    FindingSeverity::Warning,
                    conn,
                    format!(
                        "OpenVPN reset unanswered ({} sent, 0 received)",
                        conn.packets_sent
                    ),
                ));
            }
            ApplicationProtocol::Ftp(f)
                if f.username.is_some() || f.command.as_deref() == Some("PASS") =>
            {
                cleartext.push(FindingObservation::for_conn(
                    FindingSeverity::Warning,
                    conn,
                    "FTP cleartext login sequence",
                ));
            }
            ApplicationProtocol::Snmp(s)
                if matches!(s.version, SnmpVersion::V1 | SnmpVersion::V2c) =>
            {
                cleartext.push(FindingObservation::for_conn(
                    FindingSeverity::Warning,
                    conn,
                    "SNMP v1/v2c plaintext community protocol",
                ));
            }
            _ => {}
        }
    }

    for change in neighbor_changes {
        let is_gw = gateway_ips.contains(&change.ip);
        let sev = if is_gw {
            FindingSeverity::Error
        } else {
            FindingSeverity::Warning
        };
        let subject = if is_gw {
            format!("{} (gateway)", change.ip)
        } else {
            change.ip.to_string()
        };
        lan.push(FindingObservation::note(
            sev,
            subject,
            format!(
                "MAC changed {} -> {}",
                change.previous_mac, change.current_mac
            ),
        ));
    }

    let tcp_summary = join_counts(&[
        (zw_flows, "zero-window"),
        (loss_flows, "loss/reordering"),
        (low_mss_flows, "low-MSS"),
    ]);
    let tls_summary = join_counts(&[(tls_alerts, "TLS alerts"), (tls_legacy, "legacy TLS/SSL")]);
    let http_summary = format!(
        "{} plaintext error flows",
        join_counts(&[(http_5xx, "5xx"), (http_4xx, "4xx")])
    );
    let lan_summary = join_counts(&[
        (dhcp_errors, "DHCP NAK/DECLINE"),
        (neighbor_changes.len(), "IP-to-MAC changes"),
    ]);
    let tunnel_summary = format!("{} unanswered VPN handshake flows", tunnel.affected_count);
    let clear_summary = format!(
        "{} cleartext auth or legacy flows",
        cleartext.affected_count
    );

    let mut entries: Vec<FindingEntry> = [
        tcp_flow.finish(tcp_summary, "active"),
        tls.finish(tls_summary, "active"),
        http.finish(http_summary, "active"),
        eval_dns_nxdomain_burst(dns),
        lan.finish(lan_summary, "session"),
        tunnel.finish(tunnel_summary, "active"),
        cleartext.finish(clear_summary, "active"),
    ]
    .into_iter()
    .filter(|e| e.severity.is_attention())
    .collect();
    entries.sort_by_key(|e| e.severity.sort_rank());
    entries
}

fn join_counts(items: &[(usize, &str)]) -> String {
    items
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, label)| format!("{n} {label}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

fn tls_info_of(conn: &Connection) -> Option<&TlsInfo> {
    match &conn.dpi_info.as_ref()?.application {
        ApplicationProtocol::Https(h) => h.tls_info.as_ref(),
        ApplicationProtocol::MySql(m) => m.tls_info.as_ref(),
        ApplicationProtocol::PostgreSql(p) => p.tls_info.as_ref(),
        ApplicationProtocol::Quic(q) => q.tls_info.as_ref(),
        _ => None,
    }
}

fn inspect_tcp_flow(
    conn: &Connection,
    acc: &mut FindingAcc,
    zw_flows: &mut usize,
    loss_flows: &mut usize,
    low_mss_flows: &mut usize,
) {
    if conn.protocol != Protocol::Tcp {
        return;
    }
    let Some(tcp) = conn.tcp_analytics.as_ref() else {
        return;
    };
    let mut reasons = Vec::new();
    let mut sev = FindingSeverity::Muted;

    let zw = tcp
        .zero_window_in_count
        .saturating_add(tcp.zero_window_out_count);
    if zw > 0 {
        *zw_flows += 1;
        sev.escalate(FindingSeverity::observed(
            zw >= ZERO_WINDOW_ERROR_COUNT,
            true,
        ));
        reasons.push(format!(
            "zero window ({} peer / {} local)",
            tcp.zero_window_in_count, tcp.zero_window_out_count
        ));
    }

    let high_retrans = tcp.fast_retransmit_count > 0
        || tcp.retransmit_count >= RETRANSMIT_HIGH_COUNT
        || (tcp.retransmit_count >= RETRANSMIT_WARN_COUNT
            && tcp
                .retransmit_count
                .saturating_mul(100)
                .checked_div(conn.packets_sent)
                .unwrap_or(0)
                >= 2);
    let high_ooo = tcp.out_of_order_count >= OUT_OF_ORDER_WARN_COUNT;
    if high_retrans || high_ooo {
        *loss_flows += 1;
        let severe = conn.packets_sent >= 20
            && tcp.retransmit_count.saturating_mul(100) / conn.packets_sent >= 10;
        sev.escalate(FindingSeverity::observed(severe, true));
        if tcp.retransmit_count > 0 {
            reasons.push(format!("{} retransmits", tcp.retransmit_count));
        }
        if tcp.fast_retransmit_count > 0 {
            reasons.push(format!("{} fast retransmits", tcp.fast_retransmit_count));
        }
        if high_ooo {
            reasons.push(format!("{} out-of-order", tcp.out_of_order_count));
        }
    }

    let loopback = conn.local_addr.ip().is_loopback() && conn.remote_addr.ip().is_loopback();
    if !loopback
        && let Some(mss) = [tcp.mss_out, tcp.mss_in]
            .into_iter()
            .flatten()
            .filter(|&m| m > 0 && m < LOW_MSS_THRESHOLD)
            .min()
    {
        *low_mss_flows += 1;
        sev.escalate(FindingSeverity::Warning);
        reasons.push(format!("low MSS {mss} B"));
    }

    if !reasons.is_empty() {
        acc.push(FindingObservation::for_conn(sev, conn, reasons.join(" · ")));
    }
}

fn inspect_tls(
    conn: &Connection,
    tls: &TlsInfo,
    acc: &mut FindingAcc,
    alerts: &mut usize,
    legacy: &mut usize,
) {
    let mut reasons = Vec::new();
    let mut sev = FindingSeverity::Muted;

    if let Some(alert) = tls.alert
        && alert.description != 0
    {
        *alerts += 1;
        sev.escalate(FindingSeverity::observed(
            alert.level == TlsAlertLevel::Fatal,
            true,
        ));
        reasons.push(format!("TLS alert: {alert}"));
    }
    if let Some(version) = tls.version
        && version.is_legacy()
    {
        *legacy += 1;
        sev.escalate(FindingSeverity::observed(
            version == TlsVersion::Ssl30,
            true,
        ));
        reasons.push(format!("deprecated {version}"));
    }
    if !reasons.is_empty() {
        acc.push(FindingObservation::for_conn(sev, conn, reasons.join(" · ")));
    }
}

fn eval_dns_nxdomain_burst(dns: &DnsAnalyticsSnapshot) -> FindingEntry {
    let ratio = dns
        .nxdomain
        .saturating_mul(100)
        .checked_div(dns.lookups)
        .unwrap_or(0);
    let triggered = dns.nxdomain >= NXDOMAIN_BURST_HIGH_COUNT
        || (dns.nxdomain >= NXDOMAIN_BURST_MIN_COUNT && ratio >= NXDOMAIN_BURST_PERCENT);
    let mut acc = FindingAcc::new(FindingId::DnsNxdomainBurst);
    if triggered {
        acc.severity = FindingSeverity::Warning;
        let mut offenders: Vec<_> = dns.questions.iter().filter(|q| q.nxdomain > 0).collect();
        offenders.sort_by(|a, b| {
            b.nxdomain
                .cmp(&a.nxdomain)
                .then_with(|| a.name.cmp(&b.name))
        });
        for q in offenders {
            acc.push(FindingObservation::note(
                FindingSeverity::Warning,
                q.name.clone(),
                format!("{} NXDOMAIN / {} lookups", q.nxdomain, q.lookups),
            ));
        }
        acc.affected_count = dns.nxdomain;
    }
    acc.finish(
        format!(
            "{} NXDOMAIN ({ratio}% of {} lookups)",
            dns.nxdomain, dns.lookups
        ),
        dns.window_label(),
    )
}

/// Interpret the observed outbound TCP attempts, including gaps in capture coverage.
pub fn tcp_handshake_status(
    snapshot: &TcpAttemptSnapshot,
    capture_incomplete: bool,
) -> (&'static str, FindingSeverity) {
    let c = &snapshot.total;
    if capture_incomplete || snapshot.omitted > 0 {
        ("incomplete evidence", FindingSeverity::Warning)
    } else if c.reset > 0 {
        ("degraded", FindingSeverity::Error)
    } else if c.no_handshake > 0 {
        ("degraded", FindingSeverity::Warning)
    } else if c.recovered_anomalies > 0 {
        ("recovered anomalies", FindingSeverity::Warning)
    } else if c.superseded > 0 {
        ("incomplete evidence", FindingSeverity::Warning)
    } else if snapshot.pending > 0 {
        ("checking", FindingSeverity::Muted)
    } else if c.established > 0 {
        ("healthy", FindingSeverity::Healthy)
    } else {
        ("not observed", FindingSeverity::Muted)
    }
}

pub fn dns_health_status(
    health: DnsHealth,
    capture_failed: bool,
) -> (&'static str, FindingSeverity) {
    if capture_failed {
        return ("unknown (capture stopped)", FindingSeverity::Warning);
    }
    match health {
        DnsHealth::NotObserved => ("not observed", FindingSeverity::Muted),
        DnsHealth::Checking => ("checking", FindingSeverity::Muted),
        DnsHealth::Responsive => ("responsive", FindingSeverity::Healthy),
        DnsHealth::Degraded => ("degraded", FindingSeverity::Warning),
        DnsHealth::Failing => ("failing", FindingSeverity::Error),
        DnsHealth::NoReplies => ("no replies", FindingSeverity::Error),
    }
}

fn eval_tcp_handshakes(input: &FindingsInput<'_>) -> FindingEntry {
    let snap = input.tcp_attempts;
    let c = &snap.total;
    let incomplete = input.capture_error.is_some()
        || input.capture_drops > 0
        || input.interface_drops > 0
        || input.queue_drops > 0;

    let mut acc = FindingAcc::new(FindingId::TcpHandshakes);
    for (&addr, counts) in &snap.destinations {
        if !counts.is_affected() {
            continue;
        }
        let mut obs = FindingObservation::note(
            FindingSeverity::observed(counts.reset > 0, true),
            addr.to_string(),
            format!(
                "{}/{} reset or incomplete, {} anomalous, {} SYN retries",
                counts.reset + counts.no_handshake,
                counts.completed,
                counts.anomalous,
                counts.syn_retries,
            ),
        );
        obs.remote_addr = Some(addr);
        acc.push(obs);
    }

    acc.severity = tcp_handshake_status(snap, incomplete).1;
    let summary = if c.completed == 0 && snap.pending == 0 {
        "No outbound TCP handshakes observed".to_string()
    } else {
        format!(
            "{}/{} reset or incomplete, {} anomalous ({} pending)",
            c.reset + c.no_handshake,
            c.completed,
            c.anomalous,
            snap.pending
        )
    };
    acc.finish(summary, "5m")
}

fn eval_resets_and_icmp(input: &FindingsInput<'_>) -> FindingEntry {
    let resets = input
        .network_events
        .selected
        .get(NetworkEventKind::TcpReset);
    let mut icmp = 0u64;
    let mut acc = FindingAcc::new(FindingId::ResetsAndIcmp);
    for (kind, counts) in input.network_events.selected.observed() {
        if kind != NetworkEventKind::TcpReset {
            icmp = icmp.saturating_add(counts.sent + counts.received);
        }
        acc.push(FindingObservation::note(
            FindingSeverity::Warning,
            kind.to_string(),
            format!("sent {} / received {}", counts.sent, counts.received),
        ));
    }
    acc.finish(
        format!(
            "RST {} sent / {} received · {icmp} ICMP errors",
            resets.sent, resets.received
        ),
        input
            .window
            .label_since_clear(input.network_events.since_clear),
    )
}

fn eval_interface_drops(input: &FindingsInput<'_>) -> FindingEntry {
    let mut acc = FindingAcc::new(FindingId::InterfaceDrops);
    if !input.interfaces.is_empty() {
        acc.severity = FindingSeverity::Healthy;
    }
    let (mut drops, mut errors) = (0u64, 0u64);
    let mut names: Vec<_> = input.interfaces.keys().collect();
    names.sort_unstable();
    for name in names {
        let c = &input.interfaces[name];
        let (d, e) = (c.rx_dropped + c.tx_dropped, c.rx_errors + c.tx_errors);
        drops += d;
        errors += e;
        if d > 0 || e > 0 {
            acc.push(FindingObservation::note(
                FindingSeverity::observed(e > 0, d > 0),
                name.clone(),
                format!(
                    "RX/TX drops {}/{} · errors {}/{}",
                    c.rx_dropped, c.tx_dropped, c.rx_errors, c.tx_errors
                ),
            ));
        }
    }
    let summary = if input.interfaces.is_empty() {
        "Waiting for interface statistics".to_string()
    } else if errors > 0 {
        format!("{drops} drops · {errors} errors observed")
    } else {
        format!("{drops} drops observed")
    };
    acc.finish(
        summary,
        input.window.label_since_clear(input.interfaces_since_clear),
    )
}

fn eval_dns_replies(input: &FindingsInput<'_>) -> FindingEntry {
    let dns = input.dns;
    let mut acc = FindingAcc::new(FindingId::DnsReplies);
    for issue in &dns.recent_issues {
        let sev = FindingSeverity::observed(issue.kind != DnsIssueKind::Slow, true);
        let mut obs = FindingObservation::note(
            sev,
            issue
                .query_name
                .clone()
                .unwrap_or_else(|| issue.resolver.to_string()),
            format!("{} via {}", issue.kind.label(), issue.resolver),
        );
        obs.remote_addr = Some(issue.resolver);
        acc.push(obs);
    }
    acc.severity = if dns.failures > 0 {
        FindingSeverity::Error
    } else {
        dns_health_status(dns.health, input.capture_error.is_some()).1
    };
    acc.affected_count = dns.failures + dns.slow_responses;
    acc.finish(
        format!(
            "{} replies · {} timeouts · {} error replies",
            dns.answered,
            dns.timeouts,
            dns.failures.saturating_sub(dns.timeouts),
        ),
        dns.window_label(),
    )
}

fn eval_capture_quality(input: &FindingsInput<'_>) -> FindingEntry {
    let reported = input.capture_drops.saturating_add(input.interface_drops);
    let mut acc = FindingAcc::new(FindingId::CaptureQuality);
    acc.severity = FindingSeverity::Healthy;
    if let Some(error) = input.capture_error {
        acc.push(FindingObservation::note(
            FindingSeverity::Error,
            "Capture error",
            error,
        ));
    }
    for (label, count) in [
        ("Capture backend drops", input.capture_drops),
        ("Interface-reported drops", input.interface_drops),
        ("Processing queue drops", input.queue_drops),
    ] {
        if count > 0 {
            acc.push(FindingObservation::note(
                FindingSeverity::Warning,
                label,
                format!("{count} packets dropped"),
            ));
        }
    }
    let mut tcp_total = 0usize;
    let mut tcp_mid = 0;
    for conn in input
        .connections
        .iter()
        .filter(|c| !c.is_historic && c.protocol == Protocol::Tcp)
    {
        tcp_total += 1;
        tcp_mid += usize::from(conn.connection_direction.is_none());
    }
    if tcp_total >= MIDSTREAM_MIN_TCP_FLOWS && tcp_mid * 2 >= tcp_total {
        acc.observations.push(FindingObservation::note(
            FindingSeverity::Muted,
            "Mid-stream TCP connections",
            format!("{tcp_mid}/{tcp_total} TCP flows observed without initial handshake"),
        ));
    }
    let summary = if input.capture_error.is_some() {
        "Capture failed".to_string()
    } else {
        format!(
            "{reported} reported drops · {} queue drops",
            input.queue_drops
        )
    };
    acc.finish(
        summary,
        if input.network_events.since_clear {
            "since clear"
        } else {
            "since startup"
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::dns_analytics::DnsQuestionStats;
    use crate::network::types::{
        DhcpInfo, DpiInfo, FtpInfo, FtpMessageType, HttpInfo, HttpVersion, HttpsInfo, SnmpInfo,
        SnmpPduType, TcpState, TlsAlert, WireGuardInfo,
    };

    fn tcp_conn(remote: &str) -> Connection {
        let mut conn = Connection::new(
            Protocol::Tcp,
            "192.168.1.10:50000".parse().unwrap(),
            remote.parse().unwrap(),
            crate::network::types::ProtocolState::Tcp(TcpState::Established),
        );
        conn.process_name = Some("curl".into());
        conn.pid = Some(1234);
        conn
    }

    fn udp_conn(local: &str, remote: &str, app: ApplicationProtocol) -> Connection {
        let mut conn = Connection::new(
            Protocol::Udp,
            local.parse().unwrap(),
            remote.parse().unwrap(),
            crate::network::types::ProtocolState::Udp,
        );
        conn.dpi_info = Some(DpiInfo { application: app });
        conn
    }

    #[test]
    fn extended_detectors_flag_tcp_tls_http_dns_lan_tunnel_and_cleartext() {
        // TCP zero-window + loss + low MSS
        let mut bad_tcp = tcp_conn("93.184.216.34:443");
        bad_tcp.packets_sent = 40;
        let t = bad_tcp.tcp_analytics.as_mut().unwrap();
        t.zero_window_in_count = 2;
        t.retransmit_count = 6;
        t.mss_in = Some(536);

        // TLS fatal alert + legacy TLS 1.0, plus normal close_notify (ignored)
        let mut bad_tls = tcp_conn("198.51.100.1:443");
        bad_tls.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    version: Some(TlsVersion::Tls10),
                    sni: Some("legacy.example".into()),
                    alert: Some(TlsAlert {
                        level: TlsAlertLevel::Fatal,
                        description: 40,
                    }),
                    ..TlsInfo::new()
                }),
            }),
        });
        let mut clean_tls = tcp_conn("198.51.100.2:443");
        clean_tls.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    version: Some(TlsVersion::Tls13),
                    alert: Some(TlsAlert {
                        level: TlsAlertLevel::Warning,
                        description: 0,
                    }),
                    ..TlsInfo::new()
                }),
            }),
        });

        // HTTP 502 + Basic auth
        let mut bad_http = tcp_conn("198.51.100.10:80");
        bad_http.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Http(HttpInfo {
                version: HttpVersion::Http11,
                method: Some("GET".into()),
                host: Some("api.local".into()),
                path: Some("/secret".into()),
                status_code: Some(502),
                status_token: Some("502".into()),
                user_agent: None,
                has_basic_auth: true,
            }),
        });

        // Gateway + DHCP NAK + ARP MAC change
        let mut gw = tcp_conn("192.168.1.1:80");
        gw.remote_is_gateway = true;
        let dhcp = udp_conn(
            "0.0.0.0:68",
            "192.168.1.1:67",
            ApplicationProtocol::Dhcp(DhcpInfo {
                message_type: DhcpMessageType::Nak,
                hostname: Some("laptop".into()),
                client_mac: None,
            }),
        );
        let mac_change = NeighborChange {
            ip: "192.168.1.1".parse().unwrap(),
            previous_mac: "aa:bb:cc:dd:ee:01".into(),
            current_mac: "aa:bb:cc:dd:ee:02".into(),
            observed_at: SystemTime::UNIX_EPOCH,
        };

        // Unanswered WireGuard handshake
        let mut wg = udp_conn(
            "192.168.1.10:51820",
            "203.0.113.5:51820",
            ApplicationProtocol::WireGuard(WireGuardInfo {
                packet_type: WireGuardPacketType::HandshakeInitiation,
            }),
        );
        wg.packets_sent = 4;

        // Cleartext FTP PASS + SNMP v2c (never leak secrets)
        let mut ftp = tcp_conn("203.0.113.6:21");
        ftp.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Ftp(FtpInfo {
                message_type: FtpMessageType::Request,
                command: Some("PASS".into()),
                args: Some("redacted".into()),
                response_code: None,
                response_message: None,
                username: None,
                server_software: None,
                system_type: None,
            }),
        });
        let snmp = udp_conn(
            "192.168.1.10:55555",
            "192.168.1.2:161",
            ApplicationProtocol::Snmp(SnmpInfo {
                version: SnmpVersion::V2c,
                community: Some("public".into()),
                pdu_type: SnmpPduType::GetRequest,
            }),
        );

        let dns = DnsAnalyticsSnapshot {
            lookups: 20,
            nxdomain: 12,
            questions: vec![DnsQuestionStats {
                name: "bad.internal".into(),
                query_type: None,
                lookups: 12,
                nxdomain: 12,
                failures: 0,
                latency_p95: None,
            }],
            ..Default::default()
        };

        let conns = vec![
            bad_tcp, bad_tls, clean_tls, bad_http, gw, dhcp, wg, ftp, snmp,
        ];
        let entries = evaluate_extended_findings(&conns, &dns, &[mac_change]);
        let by_id = |id| entries.iter().find(|e| e.id == id).unwrap();

        let tcp_f = by_id(FindingId::TcpFlowQuality);
        assert_eq!(tcp_f.severity, FindingSeverity::Error);
        assert!(tcp_f.observations[0].detail.contains("low MSS 536 B"));

        let tls_f = by_id(FindingId::TlsHealth);
        assert_eq!(tls_f.severity, FindingSeverity::Error);
        assert_eq!(tls_f.observations.len(), 1);
        assert!(tls_f.observations[0].detail.contains("handshake_failure"));

        assert_eq!(
            by_id(FindingId::HttpErrors).severity,
            FindingSeverity::Error
        );
        assert_eq!(
            by_id(FindingId::DnsNxdomainBurst).observations[0].subject,
            "bad.internal"
        );

        let lan_f = by_id(FindingId::LanAndDhcp);
        assert_eq!(lan_f.severity, FindingSeverity::Error);
        assert_eq!(lan_f.affected_count, 2);
        assert!(
            lan_f
                .observations
                .iter()
                .any(|o| o.subject.contains("gateway"))
        );

        assert_eq!(
            by_id(FindingId::TunnelHealth).severity,
            FindingSeverity::Warning
        );

        let sec_f = by_id(FindingId::CleartextProtocols);
        assert_eq!(sec_f.affected_count, 3);
        for obs in &sec_f.observations {
            assert!(!obs.detail.contains("redacted") && !obs.detail.contains("public"));
        }
    }
}
