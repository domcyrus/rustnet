use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshConnectionState {
    Banner,
    KeyExchange,
    Authentication,
    Established,
}

impl fmt::Display for SshConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SshConnectionState::Banner => "Banner",
            SshConnectionState::KeyExchange => "Key Exchange",
            SshConnectionState::Authentication => "Authentication",
            SshConnectionState::Established => "Established",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone)]
pub struct SshInfo {
    pub version: Option<SshVersion>,
    pub client_software: Option<String>,
    pub server_software: Option<String>,
    pub connection_state: SshConnectionState,
    pub algorithms: Vec<String>,
    pub auth_method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshVersion {
    V1,
    V2,
}

impl fmt::Display for SshVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SshVersion::V1 => "SSH-1",
            SshVersion::V2 => "SSH-2",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitTorrentType {
    Peer,
    Dht,
    Utp,
}

impl fmt::Display for BitTorrentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BitTorrentType::Peer => write!(f, "Peer"),
            BitTorrentType::Dht => write!(f, "DHT"),
            BitTorrentType::Utp => write!(f, "uTP"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BitTorrentInfo {
    pub protocol_type: BitTorrentType,
    pub info_hash: Option<String>,
    pub client: Option<String>,
    pub dht_method: Option<String>,
    pub supports_dht: bool,
    pub supports_extension: bool,
    pub supports_fast: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect,
    Connack,
    Publish,
    Puback,
    Pubrec,
    Pubrel,
    Pubcomp,
    Subscribe,
    Suback,
    Unsubscribe,
    Unsuback,
    Pingreq,
    Pingresp,
    Disconnect,
    Auth,
}

impl fmt::Display for MqttPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttPacketType::Connect => write!(f, "CONNECT"),
            MqttPacketType::Connack => write!(f, "CONNACK"),
            MqttPacketType::Publish => write!(f, "PUBLISH"),
            MqttPacketType::Puback => write!(f, "PUBACK"),
            MqttPacketType::Pubrec => write!(f, "PUBREC"),
            MqttPacketType::Pubrel => write!(f, "PUBREL"),
            MqttPacketType::Pubcomp => write!(f, "PUBCOMP"),
            MqttPacketType::Subscribe => write!(f, "SUBSCRIBE"),
            MqttPacketType::Suback => write!(f, "SUBACK"),
            MqttPacketType::Unsubscribe => write!(f, "UNSUBSCRIBE"),
            MqttPacketType::Unsuback => write!(f, "UNSUBACK"),
            MqttPacketType::Pingreq => write!(f, "PINGREQ"),
            MqttPacketType::Pingresp => write!(f, "PINGRESP"),
            MqttPacketType::Disconnect => write!(f, "DISCONNECT"),
            MqttPacketType::Auth => write!(f, "AUTH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttVersion {
    V31,
    V311,
    V50,
}

impl fmt::Display for MqttVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttVersion::V31 => write!(f, "3.1"),
            MqttVersion::V311 => write!(f, "3.1.1"),
            MqttVersion::V50 => write!(f, "5.0"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MqttInfo {
    pub version: Option<MqttVersion>,
    pub packet_type: MqttPacketType,
    pub client_id: Option<String>,
    pub topic: Option<String>,
    pub qos: Option<u8>,
}

#[derive(Debug, Clone)]
pub enum ApplicationProtocol {
    Http(HttpInfo),
    Https(HttpsInfo),
    Dns(DnsInfo),
    Ssh(SshInfo),
    Quic(Box<QuicInfo>),
    Ntp(NtpInfo),
    Mdns(MdnsInfo),
    Llmnr(LlmnrInfo),
    Dhcp(DhcpInfo),
    Snmp(SnmpInfo),
    Ssdp(SsdpInfo),
    NetBios(NetBiosInfo),
    BitTorrent(BitTorrentInfo),
    Stun(StunInfo),
    Mqtt(MqttInfo),
    Ftp(FtpInfo),
}

impl ApplicationProtocol {
    /// Return a short, allocation-free key for sorting by protocol name.
    pub fn sort_key(&self) -> &'static str {
        match self {
            ApplicationProtocol::BitTorrent(_) => "BitTorrent",
            ApplicationProtocol::Dhcp(_) => "DHCP",
            ApplicationProtocol::Dns(_) => "DNS",
            ApplicationProtocol::Ftp(_) => "FTP",
            ApplicationProtocol::Http(_) => "HTTP",
            ApplicationProtocol::Https(_) => "HTTPS",
            ApplicationProtocol::Llmnr(_) => "LLMNR",
            ApplicationProtocol::Mdns(_) => "mDNS",
            ApplicationProtocol::Mqtt(_) => "MQTT",
            ApplicationProtocol::NetBios(_) => "NetBIOS",
            ApplicationProtocol::Ntp(_) => "NTP",
            ApplicationProtocol::Quic(_) => "QUIC",
            ApplicationProtocol::Snmp(_) => "SNMP",
            ApplicationProtocol::Ssh(_) => "SSH",
            ApplicationProtocol::Ssdp(_) => "SSDP",
            ApplicationProtocol::Stun(_) => "STUN",
        }
    }

    /// TLS handshake metadata for the protocols that carry it (HTTPS, QUIC).
    pub fn tls_info(&self) -> Option<&TlsInfo> {
        match self {
            ApplicationProtocol::Https(info) => info.tls_info.as_ref(),
            ApplicationProtocol::Quic(info) => info.tls_info.as_ref(),
            _ => None,
        }
    }

    /// Hostname carried in the protocol payload: the TLS SNI for HTTPS and
    /// QUIC, or the Host header for HTTP. DNS query names are deliberately
    /// excluded; call sites that want them match `Dns` explicitly.
    pub fn hostname(&self) -> Option<&str> {
        match self {
            ApplicationProtocol::Http(info) => info.host.as_deref(),
            _ => self.tls_info().and_then(|tls| tls.sni.as_deref()),
        }
    }
}

impl std::fmt::Display for ApplicationProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplicationProtocol::Http(info) => {
                if let Some(host) = &info.host {
                    write!(f, "HTTP ({})", host)
                } else {
                    write!(f, "HTTP")
                }
            }
            ApplicationProtocol::Https(info) => {
                if let Some(tls) = &info.tls_info {
                    if let Some(sni) = &tls.sni {
                        write!(f, "HTTPS ({})", sni)
                    } else {
                        write!(f, "HTTPS")
                    }
                } else {
                    write!(f, "HTTPS")
                }
            }
            ApplicationProtocol::Dns(info) => {
                if let Some(query) = &info.query_name {
                    write!(f, "DNS ({})", query)
                } else {
                    write!(f, "DNS")
                }
            }
            ApplicationProtocol::Ssh(info) => {
                if let Some(software) = info
                    .server_software
                    .as_ref()
                    .or(info.client_software.as_ref())
                {
                    // Extract just the software name without version details
                    let software_name = software.split('_').next().unwrap_or(software);
                    write!(f, "SSH ({})", software_name)
                } else {
                    write!(f, "SSH")
                }
            }
            ApplicationProtocol::Quic(info) => {
                if let Some(tls_info) = &info.tls_info {
                    if let Some(sni) = &tls_info.sni {
                        write!(f, "QUIC ({})", sni)
                    } else {
                        write!(f, "QUIC")
                    }
                } else {
                    write!(f, "QUIC")
                }
            }
            ApplicationProtocol::Ntp(info) => {
                write!(f, "NTP (v{} {})", info.version, info.mode)
            }
            ApplicationProtocol::Mdns(info) => {
                if let Some(name) = &info.query_name {
                    write!(f, "mDNS ({})", name)
                } else {
                    write!(f, "mDNS")
                }
            }
            ApplicationProtocol::Llmnr(info) => {
                if let Some(name) = &info.query_name {
                    write!(f, "LLMNR ({})", name)
                } else {
                    write!(f, "LLMNR")
                }
            }
            ApplicationProtocol::Dhcp(info) => {
                if let Some(hostname) = &info.hostname {
                    write!(f, "DHCP {} ({})", info.message_type, hostname)
                } else {
                    write!(f, "DHCP {}", info.message_type)
                }
            }
            ApplicationProtocol::Snmp(info) => {
                if let Some(community) = &info.community {
                    write!(f, "SNMP {} {} ({})", info.version, info.pdu_type, community)
                } else {
                    write!(f, "SNMP {} {}", info.version, info.pdu_type)
                }
            }
            ApplicationProtocol::Ssdp(info) => {
                if let Some(st) = &info.service_type {
                    write!(f, "SSDP {} ({})", info.method, st)
                } else {
                    write!(f, "SSDP {}", info.method)
                }
            }
            ApplicationProtocol::NetBios(info) => {
                if let Some(name) = &info.name {
                    write!(f, "NetBIOS {} ({})", info.service, name)
                } else {
                    write!(f, "NetBIOS {}", info.service)
                }
            }
            ApplicationProtocol::BitTorrent(info) => match info.protocol_type {
                BitTorrentType::Peer => {
                    if let Some(client) = &info.client {
                        write!(f, "BitTorrent ({})", client)
                    } else {
                        write!(f, "BitTorrent")
                    }
                }
                BitTorrentType::Dht => {
                    if let Some(method) = &info.dht_method {
                        write!(f, "BT DHT ({})", method)
                    } else {
                        write!(f, "BT DHT")
                    }
                }
                BitTorrentType::Utp => write!(f, "BT uTP"),
            },
            ApplicationProtocol::Stun(info) => {
                if let Some(software) = &info.software {
                    write!(
                        f,
                        "STUN {} {} ({})",
                        info.method, info.message_class, software
                    )
                } else {
                    write!(f, "STUN {} {}", info.method, info.message_class)
                }
            }
            ApplicationProtocol::Mqtt(info) => {
                if let Some(topic) = &info.topic {
                    write!(f, "MQTT {} ({})", info.packet_type, topic)
                } else if let Some(client_id) = &info.client_id {
                    write!(f, "MQTT {} ({})", info.packet_type, client_id)
                } else {
                    write!(f, "MQTT {}", info.packet_type)
                }
            }
            ApplicationProtocol::Ftp(info) => match info.message_type {
                FtpMessageType::Request => {
                    if let Some(cmd) = &info.command {
                        if let Some(args) = &info.args {
                            write!(f, "FTP {} {}", cmd, args)
                        } else {
                            write!(f, "FTP {}", cmd)
                        }
                    } else {
                        write!(f, "FTP")
                    }
                }
                FtpMessageType::Response => {
                    if let (Some(code), Some(sw)) = (info.response_code, &info.server_software) {
                        write!(f, "FTP {} ({})", code, sw)
                    } else if let Some(code) = info.response_code {
                        write!(f, "FTP {}", code)
                    } else {
                        write!(f, "FTP")
                    }
                }
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FtpMessageType {
    Request,
    Response,
}

impl fmt::Display for FtpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The protocol-name prefix is already in the surrounding column /
        // panel context, so the variant only needs to disambiguate
        // request-vs-response. Emitting "FTP_REQUEST" / "FTP_RESPONSE" here
        // produced "FTP / Message Type: FTP_REQUEST" in the details panel.
        let name = match self {
            FtpMessageType::Request => "Request",
            FtpMessageType::Response => "Response",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, Clone)]
pub struct FtpInfo {
    pub message_type: FtpMessageType,
    pub command: Option<String>,
    pub args: Option<String>,
    pub response_code: Option<u16>,
    pub response_message: Option<String>,
    pub username: Option<String>,
    pub server_software: Option<String>,
    /// OS / system type from a `215` SYST reply (RFC 959 §4.2): `UNIX`,
    /// `Windows_NT`, etc. Kept separate from `server_software` so the TUI
    /// can label them distinctly — they describe different things.
    pub system_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct HttpInfo {
    pub version: HttpVersion,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status_code: Option<u16>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http10,
    Http11,
    Http2,
}

impl fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
            HttpVersion::Http2 => "HTTP/2",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone)]
pub struct HttpsInfo {
    pub tls_info: Option<TlsInfo>,
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: Option<TlsVersion>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suite: Option<u16>,
}

impl Default for TlsInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsInfo {
    pub fn new() -> Self {
        Self {
            version: None,
            sni: None,
            alpn: Vec::new(),
            cipher_suite: None,
        }
    }

    /// Format the cipher suite with name and hex code
    pub fn format_cipher_suite(&self) -> Option<String> {
        self.cipher_suite
            .map(crate::network::dpi::format_cipher_suite)
    }

    /// Check if the cipher suite is considered secure
    pub fn is_cipher_suite_secure(&self) -> Option<bool> {
        self.cipher_suite
            .map(crate::network::dpi::is_secure_cipher_suite)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Tls10 => write!(f, "TLS 1.0"),
            TlsVersion::Tls11 => write!(f, "TLS 1.1"),
            TlsVersion::Tls12 => write!(f, "TLS 1.2"),
            TlsVersion::Tls13 => write!(f, "TLS 1.3"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsInfo {
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub response_ips: Vec<std::net::IpAddr>,
    pub is_response: bool,
    /// 16-bit transaction ID pairing a query with its response.
    pub txid: u16,
    /// Response code (RCODE); `Some` only on responses.
    pub rcode: Option<u8>,
    /// `Some(true)` when a NOERROR response carried no answer record of the
    /// queried type (NODATA, e.g. a CNAME-only answer or an empty answer
    /// section): the name exists but has no such record. Claimed per RFC 2308
    /// §2.2 only when the whole answer section parsed, the response is not
    /// truncated (TC), and the authority section is NODATA-shaped (SOA or
    /// empty, not a referral's NS-without-SOA). `Some(false)` when a NOERROR
    /// response did answer the queried type; `None` before a response is
    /// seen, when the question section is missing, or when the response is
    /// ambiguous.
    pub nodata: Option<bool>,
}

/// Standard RCODE names (RFC 1035 / RFC 2136). Unknown codes render as "RCODE n".
pub fn dns_rcode_name(rcode: u8) -> std::borrow::Cow<'static, str> {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        n => format!("RCODE {}", n).into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// DNS record type names are standardized uppercase abbreviations per RFC 1035 et al.
// Renaming e.g. AAAA to Aaaa or CNAME to Cname would be semantically incorrect.
#[allow(clippy::upper_case_acronyms)]
pub enum DnsQueryType {
    A,          // 1
    NS,         // 2
    CNAME,      // 5
    SOA,        // 6
    PTR,        // 12
    HINFO,      // 13
    MX,         // 15
    TXT,        // 16
    RP,         // 17
    AFSDB,      // 18
    SIG,        // 24
    KEY,        // 25
    AAAA,       // 28
    LOC,        // 29
    SRV,        // 33
    NAPTR,      // 35
    KX,         // 36
    CERT,       // 37
    DNAME,      // 39
    APL,        // 42
    DS,         // 43
    SSHFP,      // 44
    IPSECKEY,   // 45
    RRSIG,      // 46
    NSEC,       // 47
    DNSKEY,     // 48
    DHCID,      // 49
    NSEC3,      // 50
    NSEC3PARAM, // 51
    TLSA,       // 52
    SMIMEA,     // 53
    HIP,        // 55
    CDS,        // 59
    CDNSKEY,    // 60
    OPENPGPKEY, // 61
    CSYNC,      // 62
    ZONEMD,     // 63
    SVCB,       // 64
    HTTPS,      // 65
    EUI48,      // 108
    EUI64,      // 109
    TKEY,       // 249
    TSIG,       // 250
    URI,        // 256
    CAA,        // 257
    TA,         // 32768
    DLV,        // 32769
    Other(u16), // For any other type
}

impl DnsQueryType {
    /// Map a wire-format QTYPE / record TYPE value to its enum variant.
    pub fn from_wire(qtype: u16) -> Self {
        match qtype {
            1 => DnsQueryType::A,
            2 => DnsQueryType::NS,
            5 => DnsQueryType::CNAME,
            6 => DnsQueryType::SOA,
            12 => DnsQueryType::PTR,
            13 => DnsQueryType::HINFO,
            15 => DnsQueryType::MX,
            16 => DnsQueryType::TXT,
            17 => DnsQueryType::RP,
            18 => DnsQueryType::AFSDB,
            24 => DnsQueryType::SIG,
            25 => DnsQueryType::KEY,
            28 => DnsQueryType::AAAA,
            29 => DnsQueryType::LOC,
            33 => DnsQueryType::SRV,
            35 => DnsQueryType::NAPTR,
            36 => DnsQueryType::KX,
            37 => DnsQueryType::CERT,
            39 => DnsQueryType::DNAME,
            42 => DnsQueryType::APL,
            43 => DnsQueryType::DS,
            44 => DnsQueryType::SSHFP,
            45 => DnsQueryType::IPSECKEY,
            46 => DnsQueryType::RRSIG,
            47 => DnsQueryType::NSEC,
            48 => DnsQueryType::DNSKEY,
            49 => DnsQueryType::DHCID,
            50 => DnsQueryType::NSEC3,
            51 => DnsQueryType::NSEC3PARAM,
            52 => DnsQueryType::TLSA,
            53 => DnsQueryType::SMIMEA,
            55 => DnsQueryType::HIP,
            59 => DnsQueryType::CDS,
            60 => DnsQueryType::CDNSKEY,
            61 => DnsQueryType::OPENPGPKEY,
            62 => DnsQueryType::CSYNC,
            63 => DnsQueryType::ZONEMD,
            64 => DnsQueryType::SVCB,
            65 => DnsQueryType::HTTPS,
            108 => DnsQueryType::EUI48,
            109 => DnsQueryType::EUI64,
            249 => DnsQueryType::TKEY,
            250 => DnsQueryType::TSIG,
            256 => DnsQueryType::URI,
            257 => DnsQueryType::CAA,
            32768 => DnsQueryType::TA,
            32769 => DnsQueryType::DLV,
            other => DnsQueryType::Other(other),
        }
    }
}

impl std::fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsQueryType::Other(n) => write!(f, "TYPE{}", n),
            _ => write!(f, "{:?}", self),
        }
    }
}

// NTP-specific types
#[derive(Debug, Clone)]
pub struct NtpInfo {
    pub version: u8,
    pub mode: NtpMode,
    pub stratum: u8,
    /// Originate timestamp (raw 64-bit NTP format): in a server response,
    /// the echo of the client's transmit timestamp.
    pub origin_timestamp: u64,
    /// Transmit timestamp (raw 64-bit NTP format): when the sender put the
    /// packet on the wire, by its own clock.
    pub transmit_timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtpMode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl std::fmt::Display for NtpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NtpMode::Reserved => write!(f, "Reserved"),
            NtpMode::SymmetricActive => write!(f, "SymActive"),
            NtpMode::SymmetricPassive => write!(f, "SymPassive"),
            NtpMode::Client => write!(f, "Client"),
            NtpMode::Server => write!(f, "Server"),
            NtpMode::Broadcast => write!(f, "Broadcast"),
            NtpMode::Control => write!(f, "Control"),
            NtpMode::Private => write!(f, "Private"),
        }
    }
}

impl From<u8> for NtpMode {
    fn from(value: u8) -> Self {
        match value {
            0 => NtpMode::Reserved,
            1 => NtpMode::SymmetricActive,
            2 => NtpMode::SymmetricPassive,
            3 => NtpMode::Client,
            4 => NtpMode::Server,
            5 => NtpMode::Broadcast,
            6 => NtpMode::Control,
            7 => NtpMode::Private,
            _ => NtpMode::Reserved,
        }
    }
}

// mDNS-specific types
#[derive(Debug, Clone)]
pub struct MdnsInfo {
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub is_response: bool,
    pub response_ips: Vec<std::net::IpAddr>,
}

/// mDNS shares the DNS wire format; keep only the fields the mDNS view uses.
impl From<DnsInfo> for MdnsInfo {
    fn from(dns: DnsInfo) -> Self {
        Self {
            query_name: dns.query_name,
            query_type: dns.query_type,
            is_response: dns.is_response,
            response_ips: dns.response_ips,
        }
    }
}

// LLMNR-specific types
#[derive(Debug, Clone)]
pub struct LlmnrInfo {
    pub query_name: Option<String>,
    pub query_type: Option<DnsQueryType>,
    pub is_response: bool,
    pub response_ips: Vec<std::net::IpAddr>,
    /// 16-bit identifier copied from a query into each response.
    pub txid: u16,
}

/// LLMNR shares the DNS wire format; retain its transaction ID for response
/// timing in addition to the fields used by the protocol view.
impl From<DnsInfo> for LlmnrInfo {
    fn from(dns: DnsInfo) -> Self {
        Self {
            query_name: dns.query_name,
            query_type: dns.query_type,
            is_response: dns.is_response,
            response_ips: dns.response_ips,
            txid: dns.txid,
        }
    }
}

// DHCP-specific types
#[derive(Debug, Clone)]
pub struct DhcpInfo {
    pub message_type: DhcpMessageType,
    pub hostname: Option<String>,
    pub client_mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl std::fmt::Display for DhcpMessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpMessageType::Discover => write!(f, "DISCOVER"),
            DhcpMessageType::Offer => write!(f, "OFFER"),
            DhcpMessageType::Request => write!(f, "REQUEST"),
            DhcpMessageType::Decline => write!(f, "DECLINE"),
            DhcpMessageType::Ack => write!(f, "ACK"),
            DhcpMessageType::Nak => write!(f, "NAK"),
            DhcpMessageType::Release => write!(f, "RELEASE"),
            DhcpMessageType::Inform => write!(f, "INFORM"),
            DhcpMessageType::Unknown(v) => write!(f, "UNKNOWN({})", v),
        }
    }
}

// SNMP-specific types
#[derive(Debug, Clone)]
pub struct SnmpInfo {
    pub version: SnmpVersion,
    pub community: Option<String>,
    pub pdu_type: SnmpPduType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpVersion {
    V1,
    V2c,
    V3,
}

impl std::fmt::Display for SnmpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnmpVersion::V1 => write!(f, "v1"),
            SnmpVersion::V2c => write!(f, "v2c"),
            SnmpVersion::V3 => write!(f, "v3"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnmpPduType {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    Trap,
    GetBulkRequest,
    InformRequest,
    TrapV2,
    Report,
    /// SNMPv3 with an encrypted ScopedPDU — the PDU type is not visible.
    Encrypted,
}

impl std::fmt::Display for SnmpPduType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnmpPduType::GetRequest => write!(f, "GET"),
            SnmpPduType::GetNextRequest => write!(f, "GETNEXT"),
            SnmpPduType::GetResponse => write!(f, "RESPONSE"),
            SnmpPduType::SetRequest => write!(f, "SET"),
            SnmpPduType::Trap => write!(f, "TRAP"),
            SnmpPduType::GetBulkRequest => write!(f, "GETBULK"),
            SnmpPduType::InformRequest => write!(f, "INFORM"),
            SnmpPduType::TrapV2 => write!(f, "TRAPv2"),
            SnmpPduType::Report => write!(f, "REPORT"),
            SnmpPduType::Encrypted => write!(f, "ENCRYPTED"),
        }
    }
}

// SSDP-specific types
#[derive(Debug, Clone)]
pub struct SsdpInfo {
    pub method: SsdpMethod,
    pub service_type: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsdpMethod {
    MSearch,
    Notify,
    Response,
}

impl std::fmt::Display for SsdpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SsdpMethod::MSearch => write!(f, "M-SEARCH"),
            SsdpMethod::Notify => write!(f, "NOTIFY"),
            SsdpMethod::Response => write!(f, "RESPONSE"),
        }
    }
}

// NetBIOS-specific types
#[derive(Debug, Clone)]
pub struct NetBiosInfo {
    pub service: NetBiosService,
    pub opcode: NetBiosOpcode,
    pub name: Option<String>,
    /// Name Service transaction ID or Datagram Service datagram ID.
    pub transaction_id: u16,
    /// Whether this packet is a final response to a request.
    ///
    /// Name Service WACK packets are deliberately excluded because a later
    /// response completes the transaction.
    pub is_response: bool,
    /// Result carried by a final Name or Datagram Service response.
    pub response_status: Option<NetBiosResponseStatus>,
}

impl NetBiosInfo {
    pub fn is_request(&self) -> bool {
        !self.is_response
            && matches!(
                self.opcode,
                NetBiosOpcode::Query
                    | NetBiosOpcode::Registration
                    | NetBiosOpcode::Release
                    | NetBiosOpcode::Refresh
            )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetBiosService {
    NameService,
    DatagramService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosResponseStatus {
    /// Four-bit RCODE from a NetBIOS Name Service response.
    NameService(u8),
    DatagramPositive,
    DatagramNegative,
}

impl NetBiosResponseStatus {
    pub fn is_success(self) -> bool {
        matches!(
            self,
            NetBiosResponseStatus::NameService(0) | NetBiosResponseStatus::DatagramPositive
        )
    }
}

impl std::fmt::Display for NetBiosResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetBiosResponseStatus::NameService(0) => write!(f, "SUCCESS"),
            NetBiosResponseStatus::NameService(1) => write!(f, "FMT_ERR"),
            NetBiosResponseStatus::NameService(2) => write!(f, "SRV_ERR"),
            NetBiosResponseStatus::NameService(3) => write!(f, "NAM_ERR"),
            NetBiosResponseStatus::NameService(4) => write!(f, "IMP_ERR"),
            NetBiosResponseStatus::NameService(5) => write!(f, "RFS_ERR"),
            NetBiosResponseStatus::NameService(6) => write!(f, "ACT_ERR"),
            NetBiosResponseStatus::NameService(7) => write!(f, "CFT_ERR"),
            NetBiosResponseStatus::NameService(code) => write!(f, "RCODE {}", code),
            NetBiosResponseStatus::DatagramPositive => write!(f, "POSITIVE"),
            NetBiosResponseStatus::DatagramNegative => write!(f, "NEGATIVE"),
        }
    }
}

impl std::fmt::Display for NetBiosService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetBiosService::NameService => write!(f, "NS"),
            NetBiosService::DatagramService => write!(f, "DGM"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetBiosOpcode {
    Query,
    Registration,
    Release,
    Wack,
    Refresh,
    Response,
    /// Datagram Service message delivery (direct unique/group or broadcast).
    Datagram,
    /// Datagram Service error report.
    Error,
    Unknown(u8),
}

impl std::fmt::Display for NetBiosOpcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetBiosOpcode::Query => write!(f, "Query"),
            NetBiosOpcode::Registration => write!(f, "Register"),
            NetBiosOpcode::Release => write!(f, "Release"),
            NetBiosOpcode::Wack => write!(f, "WACK"),
            NetBiosOpcode::Refresh => write!(f, "Refresh"),
            NetBiosOpcode::Response => write!(f, "Response"),
            NetBiosOpcode::Datagram => write!(f, "Datagram"),
            NetBiosOpcode::Error => write!(f, "Error"),
            NetBiosOpcode::Unknown(v) => write!(f, "Unknown({})", v),
        }
    }
}

// STUN-specific types
#[derive(Debug, Clone)]
pub struct StunInfo {
    pub message_class: StunMessageClass,
    pub method: StunMethod,
    pub transaction_id: [u8; 12],
    pub software: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl std::fmt::Display for StunMessageClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunMessageClass::Request => write!(f, "Request"),
            StunMessageClass::Indication => write!(f, "Indication"),
            StunMessageClass::SuccessResponse => write!(f, "Success"),
            StunMessageClass::ErrorResponse => write!(f, "Error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    Binding,
    Unknown(u16),
}

impl std::fmt::Display for StunMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StunMethod::Binding => write!(f, "Binding"),
            StunMethod::Unknown(v) => write!(f, "Unknown(0x{:04x})", v),
        }
    }
}

// QUIC-specific types
#[derive(Debug, Clone)]
pub struct QuicCloseInfo {
    pub frame_type: u8,  // 0x1c (transport) or 0x1d (application)
    pub error_code: u64, // Error code from the CONNECTION_CLOSE frame
}

#[derive(Debug, Clone)]
pub struct QuicInfo {
    pub version_string: Option<Cow<'static, str>>,
    pub packet_type: QuicPacketType,
    pub connection_id: Vec<u8>,
    pub connection_id_hex: Option<String>,
    pub connection_state: QuicConnectionState,
    pub tls_info: Option<TlsInfo>, // Extracted TLS handshake info
    pub has_crypto_frame: bool,    // Whether packet contains CRYPTO frame
    pub crypto_reassembler: Option<CryptoFrameReassembler>,
    pub connection_close: Option<QuicCloseInfo>, // CONNECTION_CLOSE frame info
    pub idle_timeout: Option<Duration>,          // Idle timeout from transport params if detected
}

impl QuicInfo {
    pub fn new(version: u32) -> Self {
        Self {
            version_string: quic_version_to_string(version),
            connection_id_hex: None,
            packet_type: QuicPacketType::Unknown,
            connection_id: Vec::new(),
            connection_state: QuicConnectionState::Unknown,
            tls_info: None,
            has_crypto_frame: false,
            crypto_reassembler: None,
            connection_close: None,
            idle_timeout: None,
        }
    }
    /// Initialize reassembler if needed
    pub fn ensure_reassembler(&mut self) {
        if self.crypto_reassembler.is_none() {
            self.crypto_reassembler = Some(CryptoFrameReassembler::new());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    VersionNegotiation,
    OneRtt, // Short header
    Unknown,
}

impl fmt::Display for QuicPacketType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicPacketType::Initial => write!(f, "Initial"),
            QuicPacketType::ZeroRtt => write!(f, "0-RTT"),
            QuicPacketType::Handshake => write!(f, "Handshake"),
            QuicPacketType::Retry => write!(f, "Retry"),
            QuicPacketType::VersionNegotiation => write!(f, "Version Negotiation"),
            QuicPacketType::OneRtt => write!(f, "1-RTT"),
            QuicPacketType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicConnectionState {
    Initial,
    Handshaking,
    Connected,
    Draining,
    Closed,
    Unknown,
}

impl QuicConnectionState {
    /// Ordering used when merging observations: a connection only ever moves
    /// forward through Unknown -> Initial -> Handshaking -> Connected ->
    /// Draining -> Closed.
    pub fn priority(self) -> u8 {
        match self {
            QuicConnectionState::Unknown => 0,
            QuicConnectionState::Initial => 1,
            QuicConnectionState::Handshaking => 2,
            QuicConnectionState::Connected => 3,
            QuicConnectionState::Draining => 4,
            QuicConnectionState::Closed => 5,
        }
    }
}

impl fmt::Display for QuicConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicConnectionState::Initial => write!(f, "Initial"),
            QuicConnectionState::Handshaking => write!(f, "Handshaking"),
            QuicConnectionState::Connected => write!(f, "Connected"),
            QuicConnectionState::Draining => write!(f, "Draining"),
            QuicConnectionState::Closed => write!(f, "Closed"),
            QuicConnectionState::Unknown => write!(f, "Unknown"),
        }
    }
}

fn quic_version_to_string(version: u32) -> Option<Cow<'static, str>> {
    match version {
        0x00000001 => Some(Cow::Borrowed("v1")),
        0x6b3343cf => Some(Cow::Borrowed("v2")),
        0xff00001d => Some(Cow::Borrowed("draft-29")),
        0xff00001c => Some(Cow::Borrowed("draft-28")),
        0xff00001b => Some(Cow::Borrowed("draft-27")),
        0x51303530 => Some(Cow::Borrowed("Q050")),
        0x54303530 => Some(Cow::Borrowed("T050")),
        0xfaceb001 => Some(Cow::Borrowed("mvfst-22")),
        0xfaceb002 => Some(Cow::Borrowed("mvfst-27")),
        v if (v >> 8) == 0xff0000 => Some(Cow::Owned(format!("draft-{}", v & 0xff))),
        _ => None,
    }
}

/// Tracks CRYPTO frame fragments for reassembly
/// This is part of the QuicInfo data model, even though it's used by DPI
#[derive(Debug, Clone)]
pub struct CryptoFrameReassembler {
    /// Fragments indexed by offset - using BTreeMap for ordered iteration
    fragments: BTreeMap<u64, Vec<u8>>,

    /// Highest contiguous byte we've reassembled from offset 0
    contiguous_offset: u64,

    /// Whether we've successfully extracted complete TLS info
    has_complete_tls_info: bool,

    /// Cached TLS info once we've extracted it
    cached_tls_info: Option<TlsInfo>,

    /// Maximum total size we'll buffer (prevent memory exhaustion)
    max_buffer_size: usize,

    /// Current total buffered size
    current_buffer_size: usize,

    /// Timestamp of last update (for cleanup of stale fragments)
    last_update: Instant,
}

impl Default for CryptoFrameReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoFrameReassembler {
    pub fn new() -> Self {
        Self {
            fragments: BTreeMap::new(),
            contiguous_offset: 0,
            has_complete_tls_info: false,
            cached_tls_info: None,
            max_buffer_size: 64 * 1024, // 64KB max buffer
            current_buffer_size: 0,
            last_update: Instant::now(),
        }
    }

    /// Add a new CRYPTO frame fragment
    pub fn add_fragment(&mut self, offset: u64, data: Vec<u8>) -> Result<(), &'static str> {
        // Check if this would exceed our buffer limit
        if self.current_buffer_size + data.len() > self.max_buffer_size {
            return Err("Fragment would exceed maximum buffer size");
        }

        self.last_update = Instant::now();

        // Check for overlapping fragments
        let data_end = offset + data.len() as u64;

        // Handle overlaps by keeping the existing data (first write wins)
        for (&frag_offset, frag_data) in &self.fragments {
            let frag_end = frag_offset + frag_data.len() as u64;

            // Check for exact duplicate
            if offset == frag_offset && data_end == frag_end {
                return Ok(());
            }

            // Check for overlap
            if offset < frag_end && data_end > frag_offset {
                return Ok(());
            }
        }

        // Add the fragment
        self.current_buffer_size += data.len();
        self.fragments.insert(offset, data);

        // Try to advance contiguous offset
        self.update_contiguous_offset();

        Ok(())
    }

    /// Update the highest contiguous offset we've seen
    fn update_contiguous_offset(&mut self) {
        let mut current = self.contiguous_offset;

        for (&offset, data) in &self.fragments {
            if offset <= current {
                let fragment_end = offset + data.len() as u64;
                if fragment_end > current {
                    current = fragment_end;
                }
            } else if offset > current {
                break;
            }
        }

        self.contiguous_offset = current;
    }

    /// Get all contiguous data from offset 0
    pub fn get_contiguous_data(&self) -> Option<Vec<u8>> {
        if self.contiguous_offset == 0 {
            return None;
        }

        let mut result = Vec::with_capacity(self.contiguous_offset as usize);
        let mut current_offset = 0u64;

        for (&offset, data) in &self.fragments {
            if offset <= current_offset {
                let skip = (current_offset - offset) as usize;
                if skip < data.len() {
                    result.extend_from_slice(&data[skip..]);
                    current_offset = offset + data.len() as u64;
                }
            }

            if current_offset >= self.contiguous_offset {
                break;
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    /// Mark as having complete TLS info
    pub fn set_complete_tls_info(&mut self, tls_info: TlsInfo) {
        self.has_complete_tls_info = true;
        self.cached_tls_info = Some(tls_info);
    }

    /// Get cached TLS info if complete
    pub fn get_cached_tls_info(&self) -> Option<&TlsInfo> {
        if self.has_complete_tls_info {
            self.cached_tls_info.as_ref()
        } else {
            None
        }
    }

    /// Get a reference to the fragments for merging purposes
    /// Returns an immutable reference to the internal fragments map
    pub fn get_fragments(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.fragments
    }
}

#[derive(Debug, Clone)]
pub struct DpiInfo {
    pub application: ApplicationProtocol,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Details tab renders these values directly; pinning them here keeps
    /// the debug-formatting leaks (`V2`, `KeyExchange`, `Http11`) from coming
    /// back.
    #[test]
    fn ssh_and_http_display_forms_are_human_readable() {
        assert_eq!(SshVersion::V1.to_string(), "SSH-1");
        assert_eq!(SshVersion::V2.to_string(), "SSH-2");

        assert_eq!(SshConnectionState::Banner.to_string(), "Banner");
        assert_eq!(SshConnectionState::KeyExchange.to_string(), "Key Exchange");
        assert_eq!(
            SshConnectionState::Authentication.to_string(),
            "Authentication"
        );
        assert_eq!(SshConnectionState::Established.to_string(), "Established");

        assert_eq!(HttpVersion::Http10.to_string(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
        assert_eq!(HttpVersion::Http2.to_string(), "HTTP/2");
    }

    #[test]
    fn quic_version_string_known_versions_are_borrowed() {
        use std::borrow::Cow;
        let cases: &[(u32, &str)] = &[
            (0x00000001, "v1"),
            (0x6b3343cf, "v2"),
            (0xff00001d, "draft-29"),
            (0xff00001c, "draft-28"),
            (0xff00001b, "draft-27"),
            (0x51303530, "Q050"),
            (0x54303530, "T050"),
        ];
        for &(version, expected) in cases {
            let q = QuicInfo::new(version);
            assert_eq!(
                q.version_string.as_deref(),
                Some(expected),
                "version 0x{version:08x}"
            );
            // Known versions must not heap-allocate.
            assert!(
                matches!(q.version_string, Some(Cow::Borrowed(_))),
                "version 0x{version:08x} should be Cow::Borrowed"
            );
        }
        // Unknown version produces None.
        assert_eq!(QuicInfo::new(0xdeadbeef).version_string, None);
        // Dynamic draft variant uses Cow::Owned.
        let dynamic = QuicInfo::new(0xff000020);
        assert_eq!(dynamic.version_string.as_deref(), Some("draft-32"));
        assert!(matches!(dynamic.version_string, Some(Cow::Owned(_))));
    }
}
