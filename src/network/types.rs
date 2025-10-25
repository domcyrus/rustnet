use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)] // Protocol names are standardized
pub enum Protocol {
    TCP,
    UDP,
    ICMP,
    ARP,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::ARP => write!(f, "ARP"),
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
                if info.tls_info.is_none() {
                    write!(f, "HTTPS")
                } else {
                    let info = info.tls_info.as_ref().unwrap();
                    // If SNI is available, include it in the display
                    if let Some(sni) = &info.sni {
                        write!(f, "HTTPS ({})", sni)
                    } else {
                        write!(f, "HTTPS")
                    }
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    #[allow(dead_code)]
    // Listening is not used in our model because we track connections after they are established
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    #[allow(dead_code)]
    CloseWait,
    #[allow(dead_code)]
    LastAck,
    #[allow(dead_code)]
    TimeWait,
    Closing,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum ProtocolState {
    Tcp(TcpState),
    Udp,
    Icmp {
        icmp_type: u8,
        #[allow(dead_code)]
        icmp_code: u8,
    },
    Arp {
        operation: ArpOperation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshConnectionState {
    Banner,
    KeyExchange,
    Authentication,
    Established,
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

#[derive(Debug, Clone)]
pub enum ApplicationProtocol {
    Http(HttpInfo),
    Https(HttpsInfo),
    Dns(DnsInfo),
    Ssh(SshInfo),
    Quic(Box<QuicInfo>),
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
    #[allow(dead_code)]
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Ssl3 => write!(f, "SSL 3.0"),
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
    #[allow(dead_code)]
    pub response_ips: Vec<std::net::IpAddr>,
    pub is_response: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)] // DNS record types are standardized protocol names
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

// QUIC-specific types
#[derive(Debug, Clone)]
#[allow(dead_code)] // Legitimate protocol fields, kept for completeness
pub struct QuicCloseInfo {
    pub frame_type: u8,         // 0x1c (transport) or 0x1d (application)
    pub error_code: u64,        // Error code from the CONNECTION_CLOSE frame
    pub reason: Option<String>, // Optional reason phrase
    pub detected_at: Instant,   // When the frame was detected
}

#[derive(Debug, Clone)]
pub struct QuicInfo {
    pub version_string: Option<String>,
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

fn quic_version_to_string(version: u32) -> Option<String> {
    match version {
        0x00000001 => Some("v1".to_string()),
        0x6b3343cf => Some("v2".to_string()),
        0xff00001d => Some("draft-29".to_string()),
        0xff00001c => Some("draft-28".to_string()),
        0xff00001b => Some("draft-27".to_string()),
        0x51303530 => Some("Q050".to_string()),
        0x54303530 => Some("T050".to_string()),
        v if (v >> 8) == 0xff0000 => Some(format!("draft-{}", v & 0xff)),
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
    #[allow(dead_code)]
    pub first_packet_time: Instant,
    #[allow(dead_code)]
    pub last_update_time: Instant,
}

#[derive(Debug, Clone)]
pub struct RateInfo {
    #[allow(dead_code)]
    pub incoming_bps: f64,
    #[allow(dead_code)]
    pub outgoing_bps: f64,
    #[allow(dead_code)]
    pub last_calculation: Instant,
}

impl Default for RateInfo {
    fn default() -> Self {
        Self {
            incoming_bps: 0.0,
            outgoing_bps: 0.0,
            last_calculation: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct RateSample {
    timestamp: Instant,
    // Delta values since last sample
    delta_sent: u64,
    delta_received: u64,
}

#[derive(Debug, Clone)]
pub struct RateTracker {
    samples: VecDeque<RateSample>,
    window_duration: Duration,
    last_update: Instant,
    max_samples: usize,
    // Keep track of last byte counts for delta calculation
    last_bytes_sent: u64,
    last_bytes_received: u64,
}

impl RateTracker {
    pub fn new() -> Self {
        Self::with_window_duration(Duration::from_secs(10))
    }

    pub fn with_window_duration(window_duration: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            window_duration,
            last_update: Instant::now(),
            // Increased to allow full time window even at high packet rates
            // 5000 pps × 10 sec = 50,000 samples, but we cap at 20,000 for memory
            max_samples: 20_000,
            last_bytes_sent: 0,
            last_bytes_received: 0,
        }
    }

    /// Initialize the tracker with initial byte counts
    /// This should be called when creating a connection with existing bytes
    pub fn initialize_with_counts(&mut self, bytes_sent: u64, bytes_received: u64) {
        self.last_bytes_sent = bytes_sent;
        self.last_bytes_received = bytes_received;
    }

    /// Update the rate tracker with new byte counts
    pub fn update(&mut self, bytes_sent: u64, bytes_received: u64) {
        let now = Instant::now();

        // Calculate deltas since last update
        let delta_sent = bytes_sent.saturating_sub(self.last_bytes_sent);
        let delta_received = bytes_received.saturating_sub(self.last_bytes_received);

        // Add new sample with deltas
        self.samples.push_back(RateSample {
            timestamp: now,
            delta_sent,
            delta_received,
        });

        // Update last values for next delta calculation
        self.last_bytes_sent = bytes_sent;
        self.last_bytes_received = bytes_received;
        self.last_update = now;

        // Remove samples outside the window
        self.prune_old_samples();

        // Limit total samples to prevent memory bloat
        while self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }
    }

    /// Remove samples older than the window duration
    fn prune_old_samples(&mut self) {
        let cutoff_time = self.last_update - self.window_duration;

        while let Some(oldest) = self.samples.front() {
            if oldest.timestamp < cutoff_time {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the current incoming rate in bytes per second
    pub fn get_incoming_rate_bps(&self) -> f64 {
        self.calculate_rate_from_deltas(|sample| sample.delta_received)
    }

    /// Get the current outgoing rate in bytes per second
    pub fn get_outgoing_rate_bps(&self) -> f64 {
        self.calculate_rate_from_deltas(|sample| sample.delta_sent)
    }

    /// Calculate rate using delta values for accurate sliding window calculation
    fn calculate_rate_from_deltas<F>(&self, delta_getter: F) -> f64
    where
        F: Fn(&RateSample) -> u64,
    {
        if self.samples.is_empty() {
            return 0.0;
        }

        // If we only have one sample, we can't calculate a rate yet
        if self.samples.len() == 1 {
            return 0.0;
        }

        // Check if newest sample is too old (connection is idle)
        // We check against current time to handle idle connections where update() isn't being called
        let now = Instant::now();
        let newest = self.samples.back().unwrap();
        let oldest = self.samples.front().unwrap();
        let age_of_newest = now.duration_since(newest.timestamp).as_secs_f64();

        // If the newest sample is older than our window, all samples are stale - return 0
        // Use a slightly larger threshold to avoid edge cases at window boundary
        if age_of_newest > self.window_duration.as_secs_f64() * 1.1 {
            return 0.0;
        }

        // Calculate the time span of our samples
        let time_span = newest
            .timestamp
            .duration_since(oldest.timestamp)
            .as_secs_f64();

        // Need at least 1 second of data for meaningful average
        // This matches iftop's approach of showing stable averages
        if time_span < 1.0 {
            return 0.0;
        }

        // Sum ALL deltas in the window - each represents bytes transferred
        let total_bytes: u64 = self
            .samples
            .iter()
            .map(delta_getter)
            .sum();

        // Simple sliding window average: total bytes over time span
        // No decay - just pure average like iftop's 10-second column
        total_bytes as f64 / time_span
    }

    /// Get the age of the oldest sample in the current window
    #[allow(dead_code)]
    pub fn window_age(&self) -> Option<Duration> {
        self.samples
            .front()
            .map(|oldest| oldest.timestamp.elapsed())
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Connection {
    // Core identification
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,

    // Protocol state
    pub protocol_state: ProtocolState,

    // Process information
    pub pid: Option<u32>,
    pub process_name: Option<String>,

    // Traffic statistics
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,

    // Timing
    pub created_at: SystemTime,
    pub last_activity: SystemTime,

    // Service identification
    pub service_name: Option<String>,

    // Deep packet inspection
    pub dpi_info: Option<DpiInfo>,

    // Performance metrics
    pub rate_tracker: RateTracker,
    #[allow(dead_code)]
    // Legacy rate info - kept for backward compatibility during transition
    pub current_rate_bps: RateInfo,
    #[allow(dead_code)]
    // TODO: implement RTT estimation
    pub rtt_estimate: Option<Duration>,

    // Backward compatibility fields - updated by rate_tracker
    pub current_incoming_rate_bps: f64,
    pub current_outgoing_rate_bps: f64,
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
        Self {
            protocol,
            local_addr,
            remote_addr,
            protocol_state: state,
            pid: None,
            process_name: None,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            created_at: now,
            last_activity: now,
            service_name: None,
            dpi_info: None,
            rate_tracker: RateTracker::new(),
            current_rate_bps: RateInfo::default(),
            rtt_estimate: None,
            current_incoming_rate_bps: 0.0,
            current_outgoing_rate_bps: 0.0,
        }
    }

    /// Generate a unique key for this connection
    pub fn key(&self) -> String {
        format!(
            "{:?}:{}-{:?}:{}",
            self.protocol, self.local_addr, self.protocol, self.remote_addr
        )
    }

    /// Check if connection is active (had activity in the last minute)
    pub fn is_active(&self) -> bool {
        self.last_activity.elapsed().unwrap_or_default() < Duration::from_secs(300)
    }

    /// Get the age of the connection
    #[allow(dead_code)]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed().unwrap_or_default()
    }

    /// Get time since last activity
    #[allow(dead_code)]
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed().unwrap_or_default()
    }

    /// Get display state with enhanced UDP/QUIC visibility
    pub fn state(&self) -> String {
        match &self.protocol_state {
            ProtocolState::Tcp(tcp_state) => {
                // Format TCP states consistently in uppercase with underscores
                match tcp_state {
                    TcpState::Established => "ESTABLISHED",
                    TcpState::SynSent => "SYN_SENT",
                    TcpState::SynReceived => "SYN_RECV",
                    TcpState::FinWait1 => "FIN_WAIT1",
                    TcpState::FinWait2 => "FIN_WAIT2",
                    TcpState::TimeWait => "TIME_WAIT",
                    TcpState::CloseWait => "CLOSE_WAIT",
                    TcpState::LastAck => "LAST_ACK",
                    TcpState::Closing => "CLOSING",
                    TcpState::Closed => "CLOSED",
                    TcpState::Listen => "LISTEN",
                    TcpState::Unknown => "TCP_UNKNOWN",
                }
                .to_string()
            }
            ProtocolState::Udp => {
                // Check if it's a DPI-identified protocol
                if let Some(dpi_info) = &self.dpi_info {
                    match &dpi_info.application {
                        ApplicationProtocol::Quic(quic) => {
                            // Enhanced QUIC state display
                            match quic.connection_state {
                                QuicConnectionState::Initial => "QUIC_INITIAL".to_string(),
                                QuicConnectionState::Handshaking => "QUIC_HANDSHAKE".to_string(),
                                QuicConnectionState::Connected => "QUIC_CONNECTED".to_string(),
                                QuicConnectionState::Draining => "QUIC_DRAINING".to_string(),
                                QuicConnectionState::Closed => "QUIC_CLOSED".to_string(),
                                QuicConnectionState::Unknown => {
                                    // Use packet type for more granular unknown states
                                    match quic.packet_type {
                                        QuicPacketType::ZeroRtt => "QUIC_0RTT".to_string(),
                                        QuicPacketType::Retry => "QUIC_RETRY".to_string(),
                                        QuicPacketType::VersionNegotiation => {
                                            "QUIC_VERSION_NEG".to_string()
                                        }
                                        _ => "QUIC_UNKNOWN".to_string(),
                                    }
                                }
                            }
                        }
                        ApplicationProtocol::Dns(dns) => {
                            // DNS-specific states
                            if dns.is_response {
                                "DNS_RESPONSE".to_string()
                            } else {
                                "DNS_QUERY".to_string()
                            }
                        }
                        ApplicationProtocol::Http(_) => "HTTP_UDP".to_string(),
                        ApplicationProtocol::Https(_) => "HTTPS_UDP".to_string(),
                        ApplicationProtocol::Ssh(_) => "SSH_UDP".to_string(),
                    }
                } else {
                    // Regular UDP without DPI classification
                    // Check activity level to provide more meaningful states
                    let idle_time = self.idle_time();
                    if idle_time > Duration::from_secs(60) {
                        "UDP_STALE".to_string()
                    } else if idle_time > Duration::from_secs(30) {
                        "UDP_IDLE".to_string()
                    } else {
                        "UDP_ACTIVE".to_string()
                    }
                }
            }
            ProtocolState::Icmp { icmp_type, .. } => match icmp_type {
                8 => "ECHO_REQUEST".to_string(),
                0 => "ECHO_REPLY".to_string(),
                3 => "DEST_UNREACH".to_string(),
                11 => "TIME_EXCEEDED".to_string(),
                _ => "ICMP_OTHER".to_string(),
            },
            ProtocolState::Arp { operation } => match operation {
                ArpOperation::Request => "ARP_REQUEST".to_string(),
                ArpOperation::Reply => "ARP_REPLY".to_string(),
            },
        }
    }

    /// Update transfer rates using sliding window calculation
    pub fn update_rates(&mut self) {
        // Update the rate tracker with current byte counts
        self.rate_tracker
            .update(self.bytes_sent, self.bytes_received);

        // Update backward compatibility fields with smoothed rates
        self.current_incoming_rate_bps = self.rate_tracker.get_incoming_rate_bps();
        self.current_outgoing_rate_bps = self.rate_tracker.get_outgoing_rate_bps();

        // Also update the legacy RateInfo struct for any code that still uses it
        let now = Instant::now();
        self.current_rate_bps = RateInfo {
            incoming_bps: self.current_incoming_rate_bps,
            outgoing_bps: self.current_outgoing_rate_bps,
            last_calculation: now,
        };
    }

    /// Refresh rates without adding new data - useful for idle connections
    /// This ensures rates decay to zero when no traffic is flowing
    pub fn refresh_rates(&mut self) {
        // Just recalculate rates based on current time
        // The calculate_rate_from_deltas method now checks sample age
        self.current_incoming_rate_bps = self.rate_tracker.get_incoming_rate_bps();
        self.current_outgoing_rate_bps = self.rate_tracker.get_outgoing_rate_bps();

        // Also update the legacy RateInfo struct
        let now = Instant::now();
        self.current_rate_bps = RateInfo {
            incoming_bps: self.current_incoming_rate_bps,
            outgoing_bps: self.current_outgoing_rate_bps,
            last_calculation: now,
        };
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
                    }
                } else {
                    // Regular UDP without DPI classification
                    Duration::from_secs(60)
                }
            }
            ProtocolState::Icmp { .. } => Duration::from_secs(10),
            ProtocolState::Arp { .. } => Duration::from_secs(30),
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

                // Default established connection timeouts (increased from 300s/180s)
                if self.idle_time() < Duration::from_secs(60) {
                    Duration::from_secs(600) // 10 minutes for active connections (was 5 min)
                } else {
                    Duration::from_secs(300) // 5 minutes for idle established (was 3 min)
                }
            }
            TcpState::TimeWait => Duration::from_secs(30), // Standard TCP TIME_WAIT
            TcpState::Closed => Duration::from_secs(5),    // Quick cleanup for closed
            TcpState::FinWait1 | TcpState::FinWait2 => Duration::from_secs(60), // Allow for proper close sequence
            TcpState::CloseWait | TcpState::LastAck => Duration::from_secs(60),
            TcpState::SynSent | TcpState::SynReceived => Duration::from_secs(60), // Connection establishment
            TcpState::Closing => Duration::from_secs(30),
            TcpState::Listen => Duration::from_secs(300), // Listening sockets persist
            TcpState::Unknown => Duration::from_secs(120),
        }
    }

    /// Get QUIC-specific timeout based on connection state and close frames
    fn get_quic_timeout(&self, quic: &QuicInfo) -> Duration {
        // First check if we've detected a CONNECTION_CLOSE frame
        if let Some(close_info) = &quic.connection_close {
            return match close_info.frame_type {
                0x1c => Duration::from_secs(10), // Transport close - allow draining period
                0x1d => Duration::from_secs(1),  // Application close - immediate cleanup
                _ => Duration::from_secs(5),     // Unknown close type
            };
        }

        // Use state-based timeout if no close frame
        match quic.connection_state {
            QuicConnectionState::Initial => Duration::from_secs(60), // Allow handshake time
            QuicConnectionState::Handshaking => Duration::from_secs(60), // Crypto negotiation
            QuicConnectionState::Connected => {
                // Use idle timeout from transport params if available, otherwise default
                if let Some(idle_timeout) = quic.idle_timeout {
                    idle_timeout
                } else {
                    // Default timeout, but consider activity (increased for HTTP/3 connection reuse)
                    if self.idle_time() < Duration::from_secs(60) {
                        Duration::from_secs(600) // 10 minutes for active QUIC (was 5 min)
                    } else {
                        Duration::from_secs(300) // 5 minutes for idle QUIC (was 3 min)
                    }
                }
            }
            QuicConnectionState::Draining => Duration::from_secs(10), // RFC 9000: ~3 * PTO
            QuicConnectionState::Closed => Duration::from_secs(1),    // Immediate cleanup
            QuicConnectionState::Unknown => Duration::from_secs(120), // Conservative default
        }
    }

    /// Check if this connection should be cleaned up based on its timeout
    pub fn should_cleanup(&self, now: SystemTime) -> bool {
        let timeout = self.get_timeout();
        now.duration_since(self.last_activity).unwrap_or_default() > timeout
    }

    /// Get the staleness level as a percentage (0.0 to 1.0+)
    /// Returns how close the connection is to being cleaned up
    /// - 0.0 = just created
    /// - 0.75 = at warning threshold
    /// - 1.0 = will be cleaned up
    /// - >1.0 = should have been cleaned up already
    pub fn staleness_ratio(&self) -> f32 {
        let timeout = self.get_timeout();
        let idle = self.idle_time();

        idle.as_secs_f32() / timeout.as_secs_f32()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;

    fn create_test_connection() -> Connection {
        Connection::new(
            Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn test_rate_tracker_initialization() {
        let tracker = RateTracker::new();

        // Initial rates should be 0
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
    }

    #[test]
    fn test_sliding_window_simple_average() {
        let mut tracker = RateTracker::new();

        // Initialize with 0 bytes
        tracker.update(0, 0);

        // Simulate steady traffic: 10,000 bytes/sec for 2 seconds
        for i in 1..=20 {
            thread::sleep(Duration::from_millis(100)); // 100ms intervals
            tracker.update(i * 1000, i * 500); // 1000 bytes every 100ms = 10KB/s out, 5KB/s in
        }

        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Should converge to actual sustained rate
        // 1000 bytes / 0.1s = 10,000 bytes/sec outgoing
        // 500 bytes / 0.1s = 5,000 bytes/sec incoming
        assert!(
            outgoing_rate > 9000.0 && outgoing_rate < 11000.0,
            "Outgoing rate should be ~10KB/s, got: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate > 4500.0 && incoming_rate < 5500.0,
            "Incoming rate should be ~5KB/s, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_sliding_window_with_burst() {
        let mut tracker = RateTracker::new();

        tracker.update(0, 0);
        thread::sleep(Duration::from_millis(500));

        // Large burst: 1MB in one shot
        tracker.update(1_000_000, 500_000);
        thread::sleep(Duration::from_millis(500));

        // Then slow traffic: 10KB every 100ms
        for i in 1..=10 {
            tracker.update(1_000_000 + i * 10_000, 500_000 + i * 5_000);
            thread::sleep(Duration::from_millis(100));
        }

        let outgoing_rate = tracker.get_outgoing_rate_bps();

        // Rate should be averaged over the whole window
        // Not just the burst (which would be 2MB/s) or just the tail (which would be 100KB/s)
        // Should be somewhere in between, reflecting the mixed traffic pattern
        assert!(
            outgoing_rate > 50_000.0 && outgoing_rate < 1_000_000.0,
            "Rate should average burst and steady traffic, got: {}",
            outgoing_rate
        );
    }

    #[test]
    fn test_sliding_window_requires_minimum_timespan() {
        let mut tracker = RateTracker::new();

        tracker.update(0, 0);
        thread::sleep(Duration::from_millis(100)); // Only 100ms
        tracker.update(10_000, 5_000);

        // With only 100ms of data (< 1 second minimum), should return 0
        assert_eq!(
            tracker.get_outgoing_rate_bps(),
            0.0,
            "Should return 0 when time_span < 1 second"
        );
        assert_eq!(
            tracker.get_incoming_rate_bps(),
            0.0,
            "Should return 0 when time_span < 1 second"
        );
    }

    #[test]
    fn test_sliding_window_high_packet_rate() {
        let mut tracker = RateTracker::new();

        tracker.update(0, 0);

        // Simulate high packet rate: 100 packets/sec for 2 seconds = 200 packets
        // Each packet is 1500 bytes
        for i in 1..=200 {
            thread::sleep(Duration::from_millis(10)); // 10ms intervals = 100 pps
            tracker.update(i * 1500, i * 750);
        }

        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Expected: 1500 bytes / 0.01s = 150,000 bytes/sec = ~150 KB/s
        assert!(
            outgoing_rate > 140_000.0 && outgoing_rate < 160_000.0,
            "High packet rate should still give accurate average, got: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate > 70_000.0 && incoming_rate < 80_000.0,
            "High packet rate should still give accurate average, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_sliding_window_no_skip_first_sample() {
        let mut tracker = RateTracker::new();

        tracker.update(0, 0);
        thread::sleep(Duration::from_secs(1));

        // Add exactly one more sample
        tracker.update(10_000, 5_000);

        // Now we have 2 samples spanning 1 second with 10,000 bytes transferred
        // This should give us 10,000 bytes/sec
        // If we were .skip(1), we'd get 0 because we'd skip the only data sample!
        let outgoing_rate = tracker.get_outgoing_rate_bps();

        assert!(
            outgoing_rate > 9_000.0 && outgoing_rate < 11_000.0,
            "Should include all samples (not skip first), got: {}",
            outgoing_rate
        );
    }

    #[test]
    fn test_sliding_window_idle_connection() {
        let mut tracker = RateTracker::new();

        // Establish some traffic
        tracker.update(0, 0);
        thread::sleep(Duration::from_millis(500));
        tracker.update(100_000, 50_000);

        // Wait long enough that window slides past all traffic
        thread::sleep(Duration::from_secs(11)); // More than 10-second window

        // Should return 0 as all samples are pruned
        assert_eq!(
            tracker.get_outgoing_rate_bps(),
            0.0,
            "Should return 0 when window has slid past all traffic"
        );
    }

    #[test]
    fn test_rate_tracker_single_update() {
        let mut tracker = RateTracker::new();

        // First update establishes baseline
        tracker.update(1000, 500);
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
        // Test single update - need at least 2 samples for rate
    }

    #[test]
    fn test_rate_tracker_steady_traffic() {
        let mut tracker = RateTracker::new();

        // Add initial sample
        tracker.update(0, 0);
        thread::sleep(Duration::from_secs(1)); // Wait 1 second (minimum required)

        // Add second sample - 5000 bytes sent, 2500 received over ~1 second
        tracker.update(5000, 2500);

        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Should be approximately 5000 bytes/sec outgoing, 2500 bytes/sec incoming
        assert!(
            outgoing_rate > 4000.0 && outgoing_rate < 6000.0,
            "Outgoing rate: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate > 2000.0 && incoming_rate < 3000.0,
            "Incoming rate: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_multiple_updates() {
        let mut tracker = RateTracker::new();

        // Simulate steady transfer over time
        tracker.update(0, 0);

        // Add samples every 100ms for 1.5 seconds (15 samples)
        for i in 1..=15 {
            thread::sleep(Duration::from_millis(100));
            tracker.update(i * 1000, i * 500); // 1000 bytes/100ms = 10KB/s, 500 bytes/100ms = 5KB/s
        }

        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Should be approximately 10000 bytes/sec outgoing, 5000 bytes/sec incoming
        assert!(
            outgoing_rate > 8000.0 && outgoing_rate < 12000.0,
            "Outgoing rate: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate > 4000.0 && incoming_rate < 6000.0,
            "Incoming rate: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_window_pruning() {
        let window_duration = Duration::from_millis(300);
        let mut tracker = RateTracker::with_window_duration(window_duration);

        // Add samples that will be pruned
        tracker.update(0, 0);
        thread::sleep(Duration::from_millis(100));
        tracker.update(1000, 500);

        // Wait for samples to age out of the window
        thread::sleep(Duration::from_millis(400));
        tracker.update(2000, 1000);

        // Should only consider recent samples (rate based on last sample interval)
        let rate = tracker.get_outgoing_rate_bps();
        // After pruning, should have limited data
        assert!(rate >= 0.0); // Just verify it doesn't crash and gives reasonable result
    }

    #[test]
    fn test_connection_rate_integration() {
        let mut conn = create_test_connection();

        // Simulate receiving packets
        conn.bytes_sent = 1000;
        conn.bytes_received = 500;
        conn.update_rates();

        thread::sleep(Duration::from_millis(200));

        conn.bytes_sent = 3000;
        conn.bytes_received = 1500;
        conn.update_rates();

        // Verify backward compatibility fields are updated
        assert!(conn.current_outgoing_rate_bps >= 0.0);
        assert!(conn.current_incoming_rate_bps >= 0.0);

        // Verify rate info is updated
        assert!(conn.current_rate_bps.outgoing_bps >= 0.0);
        assert!(conn.current_rate_bps.incoming_bps >= 0.0);
    }

    #[test]
    fn test_rate_tracker_memory_limit() {
        let mut tracker = RateTracker::new();

        // Add more samples than we need, ensuring we span > 1 second
        tracker.update(0, 0);
        for i in 1..=150 {
            tracker.update(i * 100, i * 50);
            thread::sleep(Duration::from_millis(10)); // 10ms delay = 1.5 seconds total
        }

        // Should have pruned to max_samples limit (20,000)
        assert!(tracker.samples.len() <= 20_000);

        // Should still calculate rates (we have > 1 second of data)
        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();
        assert!(outgoing_rate >= 0.0);
        assert!(incoming_rate >= 0.0);
    }

    #[test]
    fn test_rate_tracker_bursty_traffic() {
        let mut tracker = RateTracker::new();

        // Initial state
        tracker.update(0, 0);
        thread::sleep(Duration::from_millis(500));

        // Burst of traffic
        tracker.update(10000, 5000);
        thread::sleep(Duration::from_millis(500));

        // No more traffic (same byte counts) - keep updating to span > 1 second
        tracker.update(10000, 5000);
        thread::sleep(Duration::from_millis(500));

        tracker.update(10000, 5000);

        // Rate should be averaged over the entire window (1.5 seconds)
        // 10,000 bytes over 1.5 seconds ≈ 6,666 bytes/sec
        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Should be smoothed average, not instantaneous burst rate (which would be 20KB/s)
        assert!(
            outgoing_rate < 12000.0,
            "Rate should be smoothed average: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate < 7000.0,
            "Rate should be smoothed average: {}",
            incoming_rate
        );
        assert!(outgoing_rate > 0.0);
        assert!(incoming_rate > 0.0);
    }

    #[test]
    fn test_rate_tracker_zero_time_diff() {
        let mut tracker = RateTracker::new();

        // Add two samples with identical or very close timestamps
        tracker.update(0, 0);
        tracker.update(1000, 500); // Immediately after, should be < 100ms apart

        // Should return 0 to avoid division by very small numbers
        assert_eq!(tracker.get_outgoing_rate_bps(), 0.0);
        assert_eq!(tracker.get_incoming_rate_bps(), 0.0);
    }

    #[test]
    fn test_rate_tracker_cumulative_fix() {
        // This test verifies the fix for the cumulative byte count issue
        let mut tracker = RateTracker::new();

        // Simulate a connection that has been running for a while with cumulative byte counts
        // Initialize tracker to simulate connection with existing traffic
        tracker.initialize_with_counts(1_000_000, 500_000);
        tracker.update(1_000_000, 500_000); // No change yet (establishing baseline)
        thread::sleep(Duration::from_millis(500));

        tracker.update(1_500_000, 750_000); // 500KB more sent, 250KB more received
        thread::sleep(Duration::from_millis(500));

        tracker.update(2_000_000, 1_000_000); // 500KB more sent, 250KB more received

        // The rate should be based on the deltas, not the cumulative values
        // We sent 1MB in deltas over ~1 second = ~1MB/s
        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // Should be approximately 1MB/s outgoing (1_000_000 bytes/sec)
        assert!(
            outgoing_rate > 800_000.0 && outgoing_rate < 1_200_000.0,
            "Outgoing rate should be ~1MB/s, got: {}",
            outgoing_rate
        );

        // Should be approximately 500KB/s incoming (500_000 bytes/sec)
        assert!(
            incoming_rate > 400_000.0 && incoming_rate < 600_000.0,
            "Incoming rate should be ~500KB/s, got: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_tracker_window_sliding() {
        // Test that rates are calculated correctly as the window slides
        let window_duration = Duration::from_secs(2); // 2-second window
        let mut tracker = RateTracker::with_window_duration(window_duration);

        // Add initial samples - 1MB/s for first second
        tracker.update(0, 0);
        for i in 1..=10 {
            thread::sleep(Duration::from_millis(100));
            tracker.update(i * 100_000, i * 50_000); // 100KB every 100ms = 1MB/s
        }

        // Wait for window to slide past first samples
        thread::sleep(Duration::from_secs(2));

        // Add new samples at same rate (add 12 to ensure > 1 second with timing variance)
        for i in 11..=22 {
            thread::sleep(Duration::from_millis(100));
            tracker.update(i * 100_000, i * 50_000); // Still 100KB every 100ms = 1MB/s
        }

        // Rate should still be consistent despite window sliding
        let outgoing_rate = tracker.get_outgoing_rate_bps();
        let incoming_rate = tracker.get_incoming_rate_bps();

        // We're sending at ~1MB/s and receiving at ~500KB/s consistently
        assert!(
            outgoing_rate > 800_000.0 && outgoing_rate < 1_200_000.0,
            "Outgoing rate after window slide: {}",
            outgoing_rate
        );
        assert!(
            incoming_rate > 400_000.0 && incoming_rate < 600_000.0,
            "Incoming rate after window slide: {}",
            incoming_rate
        );
    }

    #[test]
    fn test_rate_decay_for_idle_connections() {
        // Test that rates decay to zero when connections become idle
        let mut tracker = RateTracker::new();

        // Simulate active traffic
        tracker.update(0, 0);
        thread::sleep(Duration::from_secs(1)); // Need >= 1 second for rate calculation
        tracker.update(100_000, 50_000); // 100KB sent, 50KB received over 1 second

        // Should have non-zero rate with >= 1 second of data
        let initial_out = tracker.get_outgoing_rate_bps();
        let initial_in = tracker.get_incoming_rate_bps();
        assert!(initial_out > 0.0, "Should have outgoing traffic: {}", initial_out);
        assert!(initial_in > 0.0, "Should have incoming traffic: {}", initial_in);

        // Wait for samples to slide out of the 10-second window
        thread::sleep(Duration::from_secs(11));

        let final_out = tracker.get_outgoing_rate_bps();
        let final_in = tracker.get_incoming_rate_bps();

        // After window slides past all samples, should be zero
        assert_eq!(
            final_out, 0.0,
            "Outgoing rate should be zero after 10+ seconds idle"
        );
        assert_eq!(
            final_in, 0.0,
            "Incoming rate should be zero after 10+ seconds idle"
        );
    }

    #[test]
    fn test_connection_refresh_rates() {
        // Test that refresh_rates() properly updates cached rate values
        let mut conn = create_test_connection();

        // Initialize the rate tracker properly
        conn.rate_tracker.initialize_with_counts(0, 0);

        // Simulate first packet
        conn.bytes_sent = 50_000;
        conn.bytes_received = 25_000;
        conn.update_rates();

        thread::sleep(Duration::from_secs(1)); // Need >= 1 second for rate

        // Simulate more traffic
        conn.bytes_sent = 100_000;
        conn.bytes_received = 50_000;
        conn.update_rates();

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

        // Now simulate longer idle time and refresh (need >10s for zero)
        thread::sleep(Duration::from_secs(11));
        conn.refresh_rates();

        // Rates should be zero after refresh with long idle connection
        assert_eq!(
            conn.current_outgoing_rate_bps, 0.0,
            "Should be zero after 10+ seconds idle refresh"
        );
        assert_eq!(
            conn.current_incoming_rate_bps, 0.0,
            "Should be zero after 10+ seconds idle refresh"
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
            Protocol::UDP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            ProtocolState::Udp,
        );

        // Test QUIC with different states
        let mut quic_info = QuicInfo::new(0x00000001);
        quic_info.connection_state = QuicConnectionState::Initial;

        let dpi_info = DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_info.clone())),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        };
        conn.dpi_info = Some(dpi_info);

        assert_eq!(conn.state(), "QUIC_INITIAL");

        // Test connected state
        let mut quic_connected = quic_info.clone();
        quic_connected.connection_state = QuicConnectionState::Connected;
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_connected)),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "QUIC_CONNECTED");

        // Test draining state
        let mut quic_draining = quic_info.clone();
        quic_draining.connection_state = QuicConnectionState::Draining;
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_draining)),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "QUIC_DRAINING");
    }

    #[test]
    fn test_enhanced_state_display_dns() {
        let mut conn = Connection::new(
            Protocol::UDP,
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
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_query),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "DNS_QUERY");

        // Test DNS response
        let dns_response = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: vec!["93.184.216.34".parse().unwrap()],
            is_response: true,
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_response),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });
        assert_eq!(conn.state(), "DNS_RESPONSE");
    }

    #[test]
    fn test_enhanced_state_display_regular_udp() {
        let mut conn = Connection::new(
            Protocol::UDP,
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

        // Test established connection timeout (updated from 300s to 600s)
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);
        assert_eq!(conn.get_timeout(), Duration::from_secs(600)); // Active established (was 300)

        // Test idle established connection (updated from 180s to 300s)
        conn.last_activity = SystemTime::now() - Duration::from_secs(120);
        assert_eq!(conn.get_timeout(), Duration::from_secs(300)); // Idle established (was 180)

        // Test TIME_WAIT
        conn.protocol_state = ProtocolState::Tcp(TcpState::TimeWait);
        assert_eq!(conn.get_timeout(), Duration::from_secs(30));

        // Test closed connections
        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);
        assert_eq!(conn.get_timeout(), Duration::from_secs(5));
    }

    #[test]
    fn test_dynamic_timeout_quic() {
        let mut conn = Connection::new(
            Protocol::UDP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443),
            ProtocolState::Udp,
        );

        // Test QUIC with CONNECTION_CLOSE frame
        let mut quic_info = QuicInfo::new(0x00000001);
        quic_info.connection_close = Some(QuicCloseInfo {
            frame_type: 0x1c, // Transport close
            error_code: 0,    // NO_ERROR
            reason: None,
            detected_at: Instant::now(),
        });

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_info)),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });

        assert_eq!(conn.get_timeout(), Duration::from_secs(10)); // Draining period

        // Test application close
        let mut quic_app_close = QuicInfo::new(0x00000001);
        quic_app_close.connection_close = Some(QuicCloseInfo {
            frame_type: 0x1d, // Application close
            error_code: 1,
            reason: Some("user_cancelled".to_string()),
            detected_at: Instant::now(),
        });

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(quic_app_close)),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });

        assert_eq!(conn.get_timeout(), Duration::from_secs(1)); // Immediate cleanup
    }

    #[test]
    fn test_dynamic_timeout_dns() {
        let mut conn = Connection::new(
            Protocol::UDP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            ProtocolState::Udp,
        );

        let dns_info = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: Some(DnsQueryType::A),
            response_ips: vec![],
            is_response: false,
        };

        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(dns_info),
            first_packet_time: Instant::now(),
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
        conn.last_activity = now - Duration::from_secs(10); // Beyond 5s timeout for closed
        assert!(conn.should_cleanup(now));

        // Test established connection within timeout (updated timeout from 300s to 600s)
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);
        conn.last_activity = now - Duration::from_secs(100); // Within 600s timeout
        assert!(!conn.should_cleanup(now));

        // Test established connection beyond timeout (updated timeout to 600s)
        conn.last_activity = now - Duration::from_secs(700); // Beyond 600s timeout
        assert!(conn.should_cleanup(now));
    }

    #[test]
    fn test_staleness_ratio() {
        let mut conn = create_test_connection();
        conn.protocol_state = ProtocolState::Tcp(TcpState::Established);

        // Fresh connection - staleness ratio near 0
        let ratio = conn.staleness_ratio();
        assert!(ratio < 0.05, "Fresh connection should have low staleness ratio");

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
        assert!(ratio >= 0.75, "TIME_WAIT connection should be stale at 23s, ratio: {}", ratio);

        // Test CLOSED (5s timeout)
        conn.protocol_state = ProtocolState::Tcp(TcpState::Closed);

        // At 75% of 5s = 3.75s
        conn.last_activity = SystemTime::now() - Duration::from_secs(4);
        let ratio = conn.staleness_ratio();
        assert!(ratio >= 0.75, "CLOSED connection should be stale at 4s, ratio: {}", ratio);
    }

    #[test]
    fn test_icmp_and_arp_states() {
        // Test ICMP states
        let mut conn = Connection::new(
            Protocol::ICMP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0),
            ProtocolState::Icmp {
                icmp_type: 8,
                icmp_code: 0,
            },
        );

        assert_eq!(conn.state(), "ECHO_REQUEST");
        assert_eq!(conn.get_timeout(), Duration::from_secs(10));

        // Test ARP states
        conn.protocol = Protocol::ARP;
        conn.protocol_state = ProtocolState::Arp {
            operation: ArpOperation::Request,
        };
        assert_eq!(conn.state(), "ARP_REQUEST");
        assert_eq!(conn.get_timeout(), Duration::from_secs(30));
    }
}
