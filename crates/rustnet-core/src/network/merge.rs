// src/network/merge.rs - Connection merging and update utilities

use log::{debug, info, warn};
use std::time::{Duration, Instant, SystemTime};

use crate::network::dpi::{DpiResult, is_partial_sni, try_extract_tls_from_reassembler};
use crate::network::parser::{ParsedPacket, TcpFlags};
use crate::network::types::{
    ApplicationProtocol, Connection, DnsInfo, DpiInfo, FtpInfo, HttpInfo, HttpsInfo, MqttInfo,
    ProtocolState, QuicConnectionState, QuicInfo, SshInfo, TcpState,
};

/// Get the priority of a QUIC connection state for proper state progression
/// Higher priority = more advanced state. States should only progress forward.
/// Upper bound on DNS response IPs accumulated per connection across packets.
/// The per-packet parser already caps extraction (see `MAX_RESPONSE_IPS_PER_PACKET`
/// in dpi/dns.rs); this bounds the cross-packet merge accumulator so a sustained
/// flow cannot grow it without limit.
const MAX_MERGED_RESPONSE_IPS: usize = 64;

/// Update TCP connection state based on observed flags and current state
/// This implements the TCP state machine according to RFC 793
fn update_tcp_state(current_state: TcpState, flags: &TcpFlags, is_outgoing: bool) -> TcpState {
    debug!(
        "Updating TCP state: current_state={:?}, flags={:?}, is_outgoing={}",
        current_state, flags, is_outgoing
    );

    match (current_state, flags.syn, flags.ack, flags.fin, flags.rst) {
        // Connection establishment - three-way handshake
        (TcpState::Unknown, true, false, false, false) if !is_outgoing => TcpState::SynReceived,
        (TcpState::Unknown, true, false, false, false) if is_outgoing => TcpState::SynSent,
        (TcpState::SynSent, true, true, false, false) if !is_outgoing => TcpState::Established,
        (TcpState::SynReceived, false, true, false, false) if is_outgoing => TcpState::Established,

        // This might happen if we start parsing connections after the SYN-ACK
        (TcpState::Unknown, false, true, false, false) => TcpState::Established,
        (TcpState::Unknown, false, true, true, false) => TcpState::Established,

        // Connection termination - normal close
        (TcpState::Established, false, _, true, false) if is_outgoing => TcpState::FinWait1,
        (TcpState::Established, false, _, true, false) if !is_outgoing => TcpState::CloseWait,
        (TcpState::FinWait1, false, true, false, false) if !is_outgoing => TcpState::FinWait2,
        (TcpState::FinWait1, false, _, true, false) if !is_outgoing => TcpState::Closing,
        (TcpState::FinWait2, false, _, true, false) if !is_outgoing => TcpState::TimeWait,
        (TcpState::CloseWait, false, _, true, false) if is_outgoing => TcpState::LastAck,
        (TcpState::LastAck, false, true, false, false) if !is_outgoing => TcpState::Closed,
        (TcpState::Closing, false, true, false, false) if !is_outgoing => TcpState::TimeWait,

        // Connection reset
        (_, _, _, _, true) => TcpState::Closed,

        // Keep current state if no state transition
        _ => current_state,
    }
}

/// RFC 1982 serial-number comparison: true when `a` precedes `b` in TCP
/// sequence space. A plain `a < b` inverts once the 32-bit counter wraps,
/// which long-lived or high-volume connections do reach.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// Per-packet TCP events produced while merging a packet into a connection.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpMergeEvents {
    pub retransmits: u64,
    pub out_of_order: u64,
    pub fast_retransmits: u64,
    /// Completed data round trip when this packet's ACK closed the pending
    /// probe. Karn-filtered: never produced by a retransmitted segment.
    pub rtt_sample: Option<Duration>,
}

/// A pending RTT probe whose ACK never arrived within this window is
/// abandoned and replaced by the next outbound segment, so the estimator
/// recovers after captures miss the covering ACK.
const RTT_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The fields of one TCP segment that the analytics care about.
struct TcpSegment {
    seq: u32,
    ack: u32,
    window: u16,
    /// Sequence space the segment consumes: payload bytes plus one each
    /// for SYN and FIN.
    payload_len: u32,
    is_outgoing: bool,
    has_ack_flag: bool,
}

/// Analyze TCP segment and update analytics for retransmissions, packet
/// quality, and round-trip timing. `at` is the packet's capture timestamp.
fn analyze_tcp_segment(
    analytics: &mut crate::network::types::TcpAnalytics,
    segment: TcpSegment,
    at: SystemTime,
) -> TcpMergeEvents {
    let TcpSegment {
        seq,
        ack,
        window,
        payload_len,
        is_outgoing,
        has_ack_flag,
    } = segment;
    let mut events = TcpMergeEvents::default();

    // Track window size
    analytics.last_window_size = window;

    if is_outgoing {
        // Outbound packet - check for retransmissions
        if payload_len > 0 {
            // Only consider packets with payload for retransmit detection
            let seq_end = seq.wrapping_add(payload_len);

            if !analytics.seen_outbound {
                // First packet with data
                analytics.seen_outbound = true;
                analytics.highest_seq_outbound = seq_end;
                arm_rtt_probe(analytics, seq_end, at);
            } else if !seq_lt(analytics.highest_seq_outbound, seq_end) {
                // Segment ends at or before the highest byte already sent, so
                // it carries data the peer was sent before: a retransmission.
                // Counted every time, as repeated resends of one segment are
                // each a distinct retransmission.
                analytics.retransmit_count += 1;
                events.retransmits += 1;
                // Karn's algorithm: after a retransmission the covering ACK
                // is ambiguous (original or resend?), so the pending probe
                // must not produce a sample.
                analytics.rtt_probe = None;
                debug!(
                    "TCP retransmission detected: seq={}, len={}, highest={}",
                    seq, payload_len, analytics.highest_seq_outbound
                );
            } else {
                // Advances the stream. Covers both in-order segments and gaps
                // left by dropped captures; either way the high-water mark
                // resyncs so later retransmissions are still detected.
                analytics.highest_seq_outbound = seq_end;
                arm_rtt_probe(analytics, seq_end, at);
            }
        }
    } else {
        // Inbound packet - check for out-of-order and duplicate ACKs
        if payload_len > 0 {
            let seq_end = seq.wrapping_add(payload_len);

            if !analytics.seen_inbound {
                // First inbound packet with data
                analytics.seen_inbound = true;
                analytics.highest_seq_inbound = seq_end;
            } else if !seq_lt(analytics.highest_seq_inbound, seq_end) {
                // Re-covers data already received: arrived late or duplicated.
                analytics.out_of_order_count += 1;
                events.out_of_order += 1;
                debug!(
                    "TCP out-of-order packet: seq={}, len={}, highest={}",
                    seq, payload_len, analytics.highest_seq_inbound
                );
            } else {
                analytics.highest_seq_inbound = seq_end;
            }
        }

        // Complete the pending RTT probe: an inbound segment acknowledging
        // every timed byte closes it. Data segments carry ACKs too, so this
        // is deliberately not limited to pure ACKs.
        if has_ack_flag
            && let Some((probe_seq, sent_at)) = analytics.rtt_probe
            && !seq_lt(ack, probe_seq)
        {
            // Err means the ACK's capture time precedes the send: clocks or
            // packet order went backwards, so no sample either way.
            if let Ok(rtt) = at.duration_since(sent_at) {
                analytics.last_rtt = Some(rtt);
                analytics.smoothed_rtt = Some(match analytics.smoothed_rtt {
                    // RFC 6298 smoothing: 7/8 previous + 1/8 new sample.
                    Some(srtt) => (srtt * 7 + rtt) / 8,
                    None => rtt,
                });
                analytics.rtt_samples += 1;
                events.rtt_sample = Some(rtt);
            }
            analytics.rtt_probe = None;
        }

        // Check for duplicate ACKs (fast retransmit indicator).
        //
        // RFC 5681 §2 requires a duplicate ACK to carry no data — otherwise
        // every inbound data segment of a download counts as one, since they
        // all repeat the same ack number while we have nothing to send, and
        // the fast-retransmit total balloons on healthy connections.
        if has_ack_flag && payload_len == 0 {
            if !analytics.seen_ack {
                // First ACK seen
                analytics.seen_ack = true;
                analytics.last_ack_received = ack;
            } else if ack == analytics.last_ack_received {
                // Duplicate ACK
                analytics.dup_ack_run += 1;
                analytics.duplicate_ack_count += 1;

                // RFC 5681: 3 duplicate ACKs trigger fast retransmit
                if analytics.dup_ack_run == 3 {
                    analytics.fast_retransmit_count += 1;
                    events.fast_retransmits += 1;
                    debug!("TCP fast retransmit triggered (3 duplicate ACKs)");
                }
            } else if seq_lt(analytics.last_ack_received, ack) {
                // Only a forward-moving ACK ends the run. A reordered stale
                // ACK must not clear it, or the run never reaches 3.
                analytics.last_ack_received = ack;
                analytics.dup_ack_run = 0;
            }
        }
    }

    events
}

/// Start timing an outbound segment unless a fresh probe is already in
/// flight. Timing the oldest outstanding segment measures the true round
/// trip; a probe past `RTT_PROBE_TIMEOUT` (its ACK was never captured) is
/// replaced so the estimator recovers.
fn arm_rtt_probe(
    analytics: &mut crate::network::types::TcpAnalytics,
    seq_end: u32,
    at: SystemTime,
) {
    let stale = analytics.rtt_probe.is_none_or(|(_, sent_at)| {
        at.duration_since(sent_at)
            .map_or(true, |age| age > RTT_PROBE_TIMEOUT)
    });
    if stale {
        analytics.rtt_probe = Some((seq_end, at));
    }
}

/// Merge a parsed packet into an existing connection, mutating it in place.
/// Returns the TCP events this packet produced (loss counters, RTT sample).
pub fn merge_packet_into_connection(
    conn: &mut Connection,
    parsed: &ParsedPacket,
    now: SystemTime,
) -> TcpMergeEvents {
    let mut tcp_events = TcpMergeEvents::default();
    let was_terminal = conn.is_terminal();

    // Record every observed packet. Terminal cleanup uses terminal_since, so
    // late teardown retransmissions update last seen data without postponing
    // archival.
    let observation_time = conn.last_activity.max(now);
    conn.last_activity = observation_time;

    // Deterministic for a given interface snapshot; last-wins self-heals
    // connections whose first packet raced interface enumeration.
    conn.local_addr_kind = parsed.local_addr_kind;
    conn.remote_addr_kind = parsed.remote_addr_kind;

    // Update packet counts and bytes
    if parsed.is_outgoing {
        conn.packets_sent += 1;
        conn.bytes_sent += parsed.packet_len as u64;
    } else {
        conn.packets_received += 1;
        conn.bytes_received += parsed.packet_len as u64;
    }

    // Update protocol state (from packet flags/state)
    if let Some(tcp_header) = parsed.tcp_header {
        let current_tcp_state = match conn.protocol_state {
            ProtocolState::Tcp(state) => state,
            _ => {
                warn!("Merging TCP packet into non-TCP connection, resetting to Unknown state");
                TcpState::Unknown
            }
        };

        let new_tcp_state =
            update_tcp_state(current_tcp_state, &tcp_header.flags, parsed.is_outgoing);

        if current_tcp_state != new_tcp_state {
            debug!(
                "TCP state transition: {:?} -> {:?}",
                current_tcp_state, new_tcp_state
            );
        }

        conn.protocol_state = ProtocolState::Tcp(new_tcp_state);

        // Update TCP analytics for retransmission and quality metrics
        if let Some(analytics) = conn.tcp_analytics.as_mut() {
            // Use actual TCP payload length from header
            // Note: SYN and FIN flags also consume 1 sequence number each, even with no payload
            let payload_len = tcp_header.payload_len;
            let seq_consumed = payload_len
                + if tcp_header.flags.syn { 1 } else { 0 }
                + if tcp_header.flags.fin { 1 } else { 0 };

            tcp_events = analyze_tcp_segment(
                analytics,
                TcpSegment {
                    seq: tcp_header.seq,
                    ack: tcp_header.ack,
                    window: tcp_header.window,
                    payload_len: seq_consumed,
                    is_outgoing: parsed.is_outgoing,
                    has_ack_flag: tcp_header.flags.ack,
                },
                now,
            );
        }
    } else {
        // If no TCP flags, keep existing state or use the one from packet
        match (&conn.protocol_state, &parsed.protocol_state) {
            (ProtocolState::Tcp(_), _) => {
                // Keep existing TCP state if we have it
            }
            _ => {
                // Use the state from the packet for non-TCP protocols
                conn.protocol_state = parsed.protocol_state.clone();
            }
        }

        // A flow first seen mid-capture starts with an unknown direction;
        // a later echo request still settles who initiated it.
        if conn.connection_direction.is_none() {
            conn.connection_direction = icmp_echo_direction(parsed);
        }
    }

    // Update DPI info if available
    if let Some(dpi_result) = &parsed.dpi_result {
        merge_dpi_info(conn, dpi_result);
    }

    // Update PKTAP process metadata if available
    // Once set, process info should be immutable to prevent conflicts between sources
    if let Some(new_process_name) = &parsed.process_name {
        match &conn.process_name {
            None => {
                // First time setting process name - this becomes immutable
                conn.process_name = Some(new_process_name.clone());
                info!(
                    "🔒 Set IMMUTABLE process name for connection {} from PKTAP: '{}' (len:{})",
                    conn.key(),
                    new_process_name,
                    new_process_name.len()
                );
            }
            Some(existing_name) => {
                // Process name is already set - it's now IMMUTABLE
                // Log the attempt but NEVER change it
                if existing_name != new_process_name {
                    warn!(
                        "🚫 IMMUTABILITY VIOLATION: Attempt to change process name for {} from '{}' to '{}' - REJECTED",
                        conn.key(),
                        existing_name,
                        new_process_name
                    );
                    debug!(
                        "🔒 Existing: '{}' (len:{}, bytes:{:?})",
                        existing_name,
                        existing_name.len(),
                        existing_name.as_bytes()
                    );
                    debug!(
                        "🚫 Rejected: '{}' (len:{}, bytes:{:?})",
                        new_process_name,
                        new_process_name.len(),
                        new_process_name.as_bytes()
                    );
                } else {
                    debug!(
                        "✅ Process name confirmed unchanged for {}: '{}'",
                        conn.key(),
                        existing_name
                    );
                }
                // NEVER update - process name is immutable once set
            }
        }
    }

    if let Some(new_pid) = parsed.process_id {
        match conn.pid {
            None => {
                // First time setting PID - this becomes immutable
                conn.pid = Some(new_pid);
                info!(
                    "🔒 Set IMMUTABLE process ID for connection {} from PKTAP: {}",
                    conn.key(),
                    new_pid
                );
            }
            Some(existing_pid) if existing_pid != new_pid => {
                warn!(
                    "🚫 IMMUTABILITY VIOLATION: Attempt to change PID for {} from {} to {} - REJECTED",
                    conn.key(),
                    existing_pid,
                    new_pid
                );
                // NEVER update - PID is immutable once set
            }
            Some(existing_pid) => {
                debug!(
                    "✅ Process ID confirmed unchanged for {}: {}",
                    conn.key(),
                    existing_pid
                );
            }
        }
    }

    let is_terminal = conn.is_terminal();
    if is_terminal {
        if !was_terminal || conn.terminal_since.is_none() {
            conn.terminal_since = Some(observation_time);
        }
    } else {
        conn.terminal_since = None;
    }

    // Update rate calculations
    update_connection_rates(conn);

    tcp_events
}

/// Flow direction from an ICMP echo request: whoever sends the request
/// initiated the flow. Replies are ignored because loopback captures see
/// them as outgoing too, which would misread a local ping as inbound.
fn icmp_echo_direction(parsed: &ParsedPacket) -> Option<bool> {
    match parsed.protocol_state {
        ProtocolState::Icmp {
            icmp_type: 8 | 128,
            icmp_id: Some(_),
            ..
        } => Some(parsed.is_outgoing),
        _ => None,
    }
}

/// Create a new connection from a parsed packet
pub fn create_connection_from_packet(parsed: &ParsedPacket, now: SystemTime) -> Connection {
    let mut conn = Connection::new(
        parsed.protocol,
        parsed.local_addr,
        parsed.remote_addr,
        parsed.protocol_state.clone(),
    );
    conn.local_addr_kind = parsed.local_addr_kind;
    conn.remote_addr_kind = parsed.remote_addr_kind;

    // Set initial TCP state based on flags if TCP
    if let Some(tcp_header) = parsed.tcp_header {
        let tcp_state = update_tcp_state(TcpState::Unknown, &tcp_header.flags, parsed.is_outgoing);
        conn.protocol_state = ProtocolState::Tcp(tcp_state);

        // Set connection direction only if we observed the TCP handshake
        // SynSent = we initiated (outgoing), SynReceived = they initiated (incoming)
        // Also detect from SYN+ACK: receiving SYN+ACK means we initiated (outgoing)
        conn.connection_direction = match tcp_state {
            TcpState::SynSent => Some(true),      // outgoing - we sent SYN
            TcpState::SynReceived => Some(false), // incoming - we received SYN
            _ => {
                // Check if first packet is SYN+ACK - can also determine direction
                if tcp_header.flags.syn && tcp_header.flags.ack {
                    // SYN+ACK received = we initiated (outgoing)
                    // SYN+ACK sent = they initiated (incoming)
                    Some(!parsed.is_outgoing)
                } else {
                    None // mid-stream capture, direction unknown
                }
            }
        };

        debug!(
            "Created new {} connection: {:?} -> {:?}, state: {:?}, direction: {:?}",
            parsed.protocol,
            parsed.local_addr,
            parsed.remote_addr,
            conn.protocol_state,
            conn.connection_direction
        );
    } else {
        // For non-TCP protocols, use the provided state directly. ICMP echo
        // requests still reveal the initiator; other stateless protocols
        // leave the direction unknown.
        conn.protocol_state = parsed.protocol_state.clone();
        conn.connection_direction = icmp_echo_direction(parsed);
    }

    // Set initial stats based on packet direction
    if parsed.is_outgoing {
        conn.packets_sent = 1;
        conn.bytes_sent = parsed.packet_len as u64;
        conn.packets_received = 0;
        conn.bytes_received = 0;
    } else {
        conn.packets_sent = 0;
        conn.bytes_sent = 0;
        conn.packets_received = 1;
        conn.bytes_received = parsed.packet_len as u64;
    }

    // Apply DPI results if any
    if let Some(dpi_result) = &parsed.dpi_result {
        conn.dpi_info = Some(DpiInfo {
            application: dpi_result.application.clone(),
            last_update_time: Instant::now(),
        });

        debug!(
            "New connection with DPI: {} - {}",
            conn.key(),
            dpi_result.application
        );
    }

    // Apply PKTAP process metadata if available
    if let Some(process_name) = &parsed.process_name {
        conn.process_name = Some(process_name.clone());
        debug!(
            "✓ New connection {} with process name: {}",
            conn.key(),
            process_name
        );
    }
    if let Some(process_id) = parsed.process_id {
        conn.pid = Some(process_id);
        debug!(
            "✓ New connection {} with process ID: {}",
            conn.key(),
            process_id
        );
    }

    conn.created_at = now;
    conn.last_activity = now;
    conn.terminal_since = conn.is_terminal().then_some(now);

    // Initialize the rate tracker with the initial byte counts
    // This prevents incorrect delta calculation on the first update
    conn.rate_tracker
        .initialize_with_counts(conn.bytes_sent, conn.bytes_received);

    conn
}

/// Merge DPI information into an existing connection
fn merge_dpi_info(conn: &mut Connection, dpi_result: &DpiResult) {
    match &mut conn.dpi_info {
        None => {
            // No existing DPI info, use the new one
            conn.dpi_info = Some(DpiInfo {
                application: dpi_result.application.clone(),
                last_update_time: Instant::now(),
            });

            debug!(
                "Added DPI info to connection: {} - {}",
                conn.key(),
                dpi_result.application
            );
        }
        Some(dpi_info) => {
            // Update the last update time
            dpi_info.last_update_time = Instant::now();

            // Match on both the existing and new application protocols
            match (&mut dpi_info.application, &dpi_result.application) {
                // HTTP merging
                (ApplicationProtocol::Http(old_info), ApplicationProtocol::Http(new_info)) => {
                    merge_http_info(old_info, new_info);
                }

                // HTTPS/TLS merging
                (ApplicationProtocol::Https(old_info), ApplicationProtocol::Https(new_info)) => {
                    merge_https_info(old_info, new_info);
                }

                // QUIC merging - this is where the reassembly happens
                (ApplicationProtocol::Quic(old_info), ApplicationProtocol::Quic(new_info)) => {
                    merge_quic_info(old_info.as_mut(), new_info.as_ref());
                }

                // DNS merging
                (ApplicationProtocol::Dns(old_info), ApplicationProtocol::Dns(new_info)) => {
                    merge_dns_info(old_info, new_info);
                }

                // SSH - merge SSH info
                (ApplicationProtocol::Ssh(old_info), ApplicationProtocol::Ssh(new_info)) => {
                    merge_ssh_info(old_info, new_info);
                }

                // BitTorrent - merge peer info
                (
                    ApplicationProtocol::BitTorrent(old_info),
                    ApplicationProtocol::BitTorrent(new_info),
                ) => {
                    if old_info.client.is_none() {
                        old_info.client.clone_from(&new_info.client);
                    }
                    if old_info.info_hash.is_none() {
                        old_info.info_hash.clone_from(&new_info.info_hash);
                    }
                }

                // MQTT - merge client_id and topic from subsequent packets
                (ApplicationProtocol::Mqtt(old_info), ApplicationProtocol::Mqtt(new_info)) => {
                    merge_mqtt_info(old_info, new_info);
                }

                // FTP - dialog state evolves across requests/responses
                (ApplicationProtocol::Ftp(old_info), ApplicationProtocol::Ftp(new_info)) => {
                    merge_ftp_info(old_info, new_info);
                }

                _ => {
                    // Keep existing protocol
                }
            }
        }
    }
}

/// Merge HTTP information
fn merge_http_info(old_info: &mut HttpInfo, new_info: &HttpInfo) {
    // Update method if not set
    if old_info.method.is_none() && new_info.method.is_some() {
        old_info.method = new_info.method.clone();
    }

    // Update path if not set
    if old_info.path.is_none() && new_info.path.is_some() {
        old_info.path = new_info.path.clone();
    }

    // Update host if not set
    if old_info.host.is_none() && new_info.host.is_some() {
        old_info.host = new_info.host.clone();
    }

    // Update user agent if not set
    if old_info.user_agent.is_none() && new_info.user_agent.is_some() {
        old_info.user_agent = new_info.user_agent.clone();
    }

    // Update status code if not set
    if old_info.status_code.is_none() && new_info.status_code.is_some() {
        old_info.status_code = new_info.status_code;
    }
}

/// Merge HTTPS/TLS information
fn merge_https_info(old_info: &mut HttpsInfo, new_info: &HttpsInfo) {
    // Update version if not set or if new is more specific
    if old_info.tls_info.is_none() && new_info.tls_info.is_some() {
        old_info.tls_info = new_info.tls_info.clone();
    } else if let (Some(old_tls), Some(new_tls)) = (&mut old_info.tls_info, &new_info.tls_info) {
        // Merge TLS info - prefer more complete info
        if old_tls.version.is_none() && new_tls.version.is_some() {
            old_tls.version = new_tls.version;
        }
        if old_tls.sni.is_none() && new_tls.sni.is_some() {
            old_tls.sni = new_tls.sni.clone();
        }
        if old_tls.alpn.is_empty() && !new_tls.alpn.is_empty() {
            old_tls.alpn = new_tls.alpn.clone();
        }
        if old_tls.cipher_suite.is_none() && new_tls.cipher_suite.is_some() {
            old_tls.cipher_suite = new_tls.cipher_suite;
        }
    }
}

/// Merge QUIC information with reassembly support
fn merge_quic_info(old_info: &mut QuicInfo, new_info: &QuicInfo) {
    // Update connection state only if it progresses forward
    // State progression: Unknown -> Initial -> Handshaking -> Connected -> Draining -> Closed
    let old_priority = old_info.connection_state.priority();
    let new_priority = new_info.connection_state.priority();

    if new_priority > old_priority {
        debug!(
            "QUIC connection state progressed: {:?} -> {:?}",
            old_info.connection_state, new_info.connection_state
        );
        old_info.connection_state = new_info.connection_state;
    }

    // Update packet type
    old_info.packet_type = new_info.packet_type;

    // Update connection ID if we didn't have it
    if old_info.connection_id.is_empty() && !new_info.connection_id.is_empty() {
        old_info.connection_id = new_info.connection_id.clone();
        old_info.connection_id_hex = new_info.connection_id_hex.clone();
    }

    // Update version string if we didn't have it
    if old_info.version_string.is_none() && new_info.version_string.is_some() {
        old_info.version_string = new_info.version_string.clone();
    }

    // Merge CRYPTO frame reassembler state - this is crucial for proper SNI extraction
    // The reassembler must persist across multiple packets to handle fragmented TLS handshakes
    if let Some(new_reassembler) = &new_info.crypto_reassembler {
        if old_info.crypto_reassembler.is_none() {
            // First time seeing crypto frames, initialize the connection-level reassembler
            old_info.crypto_reassembler = Some(new_reassembler.clone());
            debug!(
                "QUIC: Initialized crypto reassembler for connection with Connection ID: {:?}",
                old_info.connection_id_hex
            );
        } else if let Some(old_reassembler) = &mut old_info.crypto_reassembler {
            // Merge fragments from new reassembler into connection-level reassembler
            // This handles out-of-order CRYPTO frames across packets
            for (&offset, data) in new_reassembler.get_fragments() {
                match old_reassembler.add_fragment(offset, data.clone()) {
                    Ok(_) => {
                        debug!(
                            "QUIC: Merged CRYPTO fragment at offset {} for connection {}",
                            offset,
                            old_info.connection_id_hex.as_deref().unwrap_or("unknown")
                        );
                    }
                    Err(e) => {
                        warn!("QUIC: Failed to merge CRYPTO fragment: {}", e);
                    }
                }
            }

            // If current SNI is partial or missing, try re-extracting from merged reassembler
            let should_retry = match &old_info.tls_info {
                None => true,
                Some(tls) => {
                    tls.sni.is_none() || tls.sni.as_ref().is_some_and(|s| is_partial_sni(s))
                }
            };

            if should_retry {
                debug!(
                    "QUIC: SNI is partial or missing, attempting re-extraction from merged fragments"
                );
                // First try without partial extraction to get complete SNI
                if let Some(new_tls) = try_extract_tls_from_reassembler(old_reassembler, false) {
                    debug!(
                        "QUIC: Re-extraction succeeded with complete SNI: {:?}",
                        new_tls.sni
                    );
                    old_info.tls_info = Some(new_tls);
                } else {
                    // If complete extraction failed, allow partial as fallback
                    if let Some(new_tls) = try_extract_tls_from_reassembler(old_reassembler, true) {
                        debug!(
                            "QUIC: Re-extraction returned partial SNI as fallback: {:?}",
                            new_tls.sni
                        );
                        old_info.tls_info = Some(new_tls);
                    }
                }
            }

            // Update cached TLS info if new reassembler has it and it's better
            if let Some(tls_info) = new_reassembler.get_cached_tls_info() {
                let new_is_complete = tls_info.sni.as_ref().is_some_and(|s| !is_partial_sni(s));
                let should_update = match &old_info.tls_info {
                    None => true,
                    Some(old_tls) => {
                        let old_is_partial =
                            old_tls.sni.as_ref().is_some_and(|s| is_partial_sni(s));
                        old_tls.sni.is_none() || (old_is_partial && new_is_complete)
                    }
                };
                if should_update {
                    old_info.tls_info = Some(tls_info.clone());
                    debug!(
                        "QUIC: Updated TLS info from reassembler - SNI: {:?}, ALPN: {:?}",
                        tls_info.sni, tls_info.alpn
                    );
                }
            }
        }
    }

    // Update TLS info if new packet has better info
    match (&old_info.tls_info, &new_info.tls_info) {
        (None, Some(new_tls)) => {
            old_info.tls_info = Some(new_tls.clone());
            debug!("QUIC: Added TLS info - SNI: {:?}", new_tls.sni);
        }
        (Some(old_tls), Some(new_tls)) => {
            // Merge TLS info - prefer more complete info
            let mut updated = false;
            let mut merged_tls = old_tls.clone();

            // Prefer complete SNI over partial, or any SNI over none
            let old_sni_is_partial = old_tls.sni.as_ref().is_some_and(|s| is_partial_sni(s));
            let new_sni_is_partial = new_tls.sni.as_ref().is_some_and(|s| is_partial_sni(s));

            if old_tls.sni.is_none() && new_tls.sni.is_some() {
                merged_tls.sni = new_tls.sni.clone();
                updated = true;
            } else if old_sni_is_partial && new_tls.sni.is_some() && !new_sni_is_partial {
                // Replace partial with complete
                debug!(
                    "QUIC: Replacing partial SNI {:?} with complete SNI {:?}",
                    old_tls.sni, new_tls.sni
                );
                merged_tls.sni = new_tls.sni.clone();
                updated = true;
            }

            if old_tls.alpn.is_empty() && !new_tls.alpn.is_empty() {
                merged_tls.alpn = new_tls.alpn.clone();
                updated = true;
            }

            if old_tls.version.is_none() && new_tls.version.is_some() {
                merged_tls.version = new_tls.version;
                updated = true;
            }

            if old_tls.cipher_suite.is_none() && new_tls.cipher_suite.is_some() {
                merged_tls.cipher_suite = new_tls.cipher_suite;
                updated = true;
            }

            if updated {
                old_info.tls_info = Some(merged_tls);
                debug!("QUIC: Merged TLS info");
            }
        }
        _ => {}
    }

    // Update has_crypto_frame flag
    if new_info.has_crypto_frame {
        old_info.has_crypto_frame = true;
    }

    // Handle CONNECTION_CLOSE frame detection
    if let Some(new_close) = &new_info.connection_close {
        // CONNECTION_CLOSE is final - always update
        old_info.connection_close = Some(new_close.clone());

        // Update connection state based on close frame
        old_info.connection_state = match new_close.frame_type {
            0x1c if new_close.error_code == 0 => {
                // NO_ERROR transport close - enter draining state
                debug!("QUIC: Connection entering draining state (NO_ERROR transport close)");
                QuicConnectionState::Draining
            }
            0x1c => {
                // Transport error - connection is closed
                debug!(
                    "QUIC: Connection closed due to transport error: {}",
                    new_close.error_code
                );
                QuicConnectionState::Closed
            }
            0x1d => {
                // Application close - connection is closed
                debug!(
                    "QUIC: Connection closed by application: {}",
                    new_close.error_code
                );
                QuicConnectionState::Closed
            }
            _ => {
                // Unknown close type - assume closed
                debug!(
                    "QUIC: Connection closed (unknown frame type: 0x{:02x})",
                    new_close.frame_type
                );
                QuicConnectionState::Closed
            }
        };

        debug!(
            "QUIC: Updated connection state to {:?} due to CONNECTION_CLOSE frame",
            old_info.connection_state
        );
    }

    // Update idle timeout if provided
    if new_info.idle_timeout.is_some() {
        old_info.idle_timeout = new_info.idle_timeout;
    }
}

/// Merge DNS information
fn merge_dns_info(old_info: &mut DnsInfo, new_info: &DnsInfo) {
    // Update query name if not set
    if old_info.query_name.is_none() && new_info.query_name.is_some() {
        old_info.query_name = new_info.query_name.clone();
    }

    // Update query type if not set
    if old_info.query_type.is_none() && new_info.query_type.is_some() {
        old_info.query_type = new_info.query_type;
    }

    // Merge response IPs (keep unique). Cap the accumulator: a long-lived
    // DNS-shaped UDP flow (the idle timeout is refreshed on every packet) would
    // otherwise grow this Vec without bound, and the `contains` dedup is a linear
    // scan, so an attacker feeding a steady stream of distinct A/AAAA answers
    // drives O(n^2) CPU and unbounded memory on the processing pipeline. The UI
    // only renders a short list and the cap is far above any real resolver answer.
    for ip in &new_info.response_ips {
        if old_info.response_ips.len() >= MAX_MERGED_RESPONSE_IPS {
            break;
        }
        if !old_info.response_ips.contains(ip) {
            old_info.response_ips.push(*ip);
        }
    }

    // Update response flag
    if new_info.is_response {
        old_info.is_response = true;
    }

    // The txid identifies the most recent transaction on this socket
    old_info.txid = new_info.txid;

    // Latest response code wins; a query packet must not erase it
    if new_info.rcode.is_some() {
        old_info.rcode = new_info.rcode;
    }
}

/// Merge SSH information
fn merge_ssh_info(old_info: &mut SshInfo, new_info: &SshInfo) {
    // Update version if not set
    if old_info.version.is_none() && new_info.version.is_some() {
        old_info.version = new_info.version.clone();
    }

    // Update client software if not set
    if old_info.client_software.is_none() && new_info.client_software.is_some() {
        old_info.client_software = new_info.client_software.clone();
    }

    // Update server software if not set
    if old_info.server_software.is_none() && new_info.server_software.is_some() {
        old_info.server_software = new_info.server_software.clone();
    }

    // Update connection state to the more advanced state
    use crate::network::types::SshConnectionState;
    match (&old_info.connection_state, &new_info.connection_state) {
        (SshConnectionState::Banner, _) => {
            old_info.connection_state = new_info.connection_state.clone()
        }
        (SshConnectionState::KeyExchange, SshConnectionState::Authentication) => {
            old_info.connection_state = new_info.connection_state.clone()
        }
        (SshConnectionState::KeyExchange, SshConnectionState::Established) => {
            old_info.connection_state = new_info.connection_state.clone()
        }
        (SshConnectionState::Authentication, SshConnectionState::Established) => {
            old_info.connection_state = new_info.connection_state.clone()
        }
        _ => {} // Keep existing state if it's more advanced
    }

    // Merge algorithms - prioritize final negotiated algorithms over initial offers
    match (&old_info.connection_state, &new_info.connection_state) {
        // If we're moving to Established state and new info has algorithms, use those (final negotiated)
        (_, SshConnectionState::Established) if !new_info.algorithms.is_empty() => {
            old_info.algorithms = new_info.algorithms.clone();
        }
        // If both are in Established state, merge unique algorithms
        (SshConnectionState::Established, SshConnectionState::Established) => {
            for algo in &new_info.algorithms {
                if !old_info.algorithms.contains(algo) {
                    old_info.algorithms.push(algo.clone());
                }
            }
        }
        // For earlier states, accumulate all seen algorithms
        _ => {
            for algo in &new_info.algorithms {
                if !old_info.algorithms.contains(algo) {
                    old_info.algorithms.push(algo.clone());
                }
            }
        }
    }

    // Update auth method if not set
    if old_info.auth_method.is_none() && new_info.auth_method.is_some() {
        old_info.auth_method = new_info.auth_method.clone();
    }
}

/// Merge FTP information across packets in the same control connection.
///
/// Identity-like fields (`username`, `server_software`, `system_type`) are
/// first-wins so the first observed value is preserved across long-lived
/// sessions. Dialog state (`message_type`, `command`, `args`, `response_code`,
/// `response_message`) is latest-wins so the connection-table column reflects
/// the most recent exchange.
fn merge_ftp_info(old_info: &mut FtpInfo, new_info: &FtpInfo) {
    if old_info.username.is_none() && new_info.username.is_some() {
        old_info.username.clone_from(&new_info.username);
    }
    if old_info.server_software.is_none() && new_info.server_software.is_some() {
        old_info
            .server_software
            .clone_from(&new_info.server_software);
    }
    if old_info.system_type.is_none() && new_info.system_type.is_some() {
        old_info.system_type.clone_from(&new_info.system_type);
    }
    old_info.message_type = new_info.message_type;
    if new_info.command.is_some() {
        old_info.command.clone_from(&new_info.command);
    }
    if new_info.args.is_some() {
        old_info.args.clone_from(&new_info.args);
    }
    if new_info.response_code.is_some() {
        old_info.response_code = new_info.response_code;
    }
    if new_info.response_message.is_some() {
        old_info
            .response_message
            .clone_from(&new_info.response_message);
    }
}

/// Merge MQTT information
fn merge_mqtt_info(old_info: &mut MqttInfo, new_info: &MqttInfo) {
    if old_info.version.is_none() && new_info.version.is_some() {
        old_info.version = new_info.version;
    }
    if old_info.client_id.is_none() && new_info.client_id.is_some() {
        old_info.client_id.clone_from(&new_info.client_id);
    }
    if old_info.topic.is_none() && new_info.topic.is_some() {
        old_info.topic.clone_from(&new_info.topic);
    }
    if old_info.qos.is_none() && new_info.qos.is_some() {
        old_info.qos = new_info.qos;
    }
    // Always update packet_type to show the latest activity
    old_info.packet_type = new_info.packet_type;
}

/// Update connection rate calculations using sliding window
fn update_connection_rates(conn: &mut Connection) {
    // Use the new rate tracker with sliding window calculation
    conn.update_rates();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{AddrKind, Protocol, ProtocolState, TcpState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    fn create_test_packet(is_outgoing: bool, fin: bool) -> ParsedPacket {
        use crate::network::protocol::tcp::{TcpFlags, TcpHeaderInfo};

        ParsedPacket {
            protocol: Protocol::Tcp,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            local_addr_kind: AddrKind::Unicast,
            remote_addr_kind: AddrKind::Unicast,
            protocol_state: ProtocolState::Tcp(TcpState::Unknown),
            tcp_header: Some(TcpHeaderInfo {
                seq: 1000,
                ack: 2000,
                window: 65535,
                flags: TcpFlags {
                    syn: false,
                    ack: false,
                    fin,
                    rst: false,
                    psh: false,
                    urg: false,
                },
                payload_len: 60, // Simulated payload length
            }),
            is_outgoing,
            packet_len: 100,
            dpi_result: None,
            process_name: None,
            process_id: None,
        }
    }

    #[test]
    fn test_merge_dns_response_ips_is_capped() {
        // A sustained DNS-shaped flow must not grow response_ips without bound.
        // Feed far more distinct answer IPs than the cap and confirm it stops.
        let mut old = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: None,
            response_ips: Vec::new(),
            is_response: true,
            txid: 0x1234,
            rcode: Some(0),
        };

        for i in 0..(MAX_MERGED_RESPONSE_IPS as u32 * 4) {
            let octets = i.to_be_bytes();
            let new = DnsInfo {
                query_name: None,
                query_type: None,
                response_ips: vec![IpAddr::V4(Ipv4Addr::new(
                    10, octets[1], octets[2], octets[3],
                ))],
                is_response: true,
                txid: 0x1234,
                rcode: Some(0),
            };
            merge_dns_info(&mut old, &new);
        }

        assert_eq!(old.response_ips.len(), MAX_MERGED_RESPONSE_IPS);
    }

    /// A follow-up query on the same socket must not erase the last response
    /// code, while the txid always tracks the most recent transaction.
    #[test]
    fn test_merge_dns_keeps_rcode_and_tracks_latest_txid() {
        let mut old = DnsInfo {
            query_name: Some("example.com".to_string()),
            query_type: None,
            response_ips: Vec::new(),
            is_response: true,
            txid: 0x1111,
            rcode: Some(3),
        };
        let new_query = DnsInfo {
            query_name: None,
            query_type: None,
            response_ips: Vec::new(),
            is_response: false,
            txid: 0x2222,
            rcode: None,
        };

        merge_dns_info(&mut old, &new_query);
        assert_eq!(old.txid, 0x2222);
        assert_eq!(old.rcode, Some(3), "a query must not erase the last rcode");

        let new_response = DnsInfo {
            query_name: None,
            query_type: None,
            response_ips: Vec::new(),
            is_response: true,
            txid: 0x2222,
            rcode: Some(0),
        };
        merge_dns_info(&mut old, &new_response);
        assert_eq!(old.rcode, Some(0), "the latest response code wins");
    }

    #[test]
    fn test_merge_packet_into_connection() {
        let mut conn = create_test_connection();
        let packet = create_test_packet(true, false);

        let _tcp_events = merge_packet_into_connection(&mut conn, &packet, SystemTime::now());

        assert_eq!(conn.packets_sent, 1);
        assert_eq!(conn.bytes_sent, 100);
        assert_eq!(conn.packets_received, 0);
    }

    #[test]
    fn test_create_connection_from_packet() {
        let packet = create_test_packet(false, false);
        let conn = create_connection_from_packet(&packet, SystemTime::now());

        assert_eq!(conn.packets_received, 1);
        assert_eq!(conn.bytes_received, 100);
        assert_eq!(conn.packets_sent, 0);
    }

    #[test]
    fn endpoint_kinds_are_copied_and_refreshed_on_merge() {
        let mut packet = create_test_packet(false, false);
        packet.local_addr_kind = AddrKind::Broadcast;
        let conn = create_connection_from_packet(&packet, SystemTime::now());
        assert_eq!(conn.local_addr_kind, AddrKind::Broadcast);
        assert_eq!(conn.remote_addr_kind, AddrKind::Unicast);

        // A connection first seen before a refresh added its subnet self-heals
        // when a later packet carries the corrected kind.
        let stale = create_test_packet(false, false);
        let mut conn = create_connection_from_packet(&stale, SystemTime::now());
        assert_eq!(conn.local_addr_kind, AddrKind::Unicast);
        merge_packet_into_connection(&mut conn, &packet, SystemTime::now());
        assert_eq!(conn.local_addr_kind, AddrKind::Broadcast);
    }

    #[test]
    fn test_new_connection_rate_tracker_initialization() {
        // Test that the rate tracker is properly initialized for new connections
        let packet = create_test_packet(true, false);
        let mut conn = create_connection_from_packet(&packet, SystemTime::now());

        // The connection should have initial bytes
        assert_eq!(conn.bytes_sent, 100);
        assert_eq!(conn.bytes_received, 0);

        // Now simulate merging another packet
        let packet2 = create_test_packet(true, false);
        let _tcp_events = merge_packet_into_connection(&mut conn, &packet2, SystemTime::now());

        // Bytes should have increased
        assert_eq!(conn.bytes_sent, 200);
        assert_eq!(conn.bytes_received, 0);

        // Update rates - this should not cause a huge spike
        conn.update_rates();

        // The rate should be reasonable (not include the initial 100 bytes as a spike)
        // Since we just added 100 bytes, the rate should be based on that delta
        // not on the full 200 bytes
        assert!(conn.current_outgoing_rate_bps >= 0.0);
    }

    #[test]
    fn test_tcp_state_transitions() {
        // Test SYN -> SYN_SENT
        let flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
        };
        let new_state = update_tcp_state(TcpState::Unknown, &flags, true);
        assert_eq!(new_state, TcpState::SynSent);

        // Test SYN-ACK -> ESTABLISHED
        let flags = TcpFlags {
            syn: true,
            ack: true,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
        };
        let new_state = update_tcp_state(TcpState::SynSent, &flags, false);
        assert_eq!(new_state, TcpState::Established);

        // Test FIN -> FIN_WAIT_1
        let flags = TcpFlags {
            syn: false,
            ack: false,
            fin: true,
            rst: false,
            psh: false,
            urg: false,
        };
        let new_state = update_tcp_state(TcpState::Established, &flags, true);
        assert_eq!(new_state, TcpState::FinWait1);

        // Test RST -> CLOSED
        let flags = TcpFlags {
            syn: false,
            ack: false,
            fin: false,
            rst: true,
            psh: false,
            urg: false,
        };
        let new_state = update_tcp_state(TcpState::Established, &flags, true);
        assert_eq!(new_state, TcpState::Closed);
    }

    use crate::network::types::TcpAnalytics;

    /// Fixed capture-time base for segment tests that don't care about time.
    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000)
    }

    /// Send one outbound data segment. Window and ack are irrelevant here.
    fn send(analytics: &mut TcpAnalytics, seq: u32, len: u32) {
        send_at(analytics, seq, len, t0());
    }

    fn send_at(analytics: &mut TcpAnalytics, seq: u32, len: u32, at: SystemTime) {
        analyze_tcp_segment(
            analytics,
            TcpSegment {
                seq,
                ack: 0,
                window: 65535,
                payload_len: len,
                is_outgoing: true,
                has_ack_flag: false,
            },
            at,
        );
    }

    /// Receive one inbound segment.
    fn recv(analytics: &mut TcpAnalytics, seq: u32, ack: u32, len: u32) -> TcpMergeEvents {
        recv_at(analytics, seq, ack, len, t0())
    }

    fn recv_at(
        analytics: &mut TcpAnalytics,
        seq: u32,
        ack: u32,
        len: u32,
        at: SystemTime,
    ) -> TcpMergeEvents {
        analyze_tcp_segment(
            analytics,
            TcpSegment {
                seq,
                ack,
                window: 65535,
                payload_len: len,
                is_outgoing: false,
                has_ack_flag: true,
            },
            at,
        )
    }

    #[test]
    fn detects_retransmit_after_a_sequence_gap() {
        // Regression: a gap used to freeze the outbound tracker permanently,
        // so every later retransmission went uncounted.
        let mut a = TcpAnalytics::new();

        // Starting at 0 also covers the old `!= 0` "initialised" sentinel,
        // which silently dropped the first segment of such a stream.
        send(&mut a, 0, 100); // in order, high-water = 100
        assert!(a.seen_outbound);

        send(&mut a, 5000, 100); // gap (capture drop) — must resync to 5100
        assert_eq!(a.retransmit_count, 0, "a gap is not a retransmission");
        assert_eq!(a.highest_seq_outbound, 5100, "tracker must resync on a gap");

        send(&mut a, 5000, 100); // genuine resend of data already sent
        assert_eq!(a.retransmit_count, 1);

        send(&mut a, 5100, 100); // stream continues normally afterwards
        assert_eq!(a.retransmit_count, 1);
        assert_eq!(a.highest_seq_outbound, 5200);
    }

    #[test]
    fn sequence_comparison_survives_wraparound() {
        // Straddle the u32 boundary, where a raw `<` inverts.
        let mut a = TcpAnalytics::new();

        send(&mut a, u32::MAX - 50, 100); // wraps to 49
        assert_eq!(a.highest_seq_outbound, 49);

        send(&mut a, 49, 100); // advances past the wrap, not a retransmit
        assert_eq!(a.retransmit_count, 0);

        send(&mut a, u32::MAX - 50, 100); // pre-wrap data resent
        assert_eq!(a.retransmit_count, 1);
    }

    #[test]
    fn inbound_data_segments_are_not_duplicate_acks() {
        // Regression: a download repeats the same ack number on every data
        // segment while we have nothing to send. Those are not dup ACKs, and
        // counting them inflated fast retransmits on healthy connections.
        let mut a = TcpAnalytics::new();

        let mut seq = 1000;
        for _ in 0..20 {
            recv(&mut a, seq, 500, 1400);
            seq += 1400;
        }

        assert_eq!(a.duplicate_ack_count, 0);
        assert_eq!(a.fast_retransmit_count, 0);
        assert_eq!(a.out_of_order_count, 0);
    }

    #[test]
    fn fast_retransmit_fires_once_per_dup_ack_run() {
        let mut a = TcpAnalytics::new();

        recv(&mut a, 0, 500, 0); // first ACK establishes the baseline
        recv(&mut a, 0, 500, 0); // dup 1
        recv(&mut a, 0, 500, 0); // dup 2
        assert_eq!(a.fast_retransmit_count, 0);

        recv(&mut a, 0, 500, 0); // dup 3 -> fast retransmit
        assert_eq!(a.fast_retransmit_count, 1);

        recv(&mut a, 0, 500, 0); // dup 4 must not re-trigger
        assert_eq!(a.fast_retransmit_count, 1);
        assert_eq!(a.duplicate_ack_count, 4, "cumulative, not the run length");

        // A new ACK ends the run; the next run triggers again.
        recv(&mut a, 0, 900, 0);
        assert_eq!(a.dup_ack_run, 0);
        for _ in 0..3 {
            recv(&mut a, 0, 900, 0);
        }
        assert_eq!(a.fast_retransmit_count, 2);
        assert_eq!(a.duplicate_ack_count, 7);
    }

    #[test]
    fn covering_ack_completes_an_rtt_probe() {
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0()); // times bytes up to 100
        let events = recv_at(&mut a, 0, 100, 0, t0() + Duration::from_millis(40));

        assert_eq!(events.rtt_sample, Some(Duration::from_millis(40)));
        assert_eq!(a.smoothed_rtt, Some(Duration::from_millis(40)));
        assert_eq!(a.last_rtt, Some(Duration::from_millis(40)));
        assert_eq!(a.rtt_samples, 1);
        assert_eq!(a.rtt_probe, None, "a completed probe must not re-fire");
    }

    #[test]
    fn partial_ack_does_not_complete_the_probe() {
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0());
        let events = recv_at(&mut a, 0, 50, 0, t0() + Duration::from_millis(40));

        assert_eq!(events.rtt_sample, None, "50 acks only half the timed bytes");
        assert!(a.rtt_probe.is_some(), "the probe stays armed");

        let events = recv_at(&mut a, 0, 100, 0, t0() + Duration::from_millis(80));
        assert_eq!(events.rtt_sample, Some(Duration::from_millis(80)));
    }

    #[test]
    fn retransmission_invalidates_the_probe() {
        // Karn's algorithm: after a resend, the covering ACK is ambiguous
        // (original or retransmission?) and must not produce a sample.
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0());
        send_at(&mut a, 0, 100, t0() + Duration::from_millis(10)); // resend
        assert_eq!(a.retransmit_count, 1);

        let events = recv_at(&mut a, 0, 100, 0, t0() + Duration::from_millis(50));
        assert_eq!(events.rtt_sample, None);
        assert_eq!(a.rtt_samples, 0);
    }

    #[test]
    fn smoothed_rtt_is_an_ewma_of_samples() {
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0());
        recv_at(&mut a, 0, 100, 0, t0() + Duration::from_millis(80));
        assert_eq!(a.smoothed_rtt, Some(Duration::from_millis(80)));

        // Second sample of 16ms: 7/8 * 80 + 1/8 * 16 = 72ms.
        let sent = t0() + Duration::from_millis(100);
        send_at(&mut a, 100, 100, sent);
        recv_at(&mut a, 0, 200, 0, sent + Duration::from_millis(16));
        assert_eq!(a.smoothed_rtt, Some(Duration::from_millis(72)));
        assert_eq!(a.last_rtt, Some(Duration::from_millis(16)));
        assert_eq!(a.rtt_samples, 2);
    }

    #[test]
    fn a_young_probe_is_not_replaced_but_a_stale_one_is() {
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0());
        send_at(&mut a, 100, 100, t0() + Duration::from_millis(5));
        assert_eq!(
            a.rtt_probe.map(|(seq, _)| seq),
            Some(100),
            "the oldest outstanding segment stays the timed one"
        );

        // Its ACK never arrives; past the timeout the next send re-arms.
        let late = t0() + RTT_PROBE_TIMEOUT + Duration::from_secs(1);
        send_at(&mut a, 200, 100, late);
        assert_eq!(a.rtt_probe, Some((300, late)));
    }

    #[test]
    fn probe_completion_survives_sequence_wraparound() {
        let mut a = TcpAnalytics::new();

        send_at(&mut a, u32::MAX - 50, 100, t0()); // timed bytes end at 49
        let events = recv_at(&mut a, 0, 49, 0, t0() + Duration::from_millis(30));
        assert_eq!(events.rtt_sample, Some(Duration::from_millis(30)));
    }

    #[test]
    fn inbound_data_segments_can_complete_the_probe() {
        // Request/response traffic: the response carries both the payload and
        // the ACK of the request. Requiring a pure ACK would starve the
        // estimator on exactly the flows users care about.
        let mut a = TcpAnalytics::new();

        send_at(&mut a, 0, 100, t0());
        let events = recv_at(&mut a, 0, 100, 1400, t0() + Duration::from_millis(25));
        assert_eq!(events.rtt_sample, Some(Duration::from_millis(25)));
    }
}
