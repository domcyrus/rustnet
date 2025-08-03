use log::{debug, warn};

// network/merge.rs - Connection merging and update utilities
use crate::network::dpi::DpiResult;
use crate::network::parser::{ParsedPacket, TcpFlags};
use crate::network::types::{Connection, DpiInfo, ProtocolState, RateInfo, TcpState};
use std::time::{Instant, SystemTime};

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

        (TcpState::Listen, true, false, false, false) if !is_outgoing => TcpState::SynReceived,
        (TcpState::Listen, true, false, false, false) if is_outgoing => TcpState::SynSent,
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

/// Merge a parsed packet into an existing connection
pub fn merge_packet_into_connection(
    mut conn: Connection,
    parsed: &ParsedPacket,
    now: SystemTime,
) -> Connection {
    // Update timing
    conn.last_activity = now;

    // Update packet counts and bytes
    if parsed.is_outgoing {
        conn.packets_sent += 1;
        conn.bytes_sent += parsed.packet_len as u64;
    } else {
        conn.packets_received += 1;
        conn.bytes_received += parsed.packet_len as u64;
    }

    // Update protocol state (from packet flags/state)
    if parsed.tcp_flags.is_some() {
        let current_tcp_state = match conn.protocol_state {
            ProtocolState::Tcp(state) => state,
            _ => {
                warn!("Merging packet into non-TCP connection, resetting to Unknown state");
                TcpState::Unknown // Default to unknown if not TCP
            }
        };
        let new_tcp_state = update_tcp_state(
            current_tcp_state,
            &parsed.tcp_flags.unwrap(),
            parsed.is_outgoing,
        );
        debug!(
            "Updated TCP state: {:?} -> {:?}",
            current_tcp_state, new_tcp_state
        );
        conn.protocol_state = ProtocolState::Tcp(new_tcp_state);
    } else {
        // If no TCP flags, assume UDP or other protocol state
        conn.protocol_state = parsed.protocol_state.clone();
    }

    // Update DPI info if available and better than what we have
    if let Some(dpi_result) = &parsed.dpi_result {
        merge_dpi_info(&mut conn, dpi_result);
    }

    conn
}

/// Create a new connection from a parsed packet
pub fn create_connection_from_packet(parsed: &ParsedPacket, now: SystemTime) -> Connection {
    let mut conn = Connection::new(
        parsed.protocol,
        parsed.local_addr,
        parsed.remote_addr,
        parsed.protocol_state.clone(),
    );

    if parsed.tcp_flags.is_some() {
        // If TCP, set initial state based on flags
        if let Some(tcp_flags) = &parsed.tcp_flags {
            let old_state = conn.protocol_state.clone();
            conn.protocol_state = ProtocolState::Tcp(update_tcp_state(
                TcpState::Unknown,
                tcp_flags,
                parsed.is_outgoing,
            ));
            debug!(
                "Created connection from packet: {:?} -> {:?}, old state: {:?}, new state: {:?}",
                parsed.local_addr, parsed.remote_addr, old_state, conn.protocol_state
            );
        } else {
            conn.protocol_state = ProtocolState::Tcp(TcpState::Unknown);
        }
    } else {
        // For non-TCP protocols, use the provided state directly
        conn.protocol_state = parsed.protocol_state.clone();
    }

    // Set initial stats based on packet direction
    if parsed.is_outgoing {
        conn.packets_sent = 1;
        conn.bytes_sent = parsed.packet_len as u64;
    } else {
        conn.packets_received = 1;
        conn.bytes_received = parsed.packet_len as u64;
    }

    // Apply DPI results if any
    if let Some(dpi_result) = &parsed.dpi_result {
        conn.dpi_info = Some(DpiInfo {
            application: dpi_result.application.clone(),
            first_packet_time: Instant::now(),
            last_update_time: Instant::now(),
        });
    }

    conn.created_at = now;
    conn.last_activity = now;

    conn
}

/// Merge DPI results into connection
fn merge_dpi_info(conn: &mut Connection, dpi_result: &DpiResult) {
    match &conn.dpi_info {
        None => {
            // No existing DPI info, use the new one
            conn.dpi_info = Some(DpiInfo {
                application: dpi_result.application.clone(),
                first_packet_time: Instant::now(),
                last_update_time: Instant::now(),
            });
        }
        // If we already have DPI info we don't want to overwrite it
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Protocol, ProtocolState, TcpState};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_connection() -> Connection {
        Connection::new(
            Protocol::TCP,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    fn create_test_packet(is_outgoing: bool) -> ParsedPacket {
        ParsedPacket {
            connection_key: "test".to_string(),
            protocol: Protocol::TCP,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80),
            protocol_state: ProtocolState::Tcp(TcpState::Unknown),
            tcp_flags: Some(TcpFlags {
                syn: false,
                ack: false,
                fin: true,
                rst: false,
                psh: false,
                urg: false,
            }),
            is_outgoing,
            packet_len: 100,
            dpi_result: None,
        }
    }

    #[test]
    fn test_merge_packet_into_connection() {
        let mut conn = create_test_connection();
        let packet = create_test_packet(true);

        conn = merge_packet_into_connection(conn, &packet, SystemTime::now());

        assert_eq!(conn.packets_sent, 1);
        assert_eq!(conn.bytes_sent, 100);
        assert_eq!(conn.packets_received, 0);
    }

    #[test]
    fn test_create_connection_from_packet() {
        let packet = create_test_packet(false);
        let conn = create_connection_from_packet(&packet, SystemTime::now());

        assert_eq!(conn.packets_received, 1);
        assert_eq!(conn.bytes_received, 100);
        assert_eq!(conn.packets_sent, 0);
    }
}
