// network/merge.rs - Connection merging and update utilities
use crate::network::dpi::DpiResult;
use crate::network::parser::ParsedPacket;
use crate::network::types::{Connection, DpiInfo, RateInfo};
use std::time::{Instant, SystemTime};

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
    conn.protocol_state = parsed.state;

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
        parsed.state,
    );

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

/// Enrich connection with process information
#[allow(dead_code)]
pub fn enrich_with_process_info(
    mut conn: Connection,
    pid: u32,
    process_name: String,
) -> Connection {
    conn.pid = Some(pid);
    conn.process_name = Some(process_name);
    conn
}

/// Enrich connection with service name
#[allow(dead_code)]
pub fn enrich_with_service_name(mut conn: Connection, service_name: String) -> Connection {
    conn.service_name = Some(service_name);
    conn
}

/// Update connection rates based on current stats
#[allow(dead_code)]
pub fn update_connection_rates(mut conn: Connection, now: Instant) -> Connection {
    let elapsed = now
        .duration_since(conn.current_rate_bps.last_calculation)
        .as_secs_f64();

    if elapsed > 0.1 {
        // Update at most every 100ms
        conn.current_rate_bps = RateInfo {
            outgoing_bps: (conn.bytes_sent as f64 * 8.0) / elapsed,
            incoming_bps: (conn.bytes_received as f64 * 8.0) / elapsed,
            last_calculation: now,
        };

        // Update backward compatibility fields
        conn.current_incoming_rate_bps = conn.current_rate_bps.incoming_bps;
        conn.current_outgoing_rate_bps = conn.current_rate_bps.outgoing_bps;
    }

    conn
}

/// Merge two connections (useful for combining data from different sources)
#[allow(dead_code)]
pub fn merge_connections(mut primary: Connection, secondary: &Connection) -> Connection {
    // Use secondary's process info if primary doesn't have it
    if primary.pid.is_none() && secondary.pid.is_some() {
        primary.pid = secondary.pid;
        primary.process_name = secondary.process_name.clone();
    }

    // Use secondary's service name if primary doesn't have it
    if primary.service_name.is_none() && secondary.service_name.is_some() {
        primary.service_name = secondary.service_name.clone();
    }

    // Merge traffic stats (take the maximum)
    primary.bytes_sent = primary.bytes_sent.max(secondary.bytes_sent);
    primary.bytes_received = primary.bytes_received.max(secondary.bytes_received);
    primary.packets_sent = primary.packets_sent.max(secondary.packets_sent);
    primary.packets_received = primary.packets_received.max(secondary.packets_received);

    // Use the earlier creation time
    if secondary.created_at < primary.created_at {
        primary.created_at = secondary.created_at;
    }

    // Use the later last activity time
    if secondary.last_activity > primary.last_activity {
        primary.last_activity = secondary.last_activity;
    }

    // Merge DPI info (prefer more specific)
    if let Some(secondary_dpi) = &secondary.dpi_info {
        match &primary.dpi_info {
            None => primary.dpi_info = Some(secondary_dpi.clone()),
            Some(_) => {}
        }
    }

    primary
}

/// Check if two connections represent the same flow
#[allow(dead_code)]
pub fn connections_match(a: &Connection, b: &Connection) -> bool {
    a.protocol == b.protocol && a.local_addr == b.local_addr && a.remote_addr == b.remote_addr
}

/// Check if a connection matches a parsed packet
#[allow(dead_code)]
pub fn connection_matches_packet(conn: &Connection, parsed: &ParsedPacket) -> bool {
    conn.protocol == parsed.protocol
        && conn.local_addr == parsed.local_addr
        && conn.remote_addr == parsed.remote_addr
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
            state: ProtocolState::Tcp(TcpState::Established),
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

    #[test]
    fn test_enrich_with_process_info() {
        let conn = create_test_connection();
        let enriched = enrich_with_process_info(conn, 1234, "firefox".to_string());

        assert_eq!(enriched.pid, Some(1234));
        assert_eq!(enriched.process_name, Some("firefox".to_string()));
    }

    #[test]
    fn test_merge_connections() {
        let mut primary = create_test_connection();
        primary.bytes_sent = 1000;

        let mut secondary = create_test_connection();
        secondary.pid = Some(5678);
        secondary.process_name = Some("chrome".to_string());
        secondary.bytes_sent = 2000;

        let merged = merge_connections(primary, &secondary);

        assert_eq!(merged.pid, Some(5678));
        assert_eq!(merged.process_name, Some("chrome".to_string()));
        assert_eq!(merged.bytes_sent, 2000); // Takes the maximum
    }

    #[test]
    fn test_connections_match() {
        let conn1 = create_test_connection();
        let conn2 = create_test_connection();

        assert!(connections_match(&conn1, &conn2));

        let mut conn3 = create_test_connection();
        conn3.local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)), 12345);

        assert!(!connections_match(&conn1, &conn3));
    }
}
