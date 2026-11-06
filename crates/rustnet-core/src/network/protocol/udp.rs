//! UDP (User Datagram Protocol) parsing

use crate::network::dpi;
use crate::network::parser::{ParsedPacket, ParserConfig};
use crate::network::protocol::{TransportParams, orient_endpoints};
use crate::network::types::{ApplicationProtocol, Protocol, ProtocolState};

/// Parse a UDP packet
pub fn parse(
    transport_data: &[u8],
    params: TransportParams,
    config: &ParserConfig,
    local_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> Option<ParsedPacket> {
    if transport_data.len() < 8 {
        return None;
    }

    let src_port = u16::from_be_bytes([transport_data[0], transport_data[1]]);
    let dst_port = u16::from_be_bytes([transport_data[2], transport_data[3]]);

    let (mut local_addr, mut remote_addr, mut is_outgoing) =
        orient_endpoints(&params, src_port, dst_port, local_ips);

    let dpi_result = if config.enable_dpi && transport_data.len() > 8 {
        let payload = &transport_data[8..];
        dpi::analyze_udp_packet(payload, local_addr.port(), remote_addr.port(), is_outgoing)
    } else {
        None
    };

    // Both endpoints of a local stub exchange can be local addresses. Orient
    // DNS replies toward the client so they match the query and its timer.
    if params.src_ip.is_loopback()
        && params.dst_ip.is_loopback()
        && let Some(result) = &dpi_result
        && let ApplicationProtocol::Dns(info) = &result.application
    {
        let source = std::net::SocketAddr::new(params.src_ip, src_port);
        let destination = std::net::SocketAddr::new(params.dst_ip, dst_port);
        (local_addr, remote_addr, is_outgoing) = if info.is_response {
            (destination, source, false)
        } else {
            (source, destination, true)
        };
    }

    let mut packet = ParsedPacket::new(
        Protocol::Udp,
        local_addr,
        remote_addr,
        ProtocolState::Udp,
        is_outgoing,
        params.packet_len,
        params.process_name,
        params.process_id,
    );
    packet.dpi_result = dpi_result;
    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::tracker::ConnectionTracker;
    use std::{
        collections::HashSet,
        net::IpAddr,
        time::{Duration, SystemTime},
    };

    fn dns_packet(
        source: IpAddr,
        destination: IpAddr,
        response: bool,
        local_ips: &HashSet<IpAddr>,
    ) -> ParsedPacket {
        let (source_port, destination_port): (u16, u16) =
            if response { (53, 53000) } else { (53000, 53) };
        let mut udp = Vec::from(source_port.to_be_bytes());
        udp.extend(destination_port.to_be_bytes());
        udp.extend([0, 27, 0, 0]);
        udp.extend([
            0,
            7,
            if response { 0x81 } else { 0x01 },
            0x80,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ]);
        udp.extend([1, b'a', 0, 0, 1, 0, 1]);
        parse(
            &udp,
            TransportParams::new(source, destination, udp.len(), None, None),
            &ParserConfig::default(),
            local_ips,
        )
        .unwrap()
    }

    #[test]
    fn loopback_dns_matches_client_flow_for_ipv4_ipv6_and_aliases() {
        for (client, server) in [
            ("127.0.0.1", "127.0.0.1"),
            ("127.0.0.1", "127.0.0.53"),
            ("127.0.0.2", "127.0.0.53"),
            ("::1", "::1"),
        ] {
            let client: IpAddr = client.parse().unwrap();
            let server: IpAddr = server.parse().unwrap();
            let local_ips = ["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()]
                .into_iter()
                .collect();
            let query = dns_packet(client, server, false, &local_ips);
            let reply = dns_packet(server, client, true, &local_ips);
            assert!(query.is_outgoing);
            assert!(!reply.is_outgoing);
            assert_eq!(query.connection_key(), reply.connection_key());
            let tracker = ConnectionTracker::new();
            let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
            tracker.ingest_at(&query, at);
            let outcome = tracker.ingest_at(&reply, at + Duration::from_millis(20));
            let response_time = tracker
                .connections()
                .get(&outcome.key)
                .unwrap()
                .dns_response_time;
            assert_eq!(response_time, Some(Duration::from_millis(20)));
            let snapshot = tracker.dns_analytics_snapshot_at(at + Duration::from_secs(11));
            assert_eq!(snapshot.answered, 1);
            assert_eq!(snapshot.timeouts, 0);
            assert_eq!(snapshot.resolvers[0].address.ip(), server);
        }
    }

    #[test]
    fn serving_remote_dns_clients_does_not_count_as_host_lookups() {
        let server: IpAddr = "192.0.2.53".parse().unwrap();
        let client: IpAddr = "192.0.2.10".parse().unwrap();
        let local_ips = [server].into_iter().collect();
        let query = dns_packet(client, server, false, &local_ips);
        let reply = dns_packet(server, client, true, &local_ips);
        assert!(!query.is_outgoing);
        assert!(reply.is_outgoing);
        let tracker = ConnectionTracker::new();
        tracker.ingest_at(&query, SystemTime::UNIX_EPOCH);
        tracker.ingest_at(&reply, SystemTime::UNIX_EPOCH + Duration::from_millis(20));
        assert_eq!(
            tracker
                .dns_analytics_snapshot_at(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
                .lookups,
            0
        );
    }
}
