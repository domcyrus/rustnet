//! Parse lsof's numeric socket inventory independently of macOS system calls.

use crate::{
    ConnectionKey, HostSocket, HostSocketState, HostTcpState, Protocol, SocketOwner, SocketScan,
    parse_socket_addr_text, remote_if_present,
};
use rustnet_core::network::util::normalize_process_name;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub(crate) fn parse_output(stdout: &str) -> SocketScan {
    let mut scan = SocketScan {
        complete: stdout.lines().next().is_some_and(|header| {
            header.split_whitespace().collect::<Vec<_>>()
                == [
                    "COMMAND", "PID", "USER", "FD", "TYPE", "DEVICE", "SIZE/OFF", "NODE", "NAME",
                ]
        }),
        ..Default::default()
    };
    for line in stdout.lines().skip(1) {
        let parts: Vec<_> = line.split_whitespace().collect();
        // COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
        if parts.len() < 9 {
            scan.complete = false;
            continue;
        }
        let wildcard = match parts[4] {
            "IPv4" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "IPv6" => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            _ => {
                scan.complete = false;
                continue;
            }
        };
        let protocol = match parts[7] {
            "TCP" => Protocol::Tcp,
            "UDP" => Protocol::Udp,
            _ => {
                scan.complete = false;
                continue;
            }
        };
        let (Ok(pid), Ok(uid)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) else {
            scan.complete = false;
            continue;
        };
        let Some((local, remote)) = parse_connection(parts[8], wildcard) else {
            scan.complete = false;
            continue;
        };
        if protocol == Protocol::Udp && local.port() == 0 {
            continue;
        }

        let owner = SocketOwner {
            pid,
            name: normalize_process_name(&decode_lsof_string(parts[0])),
            uid: Some(uid),
        };
        scan.lookup.insert(
            ConnectionKey {
                protocol,
                local_addr: local,
                remote_addr: remote,
            },
            owner.clone(),
        );
        let state = if protocol == Protocol::Tcp {
            let state = parts.get(9).copied().unwrap_or("");
            HostSocketState::Tcp(HostTcpState::parse_name(state.trim_matches(['(', ')'])))
        } else {
            HostSocketState::UdpBound
        };
        let socket = HostSocket {
            protocol,
            local_addr: local,
            remote_addr: remote_if_present(remote),
            state,
            owner: Some(owner),
            native_id: parts[5]
                .strip_prefix("0x")
                .and_then(|hex| u64::from_str_radix(hex, 16).ok()),
        };
        // -Tqs supplies byte queues beside state. Missing or malformed fields
        // disable only measurements, never inventory or ownership.
        if protocol == Protocol::Tcp
            && state != HostSocketState::Tcp(HostTcpState::Listen)
            && let Some(native_id) = socket.native_id.filter(|id| *id != 0)
            && let (Some(receive), Some(send)) =
                (queue_value(&parts, "QR="), queue_value(&parts, "QS="))
        {
            use rustnet_core::network::types::{QueueKind, QueueSample, SocketSample};
            scan.diagnostics.insert(
                socket.clone(),
                std::sync::Arc::new(SocketSample {
                    native_id,
                    netns: None,
                    tcp: None,
                    queues: Some(QueueSample {
                        source: "lsof",
                        sampled_at: std::time::SystemTime::now(),
                        kind: QueueKind::TcpBytes,
                        receive,
                        send,
                        socket_drops: None,
                    }),
                }),
            );
        }
        scan.sockets.push(socket);
    }
    scan
}

fn queue_value(parts: &[&str], prefix: &str) -> Option<u64> {
    let mut values = parts
        .iter()
        .skip(9)
        .filter_map(|value| value.trim_matches(['(', ')']).strip_prefix(prefix));
    let value = values.next()?.parse().ok()?;
    values.next().is_none().then_some(value)
}

fn parse_connection(name: &str, wildcard: IpAddr) -> Option<(SocketAddr, SocketAddr)> {
    let parse_addr = |text| parse_socket_addr_text(text, wildcard);
    if let Some((local, remote)) = name.split_once("->") {
        Some((parse_addr(local)?, parse_addr(remote)?))
    } else {
        Some((parse_addr(name)?, SocketAddr::new(wildcard, 0)))
    }
}

/// Decode lsof escape sequences like `\x20` back to regular characters.
fn decode_lsof_string(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' && chars.peek() == Some(&'x') {
            chars.next();

            let hex_digits: String = chars.by_ref().take(2).collect();
            if hex_digits.len() == 2
                && let Ok(byte_val) = u8::from_str_radix(&hex_digits, 16)
                && let Some(decoded_char) = std::char::from_u32(byte_val as u32)
            {
                result.push(decoded_char);
                continue;
            }

            result.push('\\');
            result.push('x');
            result.push_str(&hex_digits);
        } else {
            result.push(ch);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalPortStatus, SocketSnapshot};

    #[test]
    fn optional_byte_queues_preserve_state_and_reject_incomplete_values() {
        for (fields, expected) in [
            ("QR=8192 QS=0", Some(8192)),
            ("QR=0 QS=0", Some(0)),
            ("QR=bad QS=0", None),
            ("QR=1", None),
            ("QR=1 QR=2 QS=0", None),
        ] {
            let scan = parse_output(&format!(
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nclient 42 1000 3u IPv4 0xabc 0t0 TCP 127.0.0.1:5000->127.0.0.1:8080 (ESTABLISHED {fields})\n"
            ));
            assert!(scan.complete);
            assert_eq!(
                scan.sockets[0].state,
                HostSocketState::Tcp(HostTcpState::Established)
            );
            assert_eq!(
                scan.diagnostics
                    .values()
                    .next()
                    .and_then(|s| s.queues.as_ref())
                    .map(|q| q.receive),
                expected
            );
        }
        let scan = parse_output(
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nserver 42 1000 3u IPv4 0xabc 0t0 TCP *:8080 (LISTEN QR=1 QS=2)\n",
        );
        assert!(scan.diagnostics.is_empty());
    }

    #[test]
    fn wildcard_inventory_preserves_family_for_port_status() {
        use LocalPortStatus::{Closed, Opened, Unknown};

        for (family, protocol, expected_v4, expected_v6) in [
            ("IPv4", "TCP", Opened, Closed),
            ("IPv6", "TCP", Unknown, Opened),
            ("IPv4", "UDP", Opened, Closed),
            ("IPv6", "UDP", Unknown, Opened),
        ] {
            let state = if protocol == "TCP" { " (LISTEN)" } else { "" };
            let output = format!(
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                 server 42 1000 3u {family} 0x1 0t0 {protocol} *:8080{state}\n"
            );
            let scan = parse_output(&output);
            assert_eq!(scan.lookup.len(), 1);
            assert_eq!(scan.sockets.len(), 1);
            let socket = &scan.sockets[0];
            let protocol = socket.protocol;
            let wildcard = if family == "IPv6" {
                "[::]:8080"
            } else {
                "0.0.0.0:8080"
            };
            assert_eq!(socket.local_addr, wildcard.parse().unwrap());
            assert!(socket.remote_addr.is_none());
            let key = scan.lookup.keys().next().unwrap();
            assert_eq!(key.local_addr, socket.local_addr);
            assert_eq!(key.remote_addr.is_ipv6(), family == "IPv6");

            let snapshot = SocketSnapshot::new(scan.sockets);
            for (addr, expected) in [
                ("192.0.2.1:8080", expected_v4),
                ("[2001:db8::1]:8080", expected_v6),
            ] {
                assert_eq!(
                    snapshot.local_port_status(protocol, addr.parse().unwrap()),
                    expected,
                    "{family} {protocol} {addr}"
                );
            }
        }
    }

    #[test]
    fn connected_and_malformed_rows_keep_their_protocol_and_endpoints() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
client\\x20helper 42 1000 3u IPv6 0xabc 0t0 TCP [::1]:5000->[::1]:8080 (ESTABLISHED)
resolver 43 1000 4u IPv4 0x2 0t0 UDP 192.0.2.1:5001->192.0.2.2:53
short 44 1000 5u IPv4 0x3 0t0 TCP
invalid 45 1000 6u IPv6 0x4 0t0 TCP *:99999 (LISTEN)
invalid 46 1000 7u IPv4 0x5 0t0 TCP *:80->*:81->*:82 (ESTABLISHED)
unsupported 47 1000 8u IPv4 0x6 0t0 ICMP *:80
";
        let scan = parse_output(output);
        assert_eq!(scan.sockets.len(), 2);
        assert_eq!(scan.lookup.len(), 2);
        let tcp = &scan.sockets[0];
        assert_eq!(tcp.local_addr, "[::1]:5000".parse().unwrap());
        assert_eq!(tcp.remote_addr, Some("[::1]:8080".parse().unwrap()));
        assert_eq!(tcp.state, HostSocketState::Tcp(HostTcpState::Established));
        assert_eq!(tcp.native_id, Some(0xabc));
        assert_eq!(tcp.owner.as_ref().unwrap().name, "client helper");
        let udp = &scan.sockets[1];
        assert_eq!(udp.protocol, Protocol::Udp);
        assert_eq!(udp.remote_addr, Some("192.0.2.2:53".parse().unwrap()));
        assert_eq!(udp.state, HostSocketState::UdpBound);
        let snapshot = SocketSnapshot::new(scan.sockets);
        assert_eq!(
            snapshot.local_port_status(Protocol::Tcp, "[::1]:5000".parse().unwrap()),
            LocalPortStatus::Closed
        );
    }

    #[test]
    fn lsof_parser_requires_the_numeric_uid_enabled_by_dash_l() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 42 root 3u IPv4 0x1 0t0 TCP 127.0.0.1:8080 (LISTEN)
";

        assert!(parse_output(output).lookup.is_empty());
    }

    #[test]
    fn lsof_parser_reports_tcp_listeners_and_udp_binds() {
        let output = "\
COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
server 42 1000 3u IPv4 0x1 0t0 TCP *:8080 (LISTEN)
resolver 43 1000 4u IPv6 0x2 0t0 UDP [::1]:5353
client 44 1000 5u IPv4 0x3 0t0 UDP *:0 (Unbound)
";

        let scan = parse_output(output);

        assert_eq!(scan.sockets.len(), 2);
        assert_eq!(
            scan.sockets[0].state,
            HostSocketState::Tcp(HostTcpState::Listen)
        );
        assert_eq!(scan.sockets[1].state, HostSocketState::UdpBound);
        assert_eq!(scan.sockets[0].owner.as_ref().unwrap().pid, 42);
    }

    #[test]
    fn test_decode_lsof_string() {
        assert_eq!(
            decode_lsof_string("Microsoft\\x20Teams\\x20WebView\\x20Helper"),
            "Microsoft Teams WebView Helper"
        );

        assert_eq!(decode_lsof_string("Brave\\x20Browser"), "Brave Browser");

        assert_eq!(decode_lsof_string("firefox"), "firefox");

        assert_eq!(decode_lsof_string("App\\x20Name"), "App Name");

        assert_eq!(decode_lsof_string(""), "");

        assert_eq!(decode_lsof_string("launchd"), "launchd");

        // Malformed escape sequences are preserved.
        assert_eq!(
            decode_lsof_string("App\\x2G"),
            "App\\x2G" // Invalid hex
        );

        assert_eq!(
            decode_lsof_string("App\\x2"),
            "App\\x2" // Incomplete escape at the end
        );

        assert_eq!(
            decode_lsof_string("Test\\x20App\\x2D\\x2EExe"),
            "Test App-.Exe" // \x20 = space, \x2D = hyphen, \x2E = period
        );

        assert_eq!(
            decode_lsof_string("App\\Normal"),
            "App\\Normal" // Non-escape backslashes are preserved
        );
    }

    #[test]
    fn socket_scan_requires_a_valid_header_and_every_row() {
        let valid = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nbrowser 42 501 7u IPv6 0x1 0t0 UDP *:45000\n";
        let scan = parse_output(valid);
        assert!(scan.complete);
        assert_eq!(scan.sockets[0].local_addr, "[::]:45000".parse().unwrap());
        assert!(scan.sockets[0].remote_addr.is_none());
        for (local, remote) in [
            ("192.0.2.1:45000", "198.51.100.1:443"),
            ("[2001:db8::1]:45000", "[2001:db8::2]:443"),
        ] {
            let key = crate::test_support::connection_key(Protocol::Udp, local, remote);
            let (owner, quality) = crate::owner_match(&scan.lookup, &key).unwrap();
            assert_eq!(owner.pid, 42);
            assert_eq!(quality, crate::MatchQuality::ListenerSocket);
        }
        for invalid in [
            "".to_owned(),
            format!("{valid}malformed row\n"),
            valid.replace(
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME",
                "unexpected header",
            ),
        ] {
            let scan = parse_output(&invalid);
            assert!(!scan.complete);
            let snapshot = SocketSnapshot::from_inventory(scan.sockets, scan.complete);
            assert_eq!(
                snapshot.local_port_status(Protocol::Udp, "[::1]:45000".parse().unwrap()),
                LocalPortStatus::Unknown
            );
            assert!(snapshot.closure_scan_started.is_none());
        }
        let empty = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n";
        assert!(parse_output(empty).complete);
    }
}
