//! Parse sockstat's numeric socket inventory independently of FreeBSD system calls.

use crate::{
    ConnectionKey, HostSocket, HostSocketState, HostTcpState, Protocol, SocketOwner, SocketScan,
    parse_socket_addr_text, remote_if_present,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) fn parse_output(stdout: &str, protocol: Protocol) -> SocketScan {
    let mut scan = SocketScan::default();

    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();

        // Expected format:
        // USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
        // 1001     sshd       1234  3  tcp4   192.168.1.1:22        192.168.1.2:54321

        if parts.len() < 7 {
            continue;
        }

        let uid = parts[0].parse::<u32>().ok();
        let process_name = parts[1].to_string();
        let pid = parts[2].parse::<u32>().ok();

        // sockstat prints `*` for both families, including dual-stack tcp46/udp46.
        let wildcard = if parts[4].ends_with('6') {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let (Some(local_addr), Some(foreign_addr)) = (
            parse_socket_addr_text(parts[5], wildcard),
            parse_socket_addr_text(parts[6], wildcard),
        ) else {
            continue;
        };
        if protocol == Protocol::Udp && local_addr.port() == 0 {
            continue;
        }

        let key = ConnectionKey {
            protocol,
            local_addr,
            remote_addr: foreign_addr,
        };

        let owner = pid.zip(uid).map(|(pid, uid)| SocketOwner {
            pid,
            name: process_name.clone(),
            uid: Some(uid),
        });
        if let Some(owner) = &owner {
            scan.lookup.insert(key, owner.clone());
        }

        let state = match protocol {
            Protocol::Tcp => HostSocketState::Tcp(parts.get(7).map_or_else(
                || infer_tcp_state(foreign_addr),
                |value| HostTcpState::parse_name(value),
            )),
            Protocol::Udp => HostSocketState::UdpBound,
            _ => continue,
        };
        scan.sockets.push(HostSocket {
            protocol,
            local_addr,
            remote_addr: remote_if_present(foreign_addr),
            state,
            owner,
            native_id: None,
        });
    }

    scan
}

fn infer_tcp_state(remote_addr: std::net::SocketAddr) -> HostTcpState {
    if remote_addr.port() == 0 && remote_addr.ip().is_unspecified() {
        HostTcpState::Listen
    } else {
        HostTcpState::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalPortStatus, SocketSnapshot};

    #[test]
    fn wildcard_inventory_preserves_family_for_port_status() {
        use LocalPortStatus::{Closed, Opened, Unknown};

        for (family, expected_v4, expected_v6) in [
            ("4", Opened, Closed),
            ("6", Unknown, Opened),
            ("46", Unknown, Opened),
        ] {
            for (protocol, name, state) in [
                (Protocol::Tcp, "tcp", " LISTEN"),
                (Protocol::Tcp, "tcp", ""),
                (Protocol::Udp, "udp", ""),
            ] {
                let output = format!(
                    "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS STATE\n\
                     1001 server 42 3 {name}{family} *:8080 *:*{state}\n"
                );
                let scan = parse_output(&output, protocol);
                assert_eq!(scan.sockets.len(), 1);
                assert_eq!(scan.lookup.len(), 1);
                let socket = &scan.sockets[0];
                let wildcard = if family == "4" {
                    "0.0.0.0:8080"
                } else {
                    "[::]:8080"
                };
                assert_eq!(socket.local_addr, wildcard.parse().unwrap());
                assert!(socket.remote_addr.is_none());
                let key = scan.lookup.keys().next().unwrap();
                assert_eq!(key.local_addr, socket.local_addr);
                assert_eq!(key.remote_addr.is_ipv6(), family != "4");

                let snapshot = SocketSnapshot::new(scan.sockets);
                for (addr, expected) in [
                    ("192.0.2.1:8080", expected_v4),
                    ("[2001:db8::1]:8080", expected_v6),
                ] {
                    assert_eq!(
                        snapshot.local_port_status(protocol, addr.parse().unwrap()),
                        expected,
                        "{name}{family} {addr}{state}"
                    );
                }
            }
        }
    }

    #[test]
    fn sockstat_parser_requires_numeric_uid_enabled_by_dash_n() {
        let output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
root server 42 3 tcp4 127.0.0.1:8080 0.0.0.0:0
";

        assert!(parse_output(output, Protocol::Tcp).lookup.is_empty());
    }

    #[test]
    fn sockstat_parser_reports_tcp_listeners_and_udp_binds() {
        // sockstat prints a wildcard peer as `*:*`, never `0.0.0.0:0`.
        let tcp_output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS STATE
1001 server 42 3 tcp4 *:8080 *:* LISTEN
";
        let udp_output = "\
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
1001 resolver 43 4 udp4 127.0.0.1:5353 *:*
";

        let tcp = parse_output(tcp_output, Protocol::Tcp);
        let udp = parse_output(udp_output, Protocol::Udp);

        assert_eq!(tcp.sockets.len(), 1);
        assert_eq!(
            tcp.sockets[0].state,
            HostSocketState::Tcp(HostTcpState::Listen)
        );
        assert_eq!(tcp.sockets[0].local_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(tcp.sockets[0].remote_addr, None);
        assert_eq!(udp.sockets.len(), 1);
        assert_eq!(udp.sockets[0].state, HostSocketState::UdpBound);
        assert_eq!(udp.sockets[0].remote_addr, None);
    }
}
