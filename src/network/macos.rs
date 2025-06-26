use anyhow::Result;
use log::debug;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::process::Command;

use super::{Connection, ConnectionState, NetworkMonitor, Process, Protocol};

/// Get platform-specific connections for macOS
pub fn get_platform_connections(
    monitor: &NetworkMonitor,
    connections: &mut Vec<Connection>,
) -> Result<()> {
    // Try different commands to maximize connection detection
    // First try netstat - more reliable on macOS than lsof in some cases
    monitor.get_connections_from_netstat(connections)?;
    debug!("Found {} connections from netstat", connections.len());

    // Then try lsof for additional connections
    let before_count = connections.len();
    monitor.get_connections_from_lsof(connections)?;
    debug!(
        "Found {} additional connections from lsof",
        connections.len() - before_count
    );

    Ok(())
}

impl NetworkMonitor {
    /// Get connections from lsof command
    pub(super) fn get_connections_from_lsof(&self, connections: &mut Vec<Connection>) -> Result<()> {
        // Track unique connections to avoid duplicates
        let mut seen_connections = HashSet::new();
        for conn in connections.iter() {
            let key = format!(
                "{:?}:{}-{:?}:{}",
                conn.protocol, conn.local_addr, conn.protocol, conn.remote_addr
            );
            seen_connections.insert(key);
        }

        // Use more aggressive lsof command with less filtering
        let output = Command::new("lsof").args(["-i", "-n", "-P"]).output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines().skip(1) {
                // Skip header
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 8 {
                    continue;
                }

                // Get process name and PID
                let process_name = fields[0].to_string();
                let pid = fields[1].parse::<u32>().unwrap_or(0);

                // Find the field with connection info - format usually has (LISTEN), (ESTABLISHED) etc.
                let proto_addr_idx = 8;
                if fields.len() <= proto_addr_idx {
                    continue;
                }

                let proto_addr = fields[proto_addr_idx];
                let proto_end = match proto_addr.find(' ') {
                    Some(pos) => pos,
                    None => continue,
                };

                let proto_str = &proto_addr[..proto_end].to_lowercase();
                let protocol = if proto_str == "tcp" || proto_str == "tcp4" || proto_str == "tcp6" {
                    Protocol::TCP
                } else if proto_str == "udp" || proto_str == "udp4" || proto_str == "udp6" {
                    Protocol::UDP
                } else {
                    continue;
                };

                // Parse connection state
                let state = if fields.len() > proto_addr_idx + 1 {
                    match fields[proto_addr_idx + 1] {
                        "(ESTABLISHED)" => ConnectionState::Established,
                        "(LISTEN)" => ConnectionState::Listen,
                        "(TIME_WAIT)" => ConnectionState::TimeWait,
                        "(CLOSE_WAIT)" => ConnectionState::CloseWait,
                        "(SYN_SENT)" => ConnectionState::SynSent,
                        "(SYN_RECEIVED)" | "(SYN_RECV)" => ConnectionState::SynReceived,
                        "(FIN_WAIT_1)" => ConnectionState::FinWait1,
                        "(FIN_WAIT_2)" => ConnectionState::FinWait2,
                        "(LAST_ACK)" => ConnectionState::LastAck,
                        "(CLOSING)" => ConnectionState::Closing,
                        _ => ConnectionState::Unknown,
                    }
                } else {
                    ConnectionState::Unknown
                };

                // Parse addresses
                if proto_addr.find("->").is_some() {
                    // Has local and remote address (ESTABLISHED connection)
                    let addr_str = &proto_addr[proto_end + 1..];
                    let parts: Vec<&str> = addr_str.split("->").collect();
                    if parts.len() == 2 {
                        if let (Some(local), Some(remote)) =
                            (super::parse_addr(parts[0]), super::parse_addr(parts[1]))
                        {
                            // Check if this connection is already in our list
                            let conn_key =
                                format!("{:?}:{}-{:?}:{}", protocol, local, protocol, remote);

                            if !seen_connections.contains(&conn_key) {
                                let mut conn = Connection::new(protocol, local, remote, state);
                                conn.pid = Some(pid);
                                conn.process_name = Some(process_name);
                                connections.push(conn);
                                seen_connections.insert(conn_key);
                            }
                        }
                    }
                } else {
                    // Only local address (likely LISTEN)
                    let addr_str = &proto_addr[proto_end + 1..];
                    if let Some(local) = super::parse_addr(addr_str) {
                        // Use 0.0.0.0:0 as remote for listening sockets
                        let remote = if local.ip().is_ipv4() {
                            "0.0.0.0:0".parse().unwrap()
                        } else {
                            "[::]:0".parse().unwrap()
                        };

                        // Check if this connection is already in our list
                        let conn_key =
                            format!("{:?}:{}-{:?}:{}", protocol, local, protocol, remote);

                        if !seen_connections.contains(&conn_key) {
                            let mut conn = Connection::new(protocol, local, remote, state);
                            conn.pid = Some(pid);
                            conn.process_name = Some(process_name);
                            connections.push(conn);
                            seen_connections.insert(conn_key);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get connections from netstat command
    pub(super) fn get_connections_from_netstat(&self, connections: &mut Vec<Connection>) -> Result<()> {
        // Track unique connections to avoid duplicates
        let mut seen_connections = HashSet::new();

        // Get TCP connections
        let output = Command::new("netstat")
            .args(["-anv", "-p", "tcp"])
            .output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines().skip(2) {
                // Skip headers

                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 5 {
                    continue;
                }

                // Protocol is always TCP for this command
                let protocol = Protocol::TCP;

                // Parse state
                let state_idx = 5; // Index where state info is typically found
                let state = if fields.len() > state_idx {
                    match fields[state_idx] {
                        "ESTABLISHED" => ConnectionState::Established,
                        "LISTEN" => ConnectionState::Listen,
                        "TIME_WAIT" => ConnectionState::TimeWait,
                        "CLOSE_WAIT" => ConnectionState::CloseWait,
                        "SYN_SENT" => ConnectionState::SynSent,
                        "SYN_RCVD" | "SYN_RECV" => ConnectionState::SynReceived,
                        "FIN_WAIT_1" => ConnectionState::FinWait1,
                        "FIN_WAIT_2" => ConnectionState::FinWait2,
                        "LAST_ACK" => ConnectionState::LastAck,
                        "CLOSING" => ConnectionState::Closing,
                        _ => ConnectionState::Unknown,
                    }
                } else {
                    ConnectionState::Unknown
                };

                // Parse local and remote addresses
                let local_idx = 3;
                let remote_idx = 4;

                if fields.len() <= local_idx || fields.len() <= remote_idx {
                    continue;
                }

                if let (Some(local), Some(remote)) = (
                    super::parse_addr(fields[local_idx]),
                    super::parse_addr(fields[remote_idx]),
                ) {
                    // Check if this connection is already in our list
                    let conn_key = format!("{:?}:{}-{:?}:{}", protocol, local, protocol, remote);

                    if !seen_connections.contains(&conn_key) {
                        connections.push(Connection::new(protocol, local, remote, state));
                        seen_connections.insert(conn_key);
                    }
                }
            }
        }

        // Get UDP connections
        let output = Command::new("netstat")
            .args(["-anv", "-p", "udp"])
            .output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines().skip(2) {
                // Skip headers
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    continue;
                }

                // Protocol is always UDP for this command
                let protocol = Protocol::UDP;

                // Parse local address
                let local_idx = 3;

                if fields.len() <= local_idx {
                    continue;
                }

                if let Some(local) = super::parse_addr(fields[local_idx]) {
                    // Use 0.0.0.0:0 as remote for UDP
                    let remote = if local.ip().is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };

                    // Check if this connection is already in our list
                    let conn_key = format!("{:?}:{}-{:?}:{}", protocol, local, protocol, remote);

                    if !seen_connections.contains(&conn_key) {
                        connections.push(Connection::new(
                            protocol,
                            local,
                            remote,
                            ConnectionState::Unknown,
                        ));
                        seen_connections.insert(conn_key);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Parses the NAME field of lsof output to extract local and remote addresses.
pub(super) fn parse_lsof_addrs(addr_field: &str) -> Option<(SocketAddr, SocketAddr)> {
    if let Some(arrow_idx) = addr_field.find("->") {
        let local_str = &addr_field[..arrow_idx];
        let remote_str = &addr_field[arrow_idx + 2..];
        let local_addr = super::parse_addr(local_str)?;
        let remote_addr = super::parse_addr(remote_str)?;
        Some((local_addr, remote_addr))
    } else {
        let local_addr = super::parse_addr(addr_field)?;
        let remote_addr = "0.0.0.0:0".parse().ok()?;
        Some((local_addr, remote_addr))
    }
}

/// Get process information using lsof command
pub(super) fn try_lsof_command(connection: &Connection) -> Option<Process> {
    let proto_arg = match connection.protocol {
        Protocol::TCP => "TCP",
        Protocol::UDP => "UDP",
        Protocol::ICMP => return None,
    };

    let output = Command::new("lsof")
        .args(["-i", proto_arg, "-n", "-P"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                continue;
            }

            if let Some((lsof_local, lsof_remote)) = parse_lsof_addrs(fields[8]) {
                let c = connection;
                let match1 = c.local_addr == lsof_local && c.remote_addr == lsof_remote;
                let match2 = c.local_addr == lsof_remote && c.remote_addr == lsof_local;

                if match1 || match2 {
                    if let Ok(pid) = fields[1].parse::<u32>() {
                        return Some(Process {
                            pid,
                            name: fields[0].to_string(),
                        });
                    }
                }
            }
        }
    }
    None
}

/// Get process information using netstat command
pub(super) fn try_netstat_command(connection: &Connection) -> Option<Process> {
    if let Some(process) = try_lsof_command(connection) {
        return Some(process);
    }

    let output = Command::new("netstat")
        .args(["-p", "tcp", "-v"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let local_port = connection.local_addr.port();
        let remote_port = connection.remote_addr.port();

        for line in text.lines().skip(2) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                continue;
            }

            if let Some(local_addr_str) = fields.get(3) {
                if let Some(remote_addr_str) = fields.get(4) {
                    if let (Some(local_addr), Some(remote_addr)) = (
                        super::parse_addr(local_addr_str),
                        super::parse_addr(remote_addr_str),
                    ) {
                        if local_addr.port() == local_port && remote_addr.port() == remote_port {
                            if let Some(pid_str) = fields.get(8) {
                                if let Ok(pid) = pid_str.parse::<u32>() {
                                    return get_process_name_by_pid(pid)
                                        .map(|name| Process { pid, name });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Get process name by PID
#[allow(dead_code)]
pub(super) fn get_process_name_by_pid(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let name = text.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

