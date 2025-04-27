use anyhow::Result;
use std::net::SocketAddr;
use std::process::Command;

use super::{Connection, ConnectionState, NetworkMonitor, Process, Protocol};

impl NetworkMonitor {
    /// Get connections using platform-specific methods
    pub(super) fn get_platform_connections(&self, connections: &mut Vec<Connection>) -> Result<()> {
        // Use lsof on macOS
        self.get_connections_from_lsof(connections)?;

        // Fall back to netstat if needed
        if connections.is_empty() {
            self.get_connections_from_netstat(connections)?;
        }

        Ok(())
    }

    /// Get platform-specific process for a connection
    pub(super) fn get_platform_process_for_connection(
        &self,
        connection: &Connection,
    ) -> Option<Process> {
        // Try lsof first (more detailed)
        if let Some(process) = try_lsof_command(connection) {
            return Some(process);
        }

        // Fall back to netstat
        try_netstat_command(connection)
    }

    /// Get process information by PID
    pub(super) fn get_process_by_pid(&self, pid: u32) -> Option<Process> {
        // Use ps to get process info
        if let Ok(output) = Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm=,user="])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let line = text.trim();

            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let user = parts.get(1).map(|s| s.to_string());

                return Some(Process {
                    pid,
                    name,
                    command_line: None,
                    user,
                    cpu_usage: None,
                    memory_usage: None,
                });
            }
        }

        None
    }

    /// Get connections from lsof command
    fn get_connections_from_lsof(&self, connections: &mut Vec<Connection>) -> Result<()> {
        let output = Command::new("lsof").args(["-i", "-n", "-P"]).output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines().skip(1) {
                // Skip header
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 9 {
                    continue;
                }

                // Get process name and PID
                let process_name = fields[0].to_string();
                let pid = fields[1].parse::<u32>().unwrap_or(0);

                // Parse protocol and addresses
                let proto_addr = fields[8];
                if let Some(proto_end) = proto_addr.find(' ') {
                    let proto_str = &proto_addr[..proto_end];
                    let protocol = match proto_str.to_lowercase().as_str() {
                        "tcp" | "tcp6" | "tcp4" => Protocol::TCP,
                        "udp" | "udp6" | "udp4" => Protocol::UDP,
                        _ => continue,
                    };

                    // Parse connection state
                    let state = match fields.get(9) {
                        Some(&"(ESTABLISHED)") => ConnectionState::Established,
                        Some(&"(LISTEN)") => ConnectionState::Listen,
                        Some(&"(TIME_WAIT)") => ConnectionState::TimeWait,
                        Some(&"(CLOSE_WAIT)") => ConnectionState::CloseWait,
                        Some(&"(SYN_SENT)") => ConnectionState::SynSent,
                        Some(&"(SYN_RECEIVED)") | Some(&"(SYN_RECV)") => {
                            ConnectionState::SynReceived
                        }
                        Some(&"(FIN_WAIT_1)") => ConnectionState::FinWait1,
                        Some(&"(FIN_WAIT_2)") => ConnectionState::FinWait2,
                        Some(&"(LAST_ACK)") => ConnectionState::LastAck,
                        Some(&"(CLOSING)") => ConnectionState::Closing,
                        _ => ConnectionState::Unknown,
                    };

                    // Parse addresses
                    if let Some(addr_part) = proto_addr.find("->") {
                        // Has local and remote address
                        let addr_str = &proto_addr[proto_end + 1..];
                        let parts: Vec<&str> = addr_str.split("->").collect();
                        if parts.len() == 2 {
                            if let (Some(local), Some(remote)) =
                                (self.parse_addr(parts[0]), self.parse_addr(parts[1]))
                            {
                                let mut conn = Connection::new(protocol, local, remote, state);
                                conn.pid = Some(pid);
                                conn.process_name = Some(process_name);
                                connections.push(conn);
                            }
                        }
                    } else {
                        // Only local address (likely LISTEN)
                        let addr_str = &proto_addr[proto_end + 1..];
                        if let Some(local) = self.parse_addr(addr_str) {
                            // Use 0.0.0.0:0 as remote for listening sockets
                            let remote = if local.ip().is_ipv4() {
                                "0.0.0.0:0".parse().unwrap()
                            } else {
                                "[::]:0".parse().unwrap()
                            };

                            let mut conn =
                                Connection::new(protocol, local, remote, ConnectionState::Listen);
                            conn.pid = Some(pid);
                            conn.process_name = Some(process_name);
                            connections.push(conn);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Get connections from netstat command
    fn get_connections_from_netstat(&self, connections: &mut Vec<Connection>) -> Result<()> {
        let output = Command::new("netstat").args(["-p", "tcp", "-n"]).output()?;

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
                let state_pos = 5;
                let state = if fields.len() > state_pos {
                    match fields[state_pos] {
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

                if let (Some(local), Some(remote)) = (
                    self.parse_addr(fields[local_idx]),
                    self.parse_addr(fields[remote_idx]),
                ) {
                    connections.push(Connection::new(protocol, local, remote, state));
                }
            }
        }

        // Also get UDP connections
        let output = Command::new("netstat").args(["-p", "udp", "-n"]).output()?;

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

                if let Some(local) = self.parse_addr(fields[local_idx]) {
                    // Use 0.0.0.0:0 as remote for UDP
                    let remote = if local.ip().is_ipv4() {
                        "0.0.0.0:0".parse().unwrap()
                    } else {
                        "[::]:0".parse().unwrap()
                    };

                    connections.push(Connection::new(
                        protocol,
                        local,
                        remote,
                        ConnectionState::Unknown,
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Get process information using lsof command
fn try_lsof_command(connection: &Connection) -> Option<Process> {
    let output = Command::new("lsof")
        .args(["-i", "-n", "-P"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let local_port = connection.local_addr.port();
        let remote_port = connection.remote_addr.port();

        for line in text.lines().skip(1) {
            // Skip header
            if line.contains(&format!(":{}", local_port))
                && (remote_port == 0 || line.contains(&format!(":{}", remote_port)))
            {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 2 {
                    continue;
                }

                // Get process name and PID
                let process_name = fields[0].to_string();
                if let Ok(pid) = fields[1].parse::<u32>() {
                    // Try to get user
                    let user = if fields.len() > 2 {
                        Some(fields[2].to_string())
                    } else {
                        None
                    };

                    return Some(Process {
                        pid,
                        name: process_name,
                        command_line: None,
                        user,
                        cpu_usage: None,
                        memory_usage: None,
                    });
                }
            }
        }
    }

    None
}

/// Get process information using netstat command
fn try_netstat_command(connection: &Connection) -> Option<Process> {
    // macOS netstat doesn't show process info, so we need to combine with ps
    // This is a limited implementation since macOS netstat doesn't show PIDs

    // Use lsof as the main tool for macOS
    try_lsof_command(connection)
}

/// Get process name by PID
fn get_process_name_by_pid(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    Some(text.trim().to_string())
}
