use anyhow::Result;
use log::{debug, info, warn};
use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;

use super::{Connection, ConnectionState, NetworkMonitor, Process, Protocol};

/// Get IP addresses associated with an interface
pub fn get_interface_addresses(interface: &str) -> Result<Vec<IpAddr>> {
    let mut addresses = Vec::new();

    // Use ifconfig to get interface IP addresses on macOS
    let output = Command::new("ifconfig").arg(interface).output()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        debug!("ifconfig output for {}: {}", interface, text);

        // Parse IPv4 addresses
        for line in text.lines() {
            if line.contains("inet ") && !line.contains("127.0.0.1") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse() {
                        debug!("Found IPv4 address: {}", ip);
                        addresses.push(ip);
                    }
                }
            }
            // Parse IPv6 addresses
            else if line.contains("inet6 ") && !line.contains("::1") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(ip) = parts[1].parse() {
                        debug!("Found IPv6 address: {}", ip);
                        addresses.push(ip);
                    }
                }
            }
        }
    } else {
        warn!("ifconfig command failed for interface {}", interface);
        // Try fallback with ipconfig getifaddr
        if let Ok(output) = Command::new("ipconfig")
            .args(["getifaddr", interface])
            .output()
        {
            if output.status.success() {
                let ip_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Ok(ip) = ip_str.parse() {
                    addresses.push(ip);
                }
            }
        }
    }

    // Add loopback addresses for completeness
    addresses.push("127.0.0.1".parse().unwrap());
    addresses.push("::1".parse().unwrap());

    Ok(addresses)
}

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

    // Filter by interface if specified
    if let Some(iface) = &monitor.interface {
        debug!("Filtering connections for interface: {}", iface);
        let connection_count_before = connections.len();

        // Get interface addresses
        let interface_addresses = match get_interface_addresses(iface) {
            Ok(addrs) => {
                debug!(
                    "Interface {} has {} addresses: {:?}",
                    iface,
                    addrs.len(),
                    addrs
                );
                addrs
            }
            Err(e) => {
                warn!("Failed to get addresses for interface {}: {}", iface, e);
                Vec::new()
            }
        };

        if !interface_addresses.is_empty() {
            // Filter connections only if we found interface addresses
            connections.retain(|conn| {
                let local_ip = conn.local_addr.ip();
                let is_interface_match = interface_addresses.iter().any(|&addr| local_ip == addr);
                let is_unspecified = local_ip.is_unspecified();

                is_interface_match || is_unspecified
            });

            info!(
                "Interface filtering: {} -> {} connections for interface {}",
                connection_count_before,
                connections.len(),
                iface
            );
        } else {
            // If we couldn't get interface addresses, don't filter
            info!(
                "Could not determine IP addresses for interface {}, showing all connections",
                iface
            );
        }
    }

    // If still no connections, try using ss command with less filtering
    if connections.is_empty() {
        debug!("No connections found with standard methods, trying alternative approaches");
        monitor.get_connections_from_ss(connections)?;
    }

    Ok(())
}

impl NetworkMonitor {
    /// Get connections from lsof command
    fn get_connections_from_lsof(&self, connections: &mut Vec<Connection>) -> Result<()> {
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
                            (self.parse_addr(parts[0]), self.parse_addr(parts[1]))
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
                    if let Some(local) = self.parse_addr(addr_str) {
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
    fn get_connections_from_netstat(&self, connections: &mut Vec<Connection>) -> Result<()> {
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
                    self.parse_addr(fields[local_idx]),
                    self.parse_addr(fields[remote_idx]),
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

                if let Some(local) = self.parse_addr(fields[local_idx]) {
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

    /// Try ss command as an alternative (if available on system)
    fn get_connections_from_ss(&self, connections: &mut Vec<Connection>) -> Result<()> {
        // Check if ss command is available
        let ss_check = Command::new("which").arg("ss").output();
        if ss_check.is_err() || !ss_check.unwrap().status.success() {
            debug!("ss command not available");
            return Ok(());
        }

        let mut seen_connections = HashSet::new();
        for conn in connections.iter() {
            let key = format!(
                "{:?}:{}-{:?}:{}",
                conn.protocol, conn.local_addr, conn.protocol, conn.remote_addr
            );
            seen_connections.insert(key);
        }

        // Try ss command for TCP
        if let Ok(output) = Command::new("ss").args(["-tn"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(1) {
                    // Skip header
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 5 {
                        continue;
                    }

                    // Extract state, local and remote addresses
                    let state_str = fields[0];
                    let local_addr_str = fields[3];
                    let remote_addr_str = fields[4];

                    if let (Some(local), Some(remote)) = (
                        self.parse_addr(local_addr_str),
                        self.parse_addr(remote_addr_str),
                    ) {
                        // Determine connection state
                        let state = match state_str {
                            "ESTAB" => ConnectionState::Established,
                            "LISTEN" => ConnectionState::Listen,
                            "TIME-WAIT" => ConnectionState::TimeWait,
                            "CLOSE-WAIT" => ConnectionState::CloseWait,
                            "SYN-SENT" => ConnectionState::SynSent,
                            "SYN-RECV" => ConnectionState::SynReceived,
                            "FIN-WAIT-1" => ConnectionState::FinWait1,
                            "FIN-WAIT-2" => ConnectionState::FinWait2,
                            "LAST-ACK" => ConnectionState::LastAck,
                            "CLOSING" => ConnectionState::Closing,
                            _ => ConnectionState::Unknown,
                        };

                        // Add connection if not already seen
                        let conn_key = format!(
                            "{:?}:{}-{:?}:{}",
                            Protocol::TCP,
                            local,
                            Protocol::TCP,
                            remote
                        );

                        if !seen_connections.contains(&conn_key) {
                            connections.push(Connection::new(Protocol::TCP, local, remote, state));
                            seen_connections.insert(conn_key);
                        }
                    }
                }
            }
        }

        // Try ss command for UDP
        if let Ok(output) = Command::new("ss").args(["-un"]).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines().skip(1) {
                    // Skip header
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() < 4 {
                        continue;
                    }

                    // Extract local address
                    let local_addr_str = fields[3];

                    if let Some(local) = self.parse_addr(local_addr_str) {
                        // Use 0.0.0.0:0 as remote for UDP
                        let remote = if local.ip().is_ipv4() {
                            "0.0.0.0:0".parse().unwrap()
                        } else {
                            "[::]:0".parse().unwrap()
                        };

                        // Add connection if not already seen
                        let conn_key = format!(
                            "{:?}:{}-{:?}:{}",
                            Protocol::UDP,
                            local,
                            Protocol::UDP,
                            remote
                        );

                        if !seen_connections.contains(&conn_key) {
                            connections.push(Connection::new(
                                Protocol::UDP,
                                local,
                                remote,
                                ConnectionState::Unknown,
                            ));
                            seen_connections.insert(conn_key);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Get process information using lsof command
pub(super) fn try_lsof_command(connection: &Connection) -> Option<Process> {
    // Build lsof command with specific filters
    let local_port = connection.local_addr.port();
    let is_listening = connection.state == ConnectionState::Listen;

    // Different command based on whether it's LISTEN or ESTABLISHED
    let args;
    let port_spec;

    if is_listening {
        port_spec = format!(":{}", local_port);
        args = vec!["-i", &port_spec, "-n", "-P"];
    } else {
        let remote_port = connection.remote_addr.port();
        if remote_port == 0 {
            port_spec = format!(":{}", local_port);
            args = vec!["-i", &port_spec, "-n", "-P"];
        } else {
            port_spec = format!(":{}->{}", local_port, remote_port);
            args = vec!["-i", &port_spec, "-n", "-P"];
        }
    }

    let output = Command::new("lsof").args(&args).output().ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(1) {
            // Skip header
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

    // If we couldn't find it with lsof, try alternate methods
    None
}

/// Get process information using netstat command
pub(super) fn try_netstat_command(connection: &Connection) -> Option<Process> {
    // macOS netstat doesn't show process info directly
    // We need to use a combination with ps

    // First try lsof as that works best
    if let Some(process) = try_lsof_command(connection) {
        return Some(process);
    }

    // If lsof failed, try netstat -p tcp -v which shows PIDs on newer macOS
    let output = Command::new("netstat")
        .args(["-p", "tcp", "-v"])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let local_port = connection.local_addr.port();
        let remote_port = connection.remote_addr.port();

        for line in text.lines().skip(2) {
            // Skip headers
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 9 {
                // Need at least 9 fields for PID
                continue;
            }

            // Check if local port matches
            if let Some(local_addr) = fields.get(3) {
                if local_addr.contains(&format!(":{}", local_port))
                    && (remote_port == 0
                        || fields
                            .get(4)
                            .map_or(false, |addr| addr.contains(&format!(":{}", remote_port))))
                {
                    // Try to get PID from the field where it's usually stored
                    if let Some(pid_str) = fields.get(8) {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            // Now get process name using ps
                            return get_process_name_by_pid(pid).map(|name| Process {
                                pid,
                                name,
                                command_line: None,
                                user: None,
                                cpu_usage: None,
                                memory_usage: None,
                            });
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
