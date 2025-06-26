use anyhow::Result;
use std::process::Command;

use super::{Connection, ConnectionState, NetworkMonitor, Process, Protocol};

/// Get platform-specific connections for Windows
pub fn get_platform_connections(
    monitor: &NetworkMonitor,
    connections: &mut Vec<Connection>,
) -> Result<()> {
    // Use netstat on Windows for both TCP and UDP
    monitor.get_connections_from_netstat(connections)?;

    Ok(())
}

// Methods below remain part of NetworkMonitor impl
impl NetworkMonitor {
    /// Get platform-specific process for a connection
    pub(super) fn get_platform_process_for_connection(
        &self,
        connection: &Connection,
    ) -> Option<Process> {
        // Try netstat
        if let Some(process) = try_netstat_command(connection) {
            return Some(process);
        }

        // Fall back to API calls if we implement them
        try_windows_api(connection)
    }

    /// Get process information by PID
    pub(super) fn get_process_by_pid(&self, pid: u32) -> Option<Process> {
        // Use tasklist to get process info
        if let Ok(output) = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let line = text.lines().next().unwrap_or("");

            // Parse CSV format
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                // Remove quotes
                let name = parts[0].trim_matches('"').to_string();

                return Some(Process {
                    pid,
                    name,
                });
            }
        }

        None
    }

    /// Get connections from netstat command
    pub(super) fn get_connections_from_netstat(&self, connections: &mut Vec<Connection>) -> Result<()> {
        let output = Command::new("netstat").args(["-ano"]).output()?;

        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);

            for line in text.lines().skip(4) {
                // Skip headers
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 5 {
                    continue;
                }

                // Parse protocol
                let protocol = match fields[0].to_lowercase().as_str() {
                    "tcp" | "tcp6" => Protocol::TCP,
                    "udp" | "udp6" => Protocol::UDP,
                    _ => continue,
                };

                // Parse state
                let state_pos = 3;
                let state = if fields.len() > state_pos {
                    match fields[state_pos] {
                        "ESTABLISHED" => ConnectionState::Established,
                        "LISTENING" | "LISTEN" => ConnectionState::Listen,
                        "TIME_WAIT" => ConnectionState::TimeWait,
                        "CLOSE_WAIT" => ConnectionState::CloseWait,
                        "SYN_SENT" => ConnectionState::SynSent,
                        "SYN_RECEIVED" | "SYN_RECV" => ConnectionState::SynReceived,
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
                let local_idx = 1;
                let remote_idx = 2;

                if let (Some(local), Some(remote)) = (
                    super::parse_addr(fields[local_idx]),
                    super::parse_addr(fields[remote_idx]),
                ) {
                    let mut conn = Connection::new(protocol, local, remote, state);

                    // Parse PID
                    let pid_pos = 4;
                    if fields.len() > pid_pos && fields[pid_pos] != "-" {
                        if let Ok(pid) = fields[pid_pos].parse::<u32>() {
                            conn.pid = Some(pid);
                        }
                    }

                    connections.push(conn);
                }
            }
        }

        Ok(())
    }
}

/// Get process information using netstat command
pub(super) fn try_netstat_command(connection: &Connection) -> Option<Process> {
    let output = Command::new("netstat").args(["-ano"]).output().ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let local_addr = format!("{}", connection.local_addr);
        let remote_addr = format!("{}", connection.remote_addr);

        for line in text.lines().skip(2) {
            // Skip headers
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }

            // Check if this line matches our connection
            let local_idx = 1;
            let remote_idx = 2;
            let proto_idx = 0;

            let matches_protocol = match connection.protocol {
                Protocol::TCP => {
                    fields[proto_idx].eq_ignore_ascii_case("tcp")
                        || fields[proto_idx].eq_ignore_ascii_case("tcp6")
                }
                Protocol::UDP => {
                    fields[proto_idx].eq_ignore_ascii_case("udp")
                        || fields[proto_idx].eq_ignore_ascii_case("udp6")
                }
                _ => false,
            };

            if matches_protocol
                && (fields[local_idx].contains(&local_addr)
                    || fields[local_idx].contains(&format!(":{}", connection.local_addr.port())))
                && (fields[remote_idx].contains(&remote_addr)
                    || fields[remote_idx].contains(&format!(":{}", connection.remote_addr.port())))
            {
                // Found matching connection, get PID
                let pid_pos = 4;
                if fields.len() > pid_pos && fields[pid_pos] != "-" {
                    if let Ok(pid) = fields[pid_pos].parse::<u32>() {
                        // Get process name
                        let name = get_process_name_by_pid(pid)
                            .unwrap_or_else(|| format!("process-{}", pid));

                        return Some(Process {
                            pid,
                            name,
                        });
                    }
                }

                break;
            }
        }
    }

    None
}

/// Try Windows API to get process information
pub(super) fn try_windows_api(_connection: &Connection) -> Option<Process> {
    // This would require using the Windows API (like GetExtendedTcpTable)
    // For simplicity, we'll just return None as a placeholder
    // In a real implementation, you'd use the windows crate to make API calls
    None
}

/// Get process name by PID
fn get_process_name_by_pid(pid: u32) -> Option<String> {
    let output = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.lines().next()?;

    // Parse CSV format (remove quotes)
    let name_end = line.find(',')? - 1;
    let name = line[1..name_end].to_string();

    Some(name)
}
