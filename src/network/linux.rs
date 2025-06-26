use anyhow::Result;
use log::{debug, error, info};
use pnet_datalink;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;

use super::{Connection, ConnectionState, NetworkMonitor, Process, Protocol};

/// Get platform-specific connections for Linux
pub fn get_platform_connections(
    monitor: &NetworkMonitor,
    connections: &mut Vec<Connection>,
) -> Result<()> {
    debug!("Attempting to get connections using platform-specific methods");

    info!("Running ss command to get TCP connections...");
    if let Err(e) = monitor.get_connections_from_ss(connections) {
        error!("Error running ss command: {}", e);
    }

    info!("Running netstat command to get UDP connections...");
    if let Err(e) = monitor.get_connections_from_netstat(connections) {
        error!("Error running netstat command: {}", e);
    }

    debug!(
        "Found {} connections from command output",
        connections.len()
    );

    Ok(())
}

impl NetworkMonitor {
    pub(super) fn get_linux_process_for_connection(
        &self,
        connection: &Connection,
    ) -> Option<Process> {
        if let Some(process) = try_ss_command(connection) {
            return Some(process);
        }

        if let Some(process) = try_netstat_command(connection) {
            return Some(process);
        }

        try_proc_parsing(connection)
    }

    fn get_connections_from_ss(&self, connections: &mut Vec<Connection>) -> Result<()> {
        debug!("Executing 'ss -tupn' to get TCP/UDP connections.");
        let cmd_output = Command::new("ss").args(["-tupn"]).output();

        match cmd_output {
            Ok(output) => {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines().skip(1) {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        if fields.len() < 5 {
                            continue;
                        }

                        let protocol = match fields[0] {
                            "tcp" | "tcp6" => Protocol::TCP,
                            "udp" | "udp6" => Protocol::UDP,
                            _ => continue,
                        };

                        let state_str = if fields.len() > 1 { fields[1] } else { "" };
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
                            "UNCONN" if protocol == Protocol::UDP => ConnectionState::Established,
                            _ => ConnectionState::Unknown,
                        };

                        if fields.len() < 6 {
                            continue;
                        }

                        if let (Some(local), Some(remote)) =
                            (super::parse_addr(fields[4]), super::parse_addr(fields[5]))
                        {
                            let mut conn = Connection::new(protocol, local, remote, state);

                            if fields.len() >= 7 {
                                let process_info = fields[6];
                                if let Some(pid_start) = process_info.find("pid=") {
                                    let pid_part = &process_info[pid_start + 4..];
                                    if let Some(pid_end) = pid_part.find(',') {
                                        if let Ok(pid) = pid_part[..pid_end].parse::<u32>() {
                                            conn.pid = Some(pid);
                                            if let Some(name_start) = process_info.find("users:((\"") {
                                                let name_part = &process_info[name_start + 9..];
                                                if let Some(name_end) = name_part.find('"') {
                                                    conn.process_name = Some(name_part[..name_end].to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            connections.push(conn);
                        }
                    }
                } else {
                    let stderr_text = String::from_utf8_lossy(&output.stderr);
                    error!(
                        "'ss -tupn' command failed with status {}. Stderr: {}",
                        output.status, stderr_text
                    );
                }
            }
            Err(e) => {
                error!("Failed to execute 'ss -tupn' command: {}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }

    fn get_connections_from_netstat(&self, connections: &mut Vec<Connection>) -> Result<()> {
        debug!("Executing 'netstat -tupn' as supplementary/fallback.");
        let cmd_output = Command::new("netstat").args(["-tupn"]).output();

        match cmd_output {
            Ok(output) => {
                if output.status.success() {
                    let text = String::from_utf8_lossy(&output.stdout);
                    for line in text.lines().skip(2) {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        if fields.len() < 5 {
                            continue;
                        }

                        let protocol = match fields[0].to_lowercase().as_str() {
                            "tcp" | "tcp6" => Protocol::TCP,
                            "udp" | "udp6" => Protocol::UDP,
                            _ => continue,
                        };

                        let state = if fields.len() > 5 {
                            match fields[5] {
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

                        if let (Some(local), Some(remote)) = (
                            super::parse_addr(fields[3]),
                            super::parse_addr(fields[4]),
                        ) {
                            let mut conn = Connection::new(protocol, local, remote, state);

                            if fields.len() > 6 && fields[6] != "-" {
                                let pid_str_parts: Vec<&str> = fields[6].split('/').collect();
                                if let Ok(pid) = pid_str_parts[0].parse::<u32>() {
                                    conn.pid = Some(pid);
                                    if pid_str_parts.len() > 1 && pid_str_parts[1] != "-" {
                                        conn.process_name = Some(pid_str_parts[1].to_string());
                                    }
                                }
                            }
                            connections.push(conn);
                        }
                    }
                } else {
                    let stderr_text = String::from_utf8_lossy(&output.stderr);
                    error!(
                        "'netstat -tupn' command failed with status {}. Stderr: {}",
                        output.status, stderr_text
                    );
                }
            }
            Err(e) => {
                error!("Failed to execute 'netstat -tupn' command: {}", e);
                return Err(e.into());
            }
        }
        Ok(())
    }
}

fn try_ss_command(connection: &Connection) -> Option<Process> {
    let proto_flag = match connection.protocol {
        Protocol::TCP => "-t",
        Protocol::UDP => "-u",
        Protocol::ICMP => return None,
    };

    let local_port = connection.local_addr.port();
    let remote_port = connection.remote_addr.port();

    let output = Command::new("ss")
        .args([proto_flag, "-p", "-n", "sport", &format!(":{}", local_port)])
        .output()
        .ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);

        for line in text.lines().skip(1) {
            if line.contains(&format!(":{}", local_port))
                && line.contains(&format!(":{}", remote_port))
            {
                if let Some(pid_start) = line.find("pid=") {
                    let pid_part = &line[pid_start + 4..];
                    if let Some(pid_end) = pid_part.find(',') {
                        if let Ok(pid) = pid_part[..pid_end].parse::<u32>() {
                            let name = if let Some(name_start) = line.find("users:(") {
                                let name_part = &line[name_start + 7..];
                                if let Some(name_end) = name_part.find(',') {
                                    let raw_name = &name_part[..name_end];
                                    raw_name
                                        .trim_start_matches("(\"")
                                        .trim_end_matches('"')
                                        .to_string()
                                } else {
                                    format!("process-{}", pid)
                                }
                            } else {
                                format!("process-{}", pid)
                            };

                            return Some(Process { pid, name });
                        }
                    }
                }
                break;
            }
        }
    }

    None
}

fn try_netstat_command(connection: &Connection) -> Option<Process> {
    let output = Command::new("netstat").args(["-tupn"]).output().ok()?;

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout);
        let local_addr = format!("{}", connection.local_addr);
        let remote_addr = format!("{}", connection.remote_addr);

        for line in text.lines().skip(2) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 5 {
                continue;
            }

            let local_idx = 3;
            let remote_idx = 4;
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
                Protocol::ICMP => false,
            };

            if matches_protocol
                && (fields[local_idx].contains(&local_addr)
                    || fields[local_idx].contains(&format!(":{}", connection.local_addr.port())))
                && (fields[remote_idx].contains(&remote_addr)
                    || fields[remote_idx].contains(&format!(":{}", connection.remote_addr.port())))
            {
                let pid_pos = 6;
                if fields.len() > pid_pos && fields[pid_pos] != "-" {
                    if let Ok(pid) = fields[pid_pos].parse::<u32>() {
                        let name = get_process_name_by_pid(pid)
                            .unwrap_or_else(|| format!("process-{}", pid));

                        return Some(Process { pid, name });
                    }
                }

                break;
            }
        }
    }

    None
}

fn try_proc_parsing(connection: &Connection) -> Option<Process> {
    let local_addr = match connection.local_addr.ip() {
        std::net::IpAddr::V4(ip) => {
            format!("{:X}", u32::from_be_bytes(ip.octets()))
        }
        std::net::IpAddr::V6(_) => {
            return None;
        }
    };

    let local_port = format!("{:X}", connection.local_addr.port());

    let proc_path = if connection.protocol == Protocol::TCP {
        if connection.local_addr.is_ipv4() {
            "/proc/net/tcp"
        } else {
            "/proc/net/tcp6"
        }
    } else if connection.protocol == Protocol::UDP {
        if connection.local_addr.is_ipv4() {
            "/proc/net/udp"
        } else {
            "/proc/net/udp6"
        }
    } else {
        return None;
    };

    if let Ok(contents) = std::fs::read_to_string(proc_path) {
        for line in contents.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }

            if let Some(colon_pos) = fields[1].rfind(':') {
                let addr = &fields[1][..colon_pos];
                let port = &fields[1][colon_pos + 1..];

                if port == local_port && (addr == local_addr || addr == "00000000") {
                    let inode = fields[9];

                    if let Ok(entries) = std::fs::read_dir("/proc") {
                        for entry in entries.flatten() {
                            if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                                let fd_path = entry.path().join("fd");
                                if let Ok(fds) = std::fs::read_dir(fd_path) {
                                    for fd in fds.flatten() {
                                        if let Ok(target) = std::fs::read_link(fd.path()) {
                                            if target.to_string_lossy().contains(&format!("socket:[{}]", inode)) {
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
            }
        }
    }

    None
}

fn get_process_name_by_pid(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
}
