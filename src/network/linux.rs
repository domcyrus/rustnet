// linux.rs
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::{Connection, Protocol, ProtocolState};

/// Get connections with process information from /proc
pub fn get_connections_with_process_info(connections: &mut Vec<Connection>) -> Result<()> {
    // Parse TCP connections
    parse_proc_net_file("/proc/net/tcp", Protocol::TCP, connections)?;
    parse_proc_net_file("/proc/net/tcp6", Protocol::TCP, connections)?;

    // Parse UDP connections
    parse_proc_net_file("/proc/net/udp", Protocol::UDP, connections)?;
    parse_proc_net_file("/proc/net/udp6", Protocol::UDP, connections)?;

    // Build a map of inodes to process info
    let inode_to_process = build_inode_to_process_map()?;

    // Enrich connections with process info
    for conn in connections.iter_mut() {
        if let Some(inode) = get_socket_inode(conn) {
            if let Some((pid, name)) = inode_to_process.get(&inode) {
                conn.pid = Some(*pid);
                conn.process_name = Some(name.clone());
            }
        }
    }

    Ok(())
}

/// Parse a /proc/net file and add connections
fn parse_proc_net_file(
    path: &str,
    protocol: Protocol,
    connections: &mut Vec<Connection>,
) -> Result<()> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(()), // File might not exist
    };

    for (i, line) in content.lines().enumerate() {
        if i == 0 {
            continue; // Skip header
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Parse local address
        let local_addr = match parse_hex_address(parts[1]) {
            Some(addr) => addr,
            None => continue,
        };

        // Parse remote address
        let remote_addr = match parse_hex_address(parts[2]) {
            Some(addr) => addr,
            None => continue,
        };

        // Create a basic connection with minimal state
        let state = match protocol {
            Protocol::TCP => ProtocolState::Tcp(super::TcpState::Established),
            Protocol::UDP => ProtocolState::Udp,
            _ => continue,
        };

        let mut conn = Connection::new(protocol, local_addr, remote_addr, state);

        // Try to get inode from column 9 (0-indexed)
        if parts.len() > 9 {
            if let Ok(inode) = parts[9].parse::<u64>() {
                // Store inode temporarily (we'll use a hack here - store in bytes_sent)
                conn.bytes_sent = inode;
            }
        }

        connections.push(conn);
    }

    Ok(())
}

/// Parse hex address from /proc/net format
fn parse_hex_address(hex_addr: &str) -> Option<SocketAddr> {
    let parts: Vec<&str> = hex_addr.split(':').collect();
    if parts.len() != 2 {
        return None;
    }

    let ip_hex = parts[0];
    let port = u16::from_str_radix(parts[1], 16).ok()?;

    // Determine if IPv4 or IPv6 based on length
    if ip_hex.len() == 8 {
        // IPv4
        let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = Ipv4Addr::from(ip_bytes.to_le_bytes());
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    } else if ip_hex.len() == 32 {
        // IPv6
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let chunk = &ip_hex[i * 8..(i + 1) * 8];
            let value = u32::from_str_radix(chunk, 16).ok()?;
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&value.to_le_bytes());
        }
        let ip = Ipv6Addr::from(bytes);
        Some(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        None
    }
}

/// Build a map of socket inodes to process information
fn build_inode_to_process_map() -> Result<HashMap<u64, (u32, String)>> {
    let mut inode_map = HashMap::new();

    // Iterate through /proc/[pid]/fd/
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let path = entry.path();

        // Check if it's a PID directory
        if let Some(pid_str) = path.file_name().and_then(|s| s.to_str()) {
            if let Ok(pid) = pid_str.parse::<u32>() {
                // Get process name
                let comm_path = path.join("comm");
                let process_name = fs::read_to_string(&comm_path)
                    .unwrap_or_else(|_| "unknown".to_string())
                    .trim()
                    .to_string();

                // Check all file descriptors
                let fd_dir = path.join("fd");
                if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                    for fd_entry in fd_entries {
                        if let Ok(fd_entry) = fd_entry {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                if let Some(link_str) = link.to_str() {
                                    if link_str.starts_with("socket:[") {
                                        if let Some(inode) = extract_socket_inode(link_str) {
                                            inode_map.insert(inode, (pid, process_name.clone()));
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

    Ok(inode_map)
}

/// Extract inode from socket link like "socket:[12345]"
fn extract_socket_inode(link: &str) -> Option<u64> {
    if link.starts_with("socket:[") && link.ends_with(']') {
        let inode_str = &link[8..link.len() - 1];
        inode_str.parse().ok()
    } else {
        None
    }
}

/// Get socket inode for a connection
fn get_socket_inode(conn: &Connection) -> Option<u64> {
    // We stored the inode in bytes_sent temporarily
    if conn.bytes_sent > 0 {
        Some(conn.bytes_sent)
    } else {
        None
    }
}
