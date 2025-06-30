use super::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::process::Command;
use std::sync::RwLock;

pub struct MacOSProcessLookup {
    cache: RwLock<HashMap<ConnectionKey, (u32, String)>>,
}

impl MacOSProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn parse_lsof() -> Result<HashMap<ConnectionKey, (u32, String)>> {
        let mut lookup = HashMap::new();

        // Run lsof to get network connections
        let output = Command::new("lsof")
            .args(&["-i", "-n", "-P", "+c", "0"])
            .output()?;

        if !output.status.success() {
            return Ok(lookup);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }

            let process_name = parts[0].to_string();
            let pid = match parts[1].parse::<u32>() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Parse connection from NAME field
            if let Some((protocol, local, remote)) = parse_lsof_connection(parts[8]) {
                let key = ConnectionKey {
                    protocol,
                    local_addr: local,
                    remote_addr: remote,
                };
                lookup.insert(key, (pid, process_name));
            }
        }

        Ok(lookup)
    }
}

impl ProcessLookup for MacOSProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);
        self.cache.read().unwrap().get(&key).cloned()
    }

    fn refresh(&self) -> Result<()> {
        let new_cache = Self::parse_lsof()?;
        *self.cache.write().unwrap() = new_cache;
        Ok(())
    }
}

fn parse_lsof_connection(name: &str) -> Option<(Protocol, SocketAddr, SocketAddr)> {
    // Parse lsof NAME field format:
    // "192.168.1.1:443->10.0.0.1:12345"
    // Determine protocol and parse addresses

    // Implementation would parse the connection string
    None // Placeholder
}
