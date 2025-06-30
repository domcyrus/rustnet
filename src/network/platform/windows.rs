use super::{ConnectionKey, ProcessLookup};
use crate::network::types::{Connection, Protocol};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::RwLock;

pub struct WindowsProcessLookup {
    // Windows can get process info directly from connection tables
    cache: RwLock<HashMap<ConnectionKey, (u32, String)>>,
}

impl WindowsProcessLookup {
    pub fn new() -> Result<Self> {
        Ok(Self {
            cache: RwLock::new(HashMap::new()),
        })
    }

    fn refresh_tcp_processes(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        // Use GetExtendedTcpTable to get TCP connections with PIDs
        // This is pseudo-code - actual implementation would use winapi

        // For each connection in the table:
        // - Extract local/remote addresses
        // - Get PID from dwOwningPid
        // - Look up process name from PID
        // - Insert into cache

        Ok(())
    }

    fn refresh_udp_processes(
        &self,
        cache: &mut HashMap<ConnectionKey, (u32, String)>,
    ) -> Result<()> {
        // Similar to TCP using GetExtendedUdpTable
        Ok(())
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn get_process_for_connection(&self, conn: &Connection) -> Option<(u32, String)> {
        let key = ConnectionKey::from_connection(conn);
        self.cache.read().unwrap().get(&key).cloned()
    }

    fn refresh(&self) -> Result<()> {
        let mut new_cache = HashMap::new();

        self.refresh_tcp_processes(&mut new_cache)?;
        self.refresh_udp_processes(&mut new_cache)?;

        *self.cache.write().unwrap() = new_cache;
        Ok(())
    }
}
