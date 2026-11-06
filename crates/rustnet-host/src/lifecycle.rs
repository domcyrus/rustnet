//! Host evidence for retiring connections, independent of logging and UI.

use crate::ProcessLookup;
use rustnet_core::network::types::{
    Connection, ConnectionObservation, ProcessExitStatus, Protocol,
};
use std::time::SystemTime;

#[cfg(any(
    test,
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
))]
mod inventory;

#[cfg(target_os = "linux")]
pub use crate::linux::lifecycle::{ProcessExitTracker as LifecycleTracker, TrackedConnection};
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "freebsd"))]
pub use inventory::{SocketLifecycleTracker as LifecycleTracker, TrackedConnection};

/// Per-flow evidence shared by process-exit and inventory reconciliation.
#[derive(Default)]
pub(crate) struct SocketObservation {
    pub(crate) enrolled: bool,
    pub(crate) missing: Option<(SystemTime, (u64, u64))>,
    pub(crate) status: Option<ProcessExitStatus>,
}

impl LifecycleTracker {
    /// Return closure candidates without mutating the connection table.
    /// The caller must recheck generation and packet activity before retiring.
    pub fn closed_connections(
        &mut self,
        connections: &[TrackedConnection],
        process_lookup: &dyn ProcessLookup,
    ) -> Vec<ConnectionObservation> {
        #[cfg(target_os = "linux")]
        {
            // Exit watches use their own fresh procfs scans, independently of
            // the slower attribution cache and its best-effort inventory.
            let _ = process_lookup;
            self.scan_closed(connections)
        }
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "freebsd"))]
        self.scan_closed(connections, &process_lookup.socket_snapshot())
    }

    /// Break pending inventory confirmations when a lookup refresh failed.
    pub fn refresh_failed(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "windows", target_os = "freebsd"))]
        self.invalidate();
    }

    /// Diagnostic for an active TCP/UDP flow, including unavailable identity.
    pub fn connection_status(&self, connection: &Connection) -> Option<ProcessExitStatus> {
        matches!(connection.protocol, Protocol::Tcp | Protocol::Udp).then(|| {
            TrackedConnection::from_connection(connection)
                .map(|observed| self.observation_status(&observed))
                .unwrap_or(ProcessExitStatus::IdentityMissing)
        })
    }
}
