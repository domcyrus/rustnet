// macOS process attribution: PKTAP packet metadata when active, else lsof.

mod process;

use process::MacOSProcessLookup;

use crate::{DegradationReason, MatchQuality, ProcessAttribution, ProcessLookup, SocketSnapshot};
use anyhow::Result;
use rustnet_core::network::types::Connection;
use std::sync::OnceLock;

/// Why the PKTAP fast path is unavailable, as reported by the orchestrator.
///
/// PKTAP availability is decided by the capture layer, not by process
/// attribution. Rather than depend on `rustnet-capture`, this crate lets the
/// application inject the reason via [`report_pktap_degradation`]; the lsof
/// lookup reads it back in `get_degradation_reason`.
static PKTAP_DEGRADATION: OnceLock<DegradationReason> = OnceLock::new();

/// Record why PKTAP could not be used so process-attribution degradation can be
/// surfaced to the user. Intended to be called once, by the application, after
/// it has determined PKTAP availability from the capture layer. No-op if already
/// set.
pub fn report_pktap_degradation(reason: DegradationReason) {
    let _ = PKTAP_DEGRADATION.set(reason);
}

/// The reported PKTAP degradation reason, or the conservative default
/// (missing root) when nothing has been reported.
pub(crate) fn pktap_degradation() -> DegradationReason {
    PKTAP_DEGRADATION
        .get()
        .cloned()
        .unwrap_or(DegradationReason::MissingRootPrivileges)
}

/// Enrich process identity carried directly in PKTAP packet metadata.
struct PktapProcessLookup {
    socket_lookup: MacOSProcessLookup,
}

impl ProcessLookup for PktapProcessLookup {
    fn get_process_attribution(&self, conn: &Connection) -> Option<ProcessAttribution> {
        let pid = conn.pid?;
        let name = conn.process_name.clone()?;
        let mut attribution = ProcessAttribution::new(pid, name, MatchQuality::ExactTuple)
            .with_executable(process::resolve_executable(pid));
        if let Some(details) = process::resolve_process_details(pid) {
            attribution = attribution.with_details(
                details.ppid,
                Some((details.uid, details.gid)),
                None,
                process::resolve_process_lineage(pid, details.ppid),
            );
        }
        Some(attribution)
    }

    fn refresh(&self) -> Result<()> {
        self.socket_lookup.refresh()
    }

    fn get_detection_method(&self) -> &str {
        "pktap"
    }

    fn socket_snapshot(&self) -> SocketSnapshot {
        self.socket_lookup.socket_snapshot()
    }
}

/// Create a macOS process lookup implementation.
/// Enriches PKTAP packet metadata when active, otherwise falls back to lsof.
pub fn create_process_lookup(use_pktap: bool) -> Result<Box<dyn ProcessLookup>> {
    if use_pktap {
        log::info!("Using PKTAP process metadata with libproc enrichment");
        Ok(Box::new(PktapProcessLookup {
            socket_lookup: MacOSProcessLookup::new()?,
        }))
    } else {
        log::info!("Using macOS process lookup (lsof)");
        Ok(Box::new(MacOSProcessLookup::new()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustnet_core::network::types::{Protocol, ProtocolState, TcpState};

    fn connection() -> Connection {
        Connection::new(
            Protocol::Tcp,
            "127.0.0.1:5000".parse().unwrap(),
            "1.1.1.1:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        )
    }

    #[test]
    fn pktap_identity_is_enriched_with_exact_libproc_attribution() {
        let mut conn = connection();
        conn.pid = Some(std::process::id());
        conn.process_name = Some("rustnet-host-test".to_string());

        let lookup = PktapProcessLookup {
            socket_lookup: MacOSProcessLookup::empty_for_test(),
        };
        let attribution = lookup.get_process_attribution(&conn).unwrap();

        assert_eq!(attribution.tgid, std::process::id());
        assert_eq!(attribution.name, "rustnet-host-test");
        assert_eq!(attribution.quality, MatchQuality::ExactTuple);
        assert_eq!(attribution.executable, std::env::current_exe().ok());
        assert_eq!(
            attribution.ppid,
            Some(u32::try_from(unsafe { libc::getppid() }).unwrap())
        );
        // SAFETY: these libc calls only read the credentials of this process.
        let expected_credentials = unsafe { (libc::geteuid(), libc::getegid()) };
        assert_eq!(
            (attribution.uid, attribution.gid),
            (Some(expected_credentials.0), Some(expected_credentials.1))
        );
        assert_eq!(
            attribution
                .lineage
                .as_ref()
                .and_then(|lineage| lineage.ancestors.last())
                .map(|ancestor| ancestor.pid),
            attribution.ppid
        );
    }

    #[test]
    fn pktap_lookup_requires_packet_process_identity() {
        let lookup = PktapProcessLookup {
            socket_lookup: MacOSProcessLookup::empty_for_test(),
        };
        let mut conn = connection();
        assert!(lookup.get_process_attribution(&conn).is_none());

        conn.pid = Some(std::process::id());
        assert!(lookup.get_process_attribution(&conn).is_none());
    }

    #[test]
    fn pktap_factory_reports_its_detection_method() {
        let lookup = create_process_lookup(true).unwrap();
        assert_eq!(lookup.get_detection_method(), "pktap");
    }
}
