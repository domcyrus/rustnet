//! JSONL event and PCAP-sidecar emission shared by the packet, cleanup, and
//! shutdown paths.

use std::sync::Arc;
use std::time::SystemTime;

use crate::headless::events::{ConnectionEvent, PcapSidecarRecord};
use crate::headless::sink::{EventSink, FileSink, json_line, write_connection_event};
use crate::network::dns::DnsResolver;
use crate::network::types::Connection;

/// Emit the `new_connection` event to every sink that accepts the
/// connection.
pub(super) fn log_new_connection(
    sinks: &[Arc<dyn EventSink>],
    conn: &Connection,
    dns_resolver: Option<&DnsResolver>,
) {
    write_connection_event(sinks, conn, || {
        ConnectionEvent::new_connection(conn, dns_resolver)
    });
}

/// Record a closed (archived or timed-out) connection: the
/// `connection_closed` event on every sink and the PCAP sidecar line when
/// PCAP export is enabled. The duration is measured from the connection's
/// `created_at` up to `now`.
pub(super) fn log_connection_closed(
    conn: &Connection,
    now: SystemTime,
    sinks: &[Arc<dyn EventSink>],
    pcap_sidecar: Option<&FileSink>,
    dns_resolver: Option<&DnsResolver>,
) {
    write_connection_event(sinks, conn, || {
        ConnectionEvent::connection_closed(conn, now, dns_resolver)
    });
    if let Some(sidecar) = pcap_sidecar {
        log_pcap_connection(sidecar, conn);
    }
}

pub(super) fn log_pcap_connection(sidecar: &FileSink, conn: &Connection) {
    if let Some(line) = json_line(&PcapSidecarRecord::from_connection(conn)) {
        sidecar.write_line(&line);
    }
}
