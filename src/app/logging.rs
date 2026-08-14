//! JSONL event and PCAP-sidecar emission shared by the packet, cleanup, and
//! shutdown paths.

use log::warn;
use serde_json::{Map, Value, json};
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::network::dns::DnsResolver;
use crate::network::geoip::GeoIpInfo;
use crate::network::types::{AddrKind, ApplicationProtocol, Connection, ProcessLineage, Protocol};

pub(super) fn process_lineage_json(lineage: &ProcessLineage) -> Value {
    let ancestors: Vec<Value> = lineage
        .ancestors
        .iter()
        .map(|ancestor| {
            let mut value = Map::new();
            value.insert("pid".to_string(), json!(ancestor.pid));
            value.insert("name".to_string(), json!(ancestor.name));
            if let Some(executable) = &ancestor.executable {
                value.insert(
                    "executable".to_string(),
                    json!(executable.display().to_string()),
                );
            }
            if let Some(started_at_unix_ms) = ancestor.started_at_unix_ms {
                value.insert("started_at_unix_ms".to_string(), json!(started_at_unix_ms));
            }
            Value::Object(value)
        })
        .collect();
    json!({
        "ancestors": ancestors,
        "truncated": lineage.truncated,
    })
}

/// A JSONL writer opened before sandboxing and uid drop.
///
/// Keeping the descriptor open is required for paths such as `/root`: after
/// dropping to the invoking user or `nobody`, the process may no longer be able
/// to traverse the parent directory even when the file itself was chowned.
pub(super) struct JsonLineWriter {
    file: Mutex<File>,
    path: String,
    failure_reported: AtomicBool,
}

impl JsonLineWriter {
    pub(super) fn new(file: File, path: String) -> Self {
        Self {
            file: Mutex::new(file),
            path,
            failure_reported: AtomicBool::new(false),
        }
    }

    pub(super) fn write(&self, value: &serde_json::Value) {
        let result = serde_json::to_string(value)
            .map_err(std::io::Error::other)
            .and_then(|json| {
                let mut file = self
                    .file
                    .lock()
                    .map_err(|_| std::io::Error::other("JSONL writer lock poisoned"))?;
                writeln!(file, "{json}")
            });

        if let Err(e) = result
            && !self.failure_reported.swap(true, Ordering::Relaxed)
        {
            warn!(
                "Failed to write JSONL output '{}': {}. Further write errors will be suppressed.",
                self.path, e
            );
        }
    }
}

/// Address-kind and gateway markers, parameterized on the two key vocabularies
/// (`source_`/`destination_` in the event log, `local_`/`remote_` in the
/// sidecar). Only emitted for broadcast/multicast endpoints, keeping unicast
/// records (and consumers of older logs) unchanged.
fn add_addr_kind_fields(
    event: &mut Value,
    conn: &Connection,
    local_key: &str,
    remote_key: &str,
    gateway_key: &str,
) {
    if conn.local_addr_kind != AddrKind::Unicast {
        event[local_key] = json!(conn.local_addr_kind.as_token());
    }
    if conn.remote_addr_kind != AddrKind::Unicast {
        event[remote_key] = json!(conn.remote_addr_kind.as_token());
    }
    if conn.remote_is_gateway {
        event[gateway_key] = json!(true);
    }
}

/// Rich process-attribution fields shared by the event log and the sidecar:
/// ppid, executable, uid/gid, match quality, lineage, the RTT estimate, and
/// Kubernetes attribution. Both outputs are per connection, not per packet, so
/// the verbose executable path costs nothing here (unlike a PCAPNG packet
/// comment).
fn add_process_fields(event: &mut Value, conn: &Connection) {
    if let Some(ppid) = conn.process_ppid {
        event["process_ppid"] = json!(ppid);
    }
    if let Some(executable) = &conn.executable {
        event["process_executable"] = json!(executable.display().to_string());
    }
    if let Some(uid) = conn.process_uid {
        event["process_uid"] = json!(uid);
    }
    if let Some(gid) = conn.process_gid {
        event["process_gid"] = json!(gid);
    }
    if let Some(quality) = conn.attribution_quality {
        event["attribution_match"] = json!(quality.as_token());
    }
    if let Some(lineage) = &conn.process_lineage {
        event["process_lineage"] = process_lineage_json(lineage);
    }

    // Round-trip estimate: smoothed TCP data RTT, a handshake RTT, or the
    // latest ICMP echo RTT. One decimal of milliseconds.
    if let Some(rtt) = conn.current_rtt() {
        event["rtt_ms"] = json!((rtt.as_secs_f64() * 10_000.0).round() / 10.0);
    }

    // Add Kubernetes attribution if the process is part of a pod
    #[cfg(feature = "kubernetes")]
    if let Some(k8s) = kubernetes_json(conn) {
        event["kubernetes"] = k8s;
    }
}

/// The six-field Kubernetes walk; `None` when no field is populated.
#[cfg(feature = "kubernetes")]
fn kubernetes_json(conn: &Connection) -> Option<Value> {
    let k8s = conn.k8s_info.as_ref()?;
    let mut obj = Map::new();
    if let Some(v) = &k8s.pod_uid {
        obj.insert("pod_uid".into(), json!(v));
    }
    if let Some(v) = &k8s.pod_name {
        obj.insert("pod_name".into(), json!(v));
    }
    if let Some(v) = &k8s.pod_namespace {
        obj.insert("pod_namespace".into(), json!(v));
    }
    if let Some(v) = &k8s.container_id {
        obj.insert("container_id".into(), json!(v));
    }
    if let Some(v) = &k8s.container_name {
        obj.insert("container_name".into(), json!(v));
    }
    if let Some(v) = &k8s.cgroup_path {
        obj.insert("cgroup_path".into(), json!(v));
    }
    (!obj.is_empty()).then(|| Value::Object(obj))
}

/// GeoIP fields, added only when they have actual values.
///
/// The two callers historically inserted `city`/`postal_code` in opposite
/// orders; the serialized output was identical anyway because
/// `serde_json::Map` is a BTreeMap (no `preserve_order` feature), which
/// serializes keys sorted.
fn add_geoip_fields(event: &mut Value, geoip: &GeoIpInfo) {
    if let Some(ref cc) = geoip.country_code {
        event["geoip_country_code"] = json!(cc);
    }
    if let Some(ref name) = geoip.country_name {
        event["geoip_country_name"] = json!(name);
    }
    if let Some(asn) = geoip.asn {
        event["geoip_asn"] = json!(asn);
    }
    if let Some(ref org) = geoip.as_org {
        event["geoip_as_org"] = json!(org);
    }
    if let Some(ref city) = geoip.city {
        event["geoip_city"] = json!(city);
    }
    if let Some(ref postal) = geoip.postal_code {
        event["geoip_postal_code"] = json!(postal);
    }
}

/// Helper function to log connection events as JSON
pub(super) fn log_connection_event(
    writer: &JsonLineWriter,
    event_type: &str,
    conn: &Connection,
    duration_secs: Option<u64>,
    dns_resolver: Option<&DnsResolver>,
) {
    // Build JSON object based on event type
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event": event_type,
        "protocol": conn.protocol.to_string(),
        "source_ip": conn.local_addr.ip().to_string(),
        "source_port": conn.local_addr.port(),
        "destination_ip": conn.remote_addr.ip().to_string(),
        "destination_port": conn.remote_addr.port(),
    });

    add_addr_kind_fields(
        &mut event,
        conn,
        "source_addr_kind",
        "destination_addr_kind",
        "destination_is_gateway",
    );

    // Add hostname fields if DNS resolution is enabled and hostnames are resolved
    // Skip ARP connections to avoid feedback loop (DNS lookups generate ARP traffic)
    if let Some(resolver) = dns_resolver.filter(|_| conn.protocol != Protocol::Arp) {
        if let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip()) {
            event["destination_hostname"] = json!(hostname);
        }
        if let Some(hostname) = resolver.get_hostname(&conn.local_addr.ip()) {
            event["source_hostname"] = json!(hostname);
        }
    }

    // Add process information if available
    if let Some(pid) = conn.pid {
        event["pid"] = json!(pid);
    }
    if let Some(process_name) = &conn.process_name {
        event["process_name"] = json!(process_name);
    }
    add_process_fields(&mut event, conn);

    // Add service name if available
    if let Some(service_name) = &conn.service_name {
        event["service_name"] = json!(service_name);
    }

    // Add connection direction (only for TCP when we observed the handshake)
    if let Some(is_outgoing) = conn.connection_direction {
        event["direction"] = json!(if is_outgoing { "outgoing" } else { "incoming" });
    }

    // Add DPI information if available
    if let Some(dpi) = &conn.dpi_info {
        event["dpi_protocol"] = json!(dpi.application.to_string());

        // Extract domain/hostname from DPI info
        if let Some(domain) = dpi_domain(&dpi.application) {
            event["dpi_domain"] = json!(domain);
        }
    }

    // Add GeoIP information if available
    if let Some(ref geoip) = conn.geoip_info {
        add_geoip_fields(&mut event, geoip);
    }

    // Add connection statistics for closed events
    if event_type == "connection_closed" {
        event["bytes_sent"] = json!(conn.bytes_sent);
        event["bytes_received"] = json!(conn.bytes_received);
        if let Some(duration) = duration_secs {
            event["duration_secs"] = json!(duration);
        }
    }

    writer.write(&event);
}

/// Helper function to log connection info to PCAP sidecar file (JSONL format)
pub(super) fn log_pcap_connection(writer: &JsonLineWriter, conn: &Connection) {
    // Build base event without GeoIP fields
    let mut event = json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "protocol": conn.protocol.to_string(),
        "local_addr": conn.local_addr.to_string(),
        "remote_addr": conn.remote_addr.to_string(),
        "pid": conn.pid,
        "process_name": conn.process_name,
        "first_seen": conn.created_at,
        "last_seen": conn.last_activity,
        "bytes_sent": conn.bytes_sent,
        "bytes_received": conn.bytes_received,
        "state": conn.state(),
    });

    add_addr_kind_fields(
        &mut event,
        conn,
        "local_addr_kind",
        "remote_addr_kind",
        "remote_is_gateway",
    );

    add_process_fields(&mut event, conn);

    if let Some(ref geoip) = conn.geoip_info {
        add_geoip_fields(&mut event, geoip);
    }

    writer.write(&event);
}

/// Domain reported for a connection: DNS query name, or the hostname from
/// the payload (SNI or HTTP Host) for other protocols.
pub(super) fn dpi_domain(application: &ApplicationProtocol) -> Option<&str> {
    match application {
        ApplicationProtocol::Dns(info) => info.query_name.as_deref(),
        _ => application.hostname(),
    }
}
