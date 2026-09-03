//! Serializable wire shapes for the JSONL connection events. The same
//! [`ConnectionRecord`] backs the `new_connection` and `connection_closed`
//! events of `--json-log` and any stream that reports connections, and the
//! `snapshot` event of the headless stream; the PCAP sidecar has its own
//! record with `local_`/`remote_` vocabulary.
//!
//! Optional fields are omitted rather than emitted as `null`, so a consumer
//! of older logs sees the same keys it always did.

use serde::Serialize;
use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use crate::app::App;
use crate::network::dns::DnsResolver;
use crate::network::geoip::GeoIpInfo;
#[cfg(feature = "kubernetes")]
use crate::network::types::K8sInfo;
use crate::network::types::{AddrKind, ApplicationProtocol, Connection, ProcessLineage, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConnectionEventKind {
    NewConnection,
    ConnectionClosed,
}

/// One line of the connection event stream: the envelope plus the
/// connection record, with the traffic totals appended on close.
#[derive(Debug, Serialize)]
pub struct ConnectionEvent<'a> {
    timestamp: String,
    event: ConnectionEventKind,
    #[serde(flatten)]
    record: ConnectionRecord<'a>,
    #[serde(flatten)]
    close: Option<CloseRecord>,
}

#[derive(Debug, Serialize)]
struct CloseRecord {
    bytes_sent: u64,
    bytes_received: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_secs: Option<u64>,
}

impl<'a> ConnectionEvent<'a> {
    pub fn new_connection(conn: &'a Connection, dns_resolver: Option<&DnsResolver>) -> Self {
        Self {
            timestamp: rfc3339_now(),
            event: ConnectionEventKind::NewConnection,
            record: ConnectionRecord::from_connection(conn, dns_resolver),
            close: None,
        }
    }

    /// The close event for a connection archived or timed out at `now`; the
    /// duration is measured from the connection's `created_at`.
    pub fn connection_closed(
        conn: &'a Connection,
        now: SystemTime,
        dns_resolver: Option<&DnsResolver>,
    ) -> Self {
        Self {
            timestamp: rfc3339_now(),
            event: ConnectionEventKind::ConnectionClosed,
            record: ConnectionRecord::from_connection(conn, dns_resolver),
            close: Some(CloseRecord {
                bytes_sent: conn.bytes_sent,
                bytes_received: conn.bytes_received,
                duration_secs: now
                    .duration_since(conn.created_at)
                    .map(|duration| duration.as_secs())
                    .ok(),
            }),
        }
    }
}

/// The events the headless run loop itself emits, as opposed to the
/// per-connection [`ConnectionEventKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RunEventKind {
    Startup,
    Snapshot,
}

/// The first line of a headless stream: what is being captured, how the
/// process is protected, and the options the stream was started with.
#[derive(Debug, Serialize)]
pub struct StartupEvent {
    timestamp: String,
    event: RunEventKind,
    version: &'static str,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
    link_type: String,
    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", feature = "macos-sandbox")
    ))]
    sandbox: &'static str,
    process_detection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_interval_secs: Option<u64>,
}

impl StartupEvent {
    /// Describe a launched `app`; read once the capture device is open and
    /// the sandbox is applied, so the interface, link type, and sandbox
    /// status are final.
    pub fn from_app(app: &App, filter: Option<&str>, snapshot_interval: Option<Duration>) -> Self {
        let (link_type, _is_tunnel) = app.get_link_layer_info();
        Self {
            timestamp: rfc3339_now(),
            event: RunEventKind::Startup,
            version: env!("CARGO_PKG_VERSION"),
            pid: std::process::id(),
            interface: app.get_current_interface(),
            link_type,
            #[cfg(any(
                target_os = "linux",
                target_os = "windows",
                all(target_os = "macos", feature = "macos-sandbox")
            ))]
            sandbox: app.get_sandbox_info().status.label(),
            process_detection: app.get_process_detection_status().method,
            filter: filter.map(str::to_owned),
            snapshot_interval_secs: snapshot_interval.map(|interval| interval.as_secs()),
        }
    }
}

/// The full connection table at one instant, emitted by
/// `--snapshot-interval`.
#[derive(Debug, Serialize)]
pub struct SnapshotEvent<'a> {
    timestamp: String,
    event: RunEventKind,
    connections: Vec<ConnectionRecord<'a>>,
}

impl<'a> SnapshotEvent<'a> {
    pub fn new(connections: &'a [Connection], dns_resolver: Option<&DnsResolver>) -> Self {
        Self {
            timestamp: rfc3339_now(),
            event: RunEventKind::Snapshot,
            connections: connections
                .iter()
                .map(|conn| ConnectionRecord::from_connection(conn, dns_resolver))
                .collect(),
        }
    }
}

/// A connection as the event stream describes it, without an envelope.
#[derive(Debug, Serialize)]
pub struct ConnectionRecord<'a> {
    protocol: &'static str,
    source_ip: IpAddr,
    source_port: u16,
    destination_ip: IpAddr,
    destination_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_addr_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_addr_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_is_gateway: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_name: Option<&'a str>,
    #[serde(flatten)]
    process: ProcessRecord<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpi_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpi_domain: Option<&'a str>,
    #[serde(flatten)]
    geoip: Option<GeoIpRecord<'a>>,
}

impl<'a> ConnectionRecord<'a> {
    /// Build the record, asking the resolver for the endpoint hostnames it
    /// already knows (which also queues the reverse lookups it does not).
    pub fn from_connection(conn: &'a Connection, dns_resolver: Option<&DnsResolver>) -> Self {
        // ARP connections are skipped: DNS lookups generate ARP traffic, so
        // resolving them would feed back on itself.
        let (destination_hostname, source_hostname) =
            match dns_resolver.filter(|_| conn.protocol != Protocol::Arp) {
                Some(resolver) => (
                    resolver.get_hostname(&conn.remote_addr.ip()),
                    resolver.get_hostname(&conn.local_addr.ip()),
                ),
                None => (None, None),
            };

        let dpi = conn.dpi_info.as_ref().map(|dpi| &dpi.application);

        Self {
            protocol: conn.protocol.as_str(),
            source_ip: conn.local_addr.ip(),
            source_port: conn.local_addr.port(),
            destination_ip: conn.remote_addr.ip(),
            destination_port: conn.remote_addr.port(),
            source_addr_kind: addr_kind_marker(conn.local_addr_kind),
            destination_addr_kind: addr_kind_marker(conn.remote_addr_kind),
            destination_is_gateway: conn.remote_is_gateway.then_some(true),
            source_hostname,
            destination_hostname,
            pid: conn.pid,
            process_name: conn.process_name.as_deref(),
            process: ProcessRecord::from_connection(conn),
            service_name: conn.service_name.as_deref(),
            // Direction is only known for TCP when the handshake was observed.
            direction: conn
                .connection_direction
                .map(|is_outgoing| if is_outgoing { "outgoing" } else { "incoming" }),
            dpi_protocol: dpi.map(ToString::to_string),
            dpi_domain: dpi.and_then(dpi_domain),
            geoip: conn.geoip_info.as_ref().map(GeoIpRecord::from_info),
        }
    }
}

/// A connection as the PCAP sidecar describes it, written when the
/// connection closes and for every connection still open at shutdown.
#[derive(Debug, Serialize)]
pub struct PcapSidecarRecord<'a> {
    timestamp: String,
    protocol: &'static str,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    pid: Option<u32>,
    process_name: Option<&'a str>,
    first_seen: SystemTime,
    last_seen: SystemTime,
    bytes_sent: u64,
    bytes_received: u64,
    state: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_addr_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_addr_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remote_is_gateway: Option<bool>,
    #[serde(flatten)]
    process: ProcessRecord<'a>,
    #[serde(flatten)]
    geoip: Option<GeoIpRecord<'a>>,
}

impl<'a> PcapSidecarRecord<'a> {
    pub fn from_connection(conn: &'a Connection) -> Self {
        Self {
            timestamp: rfc3339_now(),
            protocol: conn.protocol.as_str(),
            local_addr: conn.local_addr,
            remote_addr: conn.remote_addr,
            pid: conn.pid,
            process_name: conn.process_name.as_deref(),
            first_seen: conn.created_at,
            last_seen: conn.last_activity,
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            state: conn.state(),
            local_addr_kind: addr_kind_marker(conn.local_addr_kind),
            remote_addr_kind: addr_kind_marker(conn.remote_addr_kind),
            remote_is_gateway: conn.remote_is_gateway.then_some(true),
            process: ProcessRecord::from_connection(conn),
            geoip: conn.geoip_info.as_ref().map(GeoIpRecord::from_info),
        }
    }
}

/// Rich process attribution shared by the event stream and the sidecar:
/// ppid, executable, uid/gid, match quality, lineage, the RTT estimate, and
/// Kubernetes attribution. Both outputs are per connection, not per packet,
/// so the verbose executable path costs nothing here (unlike a PCAPNG packet
/// comment).
#[derive(Debug, Serialize)]
struct ProcessRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    process_ppid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_gid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attribution_match: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_lineage: Option<ProcessLineageRecord<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_ms: Option<f64>,
    #[cfg(feature = "kubernetes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    kubernetes: Option<KubernetesRecord<'a>>,
}

impl<'a> ProcessRecord<'a> {
    fn from_connection(conn: &'a Connection) -> Self {
        Self {
            process_ppid: conn.process_ppid,
            process_executable: conn
                .executable
                .as_ref()
                .map(|executable| executable.display().to_string()),
            process_uid: conn.process_uid,
            process_gid: conn.process_gid,
            attribution_match: conn.attribution_quality.map(|quality| quality.as_token()),
            process_lineage: conn
                .process_lineage
                .as_deref()
                .map(ProcessLineageRecord::from),
            // Smoothed TCP data RTT, a handshake RTT, or the latest ICMP echo
            // RTT, with one decimal of milliseconds.
            rtt_ms: conn
                .current_rtt()
                .map(|rtt| (rtt.as_secs_f64() * 10_000.0).round() / 10.0),
            #[cfg(feature = "kubernetes")]
            kubernetes: conn.k8s_info.as_ref().and_then(KubernetesRecord::from_info),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ProcessLineageRecord<'a> {
    ancestors: Vec<ProcessAncestorRecord<'a>>,
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct ProcessAncestorRecord<'a> {
    pid: u32,
    name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at_unix_ms: Option<u64>,
}

impl<'a> From<&'a ProcessLineage> for ProcessLineageRecord<'a> {
    fn from(lineage: &'a ProcessLineage) -> Self {
        Self {
            ancestors: lineage
                .ancestors
                .iter()
                .map(|ancestor| ProcessAncestorRecord {
                    pid: ancestor.pid,
                    name: &ancestor.name,
                    executable: ancestor
                        .executable
                        .as_ref()
                        .map(|executable| executable.display().to_string()),
                    started_at_unix_ms: ancestor.started_at_unix_ms,
                })
                .collect(),
            truncated: lineage.truncated,
        }
    }
}

/// The Kubernetes attribution block; absent when no field is populated.
#[cfg(feature = "kubernetes")]
#[derive(Debug, Serialize)]
pub struct KubernetesRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_uid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pod_namespace: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    container_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    container_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cgroup_path: Option<&'a str>,
}

#[cfg(feature = "kubernetes")]
impl<'a> KubernetesRecord<'a> {
    pub fn from_info(k8s: &'a K8sInfo) -> Option<Self> {
        let record = Self {
            pod_uid: k8s.pod_uid.as_deref(),
            pod_name: k8s.pod_name.as_deref(),
            pod_namespace: k8s.pod_namespace.as_deref(),
            container_id: k8s.container_id.as_deref(),
            container_name: k8s.container_name.as_deref(),
            cgroup_path: k8s.cgroup_path.as_deref(),
        };
        let populated = [
            record.pod_uid,
            record.pod_name,
            record.pod_namespace,
            record.container_id,
            record.container_name,
            record.cgroup_path,
        ]
        .iter()
        .any(Option::is_some);
        populated.then_some(record)
    }
}

#[derive(Debug, Serialize)]
struct GeoIpRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_country_code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_country_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_as_org: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_city: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_postal_code: Option<&'a str>,
}

impl<'a> GeoIpRecord<'a> {
    fn from_info(geoip: &'a GeoIpInfo) -> Self {
        Self {
            geoip_country_code: geoip.country_code.as_deref(),
            geoip_country_name: geoip.country_name.as_deref(),
            geoip_asn: geoip.asn,
            geoip_as_org: geoip.as_org.as_deref(),
            geoip_city: geoip.city.as_deref(),
            geoip_postal_code: geoip.postal_code.as_deref(),
        }
    }
}

/// Address-kind markers are only emitted for broadcast/multicast endpoints,
/// keeping unicast records (and consumers of older logs) unchanged.
fn addr_kind_marker(kind: AddrKind) -> Option<&'static str> {
    (kind != AddrKind::Unicast).then(|| kind.as_token())
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Domain reported for a connection: DNS query name, or the hostname from
/// the payload (SNI or HTTP Host) for other protocols.
pub fn dpi_domain(application: &ApplicationProtocol) -> Option<&str> {
    match application {
        ApplicationProtocol::Dns(info) => info.query_name.as_deref(),
        _ => application.hostname(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{
        DpiInfo, HttpsInfo, MatchQuality, ProcessAncestor, ProtocolState, TcpState, TlsInfo,
    };
    use serde_json::{Value, json};
    use std::collections::BTreeSet;
    use std::path::PathBuf;
    use std::time::Duration;

    /// The two example lines from the "JSON Logging" section of USAGE.md.
    const USAGE_NEW_CONNECTION: &str = r#"{"timestamp":"2025-01-15T10:30:00Z","event":"new_connection","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","dpi_protocol":"HTTPS (example.com)","dpi_domain":"example.com"}"#;
    const USAGE_CONNECTION_CLOSED: &str = r#"{"timestamp":"2025-01-15T10:30:05Z","event":"connection_closed","protocol":"TCP","source_ip":"192.168.1.100","source_port":54321,"destination_ip":"93.184.216.34","destination_port":443,"pid":1234,"process_name":"curl","service_name":"https","direction":"outgoing","bytes_sent":1024,"bytes_received":4096,"duration_secs":5}"#;

    /// The connection behind the USAGE.md examples: curl talking HTTPS to
    /// example.com, with the handshake observed.
    fn usage_connection() -> Connection {
        let mut conn = Connection::new(
            Protocol::Tcp,
            "192.168.1.100:54321".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.pid = Some(1234);
        conn.process_name = Some("curl".to_string());
        conn.service_name = Some("https".to_string());
        conn.connection_direction = Some(true);
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo::with_sni("example.com".to_string())),
            }),
        });
        conn.bytes_sent = 1024;
        conn.bytes_received = 4096;
        conn
    }

    fn keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("event is a JSON object")
            .keys()
            .cloned()
            .collect()
    }

    fn to_value(event: &ConnectionEvent<'_>) -> Value {
        serde_json::from_str(&serde_json::to_string(event).unwrap()).unwrap()
    }

    #[test]
    fn new_connection_matches_the_documented_example() {
        let conn = usage_connection();
        let event = to_value(&ConnectionEvent::new_connection(&conn, None));
        let expected: Value = serde_json::from_str(USAGE_NEW_CONNECTION).unwrap();

        assert_eq!(keys(&event), keys(&expected));
        for (key, expected_value) in expected.as_object().unwrap() {
            match key.as_str() {
                "timestamp" => assert!(event[key].as_str().unwrap().ends_with("+00:00")),
                _ => assert_eq!(&event[key], expected_value, "field {key}"),
            }
        }
    }

    #[test]
    fn connection_closed_matches_the_documented_example() {
        let conn = usage_connection();
        let closed_at = conn.created_at + Duration::from_secs(5);
        let event = to_value(&ConnectionEvent::connection_closed(&conn, closed_at, None));
        let expected: Value = serde_json::from_str(USAGE_CONNECTION_CLOSED).unwrap();

        // The example omits the DPI fields the fixture carries.
        let mut expected_keys = keys(&expected);
        expected_keys.extend(["dpi_protocol".to_string(), "dpi_domain".to_string()]);
        assert_eq!(keys(&event), expected_keys);
        for (key, expected_value) in expected.as_object().unwrap() {
            if key != "timestamp" {
                assert_eq!(&event[key], expected_value, "field {key}");
            }
        }
    }

    #[test]
    fn unattributed_connection_omits_optional_keys() {
        let mut conn = Connection::new(
            Protocol::Udp,
            "10.0.0.2:5353".parse().unwrap(),
            "10.0.0.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        conn.pid = None;
        conn.process_name = None;
        let event = to_value(&ConnectionEvent::new_connection(&conn, None));

        let expected: BTreeSet<String> = [
            "timestamp",
            "event",
            "protocol",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(keys(&event), expected);
        assert_eq!(event["protocol"], json!("UDP"));
    }

    #[test]
    fn enrichment_fields_keep_their_value_types() {
        let mut conn = usage_connection();
        conn.local_addr_kind = AddrKind::Multicast;
        conn.remote_is_gateway = true;
        conn.process_ppid = Some(1);
        conn.executable = Some(PathBuf::from("/usr/bin/curl").into());
        conn.process_uid = Some(501);
        conn.process_gid = Some(20);
        conn.attribution_quality = Some(MatchQuality::ExactTuple);
        conn.initial_rtt = Some(Duration::from_micros(12_345));
        conn.geoip_info = Some(GeoIpInfo {
            country_code: Some("US".to_string()),
            asn: Some(15169),
            ..GeoIpInfo::default()
        });
        let event = to_value(&ConnectionEvent::new_connection(&conn, None));

        assert_eq!(event["source_addr_kind"], json!("multicast"));
        assert_eq!(event.get("destination_addr_kind"), None);
        assert_eq!(event["destination_is_gateway"], json!(true));
        assert_eq!(event["process_ppid"], json!(1));
        assert_eq!(event["process_executable"], json!("/usr/bin/curl"));
        assert_eq!(event["process_uid"], json!(501));
        assert_eq!(event["process_gid"], json!(20));
        assert_eq!(event["attribution_match"], json!("exact-tuple"));
        assert_eq!(event["rtt_ms"], json!(12.3));
        assert_eq!(event["geoip_country_code"], json!("US"));
        assert_eq!(event["geoip_asn"], json!(15169));
        assert_eq!(event.get("geoip_city"), None);
    }

    #[test]
    fn lineage_json_preserves_process_identity_fields() {
        let lineage = ProcessLineage {
            ancestors: vec![ProcessAncestor {
                pid: 1,
                name: "systemd".to_string(),
                executable: Some(PathBuf::from("/usr/lib/systemd/systemd")),
                started_at_unix_ms: Some(1_700_000_000_000),
            }],
            truncated: true,
        };

        assert_eq!(
            serde_json::to_value(ProcessLineageRecord::from(&lineage)).unwrap(),
            json!({
                "ancestors": [{
                    "pid": 1,
                    "name": "systemd",
                    "executable": "/usr/lib/systemd/systemd",
                    "started_at_unix_ms": 1_700_000_000_000_u64,
                }],
                "truncated": true,
            })
        );
    }

    #[test]
    fn startup_event_describes_the_app_and_its_options() {
        let app = App::new(crate::app::Config::default()).unwrap();
        app.set_current_interface_for_test(Some("en0".to_string()));
        let event: Value = serde_json::to_value(StartupEvent::from_app(
            &app,
            Some("port:443"),
            Some(Duration::from_secs(5)),
        ))
        .unwrap();

        assert_eq!(event["event"], json!("startup"));
        assert_eq!(event["version"], json!(env!("CARGO_PKG_VERSION")));
        assert_eq!(event["pid"], json!(std::process::id()));
        assert_eq!(event["interface"], json!("en0"));
        assert!(event["link_type"].is_string());
        assert!(event["process_detection"].is_string());
        assert_eq!(event["filter"], json!("port:443"));
        assert_eq!(event["snapshot_interval_secs"], json!(5));
        assert!(event["timestamp"].as_str().unwrap().ends_with("+00:00"));
        #[cfg(any(
            target_os = "linux",
            target_os = "windows",
            all(target_os = "macos", feature = "macos-sandbox")
        ))]
        assert_eq!(event["sandbox"], json!("Not applied"));

        let bare: Value = serde_json::to_value(StartupEvent::from_app(&app, None, None)).unwrap();
        assert_eq!(bare.get("filter"), None);
        assert_eq!(bare.get("snapshot_interval_secs"), None);
    }

    #[test]
    fn snapshot_event_wraps_connection_records() {
        let connections = [usage_connection()];
        let event: Value = serde_json::to_value(SnapshotEvent::new(&connections, None)).unwrap();

        assert_eq!(event["event"], json!("snapshot"));
        assert_eq!(event["connections"].as_array().unwrap().len(), 1);
        assert_eq!(event["connections"][0]["process_name"], json!("curl"));
        assert_eq!(event["connections"][0]["destination_port"], json!(443));
        assert_eq!(event["connections"][0].get("bytes_sent"), None);
    }

    #[test]
    fn sidecar_record_keeps_nullable_process_identity() {
        let mut conn = usage_connection();
        conn.pid = None;
        conn.process_name = None;
        let record: Value =
            serde_json::to_value(PcapSidecarRecord::from_connection(&conn)).unwrap();

        assert_eq!(record["protocol"], json!("TCP"));
        assert_eq!(record["local_addr"], json!("192.168.1.100:54321"));
        assert_eq!(record["remote_addr"], json!("93.184.216.34:443"));
        assert_eq!(record["pid"], Value::Null);
        assert_eq!(record["process_name"], Value::Null);
        assert_eq!(record["state"], json!("ESTABLISHED"));
        assert!(record["first_seen"]["secs_since_epoch"].is_u64());
        assert_eq!(record.get("local_addr_kind"), None);
    }
}
