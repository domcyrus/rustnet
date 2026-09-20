//! Versioned wire schema, independent of application internals.

use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

use crate::app::{App, AppStats, StopReport};
use crate::network::types::{AttributionSource, Connection, ConnectionKey};

use super::{SCHEMA_VERSION, TerminationReason};

#[derive(Serialize)]
pub(super) struct SnapshotEnvelope {
    schema_version: u8,
    #[serde(rename = "type")]
    record_type: &'static str,
    timestamp: String,
    runtime: RuntimeSnapshot,
    sandbox: SandboxSnapshot,
    stats: StatsSnapshot,
    filter: Option<String>,
    connection_count: usize,
    connections: Vec<ConnectionSnapshot>,
}

impl SnapshotEnvelope {
    pub(super) fn new(
        app: &App,
        filter_query: Option<&str>,
        phase: RuntimePhase,
        termination_reason: Option<TerminationReason>,
        stop_report: Option<StopReport>,
    ) -> (u64, Self) {
        let filter = filter_query
            .map(str::trim)
            .filter(|query| !query.is_empty());
        let (generation, connections) =
            app.get_filtered_connections_with_generation(filter.unwrap_or_default());
        let mut connections: Vec<_> = connections
            .iter()
            .map(ConnectionSnapshot::from_connection)
            .collect();
        connections.sort_unstable_by(|left, right| left.id.cmp(&right.id));

        (
            generation,
            Self {
                schema_version: SCHEMA_VERSION,
                record_type: "snapshot",
                timestamp: timestamp(SystemTime::now()),
                runtime: RuntimeSnapshot::new(
                    app,
                    generation,
                    phase,
                    termination_reason,
                    stop_report,
                ),
                sandbox: SandboxSnapshot::from_app(app),
                stats: StatsSnapshot::from_stats(&app.get_stats()),
                filter: filter.map(str::to_string),
                connection_count: connections.len(),
                connections,
            },
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum RuntimePhase {
    Starting,
    Running,
    Stopping,
    Stopped,
    StoppedWithErrors,
}

impl RuntimePhase {
    pub(super) const fn after_stop(report: StopReport, failed: bool) -> Self {
        if report.timed_out_workers > 0 {
            Self::Stopping
        } else if failed || report.panicked_workers > 0 || report.output_errors > 0 {
            Self::StoppedWithErrors
        } else {
            Self::Stopped
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::StoppedWithErrors => "stopped_with_errors",
        }
    }
}

#[derive(Serialize)]
struct RuntimeSnapshot {
    status: &'static str,
    snapshot_generation: u64,
    interface: Option<String>,
    capture_status: &'static str,
    capture_error: Option<String>,
    process_detection: ProcessDetectionSnapshot,
    termination_reason: Option<&'static str>,
    shutdown: Option<ShutdownSnapshot>,
}

impl RuntimeSnapshot {
    fn new(
        app: &App,
        generation: u64,
        phase: RuntimePhase,
        termination_reason: Option<TerminationReason>,
        stop_report: Option<StopReport>,
    ) -> Self {
        let capture_error = app.capture_error();
        let process = app.get_process_detection_status();
        Self {
            status: phase.as_str(),
            snapshot_generation: generation,
            interface: app.get_current_interface(),
            capture_status: if capture_error.is_some() {
                "failed"
            } else {
                "healthy"
            },
            capture_error,
            process_detection: ProcessDetectionSnapshot {
                method: process.method,
                degraded: process.is_degraded,
                degradation_reason: process.degradation_reason,
                unavailable_feature: process.unavailable_feature,
            },
            termination_reason: termination_reason.map(TerminationReason::as_str),
            shutdown: stop_report.map(ShutdownSnapshot::from),
        }
    }
}

#[derive(Serialize)]
struct ProcessDetectionSnapshot {
    method: String,
    degraded: bool,
    degradation_reason: Option<String>,
    unavailable_feature: Option<String>,
}

#[derive(Serialize)]
struct ShutdownSnapshot {
    joined_workers: usize,
    panicked_workers: usize,
    timed_out_workers: usize,
    output_errors: u64,
}

impl From<StopReport> for ShutdownSnapshot {
    fn from(report: StopReport) -> Self {
        Self {
            joined_workers: report.joined_workers,
            panicked_workers: report.panicked_workers,
            timed_out_workers: report.timed_out_workers,
            output_errors: report.output_errors,
        }
    }
}

#[derive(Serialize)]
struct SandboxSnapshot {
    status: &'static str,
    message: String,
    filesystem_restricted: bool,
    network_restricted: bool,
    uid_dropped: bool,
}

impl SandboxSnapshot {
    fn from_app(app: &App) -> Self {
        use rustnet_sandbox::SandboxStatus;

        let report = app.sandbox_report();
        let status = match report.status {
            SandboxStatus::FullyEnforced => "fully_enforced",
            SandboxStatus::PartiallyEnforced => "partially_enforced",
            SandboxStatus::NotApplied => "not_applied",
            SandboxStatus::Error => "error",
        };
        Self {
            status,
            message: report.message,
            filesystem_restricted: report.fs_restricted,
            network_restricted: report.net_restricted,
            uid_dropped: report.uid_dropped,
        }
    }
}

#[derive(Serialize)]
struct StatsSnapshot {
    packets_processed: u64,
    packets_dropped: u64,
    capture_packets_dropped: u64,
    interface_packets_dropped: u64,
    pre_attribution_packets: u64,
    connections_tracked: u64,
    total_connections_created: u64,
    total_connections_archived: u64,
    tcp_retransmits: u64,
    tcp_out_of_order: u64,
    tcp_fast_retransmits: u64,
    pcap_records_written: u64,
    pcap_export_errors: u64,
    pcapng_records_queued: u64,
    pcapng_records_written: u64,
    pcapng_records_annotated: u64,
    pcapng_records_unannotated: u64,
    pcapng_records_dropped: u64,
    pcapng_export_errors: u64,
}

impl StatsSnapshot {
    fn from_stats(stats: &AppStats) -> Self {
        let load = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Relaxed);
        Self {
            packets_processed: load(&stats.packets_processed),
            packets_dropped: load(&stats.packets_dropped),
            capture_packets_dropped: load(&stats.capture_packets_dropped),
            interface_packets_dropped: load(&stats.interface_packets_dropped),
            pre_attribution_packets: load(&stats.pre_attribution_packets),
            connections_tracked: load(&stats.connections_tracked),
            total_connections_created: load(&stats.total_connections_created),
            total_connections_archived: load(&stats.total_connections_archived),
            tcp_retransmits: load(&stats.total_tcp_retransmits),
            tcp_out_of_order: load(&stats.total_tcp_out_of_order),
            tcp_fast_retransmits: load(&stats.total_tcp_fast_retransmits),
            pcap_records_written: load(&stats.pcap_records_written),
            pcap_export_errors: load(&stats.pcap_export_errors),
            pcapng_records_queued: load(&stats.pcapng_records_queued),
            pcapng_records_written: load(&stats.pcapng_records_written),
            pcapng_records_annotated: load(&stats.pcapng_records_annotated),
            pcapng_records_unannotated: load(&stats.pcapng_records_unannotated),
            pcapng_records_dropped: load(&stats.pcapng_records_dropped),
            pcapng_export_errors: load(&stats.pcapng_export_errors),
        }
    }
}

#[derive(Serialize)]
struct ConnectionSnapshot {
    id: String,
    protocol: &'static str,
    state: String,
    local: EndpointSnapshot,
    remote: EndpointSnapshot,
    remote_is_gateway: bool,
    direction: Option<&'static str>,
    process: Option<ProcessSnapshot>,
    service: Option<String>,
    application: Option<&'static str>,
    hostname: Option<String>,
    hostname_source: Option<&'static str>,
    traffic: TrafficSnapshot,
    rtt: RttSnapshot,
    geoip: Option<GeoIpSnapshot>,
    kubernetes: Option<KubernetesSnapshot>,
    created_at: String,
    last_activity: String,
    historic: bool,
    closed_at: Option<String>,
}

impl ConnectionSnapshot {
    fn from_connection(connection: &Connection) -> Self {
        let authoritative_hostname = connection.authoritative_hostname();
        let (hostname, hostname_source) = if let Some(hostname) = authoritative_hostname {
            (Some(hostname.to_string()), Some("application"))
        } else if let Some(attributed) = &connection.attributed_hostname {
            let source = match attributed.source {
                AttributionSource::CapturedDns => "captured_dns",
            };
            (Some(attributed.name.clone()), Some(source))
        } else {
            (None, None)
        };

        let process = if connection.pid.is_some()
            || connection.process_ppid.is_some()
            || connection.process_name.is_some()
            || connection.executable.is_some()
            || connection.process_uid.is_some()
            || connection.process_gid.is_some()
            || connection.attribution_quality.is_some()
            || connection.process_lineage.is_some()
        {
            Some(ProcessSnapshot {
                pid: connection.pid,
                ppid: connection.process_ppid,
                name: connection.process_name.clone(),
                executable: connection
                    .executable
                    .as_ref()
                    .map(|path| path.display().to_string()),
                uid: connection.process_uid,
                gid: connection.process_gid,
                attribution_match: connection
                    .attribution_quality
                    .map(|quality| quality.as_token()),
                lineage: connection.process_lineage.as_deref().map(|lineage| {
                    ProcessLineageSnapshot {
                        ancestors: lineage
                            .ancestors
                            .iter()
                            .map(|ancestor| ProcessAncestorSnapshot {
                                pid: ancestor.pid,
                                name: ancestor.name.clone(),
                                executable: ancestor
                                    .executable
                                    .as_ref()
                                    .map(|path| path.display().to_string()),
                                started_at_unix_ms: ancestor.started_at_unix_ms,
                            })
                            .collect(),
                        truncated: lineage.truncated,
                    }
                }),
            })
        } else {
            None
        };

        let geoip = connection.geoip_info.as_ref().and_then(|info| {
            info.has_data().then(|| GeoIpSnapshot {
                country_code: info.country_code.clone(),
                country_name: info.country_name.clone(),
                asn: info.asn,
                as_org: info.as_org.clone(),
                city: info.city.clone(),
                postal_code: info.postal_code.clone(),
            })
        });

        #[cfg(feature = "kubernetes")]
        let kubernetes = connection.k8s_info.as_ref().map(|info| KubernetesSnapshot {
            pod_uid: info.pod_uid.clone(),
            pod_name: info.pod_name.clone(),
            pod_namespace: info.pod_namespace.clone(),
            container_id: info.container_id.clone(),
            container_name: info.container_name.clone(),
            cgroup_path: info.cgroup_path.clone(),
        });
        #[cfg(not(feature = "kubernetes"))]
        let kubernetes = None;

        Self {
            id: connection_id(connection),
            protocol: connection.protocol.as_str(),
            state: connection.state().into_owned(),
            local: EndpointSnapshot {
                ip: connection.local_addr.ip().to_string(),
                port: connection.local_addr.port(),
                address_kind: connection.local_addr_kind.as_token(),
            },
            remote: EndpointSnapshot {
                ip: connection.remote_addr.ip().to_string(),
                port: connection.remote_addr.port(),
                address_kind: connection.remote_addr_kind.as_token(),
            },
            remote_is_gateway: connection.remote_is_gateway,
            direction: connection
                .connection_direction
                .map(|outgoing| if outgoing { "outbound" } else { "inbound" }),
            process,
            service: connection.service_name.clone(),
            application: connection
                .dpi_info
                .as_ref()
                .map(|dpi| dpi.application.sort_key()),
            hostname,
            hostname_source,
            traffic: TrafficSnapshot {
                bytes_sent: connection.bytes_sent,
                bytes_received: connection.bytes_received,
                packets_sent: connection.packets_sent,
                packets_received: connection.packets_received,
                outgoing_bytes_per_second: finite(connection.current_outgoing_rate_bps),
                incoming_bytes_per_second: finite(connection.current_incoming_rate_bps),
            },
            rtt: RttSnapshot {
                current_ms: duration_ms(connection.current_rtt()),
                initial_ms: duration_ms(connection.initial_rtt),
                tcp_smoothed_ms: duration_ms(
                    connection
                        .tcp_analytics
                        .as_ref()
                        .and_then(|analytics| analytics.smoothed_rtt),
                ),
                dns_response_ms: duration_ms(connection.dns_response_time),
                llmnr_response_ms: duration_ms(connection.llmnr_response_time),
                netbios_response_ms: duration_ms(connection.netbios_response_time),
                icmp_echo_ms: duration_ms(connection.icmp_echo_rtt),
                stun_ms: duration_ms(connection.stun_rtt),
                ntp_ms: duration_ms(connection.ntp_rtt),
            },
            geoip,
            kubernetes,
            created_at: timestamp(connection.created_at),
            last_activity: timestamp(connection.last_activity),
            historic: connection.is_historic,
            closed_at: connection.closed_at.map(timestamp),
        }
    }
}

#[derive(Serialize)]
struct EndpointSnapshot {
    ip: String,
    port: u16,
    address_kind: &'static str,
}

#[derive(Serialize)]
struct ProcessSnapshot {
    pid: Option<u32>,
    ppid: Option<u32>,
    name: Option<String>,
    executable: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    attribution_match: Option<&'static str>,
    lineage: Option<ProcessLineageSnapshot>,
}

#[derive(Serialize)]
struct ProcessLineageSnapshot {
    ancestors: Vec<ProcessAncestorSnapshot>,
    truncated: bool,
}

#[derive(Serialize)]
struct ProcessAncestorSnapshot {
    pid: u32,
    name: String,
    executable: Option<String>,
    started_at_unix_ms: Option<u64>,
}

#[derive(Serialize)]
struct TrafficSnapshot {
    bytes_sent: u64,
    bytes_received: u64,
    packets_sent: u64,
    packets_received: u64,
    outgoing_bytes_per_second: Option<f64>,
    incoming_bytes_per_second: Option<f64>,
}

#[derive(Serialize)]
struct RttSnapshot {
    current_ms: Option<f64>,
    initial_ms: Option<f64>,
    tcp_smoothed_ms: Option<f64>,
    dns_response_ms: Option<f64>,
    llmnr_response_ms: Option<f64>,
    netbios_response_ms: Option<f64>,
    icmp_echo_ms: Option<f64>,
    stun_ms: Option<f64>,
    ntp_ms: Option<f64>,
}

#[derive(Serialize)]
struct GeoIpSnapshot {
    country_code: Option<String>,
    country_name: Option<String>,
    asn: Option<u32>,
    as_org: Option<String>,
    city: Option<String>,
    postal_code: Option<String>,
}

#[derive(Serialize)]
struct KubernetesSnapshot {
    pod_uid: Option<String>,
    pod_name: Option<String>,
    pod_namespace: Option<String>,
    container_id: Option<String>,
    container_name: Option<String>,
    cgroup_path: Option<String>,
}

fn timestamp(time: SystemTime) -> String {
    DateTime::<Utc>::from(time).to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn connection_id(connection: &Connection) -> String {
    // Tracker keys distinguish active and archived entries, but a consumer
    // needs one identity throughout a flow's lifetime, including tuple reuse.
    let created = DateTime::<Utc>::from(connection.created_at);
    format!(
        "{}:{}.{:09}",
        ConnectionKey::from_connection(connection),
        created.timestamp(),
        created.timestamp_subsec_nanos(),
    )
}

fn finite(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

fn duration_ms(value: Option<Duration>) -> Option<f64> {
    value.and_then(|duration| finite(duration.as_secs_f64() * 1_000.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headless::{
        shutdown_failure,
        tests::{app_with_connections, object_keys},
    };
    use crate::network::types::{Protocol, ProtocolState, TcpState};

    #[test]
    fn version_one_schema_keys_and_protocol_timings_are_stable() {
        let app = app_with_connections();
        let (_, snapshot) = SnapshotEnvelope::new(&app, None, RuntimePhase::Running, None, None);
        let value = serde_json::to_value(snapshot).unwrap();

        assert_eq!(
            object_keys(&value),
            [
                "connection_count",
                "connections",
                "filter",
                "runtime",
                "sandbox",
                "schema_version",
                "stats",
                "timestamp",
                "type",
            ]
        );
        assert_eq!(
            object_keys(&value["runtime"]),
            [
                "capture_error",
                "capture_status",
                "interface",
                "process_detection",
                "shutdown",
                "snapshot_generation",
                "status",
                "termination_reason",
            ]
        );
        assert_eq!(
            object_keys(&value["runtime"]["process_detection"]),
            [
                "degradation_reason",
                "degraded",
                "method",
                "unavailable_feature",
            ]
        );
        assert_eq!(
            object_keys(&value["sandbox"]),
            [
                "filesystem_restricted",
                "message",
                "network_restricted",
                "status",
                "uid_dropped",
            ]
        );
        assert_eq!(
            object_keys(&value["stats"]),
            [
                "capture_packets_dropped",
                "connections_tracked",
                "interface_packets_dropped",
                "packets_dropped",
                "packets_processed",
                "pcap_export_errors",
                "pcap_records_written",
                "pcapng_export_errors",
                "pcapng_records_annotated",
                "pcapng_records_dropped",
                "pcapng_records_queued",
                "pcapng_records_unannotated",
                "pcapng_records_written",
                "pre_attribution_packets",
                "tcp_fast_retransmits",
                "tcp_out_of_order",
                "tcp_retransmits",
                "total_connections_archived",
                "total_connections_created",
            ]
        );

        let connection = value["connections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|connection| connection["protocol"] == "TCP")
            .unwrap();
        assert_eq!(
            object_keys(connection),
            [
                "application",
                "closed_at",
                "created_at",
                "direction",
                "geoip",
                "historic",
                "hostname",
                "hostname_source",
                "id",
                "kubernetes",
                "last_activity",
                "local",
                "process",
                "protocol",
                "remote",
                "remote_is_gateway",
                "rtt",
                "service",
                "state",
                "traffic",
            ]
        );
        assert_eq!(
            object_keys(&connection["local"]),
            ["address_kind", "ip", "port"]
        );
        assert_eq!(
            object_keys(&connection["remote"]),
            ["address_kind", "ip", "port"]
        );
        assert_eq!(
            object_keys(&connection["process"]),
            [
                "attribution_match",
                "executable",
                "gid",
                "lineage",
                "name",
                "pid",
                "ppid",
                "uid",
            ]
        );
        assert_eq!(
            object_keys(&connection["traffic"]),
            [
                "bytes_received",
                "bytes_sent",
                "incoming_bytes_per_second",
                "outgoing_bytes_per_second",
                "packets_received",
                "packets_sent",
            ]
        );
        assert_eq!(
            object_keys(&connection["rtt"]),
            [
                "current_ms",
                "dns_response_ms",
                "icmp_echo_ms",
                "initial_ms",
                "llmnr_response_ms",
                "netbios_response_ms",
                "ntp_ms",
                "stun_ms",
                "tcp_smoothed_ms",
            ]
        );
        assert_eq!(connection["rtt"]["current_ms"], 18.0);
        assert_eq!(connection["rtt"]["initial_ms"], 11.0);
        assert_eq!(connection["rtt"]["tcp_smoothed_ms"], 18.0);
        assert_eq!(connection["rtt"]["dns_response_ms"], 12.0);
        assert_eq!(connection["rtt"]["llmnr_response_ms"], 13.0);
        assert_eq!(connection["rtt"]["netbios_response_ms"], 14.0);
        assert_eq!(connection["rtt"]["icmp_echo_ms"], 15.0);
        assert_eq!(connection["rtt"]["stun_ms"], 16.0);
        assert_eq!(connection["rtt"]["ntp_ms"], 17.0);
        assert!(connection["traffic"]["outgoing_bytes_per_second"].is_null());
        assert!(connection["traffic"]["incoming_bytes_per_second"].is_null());
        assert_eq!(
            value["connection_count"],
            value["connections"].as_array().unwrap().len()
        );
        assert!(value["filter"].is_null());
        DateTime::parse_from_rfc3339(value["timestamp"].as_str().unwrap()).unwrap();
        let ids: Vec<_> = value["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|connection| connection["id"].as_str().unwrap())
            .collect();
        assert!(ids.windows(2).all(|pair| pair[0] <= pair[1]));

        let lineage = serde_json::to_value(ProcessLineageSnapshot {
            ancestors: vec![ProcessAncestorSnapshot {
                pid: 1,
                name: "init".to_string(),
                executable: None,
                started_at_unix_ms: None,
            }],
            truncated: false,
        })
        .unwrap();
        assert_eq!(object_keys(&lineage), ["ancestors", "truncated"]);
        assert_eq!(
            object_keys(&lineage["ancestors"][0]),
            ["executable", "name", "pid", "started_at_unix_ms"]
        );

        let geoip = serde_json::to_value(GeoIpSnapshot {
            country_code: None,
            country_name: None,
            asn: None,
            as_org: None,
            city: None,
            postal_code: None,
        })
        .unwrap();
        assert_eq!(
            object_keys(&geoip),
            [
                "as_org",
                "asn",
                "city",
                "country_code",
                "country_name",
                "postal_code",
            ]
        );

        let kubernetes = serde_json::to_value(KubernetesSnapshot {
            pod_uid: None,
            pod_name: None,
            pod_namespace: None,
            container_id: None,
            container_name: None,
            cgroup_path: None,
        })
        .unwrap();
        assert_eq!(
            object_keys(&kubernetes),
            [
                "cgroup_path",
                "container_id",
                "container_name",
                "pod_name",
                "pod_namespace",
                "pod_uid",
            ]
        );
    }

    #[test]
    fn connection_identity_survives_archival_and_distinguishes_tuple_reuse() {
        let mut connection = Connection::new(
            Protocol::Tcp,
            "127.0.0.1:45000".parse().unwrap(),
            "93.184.216.34:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );
        connection.created_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let live = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        connection.is_historic = true;
        connection.closed_at = Some(connection.created_at + Duration::from_secs(1));
        let archived =
            serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_eq!(live["id"], archived["id"]);

        connection.is_historic = false;
        connection.closed_at = None;
        connection.created_at += Duration::from_nanos(100);
        let reused =
            serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_ne!(live["id"], reused["id"]);
        assert_eq!(live["local"], reused["local"]);
        assert_eq!(live["remote"], reused["remote"]);
    }

    #[test]
    fn traffic_rates_serialize_explicit_byte_units() {
        let mut connection = Connection::new(
            Protocol::Udp,
            "127.0.0.1:45000".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        connection.current_outgoing_rate_bps = 125.0;
        connection.current_incoming_rate_bps = 250.0;
        let value = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();
        assert_eq!(value["traffic"]["outgoing_bytes_per_second"], 125.0);
        assert_eq!(value["traffic"]["incoming_bytes_per_second"], 250.0);
        assert!(value["traffic"].get("outgoing_rate_bps").is_none());
        assert!(value["traffic"].get("incoming_rate_bps").is_none());
    }

    #[test]
    fn terminal_status_keeps_timed_out_workers_in_stopping_phase() {
        let app = app_with_connections();
        for report in [
            StopReport {
                timed_out_workers: 1,
                ..StopReport::default()
            },
            StopReport {
                timed_out_workers: 1,
                panicked_workers: 1,
                output_errors: 1,
                ..StopReport::default()
            },
        ] {
            let failure = shutdown_failure(report).unwrap();
            let (_, snapshot) = SnapshotEnvelope::new(
                &app,
                None,
                RuntimePhase::after_stop(report, true),
                Some(failure.kind.termination_reason()),
                Some(report),
            );
            let value = serde_json::to_value(snapshot).unwrap();
            assert_eq!(value["runtime"]["status"], "stopping");
            assert_eq!(value["runtime"]["termination_reason"], "runtime_failed");
            assert_eq!(value["runtime"]["shutdown"]["timed_out_workers"], 1);
        }
    }

    #[test]
    fn process_snapshot_keeps_metadata_without_a_pid_name_or_executable() {
        let mut connection = Connection::new(
            Protocol::Udp,
            "127.0.0.1:40000".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        connection.process_ppid = Some(7);

        let value = serde_json::to_value(ConnectionSnapshot::from_connection(&connection)).unwrap();

        assert_eq!(value["process"]["ppid"], 7);
        assert!(value["process"]["pid"].is_null());
        assert!(value["process"]["name"].is_null());
        assert!(value["process"]["executable"].is_null());
    }

    #[test]
    fn whitespace_only_filter_serializes_as_null() {
        let app = app_with_connections();
        let (_, snapshot) =
            SnapshotEnvelope::new(&app, Some(" \t "), RuntimePhase::Running, None, None);
        let value = serde_json::to_value(snapshot).unwrap();

        assert!(value["filter"].is_null());
        assert_eq!(value["connection_count"], 2);
    }
}
