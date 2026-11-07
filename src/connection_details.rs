//! Shared observed application fields for terminal details and headless consumers.
use crate::network::types::{Connection, HttpInfo, ProtocolState};
use serde::Serialize;

#[derive(PartialEq, Serialize)]
pub(crate) struct DetailField {
    pub label: &'static str,
    pub value: Option<String>,
    pub warning: bool,
}

#[derive(Default)]
struct Fields(Vec<DetailField>);
impl Fields {
    fn app_rows(&mut self, rows: &[(&'static str, Option<String>)]) {
        self.0.extend(rows.iter().map(|(label, value)| DetailField {
            label,
            value: value.clone(),
            warning: false,
        }));
    }
}

pub(crate) fn application_fields(conn: &Connection) -> Vec<DetailField> {
    let mut details = Fields::default();
    if let Some(dpi) = &conn.dpi_info {
        match &dpi.application {
            crate::network::types::ApplicationProtocol::Http(info) => {
                details.app_rows(&[
                    ("HTTP Version", Some(info.version.to_string())),
                    ("HTTP Method", info.method.clone()),
                    ("HTTP Host", info.host.clone()),
                    ("HTTP Path", info.path.clone()),
                    ("HTTP Status", format_http_status(info)),
                    ("User-Agent", info.user_agent.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Https(info) => {
                let tls = info.tls_info.as_ref();
                details.app_rows(&[
                    ("SNI", tls.and_then(|t| t.sni.clone())),
                    (
                        "ALPN",
                        tls.and_then(|t| (!t.alpn.is_empty()).then(|| t.alpn.join(", "))),
                    ),
                    (
                        "TLS Version",
                        tls.and_then(|t| t.version.map(|v| v.to_string())),
                    ),
                ]);
                details.app_rows(&[("Cipher Suite", tls.and_then(|t| t.format_cipher_suite()))]);
                if let Some(field) = details.0.last_mut() {
                    field.warning = tls.and_then(|t| t.is_cipher_suite_secure()) == Some(false);
                }
            }
            crate::network::types::ApplicationProtocol::Dns(info) => {
                details.app_rows(&[
                    ("DNS Query", info.query_name.clone()),
                    ("DNS Type", info.query_type.map(|t| t.to_string())),
                    ("DNS Response IPs", join_ips(&info.response_ips)),
                    (
                        "DNS Answer",
                        (info.nodata == Some(true))
                            .then(|| "no data (name exists, no record of this type)".to_string()),
                    ),
                    ("Transaction ID", Some(format!("0x{:04x}", info.txid))),
                ]);
            }
            crate::network::types::ApplicationProtocol::Quic(info) => {
                let tls = info.tls_info.as_ref();
                details.app_rows(&[
                    ("QUIC SNI", tls.and_then(|t| t.sni.clone())),
                    (
                        "QUIC ALPN",
                        tls.and_then(|t| (!t.alpn.is_empty()).then(|| t.alpn.join(", "))),
                    ),
                    (
                        "QUIC Version",
                        info.version_string.as_deref().map(str::to_owned),
                    ),
                    ("Connection ID", info.connection_id_hex.clone()),
                    ("Packet Type", Some(info.packet_type.to_string())),
                    ("Connection State", Some(info.connection_state.to_string())),
                ]);
            }
            crate::network::types::ApplicationProtocol::Ssh(info) => {
                details.app_rows(&[
                    ("SSH Version", info.version.as_ref().map(|v| v.to_string())),
                    ("Connection State", Some(info.connection_state.to_string())),
                    ("Server Software", info.server_software.clone()),
                    ("Client Software", info.client_software.clone()),
                    (
                        "Algorithms",
                        (!info.algorithms.is_empty()).then(|| info.algorithms.join(", ")),
                    ),
                    ("Auth Method", info.auth_method.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Ntp(info) => {
                details.app_rows(&[
                    ("NTP Version", Some(info.version.to_string())),
                    ("NTP Mode", Some(info.mode.to_string())),
                    (
                        "Stratum",
                        (info.stratum != 0).then(|| info.stratum.to_string()),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::Mdns(info) => {
                details.app_rows(&name_service_rows(
                    info.query_name.as_ref(),
                    info.query_type.as_ref(),
                    &info.response_ips,
                ));
            }
            crate::network::types::ApplicationProtocol::Llmnr(info) => {
                let [name, query_type, ips] = name_service_rows(
                    info.query_name.as_ref(),
                    info.query_type.as_ref(),
                    &info.response_ips,
                );
                details.app_rows(&[
                    name,
                    query_type,
                    ips,
                    ("Transaction ID", Some(format!("0x{:04x}", info.txid))),
                ]);
            }
            crate::network::types::ApplicationProtocol::Dhcp(info) => {
                details.app_rows(&[
                    ("Message Type", Some(info.message_type.to_string())),
                    ("Hostname", info.hostname.clone()),
                    ("Client MAC", info.client_mac.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Snmp(info) => {
                details.app_rows(&[
                    ("SNMP Version", Some(info.version.to_string())),
                    ("PDU Type", Some(info.pdu_type.to_string())),
                    ("Community", info.community.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Ssdp(info) => {
                details.app_rows(&[
                    ("Method", Some(info.method.to_string())),
                    ("Service Type", info.service_type.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::NetBios(info) => {
                details.app_rows(&[
                    ("Service", Some(info.service.to_string())),
                    ("Opcode", Some(info.opcode.to_string())),
                    ("Name", info.name.clone()),
                    (
                        "Transaction ID",
                        Some(format!("0x{:04x}", info.transaction_id)),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::BitTorrent(info) => {
                let extensions: Vec<&str> = [
                    (info.supports_dht, "DHT"),
                    (info.supports_extension, "Extension Protocol"),
                    (info.supports_fast, "Fast"),
                ]
                .into_iter()
                .filter_map(|(supported, name)| supported.then_some(name))
                .collect();
                details.app_rows(&[
                    ("Type", Some(info.protocol_type.to_string())),
                    ("Client", info.client.clone()),
                    ("Info Hash", info.info_hash.clone()),
                    ("DHT Method", info.dht_method.clone()),
                    (
                        "Extensions",
                        (!extensions.is_empty()).then(|| extensions.join(", ")),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::Stun(info) => {
                details.app_rows(&[
                    ("Method", Some(info.method.to_string())),
                    ("Class", Some(info.message_class.to_string())),
                    (
                        "Transaction ID",
                        Some(crate::network::util::hex_encode(&info.transaction_id, "")),
                    ),
                    ("Software", info.software.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::MySql(info) => {
                details.app_rows(&[
                    ("Server Version", info.server_version.clone()),
                    ("Connection ID", info.connection_id.map(|id| id.to_string())),
                    (
                        "TLS Advertised",
                        info.tls_supported
                            .map(|yes| if yes { "Yes" } else { "No" }.to_string()),
                    ),
                    (
                        "TLS Request",
                        info.tls_requested.then(|| "Observed".to_string()),
                    ),
                    (
                        "SNI",
                        info.tls_info.as_ref().and_then(|tls| tls.sni.clone()),
                    ),
                    (
                        "TLS Version",
                        info.tls_info
                            .as_ref()
                            .and_then(|tls| tls.version.map(|v| v.to_string())),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::Redis(info) => {
                details.app_rows(&[
                    ("Command", Some(info.command.clone())),
                    (
                        "Requested RESP",
                        info.requested_version.map(|v| v.to_string()),
                    ),
                    (
                        "Requested DB",
                        info.requested_database.map(|db| db.to_string()),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::PostgreSql(info) => {
                details.app_rows(&[
                    (
                        "Startup Version",
                        info.protocol_minor.map(|v| format!("3.{v}")),
                    ),
                    ("Database", info.database.clone()),
                    ("Client App", info.application_name.clone()),
                    (
                        "TLS Request",
                        info.tls_requested.then(|| "Observed".to_string()),
                    ),
                    (
                        "SNI",
                        info.tls_info.as_ref().and_then(|tls| tls.sni.clone()),
                    ),
                    (
                        "TLS Version",
                        info.tls_info
                            .as_ref()
                            .and_then(|tls| tls.version.map(|v| v.to_string())),
                    ),
                ]);
            }
            crate::network::types::ApplicationProtocol::Ftp(info) => {
                let response = match (info.response_code, &info.response_message) {
                    (Some(code), Some(message)) => Some(format!("{} {}", code, message)),
                    (Some(code), None) => Some(code.to_string()),
                    (None, Some(message)) => Some(message.clone()),
                    (None, None) => None,
                };
                details.app_rows(&[
                    ("Message Type", Some(info.message_type.to_string())),
                    ("Command", info.command.clone()),
                    ("Arguments", info.args.clone()),
                    ("Response", response),
                    ("Username", info.username.clone()),
                    ("Server Software", info.server_software.clone()),
                    ("System Type", info.system_type.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Mqtt(info) => {
                details.app_rows(&[
                    ("Packet Type", Some(info.packet_type.to_string())),
                    ("Version", info.version.map(|v| v.to_string())),
                    ("Client ID", info.client_id.clone()),
                    ("Topic", info.topic.clone()),
                    ("QoS", info.qos.map(|q| q.to_string())),
                ]);
            }
            crate::network::types::ApplicationProtocol::WireGuard(info) => {
                details.app_rows(&[("Packet Type", Some(info.packet_type.to_string()))]);
            }
            crate::network::types::ApplicationProtocol::OpenVpn(info) => {
                details.app_rows(&[
                    ("Packet Type", Some(info.packet_type.to_string())),
                    ("Key ID", Some(info.key_id.to_string())),
                ]);
            }
        }
    } else if let ProtocolState::Arp(info) = &conn.protocol_state {
        details.app_rows(&[
            (
                "Operation",
                Some(
                    match info.operation {
                        crate::network::types::ArpOperation::Request => "Request",
                        crate::network::types::ArpOperation::Reply => "Reply",
                    }
                    .to_string(),
                ),
            ),
            ("Sender MAC", Some(info.sender_mac.clone())),
            ("Sender Vendor", info.sender_vendor.clone()),
            ("Sender IP", Some(info.sender_ip.to_string())),
            ("Target MAC", Some(info.target_mac.clone())),
            ("Target Vendor", info.target_vendor.clone()),
            ("Target IP", Some(info.target_ip.to_string())),
        ]);
    } else if let ProtocolState::Icmp {
        icmp_type,
        icmp_id,
        icmp_sequence,
        ndp_neighbor,
    } = &conn.protocol_state
    {
        let is_ipv6 = conn.local_addr.is_ipv6();
        let neighbor = ndp_neighbor.as_ref().map(|n| match &n.vendor {
            Some(vendor) => format!("{} at {} ({})", n.ip, n.mac, vendor),
            None => format!("{} at {}", n.ip, n.mac),
        });
        details.app_rows(&[
            (
                "Message",
                Some(crate::network::types::icmp_message_name(*icmp_type, is_ipv6).into_owned()),
            ),
            ("Echo ID", icmp_id.map(|id| id.to_string())),
            ("Sequence", icmp_sequence.map(|seq| seq.to_string())),
            ("NDP Neighbor", neighbor),
        ]);
    } else if let ProtocolState::Igmp {
        igmp_type,
        group_addr,
    } = &conn.protocol_state
    {
        details.app_rows(&[
            (
                "Message",
                Some(crate::network::types::igmp_message_name(*igmp_type).into_owned()),
            ),
            ("Group Address", group_addr.map(|addr| addr.to_string())),
        ]);
    } else {
        details.app_rows(&[("Detected", None)]);
    }

    details.0
}

/// Comma-joined display form of a response-IP list, `None` when empty so the
/// Application card renders its placeholder instead of `[]`-style debug
/// output.
fn join_ips(ips: &[std::net::IpAddr]) -> Option<String> {
    (!ips.is_empty()).then(|| {
        ips.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    })
}

/// Shared Application-card row set for the name-service protocols whose info
/// structs carry identical fields (mDNS and LLMNR are distinct types with the
/// same query/response shape).
fn name_service_rows(
    query_name: Option<&String>,
    query_type: Option<&crate::network::types::DnsQueryType>,
    response_ips: &[std::net::IpAddr],
) -> [(&'static str, Option<String>); 3] {
    [
        ("Query Name", query_name.cloned()),
        ("Query Type", query_type.map(|t| t.to_string())),
        ("Response IPs", join_ips(response_ips)),
    ]
}

/// Outcomes that accompany protocol timing and request counters.
pub(crate) fn health_fields(conn: &Connection) -> Vec<DetailField> {
    use crate::network::types::ApplicationProtocol;
    let mut fields = Fields::default();
    match conn.dpi_info.as_ref().map(|d| &d.application) {
        Some(ApplicationProtocol::Quic(q)) => fields.app_rows(&[
            (
                "Idle timeout",
                q.idle_timeout.map(|d| format!("{} s", d.as_secs_f64())),
            ),
            (
                "Connection close",
                q.connection_close.as_ref().map(|c| {
                    format!(
                        "{} 0x{:x}",
                        if c.frame_type == 0x1d {
                            "application"
                        } else {
                            "transport"
                        },
                        c.error_code
                    )
                }),
            ),
        ]),
        Some(ApplicationProtocol::Dns(d)) => fields.app_rows(&[(
            "Last response code",
            d.rcode
                .map(|code| crate::network::types::dns_rcode_name(code).into_owned()),
        )]),
        Some(ApplicationProtocol::NetBios(n)) => fields.app_rows(&[(
            "Last response status",
            n.response_status.map(|status| status.to_string()),
        )]),
        _ => {}
    }
    fields.0
}

/// Preserve the observed token and flag malformed values only in the display.
fn format_http_status(info: &HttpInfo) -> Option<String> {
    let Some(token) = info.status_token.as_deref() else {
        return info.status_code.map(|code| code.to_string());
    };
    let valid = token.len() == 3
        && token.bytes().all(|byte| byte.is_ascii_digit())
        && token
            .parse::<u16>()
            .is_ok_and(|code| (100..=599).contains(&code));
    Some(if valid {
        token.to_string()
    } else {
        format!("{token} (invalid format)")
    })
}

#[cfg(test)]
mod http_status_tests {
    use super::format_http_status;
    use crate::network::types::{HttpInfo, HttpVersion};

    #[test]
    fn observed_http_status_checks_format_and_range_only_for_display() {
        let mut info = HttpInfo {
            version: HttpVersion::Http11,
            method: None,
            host: None,
            path: None,
            status_code: Some(200),
            status_token: None,
            user_agent: None,
        };
        for token in ["100", "200", "599"] {
            info.status_token = Some(token.to_string());
            assert_eq!(format_http_status(&info).as_deref(), Some(token));
        }
        for token in ["+200", "0200", "099", "600", "20", "OK", "２００"] {
            info.status_token = Some(token.to_string());
            assert_eq!(
                format_http_status(&info),
                Some(format!("{token} (invalid format)"))
            );
        }
        info.status_token = None;
        assert_eq!(format_http_status(&info).as_deref(), Some("200"));
        info.status_code = None;
        assert_eq!(format_http_status(&info), None);
    }
}
