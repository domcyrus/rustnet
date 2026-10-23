//! Shared application and connection fixtures.

pub(crate) mod scratch_dir;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::app::{App, Config};
use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};

/// A capture configuration that starts no background work: no DNS, no
/// GeoIP, no DPI, and a fixed `eth0` interface for the chrome.
pub(crate) fn test_config() -> Config {
    Config {
        interface: Some("eth0".to_string()),
        filter_localhost: false,
        refresh_interval: 1000,
        enable_dpi: false,
        bpf_filter: None,
        json_log_file: None,
        pcap_export_file: None,
        pcapng_export_file: None,
        resolve_dns: false,
        show_ptr_lookups: false,
        geoip_country_path: None,
        geoip_asn_path: None,
        geoip_city_path: None,
        disable_geoip: true,
        #[cfg(feature = "kubernetes")]
        kubernetes_mode: crate::network::kubernetes::KubernetesMode::default(),
    }
}

/// An `App` built from [`test_config`] that has finished loading and
/// reports `eth0` as its capture interface.
pub(crate) fn test_app() -> App {
    let app = App::new(test_config()).expect("App::new in test_config");
    app.set_loading_for_test(false);
    app.set_current_interface_for_test(Some("eth0".to_string()));
    app
}

/// An established TCP connection from `localhost:port` to a TEST-NET
/// address on 443, owned by `process`. Distinct ports give distinct keys.
pub(crate) fn local_tcp(port: u16, process: &str) -> Connection {
    let mut connection = Connection::new(
        Protocol::Tcp,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
        ProtocolState::Tcp(TcpState::Established),
    );
    connection.process_name = Some(process.to_string());
    connection
}
