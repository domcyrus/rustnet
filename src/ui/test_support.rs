//! Shared fixtures for the UI test modules: headless rendering into a
//! `TestBackend`, span/line text extraction, a thread-free `App`, and the
//! plain TCP connection most handler and navigation tests operate on.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ratatui::{
    Frame, Terminal,
    backend::TestBackend,
    buffer::Buffer,
    text::{Line, Span},
};

use crate::app::{App, Config};
use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};
use crate::ui::{ClickableRegions, HandlerContext, UiState};

/// Render a closure into a `width × height` test buffer and return the
/// buffer for cell-level inspection.
pub(crate) fn render_buffer<F>(width: u16, height: u16, draw: F) -> Buffer
where
    F: FnOnce(&mut Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("create test terminal");
    terminal.draw(draw).expect("draw frame");
    terminal.backend().buffer().clone()
}

/// Render a closure into a `width × height` test buffer and return a
/// plain-text dump (one line per row, no trailing whitespace trim).
pub(crate) fn render<F>(width: u16, height: u16, draw: F) -> String
where
    F: FnOnce(&mut Frame),
{
    buffer_to_string(&render_buffer(width, height, draw))
}

/// Plain-text dump of a buffer: cell symbols only, one line per row.
pub(crate) fn buffer_to_string(buffer: &Buffer) -> String {
    let area = buffer.area;
    let mut out = String::with_capacity((area.width as usize + 1) * area.height as usize);
    for y in 0..area.height {
        for x in 0..area.width {
            out.push_str(buffer[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// The concatenated text of a span run, styles dropped.
pub(crate) fn spans_text(spans: &[Span<'_>]) -> String {
    spans.iter().map(|span| span.content.as_ref()).collect()
}

/// The concatenated text of a line, styles dropped.
pub(crate) fn line_text(line: &Line<'_>) -> String {
    spans_text(&line.spans)
}

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
        show_startup_splash: true,
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

/// A handler context over an empty, ungrouped connection list.
pub(crate) fn empty_ctx<'a>(
    app: &'a App,
    ui_state: &'a mut UiState,
    click_regions: &'a ClickableRegions,
) -> HandlerContext<'a> {
    HandlerContext {
        app,
        ui_state,
        connections: &[],
        grouped_rows: None,
        click_regions,
    }
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
