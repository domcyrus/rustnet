//! Details tab — full record for the selected connection: protocol
//! header, TCP analytics, traffic stats, and protocol-specific DPI
//! info. Also owns the push_detail_field / register_detail_clicks
//! helpers that build the label/value lines and the click-to-copy
//! registry.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

use crossterm::event::{KeyEvent, MouseEvent};

use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, Protocol, ProtocolState};
use crate::ui::{
    ClickAction, ClickableRegions, Component, ComponentContext, Effect, GroupedRow, HandlerContext,
    NONE_PLACEHOLDER,
    connection_table::{build_header, column_constraints, connection_row, select_columns},
    dpi_color,
    format::{format_bytes, format_rate},
    section_header, state_color, theme, try_handle_connection_nav,
};

/// Padded width for detail labels so values line up vertically.
/// Sized for the longest expected label ("Out-of-Order Packets" = 20 chars)
/// plus 2 chars of breathing room before the value column.
const DETAIL_LABEL_WIDTH: usize = 22;

/// Below this terminal width the Details info panes collapse back to a
/// single column. With label width 22 plus reasonable values, ~50 cells
/// per side is the readable floor.
const DETAILS_SPLIT_MIN_WIDTH: u16 = 100;

/// Details tab. Pulls DNS resolver per-render from the app — no
/// per-tab state today.
pub(in crate::ui) struct DetailsTab;

impl Component for DetailsTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_connection_details(f, ctx, area, click_regions)
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        // In grouped mode, flip through the grouped view's connection
        // sequence, skipping group headers — a header has no record to
        // show on this tab. Falls through to the shared flat-list
        // helper when grouping is off (or the sequence is empty).
        if let Some(effects) = try_handle_grouped_details_nav(key, ctx) {
            return Some(effects);
        }
        // Connection navigation flips which record is shown; 'c'
        // copies its remote address. Shared with OverviewTab via
        // try_handle_connection_nav so both stay in lockstep.
        try_handle_connection_nav(key, ctx)
    }

    fn handle_mouse(
        &mut self,
        _mouse: MouseEvent,
        _ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        // No tab-specific mouse handling beyond what the global
        // ClickableRegions dispatch in main.rs already does (the
        // 'click a field to copy' CopyField regions are registered
        // during draw and routed there).
        None
    }
}

fn push_detail_field<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    label: &str,
    value: String,
    label_style: Style,
) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH),
            label_style,
        ),
        Span::raw(value.clone()),
    ]));
    fields.push(Some((label.to_string(), value)));
}

/// Push a label-value line with a custom-styled value span.
fn push_detail_field_styled<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    label: &str,
    value: String,
    label_style: Style,
    value_style: Style,
) {
    lines.push(Line::from(vec![
        Span::styled(
            format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH),
            label_style,
        ),
        Span::styled(value.clone(), value_style),
    ]));
    fields.push(Some((label.to_string(), value)));
}

/// True when a line is empty (used to trim leading separator on the right pane).
fn line_is_blank(line: &Line<'_>) -> bool {
    line.spans.iter().all(|s| s.content.is_empty())
}

/// Register one click-to-copy region per non-empty field row in a Details
/// pane. `inner` is the pane's *content* rect (the panes are borderless,
/// so callers pass the area the text actually renders into).
/// `skip_placeholder_values` mirrors the existing connection-info
/// behavior of skipping NONE_PLACEHOLDER / empty values.
fn register_detail_clicks(
    click_regions: &mut ClickableRegions,
    inner: Rect,
    fields: &[Option<(String, String)>],
    skip_placeholder_values: bool,
) {
    for (line_idx, entry) in fields.iter().enumerate() {
        if let Some((label, value)) = entry {
            if skip_placeholder_values && (value == NONE_PLACEHOLDER || value.is_empty()) {
                continue;
            }
            let row_y = inner.y + line_idx as u16;
            if row_y >= inner.y + inner.height {
                break;
            }
            let line_rect = Rect::new(inner.x, row_y, inner.width, 1);
            click_regions.register(
                line_rect,
                ClickAction::CopyField {
                    label: label.clone(),
                    value: value.clone(),
                },
            );
        }
    }
}

/// Push a bold section heading, used to group fields under a common label
/// (e.g. "Geolocation", "Application: HTTPS"). Pushes a `None` field entry
/// so click-to-copy hit-testing skips this row.
fn push_detail_section<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    title: impl Into<String>,
) {
    push_detail_section_styled(lines, fields, title, theme::bold_fg(theme::heading()));
}

/// Variant of `push_detail_section` that lets the caller pick the heading
/// style. Used by the Application section so its title takes the protocol's
/// own color (HTTPS green, QUIC cyan, etc.) and visually links to the
/// matching Application cell in the Overview table.
fn push_detail_section_styled<'a>(
    lines: &mut Vec<Line<'a>>,
    fields: &mut Vec<Option<(String, String)>>,
    title: impl Into<String>,
    style: Style,
) {
    lines.push(Line::from(""));
    fields.push(None);
    lines.push(Line::from(Span::styled(title.into(), style)));
    fields.push(None);
}

/// Height of the continuity strip: column header (1) + header margin (1)
/// + up to [`STRIP_ROWS`] connection rows + a blank separator row.
const STRIP_HEIGHT: u16 = 6;
/// Number of neighbor rows shown in the continuity strip.
const STRIP_ROWS: usize = 3;

/// Connection-row navigation for grouped mode: walks the grouped
/// view's connection sequence directly, skipping group headers. The
/// shared `try_handle_connection_nav` helper moves row-by-row through
/// `grouped_rows`, which is right for Overview but would land on
/// headers here. Claims only the navigation keys; everything else
/// (e.g. 'c' copy) returns `None` for the caller to handle.
fn try_handle_grouped_details_nav(
    key: KeyEvent,
    ctx: &mut HandlerContext<'_>,
) -> Option<Vec<Effect>> {
    use crossterm::event::{KeyCode, KeyModifiers};

    if !ctx.ui_state.grouping_enabled {
        return None;
    }
    let rows = ctx.grouped_rows?;
    // Indices of the Connection rows within grouped_rows, in display
    // order (children of collapsed groups are absent, matching the
    // Overview screen the user navigated from).
    let indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter_map(|(idx, row)| matches!(row, GroupedRow::Connection { .. }).then_some(idx))
        .collect();
    if indices.is_empty() {
        return None;
    }

    let current = ctx.ui_state.selected_connection_key.as_deref().and_then(|key| {
        indices.iter().position(|&idx| {
            matches!(&rows[idx], GroupedRow::Connection { connection, .. } if connection.key() == key)
        })
    });

    let len = indices.len();
    let page = ctx.ui_state.visible_rows.max(1);
    let target = match (key.code, key.modifiers) {
        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => match current {
            Some(0) | None => len - 1, // wrap to bottom
            Some(pos) => pos - 1,
        },
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => match current {
            Some(pos) if pos + 1 < len => pos + 1,
            _ => 0, // wrap to top
        },
        (KeyCode::PageUp, _) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
            current.unwrap_or(0).saturating_sub(page)
        }
        (KeyCode::PageDown, _) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
            (current.unwrap_or(0) + page).min(len - 1)
        }
        (KeyCode::Char('g'), KeyModifiers::NONE) => 0,
        (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) => len - 1,
        _ => return None,
    };
    ctx.ui_state
        .set_selected_grouped_by_index(rows, indices[target]);
    Some(Vec::new())
}

/// Mini connection table at the top of Details: the selected row plus
/// its neighbors, rendered with the exact same columns and styling as
/// the Overview table. This is what makes Details read as a zoom into
/// the list (j/k flips through neighbors without leaving the tab;
/// clicking a strip row selects it). The neighbors come from whatever
/// j/k navigates here: the grouped view's connection sequence when
/// grouping is on, the flat list otherwise.
fn draw_connection_strip(
    f: &mut Frame,
    ctx: &ComponentContext<'_>,
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    let ui_state = ctx.ui_state;
    let connections = ctx.connections;

    // Grouped mode: window over the grouped connection sequence. Falls
    // back to the flat list when the selection isn't in the sequence
    // (e.g. its group is collapsed).
    let grouped: Option<(Vec<&Connection>, usize)> = if ui_state.grouping_enabled {
        ctx.grouped_rows.and_then(|rows| {
            let sequence: Vec<&Connection> = rows
                .iter()
                .filter_map(|row| match row {
                    GroupedRow::Connection { connection, .. } => Some(*connection),
                    GroupedRow::Group { .. } => None,
                })
                .collect();
            let selected = ui_state
                .selected_connection_key
                .as_deref()
                .and_then(|key| sequence.iter().position(|c| c.key() == key))?;
            Some((sequence, selected))
        })
    } else {
        None
    };
    let (sequence, selected) = grouped.unwrap_or_else(|| {
        (
            connections.iter().collect(),
            ui_state.get_selected_index(connections).unwrap_or(0),
        )
    });

    let len = sequence.len();
    let window_size = STRIP_ROWS.min(len);
    // Center the selection where possible, clamped at the list edges.
    let start = selected
        .saturating_sub(1)
        .min(len.saturating_sub(window_size));
    let window = &sequence[start..start + window_size];

    let columns = select_columns(area.width, show_location);
    let widths = column_constraints(&columns);
    let header = build_header(&columns, ui_state);

    let rows: Vec<ratatui::widgets::Row> = window
        .iter()
        .map(|conn| connection_row(conn, &columns, ui_state, dns_resolver, None))
        .collect();

    let mut state = ratatui::widgets::TableState::default();
    state.select(Some(selected - start));

    let table = ratatui::widgets::Table::new(rows, &widths)
        .header(header)
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");
    f.render_stateful_widget(table, area, &mut state);

    let header_height = 2_u16; // column header (1) + bottom margin (1)
    for (i, conn) in window.iter().enumerate() {
        let row_y = area.y + header_height + i as u16;
        if row_y >= area.y + area.height {
            break;
        }
        click_regions.register(
            Rect::new(area.x, row_y, area.width, 1),
            ClickAction::SelectConnectionKey(conn.key()),
        );
    }
}

pub(in crate::ui) fn draw_connection_details(
    f: &mut Frame,
    ctx: &ComponentContext<'_>,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    let ui_state = ctx.ui_state;
    let connections = ctx.connections;
    let resolver = ctx.app.get_dns_resolver();
    let dns_resolver = resolver.as_deref();
    let (has_country_db, _has_asn_db, _has_city_db) = ctx.app.get_geoip_status();

    if connections.is_empty() {
        return Ok(());
    }

    let conn_idx = ui_state.get_selected_index(connections).unwrap_or(0);
    let conn = &connections[conn_idx];

    // Top: the continuity strip (same grid as Overview). Bottom: Traffic
    // Statistics with a fixed shape (spacer + header + 6 rows). The
    // connection information pane takes everything in between, which
    // fits more of the per-protocol DPI fields without wrapping.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(STRIP_HEIGHT),
            Constraint::Min(0),
            Constraint::Length(8),
        ])
        .split(area);

    let strip_area = Rect::new(
        chunks[0].x,
        chunks[0].y,
        chunks[0].width,
        chunks[0].height.saturating_sub(1), // trailing blank separator row
    );
    draw_connection_strip(
        f,
        ctx,
        strip_area,
        dns_resolver,
        has_country_db,
        click_regions,
    );
    // Re-point the info/traffic split at the remaining chunks.
    let chunks = [chunks[1], chunks[2]];

    // Connection details - build lines and field entries in parallel for click-to-copy.
    // All sections share a single label_style (muted gray); visual grouping comes
    // from the bold section headings inserted by push_detail_section.
    let label_style = theme::fg(theme::label());
    let mut details_text: Vec<Line> = Vec::new();
    let mut detail_fields: Vec<Option<(String, String)>> = Vec::new();
    // Index ranges in details_text/detail_fields that should move to the
    // right pane when the layout splits horizontally (Application/DPI fields,
    // TCP Analytics + RTT). Pushed in source order; drained in reverse later.
    let mut right_ranges: Vec<std::ops::Range<usize>> = Vec::new();

    push_detail_field(
        &mut details_text,
        &mut detail_fields,
        "Protocol",
        conn.protocol.to_string(),
        label_style,
    );
    if conn.is_historic {
        let closed_display = if let Some(closed_at) = conn.closed_at {
            let ago = closed_at.elapsed().unwrap_or_default();
            if ago.as_secs() < 60 {
                format!("Closed ({}s ago)", ago.as_secs())
            } else {
                format!("Closed ({}m ago)", ago.as_secs() / 60)
            }
        } else {
            "Closed".to_string()
        };
        push_detail_field_styled(
            &mut details_text,
            &mut detail_fields,
            "Status",
            closed_display,
            label_style,
            theme::fg(theme::muted()),
        );
    } else {
        // Mirror the historic Status line for active connections so the
        // user can see how recently traffic moved on this connection.
        // Color follows the same staleness buckets as the Overview row
        // styling so the cue is consistent across views.
        let ago = conn.last_activity.elapsed().unwrap_or_default();
        let active_display = if ago.as_secs() < 60 {
            format!("Active (last seen {}s ago)", ago.as_secs())
        } else {
            format!("Active (last seen {}m ago)", ago.as_secs() / 60)
        };
        let staleness = conn.staleness_ratio();
        let active_color = if staleness >= 0.90 {
            theme::err()
        } else if staleness >= 0.75 {
            theme::warn()
        } else {
            theme::ok()
        };
        push_detail_field_styled(
            &mut details_text,
            &mut detail_fields,
            "Status",
            active_display,
            label_style,
            theme::fg(active_color),
        );
    }
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Local Address",
        conn.local_addr.to_string(),
        label_style,
        theme::fg(theme::field_local_addr()),
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Remote Address",
        conn.remote_addr.to_string(),
        label_style,
        theme::fg(theme::field_remote_addr()),
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Scope",
        crate::network::bogon::classify(conn.remote_addr.ip())
            .label()
            .to_string(),
        label_style,
        theme::fg(theme::field_remote_addr()),
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "State",
        conn.state().into_owned(),
        label_style,
        theme::fg(state_color(conn)),
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Process",
        conn.process_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
        theme::fg(theme::field_process()),
    );
    push_detail_field(
        &mut details_text,
        &mut detail_fields,
        "PID",
        conn.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
    );
    push_detail_field_styled(
        &mut details_text,
        &mut detail_fields,
        "Service",
        conn.service_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        label_style,
        theme::fg(theme::field_service()),
    );

    // Add reverse DNS hostnames if available (skip ARP to avoid feedback loop)
    if let Some(resolver) = dns_resolver.filter(|_| conn.protocol != Protocol::Arp) {
        let local_hostname = resolver.get_hostname(&conn.local_addr.ip());
        let remote_hostname = resolver.get_hostname(&conn.remote_addr.ip());

        if local_hostname.is_some() || remote_hostname.is_some() {
            push_detail_section(&mut details_text, &mut detail_fields, "Hostnames");
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "Local Hostname",
                local_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
                label_style,
                theme::fg(theme::field_local_addr()),
            );
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "Remote Hostname",
                remote_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
                label_style,
                theme::fg(theme::field_remote_addr()),
            );
        }
    }

    // Add GeoIP information if available
    if let Some(ref geoip) = conn.geoip_info
        && (geoip.country_code.is_some() || geoip.asn.is_some() || geoip.city.is_some())
    {
        let location_value_style = theme::fg(theme::field_location());
        push_detail_section(&mut details_text, &mut detail_fields, "Geolocation");
        if let Some(ref country_name) = geoip.country_name {
            let country_display = if let Some(ref cc) = geoip.country_code {
                format!("{} ({})", country_name, cc)
            } else {
                country_name.clone()
            };
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "Country",
                country_display,
                label_style,
                location_value_style,
            );
        } else if let Some(ref cc) = geoip.country_code {
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "Country",
                cc.clone(),
                label_style,
                location_value_style,
            );
        }
        if let Some(ref city) = geoip.city {
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "City",
                city.clone(),
                label_style,
                location_value_style,
            );
        }
        if let Some(asn) = geoip.asn {
            let asn_display = if let Some(ref org) = geoip.as_org {
                format!("AS{} ({})", asn, org)
            } else {
                format!("AS{}", asn)
            };
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "ASN",
                asn_display,
                label_style,
                location_value_style,
            );
        }
    }

    // Add DPI / application protocol information. Section heading carries
    // both the label and the protocol so we don't need a redundant
    // "Application: <proto>" field below.
    if let Some(dpi) = &conn.dpi_info {
        let dpi_start = details_text.len();
        push_detail_section_styled(
            &mut details_text,
            &mut detail_fields,
            format!("Application: {}", dpi.application),
            theme::bold_fg(dpi_color(&dpi.application)),
        );

        // Add protocol-specific details
        match &dpi.application {
            crate::network::types::ApplicationProtocol::Http(info) => {
                if let Some(method) = &info.method {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "HTTP Method",
                        method.clone(),
                        label_style,
                    );
                }
                if let Some(path) = &info.path {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "HTTP Path",
                        path.clone(),
                        label_style,
                    );
                }
                if let Some(status) = info.status_code {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "HTTP Status",
                        status.to_string(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Https(info) => {
                if let Some(tls_info) = &info.tls_info {
                    if let Some(sni) = &tls_info.sni {
                        push_detail_field(
                            &mut details_text,
                            &mut detail_fields,
                            "SNI",
                            sni.clone(),
                            label_style,
                        );
                    }
                    if !tls_info.alpn.is_empty() {
                        push_detail_field(
                            &mut details_text,
                            &mut detail_fields,
                            "ALPN",
                            tls_info.alpn.join(", "),
                            label_style,
                        );
                    }
                    if let Some(version) = &tls_info.version {
                        push_detail_field(
                            &mut details_text,
                            &mut detail_fields,
                            "TLS Version",
                            version.to_string(),
                            label_style,
                        );
                    }
                    if let Some(formatted_cipher) = tls_info.format_cipher_suite() {
                        let cipher_color = if tls_info.is_cipher_suite_secure().unwrap_or(false) {
                            theme::ok()
                        } else {
                            theme::warn()
                        };
                        push_detail_field_styled(
                            &mut details_text,
                            &mut detail_fields,
                            "Cipher Suite",
                            formatted_cipher,
                            label_style,
                            theme::fg(cipher_color),
                        );
                    }
                }
            }
            crate::network::types::ApplicationProtocol::Dns(info) => {
                if let Some(query_type) = &info.query_type {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "DNS Type",
                        format!("{}", query_type),
                        label_style,
                    );
                }
                if !info.response_ips.is_empty() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "DNS Response IPs",
                        format!("{:?}", info.response_ips),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Quic(info) => {
                if let Some(tls_info) = &info.tls_info {
                    let sni = tls_info
                        .sni
                        .clone()
                        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "QUIC SNI",
                        sni,
                        label_style,
                    );
                    let alpn = tls_info.alpn.join(", ");
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "QUIC ALPN",
                        alpn,
                        label_style,
                    );
                }
                if let Some(version) = info.version_string.as_deref() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "QUIC Version",
                        version.to_owned(),
                        label_style,
                    );
                }
                if let Some(connection_id) = &info.connection_id_hex {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Connection ID",
                        connection_id.clone(),
                        label_style,
                    );
                }
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Packet Type",
                    info.packet_type.to_string(),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Connection State",
                    info.connection_state.to_string(),
                    label_style,
                );
            }
            crate::network::types::ApplicationProtocol::Ssh(info) => {
                if let Some(version) = &info.version {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "SSH Version",
                        format!("{:?}", version),
                        label_style,
                    );
                }
                if let Some(server_software) = &info.server_software {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Server Software",
                        server_software.clone(),
                        label_style,
                    );
                }
                if let Some(client_software) = &info.client_software {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Client Software",
                        client_software.clone(),
                        label_style,
                    );
                }
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Connection State",
                    format!("{:?}", info.connection_state),
                    label_style,
                );
                if !info.algorithms.is_empty() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Algorithms",
                        info.algorithms.join(", "),
                        label_style,
                    );
                }
                if let Some(auth_method) = &info.auth_method {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Auth Method",
                        auth_method.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Ntp(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "NTP Version",
                    format!("{}", info.version),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "NTP Mode",
                    info.mode.to_string(),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Stratum",
                    format!("{}", info.stratum),
                    label_style,
                );
            }
            crate::network::types::ApplicationProtocol::Mdns(info) => {
                if let Some(query_name) = &info.query_name {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Query Name",
                        query_name.clone(),
                        label_style,
                    );
                }
                if let Some(query_type) = &info.query_type {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Query Type",
                        format!("{}", query_type),
                        label_style,
                    );
                }
                if !info.response_ips.is_empty() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Response IPs",
                        format!("{:?}", info.response_ips),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Llmnr(info) => {
                if let Some(query_name) = &info.query_name {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Query Name",
                        query_name.clone(),
                        label_style,
                    );
                }
                if let Some(query_type) = &info.query_type {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Query Type",
                        format!("{}", query_type),
                        label_style,
                    );
                }
                if !info.response_ips.is_empty() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Response IPs",
                        format!("{:?}", info.response_ips),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Dhcp(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Message Type",
                    info.message_type.to_string(),
                    label_style,
                );
                if let Some(hostname) = &info.hostname {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Hostname",
                        hostname.clone(),
                        label_style,
                    );
                }
                if let Some(client_mac) = &info.client_mac {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Client MAC",
                        client_mac.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Snmp(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "SNMP Version",
                    info.version.to_string(),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "PDU Type",
                    info.pdu_type.to_string(),
                    label_style,
                );
                if let Some(community) = &info.community {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Community",
                        community.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Ssdp(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Method",
                    info.method.to_string(),
                    label_style,
                );
                if let Some(service_type) = &info.service_type {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Service Type",
                        service_type.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::NetBios(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Service",
                    info.service.to_string(),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Opcode",
                    info.opcode.to_string(),
                    label_style,
                );
                if let Some(name) = &info.name {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Name",
                        name.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::BitTorrent(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Type",
                    info.protocol_type.to_string(),
                    label_style,
                );
                if let Some(client) = &info.client {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Client",
                        client.clone(),
                        label_style,
                    );
                }
                if let Some(info_hash) = &info.info_hash {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Info Hash",
                        info_hash.clone(),
                        label_style,
                    );
                }
                if let Some(method) = &info.dht_method {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "DHT Method",
                        method.clone(),
                        label_style,
                    );
                }
                let mut extensions = Vec::new();
                if info.supports_dht {
                    extensions.push("DHT");
                }
                if info.supports_extension {
                    extensions.push("Extension Protocol");
                }
                if info.supports_fast {
                    extensions.push("Fast");
                }
                if !extensions.is_empty() {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Extensions",
                        extensions.join(", "),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Stun(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Method",
                    info.method.to_string(),
                    label_style,
                );
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Class",
                    info.message_class.to_string(),
                    label_style,
                );
                let txn_id = info
                    .transaction_id
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>();
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Transaction ID",
                    txn_id,
                    label_style,
                );
                if let Some(software) = &info.software {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Software",
                        software.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Ftp(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Message Type",
                    info.message_type.to_string(),
                    label_style,
                );
                if let Some(cmd) = &info.command {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Command",
                        cmd.clone(),
                        label_style,
                    );
                }
                if let Some(args) = &info.args {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Arguments",
                        args.clone(),
                        label_style,
                    );
                }
                if let Some(code) = info.response_code {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Response Code",
                        code.to_string(),
                        label_style,
                    );
                }
                if let Some(message) = &info.response_message {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Response",
                        message.clone(),
                        label_style,
                    );
                }
                if let Some(user) = &info.username {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Username",
                        user.clone(),
                        label_style,
                    );
                }
                if let Some(sw) = &info.server_software {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Server Software",
                        sw.clone(),
                        label_style,
                    );
                }
                if let Some(sys) = &info.system_type {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "System Type",
                        sys.clone(),
                        label_style,
                    );
                }
            }
            crate::network::types::ApplicationProtocol::Mqtt(info) => {
                push_detail_field(
                    &mut details_text,
                    &mut detail_fields,
                    "Packet Type",
                    info.packet_type.to_string(),
                    label_style,
                );
                if let Some(version) = &info.version {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Version",
                        version.to_string(),
                        label_style,
                    );
                }
                if let Some(client_id) = &info.client_id {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Client ID",
                        client_id.clone(),
                        label_style,
                    );
                }
                if let Some(topic) = &info.topic {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "Topic",
                        topic.clone(),
                        label_style,
                    );
                }
                if let Some(qos) = info.qos {
                    push_detail_field(
                        &mut details_text,
                        &mut detail_fields,
                        "QoS",
                        qos.to_string(),
                        label_style,
                    );
                }
            }
        }
        right_ranges.push(dpi_start..details_text.len());
    }

    // Add ARP details if this is an ARP connection
    if let ProtocolState::Arp(arp_info) = &conn.protocol_state {
        push_detail_section(&mut details_text, &mut detail_fields, "ARP");
        push_detail_field(
            &mut details_text,
            &mut detail_fields,
            "Sender MAC",
            arp_info.sender_mac.clone(),
            label_style,
        );
        if let Some(ref vendor) = arp_info.sender_vendor {
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Sender Vendor",
                vendor.clone(),
                label_style,
            );
        }
        push_detail_field(
            &mut details_text,
            &mut detail_fields,
            "Sender IP",
            arp_info.sender_ip.to_string(),
            label_style,
        );
        push_detail_field(
            &mut details_text,
            &mut detail_fields,
            "Target MAC",
            arp_info.target_mac.clone(),
            label_style,
        );
        if let Some(ref vendor) = arp_info.target_vendor {
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Target Vendor",
                vendor.clone(),
                label_style,
            );
        }
        push_detail_field(
            &mut details_text,
            &mut detail_fields,
            "Target IP",
            arp_info.target_ip.to_string(),
            label_style,
        );
    }

    // TCP Analytics + initial RTT live under a single heading so the right
    // pane reads as one cohesive "transport metrics" block.
    if conn.tcp_analytics.is_some() || conn.initial_rtt.is_some() {
        let metrics_start = details_text.len();
        push_detail_section(&mut details_text, &mut detail_fields, "TCP Analytics");
        if let Some(analytics) = &conn.tcp_analytics {
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "TCP Retransmits",
                analytics.retransmit_count.to_string(),
                label_style,
            );
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Out-of-Order Packets",
                analytics.out_of_order_count.to_string(),
                label_style,
            );
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Duplicate ACKs",
                analytics.duplicate_ack_count.to_string(),
                label_style,
            );
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Fast Retransmits",
                analytics.fast_retransmit_count.to_string(),
                label_style,
            );
            push_detail_field(
                &mut details_text,
                &mut detail_fields,
                "Window Size",
                analytics.last_window_size.to_string(),
                label_style,
            );
        }
        if let Some(rtt) = conn.initial_rtt {
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            let rtt_color = if rtt_ms < 50.0 {
                theme::ok()
            } else if rtt_ms < 150.0 {
                theme::warn()
            } else {
                theme::err()
            };
            push_detail_field_styled(
                &mut details_text,
                &mut detail_fields,
                "Initial RTT",
                format!("{:.1}ms", rtt_ms),
                label_style,
                theme::fg(rtt_color),
            );
        }
        right_ranges.push(metrics_start..details_text.len());
    }

    // Continuity: the header band echoes the selected row so users feel
    // like they zoomed into the Overview entry rather than landed on a
    // fresh view. Its color mirrors the row's staleness color from the
    // connection table, so a stale/critical row stays stale/critical
    // when zoomed into Details.
    let process_label = conn
        .process_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("?");
    let detail_title = if conn.is_historic {
        format!(" Historic · {} → {}", process_label, conn.remote_addr)
    } else {
        format!(" {} → {}", process_label, conn.remote_addr)
    };
    let staleness = conn.staleness_ratio();
    let title_style = if conn.is_historic {
        Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::DIM | Modifier::BOLD)
    } else if staleness >= 0.90 {
        theme::bold_fg(theme::err())
    } else if staleness >= 0.75 {
        theme::bold_fg(theme::warn())
    } else {
        Style::default().add_modifier(Modifier::BOLD)
    };

    // One header band across the whole info area; the panes below it
    // are borderless. When grouping is on, say so — the strip above and
    // the j/k navigation follow the grouped view's order, mirroring the
    // "Grouped by Process" suffix in the Overview title.
    let mut band = vec![Span::styled(detail_title, title_style)];
    if ui_state.grouping_enabled {
        band.push(Span::styled(
            " · grouped by process",
            theme::fg(theme::muted()),
        ));
    }
    band.push(Span::styled(
        " · click a field to copy",
        theme::fg(theme::muted()),
    ));
    let info_area = section_header(f, chunks[0], Line::from(band));

    // Drain right-pane sections (Application/DPI + TCP Analytics + RTT) out
    // of the main buffers when we have enough horizontal room to show two
    // columns side by side. The right pane always renders when split, even
    // if the connection has no DPI / TCP analytics, so the layout stays
    // consistent across connection types. Below the width threshold the
    // panel collapses back to a single column so narrow terminals stay
    // readable. The right pane needs no title of its own — its content
    // starts with the bold "Application: …" / "TCP Analytics" headings.
    let split_horizontally = info_area.width >= DETAILS_SPLIT_MIN_WIDTH;
    let mut right_text: Vec<Line> = Vec::new();
    let mut right_fields: Vec<Option<(String, String)>> = Vec::new();
    if split_horizontally {
        // Drain in reverse so earlier ranges aren't shifted by later drains.
        for range in right_ranges.iter().rev() {
            let mut sec_text: Vec<Line> = details_text.drain(range.clone()).collect();
            let mut sec_fields: Vec<Option<(String, String)>> =
                detail_fields.drain(range.clone()).collect();
            sec_text.append(&mut right_text);
            sec_fields.append(&mut right_fields);
            right_text = sec_text;
            right_fields = sec_fields;
        }
        // The first surviving entry in right_text is a leading blank from the
        // first section's separator; trim it so the right pane starts clean.
        if right_text.first().map(line_is_blank).unwrap_or(false) {
            right_text.remove(0);
            right_fields.remove(0);
        }
    }

    let info_chunks: Vec<Rect> = if split_horizontally {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .spacing(2)
            .split(info_area)
            .to_vec()
    } else {
        vec![info_area]
    };

    let left_para = Paragraph::new(details_text)
        .style(Style::default())
        // trim:false preserves any leading whitespace in labels rather than
        // collapsing it, which keeps the fixed-width label padding intact.
        .wrap(Wrap { trim: false });
    f.render_widget(left_para, info_chunks[0]);
    register_detail_clicks(click_regions, info_chunks[0], &detail_fields, true);

    if info_chunks.len() == 2 && !right_text.is_empty() {
        let right_para = Paragraph::new(right_text)
            .style(Style::default())
            .wrap(Wrap { trim: false });
        f.render_widget(right_para, info_chunks[1]);
        register_detail_clicks(click_regions, info_chunks[1], &right_fields, true);
    }

    // Traffic details - also track fields for click-to-copy
    let mut traffic_text: Vec<Line> = Vec::new();
    let mut traffic_fields: Vec<Option<(String, String)>> = Vec::new();

    let rx_value_style = theme::fg(theme::rx());
    let tx_value_style = theme::fg(theme::tx());
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Bytes Sent",
        format_bytes(conn.bytes_sent),
        label_style,
        tx_value_style,
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Bytes Received",
        format_bytes(conn.bytes_received),
        label_style,
        rx_value_style,
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Packets Sent",
        conn.packets_sent.to_string(),
        label_style,
        tx_value_style,
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Packets Received",
        conn.packets_received.to_string(),
        label_style,
        rx_value_style,
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Current Rate (In)",
        format_rate(conn.current_incoming_rate_bps),
        label_style,
        rx_value_style,
    );
    push_detail_field_styled(
        &mut traffic_text,
        &mut traffic_fields,
        "Current Rate (Out)",
        format_rate(conn.current_outgoing_rate_bps),
        label_style,
        tx_value_style,
    );

    // Blank spacer row, then the section header, then the 6 stat rows.
    let traffic_area = Rect::new(
        chunks[1].x,
        chunks[1].y + 1,
        chunks[1].width,
        chunks[1].height.saturating_sub(1),
    );
    let traffic_area = section_header(
        f,
        traffic_area,
        Span::styled(
            " Traffic Statistics",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    );
    let traffic = Paragraph::new(traffic_text)
        .style(Style::default())
        .wrap(Wrap { trim: false });

    f.render_widget(traffic, traffic_area);
    register_detail_clicks(click_regions, traffic_area, &traffic_fields, false);

    Ok(())
}
