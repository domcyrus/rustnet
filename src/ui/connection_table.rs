//! Shared column model for the connection tables: one source of truth
//! for column order, headers, widths, responsive visibility, and row
//! construction. Used by the flat Overview list, the grouped view, and
//! the Details continuity strip so all three render the same grid.
//!
//! Column order puts identifying info (process, addresses) on the left
//! and status info (state, bandwidth) on the right.
//!
//! Widths are a pure function of the available table width — never of
//! row content — so the layout is stable while scrolling and only
//! changes when the terminal is resized (or the sidebar is toggled).
//! When the table is too narrow, whole columns are hidden in a fixed
//! priority order; when there is width to spare, it is distributed to
//! the flexible columns by weight so the grid spans the full width and
//! the Bandwidth column sits flush against the right edge. Cell-level
//! ellipsis only happens as a last resort at very narrow widths, after
//! column hiding has already done its job.

use std::borrow::Cow;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row, Table};

use std::net::SocketAddr;

use crate::network::dns::DnsResolver;
use crate::network::types::{AddrKind, Connection, Protocol};
use crate::ui::{
    ClickAction, ClickableRegions, NONE_PLACEHOLDER, SortColumn, UIState, dpi_color,
    format::{format_rate_compact, format_rtt_compact, truncate_with_ellipsis},
    state_color, theme,
    widgets::scrollbar::draw_scrollbar,
};

// --- Column floors (cells). Flexible columns grow beyond their floor
// --- when surplus width is distributed; fixed columns never do.
const PROCESS_WIDTH: u16 = 22;
/// Floor for the Local column; "192.168.1.10:51234" fits in 18.
const LOCAL_MIN_WIDTH: u16 = 18;
const LOCATION_WIDTH: u16 = 4;
const SERVICE_WIDTH: u16 = 10; // most IANA service names ("netbios-ns") fit
const APP_WIDTH_FULL: u16 = 24;
const APP_WIDTH_COMPACT: u16 = 14;
const STATE_WIDTH: u16 = 12; // longest TCP state: "ESTABLISHED" (11)
const RTT_WIDTH: u16 = 7; // "234ms", "1.2s"; header "RTT ↓" when sorted
const BANDWIDTH_WIDTH: u16 = 11;
/// Floor for the Remote column; bare "ip:port" for IPv4 fits in 21.
const REMOTE_MIN_WIDTH: u16 = 21;

/// Selection bar drawn in front of the highlighted row. It is the row
/// highlight symbol, so it costs no column width, and it stays the
/// selection cue when colors are off.
pub(in crate::ui) const SELECTION_BAR: &str = "▌";

/// One of the connection-table columns. Headers use short labels and
/// single-cell glyphs (↓ ↑ ·) only — multi-width emoji are deliberately
/// avoided because double-width glyphs break ratatui column alignment
/// in many terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum ColumnId {
    /// Narrow gutter holding the connection's state dot.
    Process,
    Remote,
    Local,
    Location,
    Service,
    /// Merged protocol + application column: renders "TCP·HTTPS (sni)"
    /// (full), "TCP·HTTPS" (compact), or bare "TCP" when DPI has nothing.
    Application,
    State,
    /// Best available TCP, QUIC handshake, or ICMP echo RTT.
    Rtt,
    Bandwidth,
}

/// A column resolved for the current frame: its identity, the width it
/// was granted, and the sort key its header maps to.
#[derive(Debug, Clone, Copy)]
pub(in crate::ui) struct Column {
    pub id: ColumnId,
    pub width: u16,
    pub sort: Option<SortColumn>,
}

impl Column {
    fn new(id: ColumnId, width: u16) -> Self {
        let sort = match id {
            ColumnId::Process => Some(SortColumn::Process),
            ColumnId::Remote => Some(SortColumn::RemoteAddress),
            ColumnId::Local => Some(SortColumn::LocalAddress),
            ColumnId::Location => Some(SortColumn::Location),
            ColumnId::Service => Some(SortColumn::Service),
            ColumnId::Application => Some(SortColumn::Application),
            ColumnId::State => Some(SortColumn::State),
            ColumnId::Rtt => Some(SortColumn::Rtt),
            ColumnId::Bandwidth => Some(SortColumn::BandwidthTotal),
        };
        Self { id, width, sort }
    }
}

/// Fixed chrome the table adds around the column widths: the 1-cell
/// selection bar drawn as the row highlight symbol, plus the
/// inter-column spacing. Every caller of this grid (the Overview lists
/// and the Details continuity strip) draws the same bar, so the
/// reserve is exact and the last column lands flush right.
fn table_chrome(column_count: usize) -> u16 {
    let spacing = column_count.saturating_sub(1) as u16; // default column_spacing(1)
    1 + spacing
}

/// Pick the visible column set for `available_width` (the table area's
/// width, borders excluded). A pure function of the width — row content
/// never affects the layout, so columns stay put while scrolling.
///
/// Too narrow: whole columns are hidden in a fixed degradation order
/// (Location → Service → Local → RTT → Application shrinks to compact →
/// State) rather than truncating cells. The floor is Process ·
/// Remote · App · Bandwidth; below that ratatui clips columns from the
/// right.
///
/// Width to spare: the surplus is distributed to the flexible columns
/// proportionally to their weight (Remote 4 · App 3 · Process 2 ·
/// Local 1), so the grid spans the full width — Bandwidth lands flush
/// against the right edge and the spare space reads as even breathing
/// room between columns instead of one big gap.
pub(in crate::ui) fn select_columns(available_width: u16, has_location: bool) -> Vec<Column> {
    let mut columns = vec![
        Column::new(ColumnId::Process, PROCESS_WIDTH),
        Column::new(ColumnId::Remote, REMOTE_MIN_WIDTH),
        Column::new(ColumnId::Local, LOCAL_MIN_WIDTH),
    ];
    if has_location {
        columns.push(Column::new(ColumnId::Location, LOCATION_WIDTH));
    }
    columns.extend([
        Column::new(ColumnId::Service, SERVICE_WIDTH),
        Column::new(ColumnId::Application, APP_WIDTH_FULL),
        Column::new(ColumnId::State, STATE_WIDTH),
        Column::new(ColumnId::Rtt, RTT_WIDTH),
        Column::new(ColumnId::Bandwidth, BANDWIDTH_WIDTH),
    ]);

    let used = |cols: &[Column]| -> u16 {
        cols.iter().map(|c| c.width).sum::<u16>() + table_chrome(cols.len())
    };
    let fits = |cols: &[Column]| used(cols) <= available_width;

    for id in [
        ColumnId::Location,
        ColumnId::Service,
        ColumnId::Local,
        ColumnId::Rtt,
    ] {
        if !fits(&columns) {
            columns.retain(|c| c.id != id);
        }
    }
    if !fits(&columns) {
        for c in columns.iter_mut() {
            if c.id == ColumnId::Application {
                c.width = APP_WIDTH_COMPACT;
            }
        }
    }
    if !fits(&columns) {
        columns.retain(|c| c.id != ColumnId::State);
    }

    // Distribute the surplus by weight. A compacted Application column
    // stays compact (re-growing it would undo the degradation step).
    let weight = |c: &Column| -> u32 {
        match c.id {
            ColumnId::Remote => 4,
            ColumnId::Application if c.width >= APP_WIDTH_FULL => 3,
            ColumnId::Process => 2,
            ColumnId::Local => 1,
            _ => 0,
        }
    };
    let surplus = available_width.saturating_sub(used(&columns)) as u32;
    let total: u32 = columns.iter().map(weight).sum();
    if surplus > 0 && total > 0 {
        let mut handed = 0;
        for c in columns.iter_mut() {
            let grant = surplus * weight(c) / total;
            c.width += grant as u16;
            handed += grant;
        }
        // Integer-division remainder goes to Remote (always visible) so
        // the columns sum to the full width exactly.
        if let Some(c) = columns.iter_mut().find(|c| c.id == ColumnId::Remote) {
            c.width += (surplus - handed) as u16;
        }
    }

    columns
}

/// Map resolved columns to ratatui layout constraints. Every column is
/// `Length` — the widths already account for the full table width via
/// the weighted distribution in [`select_columns`].
pub(in crate::ui) fn column_constraints(columns: &[Column]) -> Vec<Constraint> {
    columns
        .iter()
        .map(|c| Constraint::Length(c.width))
        .collect()
}

/// Untruncated Process cell text: "name (pid)".
fn process_text(conn: &Connection) -> String {
    // Borrow the name; `format!` in the Some-pid arm (the common case)
    // allocates its own String, so cloning out of the Option first just
    // throws away a heap allocation per row per frame. Only the None-pid
    // arm needs to materialize an owned String.
    let name = conn.process_name.as_deref().unwrap_or(NONE_PLACEHOLDER);
    let text = match conn.pid {
        Some(pid) => format!("{name} ({pid})"),
        None => name.to_string(),
    };

    // Kubernetes attribution: when the resolver mapped this connection to
    // a pod, prefix the cell with "namespace/pod" so the owning workload
    // is visible at a glance. The process name/PID follow it.
    #[cfg(feature = "kubernetes")]
    if let Some(pod) = conn.k8s_info.as_ref().and_then(|k| k.pod_name.as_deref()) {
        return match conn
            .k8s_info
            .as_ref()
            .and_then(|k| k.pod_namespace.as_deref())
        {
            Some(ns) => format!("{ns}/{pod}  {text}"),
            None => format!("{pod}  {text}"),
        };
    }

    text
}

/// Untruncated Service cell text: service name or port number.
fn service_text<'a>(conn: &'a Connection, ui_state: &UIState) -> Cow<'a, str> {
    if ui_state.show_port_numbers {
        Cow::Owned(conn.remote_addr.port().to_string())
    } else {
        match conn.service_name.as_deref() {
            Some(name) => Cow::Borrowed(name),
            None => Cow::Borrowed(NONE_PLACEHOLDER),
        }
    }
}

/// Table cell for an endpoint: broadcast/multicast endpoints render as an
/// intentional label ("bcast:138", "mcast:5353") instead of an address that
/// reads like a unicast host; the full address stays visible in Details.
/// Default-gateway endpoints keep the address visible and gain a "(gw)"
/// suffix when it fits.
fn endpoint_display(
    addr: SocketAddr,
    kind: AddrKind,
    is_gateway: bool,
    max_width: usize,
) -> String {
    match kind {
        AddrKind::Broadcast => format!("bcast:{}", addr.port()),
        AddrKind::Multicast => format!("mcast:{}", addr.port()),
        AddrKind::Unicast => {
            if is_gateway {
                let with_marker = format!("{addr} (gw)");
                if with_marker.chars().count() <= max_width {
                    return with_marker;
                }
            }
            truncate_with_ellipsis(&addr.to_string(), max_width)
        }
    }
}

/// Remote address (or resolved hostname) with port, fitted to
/// `max_width` cells. Hostnames keep their port visible when cut
/// ("host…:443"); raw addresses only ellipsize as a last resort at
/// very narrow widths. Broadcast/multicast endpoints render as labels
/// and skip hostname resolution.
///
/// The bool is true when the name was attributed from an observed DNS
/// response (rendered as `~name:port` and dimmed) rather than resolved
/// via reverse DNS. Attribution takes priority over reverse DNS and
/// needs no resolver; an authoritative SNI / Host header suppresses it
/// (that name already shows in the App column).
fn remote_display(
    conn: &Connection,
    ui_state: &UIState,
    dns_resolver: Option<&DnsResolver>,
    max_width: usize,
) -> (String, bool) {
    if ui_state.show_hostnames
        && conn.protocol != Protocol::Arp
        && conn.remote_addr_kind == AddrKind::Unicast
    {
        let port = conn.remote_addr.port();
        let fit = |name: &str, prefix: &str| -> String {
            let full = format!("{prefix}{name}:{port}");
            if full.chars().count() > max_width {
                let port_str = format!(":{port}");
                let budget = max_width
                    .saturating_sub(port_str.chars().count())
                    .saturating_sub(prefix.chars().count());
                format!("{prefix}{}{port_str}", truncate_with_ellipsis(name, budget))
            } else {
                full
            }
        };

        if conn.authoritative_hostname().is_none()
            && let Some(att) = &conn.attributed_hostname
        {
            return (fit(&att.name, "~"), true);
        }
        if let Some(resolver) = dns_resolver
            && let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip())
        {
            return (fit(&hostname, ""), false);
        }
    }
    (
        endpoint_display(
            conn.remote_addr,
            conn.remote_addr_kind,
            conn.remote_is_gateway,
            max_width,
        ),
        false,
    )
}

/// Header label for a column. Short on purpose — no " Address" suffixes.
fn header_label(id: ColumnId, ui_state: &UIState) -> &'static str {
    match id {
        ColumnId::Process => "Process",
        ColumnId::Remote => "Remote",
        ColumnId::Local => "Local",
        ColumnId::Location => "Loc",
        ColumnId::Service => {
            if ui_state.show_port_numbers {
                "Port"
            } else {
                "Service"
            }
        }
        ColumnId::Application => "App",
        ColumnId::State => "State",
        ColumnId::Rtt => "RTT",
        ColumnId::Bandwidth => "", // built as spans in build_header
    }
}

/// Build the shared header row. The active sort column is bold,
/// underlined, and accent-colored with an ↑/↓ arrow appended; the
/// Bandwidth header carries the rx/tx arrows ("Rx↓/Tx↑") so the data
/// rows don't have to repeat them on every line.
pub(in crate::ui) fn build_header<'a>(columns: &[Column], ui_state: &UIState) -> Row<'a> {
    let sorting = ui_state.sort_column != SortColumn::CreatedAt;
    let sort_arrow = if ui_state.sort_ascending {
        "↑"
    } else {
        "↓"
    };

    let cells = columns.iter().map(|col| {
        let active = sorting && col.sort == Some(ui_state.sort_column);
        let style = if active {
            theme::bold_underline_fg(theme::accent())
        } else {
            theme::fg(theme::heading())
        };

        if col.id == ColumnId::Bandwidth {
            let line = if active {
                Line::from(Span::styled(format!("Rx↓/Tx↑ {sort_arrow}"), style))
            } else {
                Line::from(vec![
                    Span::styled("Rx", style),
                    Span::styled("↓", theme::fg(theme::rx())),
                    Span::styled("/Tx", style),
                    Span::styled("↑", theme::fg(theme::tx())),
                ])
            };
            return Cell::from(line.right_aligned());
        }

        let label = header_label(col.id, ui_state);
        let text = if active {
            format!("{label} {sort_arrow}")
        } else {
            label.to_string()
        };
        // RTT cells are right-aligned numbers; align the header with them.
        if col.id == ColumnId::Rtt {
            return Cell::from(Line::styled(text, style).right_aligned());
        }
        Cell::from(text).style(style)
    });

    Row::new(cells).height(1).bottom_margin(1)
}

/// Row-level staleness styling shared by every connection row. Fresh rows
/// keep per-cell colors. Historic rows turn gray, while expiring rows stay
/// yellow through the warning window and intensify toward red near removal.
///
/// A selected historic row on a theme with a selection tint keeps its
/// per-cell colors instead: the faint whole-row fg is unreadable against
/// the selection band, and the "closed" state still marks the row.
fn staleness_style(conn: &Connection, selected: bool) -> (Option<Style>, bool) {
    let staleness = conn.staleness_ratio();
    if conn.is_historic {
        if selected && theme::selection_has_bg() {
            (None, true)
        } else {
            (Some(theme::historic_row()), false)
        }
    } else if let Some(intensity) = theme::expiry_glow_intensity(staleness) {
        let color = theme::expiry_glow(intensity);
        let style = if intensity >= 0.6 {
            theme::bold_fg(color)
        } else {
            theme::fg(color)
        };
        (Some(style), false)
    } else {
        (None, true)
    }
}

/// Build one connection row for the given visible `columns`.
///
/// `process_override` replaces the Process cell content (the grouped
/// view passes the tree connector + PID since the group header above
/// already names the process). `selected` marks the table's highlighted
/// row so historic rows can stay readable on the selection band.
pub(in crate::ui) fn connection_row<'a>(
    conn: &'a Connection,
    columns: &[Column],
    ui_state: &UIState,
    dns_resolver: Option<&DnsResolver>,
    process_override: Option<Line<'a>>,
    selected: bool,
) -> Row<'a> {
    let (row_override, color_cells) = staleness_style(conn, selected);
    let style_if_colored = |c: Color| {
        if color_cells {
            theme::fg(c)
        } else {
            Style::default()
        }
    };

    let mut process_override = process_override;
    let cells: Vec<Cell<'a>> = columns
        .iter()
        .map(|col| match col.id {
            ColumnId::Process => {
                if let Some(line) = process_override.take() {
                    return Cell::from(line);
                }
                let full = process_text(conn);
                Cell::from(truncate_with_ellipsis(&full, col.width as usize))
                    .style(process_style(conn, color_cells))
            }
            ColumnId::Remote => {
                let (display, attributed) =
                    remote_display(conn, ui_state, dns_resolver, col.width as usize);
                Cell::from(display).style(style_if_colored(if attributed {
                    theme::field_attributed_hostname()
                } else {
                    theme::field_remote_addr()
                }))
            }
            ColumnId::Local => Cell::from(endpoint_display(
                conn.local_addr,
                conn.local_addr_kind,
                false,
                col.width as usize,
            ))
            .style(style_if_colored(theme::field_local_addr())),
            ColumnId::Location => {
                let location = conn
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or(NONE_PLACEHOLDER);
                Cell::from(location).style(style_if_colored(theme::field_location()))
            }
            ColumnId::Service => {
                let service =
                    truncate_with_ellipsis(&service_text(conn, ui_state), col.width as usize);
                Cell::from(service).style(style_if_colored(theme::field_service()))
            }
            ColumnId::Application => application_cell(conn, col.width, color_cells),
            ColumnId::State => {
                // Historic connections show "closed" instead of their last
                // TCP state — together with the DIM row style this is the
                // NO_COLOR-safe replacement for the old hollow status dot.
                if conn.is_historic {
                    Cell::from("closed").style(style_if_colored(theme::tcp_closed()))
                } else {
                    // Most states fit the fixed width; the odd long one
                    // (e.g. "ECHO_REP(12345)") ellipsizes instead of
                    // hard-clipping.
                    let state = truncate_with_ellipsis(&conn.state(), col.width as usize);
                    Cell::from(state).style(style_if_colored(state_color(conn)))
                }
            }
            ColumnId::Rtt => rtt_cell(conn, color_cells),
            ColumnId::Bandwidth => {
                if conn.is_historic {
                    Cell::from(Line::from("n/a").right_aligned())
                } else {
                    bandwidth_cell(
                        conn.current_incoming_rate_bps,
                        conn.current_outgoing_rate_bps,
                        color_cells,
                    )
                }
            }
        })
        .collect();

    let row = Row::new(cells);
    match row_override {
        Some(style) => row.style(style),
        None => row,
    }
}

/// Style for the Process cell: the identity tint keyed on the process
/// name, falling back to the shared process color when the theme has no
/// identity hues (NO_COLOR, no truecolor, classic preset). Rows painted
/// whole by the staleness pass keep that paint instead.
fn process_style(conn: &Connection, color_cells: bool) -> Style {
    if !color_cells {
        return Style::default();
    }
    let base = theme::fg(theme::field_process());
    match conn.process_name.as_deref() {
        Some(name) => theme::identity_color(name).map(theme::fg).unwrap_or(base),
        None => base,
    }
}

/// Merged protocol + application cell: "TCP·HTTPS (sni)" at full width,
/// "TCP·HTTPS" compact, bare "TCP" without DPI info. The protocol half
/// is muted so the detected application reads as the content.
fn application_cell<'a>(conn: &Connection, width: u16, color_cells: bool) -> Cell<'a> {
    let proto = conn.protocol.as_str();

    let Some(dpi) = conn.dpi_info.as_ref() else {
        let style = if color_cells {
            theme::fg(theme::muted())
        } else {
            Style::default()
        };
        return Cell::from(proto).style(style);
    };

    let budget = (width as usize).saturating_sub(proto.chars().count() + 1);
    let app = if width >= APP_WIDTH_FULL {
        truncate_with_ellipsis(&dpi.application.to_string(), budget)
    } else {
        truncate_with_ellipsis(dpi.application.sort_key(), budget)
    };
    if color_cells {
        Cell::from(Line::from(vec![
            Span::styled(format!("{proto}·"), theme::fg(theme::muted())),
            Span::styled(app, theme::fg(dpi_color(&dpi.application))),
        ]))
    } else {
        Cell::from(format!("{proto}·{app}"))
    }
}

/// RTT cell: best available TCP, QUIC handshake, or ICMP echo RTT,
/// right-aligned and colored by the same thresholds as the Details card
/// (green < 50ms, yellow < 150ms, red above). ICMP echo flows use their
/// latest paired request/reply RTT; protocols without a timing signal show
/// the placeholder.
fn rtt_cell<'a>(conn: &Connection, color_cells: bool) -> Cell<'a> {
    let Some(rtt) = conn.current_rtt() else {
        let line = Line::from(NONE_PLACEHOLDER).right_aligned();
        let style = if color_cells {
            theme::fg(theme::muted())
        } else {
            Style::default()
        };
        return Cell::from(line).style(style);
    };

    let ms = rtt.as_secs_f64() * 1000.0;
    let text = format_rtt_compact(rtt);
    let line = if color_cells {
        let color = if ms < 50.0 {
            theme::ok()
        } else if ms < 150.0 {
            theme::warn()
        } else {
            theme::err()
        };
        Line::from(Span::styled(text, theme::fg(color)))
    } else {
        Line::from(text)
    };
    Cell::from(line.right_aligned())
}

/// Bandwidth cell: "{rx}/{tx}" right-aligned, rx/tx halves colored when
/// there's live traffic, whole cell muted when idle (muted preset). The
/// ↓/↑ arrows live in the column header, not on every row. Takes raw
/// rates so the grouped view can feed per-group aggregates through the
/// same formatting.
pub(in crate::ui) fn bandwidth_cell<'a>(rx_bps: f64, tx_bps: f64, color_cells: bool) -> Cell<'a> {
    let rx = format_rate_compact(rx_bps, NONE_PLACEHOLDER);
    let tx = format_rate_compact(tx_bps, NONE_PLACEHOLDER);
    let active = rx_bps > 0.0 || tx_bps > 0.0;

    let line = if !color_cells {
        Line::from(format!("{rx}/{tx}"))
    } else if !active && !theme::is_classic() {
        Line::from(Span::styled(
            format!("{rx}/{tx}"),
            theme::fg(theme::muted()),
        ))
    } else {
        Line::from(vec![
            Span::styled(rx, theme::fg(theme::rx())),
            Span::raw("/"),
            Span::styled(tx, theme::fg(theme::tx())),
        ])
    };
    Cell::from(line.right_aligned())
}

/// Virtualization window over `items`: the rows at `scroll_offset`
/// that fit `visible_rows`, plus one extra for a partial bottom row.
pub(in crate::ui) fn visible_window<T>(
    items: &[T],
    scroll_offset: usize,
    visible_rows: usize,
) -> &[T] {
    let window_end = (scroll_offset + visible_rows + 1).min(items.len());
    &items[scroll_offset.min(items.len())..window_end]
}

/// How a windowed table maps onto its full row list: which rows are on
/// screen and which one is selected. Indices are into the full list.
pub(in crate::ui) struct RowWindow {
    pub selected: Option<usize>,
    pub scroll_offset: usize,
    pub total_rows: usize,
    pub visible_rows: usize,
}

/// Render a windowed connection table plus its scrollbar and click
/// regions: the shared back half of the flat and grouped Overview
/// lists. `rows` holds only the visible window described by `window`.
pub(in crate::ui) fn render_row_table(
    f: &mut Frame,
    area: Rect,
    header: Row<'_>,
    rows: Vec<Row<'_>>,
    widths: &[Constraint],
    window: RowWindow,
    click_regions: &mut ClickableRegions,
) {
    let RowWindow {
        selected,
        scroll_offset,
        total_rows,
        visible_rows,
    } = window;

    // Create table state with selection adjusted to windowed slice
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = selected {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let connections_table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol(Line::styled(SELECTION_BAR, theme::fg(theme::accent())));

    let table_area = Rect::new(area.x, area.y, area.width.saturating_sub(2), area.height);
    f.render_stateful_widget(connections_table, table_area, &mut state);

    // Scrollbar tracks the row region (below header + margin).
    let header_height = 2_u16; // header row (1) + bottom_margin (1)
    let rows_area = Rect::new(
        area.x,
        area.y + header_height,
        area.width,
        area.height.saturating_sub(header_height),
    );
    draw_scrollbar(f, rows_area, total_rows, scroll_offset, visible_rows);

    // Register click regions for visible rows
    click_regions.scroll_area = Some(area);
    let visible_start_y = area.y + header_height;
    let max_visible_rows = area.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let row_idx = scroll_offset + i;
        if row_idx >= total_rows {
            break;
        }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(area.x, row_y, area.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(row_idx));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::types::{Connection, Protocol, ProtocolState, TcpState};
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};

    fn ids(columns: &[Column]) -> Vec<ColumnId> {
        columns.iter().map(|c| c.id).collect()
    }

    fn width_of(columns: &[Column], id: ColumnId) -> u16 {
        columns.iter().find(|c| c.id == id).expect("column").width
    }

    fn used(columns: &[Column]) -> u16 {
        columns.iter().map(|c| c.width).sum::<u16>() + table_chrome(columns.len())
    }

    #[test]
    fn expiry_glow_tracks_the_removal_window() {
        assert_eq!(theme::expiry_glow_intensity(0.74), None);
        assert_eq!(theme::expiry_glow_intensity(0.75), Some(0.0));
        assert_eq!(theme::expiry_glow_intensity(0.89), Some(0.0));
        assert_eq!(theme::expiry_glow_intensity(0.90), Some(0.0));
        let midpoint = theme::expiry_glow_intensity(0.95).unwrap();
        assert!((midpoint - 0.5).abs() < 0.000_001);
        assert_eq!(theme::expiry_glow_intensity(1.0), Some(1.0));
        assert_eq!(theme::expiry_glow_intensity(1.5), Some(1.0));
        // Endpoints of the muted theme's derived warn-to-err expiry ramp.
        assert_eq!(theme::expiry_glow(0.0), Color::Rgb(250, 164, 65));
        assert_eq!(theme::expiry_glow(0.5), Color::Rgb(247, 108, 59));
        assert_eq!(theme::expiry_glow(1.0), Color::Rgb(244, 52, 52));
    }

    // Width math for the full set with Location at floor widths:
    // 22+21+18+4+10+24+12+7+11 = 129 content + chrome(9 cols) = 9 -> 138.
    const FULL_WIDTH: u16 = 138;

    #[test]
    fn select_columns_shows_everything_when_wide() {
        let cols = select_columns(FULL_WIDTH, true);
        assert_eq!(
            ids(&cols),
            vec![
                ColumnId::Process,
                ColumnId::Remote,
                ColumnId::Local,
                ColumnId::Location,
                ColumnId::Service,
                ColumnId::Application,
                ColumnId::State,
                ColumnId::Rtt,
                ColumnId::Bandwidth,
            ]
        );
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_FULL);
    }

    #[test]
    fn select_columns_degrades_in_priority_order() {
        // One cell short of the full set -> Location goes first.
        let cols = select_columns(FULL_WIDTH - 1, true);
        assert!(!ids(&cols).contains(&ColumnId::Location));
        assert!(ids(&cols).contains(&ColumnId::Service));

        // 22+21+18+10+24+12+7+11 = 125 + chrome(8) = 133 -> below that Service goes.
        let cols = select_columns(132, true);
        assert!(!ids(&cols).contains(&ColumnId::Service));
        assert!(ids(&cols).contains(&ColumnId::Local));

        // 22+21+18+24+12+7+11 = 115 + chrome(7) = 122 -> below that Local goes.
        let cols = select_columns(122, true);
        assert!(ids(&cols).contains(&ColumnId::Local));
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_FULL);
        let cols = select_columns(121, true);
        assert!(!ids(&cols).contains(&ColumnId::Local));

        // 22+21+24+12+7+11 = 97 + chrome(6) = 103 -> below that RTT goes.
        let cols = select_columns(103, true);
        assert!(ids(&cols).contains(&ColumnId::Rtt));
        let cols = select_columns(102, true);
        assert!(!ids(&cols).contains(&ColumnId::Rtt));

        // 22+21+24+12+11 = 90 + chrome(5) = 95 -> below that App compacts.
        let cols = select_columns(94, true);
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_COMPACT);
        assert!(ids(&cols).contains(&ColumnId::State));

        // 22+21+14+12+11 = 80 + chrome(5) = 85 -> below that State goes.
        let cols = select_columns(84, true);
        assert_eq!(
            ids(&cols),
            vec![
                ColumnId::Process,
                ColumnId::Remote,
                ColumnId::Application,
                ColumnId::Bandwidth,
            ]
        );

        // The floor never shrinks further, even at absurd widths.
        let cols = select_columns(10, true);
        assert_eq!(ids(&cols).len(), 4);
    }

    #[test]
    fn select_columns_without_location_never_contains_it() {
        let cols = select_columns(FULL_WIDTH, false);
        assert!(!ids(&cols).contains(&ColumnId::Location));
    }

    #[test]
    fn surplus_is_distributed_by_weight_and_spans_the_full_width() {
        // 100 spare cells split 4:3:2:1 across Remote/App/Process/Local.
        let width = FULL_WIDTH + 100;
        let cols = select_columns(width, true);
        assert_eq!(width_of(&cols, ColumnId::Remote), REMOTE_MIN_WIDTH + 40);
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_FULL + 30);
        assert_eq!(width_of(&cols, ColumnId::Process), PROCESS_WIDTH + 20);
        assert_eq!(width_of(&cols, ColumnId::Local), LOCAL_MIN_WIDTH + 10);
        // Fixed columns never grow.
        assert_eq!(width_of(&cols, ColumnId::State), STATE_WIDTH);
        assert_eq!(width_of(&cols, ColumnId::Rtt), RTT_WIDTH);
        assert_eq!(width_of(&cols, ColumnId::Bandwidth), BANDWIDTH_WIDTH);
        // The grid spans the full width exactly, so the Bandwidth
        // column sits flush against the right edge.
        assert_eq!(used(&cols), width);

        // Division remainders land on Remote so spanning stays exact.
        // 103 spare: grants are 41/30/20/10 (101 handed), remainder 2.
        let width = FULL_WIDTH + 103;
        let cols = select_columns(width, true);
        assert_eq!(used(&cols), width);
        assert_eq!(width_of(&cols, ColumnId::Remote), REMOTE_MIN_WIDTH + 41 + 2);
    }

    #[test]
    fn widths_depend_only_on_available_width() {
        for width in [60u16, 96, 131, 200, 320] {
            assert_eq!(
                ids(&select_columns(width, true)),
                ids(&select_columns(width, true))
            );
            let a: Vec<u16> = select_columns(width, true)
                .iter()
                .map(|c| c.width)
                .collect();
            let b: Vec<u16> = select_columns(width, true)
                .iter()
                .map(|c| c.width)
                .collect();
            assert_eq!(a, b);
        }
    }

    #[test]
    fn remote_display_keeps_raw_addresses_until_width_forces_ellipsis() {
        let remote = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x1111, 0x2222, 0x8a2e, 0x0370, 0x7334,
            )),
            65535,
        );
        let local = "[::1]:8080".parse().unwrap();
        let conn = Connection::new(
            Protocol::Tcp,
            local,
            remote,
            ProtocolState::Tcp(TcpState::Established),
        );
        let ui_state = UIState::default();

        let full = conn.remote_addr.to_string();
        let full_len = full.chars().count();

        // Enough width: the raw address is shown verbatim.
        assert_eq!(remote_display(&conn, &ui_state, None, full_len).0, full);
        // On a wide terminal the weighted Remote share covers a full
        // IPv6 address (40 spare cells at FULL_WIDTH+100 -> width 61).
        let cols = select_columns(FULL_WIDTH + 100, true);
        assert!(width_of(&cols, ColumnId::Remote) as usize >= full_len);

        // Last resort at narrow widths: ellipsized, never wider than asked.
        let narrow = remote_display(&conn, &ui_state, None, REMOTE_MIN_WIDTH as usize).0;
        assert_eq!(narrow.chars().count(), REMOTE_MIN_WIDTH as usize);
        assert!(narrow.ends_with('\u{2026}'));
    }

    #[test]
    fn endpoint_display_labels_broadcast_and_multicast() {
        let bcast: SocketAddr = "192.168.0.255:138".parse().unwrap();
        assert_eq!(
            endpoint_display(bcast, AddrKind::Broadcast, false, 18),
            "bcast:138"
        );

        let mcast: SocketAddr = "224.0.0.251:5353".parse().unwrap();
        assert_eq!(
            endpoint_display(mcast, AddrKind::Multicast, false, 18),
            "mcast:5353"
        );

        let unicast: SocketAddr = "192.168.0.52:60236".parse().unwrap();
        assert_eq!(
            endpoint_display(unicast, AddrKind::Unicast, false, 18),
            "192.168.0.52:60236"
        );
        assert!(endpoint_display(unicast, AddrKind::Unicast, false, 10).ends_with('\u{2026}'));
    }

    #[test]
    fn endpoint_display_marks_gateways_when_width_allows() {
        let gateway: SocketAddr = "192.168.0.1:34824".parse().unwrap();
        assert_eq!(
            endpoint_display(gateway, AddrKind::Unicast, true, 24),
            "192.168.0.1:34824 (gw)"
        );
        // Falls back to the plain address when the marker does not fit.
        assert_eq!(
            endpoint_display(gateway, AddrKind::Unicast, true, 18),
            "192.168.0.1:34824"
        );
        // The kind label wins over the gateway marker for non-unicast kinds.
        assert_eq!(
            endpoint_display(gateway, AddrKind::Broadcast, true, 24),
            "bcast:34824"
        );
    }

    #[test]
    fn remote_display_prefers_attribution_unless_sni_is_authoritative() {
        use crate::network::types::{
            ApplicationProtocol, AttributedHostname, AttributionSource, DpiInfo, HttpsInfo, TlsInfo,
        };

        let mut conn = Connection::new(
            Protocol::Udp,
            "192.168.0.132:50000".parse().unwrap(),
            "142.250.74.36:443".parse().unwrap(),
            ProtocolState::Udp,
        );
        conn.attributed_hostname = Some(AttributedHostname {
            name: "example.com".to_string(),
            source: AttributionSource::CapturedDns,
            observed_at: std::time::SystemTime::now(),
        });
        let ui_state = UIState::default();

        // No authoritative name: the attributed hostname renders with a
        // `~` prefix and flags the cell, without needing a resolver.
        assert_eq!(
            remote_display(&conn, &ui_state, None, 24),
            ("~example.com:443".to_string(), true)
        );

        // The prefix costs one cell of the hostname budget when cut.
        let (narrow, attributed) = remote_display(&conn, &ui_state, None, 12);
        assert_eq!(narrow, "~exampl\u{2026}:443");
        assert!(attributed);

        // A later-arriving authoritative SNI suppresses the inferred
        // name (it already shows in the App column).
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    sni: Some("example.com".to_string()),
                    ..TlsInfo::new()
                }),
            }),
        });
        assert_eq!(
            remote_display(&conn, &ui_state, None, 24),
            ("142.250.74.36:443".to_string(), false)
        );

        // Hostnames toggled off: plain IP even with an attribution.
        conn.dpi_info = None;
        let hostnames_off = UIState {
            show_hostnames: false,
            ..Default::default()
        };
        assert_eq!(
            remote_display(&conn, &hostnames_off, None, 24),
            ("142.250.74.36:443".to_string(), false)
        );
    }

    #[test]
    fn remote_display_labels_multicast_instead_of_resolving_hostnames() {
        let mut conn = Connection::new(
            Protocol::Udp,
            "192.168.0.132:5353".parse().unwrap(),
            "224.0.0.251:5353".parse().unwrap(),
            ProtocolState::Udp,
        );
        conn.remote_addr_kind = AddrKind::Multicast;
        let ui_state = UIState::default();

        assert_eq!(remote_display(&conn, &ui_state, None, 24).0, "mcast:5353");
    }

    #[test]
    fn truncate_with_ellipsis_is_char_safe() {
        assert_eq!(truncate_with_ellipsis("short", 10), "short");
        assert_eq!(truncate_with_ellipsis("exactly-10", 10), "exactly-10");
        assert_eq!(
            truncate_with_ellipsis("0123456789ab", 10),
            "012345678\u{2026}"
        );
        // Multi-byte chars must not split.
        assert_eq!(
            truncate_with_ellipsis("h\u{e9}ll\u{f6} w\u{f6}rld!", 6),
            "h\u{e9}ll\u{f6}\u{2026}"
        );
    }

    #[test]
    fn process_text_formats_name_pid_and_placeholder() {
        let mut conn = Connection::new(
            Protocol::Tcp,
            "[::1]:8080".parse().unwrap(),
            "[::1]:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );

        // name + pid -> "name (pid)"
        conn.process_name = Some("firefox".to_string());
        conn.pid = Some(1234);
        assert_eq!(process_text(&conn), "firefox (1234)");

        // name, no pid -> bare name
        conn.pid = None;
        assert_eq!(process_text(&conn), "firefox");

        // no name -> placeholder (bare when pid absent)
        conn.process_name = None;
        assert_eq!(process_text(&conn), NONE_PLACEHOLDER);

        // no name, with pid -> "placeholder (pid)"
        conn.pid = Some(42);
        assert_eq!(process_text(&conn), format!("{NONE_PLACEHOLDER} (42)"));
    }

    fn tcp_conn(state: TcpState) -> Connection {
        Connection::new(
            Protocol::Tcp,
            "192.168.1.10:51234".parse().unwrap(),
            "140.82.121.4:443".parse().unwrap(),
            ProtocolState::Tcp(state),
        )
    }

    #[test]
    fn process_style_falls_back_without_identity_hues() {
        let mut conn = tcp_conn(TcpState::Established);
        conn.process_name = Some("firefox".to_string());

        // Whole-row paint wins over any per-cell color.
        assert_eq!(process_style(&conn, false), Style::default());

        // The default test theme resolves without truecolor, so there are
        // no identity hues and the shared process color stands.
        let base = theme::fg(theme::field_process());
        assert_eq!(process_style(&conn, true), base);

        // Unnamed processes never hash the placeholder.
        conn.process_name = None;
        assert_eq!(process_style(&conn, true), base);
    }
}
