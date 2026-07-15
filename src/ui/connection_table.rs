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

use ratatui::layout::Constraint;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row};

use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, Protocol};
use crate::ui::{
    NONE_PLACEHOLDER, SortColumn, UIState, dpi_color, format::format_rate_compact, state_color,
    theme,
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
const BANDWIDTH_WIDTH: u16 = 11;
/// Floor for the Remote column; bare "ip:port" for IPv4 fits in 21.
const REMOTE_MIN_WIDTH: u16 = 21;

/// One of the connection-table columns. Headers use short labels and
/// single-cell glyphs (↓ ↑ ·) only — multi-width emoji are deliberately
/// avoided because double-width glyphs break ratatui column alignment
/// in many terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum ColumnId {
    Process,
    Remote,
    Local,
    Location,
    Service,
    /// Merged protocol + application column: renders "TCP·HTTPS (sni)"
    /// (full), "TCP·HTTPS" (compact), or bare "TCP" when DPI has nothing.
    Application,
    State,
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
            ColumnId::Bandwidth => Some(SortColumn::BandwidthTotal),
        };
        Self { id, width, sort }
    }
}

/// Fixed chrome the table adds around the column widths: the row
/// highlight symbol "> " (2) plus the inter-column spacing.
fn table_chrome(column_count: usize) -> u16 {
    let spacing = column_count.saturating_sub(1) as u16; // default column_spacing(1)
    2 + spacing
}

/// Pick the visible column set for `available_width` (the table area's
/// width, borders excluded). A pure function of the width — row content
/// never affects the layout, so columns stay put while scrolling.
///
/// Too narrow: whole columns are hidden in a fixed degradation order
/// (Location → Service → Local → Application shrinks to compact →
/// State) rather than truncating cells. The floor is Process · Remote ·
/// App · Bandwidth; below that ratatui clips columns from the right.
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
        Column::new(ColumnId::Bandwidth, BANDWIDTH_WIDTH),
    ]);

    let used = |cols: &[Column]| -> u16 {
        cols.iter().map(|c| c.width).sum::<u16>() + table_chrome(cols.len())
    };
    let fits = |cols: &[Column]| used(cols) <= available_width;

    for id in [ColumnId::Location, ColumnId::Service, ColumnId::Local] {
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

/// Remote address (or resolved hostname) with port, fitted to
/// `max_width` cells. Hostnames keep their port visible when cut
/// ("host…:443"); raw addresses only ellipsize as a last resort at
/// very narrow widths.
fn remote_display(
    conn: &Connection,
    ui_state: &UIState,
    dns_resolver: Option<&DnsResolver>,
    max_width: usize,
) -> String {
    if ui_state.show_hostnames
        && conn.protocol != Protocol::Arp
        && let Some(resolver) = dns_resolver
        && let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip())
    {
        let port = conn.remote_addr.port();
        let full = format!("{hostname}:{port}");
        if full.chars().count() > max_width {
            let port_str = format!(":{port}");
            let budget = max_width.saturating_sub(port_str.chars().count());
            format!("{}{}", truncate_with_ellipsis(&hostname, budget), port_str)
        } else {
            full
        }
    } else {
        truncate_with_ellipsis(&conn.remote_addr.to_string(), max_width)
    }
}

/// Char-safe truncation to `max_chars` cells, ending in "…" when cut.
fn truncate_with_ellipsis(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let keep = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
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
        Cell::from(text).style(style)
    });

    Row::new(cells).height(1).bottom_margin(1)
}

/// Row-level staleness styling shared by every connection row. Fresh rows
/// keep per-cell colors. Historic rows turn gray, while expiring rows stay
/// yellow through the warning window and intensify toward red near removal.
fn staleness_style(conn: &Connection) -> (Option<Style>, bool) {
    let staleness = conn.staleness_ratio();
    if conn.is_historic {
        (Some(theme::historic_row()), false)
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
/// already names the process).
pub(in crate::ui) fn connection_row<'a>(
    conn: &'a Connection,
    columns: &[Column],
    ui_state: &UIState,
    dns_resolver: Option<&DnsResolver>,
    process_override: Option<Line<'a>>,
) -> Row<'a> {
    let (row_override, color_cells) = staleness_style(conn);
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
                    .style(style_if_colored(theme::field_process()))
            }
            ColumnId::Remote => Cell::from(remote_display(
                conn,
                ui_state,
                dns_resolver,
                col.width as usize,
            ))
            .style(style_if_colored(theme::field_remote_addr())),
            ColumnId::Local => Cell::from(truncate_with_ellipsis(
                &conn.local_addr.to_string(),
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
            ColumnId::Bandwidth => bandwidth_cell(
                conn.current_incoming_rate_bps,
                conn.current_outgoing_rate_bps,
                color_cells,
            ),
        })
        .collect();

    let row = Row::new(cells);
    match row_override {
        Some(style) => row.style(style),
        None => row,
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

/// Bandwidth cell: "{rx}/{tx}" right-aligned, rx/tx halves colored when
/// there's live traffic, whole cell muted when idle (muted preset). The
/// ↓/↑ arrows live in the column header, not on every row. Takes raw
/// rates so the grouped view can feed per-group aggregates through the
/// same formatting.
pub(in crate::ui) fn bandwidth_cell<'a>(rx_bps: f64, tx_bps: f64, color_cells: bool) -> Cell<'a> {
    let rx = format_rate_compact(rx_bps);
    let tx = format_rate_compact(tx_bps);
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
        assert_eq!(theme::expiry_glow(0.0), Color::Rgb(0xFA, 0xCC, 0x15));
        assert_eq!(theme::expiry_glow(0.5), Color::Rgb(0xFB, 0x92, 0x3C));
        assert_eq!(theme::expiry_glow(1.0), Color::Rgb(0xFF, 0x2D, 0x55));
    }

    // Width math for the full set with Location at floor widths:
    // 22+21+18+4+10+24+12+11 = 122 content + chrome(8 cols) = 9 -> 131.
    const FULL_WIDTH: u16 = 131;

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

        // 22+21+18+10+24+12+11 = 118 + chrome(7) = 126 -> below that Service goes.
        let cols = select_columns(125, true);
        assert!(!ids(&cols).contains(&ColumnId::Service));
        assert!(ids(&cols).contains(&ColumnId::Local));

        // 22+21+18+24+12+11 = 108 + chrome(6) = 115 -> below that Local goes.
        let cols = select_columns(115, true);
        assert!(ids(&cols).contains(&ColumnId::Local));
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_FULL);
        let cols = select_columns(114, true);
        assert!(!ids(&cols).contains(&ColumnId::Local));

        // 22+21+24+12+11 = 90 + chrome(5) = 96 -> below that App compacts.
        let cols = select_columns(95, true);
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_COMPACT);
        assert!(ids(&cols).contains(&ColumnId::State));

        // 22+21+14+12+11 = 80 + chrome(5) = 86 -> below that State goes.
        let cols = select_columns(85, true);
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
        assert_eq!(remote_display(&conn, &ui_state, None, full_len), full);
        // On a wide terminal the weighted Remote share covers a full
        // IPv6 address (40 spare cells at FULL_WIDTH+100 -> width 61).
        let cols = select_columns(FULL_WIDTH + 100, true);
        assert!(width_of(&cols, ColumnId::Remote) as usize >= full_len);

        // Last resort at narrow widths: ellipsized, never wider than asked.
        let narrow = remote_display(&conn, &ui_state, None, REMOTE_MIN_WIDTH as usize);
        assert_eq!(narrow.chars().count(), REMOTE_MIN_WIDTH as usize);
        assert!(narrow.ends_with('\u{2026}'));
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
}
