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
use std::time::SystemTime;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row, Table};

use std::net::SocketAddr;

use crate::network::dns::DnsResolver;
use crate::network::types::{AddrKind, ApplicationProtocol, Connection, Protocol};
use crate::ui::{
    ClickAction, ClickableRegions, NONE_PLACEHOLDER, SortColumn, UIState, dpi_color,
    format::{format_countdown, format_rate_compact, format_rtt_compact, truncate_with_ellipsis},
    state_color, theme,
    widgets::scrollbar::draw_scrollbar,
};

// --- Column floors (cells). Flexible columns grow beyond their floor
// --- when surplus width is distributed; fixed columns never do.
/// Process column: a one-cell gutter for the stale stripe plus 21 cells of
/// name and PID at the floor width (the column grows with the terminal).
const PROCESS_WIDTH: u16 = 22;
/// Width of the gutter every connection row reserves at the start of its
/// Process cell, so names stay aligned whether or not the stripe shows.
const STRIPE_GUTTER: usize = 1;
/// Left-edge marker of a stale row, painted with the countdown's
/// yellow-to-red ramp: the lifecycle cue where the eye enters the row.
const STALE_STRIPE: &str = "▎";
/// Floor for the Local column; "192.168.1.10:51234" fits in 18.
const LOCAL_MIN_WIDTH: u16 = 18;
const LOCATION_WIDTH: u16 = 4;
const SERVICE_WIDTH: u16 = 10; // most IANA service names ("netbios-ns") fit
const APP_WIDTH_FULL: u16 = 24;
const APP_WIDTH_COMPACT: u16 = 14;
const STATE_WIDTH: u16 = 11; // longest TCP state: "ESTABLISHED" (11)
const RTT_WIDTH: u16 = 7; // "234ms", "1.2s"; header "RTT ↓" when sorted
const HEALTH_WIDTH: u16 = 5; // "R3/O1", "R1/V0", or "R2/T1"
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
    /// Protocol-aware observable health badge.
    Health,
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
            ColumnId::Health => Some(SortColumn::Health),
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
/// (Location → Service → Local → RTT → Health → Application shrinks to
/// compact → State) rather than truncating cells. The floor is Process ·
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
        Column::new(ColumnId::Health, HEALTH_WIDTH),
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
        ColumnId::Health,
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
        // Leading space mirrors the stripe gutter so the label sits over
        // the process names.
        ColumnId::Process => " Process",
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
        ColumnId::Health => "Hlth",
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
        let text = if active && col.id == ColumnId::Health {
            format!("H {sort_arrow}")
        } else if active {
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

/// How a row's cells are painted. `plain` drops every per-cell color so a
/// whole-row override (the historic gray) carries the signal alone; `fade`
/// softens a context cell's own color toward the muted tier as the
/// connection nears its timeout (0 = fully fresh), via
/// [`theme::stale_fade`]. The two never combine: historic rows are plain,
/// live rows fade. Only context columns (process, addresses, location,
/// service, application) fade; signal columns take [`CellPaint::signal`]
/// so State, RTT, Health, and Bandwidth keep full color on a stale row.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(in crate::ui) struct CellPaint {
    plain: bool,
    fade: f64,
}

impl CellPaint {
    /// Full per-cell color: fresh live rows and group aggregates.
    pub(in crate::ui) const FRESH: CellPaint = CellPaint {
        plain: false,
        fade: 0.0,
    };
    const PLAIN: CellPaint = CellPaint {
        plain: true,
        fade: 0.0,
    };

    /// Whether cells carry any styling of their own.
    fn colored(self) -> bool {
        !self.plain
    }

    /// Paint for a signal column: the same plain/colored split, with the
    /// staleness fade dropped so the cell's colors stay a pure signal.
    fn signal(self) -> CellPaint {
        CellPaint {
            plain: self.plain,
            fade: 0.0,
        }
    }

    /// Cell foreground in `color`, faded by the row's staleness.
    fn style(self, color: Color) -> Style {
        if self.plain {
            Style::default()
        } else {
            theme::stale_fade(theme::fg(color), self.fade)
        }
    }

    /// Bold cell foreground in `color`, faded by the row's staleness.
    fn bold_style(self, color: Color) -> Style {
        if self.plain {
            Style::default()
        } else {
            theme::stale_fade(theme::bold_fg(color), self.fade)
        }
    }
}

/// Row-level staleness styling shared by every connection row. Fresh rows
/// keep per-cell colors. Historic rows turn faint gray as a whole, while
/// expiring rows keep every semantic color and soften their context cells
/// toward the muted tier, so the lifecycle never borrows the warn/err
/// hues the Health, RTT, and State cells use for real problems and never
/// sinks to the historic gray.
///
/// A selected row on a theme with a selection tint keeps full color
/// instead: a faint or softened fg is unreadable against the selection
/// band, and the "closed" state (or the countdown) still marks the row.
fn staleness_style(conn: &Connection, selected: bool) -> (Option<Style>, CellPaint) {
    let on_selection_tint = selected && theme::selection_has_bg();
    if conn.is_historic {
        if on_selection_tint {
            (None, CellPaint::FRESH)
        } else {
            (Some(theme::historic_row()), CellPaint::PLAIN)
        }
    } else {
        let fade = if on_selection_tint {
            0.0
        } else {
            theme::staleness_fade_intensity(conn.staleness_ratio()).unwrap_or(0.0)
        };
        (None, CellPaint { plain: false, fade })
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
    let (row_override, paint) = staleness_style(conn, selected);
    let cell_style = |c: Color| paint.style(c);

    let mut process_override = process_override;
    let cells: Vec<Cell<'a>> = columns
        .iter()
        .map(|col| match col.id {
            ColumnId::Process => {
                // Every row starts with the stripe gutter so names line up;
                // only stale rows fill it.
                let mut spans = vec![stale_stripe(conn)];
                if let Some(line) = process_override.take() {
                    spans.extend(line.spans);
                    return Cell::from(Line::from(spans))
                        .style(theme::stale_fade(Style::default(), paint.fade));
                }
                let full = process_text(conn);
                let budget = (col.width as usize).saturating_sub(STRIPE_GUTTER);
                spans.push(Span::raw(truncate_with_ellipsis(&full, budget)));
                Cell::from(Line::from(spans)).style(process_style(conn, paint))
            }
            ColumnId::Remote => {
                let (display, attributed) =
                    remote_display(conn, ui_state, dns_resolver, col.width as usize);
                Cell::from(display).style(cell_style(if attributed {
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
            .style(cell_style(theme::field_local_addr())),
            ColumnId::Location => {
                let location = conn
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or(NONE_PLACEHOLDER);
                Cell::from(location).style(cell_style(theme::field_location()))
            }
            ColumnId::Service => {
                let service =
                    truncate_with_ellipsis(&service_text(conn, ui_state), col.width as usize);
                Cell::from(service).style(cell_style(theme::field_service()))
            }
            ColumnId::Application => application_cell(conn, col.width, paint),
            ColumnId::State => {
                // Historic connections show "closed" instead of their last
                // TCP state — together with the DIM row style this is the
                // NO_COLOR-safe replacement for the old hollow status dot.
                if conn.is_historic {
                    Cell::from("closed").style(paint.signal().style(theme::tcp_closed()))
                } else {
                    // Most states fit the fixed width; the odd long one
                    // (e.g. "ECHO_REP(12345)") ellipsizes instead of
                    // hard-clipping.
                    let state = truncate_with_ellipsis(&conn.state(), col.width as usize);
                    Cell::from(state).style(paint.signal().style(state_color(conn)))
                }
            }
            ColumnId::Rtt => rtt_cell(conn, paint.signal()),
            ColumnId::Health => health_cell(conn, paint.signal()),
            ColumnId::Bandwidth => connection_bandwidth_cell(conn, paint.signal()),
        })
        .collect();

    let row = Row::new(cells);
    match row_override {
        Some(style) => row.style(style),
        None => row,
    }
}

/// Bandwidth cell for one connection row: "n/a" once historic, the
/// removal countdown while the row is idle inside its staleness window,
/// otherwise the live rates. The countdown carries the row's urgency
/// color, yellow through orange to red as removal nears; the rest of the
/// row only softens, so the hue stays on the one cell that explains it.
fn connection_bandwidth_cell<'a>(conn: &Connection, paint: CellPaint) -> Cell<'a> {
    if conn.is_historic {
        return Cell::from(Line::from("n/a").right_aligned());
    }
    if let Some((countdown, fade)) = countdown_text(conn) {
        return Cell::from(Line::from(countdown).right_aligned())
            .style(theme::countdown_style(fade));
    }
    bandwidth_cell(
        conn.current_incoming_rate_bps,
        conn.current_outgoing_rate_bps,
        paint,
    )
}

/// Fade intensity of a live row that has gone quiet and entered its
/// staleness window; `None` for historic rows, rows still moving traffic,
/// and rows outside the window. Keyed on the staleness ratio directly, so
/// the stripe and countdown stay even when selection drops the color
/// fade. Shared by both cues so they can never disagree.
fn stale_window(conn: &Connection) -> Option<f64> {
    if conn.is_historic || conn.has_nonzero_rates() {
        return None;
    }
    theme::staleness_fade_intensity(conn.staleness_ratio())
}

/// Gutter span at the start of the Process cell: the ramp-colored stripe
/// for a stale row, a blank cell otherwise.
fn stale_stripe(conn: &Connection) -> Span<'static> {
    match stale_window(conn) {
        Some(fade) => Span::styled(STALE_STRIPE, theme::countdown_style(fade)),
        None => Span::raw(" "),
    }
}

/// "{time} left" for a stale row, paired with the fade intensity that
/// colors it: the time until cleanup removes the row.
fn countdown_text(conn: &Connection) -> Option<(String, f64)> {
    let fade = stale_window(conn)?;
    let remaining = conn
        .get_timeout()
        .saturating_sub(conn.cleanup_age(SystemTime::now()));
    Some((format!("{} left", format_countdown(remaining)), fade))
}

/// Style for the Process cell: the identity tint keyed on the process
/// name, falling back to the shared process color when the theme has no
/// identity hues (NO_COLOR, no truecolor, vivid preset). Rows painted
/// whole by the historic pass keep that paint instead.
fn process_style(conn: &Connection, paint: CellPaint) -> Style {
    if !paint.colored() {
        return Style::default();
    }
    let color = conn
        .process_name
        .as_deref()
        .and_then(theme::identity_color)
        .unwrap_or_else(theme::field_process);
    paint.style(color)
}

/// Merged protocol + application cell: "TCP·HTTPS (sni)" at full width,
/// "TCP·HTTPS" compact, bare "TCP" without DPI info. The protocol half
/// is muted so the detected application reads as the content.
fn application_cell<'a>(conn: &Connection, width: u16, paint: CellPaint) -> Cell<'a> {
    let proto = conn.protocol.as_str();

    let Some(dpi) = conn.dpi_info.as_ref() else {
        return Cell::from(proto).style(paint.style(theme::muted()));
    };

    let budget = (width as usize).saturating_sub(proto.chars().count() + 1);
    let app = if width >= APP_WIDTH_FULL {
        truncate_with_ellipsis(&dpi.application.to_string(), budget)
    } else {
        truncate_with_ellipsis(dpi.application.sort_key(), budget)
    };
    if paint.colored() {
        Cell::from(Line::from(vec![
            Span::styled(format!("{proto}·"), paint.style(theme::muted())),
            Span::styled(app, paint.style(dpi_color(&dpi.application))),
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
fn rtt_cell<'a>(conn: &Connection, paint: CellPaint) -> Cell<'a> {
    let Some(rtt) = conn.current_rtt() else {
        let line = Line::from(NONE_PLACEHOLDER).right_aligned();
        return Cell::from(line).style(paint.style(theme::muted()));
    };

    let ms = rtt.as_secs_f64() * 1000.0;
    let text = format_rtt_compact(rtt);
    let line = if paint.colored() {
        let color = if ms < 50.0 {
            theme::ok()
        } else if ms < 150.0 {
            theme::warn()
        } else {
            theme::err()
        };
        Line::from(Span::styled(text, paint.style(color)))
    } else {
        Line::from(text)
    };
    Cell::from(line.right_aligned())
}

/// Compact protocol-aware health badge. TCP shows retransmits/out-of-order,
/// QUIC shows explicit Retry/Version Negotiation packets, and transaction-based
/// UDP shows repeated requests/timeouts. Other protocols remain ungraded.
fn health_cell<'a>(conn: &Connection, paint: CellPaint) -> Cell<'a> {
    let Some((kind, first_count, second_count)) = health_counts(conn) else {
        return Cell::from(NONE_PLACEHOLDER).style(paint.style(theme::muted()));
    };
    let (first, second) = match kind {
        HealthKind::Tcp => (
            ('R', first_count, theme::err()),
            ('O', second_count, theme::warn()),
        ),
        HealthKind::Quic => (
            ('R', first_count, theme::warn()),
            ('V', second_count, theme::warn()),
        ),
        HealthKind::Transaction => (
            ('R', first_count, theme::warn()),
            ('T', second_count, theme::err()),
        ),
    };
    health_pair_cell(first, second, paint)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum HealthKind {
    Tcp,
    Quic,
    Transaction,
}

/// Classify a connection's gradable health signals: the badge kind plus its
/// two counters in display order. Shared with the Health sort so the badge
/// and the ordering can never disagree on which connections are graded.
pub(in crate::ui) fn health_counts(conn: &Connection) -> Option<(HealthKind, u64, u64)> {
    if let Some(analytics) = conn.tcp_analytics.as_ref() {
        return Some((
            HealthKind::Tcp,
            analytics.retransmit_count,
            analytics.out_of_order_count,
        ));
    }

    let application = conn.dpi_info.as_ref().map(|dpi| &dpi.application);
    if matches!(application, Some(ApplicationProtocol::Quic(_))) {
        return Some((
            HealthKind::Quic,
            conn.protocol_health.quic_retry_count,
            conn.protocol_health.quic_version_negotiation_count,
        ));
    }

    let transactional_udp = conn.protocol == Protocol::Udp
        && matches!(
            application,
            Some(
                ApplicationProtocol::Dns(_)
                    | ApplicationProtocol::Llmnr(_)
                    | ApplicationProtocol::NetBios(_)
                    | ApplicationProtocol::Stun(_)
                    | ApplicationProtocol::Ntp(_)
            )
        );
    (transactional_udp && conn.protocol_health.request_observed).then_some((
        HealthKind::Transaction,
        conn.protocol_health.request_retry_count,
        conn.protocol_health.request_timeout_count,
    ))
}

fn health_pair_cell<'a>(
    first: (char, u64, Color),
    second: (char, u64, Color),
    paint: CellPaint,
) -> Cell<'a> {
    let (first_label, first_count, first_color) = first;
    let (second_label, second_count, second_color) = second;
    if first_count.saturating_add(second_count) == 0 {
        return Cell::from("ok").style(paint.style(theme::ok()));
    }

    let first_count_text = health_count_text(first_count);
    let second_count_text = health_count_text(second_count);
    if !paint.colored() {
        return Cell::from(format!(
            "{first_label}{first_count_text}/{second_label}{second_count_text}"
        ));
    }

    let first_style = if first_count > 0 {
        paint.bold_style(first_color)
    } else {
        paint.style(theme::muted())
    };
    let second_style = if second_count > 0 {
        paint.bold_style(second_color)
    } else {
        paint.style(theme::muted())
    };
    Cell::from(Line::from(vec![
        Span::styled(format!("{first_label}{first_count_text}"), first_style),
        Span::styled("/", paint.style(theme::muted())),
        Span::styled(format!("{second_label}{second_count_text}"), second_style),
    ]))
}

fn health_count_text(count: u64) -> String {
    if count > 9 {
        "+".to_string()
    } else {
        count.to_string()
    }
}

/// Bandwidth cell: "{rx}/{tx}" right-aligned, rx/tx halves colored when
/// there's live traffic, whole cell muted when idle (muted preset). The
/// ↓/↑ arrows live in the column header, not on every row. Takes raw
/// rates so the grouped view can feed per-group aggregates through the
/// same formatting.
pub(in crate::ui) fn bandwidth_cell<'a>(rx_bps: f64, tx_bps: f64, paint: CellPaint) -> Cell<'a> {
    let rx = format_rate_compact(rx_bps, NONE_PLACEHOLDER);
    let tx = format_rate_compact(tx_bps, NONE_PLACEHOLDER);
    let active = rx_bps > 0.0 || tx_bps > 0.0;

    let line = if !paint.colored() {
        Line::from(format!("{rx}/{tx}"))
    } else if !active && !theme::is_vivid() {
        Line::from(Span::styled(
            format!("{rx}/{tx}"),
            paint.style(theme::muted()),
        ))
    } else {
        Line::from(vec![
            Span::styled(rx, paint.style(theme::rx())),
            Span::raw("/"),
            Span::styled(tx, paint.style(theme::tx())),
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
    use crate::network::types::{
        ApplicationProtocol, Connection, DnsInfo, DnsQueryType, DpiInfo, Protocol, ProtocolState,
        QuicInfo, TcpState,
    };
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
    fn staleness_fade_tracks_the_removal_window() {
        assert_eq!(theme::staleness_fade_intensity(0.49), None);
        assert_eq!(theme::staleness_fade_intensity(0.5), Some(0.0));
        let midpoint = theme::staleness_fade_intensity(0.75).unwrap();
        assert!((midpoint - 0.5).abs() < 0.000_001);
        assert_eq!(theme::staleness_fade_intensity(1.0), Some(1.0));
        assert_eq!(theme::staleness_fade_intensity(1.5), Some(1.0));
    }

    // Width math for the full set with Location at floor widths:
    // 22+21+18+4+10+24+11+7+5+11 = 133 content + chrome(10 cols) = 10 -> 143.
    const FULL_WIDTH: u16 = 143;

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
                ColumnId::Health,
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

        // 22+21+18+10+24+11+7+5+11 = 129 + chrome(9) = 138 -> below that Service goes.
        let cols = select_columns(137, true);
        assert!(!ids(&cols).contains(&ColumnId::Service));
        assert!(ids(&cols).contains(&ColumnId::Local));

        // 22+21+18+24+11+7+5+11 = 119 + chrome(8) = 127 -> below that Local goes.
        let cols = select_columns(127, true);
        assert!(ids(&cols).contains(&ColumnId::Local));
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_FULL);
        let cols = select_columns(126, true);
        assert!(!ids(&cols).contains(&ColumnId::Local));

        // 22+21+24+11+7+5+11 = 101 + chrome(7) = 108 -> below that RTT goes.
        let cols = select_columns(108, true);
        assert!(ids(&cols).contains(&ColumnId::Rtt));
        let cols = select_columns(107, true);
        assert!(!ids(&cols).contains(&ColumnId::Rtt));

        // 22+21+24+11+5+11 = 94 + chrome(6) = 100 -> below that Health goes.
        let cols = select_columns(100, true);
        assert!(ids(&cols).contains(&ColumnId::Health));
        let cols = select_columns(99, true);
        assert!(!ids(&cols).contains(&ColumnId::Health));

        // 22+21+24+11+11 = 89 + chrome(5) = 94 -> below that App compacts.
        let cols = select_columns(93, true);
        assert_eq!(width_of(&cols, ColumnId::Application), APP_WIDTH_COMPACT);
        assert!(ids(&cols).contains(&ColumnId::State));

        // 22+21+14+11+11 = 79 + chrome(5) = 84 -> below that State goes.
        let cols = select_columns(83, true);
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
        assert_eq!(width_of(&cols, ColumnId::Health), HEALTH_WIDTH);
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

        // The historic whole-row paint wins over any per-cell color.
        assert_eq!(process_style(&conn, CellPaint::PLAIN), Style::default());

        // The default test theme resolves without truecolor, so there are
        // no identity hues and the shared process color stands.
        let base = theme::fg(theme::field_process());
        assert_eq!(process_style(&conn, CellPaint::FRESH), base);

        // Unnamed processes never hash the placeholder.
        conn.process_name = None;
        assert_eq!(process_style(&conn, CellPaint::FRESH), base);
    }

    #[test]
    fn fading_rows_keep_per_cell_colors() {
        // A connection deep into its staleness window: no whole-row
        // override, cells stay colored and carry the fade instead.
        let mut conn = tcp_conn(TcpState::Established);
        conn.last_activity = SystemTime::now() - std::time::Duration::from_secs(290);
        let (row_override, paint) = staleness_style(&conn, false);
        assert_eq!(row_override, None);
        assert!(paint.colored());
        assert!(paint.fade > 0.5, "fade was {}", paint.fade);

        // Historic rows still hand the signal to the whole-row gray.
        conn.is_historic = true;
        let (row_override, paint) = staleness_style(&conn, false);
        assert_eq!(row_override, Some(theme::historic_row()));
        assert!(!paint.colored());
    }

    #[test]
    fn signal_columns_never_fade_on_a_stale_row() {
        let mut conn = tcp_conn(TcpState::Established);
        conn.last_activity = SystemTime::now() - std::time::Duration::from_secs(290);
        let (_, paint) = staleness_style(&conn, false);
        assert!(paint.fade > 0.0);

        // Signal cells drop the fade but keep their colors.
        let signal = paint.signal();
        assert!(signal.colored());
        assert_eq!(signal.fade, 0.0);
        assert_eq!(signal.style(theme::err()), theme::fg(theme::err()));

        // The historic plain paint survives the signal conversion.
        assert_eq!(CellPaint::PLAIN.signal(), CellPaint::PLAIN);
    }

    #[test]
    fn grouped_child_process_cell_follows_the_row_fade() {
        use ratatui::buffer::Buffer;
        use ratatui::widgets::Widget;

        // A stale grouped child: the PID span is raw (no foreground), so
        // the staircase steps it down to the muted tier like any other
        // context cell instead of leaving it at full terminal foreground.
        let mut conn = tcp_conn(TcpState::Established);
        conn.last_activity = SystemTime::now() - std::time::Duration::from_secs(290);
        let (_, paint) = staleness_style(&conn, false);
        assert!(paint.fade > 0.5, "fade was {}", paint.fade);

        let render = |conn: &Connection| {
            let columns = [Column::new(ColumnId::Process, PROCESS_WIDTH)];
            let line = Line::from(vec![
                Span::styled("└─ ", theme::fg(theme::muted())),
                Span::raw("4242"),
            ]);
            let row = connection_row(conn, &columns, &UIState::default(), None, Some(line), false);
            let area = Rect::new(0, 0, PROCESS_WIDTH, 1);
            let mut buf = Buffer::empty(area);
            Table::new(vec![row], [Constraint::Length(PROCESS_WIDTH)]).render(area, &mut buf);
            let text: String = (0..PROCESS_WIDTH).map(|x| buf[(x, 0)].symbol()).collect();
            let pid_x = text.find("4242").expect("PID rendered") as u16;
            buf[(pid_x, 0)].fg
        };

        assert_eq!(render(&conn), theme::muted());

        // Fresh child rows keep the raw PID at the terminal foreground.
        conn.last_activity = SystemTime::now();
        assert_eq!(render(&conn), Color::Reset);
    }

    #[test]
    fn stale_stripe_marks_only_idle_stale_live_rows() {
        // Fresh: blank gutter.
        let mut conn = tcp_conn(TcpState::Established);
        assert_eq!(stale_stripe(&conn), Span::raw(" "));

        // Stale and idle: the stripe in the countdown's own color.
        conn.last_activity = SystemTime::now() - std::time::Duration::from_secs(290);
        let stripe = stale_stripe(&conn);
        assert_eq!(stripe.content, STALE_STRIPE);
        let fade = stale_window(&conn).expect("inside the window");
        assert_eq!(stripe.style, theme::countdown_style(fade));

        // Traffic, then history, both blank the gutter again.
        conn.current_outgoing_rate_bps = 5.0;
        assert_eq!(stale_stripe(&conn), Span::raw(" "));
        conn.current_outgoing_rate_bps = 0.0;
        conn.is_historic = true;
        assert_eq!(stale_stripe(&conn), Span::raw(" "));
    }

    #[test]
    fn countdown_only_for_idle_stale_live_rows() {
        // Fresh: no countdown.
        let mut conn = tcp_conn(TcpState::Established);
        assert_eq!(countdown_text(&conn), None);

        // Stale (300s timeout, 290s idle): counts down the ~10s left, deep
        // into the red end of the glow.
        conn.last_activity = SystemTime::now() - std::time::Duration::from_secs(290);
        let (text, fade) = countdown_text(&conn).expect("stale idle row counts down");
        assert!(text.ends_with("s left"), "got {text}");
        assert!(fade > 0.8, "fade was {fade}");

        // Traffic still moving: rates win over the countdown.
        conn.current_incoming_rate_bps = 12.0;
        assert_eq!(countdown_text(&conn), None);
        conn.current_incoming_rate_bps = 0.0;

        // Historic rows show "n/a" instead.
        conn.is_historic = true;
        assert_eq!(countdown_text(&conn), None);
    }

    #[test]
    fn health_badge_keeps_both_issue_counts_compact() {
        assert_eq!(health_count_text(3), "3");
        assert_eq!(health_count_text(10), "+");
        assert_eq!(
            format!("R{}/O{}", health_count_text(3), health_count_text(1)),
            "R3/O1"
        );
    }

    #[test]
    fn health_counts_adapt_to_quic_and_transactional_udp() {
        let mut quic = Connection::new(
            Protocol::Udp,
            "192.168.1.10:50000".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
            ProtocolState::Udp,
        );
        quic.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Quic(Box::new(QuicInfo::new(1))),
        });
        quic.protocol_health.quic_retry_count = 2;
        quic.protocol_health.quic_version_negotiation_count = 1;
        assert_eq!(health_counts(&quic), Some((HealthKind::Quic, 2, 1)));

        let mut dns = Connection::new(
            Protocol::Udp,
            "192.168.1.10:50001".parse().unwrap(),
            "1.1.1.1:53".parse().unwrap(),
            ProtocolState::Udp,
        );
        dns.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Dns(DnsInfo {
                query_name: None,
                query_type: Some(DnsQueryType::A),
                response_ips: Vec::new(),
                is_response: false,
                txid: 1,
                rcode: None,
                nodata: None,
            }),
        });
        assert_eq!(health_counts(&dns), None);
        dns.protocol_health.request_observed = true;
        dns.protocol_health.request_retry_count = 3;
        dns.protocol_health.request_timeout_count = 1;
        assert_eq!(health_counts(&dns), Some((HealthKind::Transaction, 3, 1)));
    }
}
