//! Details tab — full record for the selected connection: protocol
//! header, TCP analytics, traffic stats, and protocol-specific DPI
//! info. Also owns the DetailsBuilder / register_detail_clicks
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

#[cfg(unix)]
use std::{
    collections::HashMap,
    mem::MaybeUninit,
    ptr,
    sync::{Mutex, OnceLock},
};

use crate::network::dns::DnsResolver;
use crate::network::types::{
    AddrKind, Connection, MatchQuality, ProcessLineage, Protocol, ProtocolState,
};
use crate::ui::{
    ClickAction, ClickableRegions, Component, ComponentContext, Effect, GroupedRow, HandlerContext,
    NONE_PLACEHOLDER,
    connection_table::{build_header, column_constraints, connection_row, select_columns},
    dpi_color,
    format::{format_bytes, format_rate},
    non_dpi_app_color, section_header, state_color, theme, try_handle_connection_nav,
    try_handle_pane_wheel,
    widgets::braille_graph,
    widgets::scrollbar::draw_scrollbar,
};

/// Padded width for detail labels so values line up vertically.
/// Sized for the longest expected label ("Out-of-Order Packets" = 20 chars)
/// plus 2 chars of breathing room before the value column.
pub(in crate::ui) const DETAIL_LABEL_WIDTH: usize = 22;

/// Below this terminal width the Details info panes collapse back to a
/// single column. With label width 22 plus reasonable values, ~50 cells
/// per side is the readable floor.
const DETAILS_SPLIT_MIN_WIDTH: u16 = 100;

/// Rows scrolled per Ctrl+D / Ctrl+U press in the info panes. A fixed
/// step rather than a half page — the pane height isn't known in the
/// key handler, and a small constant feels consistent across sizes.
const DETAILS_SCROLL_STEP: u16 = 5;

/// Cap on the info/traffic content width. On ultra-wide terminals an
/// uncapped 50/50 pane split pushes the right pane (and the traffic
/// wave panels) hundreds of cells away from the left column, making
/// related fields read as scattered. ~140 keeps both info columns and
/// the RX/TX waves adjacent; the continuity strip above stays full
/// width to mirror the Overview table.
const DETAILS_MAX_CONTENT_WIDTH: u16 = 140;

/// Rows reserved for the Application card before the Transport Health card.
/// The current protocol decoders expose at most seven application fields. The
/// right pane trims the first separator, so eleven buffered rows leave ten
/// visible rows and align Transport Health with Network Context on the left.
const APPLICATION_CARD_ROWS: usize = 11;

/// Rows reserved for the Transport Health card, including its blank separator
/// and heading. TCP fills all of them with the RTT rows and counters; the
/// shorter QUIC and generic-transport variants pad to the same height so
/// switching between connections of different protocols doesn't resize the
/// dashboard.
const TRANSPORT_CARD_ROWS: usize = 9;

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
        use crossterm::event::{KeyCode, KeyModifiers};

        // Ctrl+D / Ctrl+U scroll the info panes when the record is
        // taller than the pane (j/k etc. stay reserved for flipping
        // between connections).
        match (key.code, key.modifiers) {
            (KeyCode::Char('d'), KeyModifiers::CONTROL) => {
                ctx.ui_state.details_scroll.scroll_down(DETAILS_SCROLL_STEP);
                return Some(Vec::new());
            }
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                ctx.ui_state.details_scroll.scroll_up(DETAILS_SCROLL_STEP);
                return Some(Vec::new());
            }
            _ => {}
        }
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
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        // Scroll wheel scrolls the info panes. Click events are still
        // dispatched by main.rs through ClickableRegions (the 'click a
        // field to copy' CopyField regions registered during draw).
        try_handle_pane_wheel(mouse, &mut ctx.ui_state.details_scroll)
    }
}

/// Builder for one Details pane: the rendered lines and the parallel
/// click-to-copy field entries, sharing a single label style. The two
/// vectors stay index-aligned so `register_detail_clicks` can map an
/// on-screen row back to its copyable value.
struct DetailsBuilder<'a> {
    lines: Vec<Line<'a>>,
    fields: Vec<Option<(String, String)>>,
    label_style: Style,
}

impl<'a> DetailsBuilder<'a> {
    fn new(label_style: Style) -> Self {
        Self {
            lines: Vec::new(),
            fields: Vec::new(),
            label_style,
        }
    }

    /// Number of rows pushed so far; anchors section ranges and padding.
    fn rows(&self) -> usize {
        self.lines.len()
    }

    /// Push a line with no click-to-copy target (custom headings, blank
    /// separators).
    fn plain_line(&mut self, line: Line<'a>) {
        self.lines.push(line);
        self.fields.push(None);
    }

    fn field(&mut self, label: &str, value: String) {
        self.field_styled(label, value, Style::default());
    }

    /// Push a label-value line with a custom-styled value span.
    fn field_styled(&mut self, label: &str, value: String, value_style: Style) {
        self.field_with_copy(label, value.clone(), value, value_style);
    }

    /// Push a label-value line whose rendered value differs from what
    /// click-to-copy yields (a shortened path, say).
    fn field_with_copy(&mut self, label: &str, display: String, copy: String, value_style: Style) {
        self.lines.push(Line::from(vec![
            Span::styled(
                format!("{:<width$}", label, width = DETAIL_LABEL_WIDTH),
                self.label_style,
            ),
            Span::styled(display, value_style),
        ]));
        self.fields.push(Some((label.to_string(), copy)));
    }

    /// Push a fixed set of Application-card rows. Every row renders, absent
    /// data as [`NONE_PLACEHOLDER`], so the card's row set is a function of
    /// the protocol class alone and never grows or shrinks with data
    /// availability.
    fn app_rows(&mut self, rows: &[(&str, Option<String>)]) {
        for (label, value) in rows {
            self.field(
                label,
                value
                    .clone()
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            );
        }
    }

    /// Push an RTT field with the value colored by latency (green < 50ms,
    /// yellow < 150ms, red above), or the "-" placeholder when unmeasured.
    fn rtt_field(&mut self, label: &str, rtt: Option<std::time::Duration>) {
        if let Some(rtt) = rtt {
            let rtt_ms = rtt.as_secs_f64() * 1000.0;
            let rtt_color = if rtt_ms < 50.0 {
                theme::ok()
            } else if rtt_ms < 150.0 {
                theme::warn()
            } else {
                theme::err()
            };
            self.field_styled(label, format!("{:.1}ms", rtt_ms), theme::fg(rtt_color));
        } else {
            self.field(label, NONE_PLACEHOLDER.to_string());
        }
    }

    /// Push a muted explanatory line into a card. Unlike a field row this
    /// carries no label/value pair, so it registers no click-to-copy target.
    fn note(&mut self, note: &'a str) {
        self.plain_line(Line::from(Span::styled(note, theme::fg(theme::muted()))));
    }

    /// Push a bold section heading, used to group fields under a common label
    /// (e.g. "Geolocation", "Application: HTTPS"). Headings carry no
    /// click-to-copy target.
    fn section(&mut self, title: impl Into<String>) {
        self.section_styled(title, theme::bold_fg(theme::heading()));
    }

    /// Variant of [`Self::section`] that lets the caller pick the heading
    /// style. Used by the Application section so its title takes the
    /// protocol's own color (HTTPS green, QUIC cyan, etc.) and visually links
    /// to the matching Application cell in the Overview table.
    fn section_styled(&mut self, title: impl Into<String>, style: Style) {
        self.plain_line(Line::from(""));
        self.plain_line(Line::from(Span::styled(title.into(), style)));
    }

    /// Pad a detail section to a stable height. Padding rows deliberately
    /// have no click target and render as whitespace in the borderless card
    /// layout.
    fn pad_section(&mut self, section_start: usize, target_rows: usize) {
        let missing = target_rows.saturating_sub(self.rows().saturating_sub(section_start));
        for _ in 0..missing {
            self.plain_line(Line::from(""));
        }
    }
}

#[cfg(unix)]
static USER_NAMES: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();
#[cfg(unix)]
static GROUP_NAMES: OnceLock<Mutex<HashMap<u32, Option<String>>>> = OnceLock::new();

#[cfg(unix)]
fn account_name_from_buffer(name: *const libc::c_char, buffer: &[libc::c_char]) -> Option<String> {
    if name.is_null() {
        return None;
    }

    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start.checked_add(buffer.len())?;
    let name_address = name as usize;
    if !(buffer_start..buffer_end).contains(&name_address) {
        return None;
    }

    let name_start = name_address - buffer_start;
    let name_len = buffer[name_start..].iter().position(|byte| *byte == 0)?;
    let name_bytes: Vec<u8> = buffer[name_start..name_start + name_len]
        .iter()
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    Some(String::from_utf8_lossy(&name_bytes).into_owned())
}

/// Resolve an account id to its name through a `getpwuid_r`-shaped libc call.
///
/// `name_of` projects the name pointer out of a resolved entry; the name
/// itself is read from `buffer` only after bounds validation.
#[cfg(unix)]
fn resolve_account_name<T>(
    id: u32,
    getter: unsafe extern "C" fn(
        u32,
        *mut T,
        *mut libc::c_char,
        libc::size_t,
        *mut *mut T,
    ) -> libc::c_int,
    name_of: fn(&T) -> *const libc::c_char,
) -> Option<String> {
    let mut buffer: Vec<libc::c_char> = vec![0; 1024];
    loop {
        let mut entry = MaybeUninit::<T>::uninit();
        let entry_ptr = entry.as_mut_ptr();
        let mut result = ptr::null_mut();
        // SAFETY: `entry` and `buffer` are writable for the sizes supplied,
        // and `result` is an out-pointer inspected only after a successful call.
        let status = unsafe {
            getter(
                id,
                entry_ptr,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 {
            if result != entry_ptr {
                return None;
            }
            // SAFETY: a successful lookup that returns `entry_ptr` initialized
            // the caller-owned entry.
            let entry = unsafe { entry.assume_init() };
            return account_name_from_buffer(name_of(&entry), &buffer);
        }
        if status != libc::ERANGE || buffer.len() >= 1024 * 1024 {
            return None;
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

#[cfg(unix)]
fn resolve_user_name(uid: u32) -> Option<String> {
    resolve_account_name(uid, libc::getpwuid_r, |entry: &libc::passwd| {
        entry.pw_name.cast_const()
    })
}

#[cfg(unix)]
fn resolve_group_name(gid: u32) -> Option<String> {
    resolve_account_name(gid, libc::getgrgid_r, |entry: &libc::group| {
        entry.gr_name.cast_const()
    })
}

/// Names are resolved once per id and cached for the process lifetime,
/// including failures. The first lookup can stall a frame on hosts backed by
/// directory services, and a later account rename stays stale; both are
/// acceptable for a TUI session.
#[cfg(unix)]
fn cached_account_name(
    cache: &'static OnceLock<Mutex<HashMap<u32, Option<String>>>>,
    id: u32,
    resolve: fn(u32) -> Option<String>,
) -> Option<String> {
    let cache = cache.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(name) = cache.lock().expect("account name cache poisoned").get(&id) {
        return name.clone();
    }

    let name = resolve(id);
    cache
        .lock()
        .expect("account name cache poisoned")
        .insert(id, name.clone());
    name
}

fn user_group_label(
    uid: u32,
    gid: Option<u32>,
    user_name: Option<String>,
    group_name: Option<String>,
) -> String {
    let user = user_name.unwrap_or_else(|| uid.to_string());
    let Some(gid) = gid else {
        return user;
    };
    let group = group_name.unwrap_or_else(|| gid.to_string());
    format!("{user}:{group}")
}

pub(in crate::ui) fn format_user_group(uid: u32, gid: Option<u32>) -> String {
    #[cfg(unix)]
    let user_name = cached_account_name(&USER_NAMES, uid, resolve_user_name);
    #[cfg(not(unix))]
    let user_name = None;

    #[cfg(unix)]
    let group_name = gid.and_then(|gid| cached_account_name(&GROUP_NAMES, gid, resolve_group_name));
    #[cfg(not(unix))]
    let group_name = None;

    user_group_label(uid, gid, user_name, group_name)
}

/// Shorten an executable path for a one-row display slot.
///
/// Detail rows are clipped at the pane edge, which for a long path cuts off
/// the basename, its most informative part. Instead drop components from the
/// middle: the leading components say where the binary lives (`/tmp`,
/// `~/Downloads`, `/usr/bin`), the basename says what it is, and both
/// survive. A leading `$HOME` renders as `~`. Display-only; the caller keeps
/// the full path in the click-to-copy field.
fn shorten_executable_path(
    path: &std::path::Path,
    home: Option<&std::path::Path>,
    max_width: usize,
) -> String {
    let display = match home {
        // A root or empty home would swallow every absolute path; both are
        // exactly the homes without a parent.
        Some(home) if home.parent().is_some() => match path.strip_prefix(home) {
            Ok(rest) if rest.as_os_str().is_empty() => "~".to_string(),
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        },
        _ => path.display().to_string(),
    };
    fit_path_middle(&display, max_width)
}

/// Compact elapsed-time display: "5s ago", "3m ago", "2h ago".
fn format_age(elapsed: std::time::Duration) -> String {
    let s = elapsed.as_secs();
    if s < 60 {
        format!("{}s ago", s)
    } else if s < 3600 {
        format!("{}m ago", s / 60)
    } else {
        format!("{}h ago", s / 3600)
    }
}

fn process_tree_value(lineage: &ProcessLineage, owner_name: &str, max_width: usize) -> String {
    let mut names: Vec<&str> = lineage
        .ancestors
        .iter()
        .map(|ancestor| ancestor.name.as_str())
        .collect();
    names.push(owner_name);

    let render = |start: usize, truncated: bool| {
        let chain = names[start..].join(" > ");
        if truncated {
            format!("… > {chain}")
        } else {
            chain
        }
    };

    let full = render(0, lineage.truncated);
    if full.chars().count() <= max_width {
        return full;
    }

    for start in 1..names.len() {
        let candidate = render(start, true);
        if candidate.chars().count() <= max_width {
            return candidate;
        }
    }

    if owner_name.chars().count() <= max_width {
        return owner_name.to_string();
    }
    if max_width == 0 {
        return String::new();
    }
    let prefix: String = owner_name
        .chars()
        .take(max_width.saturating_sub(1))
        .collect();
    format!("{prefix}…")
}

/// Component-aware middle ellipsis: `/nix/store/…/bin/hello`.
fn fit_path_middle(display: &str, max_width: usize) -> String {
    let width = |s: &str| s.chars().count();
    if width(display) <= max_width {
        return display.to_string();
    }

    let root = if display.starts_with('/') { "/" } else { "" };
    let components: Vec<&str> = display.split('/').filter(|c| !c.is_empty()).collect();

    let candidate = |head: usize, tail: usize| -> String {
        let mut out = String::from(root);
        for component in &components[..head] {
            out.push_str(component);
            out.push('/');
        }
        out.push('…');
        for component in &components[components.len() - tail..] {
            out.push('/');
            out.push_str(component);
        }
        out
    };

    if components.is_empty() || width(&candidate(0, 1)) > max_width {
        // Not even `…/basename` fits; keep the end of the string, which at
        // least ends in the basename.
        let keep = max_width.saturating_sub(1);
        let skip = width(display).saturating_sub(keep);
        let tail: String = display.chars().skip(skip).collect();
        return format!("…{tail}");
    }

    // Grow greedily from both ends, leading components first: where the
    // binary lives outranks which intermediate directories it sits under.
    // At least one component must stay elided, or the ellipsis would lie.
    let (mut head, mut tail) = (0, 1);
    while head + tail + 1 < components.len() {
        if width(&candidate(head + 1, tail)) <= max_width {
            head += 1;
        } else if width(&candidate(head, tail + 1)) <= max_width {
            tail += 1;
        } else {
            break;
        }
    }
    candidate(head, tail)
}

/// Format a QUIC idle timeout, as advertised in the peer's transport
/// parameters. Values are whole seconds in practice (30s, 120s), so only sub-
/// second timeouts fall back to milliseconds.
fn format_idle_timeout(timeout: std::time::Duration) -> String {
    if timeout.as_secs() > 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

/// Format a QUIC CONNECTION_CLOSE frame. Frame type 0x1d carries an
/// application-level error code (an HTTP/3 code, say), anything else is a
/// transport-level one, and the two number spaces are unrelated — so the
/// origin has to be shown alongside the code (RFC 9000 §19.19).
fn format_quic_close(close: &crate::network::types::QuicCloseInfo) -> String {
    let origin = if close.frame_type == 0x1d {
        "application"
    } else {
        "transport"
    };
    format!("{} 0x{:x}", origin, close.error_code)
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

/// Endpoint address with a broadcast/multicast annotation when the address
/// is a group or broadcast destination rather than an actual host.
fn annotated_addr(addr: std::net::SocketAddr, kind: AddrKind) -> String {
    match kind {
        AddrKind::Broadcast => format!("{addr} (broadcast)"),
        AddrKind::Multicast => format!("{addr} (multicast)"),
        AddrKind::Unicast => addr.to_string(),
    }
}

/// Remote address annotated like `annotated_addr`, plus a gateway marker when
/// the endpoint is the host's default gateway (router).
fn annotated_remote_addr(addr: std::net::SocketAddr, kind: AddrKind, is_gateway: bool) -> String {
    if is_gateway && kind == AddrKind::Unicast {
        return format!("{addr} (gateway)");
    }
    annotated_addr(addr, kind)
}

/// Scope of the remote endpoint. `bogon::classify` is stateless and cannot
/// recognize subnet-directed broadcasts (it would report the private range),
/// so the connection's parser-derived kind overrides it.
fn remote_scope(conn: &Connection) -> crate::network::bogon::Scope {
    if conn.remote_addr_kind == AddrKind::Broadcast {
        crate::network::bogon::Scope::Broadcast
    } else {
        crate::network::bogon::classify(conn.remote_addr.ip())
    }
}

/// True when a line is empty (used to trim leading separator on the right pane).
fn line_is_blank(line: &Line<'_>) -> bool {
    line.spans.iter().all(|s| s.content.is_empty())
}

/// Register one click-to-copy region per non-empty field row in a Details
/// pane. `inner` is the pane's *content* rect (the panes are borderless,
/// so callers pass the area the text actually renders into); `scroll` is
/// the pane's current scroll offset, so regions land on the rows the
/// fields actually occupy on screen.
/// `skip_placeholder_values` mirrors the existing connection-info
/// behavior of skipping NONE_PLACEHOLDER / empty values.
fn register_detail_clicks(
    click_regions: &mut ClickableRegions,
    inner: Rect,
    fields: &[Option<(String, String)>],
    skip_placeholder_values: bool,
    scroll: u16,
) {
    for (line_idx, entry) in fields.iter().enumerate() {
        if let Some((label, value)) = entry {
            if skip_placeholder_values && (value == NONE_PLACEHOLDER || value.is_empty()) {
                continue;
            }
            // Rows scrolled off the top have no on-screen position.
            let Some(visible_idx) = (line_idx as u16).checked_sub(scroll) else {
                continue;
            };
            let row_y = inner.y + visible_idx;
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

    // Top: the continuity strip (same grid as Overview). The Traffic
    // section is placed directly below the info panes (not pinned to
    // the bottom of the screen), so the tab reads top-down without a
    // void in the middle.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(STRIP_HEIGHT), Constraint::Min(0)])
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
    let body = chunks[1];

    // The Executable row shortens its path to the value column, so the pane
    // width must be known while the lines are built. Mirrors the layout
    // derivation further down: content-width cap, scrollbar gutter, and the
    // two-column split with its spacing.
    let info_width = body.width.min(DETAILS_MAX_CONTENT_WIDTH);
    let pane_width = if info_width >= DETAILS_SPLIT_MIN_WIDTH {
        info_width.saturating_sub(4) / 2
    } else {
        info_width.saturating_sub(2)
    };
    let value_width = (pane_width as usize).saturating_sub(DETAIL_LABEL_WIDTH);

    // Connection details - build lines and field entries in parallel for click-to-copy.
    // All sections share a single label_style (muted gray); visual grouping comes
    // from the bold section headings inserted by DetailsBuilder::section.
    let label_style = theme::fg(theme::label());
    let mut details = DetailsBuilder::new(label_style);
    // Index ranges in the details builder that should move to the
    // right pane when the layout splits horizontally (Application fields and
    // Transport Health). Pushed in source order; drained in reverse later.
    let mut right_ranges: Vec<std::ops::Range<usize>> = Vec::new();

    // Unlike regular sections, the first card starts without a blank separator.
    // Together with the fixed nine-row Network Context card below this gives
    // the left dashboard column a 21-row footprint for every protocol, ARP
    // included, so the cards below never move.
    details.plain_line(Line::from(Span::styled(
        "Connection",
        theme::bold_fg(theme::heading()),
    )));

    details.field("Protocol", conn.protocol.to_string());
    if conn.is_historic {
        let closed_display = if let Some(closed_at) = conn.closed_at {
            format!(
                "Closed ({})",
                format_age(closed_at.elapsed().unwrap_or_default())
            )
        } else {
            "Closed".to_string()
        };
        details.field_styled("Status", closed_display, theme::fg(theme::muted()));
    } else {
        // Mirror the historic Status line for active connections so the
        // user can see how recently traffic moved on this connection.
        // Color follows the same staleness progression as the Overview row
        // styling so the cue is consistent across views.
        let active_display = format!(
            "Active (last seen {})",
            format_age(conn.last_activity.elapsed().unwrap_or_default())
        );
        let staleness = conn.staleness_ratio();
        let active_color = theme::expiry_glow_intensity(staleness)
            .map(theme::expiry_glow)
            .unwrap_or_else(theme::ok);
        details.field_styled("Status", active_display, theme::fg(active_color));
    }
    details.field_styled(
        "Local Address",
        annotated_addr(conn.local_addr, conn.local_addr_kind),
        theme::fg(theme::field_local_addr()),
    );
    details.field_styled(
        "Remote Address",
        annotated_remote_addr(
            conn.remote_addr,
            conn.remote_addr_kind,
            conn.remote_is_gateway,
        ),
        theme::fg(theme::field_remote_addr()),
    );
    details.field_styled(
        "Scope",
        remote_scope(conn).label().to_string(),
        theme::fg(theme::field_remote_addr()),
    );
    details.field_styled(
        "State",
        conn.state().into_owned(),
        theme::fg(state_color(conn)),
    );
    details.field_styled(
        "Process",
        conn.process_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_process()),
    );
    details.field(
        "PID",
        conn.pid
            .map(|p| p.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
    );
    details.field_styled(
        "Service",
        conn.service_name
            .clone()
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_service()),
    );

    // Network enrichment is a fixed card. Fields remain in the same rows even
    // while asynchronous DNS and GeoIP data arrives, which prevents the lower
    // dashboard and traffic section from jumping during connection navigation.
    let (local_hostname, remote_hostname) = dns_resolver
        .map(|resolver| {
            (
                resolver.get_hostname(&conn.local_addr.ip()),
                resolver.get_hostname(&conn.remote_addr.ip()),
            )
        })
        .unwrap_or((None, None));

    // MAC + vendor from the neighbor cache (learned from ARP and NDP).
    // Present only for on-link addresses that appeared in such an exchange,
    // so a public remote can never show the router's identity.
    let (local_mac, remote_mac) = (
        ctx.app.lookup_neighbor(conn.local_addr.ip()),
        ctx.app.lookup_neighbor(conn.remote_addr.ip()),
    );
    let format_mac = |entry: crate::network::neighbors::NeighborEntry| {
        if let Some(vendor) = entry.vendor {
            format!("{} ({})", entry.mac, vendor)
        } else if crate::network::oui::is_locally_administered(&entry.mac) {
            format!("{} (locally administered)", entry.mac)
        } else {
            entry.mac
        }
    };

    let country = conn
        .geoip_info
        .as_ref()
        .and_then(|geoip| {
            geoip.country_name.as_ref().map(|name| {
                geoip
                    .country_code
                    .as_ref()
                    .map(|cc| format!("{} ({})", name, cc))
                    .unwrap_or_else(|| name.clone())
            })
        })
        .or_else(|| {
            conn.geoip_info
                .as_ref()
                .and_then(|geoip| geoip.country_code.clone())
        })
        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
    let city = conn
        .geoip_info
        .as_ref()
        .and_then(|geoip| geoip.city.clone())
        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
    let asn = conn
        .geoip_info
        .as_ref()
        .and_then(|geoip| {
            geoip.asn.map(|asn| {
                geoip
                    .as_org
                    .as_ref()
                    .map(|org| format!("AS{} ({})", asn, org))
                    .unwrap_or_else(|| format!("AS{}", asn))
            })
        })
        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());

    details.section("Network Context");
    details.field_styled(
        "Local Hostname",
        local_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_local_addr()),
    );
    // MAC and attribution rows always render, with a placeholder when
    // unresolved, so the cards below keep static positions while navigating,
    // for every protocol including ARP. The details pane scrolls, so the
    // fixed rows cannot make content unreachable on short terminals.
    details.field_styled(
        "Local MAC",
        local_mac
            .map(format_mac)
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_local_addr()),
    );
    details.field_styled(
        "Remote Hostname",
        remote_hostname.unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_remote_addr()),
    );
    // Hostname inferred from a DNS response observed on the wire, with
    // its provenance and age so it reads as an inference, not a lookup.
    // Name and provenance on separate rows: a combined value clips at
    // the card boundary for hostnames of ordinary length, hiding the
    // provenance entirely.
    let (attributed_name, attributed_via) = match &conn.attributed_hostname {
        Some(att) => {
            let source = match att.source {
                crate::network::types::AttributionSource::CapturedDns => "Captured DNS",
            };
            let age = att
                .observed_at
                .elapsed()
                .ok()
                .map(format_age)
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
            (format!("~{}", att.name), format!("{}, {}", source, age))
        }
        None => (NONE_PLACEHOLDER.to_string(), NONE_PLACEHOLDER.to_string()),
    };
    details.field_styled(
        "Attributed Name",
        attributed_name,
        theme::fg(theme::field_attributed_hostname()),
    );
    details.field_styled(
        "Attributed Via",
        attributed_via,
        theme::fg(theme::field_attributed_hostname()),
    );
    details.field_styled(
        "Remote MAC",
        remote_mac
            .map(format_mac)
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(theme::field_remote_addr()),
    );
    let location_value_style = theme::fg(theme::field_location());
    details.field_styled("Country", country, location_value_style);
    details.field_styled("City", city, location_value_style);
    details.field_styled("ASN", asn, location_value_style);

    // Richer process attribution. Every row renders with a placeholder when
    // the platform's lookup could not resolve it, so the cards below keep
    // static positions while navigating. ARP has no owning process and shows
    // all placeholders, which keeps Traffic Statistics from jumping when the
    // selection moves between an ARP entry and its neighbors in the list.
    // The Kubernetes block below stays conditional: being a k8s workload is
    // a class distinction, not missing data.
    let process_value_style = theme::fg(theme::field_process());
    details.section("Attribution");

    details.field_styled(
        "PID",
        conn.pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        process_value_style,
    );
    details.field_styled(
        "PPID",
        conn.process_ppid
            .map(|ppid| ppid.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        process_value_style,
    );
    if let (Some(lineage), Some(owner_name)) = (&conn.process_lineage, conn.process_name.as_deref())
    {
        details.field_with_copy(
            "Process Tree",
            process_tree_value(lineage, owner_name, value_width),
            process_tree_value(lineage, owner_name, usize::MAX),
            process_value_style,
        );
    } else {
        details.field_styled(
            "Process Tree",
            NONE_PLACEHOLDER.to_string(),
            process_value_style,
        );
    }
    if let Some(ref executable) = conn.executable {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        details.field_with_copy(
            "Executable",
            shorten_executable_path(executable, home.as_deref(), value_width),
            executable.display().to_string(),
            process_value_style,
        );
    } else {
        details.field_styled(
            "Executable",
            NONE_PLACEHOLDER.to_string(),
            process_value_style,
        );
    }
    details.field(
        "User",
        conn.process_uid
            .map(|uid| format_user_group(uid, conn.process_gid))
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
    );
    // A relaxed match is a plausible owner, not a proven one, so it
    // reads as a warning rather than as confirmed fact.
    let quality_color = match conn.attribution_quality {
        Some(quality) if quality.is_exact() => theme::ok(),
        Some(MatchQuality::Unspecified) | None => theme::muted(),
        Some(_) => theme::warn(),
    };
    details.field_styled(
        "Match",
        conn.attribution_quality
            .map(|quality| quality.to_string())
            .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        theme::fg(quality_color),
    );

    // Kubernetes attribution (pod / container) when the owning process is in
    // a kubepods cgroup. The card's presence is the class distinction (being
    // a k8s workload); once present, every row renders with a placeholder
    // when unresolved, so the cards below keep static positions while the
    // enrichment thread fills fields in.
    #[cfg(feature = "kubernetes")]
    if let Some(ref k8s) = conn.k8s_info {
        let k8s_value_style = theme::fg(theme::field_process());
        details.section("Kubernetes");
        // Prefer the human-readable pod name over the raw UID; show both when
        // both are present.
        let pod_display = match (&k8s.pod_name, &k8s.pod_namespace) {
            (Some(name), Some(ns)) => format!("{}/{}", ns, name),
            (Some(name), None) => name.clone(),
            (None, _) => NONE_PLACEHOLDER.to_string(),
        };
        details.field_styled("Pod", pod_display, k8s_value_style);
        details.field_styled(
            "Pod UID",
            k8s.pod_uid
                .clone()
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            k8s_value_style,
        );
        details.field_styled(
            "Container",
            k8s.container_name
                .clone()
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            k8s_value_style,
        );
        // Container IDs are 64 hex chars; truncate to the short form
        // typically shown by `kubectl get pod ... -o wide`.
        details.field_styled(
            "Container ID",
            k8s.container_id
                .as_deref()
                .map(|cid| {
                    if cid.len() >= 12 {
                        cid[..12].to_string()
                    } else {
                        cid.to_string()
                    }
                })
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            k8s_value_style,
        );
        details.field(
            "Cgroup",
            k8s.cgroup_path
                .clone()
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        );
    }

    // Add DPI / application protocol information. Section heading carries
    // both the label and the protocol so we don't need a redundant
    // "Application: <proto>" field below.
    let application_start = details.rows();
    if let Some(dpi) = &conn.dpi_info {
        details.section_styled(
            format!("Application: {}", dpi.application.sort_key()),
            theme::bold_fg(dpi_color(&dpi.application)),
        );

        // Protocol-specific details. Each protocol class renders a fixed row
        // set: absent data shows the placeholder instead of dropping the row,
        // so labels never move while navigating between connections of the
        // same class (and the card's height never depends on the data).
        match &dpi.application {
            crate::network::types::ApplicationProtocol::Http(info) => {
                details.app_rows(&[
                    ("HTTP Version", Some(info.version.to_string())),
                    ("HTTP Method", info.method.clone()),
                    ("HTTP Host", info.host.clone()),
                    ("HTTP Path", info.path.clone()),
                    ("HTTP Status", info.status_code.map(|s| s.to_string())),
                    ("User-Agent", info.user_agent.clone()),
                ]);
            }
            crate::network::types::ApplicationProtocol::Https(info) => {
                // The full row set renders even before the handshake is
                // parsed (tls_info still None): a heading-only card would
                // read as a rendering glitch rather than as pending data.
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
                // Escape hatch from app_rows: the cipher keeps its ok/warn
                // color so a weak suite still stands out.
                match tls.and_then(|t| t.format_cipher_suite()) {
                    Some(cipher) => {
                        let cipher_color = if tls
                            .and_then(|t| t.is_cipher_suite_secure())
                            .unwrap_or(false)
                        {
                            theme::ok()
                        } else {
                            theme::warn()
                        };
                        details.field_styled("Cipher Suite", cipher, theme::fg(cipher_color));
                    }
                    None => details.field("Cipher Suite", NONE_PLACEHOLDER.to_string()),
                }
            }
            crate::network::types::ApplicationProtocol::Dns(info) => {
                // The Answer row disambiguates "record doesn't exist" from
                // "answer not parsed": a NOERROR response whose answer
                // section held no record of the queried type is a deliberate
                // empty answer (NODATA).
                details.app_rows(&[
                    ("DNS Query", info.query_name.clone()),
                    ("DNS Type", info.query_type.map(|t| t.to_string())),
                    ("DNS Response IPs", join_ips(&info.response_ips)),
                    (
                        "DNS Answer",
                        (info.nodata == Some(true))
                            .then(|| "no data (name exists, no record of this type)".to_string()),
                    ),
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
                // Stratum 0 marks an unspecified/invalid stratum (RFC 5905),
                // so it renders as the placeholder rather than a value.
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
                details.app_rows(&name_service_rows(
                    info.query_name.as_ref(),
                    info.query_type.as_ref(),
                    &info.response_ips,
                ));
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
            crate::network::types::ApplicationProtocol::Ftp(info) => {
                // Code and message describe one server reply; a merged row
                // keeps the seven-row FTP card inside the shared budget.
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
        }
    } else if let ProtocolState::Arp(arp_info) = &conn.protocol_state {
        details.section_styled("Application: ARP", theme::bold_fg(non_dpi_app_color()));
        let operation = match arp_info.operation {
            crate::network::types::ArpOperation::Request => "Request",
            crate::network::types::ArpOperation::Reply => "Reply",
        };
        details.app_rows(&[
            ("Operation", Some(operation.to_string())),
            ("Sender MAC", Some(arp_info.sender_mac.clone())),
            ("Sender Vendor", arp_info.sender_vendor.clone()),
            ("Sender IP", Some(arp_info.sender_ip.to_string())),
            ("Target MAC", Some(arp_info.target_mac.clone())),
            ("Target Vendor", arp_info.target_vendor.clone()),
            ("Target IP", Some(arp_info.target_ip.to_string())),
        ]);
    } else if let ProtocolState::Icmp {
        icmp_type,
        icmp_id,
        icmp_sequence,
        ndp_neighbor,
    } = &conn.protocol_state
    {
        let is_ipv6 = conn.local_addr.is_ipv6();
        details.section_styled(
            if is_ipv6 {
                "Application: ICMPv6"
            } else {
                "Application: ICMP"
            },
            theme::bold_fg(non_dpi_app_color()),
        );
        // "ip at mac (vendor)" mirrors what the ARP card spells out over
        // separate rows: NDP messages carry a single IP-to-MAC mapping.
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
        details.section_styled("Application: IGMP", theme::bold_fg(non_dpi_app_color()));
        details.app_rows(&[
            (
                "Message",
                Some(crate::network::types::igmp_message_name(*igmp_type).into_owned()),
            ),
            ("Group Address", group_addr.map(|addr| addr.to_string())),
        ]);
    } else {
        details.section("Application");
        details.field("Detected", NONE_PLACEHOLDER.to_string());
    }

    // Short application records keep their whitespace inside the card instead
    // of pulling Transport Health and Traffic Statistics upward. All current
    // row sets fit within this budget, including FTP's and ARP's seven rows.
    debug_assert!(
        details.rows() - application_start <= APPLICATION_CARD_ROWS,
        "Application card overflowed its {APPLICATION_CARD_ROWS}-row budget \
         ({} rows): grow the budget or trim the row set",
        details.rows() - application_start,
    );
    details.pad_section(application_start, APPLICATION_CARD_ROWS);
    right_ranges.push(application_start..details.rows());

    // Transport Health is also a fixed card, but its rows are protocol
    // specific. QUIC has no equivalent of the TCP loss counters: packet numbers
    // are header-protected and ACK frames are encrypted (RFC 9001 §5.4), so
    // they aren't merely unmeasured, they're unobservable from the wire.
    // Rendering them as empty TCP labels read as "rustnet failed to measure
    // this". Each branch pads to TRANSPORT_CARD_ROWS so the geometry still
    // holds still when flipping between connections.
    let quic_info = conn
        .dpi_info
        .as_ref()
        .and_then(|dpi| match &dpi.application {
            crate::network::types::ApplicationProtocol::Quic(info) => Some(info.as_ref()),
            _ => None,
        });
    // Unicast UDP DNS is timeable without a handshake: queries and responses
    // pair up by transaction ID. TCP DNS keeps the TCP counters branch.
    let dns_info = (conn.protocol == Protocol::Udp)
        .then(|| {
            conn.dpi_info
                .as_ref()
                .and_then(|dpi| match &dpi.application {
                    crate::network::types::ApplicationProtocol::Dns(info) => Some(info),
                    _ => None,
                })
        })
        .flatten();
    // LLMNR multicast queries and unicast responses share a transaction ID,
    // so the first response provides a resolver timing despite using another
    // connection row.
    let llmnr_info = (conn.protocol == Protocol::Udp)
        .then(|| {
            conn.dpi_info
                .as_ref()
                .and_then(|dpi| match &dpi.application {
                    crate::network::types::ApplicationProtocol::Llmnr(info) => Some(info),
                    _ => None,
                })
        })
        .flatten();
    // NetBIOS requests and responses pair by transaction ID, including
    // broadcast requests answered from a host's unicast address.
    let netbios_info = (conn.protocol == Protocol::Udp)
        .then(|| {
            conn.dpi_info
                .as_ref()
                .and_then(|dpi| match &dpi.application {
                    crate::network::types::ApplicationProtocol::NetBios(info) => Some(info),
                    _ => None,
                })
        })
        .flatten();
    // STUN requests carry a transaction ID their response echoes, so a UDP
    // flow with no handshake still has a timeable exchange.
    let stun_info = conn
        .dpi_info
        .as_ref()
        .and_then(|dpi| match &dpi.application {
            crate::network::types::ApplicationProtocol::Stun(info) => Some(info),
            _ => None,
        });
    // NTP responses echo the client's transmit timestamp, so polls are
    // timeable the same way.
    let ntp_info = conn
        .dpi_info
        .as_ref()
        .and_then(|dpi| match &dpi.application {
            crate::network::types::ApplicationProtocol::Ntp(info) => Some(info),
            _ => None,
        });
    let icmp_echo_sequence = match &conn.protocol_state {
        crate::network::types::ProtocolState::Icmp {
            icmp_type: 0 | 8 | 128 | 129,
            icmp_sequence,
            ..
        } => *icmp_sequence,
        _ => None,
    };
    let metrics_start = details.rows();
    details.section("Transport Health");
    let show_rtt = conn.protocol == Protocol::Tcp || quic_info.is_some();
    if let Some(dns) = dns_info {
        details.rtt_field("DNS Response Time", conn.dns_response_time);
        if let Some(rcode) = dns.rcode {
            let rcode_color = if rcode == 0 {
                theme::ok()
            } else {
                theme::err()
            };
            details.field_styled(
                "Last Response Code",
                crate::network::types::dns_rcode_name(rcode).into_owned(),
                theme::fg(rcode_color),
            );
        } else {
            details.field("Last Response Code", NONE_PLACEHOLDER.to_string());
        }
        // Footnote style matching the QUIC branch below.
        details.plain_line(Line::from(""));
        details.note("Timed by pairing query and response IDs");
    } else if llmnr_info.is_some() {
        details.rtt_field("LLMNR Response Time", conn.llmnr_response_time);
        details.plain_line(Line::from(""));
        details.note("First response paired by transaction ID");
    } else if let Some(netbios) = netbios_info {
        details.rtt_field("NetBIOS Response Time", conn.netbios_response_time);
        if let Some(status) = netbios.response_status {
            let status_color = if status.is_success() {
                theme::ok()
            } else {
                theme::err()
            };
            details.field_styled(
                "Last Response Status",
                status.to_string(),
                theme::fg(status_color),
            );
        } else {
            details.field("Last Response Status", NONE_PLACEHOLDER.to_string());
        }
        details.plain_line(Line::from(""));
        details.note("Timed by pairing request and response IDs");
    } else if stun_info.is_some() {
        // Method and class live in the Application card; this card keeps
        // only the measured outcome.
        details.rtt_field("STUN RTT", conn.stun_rtt);
        details.plain_line(Line::from(""));
        details.note("Paired by 96-bit transaction ID");
    } else if ntp_info.is_some() {
        // Stratum lives in the Application card; this card keeps only the
        // measured outcome.
        details.rtt_field("NTP RTT", conn.ntp_rtt);
        details.plain_line(Line::from(""));
        details.note("Paired by originate timestamp echo");
    } else if let Some(sequence) = icmp_echo_sequence {
        // The row set depends only on the class (an echo flow), never on
        // direction or measurement, which both resolve asynchronously. An
        // inbound echo keeps the row as a placeholder; the footnote explains
        // that the remote sender is the one timing it.
        let is_responder = conn.connection_direction == Some(false);
        details.rtt_field("Ping RTT", conn.icmp_echo_rtt);
        details.field("Last Sequence", sequence.to_string());
        details.plain_line(Line::from(""));
        details.note(if is_responder {
            "Inbound echo: RTT is timed by the remote sender"
        } else {
            "Paired by echo ID and sequence"
        });
    } else if !show_rtt {
        // Nothing on a bare UDP or non-echo ICMP flow is timeable or
        // countable: there is no handshake or request/reply ID to pair.
        details.note("No transport metrics for this protocol");
    } else {
        details.rtt_field("Initial RTT", conn.initial_rtt);
    }
    if let Some(quic) = quic_info {
        details.field(
            "Idle Timeout",
            quic.idle_timeout
                .map(format_idle_timeout)
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        );
        details.field(
            "Connection Close",
            quic.connection_close
                .as_ref()
                .map(format_quic_close)
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
        );
        // Separated from the fields above so it reads as a footnote on the
        // card rather than another value that failed to resolve.
        details.plain_line(Line::from(""));
        details.note("Loss counters are encrypted in QUIC");
    } else if conn.protocol == Protocol::Tcp {
        let counters = conn.tcp_analytics.as_ref();
        // Live RTT: EWMA over data-segment round trips, updated for the whole
        // life of the connection (unlike the one-shot handshake RTT above).
        details.rtt_field("Live RTT", counters.and_then(|a| a.smoothed_rtt));
        for (label, value) in [
            ("TCP Retransmits", counters.map(|a| a.retransmit_count)),
            (
                "Out-of-Order Packets",
                counters.map(|a| a.out_of_order_count),
            ),
            ("Duplicate ACKs", counters.map(|a| a.duplicate_ack_count)),
            (
                "Fast Retransmits",
                counters.map(|a| a.fast_retransmit_count),
            ),
            ("Window Size", counters.map(|a| a.last_window_size as u64)),
        ] {
            details.field(
                label,
                value
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string()),
            );
        }
    }
    details.pad_section(metrics_start, TRANSPORT_CARD_ROWS);
    right_ranges.push(metrics_start..details.rows());

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
    } else if let Some(intensity) = theme::expiry_glow_intensity(staleness) {
        theme::bold_fg(theme::expiry_glow(intensity))
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
    let info_area = section_header(f, body, Line::from(band));
    let info_area = Rect {
        width: info_area.width.min(DETAILS_MAX_CONTENT_WIDTH),
        ..info_area
    };

    // Drain the Application and Transport Health cards out
    // of the main buffers when we have enough horizontal room to show two
    // columns side by side. The right pane always renders when split, even
    // if the connection has no DPI / TCP analytics, so the layout stays
    // consistent across connection types. Below the width threshold the
    // panel collapses back to a single column so narrow terminals stay
    // readable. The right pane needs no title of its own — its content
    // starts with the bold Application and Transport Health headings.
    let split_horizontally = info_area.width >= DETAILS_SPLIT_MIN_WIDTH;
    // The builder is done; the drain below reshuffles raw lines and fields.
    let DetailsBuilder {
        lines: mut details_text,
        fields: mut detail_fields,
        ..
    } = details;
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

    // The normal wide layout resolves to fixed-height dashboard cards, while
    // optional feature sections can still increase the content height. Clamp
    // the result so the Traffic section below always fits.
    // Section header + 6 content rows: direction header, totals summary,
    // and four graph rows in each of the two aligned traffic cards.
    const TRAFFIC_HEIGHT: u16 = 7;
    let content_rows = details_text.len().max(right_text.len());
    let info_h = (content_rows as u16)
        .min(info_area.height.saturating_sub(TRAFFIC_HEIGHT + 1))
        .max(1);
    // Reserve the two rightmost columns of the info area (blank gap +
    // scrollbar) and split the panes inside the remainder.
    let panes_area = Rect::new(
        info_area.x,
        info_area.y,
        info_area.width.saturating_sub(2),
        info_h,
    );

    let info_chunks: Vec<Rect> = if split_horizontally {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .spacing(2)
            .split(panes_area)
            .to_vec()
    } else {
        vec![panes_area]
    };

    // Both panes share one scroll offset (Ctrl+D/U, mouse wheel) so
    // they stay row-aligned; the taller pane bounds it.
    let max_scroll = (content_rows as u16).saturating_sub(info_h);
    let scroll = ui_state.details_scroll.clamp_for_render(max_scroll);

    // Card rows must stay one terminal row tall. Long hostnames, SNI values,
    // and identifiers are clipped at the pane edge instead of wrapping and
    // displacing every anchor below them. The complete value remains available
    // through click-to-copy.
    let left_para = Paragraph::new(details_text)
        .style(Style::default())
        .scroll((scroll, 0));
    f.render_widget(left_para, info_chunks[0]);
    register_detail_clicks(click_regions, info_chunks[0], &detail_fields, true, scroll);

    if info_chunks.len() == 2 && !right_text.is_empty() {
        let right_para = Paragraph::new(right_text)
            .style(Style::default())
            .scroll((scroll, 0));
        f.render_widget(right_para, info_chunks[1]);
        register_detail_clicks(click_regions, info_chunks[1], &right_fields, true, scroll);
    }

    // Scrollbar on the right edge of the info area, spanning the pane
    // rows; hidden when the record fits.
    draw_scrollbar(
        f,
        Rect::new(info_area.x, info_area.y, info_area.width, info_h),
        content_rows,
        scroll as usize,
        info_h as usize,
    );

    // Traffic details - also track fields for click-to-copy
    let mut traffic = DetailsBuilder::new(label_style);

    let rx_value_style = theme::fg(theme::rx());
    let tx_value_style = theme::fg(theme::tx());
    let current_in_rate = if conn.is_historic {
        "n/a".to_string()
    } else {
        format_rate(conn.current_incoming_rate_bps)
    };
    let current_out_rate = if conn.is_historic {
        "n/a".to_string()
    } else {
        format_rate(conn.current_outgoing_rate_bps)
    };
    traffic.field_styled("Bytes Sent", format_bytes(conn.bytes_sent), tx_value_style);
    traffic.field_styled(
        "Bytes Received",
        format_bytes(conn.bytes_received),
        rx_value_style,
    );
    traffic.field_styled(
        "Packets Sent",
        conn.packets_sent.to_string(),
        tx_value_style,
    );
    traffic.field_styled(
        "Packets Received",
        conn.packets_received.to_string(),
        rx_value_style,
    );
    traffic.field_styled("Current Rate (In)", current_in_rate.clone(), rx_value_style);
    traffic.field_styled(
        "Current Rate (Out)",
        current_out_rate.clone(),
        tx_value_style,
    );
    let DetailsBuilder {
        lines: traffic_text,
        fields: traffic_fields,
        ..
    } = traffic;

    // Traffic section directly under the info panes: one blank spacer
    // row, the section header, then the stat fields with per-connection
    // RX/TX gradient waves alongside (when there's room).
    let traffic_top = panes_area.y + info_h + 1;
    let traffic_bottom = info_area.y + info_area.height;
    if traffic_top >= traffic_bottom {
        return Ok(());
    }
    let traffic_full = Rect::new(
        info_area.x,
        traffic_top,
        info_area.width,
        (traffic_bottom - traffic_top).min(TRAFFIC_HEIGHT),
    );
    let traffic_area = section_header(
        f,
        traffic_full,
        Span::styled(
            " Traffic Statistics",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    );

    if split_horizontally {
        // Reuse the exact dashboard rectangles rather than recomputing a
        // percentage split. This guarantees that RX begins under Connection
        // and TX begins under Application and Transport Health.
        let cols = [
            Rect::new(
                info_chunks[0].x,
                traffic_area.y,
                info_chunks[0].width,
                traffic_area.height,
            ),
            Rect::new(
                info_chunks[1].x,
                traffic_area.y,
                info_chunks[1].width,
                traffic_area.height,
            ),
        ];

        let history = if conn.is_historic {
            None
        } else {
            ctx.app.get_connection_rate_history(&conn.key())
        };
        let fallback_rx = [if conn.is_historic {
            0
        } else {
            conn.current_incoming_rate_bps.max(0.0) as u64
        }];
        let fallback_tx = [if conn.is_historic {
            0
        } else {
            conn.current_outgoing_rate_bps.max(0.0) as u64
        }];
        let (rx, tx): (&[u64], &[u64]) = history
            .as_ref()
            .map(|history| (history.rx.as_slice(), history.tx.as_slice()))
            .unwrap_or((&fallback_rx, &fallback_tx));
        let rx_graph_ceiling = history.as_ref().map_or_else(
            || fallback_rx[0].max(1024) as f64,
            |history| history.rx_graph_ceiling,
        );
        let tx_graph_ceiling = history.as_ref().map_or_else(
            || fallback_tx[0].max(1024) as f64,
            |history| history.tx_graph_ceiling,
        );

        let rx_total = format_bytes(conn.bytes_received);
        let tx_total = format_bytes(conn.bytes_sent);
        let rx_summary = Line::from(vec![
            Span::styled("Total ", label_style),
            Span::styled(rx_total.clone(), rx_value_style),
            Span::styled("  ·  ", theme::fg(theme::muted())),
            Span::styled(format!("{} packets", conn.packets_received), rx_value_style),
        ]);
        let tx_summary = Line::from(vec![
            Span::styled("Total ", label_style),
            Span::styled(tx_total.clone(), tx_value_style),
            Span::styled("  ·  ", theme::fg(theme::muted())),
            Span::styled(format!("{} packets", conn.packets_sent), tx_value_style),
        ]);

        let traffic_history = ctx.app.get_traffic_history();
        // A fallback contains no time series to advance. Driving its single
        // point with the aggregate sampling clock makes it move left, then
        // snap right on every tick, which is especially visible immediately
        // after a connection becomes historic.
        let frac = if history.is_some() {
            traffic_history.scroll_fraction()
        } else {
            0.0
        };
        let window = traffic_history.capacity();
        braille_graph::wave_panel(
            f,
            cols[0],
            rx,
            "↓ RX",
            braille_graph::WavePanelOptions::new(frac, window)
                .with_summary(rx_summary)
                .with_max_val(rx_graph_ceiling),
            theme::rx_wave,
        );
        braille_graph::wave_panel(
            f,
            cols[1],
            tx,
            "↑ TX",
            braille_graph::WavePanelOptions::new(frac, window)
                .with_summary(tx_summary)
                .with_max_val(tx_graph_ceiling),
            theme::tx_wave,
        );

        for (area, label, rate, total, packets) in [
            (
                cols[0],
                "Current Rate (In)",
                current_in_rate,
                rx_total,
                conn.packets_received,
            ),
            (
                cols[1],
                "Current Rate (Out)",
                current_out_rate,
                tx_total,
                conn.packets_sent,
            ),
        ] {
            click_regions.register(
                Rect::new(area.x, area.y, area.width, 1),
                ClickAction::CopyField {
                    label: label.to_string(),
                    value: rate,
                },
            );
            click_regions.register(
                Rect::new(area.x, area.y + 1, area.width, 1),
                ClickAction::CopyField {
                    label: "Traffic Total".to_string(),
                    value: format!("{total}, {packets} packets"),
                },
            );
        }
    } else {
        // Narrow terminals keep the readable single-column field list.
        let traffic = Paragraph::new(traffic_text)
            .style(Style::default())
            .wrap(Wrap { trim: false });
        f.render_widget(traffic, traffic_area);
        register_detail_clicks(click_regions, traffic_area, &traffic_fields, false, 0);
    }

    Ok(())
}

#[cfg(test)]
mod path_shortening_tests {
    use super::{
        fit_path_middle, format_user_group, process_tree_value, shorten_executable_path,
        user_group_label,
    };
    use crate::network::types::{ProcessAncestor, ProcessLineage};
    use std::path::{Path, PathBuf};

    fn lineage(truncated: bool) -> ProcessLineage {
        ProcessLineage {
            ancestors: [
                (1, "systemd", "/usr/lib/systemd/systemd"),
                (100, "sshd", "/usr/sbin/sshd"),
                (200, "bash", "/usr/bin/bash"),
            ]
            .into_iter()
            .map(|(pid, name, executable)| ProcessAncestor {
                pid,
                name: name.to_string(),
                executable: Some(PathBuf::from(executable)),
                started_at_unix_ms: None,
            })
            .collect(),
            truncated,
        }
    }

    #[test]
    fn process_tree_runs_from_oldest_ancestor_to_owner() {
        assert_eq!(
            process_tree_value(&lineage(false), "curl", usize::MAX),
            "systemd > sshd > bash > curl"
        );
    }

    #[test]
    fn process_tree_keeps_the_owner_visible_in_narrow_panes() {
        assert_eq!(
            process_tree_value(&lineage(false), "curl", 17),
            "… > bash > curl"
        );
        assert_eq!(
            process_tree_value(&lineage(true), "curl", usize::MAX),
            "… > systemd > sshd > bash > curl"
        );
    }

    #[test]
    fn short_paths_render_unchanged() {
        assert_eq!(
            shorten_executable_path(Path::new("/usr/bin/curl"), None, 46),
            "/usr/bin/curl"
        );
    }

    #[test]
    fn home_prefix_renders_as_tilde() {
        assert_eq!(
            shorten_executable_path(
                Path::new("/Users/marco/bin/tool"),
                Some(Path::new("/Users/marco")),
                46
            ),
            "~/bin/tool"
        );
    }

    #[test]
    fn root_home_never_becomes_a_tilde() {
        assert_eq!(
            shorten_executable_path(Path::new("/usr/bin/curl"), Some(Path::new("/")), 46),
            "/usr/bin/curl"
        );
    }

    #[test]
    fn tilde_shortening_composes_with_the_middle_ellipsis() {
        let path = Path::new("/home/user/.local/share/Steam/steamapps/common/Game/game-bin");
        assert_eq!(
            shorten_executable_path(path, Some(Path::new("/home/user")), 30),
            "~/.local/share/…/Game/game-bin"
        );
    }

    #[test]
    fn location_prefix_and_basename_survive_shortening() {
        assert_eq!(
            fit_path_middle("/Applications/Firefox.app/Contents/MacOS/firefox", 30),
            "/Applications/…/MacOS/firefox"
        );
    }

    #[test]
    fn store_hashes_are_the_first_components_to_go() {
        assert_eq!(
            fit_path_middle(
                "/nix/store/8xkzp1qdcnhmzy4v7c9r2c8dyl4qv8bq-hello-2.12/bin/hello",
                25
            ),
            "/nix/store/…/bin/hello"
        );
    }

    #[test]
    fn the_ellipsis_never_lies_about_a_fitting_path() {
        // Every component fits only without the ellipsis; eliding zero
        // components while showing one would misreport the path.
        let path = "/a/bb/ccc/dddd";
        assert_eq!(fit_path_middle(path, path.len()), path);
        assert_eq!(fit_path_middle(path, path.len() - 1), "/a/bb/…/dddd");
    }

    #[test]
    fn hopeless_widths_keep_the_end_of_the_path() {
        let shortened = fit_path_middle("/usr/libexec/ApplicationFirmwareUpdater", 10);
        assert_eq!(shortened, "…reUpdater");
        assert_eq!(shortened.chars().count(), 10);
    }

    #[test]
    fn unknown_account_ids_fall_back_to_numbers() {
        assert_eq!(
            user_group_label(u32::MAX, Some(u32::MAX), None, None),
            "4294967295:4294967295"
        );
    }

    #[cfg(unix)]
    #[test]
    fn current_account_ids_resolve_to_names() {
        // SAFETY: these calls only read this process's effective credentials.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let user = super::resolve_user_name(uid).expect("current user must resolve");
        let group = super::resolve_group_name(gid).expect("current group must resolve");

        assert_eq!(format_user_group(uid, Some(gid)), format!("{user}:{group}"));
    }

    #[cfg(all(target_os = "linux", feature = "landlock"))]
    #[test]
    fn current_account_ids_resolve_with_landlock_enforced() {
        use rustnet_sandbox::{SandboxConfig, SandboxMode, apply_sandbox};

        let result = apply_sandbox(&SandboxConfig {
            mode: SandboxMode::BestEffort,
            block_network: false,
            read_paths: vec![],
            write_paths: vec![],
            drop_uid: None,
        })
        .expect("best-effort sandbox must apply without error");
        if !result.fs_restricted {
            return;
        }

        // SAFETY: these calls only read this process's effective credentials.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        assert!(
            super::resolve_user_name(uid).is_some(),
            "current user must resolve inside the sandbox"
        );
        assert!(
            super::resolve_group_name(gid).is_some(),
            "current group must resolve inside the sandbox"
        );
    }

    #[cfg(unix)]
    #[test]
    fn account_name_must_be_terminated_inside_the_supplied_buffer() {
        let buffer = [
            b'x' as libc::c_char,
            b'm' as libc::c_char,
            b'a' as libc::c_char,
            b'r' as libc::c_char,
            b'c' as libc::c_char,
            b'o' as libc::c_char,
            0,
        ];
        assert_eq!(
            super::account_name_from_buffer(buffer[1..].as_ptr(), &buffer).as_deref(),
            Some("marco")
        );

        let external = [b'x' as libc::c_char, 0];
        assert_eq!(
            super::account_name_from_buffer(external.as_ptr(), &buffer),
            None
        );
        assert_eq!(
            super::account_name_from_buffer(std::ptr::null(), &buffer),
            None
        );

        let unterminated = [b'n' as libc::c_char, b'o' as libc::c_char];
        assert_eq!(
            super::account_name_from_buffer(unterminated.as_ptr(), &unterminated),
            None
        );
    }
}

#[cfg(test)]
mod endpoint_annotation_tests {
    use super::{annotated_addr, annotated_remote_addr, remote_scope};
    use crate::network::bogon::Scope;
    use crate::network::types::{AddrKind, Connection, Protocol, ProtocolState};

    #[test]
    fn addresses_are_annotated_by_kind() {
        let addr = "192.168.0.255:51234".parse().unwrap();
        assert_eq!(
            annotated_addr(addr, AddrKind::Broadcast),
            "192.168.0.255:51234 (broadcast)"
        );
        let addr = "224.0.0.251:5353".parse().unwrap();
        assert_eq!(
            annotated_addr(addr, AddrKind::Multicast),
            "224.0.0.251:5353 (multicast)"
        );
        let addr = "192.168.0.52:60236".parse().unwrap();
        assert_eq!(
            annotated_addr(addr, AddrKind::Unicast),
            "192.168.0.52:60236"
        );
    }

    #[test]
    fn remote_addresses_are_annotated_as_gateway() {
        let addr = "192.168.0.1:34824".parse().unwrap();
        assert_eq!(
            annotated_remote_addr(addr, AddrKind::Unicast, true),
            "192.168.0.1:34824 (gateway)"
        );
        assert_eq!(
            annotated_remote_addr(addr, AddrKind::Unicast, false),
            "192.168.0.1:34824"
        );
        // The kind annotation wins over the gateway marker.
        assert_eq!(
            annotated_remote_addr(addr, AddrKind::Broadcast, true),
            "192.168.0.1:34824 (broadcast)"
        );
    }

    #[test]
    fn scope_reports_broadcast_for_subnet_directed_remote() {
        let mut conn = Connection::new(
            Protocol::Udp,
            "192.168.0.132:138".parse().unwrap(),
            "192.168.0.255:138".parse().unwrap(),
            ProtocolState::Udp,
        );
        // Stateless classification alone would report the private range.
        assert_eq!(remote_scope(&conn), Scope::Private);
        conn.remote_addr_kind = AddrKind::Broadcast;
        assert_eq!(remote_scope(&conn), Scope::Broadcast);
    }
}
