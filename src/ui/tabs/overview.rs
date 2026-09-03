//! Overview tab: the main connection list (flat or grouped), the
//! stats sidebar (interface, process detection, security, mini
//! traffic), the section separator helper, and the per-interface
//! sparkline used inside the stats sidebar.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Wrap},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use log::{debug, info};

use crate::app::{App, AppStats, ConnectionCounts};
use crate::network::dns::DnsResolver;
use crate::network::types::Connection;
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, GroupedRow, HandlerContext,
    NONE_PLACEHOLDER, SelectionMove, SortColumn, UiState, alert_style, clear_all_with_confirmation,
    connection_table::{
        CellPaint, Column, ColumnId, RowWindow, bandwidth_cell, build_header, column_constraints,
        connection_row, render_row_table, select_columns, visible_window,
    },
    format::{format_bytes, truncate_with_ellipsis},
    section_header, section_title,
    state::ProcessGroupStats,
    theme, try_handle_connection_nav,
    widgets::{badge, braille_graph},
};

/// Overview tab: connection list + stats sidebar. Reads every
/// ComponentContext field; holds no per-tab state today.
pub(in crate::ui) struct OverviewTab;

impl Component for OverviewTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_overview(f, ctx, area, click_regions)
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        // Scroll wheel: navigate the connection list, but only when
        // the cursor is over the registered scroll area. Click events
        // are dispatched by tui.rs through ClickableRegions.
        let scroll_area = ctx.click_regions.scroll_area?;
        let in_scroll_area = mouse.column >= scroll_area.x
            && mouse.column < scroll_area.x + scroll_area.width
            && mouse.row >= scroll_area.y
            && mouse.row < scroll_area.y + scroll_area.height;
        if !in_scroll_area {
            return None;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                ctx.move_selection(SelectionMove::Up);
                Some(Vec::new())
            }
            MouseEventKind::ScrollDown => {
                ctx.move_selection(SelectionMove::Down);
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        // Filter mode owns its own input mini-loop.
        if ctx.ui_state.filter_mode {
            return handle_filter_mode_key(key, ctx);
        }

        if let nav @ Some(_) = try_handle_connection_nav(key, ctx) {
            return nav;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Enter, _) => {
                let on_group_header =
                    ctx.ui_state.grouping_enabled && ctx.ui_state.is_group_selected();
                if !ctx.connections.is_empty() && !on_group_header {
                    ctx.ui_state.selected_tab = 1;
                }
                Some(Vec::new())
            }

            (KeyCode::Char(' '), _)
                if ctx.ui_state.grouping_enabled
                    && ctx.ui_state.selected_group_expansion().is_some() =>
            {
                ctx.ui_state.toggle_group_expansion();
                Some(vec![Effect::Regroup])
            }
            (KeyCode::Left, _) if ctx.ui_state.grouping_enabled => {
                ctx.ui_state.collapse_selected_group();
                Some(vec![Effect::Regroup])
            }
            (KeyCode::Right, _) if ctx.ui_state.grouping_enabled => {
                ctx.ui_state.expand_selected_group();
                Some(vec![Effect::Regroup])
            }
            (KeyCode::Char('l'), _) if ctx.ui_state.grouping_enabled => {
                ctx.ui_state.expand_selected_group();
                Some(vec![Effect::Regroup])
            }

            (KeyCode::Char('/'), _) => {
                debug!("Entering filter mode");
                ctx.ui_state.enter_filter_mode();
                Some(Vec::new())
            }
            (KeyCode::Esc, _) if !ctx.ui_state.filter_query.is_empty() => {
                ctx.ui_state.clear_filter();
                Some(vec![Effect::RefreshData])
            }

            (KeyCode::Char('p'), _) => {
                ctx.ui_state.show_port_numbers = !ctx.ui_state.show_port_numbers;
                info!(
                    "Toggled port display: {}",
                    if ctx.ui_state.show_port_numbers {
                        "showing port numbers"
                    } else {
                        "showing service names"
                    }
                );
                Some(Vec::new())
            }

            (KeyCode::Char('d'), _) if ctx.app.is_dns_resolution_enabled() => {
                ctx.ui_state.show_hostnames = !ctx.ui_state.show_hostnames;
                info!(
                    "Toggled hostname display: {}",
                    if ctx.ui_state.show_hostnames {
                        "showing hostnames"
                    } else {
                        "showing IP addresses"
                    }
                );
                Some(Vec::new())
            }

            (KeyCode::Char('t'), _) => {
                ctx.ui_state.show_historic = !ctx.ui_state.show_historic;
                ctx.ui_state.scroll_offset = 0;
                ctx.ui_state.grouped_scroll_offset = 0;
                ctx.app.toggle_show_historic();
                info!(
                    "Historic connections: {}",
                    if ctx.ui_state.show_historic {
                        "showing"
                    } else {
                        "hidden"
                    }
                );
                Some(vec![Effect::RefreshData])
            }

            (KeyCode::Char('i'), _) => {
                ctx.ui_state.show_system_panel = !ctx.ui_state.show_system_panel;
                info!(
                    "System sidebar: {}",
                    if ctx.ui_state.show_system_panel {
                        "shown"
                    } else {
                        "hidden"
                    }
                );
                Some(Vec::new())
            }

            (KeyCode::Char('a'), _) => {
                ctx.ui_state.toggle_grouping();
                info!(
                    "Grouping mode: {}",
                    if ctx.ui_state.grouping_enabled {
                        "enabled (grouped by process)"
                    } else {
                        "disabled (flat list)"
                    }
                );
                Some(vec![Effect::Regroup])
            }

            (KeyCode::Char('r'), _) => {
                let was_historic = ctx.ui_state.show_historic;
                ctx.ui_state.reset_view();
                if was_historic {
                    ctx.app.set_show_historic(false);
                }
                info!("Reset view settings to defaults");
                Some(vec![Effect::RefreshData])
            }

            (KeyCode::Char('s'), KeyModifiers::NONE) => {
                ctx.ui_state.cycle_sort_column();
                info!(
                    "Sort column: {} ({})",
                    ctx.ui_state.sort_column.display_name(),
                    if ctx.ui_state.sort_ascending {
                        "ascending"
                    } else {
                        "descending"
                    }
                );
                Some(vec![Effect::RefreshData])
            }

            (KeyCode::Char('S'), _) => {
                ctx.ui_state.toggle_sort_direction();
                info!(
                    "Sort direction: {} ({})",
                    if ctx.ui_state.sort_ascending {
                        "ascending"
                    } else {
                        "descending"
                    },
                    ctx.ui_state.sort_column.display_name()
                );
                Some(vec![Effect::RefreshData])
            }

            (KeyCode::Char('x'), _) => {
                if clear_all_with_confirmation(ctx.ui_state, ctx.app) {
                    Some(vec![Effect::RefreshData])
                } else {
                    Some(Vec::new())
                }
            }

            _ => None,
        }
    }
}

/// Filter-mode input: text entry + cursor movement + arrow-key
/// navigation through the filtered list. Active only while
/// `ui_state.filter_mode` is true.
fn handle_filter_mode_key(key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
    match key.code {
        KeyCode::Enter => {
            debug!(
                "Exiting filter mode. Filter: '{}'",
                ctx.ui_state.filter_query
            );
            ctx.ui_state.exit_filter_mode();
            Some(vec![Effect::RefreshData])
        }
        KeyCode::Esc => {
            ctx.ui_state.clear_filter();
            Some(vec![Effect::RefreshData])
        }
        KeyCode::Backspace => {
            ctx.ui_state.filter_backspace();
            Some(vec![Effect::RefreshData])
        }
        KeyCode::Delete
            if ctx.ui_state.filter_cursor_position < ctx.ui_state.filter_query.len() =>
        {
            ctx.ui_state
                .filter_query
                .remove(ctx.ui_state.filter_cursor_position);
            Some(vec![Effect::RefreshData])
        }
        KeyCode::Left => {
            ctx.ui_state.filter_cursor_left();
            Some(Vec::new())
        }
        KeyCode::Right => {
            ctx.ui_state.filter_cursor_right();
            Some(Vec::new())
        }
        KeyCode::Home => {
            ctx.ui_state.filter_cursor_position = 0;
            Some(Vec::new())
        }
        KeyCode::End => {
            ctx.ui_state.filter_cursor_position = ctx.ui_state.filter_query.len();
            Some(Vec::new())
        }
        // Navigation works while typing; it uses the parent's sorted list.
        KeyCode::Up => {
            ctx.ui_state.move_selection_up(ctx.connections);
            Some(Vec::new())
        }
        KeyCode::Down => {
            ctx.ui_state.move_selection_down(ctx.connections);
            Some(Vec::new())
        }
        // Some terminals report Backspace as a raw BS/DEL control character.
        // Ctrl+H is also Backspace in several terminal configurations.
        KeyCode::Char(c) => {
            if is_filter_backspace_char(c, key.modifiers) {
                ctx.ui_state.filter_backspace();
                return Some(vec![Effect::RefreshData]);
            }
            ctx.ui_state.filter_add_char(c);
            Some(vec![Effect::RefreshData])
        }
        _ => Some(Vec::new()),
    }
}

fn is_filter_backspace_char(c: char, modifiers: KeyModifiers) -> bool {
    matches!(c, '\u{8}' | '\u{7f}') || (c == 'h' && modifiers.contains(KeyModifiers::CONTROL))
}

/// Fixed width of the System stats sidebar. A constant (rather than a
/// percentage) keeps it from ballooning on wide terminals; it just fits
/// the longest stat lines.
const SYSTEM_PANEL_WIDTH: u16 = 34;
/// Below this Overview width the sidebar is dropped even when toggled
/// on: the connection table needs the room more.
const SYSTEM_PANEL_MIN_AREA_WIDTH: u16 = 90;
/// Minimum rows reserved for the Traffic heading, its two waves, and the
/// current-rate line. Security details yield this space on short terminals.
const TRAFFIC_MIN_HEIGHT: u16 = 4;
/// Compact Security keeps its heading and overall sandbox status visible.
const COMPACT_SECURITY_HEIGHT: u16 = 2;
const NETWORK_STATS_HEIGHT: u16 = 5;
const SECTION_GAP_HEIGHT: u16 = 1;

/// The sidebar has `SYSTEM_PANEL_WIDTH` minus the rule and padding to play
/// with, so labels here are kept short enough that `Detection: <label>` stays
/// on one line. The backends report stable machine identifiers (which the JSON
/// export keeps verbatim); only the display form is abbreviated.
fn detection_method_label(method: &str) -> &str {
    match method {
        "windows-etw+iphlpapi" => "ETW + IP Helper",
        "windows-iphlpapi" => "IP Helper",
        // "fentry" alone names the trampoline backend; the paired fexit
        // program is implied and costs 6 columns we do not have.
        "eBPF fentry/fexit + procfs" => "eBPF fentry + procfs",
        _ => method,
    }
}

/// Whether the complete Security section fits without taking the four rows
/// needed to keep the live Traffic summary usable.
fn security_details_fit(area_height: u16, stats_height: u16, full_security_height: u16) -> bool {
    let required_height = stats_height
        .saturating_add(NETWORK_STATS_HEIGHT)
        .saturating_add(TRAFFIC_MIN_HEIGHT)
        .saturating_add(SECTION_GAP_HEIGHT * 3)
        .saturating_add(full_security_height);
    area_height >= required_height
}

fn draw_overview(
    f: &mut Frame,
    ctx: &ComponentContext,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    let show_system_panel =
        ctx.ui_state.show_system_panel && area.width >= SYSTEM_PANEL_MIN_AREA_WIDTH;
    let chunks = if show_system_panel {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(SYSTEM_PANEL_WIDTH)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0)])
            .split(area)
    };

    let dns_resolver = ctx.app.get_dns_resolver();

    // The Loc column only appears when the country DB is loaded.
    let (has_country_db, _has_asn_db, _has_city_db) = ctx.app.get_geoip_status();

    if ctx.ui_state.grouping_enabled {
        if let Some(rows) = ctx.grouped_rows {
            draw_grouped_connections_list(
                f,
                ctx.ui_state,
                rows,
                chunks[0],
                dns_resolver.as_deref(),
                has_country_db,
                click_regions,
            );
        }
    } else {
        draw_connections_list(
            f,
            ctx.ui_state,
            ctx.connections,
            chunks[0],
            dns_resolver.as_deref(),
            has_country_db,
            click_regions,
        );
    }

    if show_system_panel {
        let connection_counts = if ctx.ui_state.has_active_filter() {
            ctx.app.get_connection_counts()
        } else {
            ConnectionCounts::from_connections(ctx.connections)
        };
        draw_stats_panel(f, connection_counts, ctx.stats, ctx.app, chunks[1])?;
    }

    Ok(())
}

/// The list a connection grid renders: its section title, the full row
/// list, and where the viewport and selection sit within it.
struct ConnectionGrid<'a, T> {
    title: Line<'a>,
    items: &'a [T],
    scroll_offset: usize,
    selected: Option<usize>,
}

/// Render a connection grid: section title, column selection, header, the
/// visible row window built by `row`, and the scrollbar and click regions.
/// The flat and grouped Overview lists share this scaffold so toggling
/// grouping never reads as a screen change.
fn draw_connection_grid<'a, T>(
    f: &mut Frame,
    area: Rect,
    grid: ConnectionGrid<'a, T>,
    ui_state: &UiState,
    show_location: bool,
    click_regions: &mut ClickableRegions,
    row: impl Fn(&'a T, &[Column], bool) -> Row<'a>,
) {
    let ConnectionGrid {
        title,
        items,
        scroll_offset,
        selected,
    } = grid;
    // Borderless: one title row, then the table.
    let area = section_header(f, area, title);

    // Virtualization window first: the Remote column sizes itself to the
    // rows actually on screen, so the window must be known before the
    // column set is chosen.
    let visible_rows = ui_state.visible_rows.max(1);
    let visible_items = visible_window(items, scroll_offset, visible_rows);

    // Reserve the two rightmost columns: a blank gap, then the scrollbar.
    let columns = select_columns(area.width.saturating_sub(2), show_location);
    let widths = column_constraints(&columns);
    let header = build_header(&columns, ui_state);

    let rows: Vec<Row> = visible_items
        .iter()
        .enumerate()
        .map(|(i, item)| row(item, &columns, selected == Some(scroll_offset + i)))
        .collect();

    render_row_table(
        f,
        area,
        header,
        rows,
        &widths,
        RowWindow {
            selected,
            scroll_offset,
            total_rows: items.len(),
            visible_rows,
        },
        click_regions,
    );
}

fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UiState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    let grid = ConnectionGrid {
        title: connections_title(
            ui_state,
            false,
            ui_state.has_active_filter().then_some(connections.len()),
        ),
        items: connections,
        scroll_offset: ui_state.scroll_offset,
        selected: ui_state.get_selected_index(connections),
    };
    draw_connection_grid(
        f,
        area,
        grid,
        ui_state,
        show_location,
        click_regions,
        |conn, columns, is_selected| {
            connection_row(conn, columns, ui_state, dns_resolver, None, is_selected)
        },
    );
}

/// Longest filter query shown in the title chip; longer queries are cut
/// with an ellipsis so the chip cannot crowd out the title itself.
const FILTER_CHIP_MAX: usize = 20;

/// Shared section title for the flat and grouped connection tables. The
/// visual grammar stays consistent while aggregate mode names its view.
fn connections_title<'a>(
    ui_state: &UiState,
    grouped: bool,
    filtered_count: Option<usize>,
) -> Line<'a> {
    let base = match (grouped, ui_state.show_historic) {
        (true, true) => "Process Aggregate · active + historic",
        (true, false) => "Process Aggregate",
        (false, true) => "Live + Historic Connections",
        (false, false) => "Live Connections",
    };
    let mut spans = vec![Span::styled(
        format!(" {base}"),
        Style::default().add_modifier(Modifier::BOLD),
    )];
    if let Some(shown) = filtered_count {
        let counter = if grouped { "processes" } else { "shown" };
        spans.push(Span::styled(
            format!(" · {shown} {counter}"),
            theme::fg(theme::muted()),
        ));
        // The query itself rides along as a chip, so what is being
        // filtered on stays visible without reopening filter mode.
        let query = ui_state.filter_query.trim();
        if !query.is_empty() {
            spans.push(Span::raw(" "));
            spans.extend(badge::chip(&truncate_with_ellipsis(query, FILTER_CHIP_MAX)));
        }
    }

    if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        };
        spans.push(Span::styled(
            format!(
                " · sort {} {}",
                ui_state.sort_column.display_name(),
                direction
            ),
            theme::fg(theme::muted()),
        ));
    }
    Line::from(spans)
}

/// Draw the grouped connection list (grouped by process) on the same
/// column grid as the flat view: identical header, widths, and cell
/// styling. Group headers and tree-connector children are the only
/// difference, so toggling grouping doesn't read as a screen change.
fn draw_grouped_connections_list(
    f: &mut Frame,
    ui_state: &UiState,
    grouped_rows: &[GroupedRow],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    let group_count = ui_state.has_active_filter().then(|| {
        grouped_rows
            .iter()
            .filter(|row| matches!(row, GroupedRow::Group { .. }))
            .count()
    });
    let grid = ConnectionGrid {
        title: connections_title(ui_state, true, group_count),
        items: grouped_rows,
        scroll_offset: ui_state.grouped_scroll_offset,
        selected: ui_state.get_selected_grouped_index(grouped_rows),
    };
    draw_connection_grid(
        f,
        area,
        grid,
        ui_state,
        show_location,
        click_regions,
        |row, columns, is_selected| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => group_header_row(columns, process_name, stats, *expanded, ui_state),
            GroupedRow::Connection {
                connection,
                is_last_in_group,
                ..
            } => {
                // The group header above carries the process name, so the
                // child row's Process cell is just the tree connector + PID.
                // connection_row prefixes the one-cell stripe gutter.
                let connector = if *is_last_in_group {
                    " └─ "
                } else {
                    " ├─ "
                };
                let pid = connection
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
                let process_cell = Line::from(vec![
                    Span::styled(connector.to_string(), theme::fg(theme::muted())),
                    Span::raw(pid),
                ]);
                connection_row(
                    connection,
                    columns,
                    ui_state,
                    dns_resolver,
                    Some(process_cell),
                    is_selected,
                )
            }
        },
    );
}

/// A process-group header row rendered on the shared grid: name and count in
/// Process, protocol totals in State, and aggregate rates in Bandwidth.
fn group_header_row<'a>(
    columns: &[Column],
    process_name: &str,
    stats: &ProcessGroupStats,
    expanded: bool,
    ui_state: &UiState,
) -> Row<'a> {
    let indicator = if expanded { "▾" } else { "▸" };
    // Plain BOLD (no accent): group headers are structural anchors, and
    // the accent color stays reserved for the active tab / sort indicator.
    let group_style = Style::default().add_modifier(Modifier::BOLD);

    let cells: Vec<Cell<'a>> = columns
        .iter()
        .map(|col| match col.id {
            ColumnId::Process => {
                let line = if ui_state.show_historic && stats.historic_count > 0 {
                    Line::from(vec![
                        Span::styled(
                            format!("{indicator} {process_name} ({}, ", stats.connection_count),
                            group_style,
                        ),
                        Span::styled(
                            stats.historic_count.to_string(),
                            theme::fg(theme::faint()).add_modifier(Modifier::DIM | Modifier::BOLD),
                        ),
                        Span::styled(")".to_string(), group_style),
                    ])
                } else {
                    Line::from(Span::styled(
                        format!("{indicator} {process_name} ({})", stats.connection_count),
                        group_style,
                    ))
                };
                Cell::from(line)
            }
            ColumnId::State => Cell::from(Line::from(vec![
                Span::styled("TCP:", theme::fg(theme::muted())),
                Span::raw(stats.tcp_count.to_string()),
                Span::raw(" "),
                Span::styled("UDP:", theme::fg(theme::muted())),
                Span::raw(stats.udp_count.to_string()),
            ])),
            ColumnId::Bandwidth => bandwidth_cell(
                stats.total_incoming_rate_bps,
                stats.total_outgoing_rate_bps,
                CellPaint::FRESH,
            ),
            _ => Cell::from(""),
        })
        .collect();

    Row::new(cells)
}

/// Render a single-row horizontal rule between sections, styled with the
/// theme border color so it matches every other rule in the chrome.
fn render_section_separator(f: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let rule: String = "─".repeat(area.width as usize);
    let para = Paragraph::new(Line::from(rule)).style(theme::fg(theme::border()));
    f.render_widget(para, area);
}

/// Effective-UID privilege line shared by the Linux and macOS Security
/// sections. (Windows reports Administrator status instead.)
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "macos-sandbox")
))]
fn privilege_line() -> Line<'static> {
    let uid = crate::network::privileges::effective_uid();
    let (priv_label, priv_style) = if uid == 0 {
        (
            "Process: running as root".to_string(),
            theme::fg(theme::warn()),
        )
    } else {
        (format!("Process: UID {uid}"), theme::fg(theme::ok()))
    };
    Line::from(Span::styled(priv_label, priv_style))
}

/// Shared tail of the Security section: the platform-specific `head`
/// lines, the feature bullets (or the "no restrictions" warning), and
/// the privilege line.
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "macos-sandbox"),
    target_os = "windows"
))]
fn sandbox_lines<'a, S: AsRef<str>>(
    head: Vec<Line<'a>>,
    features: &[S],
    privilege: Line<'a>,
) -> Vec<Line<'a>> {
    let mut lines = head;
    if features.is_empty() {
        lines.push(Line::from(Span::styled(
            "No restrictions active",
            theme::fg(theme::warn()),
        )));
    } else {
        for f in features {
            lines.push(Line::from(Span::styled(
                format!("• {}", f.as_ref()),
                theme::fg(theme::muted()),
            )));
        }
    }
    lines.push(privilege);
    lines
}

/// An indented `label: count` statistics line whose count turns `alert`
/// colored once it is non-zero.
fn counter_line(label: &str, count: u64, alert: Color) -> Line<'static> {
    if count > 0 {
        Line::from(vec![
            Span::raw(format!("  {label}: ")),
            Span::styled(count.to_string(), theme::fg(alert)),
        ])
    } else {
        Line::from(format!("  {label}: {count}"))
    }
}

/// The Security section's lead line: `prefix` followed by the sandbox
/// status label in its ok / warn / err color.
#[cfg(any(
    target_os = "linux",
    all(target_os = "macos", feature = "macos-sandbox"),
    target_os = "windows"
))]
fn sandbox_status_line(
    prefix: &'static str,
    status: &rustnet_sandbox::SandboxStatus,
) -> Line<'static> {
    use rustnet_sandbox::SandboxStatus;

    let status_style = match status {
        SandboxStatus::FullyEnforced => theme::fg(theme::ok()),
        SandboxStatus::PartiallyEnforced => theme::fg(theme::warn()),
        _ => theme::fg(theme::err()),
    };
    Line::from(vec![
        Span::raw(prefix),
        Span::styled(status.label(), status_style),
    ])
}

fn draw_stats_panel(
    f: &mut Frame,
    connection_counts: ConnectionCounts,
    stats: &AppStats,
    app: &App,
    area: Rect,
) -> Result<()> {
    // Borderless: a single quiet vertical rule separates the sidebar
    // from the connections table, and the section header names it:
    // deliberately *not* the same chrome as the table so the two read
    // as different kinds of content.
    let panel = Block::default()
        .borders(Borders::LEFT)
        .border_style(theme::fg(theme::border()))
        .padding(Padding::horizontal(1));
    let inner_area = panel.inner(area);
    f.render_widget(panel, area);
    let inner_area = section_header(f, inner_area, section_title(" System"));

    // Build the security/sandbox text up front so the chunk height can match
    // its content. Otherwise long feature lists get clipped on narrow columns.
    #[cfg(target_os = "linux")]
    let mut security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();

        let mut features: Vec<&'static str> = Vec::new();
        if sandbox_info.cap_net_raw_dropped {
            features.push("CAP_NET_RAW dropped");
        }
        if sandbox_info.ebpf_caps_dropped {
            features.push("eBPF caps dropped");
        }
        if sandbox_info.uid_dropped {
            features.push("Root UID dropped");
        }
        if sandbox_info.fs_restricted {
            features.push("FS restricted");
        }
        if sandbox_info.net_restricted {
            features.push("Net blocked");
        }
        if sandbox_info.scope_restricted {
            features.push("IPC scoped");
        }
        if sandbox_info.no_new_privs {
            features.push("No new privs");
        }

        // Rendered on its own line: appended to the status line it
        // overflows the fixed-width sidebar ("…[Landlo" truncation).
        let available_indicator = if let Some(abi) = sandbox_info.landlock_abi {
            // The negotiated ABI tells you which restriction tier is active:
            // v4 = TCP block, v6 = + abstract-socket/signal scoping.
            Span::styled(format!("Landlock ABI v{abi}"), theme::fg(theme::muted()))
        } else if sandbox_info.landlock_available {
            Span::styled("Landlock: kernel supported", theme::fg(theme::muted()))
        } else {
            Span::styled("Landlock: kernel unsupported", theme::fg(theme::muted()))
        };

        sandbox_lines(
            vec![
                sandbox_status_line("Sandbox: ", &sandbox_info.status),
                Line::from(available_indicator),
            ],
            &features,
            privilege_line(),
        )
    };

    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    let mut security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();

        let mut features: Vec<&'static str> = Vec::new();
        if sandbox_info.seatbelt_applied {
            features.push("Seatbelt applied");
        }
        if sandbox_info.uid_dropped {
            features.push("Root UID dropped");
        }
        if sandbox_info.fs_restricted {
            features.push("FS restricted");
        }
        if sandbox_info.net_restricted {
            features.push("Net blocked");
        }

        sandbox_lines(
            vec![sandbox_status_line("Seatbelt: ", &sandbox_info.status)],
            &features,
            privilege_line(),
        )
    };

    #[cfg(all(
        unix,
        not(target_os = "linux"),
        not(all(target_os = "macos", feature = "macos-sandbox"))
    ))]
    let mut security_text: Vec<Line> = {
        let uid = crate::network::privileges::effective_uid();
        if uid == 0 {
            vec![Line::from(Span::styled(
                "Running as root (UID 0)",
                theme::fg(theme::warn()),
            ))]
        } else {
            vec![Line::from(Span::styled(
                format!("Running as UID {uid}"),
                theme::fg(theme::ok()),
            ))]
        }
    };

    #[cfg(target_os = "windows")]
    let mut security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();

        let mut features: Vec<String> = Vec::new();
        if sandbox_info.privileges_removed {
            features.push(format!(
                "{} privilege(s) removed",
                sandbox_info.privileges_removed_count
            ));
        }
        if sandbox_info.job_object_applied {
            features.push("No child processes".to_string());
        }

        let is_elevated = crate::is_admin();
        // "Process: Administrator" rather than "running as Administrator":
        // the longer form overflows the fixed-width sidebar.
        let (priv_label, priv_style) = if is_elevated {
            (
                "Process: Administrator".to_string(),
                theme::fg(theme::warn()),
            )
        } else {
            ("Process: standard user".to_string(), theme::fg(theme::ok()))
        };

        sandbox_lines(
            vec![sandbox_status_line("Sandbox: ", &sandbox_info.status)],
            &features,
            Line::from(Span::styled(priv_label, priv_style)),
        )
    };

    // The Statistics block is normally 14 lines. Degraded process detection
    // adds two compact, indented lines for the unavailable feature and impact.
    let pcap_export_enabled = app.is_pcap_export_enabled();
    let pcapng_export_enabled = app.is_pcapng_export_enabled();
    let stats_height: u16 = if app.get_process_detection_status().is_degraded {
        16
    } else {
        14
    } + if pcap_export_enabled { 4 } else { 0 }
        + if pcapng_export_enabled { 7 } else { 0 };

    // Keep Security after the live Traffic section. If both do not fit, retain
    // the overall sandbox status and hide the static detail lines. They return
    // automatically as soon as the terminal is tall enough.
    let full_security_height = 1u16.saturating_add(security_text.len() as u16);
    let compact_security = full_security_height > COMPACT_SECURITY_HEIGHT
        && !security_details_fit(inner_area.height, stats_height, full_security_height);
    if compact_security {
        security_text.truncate(1);
    }
    let security_height = 1u16.saturating_add(security_text.len() as u16);

    // Inside the frame, sections are separated by a 1-row gap (no inner
    // borders) so the right column reads as one cohesive panel with
    // headings rather than a stack of nested boxes.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(stats_height), // Statistics (1 heading + content)
            Constraint::Length(SECTION_GAP_HEIGHT),
            Constraint::Length(NETWORK_STATS_HEIGHT),
            Constraint::Length(SECTION_GAP_HEIGHT),
            Constraint::Min(TRAFFIC_MIN_HEIGHT),
            Constraint::Length(SECTION_GAP_HEIGHT),
            Constraint::Length(security_height),
        ])
        .split(inner_area);

    let interface_name = app
        .get_current_interface()
        .unwrap_or_else(|| "Unknown".to_string());

    let detection_status = app.get_process_detection_status();
    let (link_layer_type, is_tunnel) = app.get_link_layer_info();

    // Build process detection lines with a human-facing method label. The
    // platform implementations use stable machine identifiers internally,
    // but strings such as "windows-iphlpapi" are too noisy for this sidebar.
    let process_detection_color = if detection_status.is_degraded {
        theme::warn()
    } else {
        theme::ok()
    };

    let mut conn_stats_text: Vec<Line> = vec![
        Line::from(Span::styled("Statistics", theme::bold_fg(theme::heading()))),
        Line::from(format!("Interface: {}", interface_name)),
        Line::from(format!(
            "Link Layer: {}{}",
            link_layer_type,
            if is_tunnel { " (Tunnel)" } else { "" }
        )),
        Line::from(vec![
            Span::raw("Detection: "),
            Span::styled(
                detection_method_label(&detection_status.method),
                theme::fg(process_detection_color),
            ),
        ]),
    ];

    // Keep the warning and its impact separate. This avoids constructions like
    // "ETW unavailable: ETW unavailable" and wraps predictably in narrow panes.
    if detection_status.is_degraded {
        let feature = detection_status
            .unavailable_feature
            .as_deref()
            .unwrap_or("Enhanced");
        let reason = detection_status
            .degradation_reason
            .as_deref()
            .unwrap_or("insufficient permissions");
        conn_stats_text.push(Line::from(Span::styled(
            format!("  {feature} unavailable"),
            theme::fg(theme::muted()),
        )));
        conn_stats_text.push(Line::from(Span::styled(
            format!("  {reason}"),
            theme::fg(theme::muted()),
        )));
    }

    conn_stats_text.extend([
        Line::from(""),
        Line::from(format!("TCP Connections: {}", connection_counts.tcp)),
        Line::from(format!("UDP Connections: {}", connection_counts.udp)),
        Line::from(format!("Processes: {}", connection_counts.processes)),
        Line::from(format!("Total Connections: {}", connection_counts.active)),
    ]);
    if connection_counts.historic > 0 {
        conn_stats_text.push(Line::from(Span::styled(
            format!("Historic: {}", connection_counts.historic),
            theme::fg(theme::muted()),
        )));
    }
    conn_stats_text.extend([
        Line::from(""),
        Line::from(format!(
            "Packets Processed: {}",
            stats
                .packets_processed
                .load(std::sync::atomic::Ordering::Relaxed)
        )),
        Line::from(format!(
            "Packets/sec: {}",
            app.get_traffic_history().get_latest_packets_per_sec()
        )),
        {
            let dropped = stats
                .packets_dropped
                .load(std::sync::atomic::Ordering::Relaxed);
            if dropped > 0 {
                Line::from(vec![
                    Span::raw("Packets Dropped: "),
                    Span::styled(format!("{}", dropped), theme::fg(theme::warn())),
                    Span::styled(" (backpressure)", theme::fg(theme::muted())),
                ])
            } else {
                Line::from(format!("Packets Dropped: {}", dropped))
            }
        },
    ]);

    if pcap_export_enabled {
        let written = stats
            .pcap_records_written
            .load(std::sync::atomic::Ordering::Relaxed);
        let capture_drops = stats
            .packets_dropped
            .load(std::sync::atomic::Ordering::Relaxed);

        conn_stats_text.extend([
            Line::from(""),
            Line::from(Span::styled("PCAP Export", theme::fg(theme::heading()))),
            Line::from(format!("  Written: {written}")),
            counter_line("Capture Drops", capture_drops, theme::warn()),
        ]);
    }

    if pcapng_export_enabled {
        let queued = stats
            .pcapng_records_queued
            .load(std::sync::atomic::Ordering::Relaxed);
        let written = stats
            .pcapng_records_written
            .load(std::sync::atomic::Ordering::Relaxed);
        let annotated = stats
            .pcapng_records_annotated
            .load(std::sync::atomic::Ordering::Relaxed);
        let unannotated = stats
            .pcapng_records_unannotated
            .load(std::sync::atomic::Ordering::Relaxed);
        let dropped = stats
            .pcapng_records_dropped
            .load(std::sync::atomic::Ordering::Relaxed);
        let errors = stats
            .pcapng_export_errors
            .load(std::sync::atomic::Ordering::Relaxed);

        conn_stats_text.extend([
            Line::from(""),
            Line::from(Span::styled("PCAPNG Export", theme::fg(theme::heading()))),
            Line::from(format!("  Written: {written}/{queued}")),
            Line::from(format!("  Annotated: {annotated}")),
            Line::from(format!("  Unannotated: {unannotated}")),
            counter_line("Export Drops", dropped, theme::warn()),
            counter_line("Errors", errors, theme::err()),
        ]);
    }

    // Wrap so the indented reason line for a degraded eBPF status (which can
    // be ~140 chars in the EbpfLoadFailed catch-all) flows to the next visual
    // row instead of being clipped on a narrow right column. trim:false
    // preserves the leading indent on continuation rows.
    let conn_stats = Paragraph::new(conn_stats_text)
        .style(Style::default())
        .wrap(Wrap { trim: false });
    f.render_widget(conn_stats, chunks[0]);
    render_section_separator(f, chunks[1]);

    let total_retransmits = stats
        .total_tcp_retransmits
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_out_of_order = stats
        .total_tcp_out_of_order
        .load(std::sync::atomic::Ordering::Relaxed);
    let total_fast_retransmits = stats
        .total_tcp_fast_retransmits
        .load(std::sync::atomic::Ordering::Relaxed);

    let network_stats_text: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Network Stats ", theme::bold_fg(theme::heading())),
            Span::styled("(active / total)", theme::fg(theme::muted())),
        ]),
        Line::from(format!(
            "TCP Retransmits: {} / {}",
            connection_counts.tcp_retransmits, total_retransmits
        )),
        Line::from(format!(
            "Out-of-Order: {} / {}",
            connection_counts.tcp_out_of_order, total_out_of_order
        )),
        Line::from(format!(
            "Fast Retransmits: {} / {}",
            connection_counts.tcp_fast_retransmits, total_fast_retransmits
        )),
        Line::from(format!(
            "Active TCP Flows: {}",
            connection_counts.tcp_flows_with_analytics
        )),
    ];

    let network_stats = Paragraph::new(network_stats_text).style(Style::default());
    f.render_widget(network_stats, chunks[2]);
    render_section_separator(f, chunks[3]);

    draw_interface_stats_with_graph(f, app, chunks[4])?;
    render_section_separator(f, chunks[5]);

    let security_heading = if compact_security {
        Line::from(vec![
            Span::styled("Security ", theme::bold_fg(theme::heading())),
            Span::styled("(compact)", theme::fg(theme::muted())),
        ])
    } else {
        Line::from(Span::styled("Security", theme::bold_fg(theme::heading())))
    };
    let mut security_lines: Vec<Line> = vec![security_heading];
    security_lines.extend(security_text);
    let security_stats = Paragraph::new(security_lines).style(Style::default());
    f.render_widget(security_stats, chunks[6]);

    Ok(())
}

/// One-row braille wave for the sidebar traffic graphs. Keep its color at a
/// stable point in the ramp because this compact graph has no vertical rows
/// over which to distribute a gradient.
const MINI_WAVE_INTENSITY: f64 = 0.6;
const MINI_WAVE_SMOOTHING_SAMPLES: usize = 4;
const MINI_WAVE_SCALE_PERCENTILE: usize = 90;
const MINI_WAVE_MIN_CEILING: u64 = 1024;

/// The full graph preserves short bursts, but a one-cell-high wave has only
/// four vertical dot levels. A longer trailing average prevents small traffic
/// changes from blinking individual dots on and off in the Overview sidebar.
fn smooth_mini_wave(samples: &[u64]) -> Vec<u64> {
    let mut smoothed = Vec::with_capacity(samples.len());
    let mut sum = 0u128;
    for (index, &value) in samples.iter().enumerate() {
        sum += u128::from(value);
        if index >= MINI_WAVE_SMOOTHING_SAMPLES {
            sum -= u128::from(samples[index - MINI_WAVE_SMOOTHING_SAMPLES]);
        }
        let count = (index + 1).min(MINI_WAVE_SMOOTHING_SAMPLES) as u128;
        smoothed.push((sum / count) as u64);
    }
    smoothed
}

fn mini_wave_window(width: u16, history_window: usize) -> usize {
    history_window.min(width as usize * 2)
}

fn mini_wave_ceiling(samples: &[u64], visible_window: usize) -> f64 {
    let start = samples.len().saturating_sub(visible_window);
    let mut visible = samples[start..].to_vec();
    if visible.is_empty() {
        return MINI_WAVE_MIN_CEILING as f64;
    }

    visible.sort_unstable();
    let rank = (visible.len() * MINI_WAVE_SCALE_PERCENTILE).div_ceil(100);
    let representative = visible[rank.saturating_sub(1).min(visible.len() - 1)];
    representative
        .max(MINI_WAVE_MIN_CEILING)
        .checked_next_power_of_two()
        .unwrap_or(u64::MAX) as f64
}

fn mini_wave(
    samples: &[u64],
    width: u16,
    frac: f64,
    window: usize,
    wave: fn(f64) -> Color,
) -> Vec<Line<'static>> {
    // A braille cell has two horizontal dots. Keep one traffic sample per dot
    // in this compact graph so advancing the ring translates existing crests
    // instead of resampling them against shifting fractional boundaries.
    let visible_window = mini_wave_window(width, window);
    let ceiling = mini_wave_ceiling(samples, visible_window);
    braille_graph::render(
        samples,
        width as usize,
        1,
        ceiling,
        frac,
        visible_window,
        |intensity| wave(MINI_WAVE_INTENSITY * intensity),
    )
}

/// One sidebar sparkline row: the colored RX/TX label, then the
/// smoothed mini wave. Both traffic rows differ only in label, rate
/// source, and color ramp.
fn draw_mini_wave_row(
    f: &mut Frame,
    area: Rect,
    label: &'static str,
    rates: &[u64],
    frac: f64,
    window: usize,
    wave: fn(f64) -> Color,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let label = Paragraph::new(label).style(theme::fg(wave(MINI_WAVE_INTENSITY)));
    f.render_widget(label, cols[0]);

    let data = smooth_mini_wave(rates);
    f.render_widget(
        Paragraph::new(mini_wave(&data, cols[1].width, frac, window, wave)),
        cols[1],
    );
}

fn draw_interface_stats_with_graph(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
    // Heading + sparklines (3 lines) + interface details (remaining).
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Heading
            Constraint::Length(3), // Traffic sparklines
            Constraint::Min(0),    // Interface details
        ])
        .split(area);

    let heading = Paragraph::new(Line::from(vec![Span::styled(
        "Traffic",
        theme::bold_fg(theme::heading()),
    )]));
    f.render_widget(heading, layout[0]);

    let sections = &layout[1..];

    // Single-row braille waves, same gradient style as the Graph tab.
    let traffic_history = app.get_traffic_history();
    let frac = traffic_history.scroll_fraction();
    let window = traffic_history.capacity();

    let sparkline_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // RX wave
            Constraint::Length(1), // TX wave
            Constraint::Length(1), // Current rates
        ])
        .split(sections[0]);

    let rx_rates = traffic_history.get_rx_sparkline_data(usize::MAX);
    draw_mini_wave_row(
        f,
        sparkline_rows[0],
        "RX",
        &rx_rates,
        frac,
        window,
        theme::rx_wave,
    );

    let tx_rates = traffic_history.get_tx_sparkline_data(usize::MAX);
    draw_mini_wave_row(
        f,
        sparkline_rows[1],
        "TX",
        &tx_rates,
        frac,
        window,
        theme::tx_wave,
    );

    let (current_rx, current_tx) = rx_rates
        .last()
        .zip(tx_rates.last())
        .map(|(rx, tx)| (*rx, *tx))
        .unwrap_or((0, 0));

    let rates_text = Line::from(vec![
        Span::styled(
            format!("↓{}/s", format_bytes(current_rx)),
            theme::fg(theme::rx_wave(MINI_WAVE_INTENSITY)),
        ),
        Span::raw(" "),
        Span::styled(
            format!("↑{}/s", format_bytes(current_tx)),
            theme::fg(theme::tx_wave(MINI_WAVE_INTENSITY)),
        ),
    ]);
    let rates_para = Paragraph::new(rates_text);
    f.render_widget(rates_para, sparkline_rows[2]);

    // Errors/drops only; rates are in the sparklines above.
    let all_interface_stats = app.get_interface_stats();

    // Only the captured interface, or every active one for "any" / "pktap".
    let captured_interface = app.get_current_interface();
    let filtered_interface_stats: Vec<_> = if let Some(ref iface) = captured_interface {
        let is_npf_device = iface.starts_with("\\Device\\NPF_");

        if iface == "any" || iface == "pktap" || is_npf_device {
            all_interface_stats
                .into_iter()
                .filter(|s| {
                    s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0
                })
                .collect()
        } else {
            all_interface_stats
                .into_iter()
                .filter(|s| s.interface_name == *iface)
                .collect()
        }
    } else {
        all_interface_stats
            .into_iter()
            .filter(|s| s.rx_bytes > 0 || s.tx_bytes > 0 || s.rx_packets > 0 || s.tx_packets > 0)
            .collect()
    };

    // One line per interface.
    let available_height = sections[1].height as usize;
    let max_interfaces = available_height.saturating_sub(1); // Reserve 1 for "more" message

    let interface_text: Vec<Line> = if filtered_interface_stats.is_empty() {
        vec![Line::from(Span::styled(
            "No interface stats available",
            theme::fg(theme::muted()),
        ))]
    } else {
        let mut lines = Vec::new();
        let num_to_show = max_interfaces.min(filtered_interface_stats.len());

        for stat in filtered_interface_stats.iter().take(num_to_show) {
            let total_errors = stat.rx_errors + stat.tx_errors;
            let total_drops = stat.rx_dropped + stat.tx_dropped;

            let error_style = alert_style(total_errors > 0, theme::err());
            let drop_style = alert_style(total_drops > 0, theme::warn());

            lines.push(Line::from(vec![
                Span::raw(format!("{}: ", stat.interface_name)),
                Span::raw("Err: "),
                Span::styled(format!("{}", total_errors), error_style),
                Span::raw("  Drop: "),
                Span::styled(format!("{}", total_drops), drop_style),
            ]));
        }

        if filtered_interface_stats.len() > num_to_show {
            lines.push(Line::from(Span::styled(
                format!("... {} more", filtered_interface_stats.len() - num_to_show),
                theme::fg(theme::muted()),
            )));
        }
        lines
    };

    let interface_para = Paragraph::new(interface_text);
    f.render_widget(interface_para, sections[1]);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{
        MINI_WAVE_INTENSITY, OverviewTab, SYSTEM_PANEL_WIDTH, connections_title,
        detection_method_label, handle_filter_mode_key, is_filter_backspace_char, mini_wave,
        mini_wave_ceiling, mini_wave_window, security_details_fit, smooth_mini_wave,
    };
    use crate::ui::{
        ClickableRegions, Component, Effect, HandlerContext, UiState, compute_grouped_rows,
        test_support::{empty_ctx, line_text, local_tcp, test_app},
        theme,
    };

    #[test]
    fn windows_detection_methods_use_human_facing_labels() {
        assert_eq!(
            detection_method_label("windows-etw+iphlpapi"),
            "ETW + IP Helper"
        );
        assert_eq!(detection_method_label("windows-iphlpapi"), "IP Helper");
        assert_eq!(detection_method_label("procfs"), "procfs");
    }

    #[test]
    fn security_details_only_use_rows_left_after_traffic_minimum() {
        assert!(!security_details_fit(36, 14, 11));
        assert!(security_details_fit(37, 14, 11));
    }

    #[test]
    fn detection_labels_fit_the_system_panel_on_one_line() {
        // Left rule (1) + horizontal padding (2) is what the panel spends on
        // chrome; the rest is text.
        let text_width = usize::from(SYSTEM_PANEL_WIDTH) - 3;

        for method in [
            "eBPF fentry/fexit + procfs",
            "eBPF kprobe + procfs",
            "procfs",
            "windows-etw+iphlpapi",
            "windows-iphlpapi",
            "pktap",
            "lsof",
        ] {
            let rendered = format!("Detection: {}", detection_method_label(method));
            assert!(
                rendered.chars().count() <= text_width,
                "`{rendered}` is {} columns, panel fits {text_width}",
                rendered.chars().count()
            );
        }
    }

    #[test]
    fn mini_wave_color_does_not_follow_latest_rate() {
        let quiet = mini_wave(&[64, 128], 12, 0.0, 120, theme::rx_wave);
        let busy = mini_wave(&[64, 1024], 12, 0.0, 120, theme::rx_wave);
        let expected = Some(theme::rx_wave(MINI_WAVE_INTENSITY));

        assert_eq!(quiet[0].spans[0].style.fg, expected);
        assert_eq!(busy[0].spans[0].style.fg, expected);
    }

    #[test]
    fn mini_wave_uses_a_longer_trailing_average() {
        assert_eq!(
            smooth_mini_wave(&[0, 0, 0, 400, 400]),
            vec![0, 0, 0, 100, 200]
        );
        assert_eq!(smooth_mini_wave(&[100; 6]), vec![100; 6]);
    }

    #[test]
    fn mini_wave_uses_one_sample_per_horizontal_dot() {
        assert_eq!(mini_wave_window(40, 120), 80);
        assert_eq!(mini_wave_window(80, 120), 120);
        assert_eq!(mini_wave_window(0, 120), 0);
    }

    #[test]
    fn mini_wave_scale_ignores_isolated_surges() {
        let mut isolated = vec![4_096; 120];
        isolated[20] = 1_000_000;
        assert_eq!(mini_wave_ceiling(&isolated, 80), 4_096.0);

        isolated[119] = 1_000_000;
        assert_eq!(mini_wave_ceiling(&isolated, 80), 4_096.0);

        let mut sustained = vec![4_096; 80];
        sustained[70..].fill(1_000_000);
        assert_eq!(mini_wave_ceiling(&sustained, 80), 1_048_576.0);
    }

    #[test]
    fn connection_titles_only_show_counts_for_active_filters() {
        let unfiltered = UiState::default();
        assert_eq!(
            line_text(&connections_title(&unfiltered, false, None)),
            " Live Connections"
        );

        let filtered = UiState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        // The default (muted) theme has no selection tint, so the chip
        // renders in its bracket form.
        assert_eq!(
            line_text(&connections_title(&filtered, false, Some(7))),
            " Live Connections · 7 shown [port:443]"
        );
        assert_eq!(
            line_text(&connections_title(&filtered, true, Some(3))),
            " Process Aggregate · 3 processes [port:443]"
        );

        let long = UiState {
            filter_query: "process:some-very-long-daemon-name".to_string(),
            ..Default::default()
        };
        assert_eq!(
            line_text(&connections_title(&long, false, Some(1))),
            " Live Connections · 1 shown [process:some-very-l…]"
        );

        let whitespace = UiState {
            filter_query: "   ".to_string(),
            ..Default::default()
        };
        assert!(!whitespace.has_active_filter());
        assert_eq!(
            line_text(&connections_title(&whitespace, false, None)),
            " Live Connections"
        );
    }

    #[test]
    fn filter_mode_treats_terminal_backspace_variants_as_backspace() {
        assert!(is_filter_backspace_char('\u{8}', KeyModifiers::NONE));
        assert!(is_filter_backspace_char('\u{7f}', KeyModifiers::NONE));
        assert!(is_filter_backspace_char('h', KeyModifiers::CONTROL));
        assert!(!is_filter_backspace_char('h', KeyModifiers::NONE));
    }

    #[test]
    fn filter_mode_backspace_on_empty_query_stays_in_filter_mode() {
        let app = test_app();
        let mut ui_state = UiState::default();
        ui_state.enter_filter_mode();
        let click_regions = ClickableRegions::default();
        let mut ctx = empty_ctx(&app, &mut ui_state, &click_regions);

        handle_filter_mode_key(
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
            &mut ctx,
        );
        handle_filter_mode_key(
            KeyEvent::new(KeyCode::Char('\u{7f}'), KeyModifiers::NONE),
            &mut ctx,
        );

        assert!(ctx.ui_state.filter_mode);
        assert!(ctx.ui_state.filter_query.is_empty());
        assert_eq!(ctx.ui_state.filter_cursor_position, 0);
    }

    #[test]
    fn space_collapses_parent_group_from_connection_row() {
        let app = test_app();
        let connections = vec![local_tcp(1000, "alpha"), local_tcp(1001, "alpha")];
        let mut ui_state = UiState {
            grouping_enabled: true,
            expanded_groups: HashSet::from(["alpha".to_string()]),
            ..UiState::default()
        };
        let grouped_rows = compute_grouped_rows(&connections, &ui_state.expanded_groups);
        ui_state.set_selected_grouped_by_index(&grouped_rows, 1);
        let click_regions = ClickableRegions::default();
        let mut ctx = HandlerContext {
            app: &app,
            ui_state: &mut ui_state,
            connections: &connections,
            grouped_rows: Some(&grouped_rows),
            click_regions: &click_regions,
        };

        let effects = OverviewTab.handle_key(
            KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE),
            &mut ctx,
        );

        assert!(matches!(effects.as_deref(), Some([Effect::Regroup])));
        assert!(!ctx.ui_state.expanded_groups.contains("alpha"));
        assert!(ctx.ui_state.is_group_selected());
    }
}
