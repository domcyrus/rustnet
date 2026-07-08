//! Overview tab — the main connection list (flat or grouped), the
//! stats sidebar (interface, process detection, security, mini
//! traffic), the section separator helper, and the per-interface
//! sparkline used inside the stats sidebar.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Padding, Paragraph, Row, Sparkline, Table, Wrap},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use log::{debug, info};

use crate::app::{App, AppStats};
use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, Protocol};
use crate::ui::{
    ClickAction, ClickableRegions, Component, ComponentContext, Effect, GroupedRow, HandlerContext,
    NONE_PLACEHOLDER, SortColumn, UIState, clear_all_with_confirmation,
    connection_table::{
        Column, ColumnId, bandwidth_cell, build_header, column_constraints, connection_row,
        select_columns,
    },
    format::format_bytes,
    section_header,
    state::ProcessGroupStats,
    theme, try_handle_connection_nav,
    widgets::scrollbar::draw_scrollbar,
};

/// Overview tab — connection list + stats sidebar. Reads every
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
        // are dispatched by main.rs through ClickableRegions.
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
                if ctx.ui_state.grouping_enabled
                    && let Some(rows) = ctx.grouped_rows
                {
                    ctx.ui_state.move_selection_up_grouped(rows);
                } else {
                    ctx.ui_state.move_selection_up(ctx.connections);
                }
                Some(Vec::new())
            }
            MouseEventKind::ScrollDown => {
                if ctx.ui_state.grouping_enabled
                    && let Some(rows) = ctx.grouped_rows
                {
                    ctx.ui_state.move_selection_down_grouped(rows);
                } else {
                    ctx.ui_state.move_selection_down(ctx.connections);
                }
                Some(Vec::new())
            }
            _ => None,
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        // --- Filter mode owns its own input mini-loop ---
        if ctx.ui_state.filter_mode {
            return handle_filter_mode_key(key, ctx);
        }

        // --- Connection navigation + copy (shared with DetailsTab) ---
        if let nav @ Some(_) = try_handle_connection_nav(key, ctx) {
            return nav;
        }

        match (key.code, key.modifiers) {
            // --- Open Details on Enter (only for a real connection, not a group header) ---
            (KeyCode::Enter, _) => {
                let on_group_header =
                    ctx.ui_state.grouping_enabled && ctx.ui_state.is_group_selected();
                if !ctx.connections.is_empty() && !on_group_header {
                    ctx.ui_state.selected_tab = 1;
                }
                Some(Vec::new())
            }

            // --- Group expand / collapse ---
            (KeyCode::Char(' '), _)
                if ctx.ui_state.grouping_enabled && ctx.ui_state.is_group_selected() =>
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

            // --- Filter mode entry and exit ---
            (KeyCode::Char('/'), _) => {
                debug!("Entering filter mode");
                ctx.ui_state.enter_filter_mode();
                Some(Vec::new())
            }
            (KeyCode::Esc, _) if !ctx.ui_state.filter_query.is_empty() => {
                ctx.ui_state.clear_filter();
                Some(vec![Effect::RefreshData])
            }

            // --- Display toggles & sort ---

            // Toggle port number / service name display
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

            // Toggle hostname / IP display — DNS resolver must be enabled
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

            // Toggle historic-connection inclusion
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

            // Toggle the System stats sidebar
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

            // Toggle process grouping
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

            // Reset view settings
            (KeyCode::Char('r'), _) => {
                let was_historic = ctx.ui_state.show_historic;
                ctx.ui_state.reset_view();
                if was_historic {
                    ctx.app.set_show_historic(false);
                }
                info!("Reset view settings to defaults");
                Some(vec![Effect::RefreshData])
            }

            // Cycle sort column
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

            // Toggle sort direction (Shift+s)
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

            // (Connection navigation + 'c' copy are handled by
            // try_handle_connection_nav at the top of this function.)

            // Clear all connections (two-press confirmation)
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
        // Navigation works while typing — uses the parent's sorted list.
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
/// the longest stat lines ("Process Detection: …").
const SYSTEM_PANEL_WIDTH: u16 = 34;
/// Below this Overview width the sidebar is dropped even when toggled
/// on — the connection table needs the room more.
const SYSTEM_PANEL_MIN_AREA_WIDTH: u16 = 90;

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

    // Get DNS resolver from app if enabled
    let dns_resolver = ctx.app.get_dns_resolver();

    // Get GeoIP status - only show Loc column if country DB is loaded
    let (has_country_db, _has_asn_db, _has_city_db) = ctx.app.get_geoip_status();

    // Use grouped view if grouping is enabled
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
        draw_stats_panel(f, ctx.connections, ctx.stats, ctx.app, chunks[1])?;
    }

    Ok(())
}

fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    // Borderless: one title row, then the table.
    let area = section_header(
        f,
        area,
        connections_title(ui_state, false, connections.len()),
    );

    // Virtualization window first: the Remote column sizes itself to the
    // rows actually on screen, so the window must be known before the
    // column set is chosen.
    let scroll_offset = ui_state.scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(connections.len());
    let visible_connections = &connections[scroll_offset.min(connections.len())..window_end];

    // Reserve the two rightmost columns: a blank gap, then the scrollbar.
    let columns = select_columns(area.width.saturating_sub(2), show_location);
    let widths = column_constraints(&columns);
    let header = build_header(&columns, ui_state);

    let rows: Vec<Row> = visible_connections
        .iter()
        .map(|conn| connection_row(conn, &columns, ui_state, dns_resolver, None))
        .collect();

    // Create table state with selection adjusted to windowed slice
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_index(connections) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

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
    draw_scrollbar(f, rows_area, connections.len(), scroll_offset, visible_rows);

    // Register click regions for visible connection rows
    click_regions.scroll_area = Some(area);
    let visible_start_y = area.y + header_height;
    let max_visible_rows = area.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let conn_idx = scroll_offset + i;
        if conn_idx >= connections.len() {
            break;
        }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(area.x, row_y, area.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(conn_idx));
    }
}

/// Shared section title for the flat and grouped connection tables —
/// same bold base, same muted metadata, so toggling grouping reads as
/// a view change rather than a different screen.
fn connections_title<'a>(ui_state: &UIState, grouped: bool, shown: usize) -> Line<'a> {
    let mut base = if ui_state.show_historic {
        "Active + Historic Connections".to_string()
    } else {
        "Active Connections".to_string()
    };
    if grouped {
        base.push_str(" · Grouped by Process");
    }
    let counter = if grouped { "processes" } else { "shown" };
    let mut spans = vec![
        Span::styled(
            format!(" {base}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" · {shown} {counter}"), theme::fg(theme::muted())),
    ];
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
    ui_state: &UIState,
    grouped_rows: &[GroupedRow],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    // Borderless: one title row, then the table (same chrome as flat).
    let group_count = grouped_rows
        .iter()
        .filter(|row| matches!(row, GroupedRow::Group { .. }))
        .count();
    let area = section_header(f, area, connections_title(ui_state, true, group_count));

    // Virtualization: only build Row objects for the visible window
    let scroll_offset = ui_state.grouped_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(grouped_rows.len());
    let visible_grouped = &grouped_rows[scroll_offset.min(grouped_rows.len())..window_end];

    // Reserve the two rightmost columns: a blank gap, then the scrollbar.
    let columns = select_columns(area.width.saturating_sub(2), show_location);
    let widths = column_constraints(&columns);
    let header = build_header(&columns, ui_state);

    let rows: Vec<Row> = visible_grouped
        .iter()
        .map(|row| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => group_header_row(&columns, process_name, stats, *expanded, ui_state),
            GroupedRow::Connection {
                connection,
                is_last_in_group,
                ..
            } => {
                // The group header above carries the process name, so the
                // child row's Process cell is just the tree connector + PID.
                let connector = if *is_last_in_group {
                    "  └─ "
                } else {
                    "  ├─ "
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
                    &columns,
                    ui_state,
                    dns_resolver,
                    Some(process_cell),
                )
            }
        })
        .collect();

    // Create table state with selection adjusted to windowed slice
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_grouped_index(grouped_rows) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

    let table_area = Rect::new(area.x, area.y, area.width.saturating_sub(2), area.height);
    f.render_stateful_widget(connections_table, table_area, &mut state);

    // Scrollbar tracks the row region (below header + margin).
    let header_height = 2_u16;
    let rows_area = Rect::new(
        area.x,
        area.y + header_height,
        area.width,
        area.height.saturating_sub(header_height),
    );
    draw_scrollbar(
        f,
        rows_area,
        grouped_rows.len(),
        scroll_offset,
        visible_rows,
    );

    // Register click regions for visible grouped rows
    click_regions.scroll_area = Some(area);
    let visible_start_y = area.y + header_height;
    let max_visible_rows = area.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let row_idx = scroll_offset + i;
        if row_idx >= grouped_rows.len() {
            break;
        }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(area.x, row_y, area.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(row_idx));
    }
}

/// A process-group header row rendered on the shared grid: ▾/▸ + name +
/// count in the Process column, TCP/UDP breakdown in State, aggregate
/// bandwidth in the Bandwidth column; other cells stay empty.
fn group_header_row<'a>(
    columns: &[Column],
    process_name: &str,
    stats: &ProcessGroupStats,
    expanded: bool,
    ui_state: &UIState,
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
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::DIM | Modifier::BOLD),
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
                true,
            ),
            _ => Cell::from(""),
        })
        .collect();

    Row::new(cells)
}

/// Draw stats panel
/// Render a single-row horizontal rule between sections. Uses the default
/// terminal foreground so it matches the surrounding `Block` borders rather
/// than rendering muted gray.
fn render_section_separator(f: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let rule: String = "─".repeat(area.width as usize);
    let para = Paragraph::new(Line::from(rule));
    f.render_widget(para, area);
}

fn draw_stats_panel(
    f: &mut Frame,
    connections: &[Connection],
    stats: &AppStats,
    app: &App,
    area: Rect,
) -> Result<()> {
    // Borderless: a single quiet vertical rule separates the sidebar
    // from the connections table, and the section header names it —
    // deliberately *not* the same chrome as the table so the two read
    // as different kinds of content.
    let panel = Block::default()
        .borders(Borders::LEFT)
        .border_style(theme::fg(theme::border()))
        .padding(Padding::horizontal(1));
    let inner_area = panel.inner(area);
    f.render_widget(panel, area);
    let inner_area = section_header(
        f,
        inner_area,
        Span::styled(" System", Style::default().add_modifier(Modifier::BOLD)),
    );

    // Build the security/sandbox text up front so the chunk height can match
    // its content. Otherwise long feature lists get clipped on narrow columns.
    #[cfg(target_os = "linux")]
    let security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();
        let status_style = match sandbox_info.status.as_str() {
            "Fully enforced" => theme::fg(theme::ok()),
            "Partially enforced" => theme::fg(theme::warn()),
            "Not applied" | "Error" => theme::fg(theme::err()),
            _ => Style::default(),
        };

        let mut features: Vec<&'static str> = Vec::new();
        if sandbox_info.cap_dropped {
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

        let uid = crate::network::privileges::effective_uid();
        let (priv_label, priv_style) = if uid == 0 {
            (
                "Process: running as root".to_string(),
                theme::fg(theme::warn()),
            )
        } else {
            (format!("Process: UID {uid}"), theme::fg(theme::ok()))
        };

        let mut lines = vec![
            Line::from(vec![
                Span::raw("Sandbox: "),
                Span::styled(sandbox_info.status, status_style),
            ]),
            Line::from(available_indicator),
        ];
        if features.is_empty() {
            lines.push(Line::from(Span::styled(
                "No restrictions active",
                theme::fg(theme::warn()),
            )));
        } else {
            for f in &features {
                lines.push(Line::from(Span::styled(
                    format!("• {f}"),
                    theme::fg(theme::muted()),
                )));
            }
        }
        lines.push(Line::from(Span::styled(priv_label, priv_style)));
        lines
    };

    #[cfg(all(target_os = "macos", feature = "macos-sandbox"))]
    let security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();
        let is_enforced = sandbox_info.status.as_str() == "Fully enforced";
        let status_style = if is_enforced {
            theme::fg(theme::ok())
        } else {
            theme::fg(theme::err())
        };

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

        let uid = crate::network::privileges::effective_uid();
        let (priv_label, priv_style) = if uid == 0 {
            (
                "Process: running as root".to_string(),
                theme::fg(theme::warn()),
            )
        } else {
            (format!("Process: UID {uid}"), theme::fg(theme::ok()))
        };

        let mut lines = vec![Line::from(vec![
            Span::raw("Seatbelt: "),
            Span::styled(sandbox_info.status, status_style),
        ])];
        if features.is_empty() {
            lines.push(Line::from(Span::styled(
                "No restrictions active",
                theme::fg(theme::warn()),
            )));
        } else {
            for f in &features {
                lines.push(Line::from(Span::styled(
                    format!("• {f}"),
                    theme::fg(theme::muted()),
                )));
            }
        }
        lines.push(Line::from(Span::styled(priv_label, priv_style)));
        lines
    };

    #[cfg(all(
        unix,
        not(target_os = "linux"),
        not(all(target_os = "macos", feature = "macos-sandbox"))
    ))]
    let security_text: Vec<Line> = {
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
    let security_text: Vec<Line> = {
        let sandbox_info = app.get_sandbox_info();
        let status_style = match sandbox_info.status.as_str() {
            "Fully enforced" => theme::fg(theme::ok()),
            "Partially enforced" => theme::fg(theme::warn()),
            "Not applied" | "Error" => theme::fg(theme::err()),
            _ => Style::default(),
        };

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

        let mut lines = vec![Line::from(vec![
            Span::raw("Sandbox: "),
            Span::styled(sandbox_info.status, status_style),
        ])];
        if features.is_empty() {
            lines.push(Line::from(Span::styled(
                "No restrictions active",
                theme::fg(theme::warn()),
            )));
        } else {
            for f in &features {
                lines.push(Line::from(Span::styled(
                    format!("• {f}"),
                    theme::fg(theme::muted()),
                )));
            }
        }
        lines.push(Line::from(Span::styled(priv_label, priv_style)));
        lines
    };

    // 1 line for the "Security" heading + one line per content line.
    let security_height = 1u16 + security_text.len() as u16;

    // The Statistics block is normally 13 lines. When process detection is
    // degraded we render the warning as two indented lines (header +
    // reason) so the often-long reason text isn't crammed onto the same
    // line as "Process Detection: …" — which would truncate on a narrow
    // right column. Reserve enough extra rows for the reason to wrap onto
    // a second visual line on typical terminal widths.
    let pcap_export_enabled = app.is_pcap_export_enabled();
    let pcapng_export_enabled = app.is_pcapng_export_enabled();
    let stats_height: u16 = if app.get_process_detection_status().is_degraded {
        15
    } else {
        13
    } + if pcap_export_enabled { 4 } else { 0 }
        + if pcapng_export_enabled { 7 } else { 0 };

    // Inside the frame, sections are separated by a 1-row gap (no inner
    // borders) so the right column reads as one cohesive panel with
    // headings rather than a stack of nested boxes.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(stats_height), // Statistics (1 heading + content)
            Constraint::Length(1),            // gap
            Constraint::Length(5),            // Network Stats (1 heading + 4 content)
            Constraint::Length(1),            // gap
            Constraint::Length(security_height), // Security (heading + content)
            Constraint::Length(1),            // gap
            Constraint::Min(0),               // Traffic + interface details
        ])
        .split(inner_area);

    // Connection statistics (only count active connections, not historic)
    let tcp_count = connections
        .iter()
        .filter(|c| !c.is_historic && c.protocol == Protocol::Tcp)
        .count();
    let udp_count = connections
        .iter()
        .filter(|c| !c.is_historic && c.protocol == Protocol::Udp)
        .count();
    let active_count = connections.iter().filter(|c| !c.is_historic).count();
    let historic_count = connections.iter().filter(|c| c.is_historic).count();

    let interface_name = app
        .get_current_interface()
        .unwrap_or_else(|| "Unknown".to_string());

    let detection_status = app.get_process_detection_status();
    let (link_layer_type, is_tunnel) = app.get_link_layer_info();

    // Build process detection line(s) with color based on status
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
            Span::raw("Process Detection: "),
            Span::styled(
                detection_status.method.clone(),
                theme::fg(process_detection_color),
            ),
        ]),
    ];

    // Add degradation warning on two lines if degraded: a short header line
    // ("eBPF unavailable:") and the reason on its own indented line. Long
    // reasons (e.g. raw libbpf error text in EbpfLoadFailed) would otherwise
    // overflow the narrow right column and get clipped.
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
            format!("  {feature} unavailable:"),
            theme::fg(theme::muted()),
        )));
        conn_stats_text.push(Line::from(Span::styled(
            format!("    {reason}"),
            theme::fg(theme::muted()),
        )));
    }

    // Add remaining stats
    conn_stats_text.extend([
        Line::from(""),
        Line::from(format!("TCP Connections: {}", tcp_count)),
        Line::from(format!("UDP Connections: {}", udp_count)),
        Line::from(format!("Total Connections: {}", active_count)),
    ]);
    if historic_count > 0 {
        conn_stats_text.push(Line::from(Span::styled(
            format!("Historic: {}", historic_count),
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
            if capture_drops > 0 {
                Line::from(vec![
                    Span::raw("  Capture Drops: "),
                    Span::styled(format!("{capture_drops}"), theme::fg(theme::warn())),
                ])
            } else {
                Line::from(format!("  Capture Drops: {capture_drops}"))
            },
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
            if dropped > 0 {
                Line::from(vec![
                    Span::raw("  Export Drops: "),
                    Span::styled(format!("{dropped}"), theme::fg(theme::warn())),
                ])
            } else {
                Line::from(format!("  Export Drops: {dropped}"))
            },
            if errors > 0 {
                Line::from(vec![
                    Span::raw("  Errors: "),
                    Span::styled(format!("{errors}"), theme::fg(theme::err())),
                ])
            } else {
                Line::from(format!("  Errors: {errors}"))
            },
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

    // Network statistics (TCP analytics)
    let mut tcp_retransmits: u64 = 0;
    let mut tcp_out_of_order: u64 = 0;
    let mut tcp_fast_retransmits: u64 = 0;
    let mut tcp_connections_with_analytics = 0;

    for conn in connections {
        if let Some(analytics) = &conn.tcp_analytics {
            tcp_retransmits += analytics.retransmit_count;
            tcp_out_of_order += analytics.out_of_order_count;
            tcp_fast_retransmits += analytics.fast_retransmit_count;
            tcp_connections_with_analytics += 1;
        }
    }

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
            tcp_retransmits, total_retransmits
        )),
        Line::from(format!(
            "Out-of-Order: {} / {}",
            tcp_out_of_order, total_out_of_order
        )),
        Line::from(format!(
            "Fast Retransmits: {} / {}",
            tcp_fast_retransmits, total_fast_retransmits
        )),
        Line::from(format!(
            "Active TCP Flows: {}",
            tcp_connections_with_analytics
        )),
    ];

    let network_stats = Paragraph::new(network_stats_text).style(Style::default());
    f.render_widget(network_stats, chunks[2]);
    render_section_separator(f, chunks[3]);

    let mut security_lines: Vec<Line> = vec![Line::from(Span::styled(
        "Security",
        theme::bold_fg(theme::heading()),
    ))];
    security_lines.extend(security_text);
    let security_stats = Paragraph::new(security_lines).style(Style::default());
    f.render_widget(security_stats, chunks[4]);
    render_section_separator(f, chunks[5]);

    // Interface statistics with traffic graph
    draw_interface_stats_with_graph(f, app, chunks[6])?;

    Ok(())
}

/// Draw interface stats section with embedded traffic sparklines
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

    // Draw traffic sparklines
    let traffic_history = app.get_traffic_history();
    let sparkline_width = sections[0].width.saturating_sub(8) as usize; // Leave room for labels

    // Split sparkline area into rows
    let sparkline_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // RX sparkline
            Constraint::Length(1), // TX sparkline
            Constraint::Length(1), // Current rates
        ])
        .split(sections[0]);

    // RX row: label + sparkline
    let rx_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(sparkline_rows[0]);

    let rx_label = Paragraph::new("RX").style(theme::fg(theme::rx()));
    f.render_widget(rx_label, rx_cols[0]);

    let rx_data = traffic_history.get_rx_sparkline_data(sparkline_width);
    let rx_sparkline = Sparkline::default()
        .data(&rx_data)
        .style(theme::fg(theme::rx()));
    f.render_widget(rx_sparkline, rx_cols[1]);

    // TX row: label + sparkline
    let tx_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(sparkline_rows[1]);

    let tx_label = Paragraph::new("TX").style(theme::fg(theme::tx()));
    f.render_widget(tx_label, tx_cols[0]);

    let tx_data = traffic_history.get_tx_sparkline_data(sparkline_width);
    let tx_sparkline = Sparkline::default()
        .data(&tx_data)
        .style(theme::fg(theme::tx()));
    f.render_widget(tx_sparkline, tx_cols[1]);

    // Current rates row
    let (current_rx, current_tx) = rx_data
        .last()
        .zip(tx_data.last())
        .map(|(rx, tx)| (*rx, *tx))
        .unwrap_or((0, 0));

    let rates_text = Line::from(vec![
        Span::styled(
            format!("↓{}/s", format_bytes(current_rx)),
            theme::fg(theme::rx()),
        ),
        Span::raw(" "),
        Span::styled(
            format!("↑{}/s", format_bytes(current_tx)),
            theme::fg(theme::tx()),
        ),
    ]);
    let rates_para = Paragraph::new(rates_text);
    f.render_widget(rates_para, sparkline_rows[2]);

    // Interface details section (errors/drops only, rates shown in sparklines above)
    let all_interface_stats = app.get_interface_stats();

    // Filter to show only the captured interface (or active interfaces if "any" or "pktap")
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

    // Calculate how many interfaces can fit (1 line per interface now)
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

            let error_style = if total_errors > 0 {
                theme::fg(theme::err())
            } else {
                theme::fg(theme::ok())
            };

            let drop_style = if total_drops > 0 {
                theme::fg(theme::warn())
            } else {
                theme::fg(theme::ok())
            };

            // Show interface name with errors/drops on single line
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
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::{handle_filter_mode_key, is_filter_backspace_char};
    use crate::{
        app::{App, Config},
        ui::{ClickableRegions, HandlerContext, UIState},
    };

    #[test]
    fn filter_mode_treats_terminal_backspace_variants_as_backspace() {
        assert!(is_filter_backspace_char('\u{8}', KeyModifiers::NONE));
        assert!(is_filter_backspace_char('\u{7f}', KeyModifiers::NONE));
        assert!(is_filter_backspace_char('h', KeyModifiers::CONTROL));
        assert!(!is_filter_backspace_char('h', KeyModifiers::NONE));
    }

    #[test]
    fn filter_mode_backspace_on_empty_query_stays_in_filter_mode() {
        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .expect("create app");
        let mut ui_state = UIState::default();
        ui_state.enter_filter_mode();
        let connections = [];
        let click_regions = ClickableRegions::default();
        let mut ctx = HandlerContext {
            app: &app,
            ui_state: &mut ui_state,
            connections: &connections,
            grouped_rows: None,
            click_regions: &click_regions,
        };

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
}
