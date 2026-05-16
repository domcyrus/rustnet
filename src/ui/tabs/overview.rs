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
    widgets::{Cell, Paragraph, Row, Sparkline, Table, Wrap},
};

use crate::app::{App, AppStats};
use crate::network::dns::DnsResolver;
use crate::network::types::{Connection, Protocol};
use crate::ui::{
    ClickAction, ClickableRegions, GroupedRow, NONE_PLACEHOLDER, SortColumn, UIState,
    bandwidth_line, dpi_color,
    format::{format_bytes, format_rate_compact},
    panel_block, state_color, status_indicator_cell, theme,
};

pub(in crate::ui) struct DrawContext<'a> {
    pub ui_state: &'a UIState,
    pub connections: &'a [Connection],
    pub stats: &'a AppStats,
    pub app: &'a App,
    pub grouped_rows: Option<&'a [GroupedRow<'a>]>,
}

/// Draw the overview mode
pub(in crate::ui) fn draw_overview(
    f: &mut Frame,
    ctx: &DrawContext,
    area: Rect,
    click_regions: &mut ClickableRegions,
) -> Result<()> {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

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

    draw_stats_panel(f, ctx.connections, ctx.stats, ctx.app, chunks[1])?;

    Ok(())
}

/// Draw connections list
fn draw_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    connections: &[Connection],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    // When DNS resolution is enabled, we need more space for hostnames
    let remote_addr_width = if dns_resolver.is_some() && ui_state.show_hostnames {
        30
    } else {
        21
    };

    // Build column widths dynamically based on whether location is shown
    let mut widths = vec![
        Constraint::Length(1),                 // Status indicator dot
        Constraint::Length(6),                 // Protocol
        Constraint::Length(17),                // Local Address
        Constraint::Length(remote_addr_width), // Remote Address
    ];
    if show_location {
        widths.push(Constraint::Length(4)); // Location (2-char country code)
    }
    widths.extend([
        Constraint::Length(16), // State
        Constraint::Length(10), // Service
        Constraint::Length(24), // DPI/Application
        Constraint::Length(12), // Bandwidth
        Constraint::Min(20),    // Process
    ]);

    // Helper function to add sort indicator to column headers
    let add_sort_indicator = |label: &str, columns: &[SortColumn]| -> String {
        if columns.contains(&ui_state.sort_column) && ui_state.sort_column != SortColumn::CreatedAt
        {
            let arrow = if ui_state.sort_ascending {
                "↑"
            } else {
                "↓"
            };
            format!("{} {}", label, arrow)
        } else {
            label.to_string()
        }
    };

    // Special handler for bandwidth column - shows combined total when sorting by bandwidth
    let bandwidth_label = match ui_state.sort_column {
        SortColumn::BandwidthTotal => {
            let arrow = if ui_state.sort_ascending {
                "↑"
            } else {
                "↓"
            };
            format!("Down/Up {}", arrow)
        }
        _ => "Down/Up".to_string(),
    };

    // Build header labels dynamically. The leading empty label is the
    // header for the status indicator column (●/○).
    let mut header_labels = vec![
        String::new(),
        add_sort_indicator("Pro", &[SortColumn::Protocol]),
        add_sort_indicator("Local Address", &[SortColumn::LocalAddress]),
        add_sort_indicator("Remote Address", &[SortColumn::RemoteAddress]),
    ];
    if show_location {
        header_labels.push(add_sort_indicator("Loc", &[SortColumn::Location]));
    }
    header_labels.extend([
        add_sort_indicator("State", &[SortColumn::State]),
        add_sort_indicator("Service", &[SortColumn::Service]),
        add_sort_indicator("Application / Host", &[SortColumn::Application]),
        bandwidth_label,
        add_sort_indicator("Process", &[SortColumn::Process]),
    ]);

    // Compute column index offsets. Status dot is column 0, then
    // Pro(1), Local(2), Remote(3), [Loc(4)], State(4/5), Service(5/6), ...
    let state_idx = if show_location { 5 } else { 4 };
    let service_idx = if show_location { 6 } else { 5 };
    let app_idx = if show_location { 7 } else { 6 };
    let bw_idx = if show_location { 8 } else { 7 };
    let process_idx = if show_location { 9 } else { 8 };

    let header_cells = header_labels.iter().enumerate().map(|(idx, h)| {
        let is_active = (match idx {
            0 => false, // Status dot column is not sortable
            1 => ui_state.sort_column == SortColumn::Protocol,
            2 => ui_state.sort_column == SortColumn::LocalAddress,
            3 => ui_state.sort_column == SortColumn::RemoteAddress,
            i if show_location && i == 4 => ui_state.sort_column == SortColumn::Location,
            i if i == state_idx => ui_state.sort_column == SortColumn::State,
            i if i == service_idx => ui_state.sort_column == SortColumn::Service,
            i if i == app_idx => ui_state.sort_column == SortColumn::Application,
            i if i == bw_idx => ui_state.sort_column == SortColumn::BandwidthTotal,
            i if i == process_idx => ui_state.sort_column == SortColumn::Process,
            _ => false,
        }) && ui_state.sort_column != SortColumn::CreatedAt;

        let style = if is_active {
            theme::bold_underline_fg(theme::accent())
        } else {
            theme::fg(theme::heading())
        };

        Cell::from(h.as_str()).style(style)
    });
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Virtualization: only build Row objects for the visible window
    let scroll_offset = ui_state.scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(connections.len());
    let visible_connections = &connections[scroll_offset.min(connections.len())..window_end];

    let rows: Vec<Row> = visible_connections
        .iter()
        .map(|conn| {
            let pid_str = conn
                .pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());

            // Process names are now pre-normalized at the source (PKTAP/lsof), so we can use them directly
            let process_str = conn
                .process_name
                .clone()
                .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());

            let process_display = if conn.pid.is_some() {
                // Ensure exactly one space between process name and PID: "PROCESS_NAME (PID)"
                let full_display = format!("{} ({})", process_str, pid_str);

                // Truncate process display to fit in column (roughly 20+ chars available)
                if full_display.len() > 25 {
                    format!("{}...", &full_display[..22])
                } else {
                    full_display
                }
            } else {
                // Truncate process name if no PID
                if process_str.len() > 25 {
                    format!("{}...", &process_str[..22])
                } else {
                    process_str
                }
            };

            // Display port number or service name based on toggle
            let service_display = if ui_state.show_port_numbers {
                conn.remote_addr.port().to_string()
            } else {
                let service_name = conn
                    .service_name
                    .clone()
                    .unwrap_or_else(|| NONE_PLACEHOLDER.to_string());
                // Truncate service name to fit in 8 chars
                if service_name.len() > 8 {
                    format!("{:.5}...", service_name)
                } else {
                    service_name
                }
            };

            // DPI/Application protocol display (enhanced for hostnames)
            let dpi_display = match &conn.dpi_info {
                Some(dpi) => dpi.application.to_string(),
                None => NONE_PLACEHOLDER.to_string(),
            };
            let dpi_cell_color = conn
                .dpi_info
                .as_ref()
                .map(|d| dpi_color(&d.application))
                .unwrap_or_else(theme::field_application);

            // Compact bandwidth display to fit in 14 chars
            let incoming_rate = format_rate_compact(conn.current_incoming_rate_bps);
            let outgoing_rate = format_rate_compact(conn.current_outgoing_rate_bps);

            // Determine row-level style by staleness.
            //   - Fresh: per-cell field colors, no row override.
            //   - Historic: per-cell field colors preserved, row gets DIM
            //     so the colors fade but stay distinguishable.
            //   - Critical / Aging (≥90% / ≥75% TTL): per-cell colors are
            //     suppressed and the whole row goes red / yellow so the
            //     operational signal dominates.
            let staleness = conn.staleness_ratio();
            let (row_override, color_cells) = if conn.is_historic {
                (Some(Style::default().add_modifier(Modifier::DIM)), true)
            } else if staleness >= 0.90 {
                (Some(theme::fg(theme::err())), false)
            } else if staleness >= 0.75 {
                (Some(theme::fg(theme::warn())), false)
            } else {
                (None, true)
            };

            // Format addresses - use hostnames when DNS resolution is enabled and show_hostnames is true
            let local_addr_display = conn.local_addr.to_string();
            let remote_addr_display = if ui_state.show_hostnames && conn.protocol != Protocol::Arp {
                if let Some(resolver) = dns_resolver {
                    if let Some(hostname) = resolver.get_hostname(&conn.remote_addr.ip()) {
                        // Truncate hostname if too long, but always show port
                        let port = conn.remote_addr.port();
                        let max_hostname_len = (remote_addr_width as usize).saturating_sub(7); // Leave room for :port
                        if hostname.len() > max_hostname_len {
                            format!(
                                "{}...:{}",
                                &hostname[..max_hostname_len.saturating_sub(3)],
                                port
                            )
                        } else {
                            format!("{}:{}", hostname, port)
                        }
                    } else {
                        conn.remote_addr.to_string()
                    }
                } else {
                    conn.remote_addr.to_string()
                }
            } else {
                conn.remote_addr.to_string()
            };

            // When `color_cells` is true each cell carries its own field
            // color (the row's DIM, if any, fades them uniformly); otherwise
            // per-cell colors are skipped and the row override paints all
            // cells in a single staleness color.
            let style_if_colored = |c: Color| {
                if color_cells {
                    theme::fg(c)
                } else {
                    Style::default()
                }
            };

            let bandwidth_cell = if color_cells {
                Cell::from(bandwidth_line(incoming_rate, outgoing_rate))
            } else {
                Cell::from(
                    Line::from(format!("{}↓/{}↑", incoming_rate, outgoing_rate)).right_aligned(),
                )
            };

            let mut cells = vec![
                status_indicator_cell(conn),
                Cell::from(conn.protocol.to_string()).style(style_if_colored(theme::muted())),
                Cell::from(local_addr_display).style(style_if_colored(theme::field_local_addr())),
                Cell::from(remote_addr_display).style(style_if_colored(theme::field_remote_addr())),
            ];
            if show_location {
                let location_display = conn
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or("-");
                cells.push(
                    Cell::from(location_display).style(style_if_colored(theme::field_location())),
                );
            }
            cells.extend([
                Cell::from(conn.state()).style(style_if_colored(state_color(conn))),
                Cell::from(service_display).style(style_if_colored(theme::field_service())),
                Cell::from(dpi_display).style(style_if_colored(dpi_cell_color)),
                bandwidth_cell,
                Cell::from(process_display).style(style_if_colored(theme::field_process())),
            ]);

            let row = Row::new(cells);
            match row_override {
                Some(style) => row.style(style),
                None => row,
            }
        })
        .collect();

    // Create table state with selection adjusted to windowed slice
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_index(connections) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    // Build dynamic title with sort information
    let base_title = if ui_state.show_historic {
        "Active + Historic Connections"
    } else {
        "Active Connections"
    };
    let table_title = if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        };
        format!(
            "{} (Sort: {} {})",
            base_title,
            ui_state.sort_column.display_name(),
            direction
        )
    } else {
        base_title.to_string()
    };

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .block(panel_block(table_title))
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

    f.render_stateful_widget(connections_table, area, &mut state);

    // Register click regions for visible connection rows
    click_regions.scroll_area = Some(area);
    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    let header_height = 2_u16; // header row (1) + bottom_margin (1)
    let visible_start_y = inner.y + header_height;
    let max_visible_rows = inner.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let conn_idx = scroll_offset + i;
        if conn_idx >= connections.len() {
            break;
        }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(conn_idx));
    }
}

/// Draw grouped connections list (grouped by process)
fn draw_grouped_connections_list(
    f: &mut Frame,
    ui_state: &UIState,
    grouped_rows: &[GroupedRow],
    area: Rect,
    dns_resolver: Option<&DnsResolver>,
    show_location: bool,
    click_regions: &mut ClickableRegions,
) {
    // Column layout for grouped view:
    // - First column shows expand/collapse indicator + process name or tree prefix + protocol
    // - Remaining columns similar to flat view but with adjusted widths
    let remote_addr_width = if dns_resolver.is_some() && ui_state.show_hostnames {
        26
    } else {
        18
    };

    // Build widths dynamically - Loc column only when GeoIP country DB available
    let mut widths = vec![
        Constraint::Length(1),                 // Status indicator dot
        Constraint::Min(28),                   // Process/Protocol (wider for tree structure)
        Constraint::Length(17),                // Local Address
        Constraint::Length(remote_addr_width), // Remote Address
    ];
    if show_location {
        widths.push(Constraint::Length(4)); // Location (2-char country code)
    }
    widths.extend([
        Constraint::Length(12), // State
        Constraint::Length(8),  // Service
        Constraint::Length(20), // Application/Host
        Constraint::Length(14), // Bandwidth
    ]);

    let header_style = theme::fg(theme::heading());

    // Build header cells dynamically. Leading empty cell is the status
    // indicator column (●/○).
    let mut header_cells = vec![
        Cell::from("").style(header_style),
        Cell::from("Process / Protocol").style(header_style),
        Cell::from("Local Address").style(header_style),
        Cell::from("Remote Address").style(header_style),
    ];
    if show_location {
        header_cells.push(Cell::from("Loc").style(header_style));
    }
    header_cells.extend([
        Cell::from("State").style(header_style),
        Cell::from("Service").style(header_style),
        Cell::from("Application").style(header_style),
        Cell::from("Down/Up").style(header_style),
    ]);
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    // Virtualization: only build Row objects for the visible window
    let scroll_offset = ui_state.grouped_scroll_offset;
    let visible_rows = ui_state.visible_rows.max(1);
    let window_end = (scroll_offset + visible_rows + 1).min(grouped_rows.len());
    let visible_grouped = &grouped_rows[scroll_offset.min(grouped_rows.len())..window_end];

    let rows: Vec<Row> = visible_grouped
        .iter()
        .map(|row| match row {
            GroupedRow::Group {
                process_name,
                stats,
                expanded,
            } => {
                let expand_indicator = if *expanded { "[-]" } else { "[+]" };
                let process_cell = if ui_state.show_historic && stats.historic_count > 0 {
                    Line::from(vec![
                        Span::styled(
                            format!(
                                "{} {} ({}, ",
                                expand_indicator, process_name, stats.connection_count
                            ),
                            theme::bold_fg(theme::accent()),
                        ),
                        Span::styled(
                            format!("{}", stats.historic_count),
                            Style::default()
                                .fg(Color::DarkGray)
                                .add_modifier(Modifier::DIM | Modifier::BOLD),
                        ),
                        Span::styled(")".to_string(), theme::bold_fg(theme::accent())),
                    ])
                } else {
                    Line::from(Span::styled(
                        format!(
                            "{} {} ({})",
                            expand_indicator, process_name, stats.connection_count
                        ),
                        theme::bold_fg(theme::accent()),
                    ))
                };

                // Protocol breakdown: TCP count green (matches Established
                // TCP rows below), UDP count cyan; labels muted.
                let proto_breakdown = Line::from(vec![
                    Span::styled("TCP:", theme::fg(theme::muted())),
                    Span::styled(
                        stats.tcp_count.to_string(),
                        theme::fg(theme::tcp_established()),
                    ),
                    Span::raw(" "),
                    Span::styled("UDP:", theme::fg(theme::muted())),
                    Span::styled(stats.udp_count.to_string(), theme::fg(theme::accent())),
                ]);

                // Bandwidth display matches per-row split (rx green / tx blue).
                let incoming_rate = format_rate_compact(stats.total_incoming_rate_bps);
                let outgoing_rate = format_rate_compact(stats.total_outgoing_rate_bps);

                // Build cells dynamically. Status column is left blank on
                // group header rows; the per-connection child rows below
                // carry the actual status dots.
                let mut cells = vec![
                    Cell::from(""),
                    Cell::from(process_cell),
                    Cell::from(""),
                    Cell::from(""),
                ];
                if show_location {
                    cells.push(Cell::from("")); // Loc (empty for group header)
                }
                cells.extend([
                    Cell::from(proto_breakdown),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(bandwidth_line(incoming_rate, outgoing_rate)),
                ]);
                Row::new(cells)
            }
            GroupedRow::Connection {
                connection,
                is_last_in_group,
                ..
            } => {
                let prefix = if *is_last_in_group {
                    "  └── "
                } else {
                    "  ├── "
                };

                // Format addresses
                let local_addr_display = connection.local_addr.to_string();
                let remote_addr_display = if ui_state.show_hostnames
                    && connection.protocol != Protocol::Arp
                {
                    if let Some(resolver) = dns_resolver {
                        if let Some(hostname) = resolver.get_hostname(&connection.remote_addr.ip())
                        {
                            let port = connection.remote_addr.port();
                            let max_len = (remote_addr_width as usize).saturating_sub(7);
                            if hostname.len() > max_len {
                                format!("{}..:{}", &hostname[..max_len.saturating_sub(2)], port)
                            } else {
                                format!("{}:{}", hostname, port)
                            }
                        } else {
                            connection.remote_addr.to_string()
                        }
                    } else {
                        connection.remote_addr.to_string()
                    }
                } else {
                    connection.remote_addr.to_string()
                };

                // State display
                let state = connection.state();

                // Service display
                let service_display = if ui_state.show_port_numbers {
                    connection.remote_addr.port().to_string()
                } else {
                    connection
                        .service_name
                        .clone()
                        .unwrap_or_else(|| NONE_PLACEHOLDER.to_string())
                };

                // DPI display
                let dpi_display = match &connection.dpi_info {
                    Some(dpi) => dpi.application.to_string(),
                    None => NONE_PLACEHOLDER.to_string(),
                };
                let dpi_cell_color = connection
                    .dpi_info
                    .as_ref()
                    .map(|d| dpi_color(&d.application))
                    .unwrap_or_else(theme::field_application);

                // GeoIP location display (2-char country code)
                let location_display = connection
                    .geoip_info
                    .as_ref()
                    .map(|g| g.country_display())
                    .unwrap_or("-");

                // Bandwidth display
                let incoming_rate = format_rate_compact(connection.current_incoming_rate_bps);
                let outgoing_rate = format_rate_compact(connection.current_outgoing_rate_bps);

                // Row staleness override; same model as the flat view.
                // Historic rows keep their per-cell colors but get DIM so the
                // hue fades while staying scannable; aging/critical override
                // every cell with yellow/red.
                let staleness = connection.staleness_ratio();
                let (row_override, color_cells) = if connection.is_historic {
                    (Some(Style::default().add_modifier(Modifier::DIM)), true)
                } else if staleness >= 0.90 {
                    (Some(theme::fg(theme::err())), false)
                } else if staleness >= 0.75 {
                    (Some(theme::fg(theme::warn())), false)
                } else {
                    (None, true)
                };
                let style_if_colored = |c: Color| {
                    if color_cells {
                        theme::fg(c)
                    } else {
                        Style::default()
                    }
                };

                // Protocol cell: tree prefix muted, protocol name in process color.
                let protocol_cell = if color_cells {
                    Cell::from(Line::from(vec![
                        Span::styled(prefix.to_string(), theme::fg(theme::muted())),
                        Span::styled(
                            connection.protocol.to_string(),
                            theme::fg(theme::field_process()),
                        ),
                    ]))
                } else {
                    Cell::from(format!("{}{}", prefix, connection.protocol))
                };

                let bandwidth_cell = if color_cells {
                    Cell::from(bandwidth_line(incoming_rate, outgoing_rate))
                } else {
                    Cell::from(
                        Line::from(format!("{}↓/{}↑", incoming_rate, outgoing_rate))
                            .right_aligned(),
                    )
                };

                let mut cells = vec![
                    status_indicator_cell(connection),
                    protocol_cell,
                    Cell::from(local_addr_display)
                        .style(style_if_colored(theme::field_local_addr())),
                    Cell::from(remote_addr_display)
                        .style(style_if_colored(theme::field_remote_addr())),
                ];
                if show_location {
                    cells.push(
                        Cell::from(location_display)
                            .style(style_if_colored(theme::field_location())),
                    );
                }
                cells.extend([
                    Cell::from(state).style(style_if_colored(state_color(connection))),
                    Cell::from(service_display).style(style_if_colored(theme::field_service())),
                    Cell::from(dpi_display).style(style_if_colored(dpi_cell_color)),
                    bandwidth_cell,
                ]);

                let row = Row::new(cells);
                match row_override {
                    Some(style) => row.style(style),
                    None => row,
                }
            }
        })
        .collect();

    // Create table state with selection adjusted to windowed slice
    let mut state = ratatui::widgets::TableState::default();
    if let Some(selected_index) = ui_state.get_selected_grouped_index(grouped_rows) {
        state.select(Some(selected_index.saturating_sub(scroll_offset)));
    }

    // Build title showing both group sort (A-Z) and connection sort within groups
    let history_suffix = if ui_state.show_historic {
        " + Historic"
    } else {
        ""
    };
    let table_title = if ui_state.sort_column != SortColumn::CreatedAt {
        let direction = if ui_state.sort_ascending {
            "↑"
        } else {
            "↓"
        };
        format!(
            "Grouped by Process (A-Z){} │ Connections: {} {}",
            history_suffix,
            ui_state.sort_column.display_name(),
            direction
        )
    } else {
        format!(
            "Grouped by Process (A-Z){} │ Connections: Time ↑",
            history_suffix
        )
    };

    let connections_table = Table::new(rows, &widths)
        .header(header)
        .block(panel_block(table_title))
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol("> ");

    f.render_stateful_widget(connections_table, area, &mut state);

    // Register click regions for visible grouped rows
    click_regions.scroll_area = Some(area);
    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    let header_height = 2_u16;
    let visible_start_y = inner.y + header_height;
    let max_visible_rows = inner.height.saturating_sub(header_height) as usize;

    for i in 0..max_visible_rows {
        let row_idx = scroll_offset + i;
        if row_idx >= grouped_rows.len() {
            break;
        }
        let row_y = visible_start_y + i as u16;
        let row_rect = Rect::new(inner.x, row_y, inner.width, 1);
        click_regions.register(row_rect, ClickAction::SelectConnection(row_idx));
    }
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
    // Outer frame for the right column so it visually balances the
    // connections table on the left. Uses the standard rounded panel chrome
    // so every framed pane shares the same border treatment.
    let panel = panel_block(Span::styled(" System ", theme::fg(theme::heading())));
    let inner_area = panel.inner(area);
    f.render_widget(panel, area);

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
        if sandbox_info.fs_restricted {
            features.push("FS restricted");
        }
        if sandbox_info.net_restricted {
            features.push("Net blocked");
        }

        let available_indicator = if sandbox_info.landlock_available {
            Span::styled(" [kernel supported]", theme::fg(theme::muted()))
        } else {
            Span::styled(" [kernel unsupported]", theme::fg(theme::muted()))
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

        let mut lines = vec![Line::from(vec![
            Span::raw("Sandbox: "),
            Span::styled(sandbox_info.status.clone(), status_style),
            available_indicator,
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
            Span::styled(sandbox_info.status.clone(), status_style),
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
        let (priv_label, priv_style) = if is_elevated {
            (
                "Process: running as Administrator".to_string(),
                theme::fg(theme::warn()),
            )
        } else {
            ("Process: standard user".to_string(), theme::fg(theme::ok()))
        };

        let mut lines = vec![Line::from(vec![
            Span::raw("Sandbox: "),
            Span::styled(sandbox_info.status.clone(), status_style),
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
    let stats_height: u16 = if app.get_process_detection_status().is_degraded {
        15
    } else {
        13
    };

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

    let heading = Paragraph::new(Line::from(vec![
        Span::styled("Traffic ", theme::bold_fg(theme::heading())),
        Span::styled("(press 'i' for full table)", theme::fg(theme::muted())),
    ]));
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
                format!(
                    "... {} more (press 'i')",
                    filtered_interface_stats.len() - num_to_show
                ),
                theme::fg(theme::muted()),
            )));
        }
        lines
    };

    let interface_para = Paragraph::new(interface_text);
    f.render_widget(interface_para, sections[1]);

    Ok(())
}
