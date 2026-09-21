//! Process traffic browser with shared capture context and inline inspection.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table, TableState, Wrap},
};

use crate::app::App;
use crate::network::process_activity::{ProcessActivity, ProcessActivitySnapshot};
use crate::ui::{
    ActivityDirection, ActivitySection, ActivitySort, ActivityView, ClickAction, ClickableRegions,
    Component, ComponentContext, Effect, HandlerContext, UiState, draw_placeholder,
    format::{format_bytes, format_rate, format_rate_compact, truncate_with_ellipsis},
    section_header, section_title,
    state::Motion,
    theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::{
        glow_bar,
        scrollbar::{draw_scrollbar, draw_scrolled_text},
    },
};

pub(in crate::ui) struct ActivityTab;

fn capture_only(state: &UiState) -> bool {
    state.section_navigation && state.activity_section == ActivitySection::Capture
}

pub(in crate::ui) fn overview_query(state: &UiState) -> Option<String> {
    let selected = if matches!(
        state.activity_view,
        ActivityView::Processes | ActivityView::ProcessDetails
    ) {
        state.activity_members.borrow().selected.clone()
    } else {
        state.activity_table.borrow().selected.clone()
    };
    selected?.connection_filter_query()
}

impl Component for ActivityTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_activity(f, ctx.app, ctx.ui_state, area, regions);
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        let state = &mut ctx.ui_state;
        if capture_only(state) {
            if key.code == KeyCode::Esc {
                state.activity_section = ActivitySection::Applications;
                return Some(Vec::new());
            }
            return try_handle_pane_scroll(
                key,
                usize::from(state.activity_capture_scroll.viewport_rows()),
                &mut state.activity_capture_scroll,
            );
        }
        if key.code == KeyCode::Char('o') && key.modifiers == KeyModifiers::NONE {
            if let Some(query) = overview_query(state) {
                state.filter_query = query;
                state.filter_cursor_position = state.filter_query.len();
                state.filter_mode = false;
                state.show_historic = true;
                ctx.app.set_show_historic(true);
                state.overview_section = crate::ui::OverviewSection::Connections;
                state.selected_tab = 0;
                state.scroll_offset = 0;
                state.grouped_scroll_offset = 0;
                state.selected_group = None;
                state.set_connection_key(None);
                return Some(vec![Effect::RefreshData]);
            }
            return Some(Vec::new());
        }
        if state.activity_is_details() {
            if key.code == KeyCode::Esc {
                state.activity_view = if state.activity_view == ActivityView::ProcessDetails {
                    ActivityView::Processes
                } else {
                    ActivityView::Applications
                };
                return Some(Vec::new());
            }
            if key.code == KeyCode::Enter && state.activity_view == ActivityView::ApplicationDetails
            {
                state.activity_view = ActivityView::Processes;
                return Some(Vec::new());
            }
            let scroll = if state.activity_view == ActivityView::ProcessDetails {
                &mut state.activity_process_scroll
            } else {
                &mut state.activity_details_scroll
            };
            return try_handle_pane_scroll(key, usize::from(scroll.viewport_rows()), scroll);
        }
        match (key.code, key.modifiers) {
            (KeyCode::Char('d'), KeyModifiers::NONE) => {
                state.activity_direction = state.activity_direction.toggle()
            }
            (KeyCode::Char('s'), KeyModifiers::NONE) => {
                state.activity_sort = state.activity_sort.next();
                state.activity_sort_ascending = state.activity_sort == ActivitySort::Process;
            }
            (KeyCode::Char('S'), _) | (KeyCode::Char('s'), KeyModifiers::SHIFT) => {
                state.activity_sort_ascending = !state.activity_sort_ascending
            }
            (KeyCode::Esc, _) => {
                if state.activity_view == ActivityView::Processes {
                    state.activity_view = ActivityView::ApplicationDetails;
                } else {
                    state.selected_tab = 0;
                }
            }
            (KeyCode::Enter, _) => state.open_activity_details(),
            _ => {
                let page = state.activity_list().borrow().viewport.max(1);
                let motion = match (key.code, key.modifiers) {
                    (KeyCode::Up, _) | (KeyCode::Char('k'), _) => Motion::Up,
                    (KeyCode::Down, _) | (KeyCode::Char('j'), _) => Motion::Down,
                    (KeyCode::PageUp, _) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
                        Motion::PageUp(page)
                    }
                    (KeyCode::PageDown, _) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
                        Motion::PageDown(page)
                    }
                    (KeyCode::Home, _) | (KeyCode::Char('g'), KeyModifiers::NONE) => Motion::First,
                    (KeyCode::End, _)
                    | (KeyCode::Char('G'), _)
                    | (KeyCode::Char('g'), KeyModifiers::SHIFT) => Motion::Last,
                    _ => return None,
                };
                state.activity_list().borrow_mut().move_selection(motion);
            }
        }
        Some(Vec::new())
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        let state = &mut ctx.ui_state;
        let point = (mouse.column, mouse.row).into();
        if state.activity_capture_area.get().contains(point) {
            return try_handle_pane_wheel(mouse, &mut state.activity_capture_scroll);
        }
        if capture_only(state) {
            return None;
        }
        if state.activity_is_details() {
            let scroll = if state.activity_view == ActivityView::ProcessDetails {
                &mut state.activity_process_scroll
            } else {
                &mut state.activity_details_scroll
            };
            return try_handle_pane_wheel(mouse, scroll);
        }
        let mut table = state.activity_list().borrow_mut();
        if !table.area.contains(point) {
            return None;
        }
        // Wheel motion clamps at the ends rather than wrapping across the list.
        let motion = match mouse.kind {
            MouseEventKind::ScrollUp => Motion::PageUp(1),
            MouseEventKind::ScrollDown => Motion::PageDown(1),
            _ => return None,
        };
        table.move_selection(motion);
        Some(Vec::new())
    }
}

/// Leave at least 80 columns for processes, 36 for capture, and a gutter.
/// The full capture summary must fit vertically to avoid a second keyboard focus.
pub(in crate::ui) fn compact_layout(area: Rect) -> bool {
    area.width < 120 || area.height < 25
}

#[derive(Debug, Clone)]
struct InterfaceBasis {
    label: String,
    tx_window_bytes: u64,
    rx_window_bytes: u64,
    exact: bool,
}

fn interface_basis(app: &App) -> InterfaceBasis {
    let windows = app.get_interface_traffic_windows();
    if let Some(name) = app.get_current_interface()
        && name != "any"
        && let Some(window) = windows.get(&name)
    {
        return InterfaceBasis {
            label: name,
            tx_window_bytes: window.tx_bytes,
            rx_window_bytes: window.rx_bytes,
            exact: true,
        };
    }

    let tx_window_bytes = windows.values().map(|window| window.tx_bytes).sum();
    let rx_window_bytes = windows.values().map(|window| window.rx_bytes).sum();
    InterfaceBasis {
        label: "host aggregate".to_string(),
        tx_window_bytes,
        rx_window_bytes,
        exact: false,
    }
}

fn draw_activity(
    f: &mut Frame,
    app: &App,
    state: &UiState,
    area: Rect,
    regions: &mut ClickableRegions,
) {
    let snapshot = app.get_process_activity_snapshot();
    let basis = interface_basis(app);
    state.activity_capture_area.set(Rect::default());
    if capture_only(state) {
        draw_capture(f, &snapshot, &basis, state, area);
        return;
    }
    let columns = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(if state.section_navigation { 0 } else { 36 }),
    ])
    .spacing(if state.section_navigation { 0 } else { 3 })
    .split(area);
    if !state.section_navigation {
        draw_capture(f, &snapshot, &basis, state, columns[1]);
    }
    if state.activity_is_details() {
        draw_process_details(f, &snapshot, &basis, state, columns[0]);
        return;
    }
    let main = Layout::vertical([
        Constraint::Length(if state.activity_view == ActivityView::Processes {
            0
        } else if state.section_navigation {
            2
        } else {
            1
        }),
        Constraint::Min(0),
    ])
    .split(columns[0]);
    draw_summary(f, &snapshot, &basis, state, main[0]);
    draw_process_table(f, &snapshot, state, main[1], regions);
}

fn coverage_text(fraction: Option<f64>, exact: bool) -> String {
    fraction.map_or_else(
        || "n/a".to_string(),
        |f| format!("{}{:.1}%", if exact { "" } else { "~" }, f * 100.0),
    )
}

fn draw_summary(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    state: &UiState,
    area: Rect,
) {
    let mut rates = Line::from(vec![
        Span::styled(
            format!("TX {}", format_rate(snapshot.current_tx_bps)),
            theme::bold_fg(theme::tx()),
        ),
        Span::raw("   "),
        Span::styled(
            format!("RX {}", format_rate(snapshot.current_rx_bps)),
            theme::bold_fg(theme::rx()),
        ),
    ]);
    if state.has_active_filter() {
        rates
            .spans
            .push(Span::styled(" · all traffic", theme::fg(theme::muted())));
    }
    let coverage = |direction| {
        coverage_text(
            coverage_fraction(
                snapshot_window_bytes(snapshot, direction),
                interface_window_bytes(basis, direction),
            ),
            basis.exact,
        )
    };
    let line = Line::styled(
        format!(
            "Coverage 60s: TX {}  RX {}",
            coverage(ActivityDirection::Egress),
            coverage(ActivityDirection::Ingress)
        ),
        theme::fg(theme::muted()),
    );
    f.render_widget(Paragraph::new(vec![rates, line]), area);
}

fn heading(label: &str) -> Line<'static> {
    Line::styled(label.to_owned(), theme::bold_fg(theme::heading()))
}

fn field(label: &str, value: impl std::fmt::Display) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), theme::fg(theme::muted())),
        Span::raw(value.to_string()),
    ])
}

fn rule(width: u16) -> Line<'static> {
    Line::styled("─".repeat(usize::from(width)), theme::fg(theme::border()))
}

/// Both the sidebar and the compact section render these same lines.
fn draw_capture(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    state: &UiState,
    area: Rect,
) {
    state.activity_capture_area.set(area);
    let inner = section_header(f, area, section_title(" Capture"));
    let mut lines = vec![heading("Coverage · last 60s"), field("Basis", &basis.label)];
    for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
        let captured = snapshot_window_bytes(snapshot, direction);
        let interface = interface_window_bytes(basis, direction);
        lines.push(Line::styled(
            format!(
                "{} {}",
                direction.rate_label(),
                coverage_text(coverage_fraction(captured, interface), basis.exact)
            ),
            theme::bold_fg(direction_color(direction)),
        ));
        lines.push(field("Captured", format_bytes(captured)));
        lines.push(field("Interface", format_bytes(interface)));
    }
    lines.push(rule(inner.width.saturating_sub(2)));
    lines.push(heading("Attribution · retained traffic"));
    for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
        let retained = direction.pick(snapshot.retained_tx_bytes, snapshot.retained_rx_bytes);
        let attributed = direction.pick(snapshot.attributed_tx_bytes, snapshot.attributed_rx_bytes);
        let percentage =
            direction.pick(snapshot.tx_attribution_pct(), snapshot.rx_attribution_pct());
        lines.push(Line::styled(
            format!("{} {percentage:.1}% mapped", direction.rate_label()),
            theme::bold_fg(direction_color(direction)),
        ));
        lines.push(field("Mapped", format_bytes(attributed)));
        lines.push(field(
            "Unknown",
            format_bytes(retained.saturating_sub(attributed)),
        ));
        lines.push(field("Retained", format_bytes(retained)));
    }
    draw_scrolled_text(
        f,
        inner,
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        &state.activity_capture_scroll,
    );
}

fn draw_process_details(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    state: &UiState,
    area: Rect,
) {
    let individual = state.activity_view == ActivityView::ProcessDetails;
    let selected = if individual {
        state.activity_members.borrow().selected.clone()
    } else {
        state.activity_table.borrow().selected.clone()
    };
    let records = if individual {
        &snapshot.processes
    } else {
        &snapshot.applications
    };
    let scroll = if individual {
        &state.activity_process_scroll
    } else {
        &state.activity_details_scroll
    };
    let title = selected.as_ref().map_or_else(
        || " Activity details".to_string(),
        |id| {
            format!(
                " {} · {}",
                if individual { "Process" } else { "Application" },
                id.display_name()
            )
        },
    );
    let inner = section_header(
        f,
        area,
        section_title(truncate_with_ellipsis(
            &title,
            usize::from(area.width.saturating_sub(1)),
        )),
    );
    let Some(process) = records
        .iter()
        .find(|process| Some(&process.identity) == selected.as_ref())
    else {
        scroll.clamp_for_render(0);
        draw_placeholder(f, inner, "No longer retained. Esc returns to the list.");
        return;
    };
    let members: Vec<_> = snapshot
        .processes
        .iter()
        .filter(|member| member.identity.application_identity() == process.identity)
        .collect();
    let attribution = if individual {
        if process.identity.attributed {
            "Mapped"
        } else {
            "Unknown"
        }
    } else {
        let mapped = members
            .iter()
            .filter(|member| member.identity.attributed)
            .count();
        if mapped == 0 {
            "Unknown"
        } else if mapped == members.len() {
            "Mapped"
        } else {
            "Mixed"
        }
    };
    let mut lines = vec![
        field(
            if individual { "Process" } else { "Application" },
            &process.identity.name,
        ),
        field("Interface basis", &basis.label),
        field("Attribution", attribution),
        field(
            "Connections",
            format!(
                "{} active / {} retained",
                process.active_connections, process.total_connections
            ),
        ),
        field(
            "Remote peers",
            format!(
                "{}{}",
                process.unique_destinations,
                if process.destinations_truncated {
                    "+"
                } else {
                    ""
                }
            ),
        ),
    ];
    if individual {
        lines.insert(
            1,
            field(
                "PID",
                process
                    .identity
                    .pid
                    .map_or_else(|| "-".into(), |pid| pid.to_string()),
            ),
        );
    } else {
        lines.insert(1, field("Processes", members.len()));
    }
    for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
        lines.push(rule(inner.width.saturating_sub(2)));
        lines.push(heading(direction.display_name_with_rate()));
        lines.extend([
            field(
                "Current rate",
                format_rate(current_rate(process, direction)),
            ),
            field("Peak rate", format_rate(peak_rate(process, direction))),
            field("Last 60s", format_bytes(window_bytes(process, direction))),
            field(
                "Share of captured 60s",
                format!("{:.1}%", window_share(process, direction)),
            ),
            field("Retained", format_bytes(retained_bytes(process, direction))),
            field(
                "Share of retained",
                format!("{:.1}%", retained_share(process, direction)),
            ),
        ]);
        let interface_bytes = interface_window_bytes(basis, direction)
            .max(snapshot_window_bytes(snapshot, direction));
        lines.push(field(
            "Share of interface 60s",
            coverage_text(
                coverage_fraction(window_bytes(process, direction), interface_bytes),
                basis.exact,
            ),
        ));
        if let Some(peer) = top_destination(process, direction) {
            lines.push(field("Top remote peer", peer.display_name()));
            if peer.label.is_some() {
                lines.push(field("Remote address", peer.remote_addr));
            }
        } else {
            lines.push(field("Top remote peer", "-"));
        }
    }
    draw_scrolled_text(
        f,
        inner,
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        scroll,
    );
}

fn coverage_fraction(captured_bytes: u64, interface_bytes: u64) -> Option<f64> {
    (interface_bytes > 0).then(|| (captured_bytes as f64 / interface_bytes as f64).min(1.0))
}

fn direction_color(direction: ActivityDirection) -> Color {
    direction.pick(theme::tx(), theme::rx())
}

fn current_rate(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    direction.pick(process.current_tx_bps, process.current_rx_bps)
}

fn peak_rate(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    direction.pick(process.peak_tx_bps, process.peak_rx_bps)
}

fn window_bytes(process: &ProcessActivity, direction: ActivityDirection) -> u64 {
    direction.pick(process.window_tx_bytes, process.window_rx_bytes)
}

fn retained_bytes(process: &ProcessActivity, direction: ActivityDirection) -> u64 {
    direction.pick(process.retained_tx_bytes, process.retained_rx_bytes)
}

fn window_share(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    direction.pick(process.window_tx_share, process.window_rx_share)
}

fn retained_share(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    direction.pick(process.retained_tx_share, process.retained_rx_share)
}

fn snapshot_window_bytes(snapshot: &ProcessActivitySnapshot, direction: ActivityDirection) -> u64 {
    direction.pick(snapshot.window_tx_bytes, snapshot.window_rx_bytes)
}

fn interface_window_bytes(basis: &InterfaceBasis, direction: ActivityDirection) -> u64 {
    direction.pick(basis.tx_window_bytes, basis.rx_window_bytes)
}

fn top_destination(
    process: &ProcessActivity,
    direction: ActivityDirection,
) -> Option<&crate::network::process_activity::DestinationActivity> {
    match direction {
        ActivityDirection::Egress => process.top_tx_destination.as_ref(),
        ActivityDirection::Ingress => process.top_rx_destination.as_ref(),
    }
}

fn sort_processes(
    mut processes: Vec<ProcessActivity>,
    sort: ActivitySort,
    ascending: bool,
    direction: ActivityDirection,
) -> Vec<ProcessActivity> {
    processes.sort_by(|a, b| {
        let ordering = match sort {
            ActivitySort::RetainedTx => {
                retained_bytes(a, direction).cmp(&retained_bytes(b, direction))
            }
            ActivitySort::WindowTx => window_bytes(a, direction).cmp(&window_bytes(b, direction)),
            ActivitySort::CurrentTx => {
                current_rate(a, direction).total_cmp(&current_rate(b, direction))
            }
            ActivitySort::PeakTx => peak_rate(a, direction).total_cmp(&peak_rate(b, direction)),
            ActivitySort::Connections => a.total_connections.cmp(&b.total_connections),
            ActivitySort::Destinations => a.unique_destinations.cmp(&b.unique_destinations),
            ActivitySort::Process => a
                .identity
                .name
                .to_lowercase()
                .cmp(&b.identity.name.to_lowercase())
                .then_with(|| a.identity.pid.cmp(&b.identity.pid)),
        };
        let ordering = if ascending {
            ordering
        } else {
            ordering.reverse()
        };
        ordering.then_with(|| {
            a.identity
                .name
                .cmp(&b.identity.name)
                .then_with(|| a.identity.pid.cmp(&b.identity.pid))
        })
    });
    processes
}

fn draw_process_table(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    state: &UiState,
    area: Rect,
    regions: &mut ClickableRegions,
) {
    let direction = state.activity_direction;
    let application = state.activity_table.borrow().selected.clone();
    let members = state.activity_view == ActivityView::Processes;
    let records = if members {
        snapshot
            .processes
            .iter()
            .filter(|process| Some(process.identity.application_identity()) == application)
            .cloned()
            .collect()
    } else {
        snapshot.applications.clone()
    };
    let processes = sort_processes(
        records,
        state.activity_sort,
        state.activity_sort_ascending,
        direction,
    );
    // Heading and column labels each occupy one row. Reserve the shared scrollbar gutter.
    let rows_area = Rect::new(
        area.x,
        area.y.saturating_add(area.height.min(2)),
        area.width,
        area.height.saturating_sub(2),
    );
    let mut browser = state.activity_list().borrow_mut();
    browser.prepare(
        processes.iter().map(|p| p.identity.clone()).collect(),
        rows_area,
    );
    let offset = browser.offset;
    let end = (offset + browser.viewport).min(processes.len());
    let range = if end > offset {
        format!(" {}-{end}/{} ", offset + 1, processes.len())
    } else {
        format!(" 0/{} ", processes.len())
    };
    let label = if members {
        application.as_ref().map_or_else(
            || "Processes".to_string(),
            |id| format!("{} · Processes", id.name),
        )
    } else {
        "Applications".to_string()
    };
    let title = format!(
        " {label} · {} · {} {}",
        direction.rate_label(),
        state.activity_sort.display_name(direction),
        if state.activity_sort_ascending {
            "↑"
        } else {
            "↓"
        }
    );
    let title = truncate_with_ellipsis(
        &title,
        usize::from(area.width).saturating_sub(range.len() + 3),
    );
    let inner = section_header(f, area, section_title(title));
    // Keep the range visible even when the title is shortened by the viewport.
    if usize::from(area.width) > range.len() + 4 && area.height > 0 {
        let x = area.right() - range.len() as u16;
        f.render_widget(
            Paragraph::new(Line::styled(range.clone(), theme::fg(theme::muted()))),
            Rect::new(x, area.y, range.len() as u16, 1),
        );
    }
    if processes.is_empty() {
        draw_placeholder(
            f,
            inner,
            if members {
                "No retained processes for this application."
            } else {
                "Waiting for application traffic..."
            },
        );
        return;
    }
    let width = inner.width.saturating_sub(2);
    let medium = width >= 100;
    let wide = width >= 130;
    let normal = width >= 65;
    let mut headers = vec![
        Cell::from(if members { "Process" } else { "Application" }),
        right_cell(format!("{}/s", direction.rate_label())),
    ];
    let mut widths = vec![Constraint::Min(1), Constraint::Length(10)];
    if normal {
        headers.push(right_cell("60s %"));
        widths.push(Constraint::Length(7));
    }
    headers.push(right_cell("Retained"));
    widths.push(Constraint::Length(10));
    if normal {
        headers.push(right_cell("Conns"));
        widths.push(Constraint::Length(7));
    }
    if medium {
        headers.push(Cell::from("Share · 60s"));
        widths.push(Constraint::Length(12));
        headers.push(Cell::from("Top remote peer"));
        widths.push(Constraint::Length(22));
    }
    if wide {
        headers.push(right_cell("Peak/s"));
        widths.push(Constraint::Length(10));
    }
    // Leave room for every fixed column, inter-column gap, and the selection marker.
    let fixed_width = widths
        .iter()
        .map(|constraint| match constraint {
            Constraint::Length(width) => *width,
            _ => 0,
        })
        .sum::<u16>()
        + widths.len().saturating_sub(1) as u16
        + 2;
    let name_width = width.saturating_sub(fixed_width).max(1);
    let rows: Vec<_> = processes
        .iter()
        .enumerate()
        .skip(offset)
        .take(browser.viewport)
        .map(|(index, process)| {
            let mut cells = vec![
                Cell::from(truncate_with_ellipsis(
                    &process.identity.display_name(),
                    usize::from(name_width),
                ))
                .style(if process.identity.attributed {
                    theme::fg(theme::text())
                } else {
                    theme::fg(theme::warn())
                }),
                right_cell(format_rate_compact(current_rate(process, direction), "-"))
                    .style(theme::fg(direction_color(direction))),
            ];
            if normal {
                cells.push(right_cell(format!(
                    "{:.1}%",
                    window_share(process, direction)
                )));
            }
            cells.push(right_cell(format_bytes(retained_bytes(process, direction))));
            if normal {
                cells.push(right_cell(format!(
                    "{}/{}",
                    process.active_connections, process.total_connections
                )));
            }
            if medium {
                cells.push(Cell::from(Line::from(glow_bar::themed_spans(
                    window_share(process, direction) / 100.0,
                    12,
                    direction_color(direction),
                ))));
                cells.push(Cell::from(
                    top_destination(process, direction)
                        .map(|peer| peer.display_name())
                        .unwrap_or_else(|| "-".into()),
                ));
            }
            if wide {
                cells.push(right_cell(format_rate_compact(
                    peak_rate(process, direction),
                    "-",
                )));
            }
            regions.register(
                Rect::new(rows_area.x, rows_area.y + (index - offset) as u16, width, 1),
                ClickAction::SelectActivityProcess(process.identity.clone()),
            );
            Row::new(cells)
        })
        .collect();
    let table = Table::new(rows, widths)
        .header(Row::new(headers).style(theme::bold_fg(theme::heading())))
        .row_highlight_style(theme::row_highlight())
        .highlight_symbol(Line::styled("▌ ", theme::fg(theme::accent())));
    let mut selection =
        TableState::default().with_selected(Some(browser.selected_index().saturating_sub(offset)));
    f.render_stateful_widget(table, Rect { width, ..inner }, &mut selection);
    draw_scrollbar(f, rows_area, processes.len(), offset, browser.viewport);
}

fn right_cell(value: impl Into<String>) -> Cell<'static> {
    Cell::from(Line::from(value.into()).right_aligned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::process_activity::ProcessIdentity;

    fn activity(name: &str, tx: u64, rx: u64, connections: u64) -> ProcessActivity {
        ProcessActivity {
            identity: ProcessIdentity {
                pid: Some(connections as u32),
                name: name.to_string(),
                attributed: true,
            },
            current_tx_bps: tx as f64,
            current_rx_bps: rx as f64,
            window_tx_bytes: tx,
            window_rx_bytes: rx,
            peak_tx_bps: tx as f64,
            peak_rx_bps: rx as f64,
            retained_tx_bytes: tx,
            retained_rx_bytes: rx,
            active_connections: connections as usize,
            total_connections: connections,
            unique_destinations: connections as usize,
            destinations_truncated: false,
            top_tx_destination: None,
            top_rx_destination: None,
            window_tx_share: 0.0,
            window_rx_share: 0.0,
            retained_tx_share: 0.0,
            retained_rx_share: 0.0,
        }
    }

    #[test]
    fn process_sorting_honors_metric_and_direction() {
        let processes = vec![activity("small", 1, 20, 9), activity("large", 10, 2, 1)];
        let sorted = sort_processes(
            processes.clone(),
            ActivitySort::RetainedTx,
            false,
            ActivityDirection::Egress,
        );
        assert_eq!(sorted[0].identity.name, "large");
        let sorted = sort_processes(
            processes.clone(),
            ActivitySort::PeakTx,
            false,
            ActivityDirection::Ingress,
        );
        assert_eq!(sorted[0].identity.name, "small");
        let sorted = sort_processes(
            processes.clone(),
            ActivitySort::PeakTx,
            false,
            ActivityDirection::Egress,
        );
        assert_eq!(sorted[0].identity.name, "large");
        let sorted = sort_processes(
            processes,
            ActivitySort::Connections,
            false,
            ActivityDirection::Ingress,
        );
        assert_eq!(sorted[0].identity.name, "small");
    }

    #[test]
    fn coverage_requires_interface_window_data() {
        assert_eq!(coverage_fraction(100, 0), None);
        assert_eq!(coverage_fraction(50, 100), Some(0.5));
        assert_eq!(coverage_fraction(120, 100), Some(1.0));
    }

    #[test]
    fn truncation_uses_single_cell_ellipsis() {
        assert_eq!(truncate_with_ellipsis("agent-helper", 6), "agent…");
        assert_eq!(truncate_with_ellipsis("short", 6), "short");
    }

    #[test]
    fn directional_bar_tips_preserve_the_theme_token() {
        for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
            let color = direction_color(direction);
            let spans = glow_bar::themed_spans(0.625, 4, color);
            assert_eq!(spans[2].style, theme::fg(color));
        }
    }
}
