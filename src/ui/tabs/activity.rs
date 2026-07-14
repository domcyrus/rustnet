//! Activity tab: retained process traffic, glowing traffic-share bars,
//! attribution coverage, and a toggleable detailed interface table.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::network::process_activity::{ProcessActivity, ProcessActivitySnapshot};
use crate::ui::{
    ActivityDirection, ActivitySort, ClickableRegions, Component, ComponentContext, Effect,
    HandlerContext, UIState,
    format::{format_bytes, format_rate},
    section_header, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::glow_bar,
};

use super::interfaces::draw_interface_stats;

const MAX_VISIBLE_PROCESSES: usize = 10;

pub(in crate::ui) struct ActivityTab;

impl Component for ActivityTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        if ctx.ui_state.activity_show_interfaces {
            draw_interface_stats(f, ctx.app, ctx.ui_state, area)
        } else {
            draw_activity(f, ctx.app, ctx.ui_state, area)
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('i'), KeyModifiers::NONE) => {
                ctx.ui_state.activity_show_interfaces = !ctx.ui_state.activity_show_interfaces;
                ctx.ui_state.interfaces_scroll.reset();
                Some(Vec::new())
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) if !ctx.ui_state.activity_show_interfaces => {
                ctx.ui_state.activity_direction = ctx.ui_state.activity_direction.toggle();
                Some(Vec::new())
            }
            (KeyCode::Char('s'), KeyModifiers::NONE) if !ctx.ui_state.activity_show_interfaces => {
                ctx.ui_state.activity_sort = ctx.ui_state.activity_sort.next();
                ctx.ui_state.activity_sort_ascending =
                    ctx.ui_state.activity_sort == ActivitySort::Process;
                Some(Vec::new())
            }
            (KeyCode::Char('S'), _) | (KeyCode::Char('s'), KeyModifiers::SHIFT)
                if !ctx.ui_state.activity_show_interfaces =>
            {
                ctx.ui_state.activity_sort_ascending = !ctx.ui_state.activity_sort_ascending;
                Some(Vec::new())
            }
            _ if ctx.ui_state.activity_show_interfaces => try_handle_pane_scroll(
                key,
                ctx.ui_state.visible_rows,
                &mut ctx.ui_state.interfaces_scroll,
            ),
            _ => None,
        }
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        ctx.ui_state
            .activity_show_interfaces
            .then(|| try_handle_pane_wheel(mouse, &mut ctx.ui_state.interfaces_scroll))
            .flatten()
    }
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

pub(in crate::ui) fn draw_activity(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
    area: Rect,
) -> Result<()> {
    let snapshot = app.get_process_activity_snapshot();
    let basis = interface_basis(app);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(9),
            Constraint::Min(8),
            Constraint::Length(9),
        ])
        .split(area);

    draw_traffic_pulse(f, &snapshot, &basis, chunks[0]);
    draw_process_table(f, &snapshot, &basis, ui_state, chunks[1]);

    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .spacing(2)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(chunks[2]);
    draw_traffic_share(f, &snapshot, ui_state.activity_direction, bottom[0]);
    draw_interface_pulse(f, app, ui_state.activity_direction, bottom[1]);

    Ok(())
}

fn title(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::default().add_modifier(Modifier::BOLD))
}

fn draw_traffic_pulse(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    area: Rect,
) {
    let inner = section_header(f, area, title(" Traffic Pulse"));
    if inner.height == 0 {
        return;
    }

    let tx_fraction = coverage_fraction(snapshot.window_tx_bytes, basis.tx_window_bytes);
    let rx_fraction = coverage_fraction(snapshot.window_rx_bytes, basis.rx_window_bytes);
    let basis_marker = if basis.exact { "" } else { "~" };
    let unknown_tx = snapshot
        .retained_tx_bytes
        .saturating_sub(snapshot.attributed_tx_bytes);
    let unknown_rx = snapshot
        .retained_rx_bytes
        .saturating_sub(snapshot.attributed_rx_bytes);

    let tx_line = Line::from(vec![
        Span::styled("TX now ", theme::fg(theme::muted())),
        Span::styled(
            format_rate(snapshot.current_tx_bps),
            theme::bold_fg(theme::tx_wave(1.0)),
        ),
        Span::styled("   60s captured ", theme::fg(theme::muted())),
        Span::styled(
            format_bytes(snapshot.window_tx_bytes),
            theme::bold_fg(theme::tx()),
        ),
        Span::styled(" / ", theme::fg(theme::muted())),
        Span::styled(
            format!("{} {}", basis.label, format_bytes(basis.tx_window_bytes)),
            theme::fg(theme::accent()),
        ),
        Span::styled(
            coverage_label(tx_fraction, basis_marker),
            theme::fg(if tx_fraction.is_some_and(|fraction| fraction > 1.05) {
                theme::warn()
            } else {
                theme::muted()
            }),
        ),
    ]);
    f.render_widget(
        Paragraph::new(tx_line),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    if inner.height > 1 {
        let bar_width = inner.width.saturating_sub(20) as usize;
        let mut spans = vec![Span::styled("TX 60s coverage ", theme::fg(theme::muted()))];
        spans.extend(glow_bar::spans(
            tx_fraction.unwrap_or_default(),
            bar_width,
            theme::tx_wave,
        ));
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }

    if inner.height > 2 {
        let rx_line = Line::from(vec![
            Span::styled("RX now ", theme::fg(theme::muted())),
            Span::styled(
                format_rate(snapshot.current_rx_bps),
                theme::bold_fg(theme::rx_wave(1.0)),
            ),
            Span::styled("   60s captured ", theme::fg(theme::muted())),
            Span::styled(
                format_bytes(snapshot.window_rx_bytes),
                theme::bold_fg(theme::rx()),
            ),
            Span::styled(" / ", theme::fg(theme::muted())),
            Span::styled(
                format!("{} {}", basis.label, format_bytes(basis.rx_window_bytes)),
                theme::fg(theme::accent()),
            ),
            Span::styled(
                coverage_label(rx_fraction, basis_marker),
                theme::fg(if rx_fraction.is_some_and(|fraction| fraction > 1.05) {
                    theme::warn()
                } else {
                    theme::muted()
                }),
            ),
        ]);
        f.render_widget(
            Paragraph::new(rx_line),
            Rect::new(inner.x, inner.y + 2, inner.width, 1),
        );
    }

    if inner.height > 3 {
        let bar_width = inner.width.saturating_sub(20) as usize;
        let mut spans = vec![Span::styled("RX 60s coverage ", theme::fg(theme::muted()))];
        spans.extend(glow_bar::spans(
            rx_fraction.unwrap_or_default(),
            bar_width,
            theme::rx_wave,
        ));
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, inner.y + 3, inner.width, 1),
        );
    }

    if inner.height > 4 {
        let retained = Line::from(vec![
            Span::styled("retained TX ", theme::fg(theme::muted())),
            Span::styled(
                format_bytes(snapshot.retained_tx_bytes),
                theme::bold_fg(theme::tx()),
            ),
            Span::styled("   RX ", theme::fg(theme::muted())),
            Span::styled(
                format_bytes(snapshot.retained_rx_bytes),
                theme::bold_fg(theme::rx()),
            ),
        ]);
        f.render_widget(
            Paragraph::new(retained),
            Rect::new(inner.x, inner.y + 4, inner.width, 1),
        );
    }

    if inner.height > 5 {
        let attribution = Line::from(vec![
            Span::styled("process attribution TX ", theme::fg(theme::muted())),
            Span::styled(
                format!("{:.1}%", snapshot.tx_attribution_pct()),
                attribution_style(snapshot.tx_attribution_pct()),
            ),
            Span::styled(
                format!("  unknown {}", format_bytes(unknown_tx)),
                unknown_style(unknown_tx),
            ),
            Span::styled("   RX ", theme::fg(theme::muted())),
            Span::styled(
                format!("{:.1}%", snapshot.rx_attribution_pct()),
                attribution_style(snapshot.rx_attribution_pct()),
            ),
            Span::styled(
                format!("  unknown {}", format_bytes(unknown_rx)),
                unknown_style(unknown_rx),
            ),
        ]);
        f.render_widget(
            Paragraph::new(attribution),
            Rect::new(inner.x, inner.y + 5, inner.width, 1),
        );
    }

    if inner.height > 6 {
        let legend = Line::from(vec![
            Span::styled("60s coverage", theme::fg(theme::accent())),
            Span::styled(" = captured ÷ interface  |  ", theme::fg(theme::muted())),
            Span::styled("Retained", theme::fg(theme::accent())),
            Span::styled(" = active + recent closed  |  ", theme::fg(theme::muted())),
            Span::styled("Attribution", theme::fg(theme::accent())),
            Span::styled(" = mapped to PID/name", theme::fg(theme::muted())),
        ]);
        f.render_widget(
            Paragraph::new(legend),
            Rect::new(inner.x, inner.y + 6, inner.width, 1),
        );
    }
}

fn coverage_fraction(captured_bytes: u64, interface_bytes: u64) -> Option<f64> {
    (interface_bytes > 0).then(|| (captured_bytes as f64 / interface_bytes as f64).min(1.0))
}

fn coverage_label(fraction: Option<f64>, basis_marker: &str) -> String {
    fraction.map_or_else(
        || "   coverage n/a".to_string(),
        |fraction| format!("   {basis_marker}{:.1}% observed", fraction * 100.0),
    )
}

fn attribution_style(percentage: f64) -> Style {
    theme::fg(if percentage >= 90.0 {
        theme::ok()
    } else {
        theme::warn()
    })
}

fn unknown_style(bytes: u64) -> Style {
    theme::fg(if bytes > 0 {
        theme::warn()
    } else {
        theme::muted()
    })
}

fn direction_ramp(direction: ActivityDirection) -> fn(f64) -> Color {
    match direction {
        ActivityDirection::Egress => theme::tx_wave,
        ActivityDirection::Ingress => theme::rx_wave,
    }
}

fn direction_color(direction: ActivityDirection) -> Color {
    match direction {
        ActivityDirection::Egress => theme::tx(),
        ActivityDirection::Ingress => theme::rx(),
    }
}

fn current_rate(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    match direction {
        ActivityDirection::Egress => process.current_tx_bps,
        ActivityDirection::Ingress => process.current_rx_bps,
    }
}

fn peak_rate(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    match direction {
        ActivityDirection::Egress => process.peak_tx_bps,
        ActivityDirection::Ingress => process.peak_rx_bps,
    }
}

fn window_bytes(process: &ProcessActivity, direction: ActivityDirection) -> u64 {
    match direction {
        ActivityDirection::Egress => process.window_tx_bytes,
        ActivityDirection::Ingress => process.window_rx_bytes,
    }
}

fn retained_bytes(process: &ProcessActivity, direction: ActivityDirection) -> u64 {
    match direction {
        ActivityDirection::Egress => process.retained_tx_bytes,
        ActivityDirection::Ingress => process.retained_rx_bytes,
    }
}

fn window_share(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    match direction {
        ActivityDirection::Egress => process.window_tx_share,
        ActivityDirection::Ingress => process.window_rx_share,
    }
}

fn retained_share(process: &ProcessActivity, direction: ActivityDirection) -> f64 {
    match direction {
        ActivityDirection::Egress => process.retained_tx_share,
        ActivityDirection::Ingress => process.retained_rx_share,
    }
}

fn snapshot_window_bytes(snapshot: &ProcessActivitySnapshot, direction: ActivityDirection) -> u64 {
    match direction {
        ActivityDirection::Egress => snapshot.window_tx_bytes,
        ActivityDirection::Ingress => snapshot.window_rx_bytes,
    }
}

fn interface_window_bytes(basis: &InterfaceBasis, direction: ActivityDirection) -> u64 {
    match direction {
        ActivityDirection::Egress => basis.tx_window_bytes,
        ActivityDirection::Ingress => basis.rx_window_bytes,
    }
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
    basis: &InterfaceBasis,
    ui_state: &UIState,
    area: Rect,
) {
    let sort_direction = if ui_state.activity_sort_ascending {
        "↑"
    } else {
        "↓"
    };
    let traffic_direction = ui_state.activity_direction;
    let inner = section_header(
        f,
        area,
        Line::from(vec![
            title(format!(
                " Top Processes: {}",
                traffic_direction.display_name_with_rate()
            )),
            Span::styled(
                format!(
                    "  {} {sort_direction}",
                    ui_state.activity_sort.display_name(traffic_direction)
                ),
                theme::fg(theme::muted()),
            ),
        ]),
    );

    if snapshot.processes.is_empty() {
        f.render_widget(
            Paragraph::new("Listening for process traffic...").style(theme::fg(theme::muted())),
            inner,
        );
        return;
    }

    let processes = sort_processes(
        snapshot.processes.clone(),
        ui_state.activity_sort,
        ui_state.activity_sort_ascending,
        traffic_direction,
    );
    let visible = inner
        .height
        .saturating_sub(1)
        .min(MAX_VISIBLE_PROCESSES as u16) as usize;
    let wide = inner.width >= 132;
    let medium = inner.width >= 90;
    let pulse_width = if wide { 14 } else { 10 };

    let rows: Vec<Row> = processes
        .into_iter()
        .take(visible)
        .map(|process| {
            let pulse_fraction = if snapshot_window_bytes(snapshot, traffic_direction) > 0 {
                window_share(&process, traffic_direction) / 100.0
            } else {
                retained_share(&process, traffic_direction) / 100.0
            };
            let mut cells = vec![Cell::from(process.identity.display_name())];
            if medium {
                cells.push(Cell::from(Line::from(glow_bar::spans(
                    pulse_fraction,
                    pulse_width,
                    if process.identity.attributed {
                        direction_ramp(traffic_direction)
                    } else {
                        theme::warn_wave
                    },
                ))));
            }
            cells.push(right_cell(format_rate(current_rate(
                &process,
                traffic_direction,
            ))));
            if wide {
                cells.push(right_cell(format_rate(peak_rate(
                    &process,
                    traffic_direction,
                ))));
            }
            cells.push(right_cell(format!(
                "{:.1}%",
                window_share(&process, traffic_direction)
            )));
            if wide {
                let basis_bytes = interface_window_bytes(basis, traffic_direction)
                    .max(snapshot_window_bytes(snapshot, traffic_direction));
                let iface_share = if basis_bytes > 0 {
                    window_bytes(&process, traffic_direction) as f64 / basis_bytes as f64 * 100.0
                } else {
                    0.0
                };
                cells.push(right_cell(format!(
                    "{}{iface_share:.1}%",
                    if basis.exact { "" } else { "~" }
                )));
                cells.push(right_cell(format_bytes(window_bytes(
                    &process,
                    traffic_direction,
                ))));
            }
            cells.push(right_cell(format_bytes(retained_bytes(
                &process,
                traffic_direction,
            ))));
            cells.push(right_cell(format!(
                "{}/{}",
                process.active_connections, process.total_connections
            )));
            if medium {
                let destinations = format!(
                    "{}{}",
                    process.unique_destinations,
                    if process.destinations_truncated {
                        "+"
                    } else {
                        ""
                    }
                );
                cells.push(right_cell(destinations));
                cells.push(Cell::from(
                    top_destination(&process, traffic_direction)
                        .map(|destination| destination.display_name())
                        .unwrap_or_else(|| "-".to_string()),
                ));
            }
            let style = if process.identity.attributed {
                Style::default()
            } else {
                theme::fg(theme::warn())
            };
            Row::new(cells).style(style)
        })
        .collect();

    let mut headers = vec![Cell::from("Process")];
    let mut constraints = vec![Constraint::Length(if wide { 24 } else { 20 })];
    if medium {
        headers.push(Cell::from("Pulse"));
        constraints.push(Constraint::Length(pulse_width as u16));
    }
    headers.push(right_cell(format!(
        "{} now",
        traffic_direction.rate_label()
    )));
    constraints.push(Constraint::Length(11));
    if wide {
        headers.push(right_cell(format!(
            "Peak {}",
            traffic_direction.rate_label()
        )));
        constraints.push(Constraint::Length(11));
    }
    headers.push(right_cell("60s %".to_string()));
    constraints.push(Constraint::Length(8));
    if wide {
        headers.push(right_cell("Iface 60s".to_string()));
        headers.push(right_cell(format!(
            "{} 60s",
            traffic_direction.rate_label()
        )));
        constraints.push(Constraint::Length(9));
        constraints.push(Constraint::Length(11));
    }
    headers.push(right_cell("Retained".to_string()));
    headers.push(right_cell("Conns".to_string()));
    constraints.push(Constraint::Length(11));
    constraints.push(Constraint::Length(9));
    if medium {
        headers.push(right_cell("Remote".to_string()));
        headers.push(Cell::from("Top remote peer"));
        constraints.push(Constraint::Length(8));
        constraints.push(Constraint::Min(12));
    }

    let table =
        Table::new(rows, constraints).header(Row::new(headers).style(theme::fg(theme::heading())));
    f.render_widget(table, inner);
}

fn right_cell(value: String) -> Cell<'static> {
    Cell::from(Line::from(value).right_aligned())
}

fn draw_traffic_share(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    direction: ActivityDirection,
    area: Rect,
) {
    let inner = section_header(
        f,
        area,
        title(format!(
            " {} Share (60s)",
            direction.display_name_with_rate()
        )),
    );
    if snapshot.processes.is_empty() {
        f.render_widget(
            Paragraph::new("Waiting for traffic...").style(theme::fg(theme::muted())),
            inner,
        );
        return;
    }

    let mut processes = snapshot.processes.clone();
    processes.sort_by(|a, b| {
        window_bytes(b, direction)
            .cmp(&window_bytes(a, direction))
            .then_with(|| retained_bytes(b, direction).cmp(&retained_bytes(a, direction)))
    });
    let name_width = (inner.width as usize / 4).clamp(10, 18);
    let bar_width = (inner.width as usize).saturating_sub(name_width + 9).max(1);
    let lines: Vec<Line> = processes
        .into_iter()
        .take(inner.height as usize)
        .map(|process| {
            let name = truncate(&process.identity.display_name(), name_width);
            let mut spans = vec![Span::styled(
                format!("{name:<name_width$} "),
                theme::fg(theme::field_process()),
            )];
            spans.extend(glow_bar::spans(
                window_share(&process, direction) / 100.0,
                bar_width,
                if process.identity.attributed {
                    direction_ramp(direction)
                } else {
                    theme::warn_wave
                },
            ));
            spans.push(Span::styled(
                format!(" {:>5.1}%", window_share(&process, direction)),
                theme::fg(direction_color(direction)),
            ));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_interface_pulse(f: &mut Frame, app: &App, direction: ActivityDirection, area: Rect) {
    let inner = section_header(
        f,
        area,
        title(format!(" Interface Pulse: {}", direction.rate_label())),
    );
    let rates = app.get_interface_rates();
    if rates.is_empty() {
        f.render_widget(
            Paragraph::new("Collecting interface counters...").style(theme::fg(theme::muted())),
            inner,
        );
        return;
    }

    let mut rates: Vec<_> = rates.into_iter().collect();
    rates.sort_by(|a, b| {
        let a_total = match direction {
            ActivityDirection::Egress => a.1.tx_bytes_per_sec,
            ActivityDirection::Ingress => a.1.rx_bytes_per_sec,
        };
        let b_total = match direction {
            ActivityDirection::Egress => b.1.tx_bytes_per_sec,
            ActivityDirection::Ingress => b.1.rx_bytes_per_sec,
        };
        b_total.cmp(&a_total).then_with(|| a.0.cmp(&b.0))
    });
    let peak = rates
        .iter()
        .map(|(_, rate)| match direction {
            ActivityDirection::Egress => rate.tx_bytes_per_sec,
            ActivityDirection::Ingress => rate.rx_bytes_per_sec,
        })
        .max()
        .unwrap_or(1)
        .max(1);
    let name_width = 10usize.min(inner.width as usize / 3).max(4);
    let bar_width = (inner.width as usize)
        .saturating_sub(name_width + 17)
        .max(1);
    let lines: Vec<Line> = rates
        .into_iter()
        .take(inner.height as usize)
        .map(|(name, rate)| {
            let selected_rate = match direction {
                ActivityDirection::Egress => rate.tx_bytes_per_sec,
                ActivityDirection::Ingress => rate.rx_bytes_per_sec,
            };
            let mut spans = vec![Span::styled(
                format!("{:<name_width$} ", truncate(&name, name_width)),
                theme::fg(theme::field_local_addr()),
            )];
            spans.extend(glow_bar::spans(
                selected_rate as f64 / peak as f64,
                bar_width,
                direction_ramp(direction),
            ));
            spans.push(Span::styled(
                format!(" ↑{}", compact_rate(rate.tx_bytes_per_sec)),
                theme::fg(theme::tx()),
            ));
            spans.push(Span::styled(
                format!(" ↓{}", compact_rate(rate.rx_bytes_per_sec)),
                theme::fg(theme::rx()),
            ));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
}

fn compact_rate(bytes_per_second: u64) -> String {
    if bytes_per_second >= 1024 * 1024 * 1024 {
        format!(
            "{:.1}G",
            bytes_per_second as f64 / (1024.0 * 1024.0 * 1024.0)
        )
    } else if bytes_per_second >= 1024 * 1024 {
        format!("{:.1}M", bytes_per_second as f64 / (1024.0 * 1024.0))
    } else if bytes_per_second >= 1024 {
        format!("{:.0}K", bytes_per_second as f64 / 1024.0)
    } else {
        format!("{bytes_per_second}B")
    }
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let mut result: String = value.chars().take(width - 1).collect();
    result.push('…');
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::process_activity::ProcessIdentity;
    use std::time::SystemTime;

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
            current_tx_share: 0.0,
            current_rx_share: 0.0,
            window_tx_share: 0.0,
            window_rx_share: 0.0,
            retained_tx_share: 0.0,
            retained_rx_share: 0.0,
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
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
        assert_eq!(coverage_label(None, ""), "   coverage n/a");
        assert_eq!(coverage_fraction(50, 100), Some(0.5));
        assert_eq!(coverage_label(Some(0.5), "~"), "   ~50.0% observed");
        assert_eq!(coverage_fraction(120, 100), Some(1.0));
        assert_eq!(coverage_label(Some(1.0), "~"), "   ~100.0% observed");
    }

    #[test]
    fn truncation_uses_single_cell_ellipsis() {
        assert_eq!(truncate("agent-helper", 6), "agent…");
        assert_eq!(truncate("short", 6), "short");
    }

    #[test]
    fn direction_bars_match_graph_wave_colors() {
        assert_eq!(
            direction_ramp(ActivityDirection::Egress)(0.75),
            theme::tx_wave(0.75)
        );
        assert_eq!(
            direction_ramp(ActivityDirection::Ingress)(0.75),
            theme::rx_wave(0.75)
        );
    }
}
