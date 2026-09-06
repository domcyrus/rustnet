//! Activity tab: retained process traffic, directional traffic-share bars,
//! and attribution coverage.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::network::process_activity::{ProcessActivity, ProcessActivitySnapshot};
use crate::ui::{
    ActivityDirection, ActivitySort, ClickableRegions, Component, ComponentContext, Effect,
    HandlerContext, UiState, draw_placeholder,
    format::{format_bytes, format_rate, format_rate_compact, truncate_with_ellipsis},
    section_header, section_title, theme,
    widgets::glow_bar,
};

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
        draw_activity(f, ctx.app, ctx.ui_state, area)
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('d'), KeyModifiers::NONE) => {
                ctx.ui_state.activity_direction = ctx.ui_state.activity_direction.toggle();
                Some(Vec::new())
            }
            (KeyCode::Char('s'), KeyModifiers::NONE) => {
                ctx.ui_state.activity_sort = ctx.ui_state.activity_sort.next();
                ctx.ui_state.activity_sort_ascending =
                    ctx.ui_state.activity_sort == ActivitySort::Process;
                Some(Vec::new())
            }
            (KeyCode::Char('S'), _) | (KeyCode::Char('s'), KeyModifiers::SHIFT) => {
                ctx.ui_state.activity_sort_ascending = !ctx.ui_state.activity_sort_ascending;
                Some(Vec::new())
            }
            _ => None,
        }
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
    ui_state: &UiState,
    area: Rect,
) -> Result<()> {
    let snapshot = app.get_process_activity_snapshot();
    let basis = interface_basis(app);

    // Keep capture quality separate from process ranking on wide terminals;
    // narrow terminals fold the essentials into the traffic summaries.
    let sidebar = area.width >= 140 && area.height >= 22;
    let columns = Layout::horizontal([
        Constraint::Min(0),
        Constraint::Length(if sidebar { 38 } else { 0 }),
    ])
    .spacing(if sidebar { 3 } else { 0 })
    .split(area);
    let main = Layout::vertical([
        Constraint::Length(if sidebar { 6 } else { 7 }),
        Constraint::Min(5),
    ])
    .spacing(1)
    .split(columns[0]);
    let summary = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .spacing(3)
        .split(main[0]);
    draw_direction_pulse(
        f,
        &snapshot,
        &basis,
        ActivityDirection::Egress,
        sidebar,
        summary[0],
    );
    draw_direction_pulse(
        f,
        &snapshot,
        &basis,
        ActivityDirection::Ingress,
        sidebar,
        summary[1],
    );
    draw_process_table(f, &snapshot, &basis, ui_state, main[1]);
    if sidebar {
        let panels = Layout::vertical([
            Constraint::Length(9),
            Constraint::Length(7),
            Constraint::Min(4),
        ])
        .spacing(1)
        .split(columns[1]);
        draw_coverage(f, &snapshot, &basis, panels[0]);
        draw_attribution(f, &snapshot, panels[1]);
        draw_interface_pulse(f, app, ui_state.activity_direction, panels[2]);
    }
    Ok(())
}

fn metric_line(label: &str, value: String, style: Style, width: u16) -> Line<'static> {
    let value_width = Span::raw(&value).width();
    let label_width = usize::from(width).saturating_sub(value_width + 1);
    let label = truncate_with_ellipsis(label, label_width);
    let gap = usize::from(width).saturating_sub(Span::raw(&label).width() + value_width);
    Line::from(vec![
        Span::styled(label, theme::fg(theme::muted())),
        Span::raw(" ".repeat(gap)),
        Span::styled(value, style),
    ])
}

fn draw_direction_pulse(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    direction: ActivityDirection,
    sidebar: bool,
    area: Rect,
) {
    let inner = section_header(
        f,
        area,
        section_title(format!(" {}", direction.display_name_with_rate())),
    );
    let color = direction_color(direction);
    let captured = snapshot_window_bytes(snapshot, direction);
    let retained = direction.pick(snapshot.retained_tx_bytes, snapshot.retained_rx_bytes);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format_rate(snapshot_current_bps(snapshot, direction)),
                theme::bold_fg(color),
            ),
            Span::styled("  now", theme::fg(theme::muted())),
        ]),
        Line::default(),
        metric_line(
            "Captured · 60s",
            format_bytes(captured),
            theme::fg(theme::text()),
            inner.width,
        ),
        metric_line(
            "Retained",
            format_bytes(retained),
            theme::fg(theme::text()),
            inner.width,
        ),
    ];
    if !sidebar {
        let coverage = coverage_text(
            coverage_fraction(captured, interface_window_bytes(basis, direction)),
            basis.exact,
        );
        lines.push(metric_line(
            "Coverage · 60s",
            coverage,
            theme::fg(color),
            inner.width,
        ));
        let percentage =
            direction.pick(snapshot.tx_attribution_pct(), snapshot.rx_attribution_pct());
        lines.push(metric_line(
            "Attributed",
            format!("{percentage:.1}%"),
            attribution_style(percentage),
            inner.width,
        ));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn coverage_text(fraction: Option<f64>, exact: bool) -> String {
    fraction.map_or_else(
        || "n/a".to_string(),
        |f| format!("{}{:.1}%", if exact { "" } else { "~" }, f * 100.0),
    )
}

fn draw_coverage(
    f: &mut Frame,
    snapshot: &ProcessActivitySnapshot,
    basis: &InterfaceBasis,
    area: Rect,
) {
    let inner = section_header(f, area, section_title(" Capture coverage · 60s"));
    let mut lines = Vec::new();
    for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
        let color = direction_color(direction);
        let fraction = coverage_fraction(
            snapshot_window_bytes(snapshot, direction),
            interface_window_bytes(basis, direction),
        );
        lines.push(metric_line(
            direction.rate_label(),
            coverage_text(fraction, basis.exact),
            theme::fg(color),
            inner.width,
        ));
        lines.push(Line::from(glow_bar::themed_spans(
            fraction.unwrap_or_default(),
            usize::from(inner.width),
            color,
        )));
        lines.push(Line::default());
    }
    lines.push(metric_line(
        &format!("{} TX", basis.label),
        format_bytes(basis.tx_window_bytes),
        theme::fg(theme::muted()),
        inner.width,
    ));
    lines.push(metric_line(
        &format!("{} RX", basis.label),
        format_bytes(basis.rx_window_bytes),
        theme::fg(theme::muted()),
        inner.width,
    ));
    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_attribution(f: &mut Frame, snapshot: &ProcessActivitySnapshot, area: Rect) {
    let inner = section_header(f, area, section_title(" Process attribution"));
    let mut lines = Vec::new();
    for direction in [ActivityDirection::Egress, ActivityDirection::Ingress] {
        let percentage =
            direction.pick(snapshot.tx_attribution_pct(), snapshot.rx_attribution_pct());
        let unknown = direction.pick(
            snapshot
                .retained_tx_bytes
                .saturating_sub(snapshot.attributed_tx_bytes),
            snapshot
                .retained_rx_bytes
                .saturating_sub(snapshot.attributed_rx_bytes),
        );
        lines.push(metric_line(
            direction.rate_label(),
            format!("{percentage:.1}% mapped"),
            attribution_style(percentage),
            inner.width,
        ));
        lines.push(metric_line(
            "Unknown",
            format_bytes(unknown),
            unknown_style(unknown),
            inner.width,
        ));
        lines.push(Line::default());
    }
    f.render_widget(Paragraph::new(lines), inner);
}

fn coverage_fraction(captured_bytes: u64, interface_bytes: u64) -> Option<f64> {
    (interface_bytes > 0).then(|| (captured_bytes as f64 / interface_bytes as f64).min(1.0))
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

fn snapshot_current_bps(snapshot: &ProcessActivitySnapshot, direction: ActivityDirection) -> f64 {
    direction.pick(snapshot.current_tx_bps, snapshot.current_rx_bps)
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
    basis: &InterfaceBasis,
    ui_state: &UiState,
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
            section_title(format!(
                " Processes · {}",
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
        draw_placeholder(f, inner, "Waiting for process traffic...");
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
        .saturating_sub(2)
        .div_euclid(2)
        .min(MAX_VISIBLE_PROCESSES as u16) as usize;
    let wide = inner.width >= 148;
    let medium = inner.width >= 105;
    let pulse_width = if wide {
        14
    } else {
        usize::from(inner.width).saturating_sub(94).clamp(10, 22)
    };
    let name_width = if wide {
        24
    } else {
        usize::from(inner.width / 4).clamp(8, 20)
    };

    let rows: Vec<Row> = processes
        .into_iter()
        .take(visible)
        .map(|process| {
            let pulse_fraction = if snapshot_window_bytes(snapshot, traffic_direction) > 0 {
                window_share(&process, traffic_direction) / 100.0
            } else {
                retained_share(&process, traffic_direction) / 100.0
            };
            let name = truncate_with_ellipsis(&process.identity.display_name(), name_width);
            let name_cell = Cell::from(if medium {
                vec![Line::from(name)]
            } else {
                vec![
                    Line::from(name),
                    Line::from(glow_bar::themed_spans(
                        pulse_fraction,
                        name_width.min(14),
                        if process.identity.attributed {
                            direction_color(traffic_direction)
                        } else {
                            theme::warn()
                        },
                    )),
                ]
            })
            .style(if process.identity.attributed {
                theme::bold_fg(theme::text())
            } else {
                theme::bold_fg(theme::warn())
            });
            let mut cells = vec![name_cell];
            if medium {
                cells.push(Cell::from(Line::from(glow_bar::themed_spans(
                    pulse_fraction,
                    pulse_width,
                    if process.identity.attributed {
                        direction_color(traffic_direction)
                    } else {
                        theme::warn()
                    },
                ))));
            }
            cells.push(
                right_cell(format_rate(current_rate(&process, traffic_direction)))
                    .style(theme::bold_fg(direction_color(traffic_direction))),
            );
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
            Row::new(cells)
                .style(style)
                .height(if medium { 1 } else { 2 })
                .bottom_margin(u16::from(medium))
        })
        .collect();

    let mut headers = vec![Cell::from("Process")];
    let mut constraints = vec![Constraint::Length(name_width as u16)];
    if medium {
        headers.push(Cell::from("Share"));
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
        constraints.push(Constraint::Min(20));
    }

    let table = Table::new(rows, constraints).header(
        Row::new(headers)
            .style(theme::bold_fg(theme::heading()))
            .bottom_margin(1),
    );
    f.render_widget(table, inner);
}

fn right_cell(value: String) -> Cell<'static> {
    Cell::from(Line::from(value).right_aligned())
}

fn draw_interface_pulse(f: &mut Frame, app: &App, direction: ActivityDirection, area: Rect) {
    let inner = section_header(
        f,
        area,
        section_title(format!(" Interfaces · {}", direction.rate_label())),
    );
    let rates = app.get_interface_rates();
    if rates.is_empty() {
        draw_placeholder(f, inner, "Waiting for interface counters...");
        return;
    }

    let rate_of = |rate: &crate::network::interface_stats::InterfaceRates| {
        direction.pick(rate.tx_bytes_per_sec, rate.rx_bytes_per_sec)
    };
    let mut rates: Vec<_> = rates.into_iter().collect();
    rates.sort_by(|a, b| {
        rate_of(&b.1)
            .cmp(&rate_of(&a.1))
            .then_with(|| a.0.cmp(&b.0))
    });
    let peak = rates
        .iter()
        .map(|(_, rate)| rate_of(rate))
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
            let selected_rate = rate_of(&rate);
            let mut spans = vec![Span::styled(
                format!(
                    "{:<name_width$} ",
                    truncate_with_ellipsis(&name, name_width)
                ),
                theme::fg(theme::text()),
            )];
            spans.extend(glow_bar::themed_spans(
                selected_rate as f64 / peak as f64,
                bar_width,
                direction_color(direction),
            ));
            spans.push(Span::styled(
                format!(
                    " ↑{}",
                    format_rate_compact(rate.tx_bytes_per_sec as f64, "0B")
                ),
                theme::fg(theme::tx()),
            ));
            spans.push(Span::styled(
                format!(
                    " ↓{}",
                    format_rate_compact(rate.rx_bytes_per_sec as f64, "0B")
                ),
                theme::fg(theme::rx()),
            ));
            Line::from(spans)
        })
        .collect();
    f.render_widget(Paragraph::new(lines), inner);
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
