//! Detailed per-interface table used by the Host tab.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Wrap},
};

use crate::app::App;
use crate::network::interface_stats::{InterfaceErrorCounts, InterfaceRates, InterfaceStats};
use crate::ui::{
    UiState,
    format::format_bytes,
    section_header, section_title, theme,
    widgets::scrollbar::{draw_scrolled_text, render_scrolled_table},
};

pub(in crate::ui) fn draw_interface_stats(
    f: &mut Frame,
    app: &App,
    ui_state: &UiState,
    area: Rect,
) -> Result<()> {
    let mut stats = app.get_interface_stats();
    let rates = app.get_interface_rates();
    let (errors, since_clear) = app.get_interface_errors(ui_state.host_window);
    let label = ui_state.host_window.label_since_clear(since_clear);

    // Sort interfaces to show the captured interface first
    let captured_interface = app.get_current_interface();
    if let Some(ref captured) = captured_interface {
        stats.sort_by(|a, b| {
            let a_is_captured = &a.interface_name == captured;
            let b_is_captured = &b.interface_name == captured;
            match (a_is_captured, b_is_captured) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => a.interface_name.cmp(&b.interface_name),
            }
        });
    }

    let inner = section_header(
        f,
        area,
        section_title(format!("Interface Statistics · {label}")),
    );
    let legend = if area.width < 90 {
        "Errors/drops/collisions: window / OS total\nPackets: OS total · rates: live"
    } else {
        "Errors/drops/collisions: window / OS total · packets: OS total · rates: live"
    };
    if stats.is_empty() {
        ui_state.interfaces_scroll.clamp_for_render(0);
        crate::ui::draw_placeholder(f, inner, "Waiting for interface statistics...");
        return Ok(());
    }
    let rows: Vec<_> = stats
        .iter()
        .map(|stat| {
            InterfaceRow::new(
                stat,
                rates.get(&stat.interface_name),
                errors.get(&stat.interface_name),
            )
        })
        .collect();
    let mut column_widths = [14u16, 12, 12, 10, 10, 9, 9, 10, 10, 10];
    for row in &rows {
        for (width, value) in column_widths.iter_mut().zip(&row.values) {
            *width = (*width).max(u16::try_from(value.width()).unwrap_or(u16::MAX));
        }
    }
    // Include column gaps and the shared scrollbar gutter before choosing records.
    let required_width = column_widths
        .iter()
        .map(|&width| usize::from(width))
        .sum::<usize>()
        + column_widths.len()
        - 1
        + 2;
    if area.width < 120 || usize::from(area.width) < required_width {
        let mut lines: Vec<_> = legend
            .lines()
            .map(|line| Line::from(Span::styled(line, theme::fg(theme::muted()))))
            .collect();
        for row in rows {
            let [
                name,
                rx,
                tx,
                rx_packets,
                tx_packets,
                rx_errors,
                tx_errors,
                rx_dropped,
                tx_dropped,
                mut collisions,
            ] = row.values;
            collisions.spans.insert(0, Span::raw("Collisions: "));
            lines.extend([
                Line::from(section_title(name.to_string())),
                Line::styled(format!("RX {rx}  ·  TX {tx}"), theme::fg(theme::text())),
                Line::from(format!("Packets: RX {rx_packets}  TX {tx_packets}")),
                counter_pair("Errors", rx_errors, tx_errors),
                counter_pair("Drops", rx_dropped, tx_dropped),
                collisions,
                Line::default(),
            ]);
        }
        if lines.last().is_some_and(|line| line.width() == 0) {
            lines.pop();
        }
        draw_scrolled_text(
            f,
            inner,
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            &ui_state.interfaces_scroll,
        );
        return Ok(());
    }

    let legend_height = if area.width < 90 { 2 } else { 1 }.min(inner.height);
    f.render_widget(
        Paragraph::new(legend).style(theme::fg(theme::muted())),
        Rect {
            height: legend_height,
            ..inner
        },
    );
    let inner = Rect {
        y: inner.y + legend_height,
        height: inner.height - legend_height,
        ..inner
    };

    let rows = rows
        .into_iter()
        .map(|row| {
            Row::new(row.values.into_iter().enumerate().map(|(column, value)| {
                Cell::from(if column == 0 {
                    value
                } else {
                    value.right_aligned()
                })
            }))
        })
        .collect();

    let header = Row::new(
        [
            "Interface",
            "RX Rate",
            "TX Rate",
            "RX Packets",
            "TX Packets",
            "RX Err",
            "TX Err",
            "RX Drop",
            "TX Drop",
            "Collisions",
        ]
        .into_iter()
        .enumerate()
        .map(|(column, title)| {
            let line = Line::from(title);
            Cell::from(if column == 0 {
                line
            } else {
                line.right_aligned()
            })
        }),
    );
    // Windowed against the scroll offset so hosts with dozens of
    // bridge/veth interfaces can reach them all.
    render_scrolled_table(
        f,
        inner,
        header,
        rows,
        &column_widths
            .iter()
            .enumerate()
            .map(|(index, &width)| {
                if index == 0 {
                    Constraint::Min(width)
                } else {
                    Constraint::Length(width)
                }
            })
            .collect::<Vec<_>>(),
        &ui_state.interfaces_scroll,
    );

    Ok(())
}

fn counter_pair(label: &str, rx: Line<'static>, tx: Line<'static>) -> Line<'static> {
    let mut line = Line::from(format!("{label}: RX "));
    line.extend(rx.spans);
    line.push_span("  TX ");
    line.extend(tx.spans);
    line
}

/// Format once so compact records, table cells and width measurements agree.
struct InterfaceRow {
    values: [Line<'static>; 10],
}

impl InterfaceRow {
    fn new(
        stat: &InterfaceStats,
        rate: Option<&InterfaceRates>,
        selected: Option<&InterfaceErrorCounts>,
    ) -> Self {
        let pair = |value: Option<u64>, total: u64, color: Color| {
            Line::from(vec![
                value.map_or_else(|| Span::raw("-"), |n| super::count_span(n, color)),
                Span::raw(format!("/{total}")),
            ])
        };
        let format_rate = |value: Option<u64>| {
            Line::from(value.map_or_else(|| "-".into(), |n| format!("{}/s", format_bytes(n))))
        };
        Self {
            values: [
                Line::from(stat.interface_name.clone()),
                format_rate(rate.map(|r| r.rx_bytes_per_sec)),
                format_rate(rate.map(|r| r.tx_bytes_per_sec)),
                Line::from(stat.rx_packets.to_string()),
                Line::from(stat.tx_packets.to_string()),
                pair(selected.map(|c| c.rx_errors), stat.rx_errors, theme::err()),
                pair(selected.map(|c| c.tx_errors), stat.tx_errors, theme::err()),
                pair(
                    selected.map(|c| c.rx_dropped),
                    stat.rx_dropped,
                    theme::warn(),
                ),
                pair(
                    selected.map(|c| c.tx_dropped),
                    stat.tx_dropped,
                    theme::warn(),
                ),
                pair(
                    selected.map(|c| c.collisions),
                    stat.collisions,
                    theme::warn(),
                ),
            ],
        }
    }
}
