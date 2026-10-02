//! Detailed per-interface table used by the Host tab.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Wrap},
};

use crate::app::App;
use crate::ui::{
    UiState, alert_style,
    format::{cell_width, format_bytes},
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

    let inner = section_header(f, area, section_title("Interface Statistics"));
    if stats.is_empty() {
        ui_state.interfaces_scroll.clamp_for_render(0);
        crate::ui::draw_placeholder(f, inner, "Waiting for interface statistics...");
        return Ok(());
    }
    let mut column_widths = [14u16, 12, 12, 10, 10, 9, 9, 10, 10, 10];
    for stat in &stats {
        let rate = rates.get(&stat.interface_name);
        let values = [
            stat.interface_name.clone(),
            rate.map_or_else(
                || "-".into(),
                |r| format!("{}/s", format_bytes(r.rx_bytes_per_sec)),
            ),
            rate.map_or_else(
                || "-".into(),
                |r| format!("{}/s", format_bytes(r.tx_bytes_per_sec)),
            ),
            stat.rx_packets.to_string(),
            stat.tx_packets.to_string(),
            stat.rx_errors.to_string(),
            stat.tx_errors.to_string(),
            stat.rx_dropped.to_string(),
            stat.tx_dropped.to_string(),
            stat.collisions.to_string(),
        ];
        for (width, value) in column_widths.iter_mut().zip(values) {
            *width = (*width).max(u16::try_from(cell_width(&value)).unwrap_or(u16::MAX));
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
        let mut lines = Vec::new();
        for stat in &stats {
            let rate = rates.get(&stat.interface_name);
            let rx = rate.map_or_else(
                || "-".to_string(),
                |r| format!("{}/s", format_bytes(r.rx_bytes_per_sec)),
            );
            let tx = rate.map_or_else(
                || "-".to_string(),
                |r| format!("{}/s", format_bytes(r.tx_bytes_per_sec)),
            );
            lines.extend([
                Line::from(section_title(stat.interface_name.clone())),
                Line::from(Span::styled(
                    format!("RX {rx}  ·  TX {tx}"),
                    theme::fg(theme::text()),
                )),
                Line::from(format!(
                    "Packets: RX {}  TX {}",
                    stat.rx_packets, stat.tx_packets
                )),
                Line::from(Span::styled(
                    format!("Errors: RX {}  TX {}", stat.rx_errors, stat.tx_errors),
                    alert_style(stat.rx_errors > 0 || stat.tx_errors > 0, theme::err()),
                )),
                Line::from(Span::styled(
                    format!("Drops: RX {}  TX {}", stat.rx_dropped, stat.tx_dropped),
                    alert_style(stat.rx_dropped > 0 || stat.tx_dropped > 0, theme::warn()),
                )),
                Line::from(format!("Collisions: {}", stat.collisions)),
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

    let mut rows = Vec::new();

    for stat in &stats {
        let error_style = alert_style(stat.rx_errors > 0 || stat.tx_errors > 0, theme::err());
        let drop_style = alert_style(stat.rx_dropped > 0 || stat.tx_dropped > 0, theme::warn());

        let rx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.rx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let tx_rate_str = if let Some(rate) = rates.get(&stat.interface_name) {
            format!("{}/s", format_bytes(rate.tx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let right = |s: String| Cell::from(Line::from(s).right_aligned());
        let right_styled = |s: String, style: Style| {
            Cell::from(Line::from(Span::styled(s, style)).right_aligned())
        };
        rows.push(Row::new(vec![
            Cell::from(stat.interface_name.clone()),
            right(rx_rate_str),
            right(tx_rate_str),
            right(format!("{}", stat.rx_packets)),
            right(format!("{}", stat.tx_packets)),
            right_styled(format!("{}", stat.rx_errors), error_style),
            right_styled(format!("{}", stat.tx_errors), error_style),
            right_styled(format!("{}", stat.rx_dropped), drop_style),
            right_styled(format!("{}", stat.tx_dropped), drop_style),
            right(format!("{}", stat.collisions)),
        ]));
    }

    let header = {
        let right = |s: &str| Cell::from(Line::from(s.to_string()).right_aligned());
        Row::new(vec![
            Cell::from("Interface"),
            right("RX Rate"),
            right("TX Rate"),
            right("RX Packets"),
            right("TX Packets"),
            right("RX Err"),
            right("TX Err"),
            right("RX Drop"),
            right("TX Drop"),
            right("Collisions"),
        ])
    };
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
