//! Detailed per-interface table used as the Activity tab's secondary view.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{Cell, Row, Table},
};

use crate::app::App;
use crate::ui::{
    UIState, format::format_bytes, section_header, theme, widgets::scrollbar::draw_scrollbar,
};

pub(in crate::ui) fn draw_interface_stats(
    f: &mut Frame,
    app: &App,
    ui_state: &UIState,
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

    if stats.is_empty() {
        return Ok(());
    }

    // Create table rows
    let mut rows = Vec::new();

    for stat in &stats {
        // Determine error style
        let error_style = if stat.rx_errors > 0 || stat.tx_errors > 0 {
            theme::fg(theme::err())
        } else {
            theme::fg(theme::ok())
        };

        // Determine drop style
        let drop_style = if stat.rx_dropped > 0 || stat.tx_dropped > 0 {
            theme::fg(theme::warn())
        } else {
            theme::fg(theme::ok())
        };

        // Get rate for this interface
        let rate = rates.get(&stat.interface_name);
        let rx_rate_str = if let Some(rate) = rate {
            format!("{}/s", format_bytes(rate.rx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let tx_rate_str = if let Some(rate) = rate {
            format!("{}/s", format_bytes(rate.tx_bytes_per_sec))
        } else {
            "---".to_string()
        };

        let right = |s: String| Cell::from(Line::from(s).right_aligned());
        let right_styled = |s: String, style: Style| {
            Cell::from(Line::from(Span::styled(s, style)).right_aligned())
        };
        rows.push(Row::new(vec![
            Cell::from(stat.interface_name.as_str()),
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

    let inner = section_header(
        f,
        area,
        ratatui::text::Span::styled(
            " Interface Statistics",
            Style::default().add_modifier(ratatui::style::Modifier::BOLD),
        ),
    );

    // Window the rows against the scroll offset so hosts with dozens of
    // bridge/veth interfaces can reach them all. The viewport excludes
    // the table's header row.
    let total_rows = rows.len();
    let viewport = inner.height.saturating_sub(1) as usize;
    let max_scroll = (total_rows as u16).saturating_sub(viewport as u16);
    let scroll = ui_state.interfaces_scroll.clamp_for_render(max_scroll) as usize;
    let windowed: Vec<Row> = rows.into_iter().skip(scroll).collect();

    // Create table; reserve the two rightmost columns for a blank gap
    // plus the scrollbar, mirroring the Overview table.
    let table = Table::new(
        windowed,
        [
            Constraint::Length(14), // Interface
            Constraint::Length(12), // RX Bytes
            Constraint::Length(12), // TX Bytes
            Constraint::Length(10), // RX Packets
            Constraint::Length(10), // TX Packets
            Constraint::Length(9),  // RX Err
            Constraint::Length(9),  // TX Err
            Constraint::Length(10), // RX Drop
            Constraint::Length(10), // TX Drop
            Constraint::Length(10), // Collis
        ],
    )
    .header({
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
        .style(theme::fg(theme::heading()))
    })
    .style(Style::default());

    let table_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    f.render_widget(table, table_area);

    // Scrollbar tracks the row region (below the header row).
    let rows_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    draw_scrollbar(f, rows_area, total_rows, scroll, viewport);

    Ok(())
}
