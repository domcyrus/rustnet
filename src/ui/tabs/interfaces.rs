//! Interfaces tab — full table of per-NIC counters (RX/TX rate,
//! packets, errors, drops, collisions) sorted with the active
//! capture interface first. Read-only, no input handling.

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
    ClickableRegions, Component, ComponentContext, format::format_bytes, section_header, theme,
};

/// Read-only interfaces tab. Stateless for now; the table is rebuilt
/// from the App's interface-stats DashMap every render.
pub(in crate::ui) struct InterfacesTab;

impl Component for InterfacesTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_interface_stats(f, ctx.app, area)
    }
}

pub(in crate::ui) fn draw_interface_stats(f: &mut Frame, app: &App, area: Rect) -> Result<()> {
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

        // Get rate for this interface — single lookup shared by rx and tx.
        let rate = rates.get(&stat.interface_name);
        let rx_rate_str = rate.map_or_else(
            || "---".to_string(),
            |r| format!("{}/s", format_bytes(r.rx_bytes_per_sec)),
        );
        let tx_rate_str = rate.map_or_else(
            || "---".to_string(),
            |r| format!("{}/s", format_bytes(r.tx_bytes_per_sec)),
        );

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

    // Create table
    let table = Table::new(
        rows,
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
        let right = |s: &'static str| Cell::from(Line::from(s).right_aligned());
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

    let area = section_header(
        f,
        area,
        ratatui::text::Span::styled(
            " Interface Statistics",
            Style::default().add_modifier(ratatui::style::Modifier::BOLD),
        ),
    );
    f.render_widget(table, area);

    Ok(())
}
