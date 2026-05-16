//! Graph tab — traffic chart, connections sparkline, network
//! health, TCP counters, TCP state distribution, application
//! protocol distribution, and top processes by bandwidth.

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols,
    text::{Line, Span},
    widgets::{Axis, Cell, Chart, Dataset, GraphType, Paragraph, Row, Sparkline, Table},
};

use crate::app::App;
use crate::network::types::{
    AppProtocolDistribution, Connection, Protocol, ProtocolState, TcpState, TrafficHistory,
};
use crate::ui::{
    format::{format_rate, format_rate_compact},
    panel_block, theme,
};

pub(in crate::ui) fn draw_graph_tab(
    f: &mut Frame,
    app: &App,
    connections: &[Connection],
    area: Rect,
) -> Result<()> {
    // Filter out historic connections — graph should only show alive connections
    let active_connections: Vec<Connection> = connections
        .iter()
        .filter(|c| !c.is_historic)
        .cloned()
        .collect();
    let connections = &active_connections;

    let traffic_history = app.get_traffic_history();

    // Each panel gets its own Block::ALL border so the Graph tab matches the
    // style of the connections table and the Details panes. No outer frame
    // and no custom separator characters — ratatui's box-drawing renders
    // cleanly without needing manual junctions.
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35), // Traffic chart (RX/TX legend is built into the chart)
            Constraint::Percentage(20), // Network health + TCP states
            Constraint::Min(0),         // App distribution + top processes
        ])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    let health_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[2]);

    draw_traffic_chart(f, &traffic_history, top_chunks[0]);
    draw_connections_sparkline(f, &traffic_history, top_chunks[1]);
    draw_health_chart(f, &traffic_history, health_chunks[0]);
    draw_tcp_counters(f, app, health_chunks[1]);
    draw_tcp_states(f, connections, health_chunks[2]);
    draw_app_distribution(f, connections, bottom_chunks[0]);
    draw_top_processes(f, connections, bottom_chunks[1]);

    Ok(())
}

/// Draw the full traffic chart with RX/TX lines
fn draw_traffic_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Traffic Over Time (60s) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting data...").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    // Reserve a 1-cell legend strip at the bottom of the panel so RX/TX
    // labels are always visible (ratatui's built-in chart legend gets hidden
    // by `hidden_legend_constraints` when the chart area is small).
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(inner);
    let chart_area = layout[0];
    let legend_area = layout[1];

    let legend = Paragraph::new(Line::from(vec![
        Span::styled("▬ RX (incoming) ↓", theme::fg(theme::rx())),
        Span::raw("   "),
        Span::styled("▬ TX (outgoing) ↑", theme::fg(theme::tx())),
    ]));
    f.render_widget(legend, legend_area);

    let (rx_data, tx_data) = history.get_chart_data();

    // Find max value for Y axis scaling
    let max_rate = rx_data
        .iter()
        .chain(tx_data.iter())
        .map(|(_, y)| *y)
        .fold(0.0f64, |a, b| a.max(b))
        .max(1024.0); // Minimum 1 KB/s scale

    let datasets = vec![
        Dataset::default()
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(theme::fg(theme::rx()))
            .data(&rx_data),
        Dataset::default()
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(theme::fg(theme::tx()))
            .data(&tx_data),
    ];

    let chart = Chart::new(datasets)
        .x_axis(
            Axis::default()
                .title("Time")
                .style(theme::fg(theme::muted()))
                .bounds([-60.0, 0.0])
                .labels(vec![
                    Line::from("-60s"),
                    Line::from("-30s"),
                    Line::from("now"),
                ]),
        )
        .y_axis(
            Axis::default()
                .title("Rate")
                .style(theme::fg(theme::muted()))
                .bounds([0.0, max_rate])
                .labels(vec![
                    Line::from("0"),
                    Line::from(format_rate_compact(max_rate / 2.0)),
                    Line::from(format_rate_compact(max_rate)),
                ]),
        );

    f.render_widget(chart, chart_area);
}

/// Draw connections count sparkline
fn draw_connections_sparkline(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Connections ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting...").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    // Layout: sparkline + current count label
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let width = inner.width as usize;
    let conn_data = history.get_connection_sparkline_data(width);

    let sparkline = Sparkline::default()
        .data(&conn_data)
        .style(theme::fg(theme::accent()));
    f.render_widget(sparkline, chunks[0]);

    // Current connection count label (active connections only)
    let current_count = conn_data.last().copied().unwrap_or(0);
    let label = Paragraph::new(format!("{} active connections", current_count));
    f.render_widget(label, chunks[1]);
}

/// Draw application protocol distribution
fn draw_app_distribution(f: &mut Frame, connections: &[Connection], area: Rect) {
    let block = panel_block(" Application Distribution ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let dist = AppProtocolDistribution::from_connections(connections);
    let percentages = dist.as_percentages();

    // Filter out zero-count protocols and create bars.
    // Layout per row: "{label:6} {bar} {pct:5.1}%" — 6 + 1 + bar + 1 + 6 = 14 + bar.
    // Reserve those 14 cells plus 1 for right padding so bars don't touch
    // the panel edge.
    const LABEL_WIDTH: usize = 6;
    const PCT_WIDTH: usize = 6; // " 99.9%"
    const SPACERS_AND_PAD: usize = 3; // " bar " + 1 right pad
    let bar_width = (inner.width as usize)
        .saturating_sub(LABEL_WIDTH + PCT_WIDTH + SPACERS_AND_PAD)
        .max(1);
    let mut lines: Vec<Line> = Vec::new();

    for (label, count, pct) in percentages {
        if count == 0 {
            continue;
        }

        let filled = ((pct / 100.0) * bar_width as f64) as usize;
        let bar: String = "█".repeat(filled) + &"░".repeat(bar_width.saturating_sub(filled));

        let color = match label {
            "HTTPS" => theme::proto_https(),
            "QUIC" => theme::proto_quic(),
            "HTTP" => theme::proto_http(),
            "DNS" => theme::proto_dns(),
            "SSH" => theme::proto_ssh(),
            _ => theme::proto_other(),
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<width$}", label, width = LABEL_WIDTH),
                theme::fg(color),
            ),
            Span::raw(" "),
            Span::styled(bar, theme::fg(color)),
            Span::raw(format!(" {:>5.1}%", pct)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "No connections",
            theme::fg(theme::muted()),
        )));
    }

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

/// Draw top processes by bandwidth
fn draw_top_processes(f: &mut Frame, connections: &[Connection], area: Rect) {
    use std::collections::HashMap;

    let block = panel_block(" Top Processes ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Aggregate traffic by process
    let mut process_traffic: HashMap<String, f64> = HashMap::new();
    for conn in connections {
        let name = conn
            .process_name
            .clone()
            .unwrap_or_else(|| "Unknown".to_string());
        let traffic = conn.current_incoming_rate_bps + conn.current_outgoing_rate_bps;
        *process_traffic.entry(name).or_insert(0.0) += traffic;
    }

    // Sort by traffic descending, filter out processes with no traffic
    let mut sorted: Vec<_> = process_traffic
        .into_iter()
        .filter(|(_, rate)| *rate > 0.0)
        .collect();
    sorted.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // Create rows for top 5 processes. Process name absorbs whatever width is
    // left after the fixed-width Rate column, and Rate is right-aligned so the
    // numbers form a clean right edge.
    let rows: Vec<Row> = sorted
        .into_iter()
        .take(5)
        .map(|(name, rate)| {
            let display_name = if name.len() > 20 {
                format!("{}...", &name[..17])
            } else {
                name
            };
            Row::new(vec![
                Cell::from(display_name),
                Cell::from(Line::from(format_rate(rate)).right_aligned())
                    .style(theme::fg(theme::accent())),
            ])
        })
        .collect();

    if rows.is_empty() {
        let placeholder = Paragraph::new("No active processes").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    let table = Table::new(rows, [Constraint::Min(0), Constraint::Length(12)]).header(
        Row::new(vec![
            Cell::from("Process"),
            Cell::from(Line::from("Rate").right_aligned()),
        ])
        .style(theme::fg(theme::heading())),
    );

    f.render_widget(table, inner);
}

/// Draw the network health gauges with RTT and packet loss bars
fn draw_health_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let block = panel_block(" Network Health ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting data...").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    // Get current values from history
    let (loss_data, rtt_data) = history.get_health_chart_data();

    // Get most recent values (last data point)
    let current_loss = loss_data.last().map(|(_, v)| *v).unwrap_or(0.0);
    let current_rtt = rtt_data.last().map(|(_, v)| *v);

    // Calculate averages
    let avg_loss = if !loss_data.is_empty() {
        loss_data.iter().map(|(_, v)| v).sum::<f64>() / loss_data.len() as f64
    } else {
        0.0
    };
    let avg_rtt = if !rtt_data.is_empty() {
        Some(rtt_data.iter().map(|(_, v)| v).sum::<f64>() / rtt_data.len() as f64)
    } else {
        None
    };

    // Thresholds for gauges
    const RTT_MAX: f64 = 200.0; // 200ms max scale
    const LOSS_MAX: f64 = 10.0; // 10% max scale

    // Layout per row: "  {label:5}{bar} {value:>9}" with 1 cell of right pad.
    // Reserve 2 (lead) + 5 (label) + 1 (gap) + 9 (value) + 1 (pad) = 18.
    let bar_width = (inner.width as usize).saturating_sub(18).max(1);

    // Build RTT gauge
    let rtt_line = if let Some(rtt) = current_rtt {
        let rtt_pct = (rtt / RTT_MAX).min(1.0);
        let filled = (rtt_pct * bar_width as f64) as usize;
        let empty = bar_width.saturating_sub(filled);

        let color = if rtt < 50.0 {
            theme::ok()
        } else if rtt < 150.0 {
            theme::warn()
        } else {
            theme::err()
        };

        Line::from(vec![
            Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("█".repeat(filled), theme::fg(color)),
            Span::styled("░".repeat(empty), theme::fg(theme::muted())),
            Span::styled(format!(" {:>6.1}ms", rtt), theme::fg(color)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  RTT  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled("░".repeat(bar_width), theme::fg(theme::muted())),
            Span::styled("    --  ", theme::fg(theme::muted())),
        ])
    };

    // Build Loss gauge
    let loss_pct = (current_loss / LOSS_MAX).min(1.0);
    let filled = (loss_pct * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);

    let loss_color = if current_loss < 1.0 {
        theme::ok()
    } else if current_loss < 5.0 {
        theme::warn()
    } else {
        theme::err()
    };

    let loss_line = Line::from(vec![
        Span::styled("  Loss ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            "█".repeat(filled.max(if current_loss > 0.0 { 1 } else { 0 })),
            theme::fg(loss_color),
        ),
        Span::styled("░".repeat(empty.min(bar_width)), theme::fg(theme::muted())),
        Span::styled(format!(" {:>6.2}%", current_loss), theme::fg(loss_color)),
    ]);

    // Build averages line
    let avg_line = Line::from(vec![
        Span::styled("  avg: ", theme::fg(theme::muted())),
        Span::styled(
            avg_rtt
                .map(|r| format!("{:.0}ms", r))
                .unwrap_or_else(|| "--".to_string()),
            theme::fg(theme::muted()),
        ),
        Span::styled(" / ", theme::fg(theme::muted())),
        Span::styled(format!("{:.2}%", avg_loss), theme::fg(theme::muted())),
    ]);

    let paragraph = Paragraph::new(vec![rtt_line, loss_line, avg_line]);
    f.render_widget(paragraph, inner);
}

/// Draw TCP counters (retransmits, out of order, fast retransmits)
fn draw_tcp_counters(f: &mut Frame, app: &App, area: Rect) {
    use std::sync::atomic::Ordering;

    let stats = app.get_stats();
    let retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
    let out_of_order = stats.total_tcp_out_of_order.load(Ordering::Relaxed);
    let fast_retransmits = stats.total_tcp_fast_retransmits.load(Ordering::Relaxed);

    let block = panel_block(" TCP Counters ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    // Color based on counts (higher = more concerning)
    let retrans_color = if retransmits == 0 {
        theme::ok()
    } else if retransmits < 100 {
        theme::warn()
    } else {
        theme::err()
    };

    let ooo_color = if out_of_order == 0 {
        theme::ok()
    } else if out_of_order < 50 {
        theme::warn()
    } else {
        theme::err()
    };

    let fast_color = if fast_retransmits == 0 {
        theme::ok()
    } else if fast_retransmits < 50 {
        theme::warn()
    } else {
        theme::err()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(
                "  Retransmits  ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", retransmits), theme::fg(retrans_color)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Out of Order ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", out_of_order), theme::fg(ooo_color)),
        ]),
        Line::from(vec![
            Span::styled(
                "  Fast Retrans ",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{:>8}", fast_retransmits), theme::fg(fast_color)),
        ]),
    ];

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

/// Draw TCP connection states breakdown
fn draw_tcp_states(f: &mut Frame, connections: &[Connection], area: Rect) {
    use std::collections::HashMap;

    // Count TCP states
    let mut state_counts: HashMap<&str, usize> = HashMap::new();
    for conn in connections {
        if conn.protocol == Protocol::Tcp
            && let ProtocolState::Tcp(tcp_state) = &conn.protocol_state
        {
            let state_name = match tcp_state {
                TcpState::Established => "ESTAB",
                TcpState::SynSent => "SYN_SENT",
                TcpState::SynReceived => "SYN_RECV",
                TcpState::FinWait1 => "FIN_WAIT1",
                TcpState::FinWait2 => "FIN_WAIT2",
                TcpState::TimeWait => "TIME_WAIT",
                TcpState::CloseWait => "CLOSE_WAIT",
                TcpState::LastAck => "LAST_ACK",
                TcpState::Closing => "CLOSING",
                TcpState::Closed => "CLOSED",
                TcpState::Unknown => "UNKNOWN",
            };
            *state_counts.entry(state_name).or_insert(0) += 1;
        }
    }

    // Fixed order based on connection lifecycle (most important first)
    const STATE_ORDER: &[&str] = &[
        "ESTAB",
        "SYN_SENT",
        "SYN_RECV",
        "FIN_WAIT1",
        "FIN_WAIT2",
        "TIME_WAIT",
        "CLOSE_WAIT",
        "LAST_ACK",
        "CLOSING",
        "CLOSED",
        "LISTEN",
        "UNKNOWN",
    ];

    // Build ordered list with only non-zero counts
    let states: Vec<_> = STATE_ORDER
        .iter()
        .filter_map(|&name| state_counts.get(name).map(|&count| (name, count)))
        .collect();

    let block = panel_block(" TCP States ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    if states.is_empty() {
        let text = Paragraph::new("No TCP connections").style(theme::fg(theme::muted()));
        f.render_widget(text, inner);
        return;
    }

    // Find max count for bar scaling.
    // Layout per row: "{name:>10} {bar} {count:>4}" with 1 cell of right pad.
    // Reserve 10 (name) + 1 + 1 (count gap) + 4 (count) + 1 (right pad) = 17.
    let max_count = states.iter().map(|(_, c)| *c).max().unwrap_or(1);
    const RESERVED: usize = 17;
    let bar_width = (inner.width as usize).saturating_sub(RESERVED).max(1);

    // Build lines for each state (limit to available height)
    let max_rows = inner.height as usize;
    let lines: Vec<Line> = states
        .iter()
        .take(max_rows)
        .map(|(name, count)| {
            let bar_len = (*count * bar_width).checked_div(max_count).unwrap_or(0);
            let bar = "█".repeat(bar_len.max(1).min(bar_width));

            // Color based on state health
            let color = match *name {
                "ESTAB" => theme::tcp_established(),
                "SYN_SENT" | "SYN_RECV" => theme::tcp_opening(),
                "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => theme::tcp_closing(),
                "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => theme::tcp_waiting(),
                "CLOSED" => theme::tcp_closed(),
                _ => Color::Reset,
            };

            Line::from(vec![
                Span::styled(format!("{:>10} ", name), theme::fg(color)),
                Span::styled(bar, theme::fg(color)),
                Span::raw(format!(" {:>4}", count)),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}
