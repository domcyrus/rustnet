//! Graph tab — traffic chart, connections sparkline, network
//! health, TCP counters, TCP state distribution, application
//! protocol distribution, and top processes by bandwidth.

use std::collections::HashMap;

use anyhow::Result;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};

use crate::app::App;
use crate::network::types::{
    AppProtocolDistribution, Connection, Protocol, ProtocolState, TcpState, TrafficHistory,
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext,
    format::format_rate,
    section_header, theme,
    widgets::{braille_graph, glow_bar},
};

const TCP_STATE_NAMES: [&str; 11] = [
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
    "UNKNOWN",
];

/// Data used by the connection-derived graph panels. Building it once keeps
/// the render cost to one pass over active connections.
struct GraphAnalytics<'a> {
    app_distribution: AppProtocolDistribution,
    process_traffic: HashMap<&'a str, f64>,
    tcp_state_counts: [usize; TCP_STATE_NAMES.len()],
}

impl<'a> GraphAnalytics<'a> {
    fn from_connections(connections: &'a [Connection]) -> Self {
        let mut analytics = Self {
            app_distribution: AppProtocolDistribution::default(),
            process_traffic: HashMap::new(),
            tcp_state_counts: [0; TCP_STATE_NAMES.len()],
        };

        for conn in connections.iter().filter(|conn| !conn.is_historic) {
            analytics.app_distribution.record_connection(conn);

            let name = conn.process_name.as_deref().unwrap_or("Unknown");
            let traffic = conn.current_incoming_rate_bps + conn.current_outgoing_rate_bps;
            *analytics.process_traffic.entry(name).or_insert(0.0) += traffic;

            if conn.protocol == Protocol::Tcp
                && let ProtocolState::Tcp(state) = &conn.protocol_state
            {
                analytics.tcp_state_counts[tcp_state_index(state)] += 1;
            }
        }

        analytics
    }
}

fn tcp_state_index(state: &TcpState) -> usize {
    match state {
        TcpState::Established => 0,
        TcpState::SynSent => 1,
        TcpState::SynReceived => 2,
        TcpState::FinWait1 => 3,
        TcpState::FinWait2 => 4,
        TcpState::TimeWait => 5,
        TcpState::CloseWait => 6,
        TcpState::LastAck => 7,
        TcpState::Closing => 8,
        TcpState::Closed => 9,
        TcpState::Unknown => 10,
    }
}

/// Bold default-foreground title span for a graph section header.
fn graph_title(text: &str) -> Span<'_> {
    Span::styled(text, Style::default().add_modifier(Modifier::BOLD))
}

/// Read-only graph tab. Aggregates traffic history, protocol mix,
/// and TCP analytics every render — no per-tab state today.
pub(in crate::ui) struct GraphTab;

impl Component for GraphTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_graph_tab(f, ctx.app, ctx.connections, area)
    }
}

pub(in crate::ui) fn draw_graph_tab(
    f: &mut Frame,
    app: &App,
    connections: &[Connection],
    area: Rect,
) -> Result<()> {
    let analytics = GraphAnalytics::from_connections(connections);
    let traffic_history = app.get_traffic_history();

    // Each panel is a borderless section_header region; layout spacing
    // provides the breathing room the old borders used to. The health
    // and distribution rows hold a handful of lines each, so they get
    // fixed heights and the wave panels absorb the rest — percentage
    // sizing left a large hole between sections on tall terminals.
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Min(8),     // Traffic + connections waves
            Constraint::Length(10), // Network health + TCP counters/states
            Constraint::Length(12), // App distribution + top processes
        ])
        .split(area);

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .spacing(2)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(main_chunks[0]);

    let health_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .spacing(2)
        .constraints([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .split(main_chunks[1]);

    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .spacing(2)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(main_chunks[2]);

    draw_traffic_chart(f, &traffic_history, top_chunks[0]);
    draw_connections_sparkline(f, &traffic_history, top_chunks[1]);
    draw_health_chart(f, &traffic_history, health_chunks[0]);
    draw_tcp_counters(f, app, health_chunks[1]);
    draw_tcp_states(f, &analytics.tcp_state_counts, health_chunks[2]);
    draw_app_distribution(f, &analytics.app_distribution, bottom_chunks[0]);
    draw_top_processes(f, &analytics.process_traffic, bottom_chunks[1]);

    Ok(())
}

/// Draw the RX/TX traffic waves: two stacked braille area graphs with
/// a vertical gradient (bright crest, saturated base), each header
/// showing the current rate, a trend arrow, and the 60s peak.
fn draw_traffic_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, graph_title(" Traffic Over Time (60s)"));

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting data...").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    // Blank row between the halves so the TX header doesn't sit
    // directly on the RX wave's baseline.
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Length(1),
            Constraint::Percentage(50),
        ])
        .split(inner);

    let frac = history.scroll_fraction();
    let window = history.capacity();
    let rx = history.get_rx_sparkline_data(usize::MAX);
    let tx = history.get_tx_sparkline_data(usize::MAX);
    braille_graph::wave_panel(
        f,
        halves[0],
        &rx,
        "↓ RX",
        braille_graph::WavePanelOptions::new(frac, window),
        theme::rx_wave,
    );
    braille_graph::wave_panel(
        f,
        halves[2],
        &tx,
        "↑ TX",
        braille_graph::WavePanelOptions::new(frac, window),
        theme::tx_wave,
    );
}

/// Horizontal bar with the same dark→bright glow as the waves: each
/// filled cell walks the gradient from deep hue at the origin to the
/// bright crest at the tip; the remainder renders as muted `░` track.
/// Draw the connection-count wave: same gradient braille style as the
/// traffic panels, in the accent (cyan) hue.
fn draw_connections_sparkline(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, graph_title(" Connections"));

    if !history.has_enough_data() {
        let placeholder = Paragraph::new("Collecting...").style(theme::fg(theme::muted()));
        f.render_widget(placeholder, inner);
        return;
    }

    let conn_data = history.get_connection_sparkline_data(usize::MAX);
    if inner.height < 2 || conn_data.is_empty() {
        return;
    }

    let current = *conn_data.last().unwrap();
    let peak = conn_data.iter().copied().max().unwrap_or(0).max(1);
    let ratio = current as f64 / peak as f64;

    let left = vec![
        Span::styled(
            format!("{current} active"),
            theme::bold_fg(theme::accent_wave(0.35 + 0.65 * ratio)),
        ),
        Span::styled(
            format!(" {}", braille_graph::trend_glyph(&conn_data)),
            theme::fg(theme::muted()),
        ),
    ];
    let right = Span::styled(format!("peak {peak}"), theme::fg(theme::muted()));
    f.render_widget(
        Paragraph::new(braille_graph::spread_line(left, right, inner.width)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let graph_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    let lines = braille_graph::render(
        &conn_data,
        graph_area.width as usize,
        graph_area.height as usize,
        peak as f64,
        history.scroll_fraction(),
        history.capacity(),
        |intensity| theme::accent_wave((0.6 + 0.4 * ratio) * intensity),
    );
    f.render_widget(Paragraph::new(lines), graph_area);
}

/// Draw application protocol distribution
fn draw_app_distribution(f: &mut Frame, dist: &AppProtocolDistribution, area: Rect) {
    let inner = section_header(f, area, graph_title(" Application Distribution"));

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

        let (color, ramp): (Color, fn(f64) -> Color) = match label {
            "HTTPS" => (theme::proto_https(), theme::ok_wave),
            "QUIC" => (theme::proto_quic(), theme::accent_wave),
            "HTTP" => (theme::proto_http(), theme::warn_wave),
            "DNS" => (theme::proto_dns(), theme::special_wave),
            "SSH" => (theme::proto_ssh(), theme::tx_wave),
            _ => (theme::proto_other(), theme::muted_wave),
        };

        let mut spans = vec![
            Span::styled(
                format!("{:<width$}", label, width = LABEL_WIDTH),
                theme::fg(color),
            ),
            Span::raw(" "),
        ];
        spans.extend(glow_bar::from_filled(filled, bar_width, ramp));
        spans.push(Span::raw(format!(" {:>5.1}%", pct)));
        lines.push(Line::from(spans));
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
fn draw_top_processes(f: &mut Frame, process_traffic: &HashMap<&str, f64>, area: Rect) {
    let inner = section_header(f, area, graph_title(" Top Processes"));

    let top_processes = select_top_processes(process_traffic, 5);

    // Create rows for top 5 processes. Process name absorbs whatever width is
    // left after the fixed-width Rate column, and Rate is right-aligned so the
    // numbers form a clean right edge.
    let rows: Vec<Row> = top_processes
        .into_iter()
        .map(|(name, rate)| {
            let display_name = if name.chars().count() > 20 {
                format!("{}...", name.chars().take(17).collect::<String>())
            } else {
                name.to_string()
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

fn select_top_processes<'a>(
    process_traffic: &HashMap<&'a str, f64>,
    limit: usize,
) -> Vec<(&'a str, f64)> {
    let mut processes: Vec<_> = process_traffic
        .iter()
        .filter_map(|(&name, &rate)| (rate > 0.0).then_some((name, rate)))
        .collect();
    let compare = |a: &(&str, f64), b: &(&str, f64)| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(b.0));

    if processes.len() > limit {
        processes.select_nth_unstable_by(limit, compare);
        processes.truncate(limit);
    }
    processes.sort_unstable_by(compare);
    processes
}

/// Draw the network health gauges with RTT and packet loss bars
fn draw_health_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, graph_title(" Network Health"));

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

        let (color, ramp): (Color, fn(f64) -> Color) = if rtt < 50.0 {
            (theme::ok(), theme::ok_wave)
        } else if rtt < 150.0 {
            (theme::warn(), theme::warn_wave)
        } else {
            (theme::err(), theme::err_wave)
        };

        let mut spans = vec![Span::styled(
            "  RTT  ",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        spans.extend(glow_bar::from_filled(filled, bar_width, ramp));
        spans.push(Span::styled(format!(" {:>6.1}ms", rtt), theme::fg(color)));
        Line::from(spans)
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

    let (loss_color, loss_ramp): (Color, fn(f64) -> Color) = if current_loss < 1.0 {
        (theme::ok(), theme::ok_wave)
    } else if current_loss < 5.0 {
        (theme::warn(), theme::warn_wave)
    } else {
        (theme::err(), theme::err_wave)
    };

    let mut loss_spans = vec![Span::styled(
        "  Loss ",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    loss_spans.extend(glow_bar::from_filled(
        filled.max(if current_loss > 0.0 { 1 } else { 0 }),
        bar_width,
        loss_ramp,
    ));
    loss_spans.push(Span::styled(
        format!(" {:>6.2}%", current_loss),
        theme::fg(loss_color),
    ));
    let loss_line = Line::from(loss_spans);

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

    let inner = section_header(f, area, graph_title(" TCP Counters"));

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
fn draw_tcp_states(f: &mut Frame, state_counts: &[usize; TCP_STATE_NAMES.len()], area: Rect) {
    // Build ordered list with only non-zero counts
    let states: Vec<_> = TCP_STATE_NAMES
        .iter()
        .zip(state_counts)
        .filter_map(|(&name, &count)| (count > 0).then_some((name, count)))
        .collect();

    let inner = section_header(f, area, graph_title(" TCP States"));

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

            // Label color keeps the semantic state alias; the bar
            // itself glows in the matching gradient family.
            let (color, ramp): (Color, fn(f64) -> Color) = match *name {
                "ESTAB" => (theme::tcp_established(), theme::ok_wave),
                "SYN_SENT" | "SYN_RECV" => (theme::tcp_opening(), theme::warn_wave),
                "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => {
                    (theme::tcp_closing(), theme::muted_wave)
                }
                "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => (theme::tcp_waiting(), theme::muted_wave),
                "CLOSED" => (theme::tcp_closed(), theme::muted_wave),
                _ => (Color::Reset, theme::muted_wave),
            };

            let mut spans = vec![Span::styled(format!("{:>10} ", name), theme::fg(color))];
            // No empty track here: rows are scaled to the max count,
            // so a full-width track would just add noise.
            let filled = bar_len.max(1).min(bar_width);
            spans.extend(glow_bar::from_filled(filled, filled, ramp));
            spans.push(Span::raw(format!(" {:>4}", count)));
            Line::from(spans)
        })
        .collect();

    let paragraph = Paragraph::new(lines);
    f.render_widget(paragraph, inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_connection(
        port: u16,
        process: &str,
        rate: f64,
        state: TcpState,
        historic: bool,
    ) -> Connection {
        let mut connection = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ProtocolState::Tcp(state),
        );
        connection.process_name = Some(process.to_string());
        connection.current_incoming_rate_bps = rate;
        connection.is_historic = historic;
        connection
    }

    #[test]
    fn analytics_aggregate_active_connections_once() {
        let connections = vec![
            test_connection(1000, "alpha", 10.0, TcpState::Established, false),
            test_connection(1001, "alpha", 20.0, TcpState::TimeWait, false),
            test_connection(1002, "beta", 5.0, TcpState::Established, false),
            test_connection(1003, "old", 100.0, TcpState::Closed, true),
        ];

        let analytics = GraphAnalytics::from_connections(&connections);

        assert_eq!(analytics.app_distribution.total(), 3);
        assert_eq!(analytics.process_traffic.get("alpha"), Some(&30.0));
        assert_eq!(analytics.process_traffic.get("beta"), Some(&5.0));
        assert!(!analytics.process_traffic.contains_key("old"));
        assert_eq!(
            analytics.tcp_state_counts[tcp_state_index(&TcpState::Established)],
            2
        );
        assert_eq!(
            analytics.tcp_state_counts[tcp_state_index(&TcpState::TimeWait)],
            1
        );
        assert_eq!(
            analytics.tcp_state_counts[tcp_state_index(&TcpState::Closed)],
            0
        );
    }

    #[test]
    fn top_process_selection_only_sorts_the_requested_prefix() {
        let traffic = HashMap::from([
            ("one", 1.0),
            ("two", 2.0),
            ("three", 3.0),
            ("four", 4.0),
            ("five", 5.0),
            ("six", 6.0),
            ("seven", 7.0),
            ("eight", 8.0),
        ]);

        let top = select_top_processes(&traffic, 3);

        assert_eq!(top, vec![("eight", 8.0), ("seven", 7.0), ("six", 6.0)]);
        assert!(select_top_processes(&traffic, 0).is_empty());
    }
}
