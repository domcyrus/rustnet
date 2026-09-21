//! Graph tab: traffic chart, connections sparkline, network
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
    ClickableRegions, Component, ComponentContext, UiState, draw_placeholder,
    format::format_rate,
    section_header, section_title,
    state::GraphSection,
    theme,
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

            let name = crate::ui::process_group_label(conn);
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

/// Graph dashboard with section navigation when the full layout cannot fit.
pub(in crate::ui) struct GraphTab;

impl Component for GraphTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_graph_tab(f, ctx.app, ctx.connections, ctx.ui_state, area);
        Ok(())
    }
}

fn draw_graph_tab(
    f: &mut Frame,
    app: &App,
    connections: &[Connection],
    ui_state: &UiState,
    area: Rect,
) {
    const WAVE_MIN_ROWS: u16 = 8;
    const HEALTH_ROWS: u16 = 10;
    const DISTRIBUTION_ROWS: u16 = 12;
    let compact =
        area.height < WAVE_MIN_ROWS + HEALTH_ROWS + DISTRIBUTION_ROWS + 2 || area.width < 100;
    ui_state.graph_compact.set(compact);
    let traffic_history = app.get_traffic_history();
    let analytics = GraphAnalytics::from_connections(connections);

    if compact {
        let inner = area;
        match ui_state.graph_section {
            GraphSection::Traffic => draw_traffic_panels(f, &traffic_history, inner),
            GraphSection::Health => draw_health_panels(f, app, &traffic_history, &analytics, inner),
            GraphSection::Distribution => draw_distribution_panels(f, &analytics, inner),
        }
        return;
    }

    let sections = Layout::vertical([
        Constraint::Min(WAVE_MIN_ROWS),
        Constraint::Length(HEALTH_ROWS),
        Constraint::Length(DISTRIBUTION_ROWS),
    ])
    .spacing(1)
    .split(area);
    draw_traffic_panels(f, &traffic_history, sections[0]);
    draw_health_panels(f, app, &traffic_history, &analytics, sections[1]);
    draw_distribution_panels(f, &analytics, sections[2]);
    for (index, area) in sections.iter().enumerate() {
        crate::ui::sections::focus_panel(f, *area, index == ui_state.graph_section as usize);
    }
}

fn draw_traffic_panels(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let narrow = area.width < 100;
    let panels = Layout::default()
        .direction(if narrow {
            Direction::Vertical
        } else {
            Direction::Horizontal
        })
        .spacing(if narrow { 1 } else { 2 })
        .constraints(if narrow {
            [Constraint::Percentage(60), Constraint::Percentage(40)]
        } else {
            [Constraint::Percentage(70), Constraint::Percentage(30)]
        })
        .split(area);
    draw_traffic_chart(f, history, panels[0]);
    draw_connection_lifecycle(f, history, panels[1]);
}

fn draw_health_panels(
    f: &mut Frame,
    app: &App,
    history: &TrafficHistory,
    analytics: &GraphAnalytics<'_>,
    area: Rect,
) {
    let (health, counters, states) = if area.width < 100 {
        let rows = Layout::vertical([Constraint::Length(4), Constraint::Min(0)])
            .spacing(1)
            .split(area);
        let top = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
            .spacing(2)
            .split(rows[0]);
        (top[0], top[1], rows[1])
    } else {
        let columns = Layout::horizontal([
            Constraint::Percentage(35),
            Constraint::Percentage(35),
            Constraint::Percentage(30),
        ])
        .spacing(2)
        .split(area);
        (columns[0], columns[1], columns[2])
    };
    draw_health_chart(f, history, health);
    draw_tcp_counters(f, app, counters);
    draw_tcp_states(f, &analytics.tcp_state_counts, states);
}

fn draw_distribution_panels(f: &mut Frame, analytics: &GraphAnalytics<'_>, area: Rect) {
    let panels = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .spacing(2)
        .split(area);
    draw_app_distribution(f, &analytics.app_distribution, panels[0]);
    draw_top_processes(f, &analytics.process_traffic, panels[1]);
}

/// Draw the RX/TX traffic waves: two stacked braille area graphs with
/// a vertical gradient (bright crest, saturated base), each header
/// showing the current rate, a trend arrow, and the 60s peak.
fn draw_traffic_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, section_title(" Traffic Over Time (60s)"));

    if !history.has_enough_data() {
        draw_placeholder(f, inner, "Waiting for traffic data...");
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
        braille_graph::WavePanelOptions::new(frac, window)
            .with_max_val(history.rx_graph_ceiling())
            .with_header_color(theme::rx()),
        theme::rx_wave,
    );
    braille_graph::wave_panel(
        f,
        halves[2],
        &tx,
        "↑ TX",
        braille_graph::WavePanelOptions::new(frac, window)
            .with_max_val(history.tx_graph_ceiling())
            .with_header_color(theme::tx()),
        theme::tx_wave,
    );
}

fn draw_connection_lifecycle(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, section_title(" Connection Lifecycle"));

    if !history.has_enough_data() {
        draw_placeholder(f, inner, "Waiting for connection data...");
        return;
    }

    if inner.height == 0 {
        return;
    }

    let (active, retained) = history.latest_connection_counts();
    let summary = Line::from(vec![
        Span::styled(
            format!("{active} active"),
            theme::bold_fg(theme::accent_wave(0.8)),
        ),
        Span::styled("  ", theme::fg(theme::muted())),
        Span::styled(format!("{retained} retained"), theme::fg(theme::muted())),
    ]);
    f.render_widget(
        Paragraph::new(summary),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let waves_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    let halves = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Length(1),
            Constraint::Percentage(50),
        ])
        .split(waves_area);
    let opened = history.get_opened_sparkline_data(usize::MAX);
    let closed = history.get_closed_sparkline_data(usize::MAX);
    draw_lifecycle_wave(
        f,
        halves[0],
        &opened,
        "OPENED",
        LifecycleWaveOptions {
            max_val: history.opened_graph_ceiling(),
            frac: history.scroll_fraction(),
            window: history.capacity(),
            wave: theme::special_wave,
        },
    );
    draw_lifecycle_wave(
        f,
        halves[2],
        &closed,
        "CLOSED",
        LifecycleWaveOptions {
            max_val: history.closed_graph_ceiling(),
            frac: history.scroll_fraction(),
            window: history.capacity(),
            wave: theme::muted_wave,
        },
    );
}

struct LifecycleWaveOptions {
    max_val: f64,
    frac: f64,
    window: usize,
    wave: fn(f64) -> Color,
}

fn draw_lifecycle_wave(
    f: &mut Frame,
    area: Rect,
    samples: &[u64],
    label: &str,
    options: LifecycleWaveOptions,
) {
    if area.height < 2 || samples.is_empty() {
        return;
    }

    let current = samples.last().copied().unwrap_or(0);
    let peak = samples.iter().copied().max().unwrap_or(0);
    let speed_ratio = (current as f64 / options.max_val.max(1.0)).clamp(0.0, 1.0);
    let left = vec![
        Span::styled(format!("{label} "), theme::bold_fg((options.wave)(0.4))),
        Span::styled(
            format_lifecycle_rate(current),
            theme::bold_fg((options.wave)(0.35 + 0.65 * speed_ratio)),
        ),
        Span::styled(
            format!(" {}", braille_graph::trend_glyph(samples)),
            theme::fg(theme::muted()),
        ),
    ];
    let right = Span::styled(
        format!("peak {}", format_lifecycle_rate(peak)),
        theme::fg(theme::muted()),
    );
    f.render_widget(
        Paragraph::new(braille_graph::spread_line(left, right, area.width)),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let graph_area = Rect::new(
        area.x,
        area.y + 1,
        area.width,
        area.height.saturating_sub(1),
    );
    let lines = braille_graph::render(
        samples,
        graph_area.width as usize,
        graph_area.height as usize,
        options.max_val.max(1.0),
        options.frac,
        options.window,
        options.wave,
    );
    f.render_widget(Paragraph::new(lines), graph_area);
}

fn format_lifecycle_rate(rate_tenths: u64) -> String {
    if rate_tenths.is_multiple_of(10) {
        format!("{}/s", rate_tenths / 10)
    } else {
        format!("{}.{}/s", rate_tenths / 10, rate_tenths % 10)
    }
}

fn draw_app_distribution(f: &mut Frame, dist: &AppProtocolDistribution, area: Rect) {
    let inner = section_header(f, area, section_title(" Application Distribution"));

    let percentages = dist.as_percentages();

    // Zero-count protocols are skipped.
    // Layout per row: "{label:6} {bar} {pct:5.1}%", i.e. 6 + 1 + bar + 1 + 6 = 14 + bar.
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

        let color = match label {
            "HTTPS" => theme::proto_https(),
            "QUIC" => theme::proto_quic(),
            "HTTP" => theme::proto_http(),
            "DNS" => theme::proto_dns(),
            "SSH" => theme::proto_ssh(),
            _ => theme::proto_other(),
        };

        let mut spans = vec![
            Span::styled(
                format!("{:<width$}", label, width = LABEL_WIDTH),
                theme::fg(color),
            ),
            Span::raw(" "),
        ];
        spans.extend(glow_bar::themed_spans(pct / 100.0, bar_width, color));
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

fn draw_top_processes(f: &mut Frame, process_traffic: &HashMap<&str, f64>, area: Rect) {
    let inner = section_header(f, area, section_title(" Top Processes"));

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
        draw_placeholder(f, inner, "No active processes");
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

fn draw_health_chart(f: &mut Frame, history: &TrafficHistory, area: Rect) {
    let inner = section_header(f, area, section_title(" Observed Network Health"));

    if !history.has_enough_data() {
        draw_placeholder(f, inner, "Waiting for health data...");
        return;
    }

    let (loss_data, rtt_data) = history.get_health_chart_data();

    let current_loss = loss_data.last().map(|(_, v)| *v).unwrap_or(0.0);
    let current_rtt = rtt_data.last().map(|(_, v)| *v);

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

    const RTT_MAX: f64 = 200.0; // 200ms max scale
    const LOSS_MAX: f64 = 10.0; // 10% max scale

    // Layout per row: "  {label:5}{bar} {value:>9}" with 1 cell of right pad.
    // Reserve 2 (lead) + 5 (label) + 1 (gap) + 9 (value) + 1 (pad) = 18.
    let bar_width = (inner.width as usize).saturating_sub(18).max(1);

    let rtt_line = if let Some(rtt) = current_rtt {
        let rtt_pct = (rtt / RTT_MAX).min(1.0);
        let color = theme::rtt_color(rtt);

        let mut spans = vec![Span::styled(
            "  RTT  ",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        spans.extend(glow_bar::themed_spans(rtt_pct, bar_width, color));
        spans.push(Span::styled(format!(" {:>6.1}ms", rtt), theme::fg(color)));
        Line::from(spans)
    } else {
        let mut spans = vec![Span::styled(
            "  RTT  ",
            Style::default().add_modifier(Modifier::BOLD),
        )];
        spans.extend(glow_bar::themed_spans(0.0, bar_width, theme::muted()));
        spans.push(Span::styled(
            format!(" {:>8}", "--"),
            theme::fg(theme::muted()),
        ));
        Line::from(spans)
    };

    // Keep a positive loss visible without rounding it up to a whole cell.
    let loss_pct = if current_loss > 0.0 {
        (current_loss / LOSS_MAX).clamp(0.125 / bar_width as f64, 1.0)
    } else {
        0.0
    };
    let loss_color = theme::tier_color(current_loss, 1.0, 5.0);

    let mut loss_spans = vec![Span::styled(
        "  Loss ",
        Style::default().add_modifier(Modifier::BOLD),
    )];
    loss_spans.extend(glow_bar::themed_spans(loss_pct, bar_width, loss_color));
    loss_spans.push(Span::styled(
        format!(" {:>6.2}%", current_loss),
        theme::fg(loss_color),
    ));
    let loss_line = Line::from(loss_spans);

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

fn draw_tcp_counters(f: &mut Frame, app: &App, area: Rect) {
    use std::sync::atomic::Ordering;

    let stats = app.get_stats();
    let retransmits = stats.total_tcp_retransmits.load(Ordering::Relaxed);
    let out_of_order = stats.total_tcp_out_of_order.load(Ordering::Relaxed);
    let fast_retransmits = stats.total_tcp_fast_retransmits.load(Ordering::Relaxed);

    let inner = section_header(f, area, section_title(" TCP Counters"));

    // Color based on counts (higher = more concerning): zero is healthy,
    // anything below the error threshold a warning.
    let retrans_color = theme::tier_color(retransmits, 1, 100);
    let ooo_color = theme::tier_color(out_of_order, 1, 50);
    let fast_color = theme::tier_color(fast_retransmits, 1, 50);

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

fn draw_tcp_states(f: &mut Frame, state_counts: &[usize; TCP_STATE_NAMES.len()], area: Rect) {
    let states: Vec<_> = TCP_STATE_NAMES
        .iter()
        .zip(state_counts)
        .filter_map(|(&name, &count)| (count > 0).then_some((name, count)))
        .collect();

    let inner = section_header(f, area, section_title(" Observed TCP States"));

    if states.is_empty() {
        draw_placeholder(f, inner, "No TCP connections");
        return;
    }

    // Layout per row: "{name:>10} {bar} {count:>4}" with 1 cell of right pad.
    // Reserve 10 (name) + 1 + 1 (count gap) + 4 (count) + 1 (right pad) = 17.
    let max_count = states.iter().map(|(_, c)| *c).max().unwrap_or(1);
    const RESERVED: usize = 17;
    let bar_width = (inner.width as usize).saturating_sub(RESERVED).max(1);

    let max_rows = inner.height as usize;
    let lines: Vec<Line> = states
        .iter()
        .take(max_rows)
        .map(|(name, count)| {
            let color = match *name {
                "ESTAB" => theme::tcp_established(),
                "SYN_SENT" | "SYN_RECV" => theme::tcp_opening(),
                "TIME_WAIT" | "FIN_WAIT1" | "FIN_WAIT2" => theme::tcp_closing(),
                "CLOSE_WAIT" | "LAST_ACK" | "CLOSING" => theme::tcp_waiting(),
                "CLOSED" => theme::tcp_closed(),
                _ => Color::Reset,
            };

            let mut spans = vec![Span::styled(format!("{:>10} ", name), theme::fg(color))];
            // Keep rare states visible with at least an eighth-cell tip.
            // A shared track width aligns counts across the state rows.
            let fraction = (*count as f64 / max_count as f64).max(0.125 / bar_width as f64);
            spans.extend(glow_bar::themed_spans(fraction, bar_width, color));
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

    #[test]
    fn lifecycle_rates_keep_low_activity_visible() {
        assert_eq!(format_lifecycle_rate(0), "0/s");
        assert_eq!(format_lifecycle_rate(2), "0.2/s");
        assert_eq!(format_lifecycle_rate(20), "2/s");
    }
}
