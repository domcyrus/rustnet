//! Host socket inventory and interface statistics.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table},
};
use rustnet_host::{HostSocket, HostSocketState, HostTcpState};

use crate::network::dns_analytics::{DnsAnalyticsSnapshot, DnsHealth, DnsQuestionStats};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, DnsSort, Effect, HandlerContext, HostView,
    format::format_rtt_compact,
    section_header, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::{glow_bar, scrollbar::draw_scrollbar},
};

use super::interfaces::draw_interface_stats;

pub(in crate::ui) struct HostTab;

impl Component for HostTab {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        _click_regions: &mut ClickableRegions,
    ) -> Result<()> {
        draw_selector(f, area, ctx.ui_state.host_view);
        let content = Rect::new(
            area.x,
            area.y + 2,
            area.width,
            area.height.saturating_sub(2),
        );
        match ctx.ui_state.host_view {
            HostView::Sockets => draw_sockets(f, content, ctx),
            HostView::Interfaces => draw_interface_stats(f, ctx.app, ctx.ui_state, content),
            HostView::Dns => draw_dns_analytics(f, content, ctx),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('s'), KeyModifiers::NONE) => {
                ctx.ui_state.host_view = HostView::Sockets;
                Some(Vec::new())
            }
            (KeyCode::Char('i'), KeyModifiers::NONE) => {
                ctx.ui_state.host_view = HostView::Interfaces;
                Some(Vec::new())
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) => {
                ctx.ui_state.host_view = HostView::Dns;
                Some(Vec::new())
            }
            (KeyCode::Left, _) => {
                ctx.ui_state.host_view = ctx.ui_state.host_view.previous();
                Some(Vec::new())
            }
            (KeyCode::Right, _) => {
                ctx.ui_state.host_view = ctx.ui_state.host_view.next();
                Some(Vec::new())
            }
            (KeyCode::Char('o'), KeyModifiers::NONE) if ctx.ui_state.host_view == HostView::Dns => {
                ctx.ui_state.dns_sort = ctx.ui_state.dns_sort.next();
                ctx.ui_state.dns_questions_scroll.reset();
                Some(Vec::new())
            }
            _ => match ctx.ui_state.host_view {
                HostView::Sockets => try_handle_pane_scroll(
                    key,
                    ctx.ui_state.visible_rows,
                    &mut ctx.ui_state.host_sockets_scroll,
                ),
                HostView::Interfaces => try_handle_pane_scroll(
                    key,
                    ctx.ui_state.visible_rows,
                    &mut ctx.ui_state.interfaces_scroll,
                ),
                HostView::Dns => try_handle_pane_scroll(
                    key,
                    ctx.ui_state.dns_questions_scroll.viewport_rows() as usize,
                    &mut ctx.ui_state.dns_questions_scroll,
                ),
            },
        }
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        match ctx.ui_state.host_view {
            HostView::Sockets => {
                try_handle_pane_wheel(mouse, &mut ctx.ui_state.host_sockets_scroll)
            }
            HostView::Interfaces => {
                try_handle_pane_wheel(mouse, &mut ctx.ui_state.interfaces_scroll)
            }
            HostView::Dns => try_handle_pane_wheel(mouse, &mut ctx.ui_state.dns_questions_scroll),
        }
    }
}

fn draw_selector(f: &mut Frame, area: Rect, view: HostView) {
    let item = |label: &'static str, active| {
        if active {
            Span::styled(
                format!(" {label} "),
                theme::fg(theme::accent()).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(format!(" {label} "), theme::fg(theme::muted()))
        }
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Host  ", theme::bold_fg(theme::heading())),
            item("Sockets", view == HostView::Sockets),
            Span::styled(" · ", theme::fg(theme::border())),
            item("Interfaces", view == HostView::Interfaces),
            Span::styled(" · ", theme::fg(theme::border())),
            item("DNS", view == HostView::Dns),
        ])),
        Rect::new(area.x, area.y, area.width, area.height.min(1)),
    );
}

fn draw_dns_analytics(f: &mut Frame, area: Rect, ctx: &ComponentContext<'_>) -> Result<()> {
    if area.height == 0 {
        return Ok(());
    }
    let snapshot = ctx.app.get_dns_analytics_snapshot();
    let summary_height = area.height.saturating_sub(4).min(7);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([Constraint::Length(summary_height), Constraint::Min(0)])
        .split(area);

    if chunks[0].width >= 110 {
        let summary = Layout::default()
            .direction(Direction::Horizontal)
            .spacing(2)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(chunks[0]);
        draw_dns_outcomes(f, summary[0], &snapshot, false);
        draw_dns_latency(f, summary[1], &snapshot);
    } else {
        draw_dns_outcomes(f, chunks[0], &snapshot, true);
    }
    draw_dns_questions(f, chunks[1], ctx, &snapshot.questions);
    Ok(())
}

fn dns_health_style(health: DnsHealth) -> (&'static str, Color) {
    match health {
        DnsHealth::NotObserved => ("not observed", theme::muted()),
        DnsHealth::Checking => ("checking", theme::muted()),
        DnsHealth::Responsive => ("responsive", theme::ok()),
        DnsHealth::Degraded => ("degraded", theme::warn()),
        DnsHealth::Failing => ("failing", theme::err()),
        DnsHealth::NoReplies => ("no replies", theme::err()),
    }
}

fn draw_dns_outcomes(
    f: &mut Frame,
    area: Rect,
    snapshot: &DnsAnalyticsSnapshot,
    include_latency: bool,
) {
    let inner = section_header(
        f,
        area,
        Span::styled(
            " DNS Outcomes (60s)",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    );
    if inner.height == 0 {
        return;
    }

    let (health, health_color) = dns_health_style(snapshot.health);
    let mut status = vec![
        label("Status "),
        Span::styled(health, theme::bold_fg(health_color)),
    ];
    if snapshot.truncated {
        status.push(Span::styled("   sampled", theme::fg(theme::warn())));
    }
    f.render_widget(
        Paragraph::new(Line::from(status)),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    let lines = [
        Line::from(vec![
            label("Lookups "),
            value(snapshot.lookups),
            label("   answered "),
            value(snapshot.answered),
            label("   pending "),
            value(snapshot.pending),
            label("   timeout "),
            Span::styled(snapshot.timeouts.to_string(), theme::fg(theme::err())),
        ]),
        Line::from(vec![
            label("NOERROR "),
            Span::styled(snapshot.noerror.to_string(), theme::fg(theme::ok())),
            label("   NXDOMAIN "),
            Span::styled(snapshot.nxdomain.to_string(), theme::fg(theme::warn())),
            label("   NODATA "),
            value(snapshot.nodata),
        ]),
        Line::from(vec![
            label("SERVFAIL "),
            Span::styled(snapshot.servfail.to_string(), theme::fg(theme::err())),
            label("   REFUSED "),
            Span::styled(snapshot.refused.to_string(), theme::fg(theme::err())),
            label("   other "),
            value(snapshot.other_rcodes),
        ]),
    ];
    for (index, line) in lines.into_iter().enumerate() {
        let y = inner.y + 1 + index as u16;
        if y >= inner.bottom() {
            break;
        }
        f.render_widget(Paragraph::new(line), Rect::new(inner.x, y, inner.width, 1));
    }

    if include_latency && inner.height > 4 {
        let line = Line::from(vec![
            label("Response time  p50 "),
            Span::styled(
                snapshot
                    .latency_p50
                    .map_or_else(|| "-".to_string(), format_rtt_compact),
                theme::fg(theme::text()),
            ),
            label("   p95 "),
            Span::styled(
                snapshot
                    .latency_p95
                    .map_or_else(|| "-".to_string(), format_rtt_compact),
                theme::fg(theme::warn()),
            ),
            label("   max "),
            Span::styled(
                snapshot
                    .latency_max
                    .map_or_else(|| "-".to_string(), format_rtt_compact),
                theme::fg(theme::text()),
            ),
        ]);
        f.render_widget(
            Paragraph::new(line),
            Rect::new(inner.x, inner.y + 4, inner.width, 1),
        );
    }
}

fn draw_dns_latency(f: &mut Frame, area: Rect, snapshot: &DnsAnalyticsSnapshot) {
    let inner = section_header(
        f,
        area,
        Span::styled(
            " Response Time (matched txid)",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    );
    if inner.height == 0 {
        return;
    }
    if snapshot.latency_samples == 0 {
        f.render_widget(
            Paragraph::new("Waiting for matched responses...").style(theme::fg(theme::muted())),
            inner,
        );
        return;
    }

    let summary = Line::from(vec![
        label("p50 "),
        Span::styled(
            format_rtt_compact(snapshot.latency_p50.unwrap_or_default()),
            theme::fg(theme::text()),
        ),
        label("   p95 "),
        Span::styled(
            format_rtt_compact(snapshot.latency_p95.unwrap_or_default()),
            theme::fg(theme::warn()),
        ),
        label("   max "),
        Span::styled(
            format_rtt_compact(snapshot.latency_max.unwrap_or_default()),
            theme::fg(theme::text()),
        ),
    ]);
    f.render_widget(
        Paragraph::new(summary),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    for (index, (bucket_label, count)) in [
        ("<10ms", snapshot.latency_buckets[0]),
        ("10-50ms", snapshot.latency_buckets[1]),
        ("50-100ms", snapshot.latency_buckets[2]),
        (">=100ms", snapshot.latency_buckets[3]),
    ]
    .into_iter()
    .enumerate()
    {
        let y = inner.y + 1 + index as u16;
        if y >= inner.bottom() {
            break;
        }
        let fraction = count as f64 / snapshot.latency_samples as f64;
        let bar_width = inner.width.saturating_sub(17) as usize;
        let mut spans = vec![Span::styled(
            format!("{bucket_label:<9}"),
            theme::fg(theme::muted()),
        )];
        spans.extend(glow_bar::spans(fraction, bar_width, theme::accent_wave));
        spans.push(Span::styled(
            format!(" {:>3}%", (fraction * 100.0).round() as usize),
            theme::fg(theme::muted()),
        ));
        f.render_widget(
            Paragraph::new(Line::from(spans)),
            Rect::new(inner.x, y, inner.width, 1),
        );
    }
}

fn draw_dns_questions(
    f: &mut Frame,
    area: Rect,
    ctx: &ComponentContext<'_>,
    question_stats: &[DnsQuestionStats],
) {
    let mut questions = question_stats.to_vec();
    let compare = |a: &DnsQuestionStats, b: &DnsQuestionStats| {
        let primary = match ctx.ui_state.dns_sort {
            DnsSort::Lookups => b.lookups.cmp(&a.lookups),
            DnsSort::Nxdomain => b.nxdomain.cmp(&a.nxdomain),
            DnsSort::Failures => b.failures.cmp(&a.failures),
            DnsSort::Latency => b.latency_p95.cmp(&a.latency_p95),
        };
        primary.then_with(|| a.name.cmp(&b.name))
    };
    questions.sort_unstable_by(compare);

    let inner = section_header(
        f,
        area,
        Line::from(vec![
            Span::styled(
                " Question Names (60s)",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  sort: {}", ctx.ui_state.dns_sort.display_name()),
                theme::fg(theme::muted()),
            ),
        ]),
    );
    if inner.height == 0 {
        return;
    }
    if questions.is_empty() {
        ctx.ui_state.dns_questions_scroll.clamp_for_render(0);
        ctx.ui_state
            .dns_questions_scroll
            .record_viewport(inner.height);
        f.render_widget(
            Paragraph::new("Waiting for completed DNS lookups...").style(theme::fg(theme::muted())),
            inner,
        );
        return;
    }

    let viewport = inner.height.saturating_sub(1);
    ctx.ui_state.dns_questions_scroll.record_viewport(viewport);
    let total = u16::try_from(questions.len()).unwrap_or(u16::MAX);
    let max_scroll = total.saturating_sub(viewport);
    let scroll = ctx
        .ui_state
        .dns_questions_scroll
        .clamp_for_render(max_scroll) as usize;

    let show_full = inner.width >= 82;
    let rows = questions.iter().skip(scroll).map(|question| {
        let query_type = question
            .query_type
            .map_or_else(|| "-".to_string(), |value| value.to_string());
        let latency = question
            .latency_p95
            .map_or_else(|| "-".to_string(), format_rtt_compact);
        if show_full {
            Row::new(vec![
                Cell::from(question.name.clone()),
                Cell::from(query_type),
                Cell::from(Line::from(question.lookups.to_string()).right_aligned()),
                Cell::from(Line::from(question.nxdomain.to_string()).right_aligned()),
                Cell::from(Line::from(question.failures.to_string()).right_aligned()),
                Cell::from(Line::from(latency).right_aligned()),
            ])
        } else {
            Row::new(vec![
                Cell::from(question.name.clone()),
                Cell::from(Line::from(question.lookups.to_string()).right_aligned()),
                Cell::from(Line::from(question.nxdomain.to_string()).right_aligned()),
                Cell::from(Line::from(question.failures.to_string()).right_aligned()),
            ])
        }
    });
    let table = if show_full {
        Table::new(
            rows,
            [
                Constraint::Min(24),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(10),
            ],
        )
        .header(
            Row::new(["Question", "Type", "Lookups", "NXDOMAIN", "Failures", "p95"])
                .style(theme::fg(theme::heading())),
        )
    } else {
        Table::new(
            rows,
            [
                Constraint::Min(20),
                Constraint::Length(8),
                Constraint::Length(5),
                Constraint::Length(6),
            ],
        )
        .header(Row::new(["Question", "Lookups", "NX", "Fail"]).style(theme::fg(theme::heading())))
    };
    let table_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    f.render_widget(table, table_area);
    let rows_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    draw_scrollbar(f, rows_area, questions.len(), scroll, viewport as usize);
}

fn draw_sockets(f: &mut Frame, area: Rect, ctx: &ComponentContext<'_>) -> Result<()> {
    let snapshot = ctx.app.get_socket_snapshot();
    let mut endpoints: Vec<&HostSocket> = snapshot
        .sockets
        .iter()
        .filter(|socket| {
            matches!(
                socket.state,
                HostSocketState::Tcp(HostTcpState::Listen) | HostSocketState::UdpBound
            )
        })
        .collect();
    endpoints.sort_by_key(|socket| (socket.protocol, socket.local_addr, socket.remote_addr));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([Constraint::Length(5), Constraint::Min(5)])
        .split(area);
    draw_socket_summary(f, chunks[0], &snapshot.sockets, ctx.connections);
    draw_endpoint_table(f, chunks[1], ctx, &endpoints);
    Ok(())
}

fn draw_socket_summary(
    f: &mut Frame,
    area: Rect,
    sockets: &[HostSocket],
    connections: &[crate::network::types::Connection],
) {
    let inner = section_header(
        f,
        area,
        Span::styled(
            " Host Socket States",
            Style::default().add_modifier(Modifier::BOLD),
        ),
    );
    let tcp_total = sockets
        .iter()
        .filter(|socket| matches!(socket.state, HostSocketState::Tcp(_)))
        .count();
    let tcp_count = |wanted| {
        sockets
            .iter()
            .filter(|socket| socket.state == HostSocketState::Tcp(wanted))
            .count()
    };
    let udp_bound = sockets
        .iter()
        .filter(|socket| socket.state == HostSocketState::UdpBound)
        .count();
    let opening = tcp_count(HostTcpState::SynSent) + tcp_count(HostTcpState::SynReceived);
    let closing = tcp_count(HostTcpState::FinWait1)
        + tcp_count(HostTcpState::FinWait2)
        + tcp_count(HostTcpState::CloseWait)
        + tcp_count(HostTcpState::Closing)
        + tcp_count(HostTcpState::LastAck);
    let listen = tcp_count(HostTcpState::Listen);
    let established = tcp_count(HostTcpState::Established);
    let time_wait = tcp_count(HostTcpState::TimeWait);
    let other = tcp_total.saturating_sub(listen + established + opening + closing + time_wait);

    let state_line = Line::from(vec![
        label("TCP "),
        value(tcp_total),
        label("   LISTEN "),
        value(listen),
        label("   ESTAB "),
        value(established),
        label("   OPENING "),
        value(opening),
        label("   CLOSING "),
        value(closing),
        label("   TIME_WAIT "),
        value(time_wait),
        label("   OTHER "),
        value(other),
        label("   UDP BOUND "),
        value(udp_bound),
    ]);
    f.render_widget(
        Paragraph::new(state_line),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    if inner.height > 1 {
        let rtts: Vec<Duration> = connections
            .iter()
            .filter_map(|conn| conn.current_rtt())
            .collect();
        let rtt_line = if rtts.is_empty() {
            Line::from(vec![label("Observed RTT  "), Span::raw("no samples")])
        } else {
            let average = rtts.iter().sum::<Duration>() / u32::try_from(rtts.len()).unwrap_or(1);
            let maximum = rtts.iter().max().copied().unwrap_or_default();
            Line::from(vec![
                label("Observed RTT  "),
                Span::styled(format!("{} samples", rtts.len()), theme::fg(theme::text())),
                label("   average "),
                Span::styled(format_rtt_compact(average), theme::fg(theme::ok())),
                label("   max "),
                Span::styled(format_rtt_compact(maximum), theme::fg(theme::warn())),
            ])
        };
        f.render_widget(
            Paragraph::new(rtt_line),
            Rect::new(inner.x, inner.y + 1, inner.width, 1),
        );
    }
}

fn label(text: &'static str) -> Span<'static> {
    Span::styled(text, theme::fg(theme::muted()))
}

fn value(value: usize) -> Span<'static> {
    Span::styled(value.to_string(), theme::bold_fg(theme::text()))
}

fn draw_endpoint_table(
    f: &mut Frame,
    area: Rect,
    ctx: &ComponentContext<'_>,
    endpoints: &[&HostSocket],
) {
    let inner = section_header(
        f,
        area,
        Line::from(vec![
            Span::styled(
                " Listening and Bound Endpoints",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  {} rows", endpoints.len()),
                theme::fg(theme::muted()),
            ),
        ]),
    );
    let viewport = inner.height.saturating_sub(1) as usize;
    let max_scroll = (endpoints.len() as u16).saturating_sub(viewport as u16);
    let scroll = ctx
        .ui_state
        .host_sockets_scroll
        .clamp_for_render(max_scroll) as usize;

    let rows = endpoints.iter().skip(scroll).map(|socket| {
        let state = match socket.state {
            HostSocketState::Tcp(state) => state.to_string(),
            HostSocketState::UdpBound => "BOUND".to_string(),
        };
        let service = ctx
            .app
            .get_service_name(socket.local_addr.port(), socket.protocol)
            .unwrap_or("-");
        let (pid, process) = socket.owner.as_ref().map_or_else(
            || ("-".to_string(), "-".to_string()),
            |owner| (owner.pid.to_string(), owner.name.clone()),
        );
        Row::new(vec![
            Cell::from(socket.protocol.to_string()),
            Cell::from(state),
            Cell::from(socket.local_addr.to_string()),
            Cell::from(
                socket
                    .remote_addr
                    .map_or_else(|| "-".to_string(), |peer| peer.to_string()),
            ),
            Cell::from(service.to_string()),
            Cell::from(Line::from(pid).right_aligned()),
            Cell::from(process),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Min(22),
            Constraint::Min(18),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(20),
        ],
    )
    .header(
        Row::new([
            "Proto",
            "State",
            "Local endpoint",
            "Peer",
            "Service",
            "PID",
            "Process",
        ])
        .style(theme::fg(theme::heading())),
    );
    let table_area = Rect::new(
        inner.x,
        inner.y,
        inner.width.saturating_sub(2),
        inner.height,
    );
    f.render_widget(table, table_area);
    let rows_area = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    draw_scrollbar(f, rows_area, endpoints.len(), scroll, viewport);
}
