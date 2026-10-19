//! Host socket inventory and interface statistics.

use std::time::{Duration, SystemTime};

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Color,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Wrap},
};
use rustnet_host::{HostSocket, HostSocketState, HostTcpState};

use crate::network::dns_analytics::{
    DnsAnalyticsSnapshot, DnsHealth, DnsIssue, DnsIssueKind, DnsQuestionStats,
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, DnsSort, Effect, HandlerContext, HostView,
    format::format_rtt_compact,
    section_header, section_title, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::{
        glow_bar,
        scrollbar::{draw_scrolled_text, render_scrolled_table},
    },
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
        let content = area;
        match ctx.ui_state.host_view {
            HostView::Sockets => draw_sockets(f, content, ctx),
            HostView::Interfaces => draw_interface_stats(f, ctx.app, ctx.ui_state, content),
            HostView::Dns => draw_dns_analytics(f, content, ctx),
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        if key.code == KeyCode::Char('w') && key.modifiers == KeyModifiers::NONE {
            ctx.ui_state.host_window = ctx.ui_state.host_window.next();
            ctx.ui_state.dns_questions_scroll.reset();
            return Some(Vec::new());
        }
        if key.code == KeyCode::Char('o')
            && key.modifiers == KeyModifiers::NONE
            && ctx.ui_state.host_view == HostView::Dns
        {
            ctx.ui_state.dns_sort = ctx.ui_state.dns_sort.next();
            ctx.ui_state.dns_questions_scroll.reset();
            return Some(Vec::new());
        }
        match ctx.ui_state.host_view {
            HostView::Sockets => try_handle_pane_scroll(
                key,
                usize::from(ctx.ui_state.host_sockets_scroll.viewport_rows()),
                &mut ctx.ui_state.host_sockets_scroll,
            ),
            HostView::Interfaces => try_handle_pane_scroll(
                key,
                usize::from(ctx.ui_state.interfaces_scroll.viewport_rows()),
                &mut ctx.ui_state.interfaces_scroll,
            ),
            HostView::Dns => try_handle_pane_scroll(
                key,
                usize::from(ctx.ui_state.dns_questions_scroll.viewport_rows()),
                &mut ctx.ui_state.dns_questions_scroll,
            ),
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

fn draw_dns_analytics(f: &mut Frame, area: Rect, ctx: &ComponentContext<'_>) -> Result<()> {
    if area.height == 0 {
        return Ok(());
    }
    let snapshot = ctx
        .app
        .get_dns_analytics_for_window(ctx.ui_state.host_window);
    let summary_height = area.height.saturating_sub(4).min(6);
    let groups = dns_issue_groups(&snapshot.recent_issues);
    let evidence_rows = 3
        + snapshot.resolvers.len().min(3)
        + usize::from(snapshot.resolvers.len() > 3)
        + groups.len().clamp(1, 3);
    let evidence_height = area.height.saturating_sub(11).min(evidence_rows as u16);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(summary_height),
            Constraint::Length(evidence_height),
            Constraint::Min(0),
        ])
        .split(area);

    if chunks[0].width >= 110 {
        let summary = Layout::default()
            .direction(Direction::Horizontal)
            .spacing(2)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(chunks[0]);
        draw_dns_outcomes(
            f,
            summary[0],
            &snapshot,
            false,
            ctx.app.capture_error().is_some(),
        );
        draw_dns_latency(f, summary[1], &snapshot, &ctx.ui_state.bar_animations);
    } else {
        draw_dns_outcomes(
            f,
            chunks[0],
            &snapshot,
            true,
            ctx.app.capture_error().is_some(),
        );
    }
    draw_dns_evidence(f, chunks[1], &snapshot, ctx.app.capture_error().is_some());
    draw_dns_questions(f, chunks[2], ctx, &snapshot);
    Ok(())
}

fn dns_guidance(snapshot: &DnsAnalyticsSnapshot, capture_failed: bool) -> &'static str {
    if capture_failed {
        "Capture stopped: restore capture before judging DNS health."
    } else if snapshot.timeouts > 0 {
        "Missing replies: check resolver reachability, capture loss, and Host > Sockets."
    } else if snapshot.servfail > 0 {
        "SERVFAIL: resolver could not answer; check its upstream path and DNSSEC."
    } else if snapshot.refused > 0 {
        "REFUSED: check resolver access policy and the selected DNS server."
    } else if snapshot
        .resolvers
        .iter()
        .any(|resolver| resolver.retries > 0)
    {
        "Repeated queries: inspect pending age, resolver reachability, and packet loss."
    } else if snapshot.slow_responses > 0 {
        "Slow replies: compare resolver latency and check upstream connectivity."
    } else if snapshot.lookups == 0 && !snapshot.recent_issues.is_empty() {
        "No recent UDP DNS; retained issues below may describe an earlier outage."
    } else if snapshot.lookups == 0 {
        if cfg!(target_os = "linux") {
            "No DNS seen: try -i any; caches, NSS and encrypted DNS may emit no UDP DNS."
        } else {
            "No DNS seen: check capture scope; caches and encrypted DNS are not visible."
        }
    } else {
        "Passive UDP DNS only; NXDOMAIN is a reply, not a resolver outage."
    }
}

fn dns_issue_groups(issues: &[DnsIssue]) -> Vec<(&DnsIssue, usize)> {
    let mut groups: Vec<(&DnsIssue, usize)> = Vec::new();
    for issue in issues {
        if let Some((_, count)) = groups.iter_mut().find(|(previous, _)| {
            previous.resolver == issue.resolver && previous.kind == issue.kind
        }) {
            *count += 1;
        } else {
            groups.push((issue, 1));
        }
    }
    groups
}

fn draw_dns_evidence(
    f: &mut Frame,
    area: Rect,
    snapshot: &DnsAnalyticsSnapshot,
    capture_failed: bool,
) {
    if area.height == 0 {
        return;
    }
    let inner = section_header(
        f,
        area,
        section_title(format!(" Resolver Evidence ({})", snapshot.window_label())),
    );
    let mut lines = vec![Line::styled(
        dns_guidance(snapshot, capture_failed),
        theme::fg(theme::muted()),
    )];
    // Keep both live resolver evidence and retained failures visible on a
    // standard terminal. Explicit counts disclose rows omitted for space.
    let resolver_limit = if inner.height >= 7 { 3 } else { 2 };
    for resolver in snapshot.resolvers.iter().take(resolver_limit) {
        let (health, color) = if capture_failed {
            ("unknown", theme::warn())
        } else {
            dns_health_style(resolver.health)
        };
        let failures = resolver
            .timeouts
            .saturating_add(resolver.servfail)
            .saturating_add(resolver.refused)
            .saturating_add(resolver.other_rcodes);
        let timing = if let Some(age) = resolver.oldest_pending {
            format!("oldest {}s", age.as_secs())
        } else {
            format!(
                "{}p95 {}",
                if snapshot.approximate_latency {
                    "~"
                } else {
                    ""
                },
                resolver
                    .latency_p95
                    .map_or_else(|| "-".into(), format_rtt_compact)
            )
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", resolver.address), theme::fg(theme::text())),
            Span::styled(health, theme::fg(color)),
            label(format!(
                "  fail {}/{}  wait {}  retry {}  {}",
                failures,
                resolver.answered.saturating_add(resolver.timeouts),
                resolver.pending,
                resolver.retries,
                timing
            )),
        ]));
    }
    if snapshot.resolvers.len() > resolver_limit {
        lines.push(Line::styled(
            format!(
                "+{} more observed resolvers (problems shown first)",
                snapshot.resolvers.len() - resolver_limit
            ),
            theme::fg(theme::muted()),
        ));
    }
    let groups = dns_issue_groups(&snapshot.recent_issues);
    let available = usize::from(inner.height).saturating_sub(lines.len() + 1);
    lines.push(Line::styled(
        format!(
            "Recent issues (15m, {}/{} groups, {} retained)",
            available.min(groups.len()),
            groups.len(),
            snapshot.recent_issues.len()
        ),
        theme::fg(theme::muted()),
    ));
    if groups.is_empty() {
        lines.push(Line::styled(
            "No retained DNS issues.",
            theme::fg(theme::muted()),
        ));
    }
    let now = SystemTime::now();
    for (issue, count) in groups.into_iter().take(available) {
        let age = now.duration_since(issue.at).unwrap_or_default().as_secs();
        let age = if age < 60 {
            format!("{age}s")
        } else {
            format!("{}m", age / 60)
        };
        let color = if issue.kind == DnsIssueKind::Slow {
            theme::warn()
        } else {
            theme::err()
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{} {} x{}", issue.resolver, issue.kind.label(), count),
                theme::fg(color),
            ),
            label(format!(
                "  {age} ago  {}",
                issue.query_name.as_deref().unwrap_or("unknown question")
            )),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
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
    capture_failed: bool,
) {
    let inner = section_header(
        f,
        area,
        section_title(format!(" DNS Outcomes ({})", snapshot.window_label())),
    );
    if inner.height == 0 {
        return;
    }

    let (health, health_color) = if capture_failed {
        ("unknown (capture stopped)", theme::warn())
    } else {
        dns_health_style(snapshot.health)
    };
    let mut status = vec![
        label("Status "),
        Span::styled(health, theme::bold_fg(health_color)),
    ];
    if snapshot.details_truncated {
        status.push(Span::styled("   details limited", theme::fg(theme::warn())));
    }
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
            label(if snapshot.approximate_latency {
                "Response time  ~p50 "
            } else {
                "Response time  p50 "
            }),
            Span::styled(
                snapshot
                    .latency_p50
                    .map_or_else(|| "-".to_string(), format_rtt_compact),
                theme::fg(theme::text()),
            ),
            label(if snapshot.approximate_latency {
                "   ~p95 "
            } else {
                "   p95 "
            }),
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

fn draw_dns_latency(
    f: &mut Frame,
    area: Rect,
    snapshot: &DnsAnalyticsSnapshot,
    animation: &glow_bar::BarAnimations,
) {
    let inner = section_header(f, area, section_title(" Response Time (matched txid)"));
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
        label(if snapshot.approximate_latency {
            "~p50 "
        } else {
            "p50 "
        }),
        Span::styled(
            format_rtt_compact(snapshot.latency_p50.unwrap_or_default()),
            theme::fg(theme::text()),
        ),
        label(if snapshot.approximate_latency {
            "   ~p95 "
        } else {
            "   p95 "
        }),
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
        spans.extend(animation.spans(
            format!("host/dns/{bucket_label}"),
            fraction,
            bar_width,
            theme::accent(),
        ));
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
    snapshot: &DnsAnalyticsSnapshot,
) {
    let mut questions = snapshot.questions.clone();
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
            section_title(format!(" Question Names ({})", snapshot.window_label())),
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
    let show_full = inner.width >= 82;
    let rows = questions.iter().map(|question| {
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
    let (header, widths) = if show_full {
        (
            Row::new([
                Cell::from("Question"),
                Cell::from("Type"),
                right_header("Lookups"),
                right_header("NXDOMAIN"),
                right_header("Failures"),
                right_header(if snapshot.approximate_latency {
                    "~p95"
                } else {
                    "p95"
                }),
            ]),
            vec![
                Constraint::Min(24),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(10),
            ],
        )
    } else {
        (
            Row::new([
                Cell::from("Question"),
                right_header("Lookups"),
                right_header("NX"),
                right_header("Fail"),
            ]),
            vec![
                Constraint::Min(20),
                Constraint::Length(8),
                Constraint::Length(5),
                Constraint::Length(6),
            ],
        )
    };
    render_scrolled_table(
        f,
        inner,
        header,
        rows.collect(),
        &widths,
        &ctx.ui_state.dns_questions_scroll,
    );
}

fn draw_sockets(f: &mut Frame, area: Rect, ctx: &ComponentContext<'_>) -> Result<()> {
    let snapshot = ctx.app.get_socket_snapshot();
    let events = ctx.app.get_network_event_snapshot(ctx.ui_state.host_window);
    let event_lines = network_event_lines(&events, ctx.ui_state.host_window, area.width < 100);
    let event_height = event_lines.len() as u16 + 1;
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

    let endpoint_width = endpoints
        .iter()
        .map(|s| s.local_addr.to_string().len())
        .max()
        .unwrap_or(0)
        .max(22);
    let peer_width = endpoints
        .iter()
        .filter_map(|s| s.remote_addr)
        .map(|a| a.to_string().len())
        .max()
        .unwrap_or(0)
        .max(18);
    let process_width = endpoints
        .iter()
        .filter_map(|s| s.owner.as_ref())
        .map(|o| crate::ui::format::cell_width(&o.name))
        .max()
        .unwrap_or(0)
        .max(20);
    let service_width = endpoints
        .iter()
        .map(|s| {
            ctx.app
                .get_service_name(s.local_addr.port(), s.protocol)
                .unwrap_or("-")
                .len()
        })
        .max()
        .unwrap_or(0)
        .max(14);
    let pid_width = endpoints
        .iter()
        .filter_map(|s| s.owner.as_ref())
        .map(|o| o.pid.to_string().len())
        .max()
        .unwrap_or(0)
        .max(8);
    let required_width =
        7 + 10 + endpoint_width + peer_width + service_width + pid_width + process_width + 8;
    if area.width < 120
        || area.height < 10 + event_height
        || usize::from(area.width) < required_width
    {
        let inner = section_header(f, area, section_title("Host Socket States and Endpoints"));
        let mut lines = socket_summary_lines(&snapshot.sockets, ctx.connections);
        lines.push(Line::default());
        lines.push(Line::from(section_title("Observed network events")));
        lines.extend(event_lines);
        lines.push(Line::default());
        lines.push(Line::from(section_title(format!(
            "Listening and Bound Endpoints · {} rows",
            endpoints.len()
        ))));
        for socket in endpoints {
            let state = match socket.state {
                HostSocketState::Tcp(state) => state.to_string(),
                HostSocketState::UdpBound => "BOUND".to_string(),
            };
            lines.push(Line::from(section_title(format!(
                "{} {state}",
                socket.protocol
            ))));
            lines.push(Line::from(format!("Local: {}", socket.local_addr)));
            lines.push(Line::from(format!(
                "Peer: {}",
                socket
                    .remote_addr
                    .map_or_else(|| "-".to_string(), |a| a.to_string())
            )));
            lines.push(Line::from(format!(
                "Service: {}",
                ctx.app
                    .get_service_name(socket.local_addr.port(), socket.protocol)
                    .unwrap_or("-")
            )));
            lines.push(Line::from(socket.owner.as_ref().map_or_else(
                || "Process: -".to_string(),
                |o| format!("Process: {} (PID {})", o.name, o.pid),
            )));
            lines.push(Line::default());
        }
        if lines.last().is_some_and(|line| line.width() == 0) {
            lines.pop();
        }
        draw_scrolled_text(
            f,
            inner,
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            &ctx.ui_state.host_sockets_scroll,
        );
        return Ok(());
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .spacing(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(event_height),
            Constraint::Min(5),
        ])
        .split(area);
    draw_socket_summary(f, chunks[0], &snapshot.sockets, ctx.connections);
    let event_area = section_header(f, chunks[1], section_title(" Observed network events"));
    f.render_widget(Paragraph::new(event_lines), event_area);
    let widths = [
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Min(endpoint_width as u16),
        Constraint::Min(peer_width as u16),
        Constraint::Length(service_width as u16),
        Constraint::Length(pid_width as u16),
        Constraint::Length(process_width as u16),
    ];
    draw_endpoint_table(f, chunks[2], ctx, &endpoints, &widths);
    Ok(())
}

fn network_event_lines(
    events: &crate::network::types::NetworkEventSnapshot,
    window: crate::network::time_window::TimeWindow,
    compact: bool,
) -> Vec<Line<'static>> {
    let label = window.label_since_clear(events.since_clear);
    let total_label = if events.since_clear {
        "since clear"
    } else {
        "since startup"
    };
    let mut lines = vec![Line::from(Span::styled(
        format!("{label} / total ({total_label}) · captured packets"),
        theme::fg(theme::muted()),
    ))];
    let mut observed = events.total.observed().peekable();
    if observed.peek().is_none() {
        lines.push(Line::from("No events observed"));
        return lines;
    }
    if !compact {
        lines.push(Line::from(Span::styled(
            format!(
                "{:<42}{:>26}{:>26}",
                "", "Sent: window / total", "Received: window / total"
            ),
            theme::fg(theme::muted()),
        )));
    }
    for (kind, total) in observed {
        let selected = events.selected.get(kind);
        if compact {
            lines.push(Line::from(kind.to_string()));
            lines.push(Line::from(format!(
                "  Sent {} / {}   Received {} / {}",
                selected.sent, total.sent, selected.received, total.received
            )));
        } else {
            lines.push(Line::from(format!(
                "{:<42}{:>26}{:>26}",
                kind.as_str(),
                format!("{} / {}", selected.sent, total.sent),
                format!("{} / {}", selected.received, total.received)
            )));
        }
    }
    lines
}

fn draw_socket_summary(
    f: &mut Frame,
    area: Rect,
    sockets: &[HostSocket],
    connections: &[crate::network::types::Connection],
) {
    let inner = section_header(f, area, section_title(" Host Socket States"));
    f.render_widget(
        Paragraph::new(socket_summary_lines(sockets, connections)).wrap(Wrap { trim: false }),
        inner,
    );
}

fn socket_summary_lines(
    sockets: &[HostSocket],
    connections: &[crate::network::types::Connection],
) -> Vec<Line<'static>> {
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
    vec![state_line, rtt_line]
}

fn right_header(text: &'static str) -> Cell<'static> {
    Cell::from(Line::from(text).right_aligned())
}

fn label(text: impl Into<std::borrow::Cow<'static, str>>) -> Span<'static> {
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
    widths: &[Constraint; 7],
) {
    let inner = section_header(
        f,
        area,
        Line::from(vec![
            section_title(" Listening and Bound Endpoints"),
            Span::styled(
                format!("  {} rows", endpoints.len()),
                theme::fg(theme::muted()),
            ),
        ]),
    );
    let rows: Vec<Row> = endpoints
        .iter()
        .map(|socket| {
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
        })
        .collect();
    let header = Row::new([
        Cell::from("Proto"),
        Cell::from("State"),
        Cell::from("Local endpoint"),
        Cell::from("Peer"),
        Cell::from("Service"),
        right_header("PID"),
        Cell::from("Process"),
    ]);
    render_scrolled_table(
        f,
        inner,
        header,
        rows,
        widths,
        &ctx.ui_state.host_sockets_scroll,
    );
}
