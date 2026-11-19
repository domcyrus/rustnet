//! Expandable network health findings from the existing capture and OS counters.
use std::{net::SocketAddr, sync::atomic::Ordering::Relaxed, time::SystemTime};

use super::{HealthLevel, count_span, dns_health_status, tcp_handshake_status};
use crate::network::{
    dns_analytics::DnsIssue,
    process_activity::process_group_label,
    tcp_attempts::{AttemptCounts, AttemptOutcome},
    types::{Connection, ConnectionKey, NetworkEventKind},
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, HostView, UiState,
    section_header, section_title, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::scrollbar::draw_scrollbar,
};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::ui) enum Finding {
    Tcp,
    Events,
    Interfaces,
    Dns,
    Capture,
}

impl Finding {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "TCP handshakes",
            Self::Events => "Resets and ICMP",
            Self::Interfaces => "Interface drops",
            Self::Dns => "DNS replies",
            Self::Capture => "Capture quality",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::ui) enum HealthTarget {
    Finding(Finding),
    Destination(SocketAddr),
    Attempt {
        key: ConnectionKey,
        created: Option<SystemTime>,
        seq: u32,
        started: SystemTime,
    },
    Resolver(Option<SocketAddr>),
    DnsIssue(DnsIssue, usize),
    Interface(Option<String>),
    Event(NetworkEventKind),
    Capture(&'static str),
}

impl HealthTarget {
    pub(in crate::ui) fn finding(&self) -> Finding {
        match self {
            Self::Finding(f) => *f,
            Self::Destination(_) | Self::Attempt { .. } => Finding::Tcp,
            Self::Resolver(_) | Self::DnsIssue(..) => Finding::Dns,
            Self::Interface(_) => Finding::Interfaces,
            Self::Event(_) => Finding::Events,
            Self::Capture(_) => Finding::Capture,
        }
    }

    fn connection(&self, connections: &[Connection]) -> Option<usize> {
        let Self::Attempt {
            key,
            created: Some(created),
            ..
        } = self
        else {
            return None;
        };
        connections
            .iter()
            .position(|c| c.created_at == *created && ConnectionKey::from_connection(c) == *key)
    }

    fn link(&self, connections: &[Connection]) -> Option<&'static str> {
        match self {
            Self::Resolver(_) | Self::DnsIssue(..) => Some("Open DNS resolvers"),
            Self::Interface(_) => Some("Open interface counters"),
            Self::Attempt { .. } if self.connection(connections).is_some() => Some("Open Details"),
            _ => None,
        }
    }

    fn activate(&self, ctx: &mut HandlerContext<'_>) -> Vec<Effect> {
        let state = &mut ctx.ui_state;
        let view = match self {
            Self::Resolver(_) | Self::DnsIssue(..) => HostView::Dns,
            Self::Interface(_) => HostView::Interfaces,
            Self::Attempt { .. } => {
                if let Some(i) = self.connection(ctx.connections) {
                    state.set_selected_by_index(ctx.connections, i);
                    state.jump_to_tab(1);
                    state.return_to_finding = true;
                    if state.grouping_enabled
                        && state
                            .expanded_groups
                            .insert(process_group_label(&ctx.connections[i]).to_owned())
                    {
                        return vec![Effect::Regroup];
                    }
                }
                return Vec::new();
            }
            _ => return Vec::new(),
        };
        state.select_section(view as usize);
        state.return_to_finding = true;
        Vec::new()
    }
}

#[derive(Debug, Default)]
pub(in crate::ui) struct HealthCursor {
    pub(in crate::ui) target: Option<HealthTarget>,
    pub(in crate::ui) link: Option<&'static str>,
    sibling: usize,
    wrapped_row: Option<usize>,
    notice: Option<&'static str>,
    scrolled: bool,
}

impl HealthCursor {
    /// Keep the same observation across refreshes. If it disappears, stay at the nearest
    /// surviving sibling in that group, including its heading when the group is empty.
    fn resolve(&mut self, targets: &[(usize, HealthTarget)]) -> usize {
        let previous_target = self.target.take();
        let prev = previous_target.as_ref();
        let selected = targets
            .iter()
            .position(|(_, t)| Some(t) == prev)
            .unwrap_or_else(|| {
                let Some(prev) = prev else { return 0 };
                self.notice = match prev {
                    HealthTarget::Attempt { .. } => {
                        Some("Attempt no longer retained (5m / last 32)")
                    }
                    HealthTarget::Destination(_) => Some("Destination left affected list (5m)"),
                    _ => None,
                };
                let siblings = targets
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, t))| t.finding() == prev.finding());
                siblings.take(self.sibling + 1).last().map_or(0, |(i, _)| i)
            });
        let target = &targets[selected].1;
        self.sibling = targets[..selected]
            .iter()
            .rev()
            .take_while(|(_, t)| t.finding() == target.finding())
            .count();
        self.target = Some(target.clone());
        selected
    }

    fn select(&mut self, target: HealthTarget) {
        self.target = Some(target);
        self.wrapped_row = None;
        self.scrolled = false;
        self.notice = None;
    }
}

fn fold(state: &mut UiState, finding: Finding, expand: bool) {
    if expand {
        state.expanded_findings.insert(finding);
    } else {
        state.expanded_findings.remove(&finding);
    }
    state
        .health_cursor
        .get_mut()
        .select(HealthTarget::Finding(finding));
}

fn health_key(key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
    if key.modifiers != KeyModifiers::NONE {
        return None;
    }
    let state = &mut ctx.ui_state;
    let rows = &ctx.click_regions.health_rows;
    let cursor = state.health_cursor.get_mut();
    let selected = cursor.target.as_ref()?;
    let finding = selected.finding();
    match key.code {
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
            let i = rows.iter().position(|(t, _)| t == selected)?;
            let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
            let next = if cursor.scrolled && rows[i].1.is_empty() {
                if down {
                    rows.iter().position(|(_, r)| !r.is_empty())
                } else {
                    rows.iter().rposition(|(_, r)| !r.is_empty())
                }
            } else {
                None
            };
            let next = next.unwrap_or_else(|| {
                if down {
                    (i + 1).min(rows.len() - 1)
                } else {
                    i.saturating_sub(1)
                }
            });
            cursor.select(rows[next].0.clone());
        }
        KeyCode::Char(' ') => fold(state, finding, !state.expanded_findings.contains(&finding)),
        KeyCode::Right => {
            if matches!(selected, HealthTarget::Finding(_)) {
                fold(state, finding, true);
            }
        }
        KeyCode::Left => {
            if matches!(selected, HealthTarget::Finding(_)) {
                fold(state, finding, false);
            } else {
                cursor.select(HealthTarget::Finding(finding));
            }
        }
        KeyCode::Enter => {
            if rows.iter().any(|(t, r)| t == selected && !r.is_empty()) {
                return Some(selected.clone().activate(ctx));
            }
            cursor.wrapped_row = None;
            cursor.scrolled = false;
        }
        _ => return None,
    }
    Some(Vec::new())
}

fn network_event_lines(
    events: &crate::network::types::NetworkEventSnapshot,
    window: crate::network::time_window::TimeWindow,
    compact: bool,
    rows: &mut FindingRows,
) {
    let label = window.label_since_clear(events.since_clear);
    let total_label = if events.since_clear {
        "since clear"
    } else {
        "since startup"
    };
    rows.text(Line::from(Span::styled(
        format!("{label} / total ({total_label}) · captured packets"),
        theme::fg(theme::muted()),
    )));
    let mut observed = events.total.observed().peekable();
    if observed.peek().is_none() {
        rows.text(Line::from("No resets or ICMP errors observed"));
        return;
    }
    if !compact {
        rows.text(Line::from(Span::styled(
            format!(
                "{:<42}{:>26}{:>26}",
                "", "Sent: window / total", "Received: window / total"
            ),
            theme::fg(theme::muted()),
        )));
    }
    for (kind, total) in observed {
        let selected = events.selected.get(kind);
        let mut line = Line::from(Span::styled(
            kind.to_string(),
            if selected.sent > 0 || selected.received > 0 {
                theme::fg(theme::warn())
            } else {
                theme::fg(theme::muted())
            },
        ));
        if compact {
            rows.item(HealthTarget::Event(kind), line);
            rows.text(Line::from(format!(
                "  Sent {} / {}   Received {} / {}",
                selected.sent, total.sent, selected.received, total.received
            )));
        } else {
            line.push_span(" ".repeat(42usize.saturating_sub(line.width())));
            line.push_span(format!(
                "{:>26}{:>26}",
                format!("{} / {}", selected.sent, total.sent),
                format!("{} / {}", selected.received, total.received)
            ));
            rows.item(HealthTarget::Event(kind), line);
        }
    }
}

pub(in crate::ui) struct HealthTab;

impl Component for HealthTab {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        health_key(key, ctx).or_else(|| {
            let state = &mut ctx.ui_state;
            let scroll = &mut state.health_scroll;
            let result = try_handle_pane_scroll(key, usize::from(scroll.viewport_rows()), scroll);
            if result.is_some() {
                state.health_cursor.get_mut().scrolled = true;
            }
            result
        })
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        let point = (mouse.column, mouse.row).into();
        let regions = ctx.click_regions;
        if !regions.findings_area.contains(point) {
            return None;
        }
        let state = &mut ctx.ui_state;
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            state.quit_confirmation = false;
            state.clear_confirmation = false;
            if let Some((target, _)) = regions
                .health_rows
                .iter()
                .find(|(_, rect)| rect.contains(point))
            {
                if let HealthTarget::Finding(f) = target {
                    fold(state, *f, !state.expanded_findings.contains(f));
                } else {
                    state.health_cursor.get_mut().select(target.clone());
                    if regions.health_links.iter().any(|rect| rect.contains(point)) {
                        return Some(target.activate(ctx));
                    }
                }
            }
            return Some(Vec::new());
        }
        let result = try_handle_pane_wheel(mouse, &mut state.health_scroll);
        if result.is_some() {
            state.health_cursor.get_mut().scrolled = true;
        }
        result
    }

    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        regions: &mut ClickableRegions,
    ) -> Result<()> {
        regions.findings_area = area;
        let state = ctx.ui_state;
        let window = state.host_window;
        let tcp = ctx.app.get_tcp_attempt_snapshot();
        let events = ctx.app.get_network_event_snapshot(window);
        let (interfaces, since_clear) = ctx.app.get_interface_errors(window);
        let dns = ctx.app.get_dns_analytics_for_window(window);
        let capture_error = ctx.app.capture_error();
        let queue = ctx.stats.packets_dropped.load(Relaxed);
        let capture = ctx.stats.capture_packets_dropped.load(Relaxed);
        let iface = ctx.stats.interface_packets_dropped.load(Relaxed);
        let resets = events.selected.get(NetworkEventKind::TcpReset);
        let icmp: u64 = events
            .selected
            .observed()
            .filter(|(k, _)| *k != NetworkEventKind::TcpReset)
            .map(|(_, c)| c.sent + c.received)
            .sum();
        let drops: u64 = interfaces
            .values()
            .map(|c| c.rx_dropped + c.tx_dropped)
            .sum();
        let reported = capture.saturating_add(iface);
        let c = &tcp.total;
        let (tcp_status, tcp_level) =
            tcp_handshake_status(&tcp, capture_error.is_some() || reported > 0 || queue > 0);
        let (dns_status, dns_level) = dns_health_status(dns.health, capture_error.is_some());
        let mut tcp_summary = Line::from(Span::styled(tcp_status, theme::fg(tcp_level.color())));
        if c.completed > 0 {
            tcp_summary.push_span(format!(
                " · {}/{} reset or incomplete · {} anomalous",
                c.reset + c.no_handshake,
                c.completed,
                c.anomalous
            ));
        }
        if tcp.pending > 0 {
            tcp_summary.push_span(format!(" · {} pending", tcp.pending));
        }
        let errors: u64 = interfaces.values().map(|c| c.rx_errors + c.tx_errors).sum();
        let mut interface_summary = if interfaces.is_empty() {
            Line::from(Span::styled(
                "Waiting for interface statistics",
                theme::fg(theme::muted()),
            ))
        } else {
            Line::from(vec![
                count_span(drops, theme::warn()),
                Span::raw(" drops observed"),
            ])
        };
        if errors > 0 {
            interface_summary.extend([
                Span::raw(" · "),
                count_span(errors, theme::err()),
                Span::raw(" errors"),
            ]);
        }
        let mut dns_summary = Line::from(vec![
            Span::styled(dns_status, theme::fg(dns_level.color())),
            Span::raw(format!(" · {} replies · ", dns.answered)),
            count_span(dns.timeouts as u64, theme::err()),
            Span::raw(" timeouts"),
        ]);
        let error_replies = dns.failures.saturating_sub(dns.timeouts);
        if error_replies > 0 {
            dns_summary.extend([
                Span::raw(" · "),
                count_span(error_replies as u64, theme::err()),
                Span::raw(" error replies"),
            ]);
        }
        // Stable ties follow the familiar category order, independent of count and theme.
        let mut summaries = [
            (Finding::Tcp, tcp_summary, "5m", tcp_level),
            (
                Finding::Events,
                Line::from(vec![
                    Span::raw("RST "),
                    count_span(resets.sent, theme::warn()),
                    Span::raw(" sent / "),
                    count_span(resets.received, theme::warn()),
                    Span::raw(" received · "),
                    count_span(icmp, theme::warn()),
                    Span::raw(" ICMP"),
                ]),
                window.label_since_clear(events.since_clear),
                HealthLevel::observed(false, resets.sent > 0 || resets.received > 0 || icmp > 0),
            ),
            (
                Finding::Interfaces,
                interface_summary,
                window.label_since_clear(since_clear),
                HealthLevel::observed(errors > 0, drops > 0),
            ),
            (
                Finding::Dns,
                dns_summary,
                dns.window_label(),
                if dns.failures > 0 {
                    HealthLevel::Error
                } else {
                    dns_level
                },
            ),
            (
                Finding::Capture,
                if capture_error.is_some() {
                    Line::from(Span::styled("Capture failed", theme::fg(theme::err())))
                } else {
                    Line::from(vec![
                        count_span(reported, theme::warn()),
                        Span::raw(" reported drops · "),
                        count_span(queue, theme::warn()),
                        Span::raw(" queue drops"),
                    ])
                },
                if events.since_clear {
                    "since clear"
                } else {
                    "since startup"
                },
                HealthLevel::observed(capture_error.is_some(), reported > 0 || queue > 0),
            ),
        ];
        summaries.sort_by_key(|(_, _, _, level)| level.attention_order());
        let mut rows = FindingRows::default();
        for (finding, summary, window_label, _) in summaries {
            let name = finding.name();
            let expanded = state.expanded_findings.contains(&finding);
            let marker = if expanded { "▾" } else { "▸" };
            let mut heading = Line::from(vec![
                Span::raw(format!("{marker} {name} ")),
                Span::styled(format!("({window_label})  "), theme::fg(theme::muted())),
            ]);
            heading.extend(summary.spans);
            rows.item(HealthTarget::Finding(finding), heading);
            if !expanded {
                continue;
            }
            match finding {
                Finding::Tcp => tcp_attempt_lines(&tcp, &mut rows),
                Finding::Events => {
                    network_event_lines(&events, window, area.width < 100, &mut rows)
                }
                Finding::Dns => {
                    rows.text(Line::styled(
                        super::host::dns_guidance(&dns, capture_error.is_some()),
                        theme::fg(theme::muted()),
                    ));
                    for resolver in &dns.resolvers {
                        rows.item(
                            HealthTarget::Resolver(Some(resolver.address)),
                            super::host::resolver_line(
                                resolver,
                                capture_error.is_some(),
                                dns.approximate_latency,
                            ),
                        );
                    }
                    if dns.resolvers.is_empty() {
                        rows.item(HealthTarget::Resolver(None), "No observed resolvers");
                    }
                    rows.text(format!(
                        "Recent issues (15m, {} retained)",
                        dns.recent_issues.len()
                    ));
                    for (i, issue) in dns.recent_issues.iter().enumerate() {
                        // Identical observations can share the same timestamp and question.
                        let duplicate = dns.recent_issues[i + 1..]
                            .iter()
                            .filter(|other| *other == issue)
                            .count();
                        rows.item(
                            HealthTarget::DnsIssue(issue.clone(), duplicate),
                            super::host::dns_issue_line(issue, 1),
                        );
                    }
                    if dns.truncated {
                        rows.text(Line::styled(
                            "Incomplete DNS evidence",
                            theme::fg(theme::warn()),
                        ));
                    }
                }
                Finding::Interfaces => {
                    let mut interfaces: Vec<_> = interfaces.iter().collect();
                    interfaces.sort_unstable_by_key(|(name, _)| *name);
                    if interfaces.is_empty() {
                        rows.item(
                            HealthTarget::Interface(None),
                            "No interface samples available",
                        );
                    }
                    for (name, c) in interfaces {
                        rows.item(
                            HealthTarget::Interface(Some(name.clone())),
                            Line::from(vec![
                                Span::raw(format!("{name}  RX drops ")),
                                count_span(c.rx_dropped, theme::warn()),
                                Span::raw(" · TX drops "),
                                count_span(c.tx_dropped, theme::warn()),
                                Span::raw(" · RX errors "),
                                count_span(c.rx_errors, theme::err()),
                                Span::raw(" · TX errors "),
                                count_span(c.tx_errors, theme::err()),
                            ]),
                        );
                    }
                }
                Finding::Capture => {
                    if let Some(error) = &capture_error {
                        rows.item(
                            HealthTarget::Capture("Capture failed"),
                            Line::styled(error.clone(), theme::fg(theme::err())),
                        );
                    }
                    for (name, value) in [
                        ("Capture backend drops", capture),
                        ("Interface-reported drops", iface),
                        ("Processing queue drops", queue),
                    ] {
                        rows.item(
                            HealthTarget::Capture(name),
                            Line::from(vec![
                                Span::raw(format!("{name} ")),
                                count_span(value, theme::warn()),
                            ]),
                        );
                    }
                }
            }
        }
        rows.draw(f, area, ctx, regions);
        Ok(())
    }
}

#[derive(Default)]
struct FindingRows {
    lines: Vec<Line<'static>>,
    targets: Vec<(usize, HealthTarget)>,
}

impl FindingRows {
    fn item(&mut self, target: HealthTarget, line: impl Into<Line<'static>>) {
        self.targets.push((self.lines.len(), target));
        self.text(line);
    }
    fn text(&mut self, line: impl Into<Line<'static>>) {
        self.lines.push(line.into());
    }

    fn draw(
        mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        regions: &mut ClickableRegions,
    ) {
        let state = ctx.ui_state;
        let mut cursor = state.health_cursor.borrow_mut();
        let selected = cursor.resolve(&self.targets);
        let target = &self.targets[selected].1;
        cursor.link = target.link(ctx.connections);
        let title = if let Some(notice) = cursor.notice {
            notice.to_owned()
        } else if matches!(target, HealthTarget::Finding(_)) {
            "Findings".to_owned()
        } else {
            let following = self.targets[selected + 1..]
                .iter()
                .take_while(|(_, t)| t.finding() == target.finding())
                .count();
            let index = cursor.sibling;
            let position = format!(
                "{} · {index}/{}",
                target.finding().name(),
                index + following
            );
            if let HealthTarget::Attempt { key, .. } = target {
                format!("{position} · {}", key.remote_addr)
            } else {
                position
            }
        };
        let inner = section_header(f, area, section_title(title));
        let width = inner.width.saturating_sub(2).max(1);
        let mut positions = Vec::with_capacity(self.targets.len());
        let mut next = self.targets.into_iter().enumerate().peekable();
        let mut starts = Vec::with_capacity(self.lines.len());
        let mut top = 0usize;
        for (index, line) in self.lines.iter_mut().enumerate() {
            let item = next.next_if(|(_, (line_index, _))| *line_index == index);
            let mut label_width = 0;
            if let Some((idx, (_, target))) = &item {
                let link = target.link(ctx.connections);
                if let Some(label) = link {
                    // Keep the entire mouse link on one physical row on narrow terminals.
                    let text = if usize::from(width) >= label.len() + 6 {
                        format!("[{label}] ")
                    } else {
                        "[>] ".to_owned()
                    };
                    label_width = text.len() as u16 - 1;
                    line.spans
                        .insert(0, Span::styled(text, theme::fg(theme::accent())));
                } else if matches!(target, HealthTarget::Attempt { .. }) {
                    line.push_span(" · Details unavailable");
                }
                let marker = if *idx == selected { "▌ " } else { "  " };
                line.spans
                    .insert(0, Span::styled(marker, theme::fg(theme::accent())));
                if !matches!(target, HealthTarget::Finding(_)) {
                    line.spans.insert(0, Span::raw("  "));
                }
                if *idx == selected {
                    highlight_line(line);
                }
            } else {
                line.spans.insert(0, Span::raw("    "));
            }
            starts.push(top);
            let height = if line.width() <= usize::from(width) {
                1
            } else {
                Paragraph::new(line.clone())
                    .wrap(Wrap { trim: false })
                    .line_count(width)
            };
            if let Some((idx, (_, target))) = item {
                if idx == selected {
                    let old = cursor.wrapped_row.replace(top);
                    if !cursor.scrolled {
                        state
                            .health_scroll
                            .follow_row(top, height, usize::from(inner.height), old);
                    }
                }
                positions.push((target, top, height, label_width));
            }
            top = top.saturating_add(height);
        }
        // Only the visible logical lines go into Paragraph. Its scroll offset is u16,
        // but a large set of wrapped destinations can span more than 65,535 lines.
        let viewport = usize::from(inner.height);
        let scroll = &state.health_scroll;
        scroll.record_viewport(inner.height);
        let offset = scroll.clamp_for_render_len(top.saturating_sub(viewport));
        let first = starts.partition_point(|&y| y <= offset).saturating_sub(1);
        let end = starts
            .partition_point(|&y| y < offset + viewport)
            .max(first);
        let area = Rect {
            width: inner.width.saturating_sub(2),
            ..inner
        };
        let visible = self.lines.drain(first..end).collect::<Vec<_>>();
        f.render_widget(
            Paragraph::new(visible)
                .wrap(Wrap { trim: false })
                .scroll(((offset - starts[first]) as u16, 0)),
            area,
        );
        draw_scrollbar(f, inner, top, offset, viewport);
        for (target, top, height, label_width) in positions {
            let start = top.saturating_sub(offset).min(viewport) as u16;
            let end = (top + height).saturating_sub(offset).min(viewport) as u16;
            let rect = Rect::new(area.x, area.y + start, area.width, end - start);
            if label_width > 0 && top >= offset && !rect.is_empty() {
                regions.health_links.push(Rect::new(
                    rect.x + 4,
                    rect.y,
                    label_width.min(rect.width.saturating_sub(4)),
                    1,
                ));
            }
            regions.health_rows.push((target, rect));
        }
    }
}

fn highlight_line(line: &mut Line<'_>) {
    let selection = theme::row_highlight();
    line.style = line.style.patch(selection);
    // An explicit selection foreground in a custom theme takes precedence.
    if selection.fg.is_some() {
        for span in &mut line.spans {
            span.style = span.style.patch(selection);
        }
    }
}

fn outcome_counts(counts: &AttemptCounts, indent: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::raw(indent),
        count_span(counts.established, theme::ok()),
        Span::raw(" established, "),
        count_span(counts.reset, theme::err()),
        Span::raw(" reset, "),
        count_span(counts.no_handshake, theme::warn()),
        Span::raw(" no handshake, "),
        count_span(counts.superseded, theme::warn()),
        Span::raw(" superseded"),
    ])
}

fn tcp_attempt_lines(
    snapshot: &crate::network::tcp_attempts::TcpAttemptSnapshot,
    rows: &mut FindingRows,
) {
    let c = &snapshot.total;
    rows.text(format!(
        "{} completed, {} pending",
        c.completed, snapshot.pending
    ));
    rows.text(outcome_counts(c, ""));
    let mut destinations: Vec<_> = snapshot
        .destinations
        .iter()
        .filter(|(_, c)| c.is_affected())
        .collect();
    destinations.sort_by(|a, b| super::compare_tcp_destinations(*b, *a));
    if destinations.is_empty() {
        rows.text("No affected destinations in the last 5 min");
    } else {
        rows.text("Affected destinations · issues expire after 5 min");
    }
    for (address, c) in destinations {
        let mut issues = snapshot
            .recent_issues
            .iter()
            .filter(|issue| issue.key.remote_addr == *address)
            .peekable();
        rows.item(
            HealthTarget::Destination(*address),
            Line::from(vec![
                Span::raw(format!("{address}  ")),
                count_span(c.reset + c.no_handshake, theme::warn()),
                Span::raw(format!("/{} reset or incomplete, ", c.completed)),
                count_span(c.anomalous, theme::warn()),
                Span::raw(" anomalous, "),
                count_span(c.syn_retries, theme::warn()),
                Span::raw(" SYN retries"),
            ]),
        );
        rows.text(outcome_counts(c, "  "));
        if issues.peek().is_none() {
            rows.text(Line::from(
                "    No matching attempt in the 32 most recent issues",
            ));
        }
        for issue in issues {
            let (outcome, color) = match issue.outcome {
                AttemptOutcome::Established => ("established after anomaly", theme::warn()),
                AttemptOutcome::NoHandshake => ("no handshake observed", theme::warn()),
                AttemptOutcome::Reset => ("reset", theme::err()),
                AttemptOutcome::Superseded => ("superseded", theme::warn()),
            };
            rows.item(
                HealthTarget::Attempt {
                    key: issue.key,
                    created: issue.connection_created_at,
                    seq: issue.initial_sequence,
                    started: issue.started_at,
                },
                Line::from(vec![
                    Span::raw(format!(
                        "{}  ",
                        chrono::DateTime::<chrono::Local>::from(issue.finished_at)
                            .format("%H:%M:%S")
                    )),
                    Span::styled(outcome, theme::fg(color)),
                    Span::raw(format!(
                        "  {} · expires {}",
                        issue.key.local_addr,
                        chrono::DateTime::<chrono::Local>::from(
                            issue.finished_at + crate::network::tcp_attempts::WINDOW
                        )
                        .format("%H:%M:%S")
                    )),
                ]),
            );
            if issue.unexpected_acks
                + issue.invalid_syn_acks
                + issue.local_resets
                + issue.syn_retries
                > 0
            {
                rows.text(Line::from(format!("      SYN retries {}  unexpected ACKs {}  invalid SYN-ACKs {}  local resets {}", issue.syn_retries, issue.unexpected_acks, issue.invalid_syn_acks, issue.local_resets)));
            }
        }
    }
    if snapshot.omitted > 0 {
        rows.text(Line::styled(
            format!(
                "  Incomplete evidence: {} capacity omissions since clear",
                snapshot.omitted
            ),
            theme::fg(theme::warn()),
        ));
    }
    if c.no_handshake + c.anomalous > 0 {
        rows.text(Line::from(
            "  Missing capture packets or local cancellation can also prevent observed completion.",
        ));
    }
}

#[cfg(test)]
mod tcp_attempt_tests {
    use super::*;
    use crate::network::tcp_attempts::{AttemptCounts, TcpAttemptSnapshot};

    #[test]
    fn every_affected_destination_is_ranked_and_browsable_without_an_issue_record() {
        let mut snapshot = TcpAttemptSnapshot::default();
        for (ip, completed, failures) in [
            (1, 100, 15),
            (2, 10, 5),
            (3, 20, 10),
            (4, 100, 14),
            (5, 100, 13),
        ] {
            snapshot.destinations.insert(
                SocketAddr::from(([192, 0, 2, ip], 443)),
                AttemptCounts {
                    completed,
                    no_handshake: failures,
                    ..Default::default()
                },
            );
        }
        let mut rows = FindingRows::default();
        tcp_attempt_lines(&snapshot, &mut rows);
        let expected = [3, 2, 1, 4, 5]
            .map(|ip| HealthTarget::Destination(SocketAddr::from(([192, 0, 2, ip], 443))));
        assert_eq!(
            rows.targets.into_iter().map(|(_, t)| t).collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn selected_attempt_leaving_the_window_stays_in_its_group() {
        let heading = HealthTarget::Finding(Finding::Tcp);
        let other = HealthTarget::Finding(Finding::Dns);
        let addr = SocketAddr::from(([192, 0, 2, 1], 443));
        let destination = HealthTarget::Destination(addr);
        let attempt = |seq| HealthTarget::Attempt {
            key: ConnectionKey::new(crate::network::types::Protocol::Tcp, addr, addr),
            created: None,
            seq,
            started: SystemTime::UNIX_EPOCH,
        };
        let rows = |items: Vec<HealthTarget>| items.into_iter().enumerate().collect::<Vec<_>>();
        let original = rows(vec![
            heading.clone(),
            destination.clone(),
            attempt(1),
            attempt(2),
            other.clone(),
        ]);
        let mut cursor = HealthCursor::default();
        cursor.select(attempt(1));
        cursor.resolve(&original);
        let updated = rows(vec![
            other.clone(),
            heading.clone(),
            destination,
            attempt(2),
        ]);
        cursor.resolve(&updated);
        assert_eq!(cursor.target, Some(attempt(2)));
        assert!(cursor.notice.unwrap().contains("5m / last 32"));
        cursor.resolve(&updated);
        assert!(cursor.notice.is_some());
        cursor.resolve(&rows(vec![other.clone(), heading.clone()]));
        assert_eq!(cursor.target, Some(heading));
        assert!(cursor.notice.is_some());
        cursor.select(other);
        assert!(cursor.notice.is_none());
    }

    #[test]
    fn attempt_summary_names_evidence_and_capacity_limits() {
        let counts = AttemptCounts {
            completed: 3,
            established: 1,
            no_handshake: 2,
            anomalous: 1,
            ..Default::default()
        };
        let snapshot = TcpAttemptSnapshot {
            total: counts.clone(),
            pending: 2,
            omitted: 4,
            destinations: [("198.51.100.1:443".parse().unwrap(), counts)].into(),
            ..Default::default()
        };
        let mut rows = FindingRows::default();
        tcp_attempt_lines(&snapshot, &mut rows);
        let text = rows
            .lines
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("3 completed, 2 pending"));
        assert!(text.contains("2 no handshake"));
        assert!(text.contains("198.51.100.1:443  2/3"));
        assert!(text.contains("4 capacity omissions"));
        assert!(text.contains("Missing capture packets or local cancellation"));
    }
}
