//! Expandable network health findings from the existing capture and OS counters.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering::Relaxed},
    time::{Duration, SystemTime},
};

use super::{HealthLevel, count_span, dns_health_status, tcp_handshake_status};
use crate::app::{App, AppStats};
use crate::network::{
    dns_analytics::{DnsAnalyticsSnapshot, DnsIssue},
    interface_stats::InterfaceErrorCounts,
    process_activity::process_group_label,
    tcp_attempts::{AttemptCounts, AttemptOutcome, TcpAttempt, TcpAttemptSnapshot},
    time_window::TimeWindow,
    types::{Connection, ConnectionKey, NetworkEventKind, NetworkEventSnapshot},
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, HostView, UiState,
    section_header, section_title, theme, try_handle_pane_wheel,
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
pub enum Finding {
    Tcp,
    Events,
    Interfaces,
    Dns,
    Capture,
}

impl Finding {
    const ALL: [Self; 5] = [
        Self::Tcp,
        Self::Events,
        Self::Interfaces,
        Self::Dns,
        Self::Capture,
    ];

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

/// Cross-tab summary of findings that currently need attention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(in crate::ui) struct HealthBadge {
    pub errors: usize,
    pub warnings: usize,
}

impl HealthBadge {
    pub(in crate::ui) fn attention_count(self) -> usize {
        self.errors + self.warnings
    }

    pub(in crate::ui) fn level(self) -> HealthLevel {
        HealthLevel::observed(self.errors > 0, self.warnings > 0)
    }

    fn record(&mut self, level: HealthLevel) {
        match level {
            HealthLevel::Error => self.errors += 1,
            HealthLevel::Warning => self.warnings += 1,
            HealthLevel::Healthy | HealthLevel::Muted => {}
        }
    }
}

/// Single snapshot of all five finding sources and their derived severities.
struct HealthInputs {
    tcp: Arc<TcpAttemptSnapshot>,
    events: NetworkEventSnapshot,
    interfaces: HashMap<String, InterfaceErrorCounts>,
    interfaces_since_clear: bool,
    dns: DnsAnalyticsSnapshot,
    capture_error: Option<String>,
    queue: u64,
    capture: u64,
    iface: u64,
    reported: u64,
    resets_sent: u64,
    resets_received: u64,
    icmp: u64,
    drops: u64,
    errors: u64,
    tcp_status: &'static str,
    tcp_level: HealthLevel,
    dns_status: &'static str,
    dns_level: HealthLevel,
    levels: [(Finding, HealthLevel); 5],
}

impl HealthInputs {
    fn collect(app: &App, stats: &AppStats, window: TimeWindow) -> Self {
        let tcp = app.get_tcp_attempt_snapshot();
        let events = app.get_network_event_snapshot(window);
        let (interfaces, interfaces_since_clear) = app.get_health_interface_errors(window);
        let dns = app.get_dns_analytics_for_window(window);
        let capture_error = app.capture_error();
        let queue = stats.packets_dropped.load(Relaxed);
        let capture = stats.capture_packets_dropped.load(Relaxed);
        let iface = stats.interface_packets_dropped.load(Relaxed);
        let reported = capture.saturating_add(iface);
        let resets = events.selected.get(NetworkEventKind::TcpReset);
        let icmp = events
            .selected
            .observed()
            .filter(|(k, _)| *k != NetworkEventKind::TcpReset)
            .map(|(_, c)| c.sent + c.received)
            .sum();
        let drops = interfaces
            .values()
            .map(|c| c.rx_dropped + c.tx_dropped)
            .sum();
        let errors = interfaces.values().map(|c| c.rx_errors + c.tx_errors).sum();
        let (tcp_status, tcp_level) =
            tcp_handshake_status(&tcp, capture_error.is_some() || reported > 0 || queue > 0);
        let (dns_status, dns_level) = dns_health_status(dns.health, capture_error.is_some());
        let levels = [
            (Finding::Tcp, tcp_level),
            (
                Finding::Events,
                HealthLevel::observed(false, resets.sent > 0 || resets.received > 0 || icmp > 0),
            ),
            (
                Finding::Interfaces,
                HealthLevel::observed(errors > 0, drops > 0),
            ),
            (
                Finding::Dns,
                if dns.failures > 0 {
                    HealthLevel::Error
                } else {
                    dns_level
                },
            ),
            (
                Finding::Capture,
                HealthLevel::observed(capture_error.is_some(), reported > 0 || queue > 0),
            ),
        ];
        Self {
            tcp,
            events,
            interfaces,
            interfaces_since_clear,
            dns,
            capture_error,
            queue,
            capture,
            iface,
            reported,
            resets_sent: resets.sent,
            resets_received: resets.received,
            icmp,
            drops,
            errors,
            tcp_status,
            tcp_level,
            dns_status,
            dns_level,
            levels,
        }
    }

    fn badge(&self) -> HealthBadge {
        let mut badge = HealthBadge::default();
        for &(_, level) in &self.levels {
            badge.record(level);
        }
        badge
    }
}

pub(in crate::ui) fn health_badge(app: &App, stats: &AppStats, window: TimeWindow) -> HealthBadge {
    HealthInputs::collect(app, stats, window).badge()
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

    fn copy_value(&self) -> Option<String> {
        match self {
            Self::Destination(addr) | Self::Resolver(Some(addr)) => Some(addr.to_string()),
            Self::Attempt { key, .. } => Some(key.remote_addr.to_string()),
            Self::DnsIssue(issue, _) => Some(
                issue
                    .query_name
                    .clone()
                    .unwrap_or_else(|| issue.resolver.to_string()),
            ),
            Self::Interface(Some(name)) => Some(name.clone()),
            _ => None,
        }
    }

    fn activate(&self, ctx: &mut HandlerContext<'_>) -> Vec<Effect> {
        let state = &mut ctx.ui_state;
        let view = match self {
            Self::Finding(f) => {
                fold(state, *f, !state.expanded_findings.contains(f));
                return Vec::new();
            }
            Self::Resolver(_) | Self::DnsIssue(..) => HostView::Dns,
            Self::Interface(_) => HostView::Interfaces,
            Self::Attempt { .. } => {
                if let Some(i) = self.connection(ctx.connections) {
                    state.set_selected_by_index(ctx.connections, i);
                    state.jump_to_tab(1);
                    state.return_to_finding = true;
                    if state.grouping_enabled {
                        let group = process_group_label(&ctx.connections[i]).to_owned();
                        state.selected_group = Some(group.clone());
                        if state.expanded_groups.insert(group) {
                            return vec![Effect::Regroup];
                        }
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
    pub(in crate::ui) copyable: bool,
    attention_findings: Vec<Finding>,
    sibling: usize,
    wrapped_row: Option<usize>,
    notice: Option<&'static str>,
    scrolled: bool,
}

impl HealthCursor {
    /// Keep the same observation across refreshes. If it disappears, stay at the nearest
    /// surviving sibling in that group, including its heading when the group is empty.
    fn resolve(&mut self, targets: &[(usize, HealthTarget)]) -> usize {
        let previous = self.target.take();
        let selected = targets
            .iter()
            .position(|(_, t)| Some(t) == previous.as_ref())
            .unwrap_or_else(|| {
                let Some(prev) = previous.as_ref() else {
                    return 0;
                };
                self.notice = match prev {
                    HealthTarget::Attempt { .. } => {
                        Some("Attempt no longer retained (5m / last 32)")
                    }
                    HealthTarget::Destination(_) => Some("Destination left affected list (5m)"),
                    _ => None,
                };
                targets
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, t))| t.finding() == prev.finding())
                    .take(self.sibling + 1)
                    .last()
                    .map_or(0, |(i, _)| i)
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

    pub(in crate::ui) fn select(&mut self, target: HealthTarget) {
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
    let state = &mut ctx.ui_state;
    let rows = &ctx.click_regions.health_rows;
    let page = usize::from(state.health_scroll.viewport_rows()).max(1);
    let cursor = state.health_cursor.get_mut();
    let selected = cursor.target.as_ref()?.clone();
    let finding = selected.finding();
    let pos = rows.iter().position(|(t, _)| t == &selected);

    match (key.code, key.modifiers) {
        (
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k'),
            KeyModifiers::NONE,
        ) => {
            let i = pos?;
            let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
            let next = (cursor.scrolled && rows[i].1.is_empty())
                .then(|| {
                    if down {
                        rows.iter().position(|(_, r)| !r.is_empty())
                    } else {
                        rows.iter().rposition(|(_, r)| !r.is_empty())
                    }
                })
                .flatten()
                .unwrap_or_else(|| {
                    if down {
                        (i + 1).min(rows.len() - 1)
                    } else {
                        i.saturating_sub(1)
                    }
                });
            cursor.select(rows[next].0.clone());
        }
        (KeyCode::PageDown, KeyModifiers::NONE) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
            if let Some(i) = pos {
                cursor.select(rows[(i + page).min(rows.len() - 1)].0.clone());
            } else {
                state.health_scroll.scroll_down(page as u16);
                cursor.scrolled = true;
            }
        }
        (KeyCode::PageUp, KeyModifiers::NONE) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
            if let Some(i) = pos {
                cursor.select(rows[i.saturating_sub(page)].0.clone());
            } else {
                state.health_scroll.scroll_up(page as u16);
                cursor.scrolled = true;
            }
        }
        (KeyCode::Char('g') | KeyCode::Home, KeyModifiers::NONE) => {
            if let Some((first, _)) = rows.first() {
                cursor.select(first.clone());
            } else {
                state.health_scroll.scroll_to_top();
                cursor.scrolled = true;
            }
        }
        (KeyCode::Char('G'), KeyModifiers::NONE | KeyModifiers::SHIFT)
        | (KeyCode::Char('g'), KeyModifiers::SHIFT)
        | (KeyCode::End, KeyModifiers::NONE) => {
            if let Some((last, _)) = rows.last() {
                cursor.select(last.clone());
            } else {
                state.health_scroll.scroll_to_bottom();
                cursor.scrolled = true;
            }
        }
        (KeyCode::Char(' '), KeyModifiers::NONE) => {
            fold(state, finding, !state.expanded_findings.contains(&finding));
        }
        (KeyCode::Right | KeyCode::Char('l'), KeyModifiers::NONE) => {
            if matches!(selected, HealthTarget::Finding(_)) {
                fold(state, finding, true);
            }
        }
        (KeyCode::Left, KeyModifiers::NONE) => {
            if matches!(selected, HealthTarget::Finding(_)) {
                fold(state, finding, false);
            } else {
                cursor.select(HealthTarget::Finding(finding));
            }
        }
        (KeyCode::Char('e'), KeyModifiers::NONE) => {
            let attention = cursor.attention_findings.clone();
            let targets: &[Finding] = if attention.is_empty() {
                &Finding::ALL
            } else {
                &attention
            };
            if targets.iter().all(|f| state.expanded_findings.contains(f)) {
                state.expanded_findings.clear();
                state
                    .health_cursor
                    .get_mut()
                    .select(HealthTarget::Finding(finding));
            } else {
                state.expanded_findings.extend(targets.iter().copied());
            }
        }
        (KeyCode::Char('c'), KeyModifiers::NONE) => {
            return Some(
                selected
                    .copy_value()
                    .map(|value| Effect::Copy {
                        label: value.clone(),
                        value,
                    })
                    .into_iter()
                    .collect(),
            );
        }
        (KeyCode::Enter, KeyModifiers::NONE) => {
            if rows.iter().any(|(t, r)| t == &selected && !r.is_empty()) {
                return Some(selected.activate(ctx));
            }
            cursor.wrapped_row = None;
            cursor.scrolled = false;
        }
        _ => return None,
    }
    Some(Vec::new())
}

fn network_event_lines(
    events: &NetworkEventSnapshot,
    window: TimeWindow,
    compact: bool,
    rows: &mut FindingRows,
) {
    let label = window.label_since_clear(events.since_clear);
    let total_label = if events.since_clear {
        "since clear"
    } else {
        "since startup"
    };
    rows.text(Line::styled(
        format!("{label} / total ({total_label}) · captured packets"),
        theme::fg(theme::muted()),
    ));
    let mut observed = events.total.observed().peekable();
    if observed.peek().is_none() {
        rows.text(Line::styled(
            "No resets or ICMP errors observed",
            theme::fg(theme::muted()),
        ));
        return;
    }
    if !compact {
        rows.text(Line::styled(
            format!(
                "{:<42}{:>26}{:>26}",
                "", "Sent: window / total", "Received: window / total"
            ),
            theme::fg(theme::muted()),
        ));
    }
    for (kind, total) in observed {
        let sel = events.selected.get(kind);
        let name_color = if sel.sent > 0 || sel.received > 0 {
            theme::warn()
        } else {
            theme::muted()
        };
        let mut line = Line::from(Span::styled(kind.to_string(), theme::fg(name_color)));
        if compact {
            rows.item(HealthTarget::Event(kind), line);
            rows.text(Line::from(vec![
                Span::raw("  Sent "),
                count_span(sel.sent, theme::warn()),
                Span::raw(format!(" / {}   Received ", total.sent)),
                count_span(sel.received, theme::warn()),
                Span::raw(format!(" / {}", total.received)),
            ]));
        } else {
            line.push_span(" ".repeat(42usize.saturating_sub(line.width())));
            for (win, tot) in [(sel.sent, total.sent), (sel.received, total.received)] {
                let text_len = format!("{win} / {tot}").len();
                line.push_span(" ".repeat(26usize.saturating_sub(text_len)));
                line.push_span(count_span(win, theme::warn()));
                line.push_span(format!(" / {tot}"));
            }
            rows.item(HealthTarget::Event(kind), line);
        }
    }
}

pub(in crate::ui) struct HealthTab;

impl Component for HealthTab {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        health_key(key, ctx)
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
            if let Some((target, _)) = regions.health_rows.iter().find(|(_, r)| r.contains(point)) {
                if let HealthTarget::Finding(f) = target {
                    fold(state, *f, !state.expanded_findings.contains(f));
                } else {
                    state.health_cursor.get_mut().select(target.clone());
                    if regions.health_links.iter().any(|r| r.contains(point)) {
                        return Some(target.activate(ctx));
                    }
                }
            }
            return Some(Vec::new());
        }
        state.health_scroll.clamp_offset();
        let before = state.health_scroll.offset();
        let result = try_handle_pane_wheel(mouse, &mut state.health_scroll);
        if result.is_some() && state.health_scroll.offset() != before {
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
        let data = HealthInputs::collect(ctx.app, ctx.stats, window);

        let mut order = data.levels;
        order.sort_by_key(|(_, level)| level.attention_order());
        state.health_cursor.borrow_mut().attention_findings = order
            .iter()
            .filter_map(|&(finding, level)| {
                matches!(level, HealthLevel::Error | HealthLevel::Warning).then_some(finding)
            })
            .collect();

        let mut rows = FindingRows {
            window_label: window.label_since_clear(data.events.since_clear),
            badge: data.badge(),
            ..Default::default()
        };
        for (finding, _) in order {
            let (summary, window_label) = finding_summary(&data, finding, window);
            let expanded = state.expanded_findings.contains(&finding);
            let marker = if expanded { "▾" } else { "▸" };
            let mut heading = Line::from(vec![
                Span::raw(format!("{marker} {} ", finding.name())),
                Span::styled(format!("({window_label})  "), theme::fg(theme::muted())),
            ]);
            heading.extend(summary.spans);
            rows.item(HealthTarget::Finding(finding), heading);
            if expanded {
                append_finding_details(&data, finding, window, area.width < 100, &mut rows);
            }
        }
        rows.draw(f, area, ctx, regions);
        Ok(())
    }
}

fn finding_summary(
    data: &HealthInputs,
    finding: Finding,
    window: TimeWindow,
) -> (Line<'static>, &'static str) {
    match finding {
        Finding::Tcp => {
            let c = &data.tcp.total;
            let mut line = Line::from(Span::styled(
                data.tcp_status,
                theme::fg(data.tcp_level.color()),
            ));
            if c.completed > 0 {
                let fail_color = if c.reset > 0 {
                    theme::err()
                } else {
                    theme::warn()
                };
                line.extend([
                    Span::raw(" · "),
                    count_span(c.reset + c.no_handshake, fail_color),
                    Span::raw(format!("/{} reset or incomplete · ", c.completed)),
                    count_span(c.anomalous, theme::warn()),
                    Span::raw(" anomalous"),
                ]);
            }
            if data.tcp.pending > 0 {
                line.push_span(format!(" · {} pending", data.tcp.pending));
            }
            (line, "5m")
        }
        Finding::Events => (
            Line::from(vec![
                Span::raw("RST "),
                count_span(data.resets_sent, theme::warn()),
                Span::raw(" sent / "),
                count_span(data.resets_received, theme::warn()),
                Span::raw(" received · "),
                count_span(data.icmp, theme::warn()),
                Span::raw(" ICMP"),
            ]),
            window.label_since_clear(data.events.since_clear),
        ),
        Finding::Interfaces => {
            let mut line = if data.interfaces.is_empty() {
                Line::from(Span::styled(
                    "Waiting for interface statistics",
                    theme::fg(theme::muted()),
                ))
            } else {
                Line::from(vec![
                    count_span(data.drops, theme::warn()),
                    Span::raw(" drops observed"),
                ])
            };
            if data.errors > 0 {
                line.extend([
                    Span::raw(" · "),
                    count_span(data.errors, theme::err()),
                    Span::raw(" errors"),
                ]);
            }
            (line, window.label_since_clear(data.interfaces_since_clear))
        }
        Finding::Dns => {
            let mut line = Line::from(vec![
                Span::styled(data.dns_status, theme::fg(data.dns_level.color())),
                Span::raw(format!(" · {} replies · ", data.dns.answered)),
                count_span(data.dns.timeouts as u64, theme::err()),
                Span::raw(" timeouts"),
            ]);
            let error_replies = data.dns.failures.saturating_sub(data.dns.timeouts);
            if error_replies > 0 {
                line.extend([
                    Span::raw(" · "),
                    count_span(error_replies as u64, theme::err()),
                    Span::raw(" error replies"),
                ]);
            }
            (line, data.dns.window_label())
        }
        Finding::Capture => (
            if data.capture_error.is_some() {
                Line::from(Span::styled("Capture failed", theme::fg(theme::err())))
            } else {
                Line::from(vec![
                    count_span(data.reported, theme::warn()),
                    Span::raw(" reported drops · "),
                    count_span(data.queue, theme::warn()),
                    Span::raw(" queue drops"),
                ])
            },
            if data.events.since_clear {
                "since clear"
            } else {
                "since startup"
            },
        ),
    }
}

fn append_finding_details(
    data: &HealthInputs,
    finding: Finding,
    window: TimeWindow,
    compact: bool,
    rows: &mut FindingRows,
) {
    match finding {
        Finding::Tcp => tcp_attempt_lines(&data.tcp, rows),
        Finding::Events => network_event_lines(&data.events, window, compact, rows),
        Finding::Dns => {
            let failed = data.capture_error.is_some();
            rows.text(Line::styled(
                super::host::dns_guidance(&data.dns, failed),
                theme::fg(theme::muted()),
            ));
            for resolver in &data.dns.resolvers {
                rows.item(
                    HealthTarget::Resolver(Some(resolver.address)),
                    super::host::resolver_line(resolver, failed, data.dns.approximate_latency),
                );
            }
            if data.dns.resolvers.is_empty() {
                rows.item(
                    HealthTarget::Resolver(None),
                    Line::styled("No observed resolvers", theme::fg(theme::muted())),
                );
            }
            rows.text(Line::styled(
                format!(
                    "Recent issues (15m, {} retained)",
                    data.dns.recent_issues.len()
                ),
                theme::fg(theme::muted()),
            ));
            for (i, issue) in data.dns.recent_issues.iter().enumerate() {
                let duplicate = data.dns.recent_issues[i + 1..]
                    .iter()
                    .filter(|other| *other == issue)
                    .count();
                rows.item(
                    HealthTarget::DnsIssue(issue.clone(), duplicate),
                    super::host::dns_issue_line(issue, None),
                );
            }
            if data.dns.truncated {
                rows.text(Line::styled(
                    "Incomplete DNS evidence",
                    theme::fg(theme::warn()),
                ));
            }
        }
        Finding::Interfaces => {
            let mut interfaces: Vec<_> = data.interfaces.iter().collect();
            interfaces.sort_unstable_by_key(|(name, _)| *name);
            if interfaces.is_empty() {
                rows.item(
                    HealthTarget::Interface(None),
                    Line::styled("No interface samples available", theme::fg(theme::muted())),
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
            if let Some(error) = &data.capture_error {
                rows.item(
                    HealthTarget::Capture("Capture failed"),
                    Line::styled(error.clone(), theme::fg(theme::err())),
                );
            }
            for (name, value) in [
                ("Capture backend drops", data.capture),
                ("Interface-reported drops", data.iface),
                ("Processing queue drops", data.queue),
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

#[derive(Default)]
struct FindingRows {
    lines: Vec<Line<'static>>,
    targets: Vec<(usize, HealthTarget)>,
    window_label: &'static str,
    badge: HealthBadge,
}

impl FindingRows {
    fn item(&mut self, target: HealthTarget, line: impl Into<Line<'static>>) {
        self.targets.push((self.lines.len(), target));
        self.text(line);
    }

    fn text(&mut self, line: impl Into<Line<'static>>) {
        self.lines.push(line.into());
    }

    fn header_line(&self, cursor: &HealthCursor, selected: usize) -> Line<'static> {
        let target = &self.targets[selected].1;
        if let Some(notice) = cursor.notice {
            return Line::from(section_title(notice));
        }
        if matches!(target, HealthTarget::Finding(_)) {
            let mut spans = vec![section_title("Findings")];
            if !self.window_label.is_empty() {
                spans.push(Span::styled(
                    format!("  window: {}", self.window_label),
                    theme::fg(theme::muted()),
                ));
            }
            for (n, singular, plural, color) in [
                (self.badge.errors, "error", "errors", theme::err()),
                (self.badge.warnings, "warning", "warnings", theme::warn()),
            ] {
                if n > 0 {
                    spans.push(Span::styled(" · ", theme::fg(theme::muted())));
                    spans.push(Span::styled(
                        format!("{n} {}", if n == 1 { singular } else { plural }),
                        theme::fg(color),
                    ));
                }
            }
            return Line::from(spans);
        }
        let following = self.targets[selected + 1..]
            .iter()
            .take_while(|(_, t)| t.finding() == target.finding())
            .count();
        let pos = format!(
            "{} · {}/{}",
            target.finding().name(),
            cursor.sibling,
            cursor.sibling + following
        );
        let title = if let HealthTarget::Attempt { key, .. } = target {
            format!("{pos} · {}", key.remote_addr)
        } else {
            pos
        };
        Line::from(section_title(title))
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
        cursor.copyable = target.copy_value().is_some();
        let inner = section_header(f, area, self.header_line(&cursor, selected));
        let width = inner.width.saturating_sub(2).max(1);
        let mut positions = Vec::with_capacity(self.targets.len());
        let mut next = self.targets.into_iter().enumerate().peekable();
        let mut starts = Vec::with_capacity(self.lines.len());
        let mut top = 0usize;
        for (index, line) in self.lines.iter_mut().enumerate() {
            let item = next.next_if(|(_, (line_index, _))| *line_index == index);
            let mut link_badge: Option<String> = None;
            if let Some((idx, (_, target))) = &item {
                let is_selected = *idx == selected;
                if let Some(label) = target.link(ctx.connections) {
                    let badge = if is_selected && usize::from(width) >= label.len() + 8 {
                        format!("[{label} ↵]")
                    } else {
                        "[↗]".to_owned()
                    };
                    let color = if is_selected {
                        theme::accent()
                    } else {
                        theme::muted()
                    };
                    line.push_span(Span::raw("  "));
                    line.push_span(Span::styled(badge.clone(), theme::fg(color)));
                    link_badge = Some(badge);
                } else if matches!(target, HealthTarget::Attempt { .. }) {
                    let hint = match (state.has_active_filter(), state.show_historic) {
                        (true, false) => " · Details unavailable (filter active / history off)",
                        (true, true) => " · Details unavailable (filtered)",
                        (false, false) => " · Details unavailable (press t for history)",
                        (false, true) => " · Details unavailable",
                    };
                    line.push_span(Span::styled(hint, theme::fg(theme::muted())));
                }
                let marker = if is_selected { "▌ " } else { "  " };
                line.spans
                    .insert(0, Span::styled(marker, theme::fg(theme::accent())));
                if !matches!(target, HealthTarget::Finding(_)) {
                    line.spans.insert(0, Span::raw("  "));
                }
                if is_selected {
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
                positions.push((target, top, height, link_badge));
            }
            top = top.saturating_add(height);
        }
        // Slice to visible logical lines so Paragraph's u16 scroll never overflows.
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
        let buf = f.buffer_mut();
        for (target, top, height, link_badge) in positions {
            let start = top.saturating_sub(offset).min(viewport) as u16;
            let end = (top + height).saturating_sub(offset).min(viewport) as u16;
            let rect = Rect::new(area.x, area.y + start, area.width, end - start);
            if let Some(badge) = link_badge
                && !rect.is_empty()
                && let Some(link_rect) = find_link_rect(buf, rect, &badge)
            {
                regions.health_links.push(link_rect);
            }
            regions.health_rows.push((target, rect));
        }
    }
}

/// Locate the rendered trailing link badge inside `rect` across wrapped rows.
fn find_link_rect(buf: &ratatui::buffer::Buffer, rect: Rect, badge: &str) -> Option<Rect> {
    let badge_chars: Vec<char> = badge.chars().collect();
    let w = Span::raw(badge).width() as u16;
    if badge_chars.is_empty() || w == 0 || rect.width < w {
        return None;
    }
    for y in (rect.y..rect.bottom()).rev() {
        for x in (rect.x..=rect.right().saturating_sub(w)).rev() {
            let mut col = x;
            if badge_chars.iter().all(|&ch| {
                if col >= rect.right() {
                    return false;
                }
                let sym = buf[(col, y)].symbol();
                let mut chars = sym.chars();
                let ok = chars.next() == Some(ch) && chars.next().is_none();
                col += Span::raw(sym).width().max(1) as u16;
                ok
            }) {
                return Some(Rect::new(x, y, w, 1));
            }
        }
    }
    None
}

fn highlight_line(line: &mut Line<'_>) {
    let selection = theme::row_highlight();
    line.style = line.style.patch(selection);
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

fn format_remaining(remaining: Duration) -> String {
    let secs = remaining.as_secs();
    if secs >= 60 {
        format!("{}m {:02}s left", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{secs}s left")
    } else {
        "<1s left".to_owned()
    }
}

fn anomaly_detail_line(issue: &TcpAttempt) -> Option<Line<'static>> {
    let mut spans = Vec::new();
    for (label, count, color) in [
        ("SYN retries", issue.syn_retries, theme::warn()),
        ("unexpected ACKs", issue.unexpected_acks, theme::warn()),
        ("invalid SYN-ACKs", issue.invalid_syn_acks, theme::err()),
        ("local resets", issue.local_resets, theme::warn()),
    ] {
        if count == 0 {
            continue;
        }
        spans.push(if spans.is_empty() {
            Span::raw("      ")
        } else {
            Span::styled(" · ", theme::fg(theme::muted()))
        });
        spans.push(Span::styled(format!("{label} "), theme::fg(theme::muted())));
        spans.push(count_span(count, color));
    }
    (!spans.is_empty()).then(|| Line::from(spans))
}

fn tcp_attempt_lines(snapshot: &TcpAttemptSnapshot, rows: &mut FindingRows) {
    let c = &snapshot.total;
    rows.text(Line::styled(
        format!("{} completed, {} pending", c.completed, snapshot.pending),
        theme::fg(theme::muted()),
    ));
    rows.text(outcome_counts(c, ""));
    let mut destinations: Vec<_> = snapshot
        .destinations
        .iter()
        .filter(|(_, c)| c.is_affected())
        .collect();
    destinations.sort_by(|a, b| super::compare_tcp_destinations(*b, *a));
    rows.text(Line::styled(
        if destinations.is_empty() {
            "No affected destinations in the last 5 min"
        } else {
            "Affected destinations · issues expire after 5 min"
        },
        theme::fg(theme::muted()),
    ));
    let mut issues_by_dest: HashMap<SocketAddr, Vec<&TcpAttempt>> = HashMap::new();
    for issue in &snapshot.recent_issues {
        issues_by_dest
            .entry(issue.key.remote_addr)
            .or_default()
            .push(issue);
    }
    let now = SystemTime::now();
    for (address, c) in destinations {
        let issues = issues_by_dest.get(address).map_or(&[][..], Vec::as_slice);
        let fail_color = if c.reset > 0 {
            theme::err()
        } else {
            theme::warn()
        };
        rows.item(
            HealthTarget::Destination(*address),
            Line::from(vec![
                Span::raw(format!("{address}  ")),
                count_span(c.reset + c.no_handshake, fail_color),
                Span::raw(format!("/{} reset or incomplete, ", c.completed)),
                count_span(c.anomalous, theme::warn()),
                Span::raw(" anomalous, "),
                count_span(c.syn_retries, theme::warn()),
                Span::raw(" SYN retries"),
            ]),
        );
        rows.text(outcome_counts(c, "  "));
        if issues.is_empty() {
            rows.text(Line::styled(
                "    No matching attempt in the 32 most recent issues",
                theme::fg(theme::muted()),
            ));
        }
        for issue in issues {
            let (outcome, color) = match issue.outcome {
                AttemptOutcome::Established => ("established after anomaly", theme::warn()),
                AttemptOutcome::NoHandshake => ("no handshake observed", theme::warn()),
                AttemptOutcome::Reset => ("reset", theme::err()),
                AttemptOutcome::Superseded => ("superseded", theme::warn()),
            };
            let expires_at = issue.finished_at + crate::network::tcp_attempts::WINDOW;
            let remaining = expires_at.duration_since(now).unwrap_or_default();
            rows.item(
                HealthTarget::Attempt {
                    key: issue.key,
                    created: issue.connection_created_at,
                    seq: issue.initial_sequence,
                    started: issue.started_at,
                },
                Line::from(vec![
                    Span::styled(
                        format!(
                            "{}  ",
                            chrono::DateTime::<chrono::Local>::from(issue.finished_at)
                                .format("%H:%M:%S")
                        ),
                        theme::fg(theme::muted()),
                    ),
                    Span::styled(outcome, theme::fg(color)),
                    Span::raw(format!("  {} ", issue.key.local_addr)),
                    Span::styled(
                        format!(
                            "· expires {} ({})",
                            chrono::DateTime::<chrono::Local>::from(expires_at).format("%H:%M:%S"),
                            format_remaining(remaining),
                        ),
                        theme::fg(theme::muted()),
                    ),
                ]),
            );
            if let Some(detail) = anomaly_detail_line(issue) {
                rows.text(detail);
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
        rows.text(Line::styled(
            "  Missing capture packets or local cancellation can also prevent observed completion.",
            theme::fg(theme::muted()),
        ));
    }
}

#[cfg(test)]
mod tcp_attempt_tests {
    use super::*;

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

    #[test]
    fn anomaly_detail_line_omits_zero_counters() {
        let addr: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let issue = TcpAttempt {
            key: ConnectionKey::new(crate::network::types::Protocol::Tcp, addr, addr),
            connection_created_at: None,
            started_at: SystemTime::UNIX_EPOCH,
            finished_at: SystemTime::UNIX_EPOCH,
            initial_sequence: 1,
            expected_acknowledgment: 2,
            last_unexpected_acknowledgment: Some(99),
            outcome: AttemptOutcome::NoHandshake,
            syn_retries: 2,
            unexpected_acks: 1,
            invalid_syn_acks: 0,
            local_resets: 0,
        };
        let text = anomaly_detail_line(&issue).unwrap().to_string();
        assert!(text.contains("SYN retries 2"));
        assert!(text.contains("unexpected ACKs 1"));
        assert!(!text.contains("invalid SYN-ACKs"));
        assert!(!text.contains("local resets"));
    }
}
