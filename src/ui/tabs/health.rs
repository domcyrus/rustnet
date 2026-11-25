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
    findings::{
        ConnectionRef, FindingEntry, FindingId, FindingSeverity, evaluate_extended_findings,
    },
    interface_stats::InterfaceErrorCounts,
    process_activity::process_group_label,
    tcp_attempts::{AttemptCounts, AttemptOutcome, TcpAttempt, TcpAttemptSnapshot},
    time_window::TimeWindow,
    types::{Connection, ConnectionKey, NetworkEventKind, NetworkEventSnapshot},
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, HostView, UiState,
    section_header, section_title, theme, try_handle_pane_wheel,
    widgets::{badge::pill, scrollbar::draw_scrollbar},
};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use log::info;
use ratatui::{
    Frame,
    layout::Rect,
    style::Color,
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
    Extended(FindingId),
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
            Self::Extended(id) => id.title(),
        }
    }
}

fn severity_to_health_level(severity: FindingSeverity) -> HealthLevel {
    match severity {
        FindingSeverity::Error => HealthLevel::Error,
        FindingSeverity::Warning => HealthLevel::Warning,
        FindingSeverity::Healthy => HealthLevel::Healthy,
        FindingSeverity::Muted => HealthLevel::Muted,
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

/// Single snapshot of all finding sources and their derived severities.
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
    dns_status: &'static str,
    dns_level: HealthLevel,
    extended: Vec<FindingEntry>,
    levels: Vec<(Finding, HealthLevel)>,
}

impl HealthInputs {
    fn collect(
        app: &App,
        stats: &AppStats,
        connections: &[Connection],
        window: TimeWindow,
    ) -> Self {
        let tcp = app.get_tcp_attempt_snapshot();
        let events = app.get_network_event_snapshot(window);
        let (interfaces, interfaces_since_clear) = app.get_health_interface_errors(window);
        let dns = app.get_dns_analytics_for_window(window);
        let neighbor_changes = app.recent_neighbor_changes();
        let extended = evaluate_extended_findings(connections, &dns, &neighbor_changes);
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
        let mut levels = vec![
            (Finding::Tcp, tcp_level),
            (
                Finding::Events,
                HealthLevel::observed(false, resets.sent > 0 || resets.received > 0 || icmp > 0),
            ),
            (
                Finding::Interfaces,
                if errors > 0 {
                    HealthLevel::Error
                } else if drops > 0 {
                    HealthLevel::Warning
                } else if interfaces.is_empty() {
                    HealthLevel::Muted
                } else {
                    HealthLevel::Healthy
                },
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
                if capture_error.is_some() {
                    HealthLevel::Error
                } else if reported > 0 || queue > 0 {
                    HealthLevel::Warning
                } else {
                    HealthLevel::Healthy
                },
            ),
        ];
        for entry in &extended {
            levels.push((
                Finding::Extended(entry.id),
                severity_to_health_level(entry.severity),
            ));
        }
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
            dns_status,
            dns_level,
            extended,
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

    fn extended_entry(&self, id: FindingId) -> Option<&FindingEntry> {
        self.extended.iter().find(|entry| entry.id == id)
    }
}

pub(in crate::ui) fn health_badge(
    app: &App,
    stats: &AppStats,
    connections: &[Connection],
    window: TimeWindow,
) -> HealthBadge {
    HealthInputs::collect(app, stats, connections, window).badge()
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
    Observation {
        finding: FindingId,
        index: usize,
        subject: String,
        remote_addr: Option<SocketAddr>,
        connection: Option<ConnectionRef>,
    },
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
            Self::Observation { finding, .. } => Finding::Extended(*finding),
        }
    }

    fn connection(&self, connections: &[Connection]) -> Option<usize> {
        let (key, created) = match self {
            Self::Attempt {
                key,
                created: Some(created),
                ..
            } => (*key, *created),
            Self::Observation {
                connection: Some(conn_ref),
                ..
            } => (conn_ref.key, conn_ref.created_at),
            _ => return None,
        };
        connections
            .iter()
            .position(|c| c.created_at == created && ConnectionKey::from_connection(c) == key)
    }

    fn link(&self, connections: &[Connection]) -> Option<&'static str> {
        match self {
            Self::Resolver(_) | Self::DnsIssue(..) => Some("Open DNS resolvers"),
            Self::Interface(_) => Some("Open interface counters"),
            Self::Attempt { .. } | Self::Observation { .. }
                if self.connection(connections).is_some() =>
            {
                Some("Open Details")
            }
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
            Self::Observation {
                remote_addr,
                subject,
                ..
            } => Some(
                remote_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| subject.clone()),
            ),
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
            Self::Attempt { .. } | Self::Observation { .. } => {
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
    if matches!(
        (key.code, key.modifiers),
        (KeyCode::Char('t'), KeyModifiers::NONE)
    ) {
        state.show_historic = !state.show_historic;
        state.scroll_offset = 0;
        state.grouped_scroll_offset = 0;
        ctx.app.toggle_show_historic();
        info!(
            "Historic connections: {}",
            if state.show_historic {
                "showing"
            } else {
                "hidden"
            }
        );
        return Some(vec![Effect::RefreshData]);
    }
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
    let observed: Vec<_> = events.total.observed().collect();
    if observed.is_empty() {
        rows.body(Line::styled(
            format!("{label} / total ({total_label}) · captured packets"),
            theme::fg(theme::muted()),
        ));
        rows.footer(Line::styled(
            "No resets or ICMP errors observed",
            theme::fg(theme::muted()),
        ));
        return;
    }
    if compact {
        rows.body(Line::styled(
            format!("{label} / total ({total_label}) · captured packets"),
            theme::fg(theme::muted()),
        ));
    } else {
        const NAME_COL: usize = 36;
        const COUNT_COL: usize = 20;
        let header_name = format!("Event ({label} / {total_label})");
        rows.body(Line::styled(
            format!(
                "{:<NAME_COL$}{:>COUNT_COL$}{:>COUNT_COL$}",
                header_name,
                format!("Sent ({label} / total)"),
                format!("Recv ({label} / total)"),
            ),
            theme::fg(theme::muted()),
        ));
        rows.body(Line::styled(
            "─".repeat(NAME_COL + COUNT_COL * 2),
            theme::fg(theme::faint()),
        ));
    }
    let last_idx = observed.len().saturating_sub(1);
    for (idx, (kind, total)) in observed.into_iter().enumerate() {
        let is_last = idx == last_idx;
        let sel = events.selected.get(kind);
        let name_color = if sel.sent > 0 || sel.received > 0 {
            theme::warn()
        } else {
            theme::muted()
        };
        let mut line = Line::from(Span::styled(kind.to_string(), theme::fg(name_color)));
        if compact {
            rows.child(HealthTarget::Event(kind), is_last, line);
            rows.child_detail(
                is_last,
                Line::from(vec![
                    Span::styled("Sent ", theme::fg(theme::muted())),
                    count_span(sel.sent, theme::warn()),
                    Span::styled(
                        format!(" / {}   Received ", total.sent),
                        theme::fg(theme::muted()),
                    ),
                    count_span(sel.received, theme::warn()),
                    Span::styled(format!(" / {}", total.received), theme::fg(theme::muted())),
                ]),
            );
        } else {
            const NAME_COL: usize = 36;
            const COUNT_COL: usize = 20;
            line.push_span(" ".repeat(NAME_COL.saturating_sub(line.width())));
            for (win, tot) in [(sel.sent, total.sent), (sel.received, total.received)] {
                let text = format!("{win} / {tot}");
                line.push_span(" ".repeat(COUNT_COL.saturating_sub(text.len())));
                if win == 0 && tot == 0 {
                    line.push_span(Span::styled(text, theme::fg(theme::faint())));
                } else {
                    line.push_span(count_span(win, theme::warn()));
                    line.push_span(Span::styled(format!(" / {tot}"), theme::fg(theme::muted())));
                }
            }
            rows.child(HealthTarget::Event(kind), is_last, line);
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
        let data = HealthInputs::collect(ctx.app, ctx.stats, ctx.connections, window);

        let mut order = data.levels.clone();
        order.sort_by_key(|(_, level)| level.attention_order());
        state.health_cursor.borrow_mut().attention_findings = order
            .iter()
            .filter_map(|&(finding, level)| {
                matches!(level, HealthLevel::Error | HealthLevel::Warning).then_some(finding)
            })
            .collect();

        let compact = area.width < 100;
        let content_width = usize::from(area.width.saturating_sub(2)).max(1);
        let mut rows = FindingRows {
            window_label: window.label_since_clear(data.events.since_clear),
            badge: data.badge(),
            ..Default::default()
        };
        let last_finding = order.len().saturating_sub(1);
        for (idx, (finding, severity)) in order.into_iter().enumerate() {
            let expanded = state.expanded_findings.contains(&finding);
            let heading = finding_heading(
                &data,
                finding,
                severity,
                window,
                expanded,
                compact,
                content_width,
            );
            rows.heading(HealthTarget::Finding(finding), heading);
            if expanded {
                append_finding_details(&data, finding, window, compact, &mut rows);
                if idx < last_finding {
                    rows.spacer();
                }
            }
        }
        rows.draw(f, area, ctx, regions);
        Ok(())
    }
}

fn severity_icon(level: HealthLevel) -> Span<'static> {
    let glyph = match level {
        HealthLevel::Error => "✕ ",
        HealthLevel::Warning => "▲ ",
        HealthLevel::Healthy => "● ",
        HealthLevel::Muted => "○ ",
    };
    Span::styled(glyph, theme::fg(level.color()))
}

fn finding_heading(
    data: &HealthInputs,
    finding: Finding,
    severity: HealthLevel,
    window: TimeWindow,
    expanded: bool,
    compact: bool,
    content_width: usize,
) -> Line<'static> {
    const NAME_COL: usize = 17;
    const STATUS_COL: usize = 14;

    let (status_text, status_level, summary, window_label) =
        finding_summary(data, finding, severity, window);
    let marker = if expanded { "▾" } else { "▸" };
    let align_cols = content_width >= 70;
    let name_text = if align_cols {
        format!("{:<NAME_COL$}", finding.name())
    } else {
        format!("{}  ", finding.name())
    };
    let mut heading = Line::from(vec![
        Span::styled(format!("{marker} "), theme::fg(theme::muted())),
        Span::styled(name_text, theme::bold_fg(theme::heading())),
        severity_icon(severity),
    ]);
    let status_spans = match status_level {
        HealthLevel::Error | HealthLevel::Warning => pill(status_text, status_level.color()),
        HealthLevel::Healthy | HealthLevel::Muted => {
            vec![Span::styled(status_text, theme::fg(status_level.color()))]
        }
    };
    let status_width: usize = status_spans.iter().map(Span::width).sum();
    heading.extend(status_spans);

    if !summary.spans.is_empty() {
        let gap = if align_cols {
            STATUS_COL.saturating_sub(status_width).max(2)
        } else {
            2
        };
        heading.push_span(Span::raw(" ".repeat(gap)));
        heading.extend(summary.spans);
    }

    let win_text = format!("({window_label})");
    // Account for the 2-cell selection gutter added during draw.
    let used = 2 + heading.width();
    if !compact && used + 2 + win_text.len() <= content_width {
        heading.push_span(Span::raw(" ".repeat(content_width - used - win_text.len())));
    } else {
        heading.push_span(Span::raw("  "));
    }
    heading.push_span(Span::styled(win_text, theme::fg(theme::muted())));
    heading
}

fn finding_summary(
    data: &HealthInputs,
    finding: Finding,
    severity: HealthLevel,
    window: TimeWindow,
) -> (&'static str, HealthLevel, Line<'static>, &'static str) {
    match finding {
        Finding::Tcp => {
            let c = &data.tcp.total;
            let mut spans = Vec::new();
            if c.completed > 0 {
                let fail_color = if c.reset > 0 {
                    theme::err()
                } else {
                    theme::warn()
                };
                spans.push(count_span(c.reset + c.no_handshake, fail_color));
                spans.push(Span::styled(
                    format!("/{} reset or incomplete", c.completed),
                    theme::fg(theme::muted()),
                ));
                if c.anomalous > 0 {
                    spans.push(Span::styled(" · ", theme::fg(theme::faint())));
                    spans.push(count_span(c.anomalous, theme::warn()));
                    spans.push(Span::styled(" anomalous", theme::fg(theme::muted())));
                }
            }
            if data.tcp.pending > 0 {
                if !spans.is_empty() {
                    spans.push(Span::styled(" · ", theme::fg(theme::faint())));
                }
                spans.push(Span::raw(format!("{} ", data.tcp.pending)));
                spans.push(Span::styled("pending", theme::fg(theme::muted())));
            }
            (data.tcp_status, severity, Line::from(spans), "5m")
        }
        Finding::Events => {
            let status = if severity == HealthLevel::Warning {
                "observed"
            } else {
                "quiet"
            };
            (
                status,
                severity,
                Line::from(vec![
                    Span::styled("RST ", theme::fg(theme::muted())),
                    count_span(data.resets_sent, theme::warn()),
                    Span::styled(" sent / ", theme::fg(theme::muted())),
                    count_span(data.resets_received, theme::warn()),
                    Span::styled(" recv · ", theme::fg(theme::muted())),
                    count_span(data.icmp, theme::warn()),
                    Span::styled(" ICMP", theme::fg(theme::muted())),
                ]),
                window.label_since_clear(data.events.since_clear),
            )
        }
        Finding::Interfaces => {
            let (status, line) = if data.interfaces.is_empty() {
                (
                    "waiting",
                    Line::from(Span::styled(
                        "Waiting for interface statistics",
                        theme::fg(theme::muted()),
                    )),
                )
            } else {
                let status = match severity {
                    HealthLevel::Error => "errors",
                    HealthLevel::Warning => "drops",
                    _ => "clear",
                };
                let mut line = Line::from(vec![
                    count_span(data.drops, theme::warn()),
                    Span::styled(" drops observed", theme::fg(theme::muted())),
                ]);
                if data.errors > 0 {
                    line.extend([
                        Span::styled(" · ", theme::fg(theme::faint())),
                        count_span(data.errors, theme::err()),
                        Span::styled(" errors", theme::fg(theme::muted())),
                    ]);
                }
                (status, line)
            };
            (
                status,
                severity,
                line,
                window.label_since_clear(data.interfaces_since_clear),
            )
        }
        Finding::Dns => {
            let mut line = Line::from(vec![
                Span::raw(format!("{} ", data.dns.answered)),
                Span::styled("replies · ", theme::fg(theme::muted())),
                count_span(data.dns.timeouts as u64, theme::err()),
                Span::styled(" timeouts", theme::fg(theme::muted())),
            ]);
            let error_replies = data.dns.failures.saturating_sub(data.dns.timeouts);
            if error_replies > 0 {
                line.extend([
                    Span::styled(" · ", theme::fg(theme::faint())),
                    count_span(error_replies as u64, theme::err()),
                    Span::styled(" error replies", theme::fg(theme::muted())),
                ]);
            }
            (
                data.dns_status,
                data.dns_level,
                line,
                data.dns.window_label(),
            )
        }
        Finding::Capture => {
            let (status, line) = if data.capture_error.is_some() {
                ("Capture failed", Line::default())
            } else {
                let status = if severity == HealthLevel::Warning {
                    "drops"
                } else {
                    "healthy"
                };
                (
                    status,
                    Line::from(vec![
                        count_span(data.reported, theme::warn()),
                        Span::styled(" reported drops · ", theme::fg(theme::muted())),
                        count_span(data.queue, theme::warn()),
                        Span::styled(" queue drops", theme::fg(theme::muted())),
                    ]),
                )
            };
            (
                status,
                severity,
                line,
                if data.events.since_clear {
                    "since clear"
                } else {
                    "since startup"
                },
            )
        }
        Finding::Extended(id) => {
            if let Some(entry) = data.extended_entry(id) {
                (
                    entry.severity.as_str(),
                    severity,
                    Line::styled(entry.summary.clone(), theme::fg(theme::muted())),
                    entry.window_label,
                )
            } else {
                ("quiet", HealthLevel::Muted, Line::default(), "active")
            }
        }
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
        Finding::Tcp => tcp_attempt_lines(&data.tcp, compact, rows),
        Finding::Events => network_event_lines(&data.events, window, compact, rows),
        Finding::Dns => {
            let failed = data.capture_error.is_some();
            rows.body(Line::styled(
                super::host::dns_guidance(&data.dns, failed),
                theme::fg(theme::muted()),
            ));
            for resolver in &data.dns.resolvers {
                rows.child(
                    HealthTarget::Resolver(Some(resolver.address)),
                    false,
                    super::host::resolver_line(resolver, failed, data.dns.approximate_latency),
                );
            }
            if data.dns.resolvers.is_empty() {
                rows.child(
                    HealthTarget::Resolver(None),
                    false,
                    Line::styled("No observed resolvers", theme::fg(theme::muted())),
                );
            }
            let issues_heading = format!(
                "Recent issues (15m, {} retained)",
                data.dns.recent_issues.len()
            );
            if data.dns.recent_issues.is_empty() && !data.dns.truncated {
                rows.footer(Line::styled(issues_heading, theme::fg(theme::muted())));
            } else {
                rows.body(Line::styled(issues_heading, theme::fg(theme::muted())));
                let last_issue = data.dns.recent_issues.len().saturating_sub(1);
                let outer_rail = data.dns.truncated;
                for (i, issue) in data.dns.recent_issues.iter().enumerate() {
                    let duplicate = data.dns.recent_issues[i + 1..]
                        .iter()
                        .filter(|other| *other == issue)
                        .count();
                    rows.grand_child(
                        HealthTarget::DnsIssue(issue.clone(), duplicate),
                        outer_rail,
                        i == last_issue,
                        super::host::dns_issue_line(issue, None),
                    );
                }
                if data.dns.truncated {
                    rows.footer(Line::styled(
                        "Incomplete DNS evidence",
                        theme::fg(theme::warn()),
                    ));
                }
            }
        }
        Finding::Interfaces => {
            let mut interfaces: Vec<_> = data.interfaces.iter().collect();
            interfaces.sort_unstable_by_key(|(name, _)| *name);
            if interfaces.is_empty() {
                rows.child(
                    HealthTarget::Interface(None),
                    true,
                    Line::styled("No interface samples available", theme::fg(theme::muted())),
                );
                return;
            }
            if !compact {
                const NAME_COL: usize = 16;
                const NUM_COL: usize = 11;
                rows.body(Line::styled(
                    format!(
                        "{:<NAME_COL$}{:>NUM_COL$}{:>NUM_COL$}{:>NUM_COL$}{:>NUM_COL$}",
                        "Interface", "RX drops", "TX drops", "RX errors", "TX errors"
                    ),
                    theme::fg(theme::muted()),
                ));
                rows.body(Line::styled(
                    "─".repeat(NAME_COL + NUM_COL * 4),
                    theme::fg(theme::faint()),
                ));
            }
            let last_idx = interfaces.len().saturating_sub(1);
            for (idx, (name, c)) in interfaces.into_iter().enumerate() {
                let is_last = idx == last_idx;
                let line = if compact {
                    Line::from(vec![
                        Span::styled(name.clone(), theme::bold_fg(theme::heading())),
                        Span::styled("  RX drops ", theme::fg(theme::muted())),
                        count_span(c.rx_dropped, theme::warn()),
                        Span::styled(" · TX drops ", theme::fg(theme::muted())),
                        count_span(c.tx_dropped, theme::warn()),
                        Span::styled(" · RX err ", theme::fg(theme::muted())),
                        count_span(c.rx_errors, theme::err()),
                        Span::styled(" · TX err ", theme::fg(theme::muted())),
                        count_span(c.tx_errors, theme::err()),
                    ])
                } else {
                    const NAME_COL: usize = 16;
                    const NUM_COL: usize = 11;
                    let mut spans = vec![Span::styled(
                        format!("{:<NAME_COL$}", name),
                        theme::bold_fg(theme::heading()),
                    )];
                    for (val, color) in [
                        (c.rx_dropped, theme::warn()),
                        (c.tx_dropped, theme::warn()),
                        (c.rx_errors, theme::err()),
                        (c.tx_errors, theme::err()),
                    ] {
                        let text = val.to_string();
                        spans.push(Span::raw(" ".repeat(NUM_COL.saturating_sub(text.len()))));
                        if val == 0 {
                            spans.push(Span::styled(text, theme::fg(theme::faint())));
                        } else {
                            spans.push(Span::styled(text, theme::fg(color)));
                        }
                    }
                    Line::from(spans)
                };
                rows.child(HealthTarget::Interface(Some(name.clone())), is_last, line);
            }
        }
        Finding::Capture => {
            if let Some(error) = &data.capture_error {
                rows.child(
                    HealthTarget::Capture("Capture failed"),
                    false,
                    Line::styled(error.clone(), theme::fg(theme::err())),
                );
            }
            let metrics = [
                ("Capture backend drops", data.capture),
                ("Interface-reported drops", data.iface),
                ("Processing queue drops", data.queue),
            ];
            let last_idx = metrics.len().saturating_sub(1);
            for (idx, (name, value)) in metrics.into_iter().enumerate() {
                rows.child(
                    HealthTarget::Capture(name),
                    idx == last_idx,
                    Line::from(vec![
                        Span::styled(format!("{name:<26}"), theme::fg(theme::muted())),
                        if value == 0 {
                            Span::styled("0", theme::fg(theme::faint()))
                        } else {
                            count_span(value, theme::warn())
                        },
                    ]),
                );
            }
        }
        Finding::Extended(id) => {
            let Some(entry) = data.extended_entry(id) else {
                rows.footer(Line::styled(
                    "No active observations",
                    theme::fg(theme::muted()),
                ));
                return;
            };
            rows.body(Line::styled(entry.id.hint(), theme::fg(theme::muted())));
            for (index, obs) in entry.observations.iter().enumerate() {
                let color = severity_to_health_level(obs.severity).color();
                let mut spans = vec![
                    Span::styled(obs.subject.clone(), theme::fg(color)),
                    Span::raw(format!("  {}", obs.detail)),
                ];
                if let Some(proc_name) = &obs.process_name {
                    let proc_label = match obs.pid {
                        Some(pid) => format!(" · {proc_name} ({pid})"),
                        None => format!(" · {proc_name}"),
                    };
                    spans.push(Span::styled(proc_label, theme::fg(theme::muted())));
                }
                rows.child(
                    HealthTarget::Observation {
                        finding: id,
                        index,
                        subject: obs.subject.clone(),
                        remote_addr: obs.remote_addr,
                        connection: obs.connection.clone(),
                    },
                    index + 1 == entry.observations.len(),
                    Line::from(spans),
                );
            }
        }
    }
}

#[derive(Clone, Copy)]
enum RowKind {
    Heading,
    Spacer,
    Body,
    Child { is_last: bool },
    ChildDetail { parent_is_last: bool },
    GrandChild { outer_rail: bool, is_last: bool },
    GrandChildNote { outer_rail: bool },
    Footer,
}

impl RowKind {
    fn rail(self) -> &'static str {
        match self {
            Self::Heading | Self::Spacer => "",
            Self::Body => "│  ",
            Self::Child { is_last: false } => "├─ ",
            Self::Child { is_last: true } | Self::Footer => "└─ ",
            Self::ChildDetail {
                parent_is_last: false,
            } => "│    ",
            Self::ChildDetail {
                parent_is_last: true,
            } => "     ",
            Self::GrandChild {
                outer_rail: true,
                is_last: false,
            } => "│  ├─ ",
            Self::GrandChild {
                outer_rail: true,
                is_last: true,
            }
            | Self::GrandChildNote { outer_rail: true } => "│  └─ ",
            Self::GrandChild {
                outer_rail: false,
                is_last: false,
            } => "   ├─ ",
            Self::GrandChild {
                outer_rail: false,
                is_last: true,
            }
            | Self::GrandChildNote { outer_rail: false } => "   └─ ",
        }
    }
}

#[derive(Default)]
struct FindingRows {
    lines: Vec<(RowKind, Line<'static>)>,
    targets: Vec<(usize, HealthTarget)>,
    window_label: &'static str,
    badge: HealthBadge,
}

impl FindingRows {
    fn push_item(&mut self, kind: RowKind, target: HealthTarget, line: impl Into<Line<'static>>) {
        self.targets.push((self.lines.len(), target));
        self.lines.push((kind, line.into()));
    }

    fn heading(&mut self, target: HealthTarget, line: impl Into<Line<'static>>) {
        self.push_item(RowKind::Heading, target, line);
    }

    fn child(&mut self, target: HealthTarget, is_last: bool, line: impl Into<Line<'static>>) {
        self.push_item(RowKind::Child { is_last }, target, line);
    }

    fn grand_child(
        &mut self,
        target: HealthTarget,
        outer_rail: bool,
        is_last: bool,
        line: impl Into<Line<'static>>,
    ) {
        self.push_item(
            RowKind::GrandChild {
                outer_rail,
                is_last,
            },
            target,
            line,
        );
    }

    fn body(&mut self, line: impl Into<Line<'static>>) {
        self.lines.push((RowKind::Body, line.into()));
    }

    fn child_detail(&mut self, parent_is_last: bool, line: impl Into<Line<'static>>) {
        self.lines
            .push((RowKind::ChildDetail { parent_is_last }, line.into()));
    }

    fn grand_child_note(&mut self, outer_rail: bool, line: impl Into<Line<'static>>) {
        self.lines
            .push((RowKind::GrandChildNote { outer_rail }, line.into()));
    }

    fn footer(&mut self, line: impl Into<Line<'static>>) {
        self.lines.push((RowKind::Footer, line.into()));
    }

    fn spacer(&mut self) {
        self.lines.push((RowKind::Spacer, Line::default()));
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
        for (index, (kind, line)) in self.lines.iter_mut().enumerate() {
            let item = next.next_if(|(_, (line_index, _))| *line_index == index);
            let mut link_badge: Option<String> = None;
            let rail = kind.rail();
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
                    if is_selected {
                        let hint = match (state.has_active_filter(), state.show_historic) {
                            (true, false) => {
                                "  Details unavailable (filter active · press t for history)"
                            }
                            (true, true) => "  Details unavailable (filtered)",
                            (false, false) => "  Details unavailable (press t for history)",
                            (false, true) => "  Details unavailable",
                        };
                        line.push_span(Span::styled(hint, theme::fg(theme::muted())));
                    } else {
                        let tag = match (state.has_active_filter(), state.show_historic) {
                            (true, false) => "  filtered · history off",
                            (true, true) => "  filtered",
                            (false, false) => "  history off",
                            (false, true) => "  —",
                        };
                        line.push_span(Span::styled(tag, theme::fg(theme::faint())));
                    }
                }
                if !rail.is_empty() {
                    line.spans
                        .insert(0, Span::styled(rail, theme::fg(theme::faint())));
                }
                let marker = if is_selected { "▌ " } else { "  " };
                line.spans
                    .insert(0, Span::styled(marker, theme::fg(theme::accent())));
                if is_selected {
                    highlight_line(line, usize::from(width));
                }
            } else if !matches!(kind, RowKind::Spacer) {
                if !rail.is_empty() {
                    line.spans
                        .insert(0, Span::styled(rail, theme::fg(theme::faint())));
                }
                line.spans.insert(0, Span::raw("  "));
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
        let visible = self
            .lines
            .drain(first..end)
            .map(|(_, line)| line)
            .collect::<Vec<_>>();
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

fn highlight_line(line: &mut Line<'_>, width: usize) {
    let selection = theme::row_highlight();
    let pad = width.saturating_sub(line.width());
    if pad > 0 {
        line.push_span(Span::raw(" ".repeat(pad)));
    }
    line.style = line.style.patch(selection);
    if selection.fg.is_some() {
        for span in &mut line.spans {
            if span.style.bg.is_none() {
                span.style = span.style.patch(selection);
            }
        }
    }
}

/// Compact proportional bar showing established / incomplete / reset ratio.
fn tcp_health_bar(counts: &AttemptCounts, width: usize) -> Vec<Span<'static>> {
    if width == 0 || counts.completed == 0 {
        return Vec::new();
    }
    let total = counts.completed as f64;
    let warn_count = counts.no_handshake.saturating_add(counts.superseded);
    let mut err_cells = ((counts.reset as f64 / total) * width as f64).round() as usize;
    let mut warn_cells = ((warn_count as f64 / total) * width as f64).round() as usize;
    if counts.reset > 0 && err_cells == 0 {
        err_cells = 1;
    }
    if warn_count > 0 && warn_cells == 0 {
        warn_cells = 1;
    }
    let fail_cells = (err_cells + warn_cells).min(width);
    err_cells = err_cells.min(fail_cells);
    warn_cells = fail_cells.saturating_sub(err_cells);
    let ok_cells = if counts.established > 0 {
        width.saturating_sub(fail_cells)
    } else {
        0
    };
    let rem = width.saturating_sub(ok_cells + warn_cells + err_cells);

    let mut spans = Vec::with_capacity(4);
    if ok_cells > 0 {
        spans.push(Span::styled("█".repeat(ok_cells), theme::fg(theme::ok())));
    }
    if warn_cells > 0 {
        spans.push(Span::styled(
            "▓".repeat(warn_cells),
            theme::fg(theme::warn()),
        ));
    }
    if err_cells > 0 {
        spans.push(Span::styled("▒".repeat(err_cells), theme::fg(theme::err())));
    }
    if rem > 0 {
        spans.push(Span::styled("·".repeat(rem), theme::fg(theme::faint())));
    }
    spans
}

fn push_nonzero_outcomes(counts: &AttemptCounts, spans: &mut Vec<Span<'static>>) {
    for (count, label, color) in [
        (counts.established, "established", theme::ok()),
        (counts.reset, "reset", theme::err()),
        (counts.no_handshake, "no handshake", theme::warn()),
        (counts.superseded, "superseded", theme::warn()),
    ] {
        if count == 0 {
            continue;
        }
        if !spans.is_empty() {
            spans.push(Span::styled(" · ", theme::fg(theme::faint())));
        }
        spans.push(count_span(count, color));
        spans.push(Span::styled(format!(" {label}"), theme::fg(theme::muted())));
    }
}

fn format_remaining_compact(remaining: Duration) -> String {
    let secs = remaining.as_secs();
    if secs >= 60 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else if secs > 0 {
        format!("{secs}s")
    } else {
        "<1s".to_owned()
    }
}

fn compact_anomaly_parts(issue: &TcpAttempt) -> Vec<(String, Color)> {
    let mut parts = Vec::new();
    for (count, label, color) in [
        (issue.syn_retries, "SYN retry", theme::warn()),
        (issue.unexpected_acks, "unexp ACK", theme::warn()),
        (issue.invalid_syn_acks, "bad SYN-ACK", theme::err()),
        (issue.local_resets, "local RST", theme::warn()),
    ] {
        if count > 0 {
            parts.push((format!("{count}× {label}"), color));
        }
    }
    parts
}

fn tcp_attempt_lines(snapshot: &TcpAttemptSnapshot, compact: bool, rows: &mut FindingRows) {
    let c = &snapshot.total;
    if c.completed > 0 {
        let bar_width = if compact { 12 } else { 22 };
        let mut summary = tcp_health_bar(c, bar_width);
        summary.push(Span::raw("  "));
        let mut breakdown = Vec::new();
        push_nonzero_outcomes(c, &mut breakdown);
        if snapshot.pending > 0 {
            if !breakdown.is_empty() {
                breakdown.push(Span::styled(" · ", theme::fg(theme::faint())));
            }
            breakdown.push(Span::raw(format!("{} ", snapshot.pending)));
            breakdown.push(Span::styled("pending", theme::fg(theme::muted())));
        }
        summary.extend(breakdown);
        rows.body(Line::from(summary));
    } else {
        rows.body(Line::styled(
            format!("{} completed, {} pending", c.completed, snapshot.pending),
            theme::fg(theme::muted()),
        ));
    }

    let mut destinations: Vec<_> = snapshot
        .destinations
        .iter()
        .filter(|(_, c)| c.is_affected())
        .collect();
    destinations.sort_by(|a, b| super::compare_tcp_destinations(*b, *a));
    if destinations.is_empty() {
        if snapshot.omitted > 0 {
            rows.body(Line::styled(
                format!(
                    "Incomplete evidence: {} capacity omissions since clear",
                    snapshot.omitted
                ),
                theme::fg(theme::warn()),
            ));
        }
        rows.footer(Line::styled(
            "No affected destinations in the last 5 min",
            theme::fg(theme::muted()),
        ));
        return;
    }

    rows.body(Line::default());

    let mut issues_by_dest: HashMap<SocketAddr, Vec<&TcpAttempt>> = HashMap::new();
    for issue in &snapshot.recent_issues {
        issues_by_dest
            .entry(issue.key.remote_addr)
            .or_default()
            .push(issue);
    }

    let has_omitted = snapshot.omitted > 0;
    let has_note = c.no_handshake + c.anomalous > 0;
    let has_footer = has_omitted || has_note;
    let last_dest = destinations.len().saturating_sub(1);
    let now = SystemTime::now();

    for (dest_idx, (address, dc)) in destinations.into_iter().enumerate() {
        let issues = issues_by_dest.get(address).map_or(&[][..], Vec::as_slice);
        let outer_rail = dest_idx < last_dest || has_footer;
        let fail_count = dc.reset + dc.no_handshake;
        let fail_color = if dc.reset > 0 {
            theme::err()
        } else {
            theme::warn()
        };

        let mut dest_spans = vec![
            Span::styled(address.to_string(), theme::bold_fg(theme::heading())),
            Span::raw("  "),
        ];
        if fail_count > 0 {
            dest_spans.push(count_span(fail_count, fail_color));
            let fail_label = if dc.reset == 0 {
                " no handshake"
            } else if dc.no_handshake == 0 {
                " reset"
            } else {
                " reset or incomplete"
            };
            dest_spans.push(Span::styled(
                format!("/{}{fail_label}", dc.completed),
                theme::fg(theme::muted()),
            ));
            if dc.reset > 0 && dc.no_handshake > 0 {
                dest_spans.push(Span::styled(" (", theme::fg(theme::muted())));
                dest_spans.push(count_span(dc.reset, theme::err()));
                dest_spans.push(Span::styled(" reset, ", theme::fg(theme::muted())));
                dest_spans.push(count_span(dc.no_handshake, theme::warn()));
                dest_spans.push(Span::styled(" no handshake)", theme::fg(theme::muted())));
            }
        }
        if dc.established > 0 {
            if fail_count > 0 {
                dest_spans.push(Span::styled(" · ", theme::fg(theme::faint())));
            }
            dest_spans.push(count_span(dc.established, theme::ok()));
            dest_spans.push(Span::styled(" established", theme::fg(theme::muted())));
        }
        if dc.superseded > 0 {
            dest_spans.push(Span::styled(" · ", theme::fg(theme::faint())));
            dest_spans.push(count_span(dc.superseded, theme::warn()));
            dest_spans.push(Span::styled(" superseded", theme::fg(theme::muted())));
        }
        if dc.anomalous > 0 {
            dest_spans.push(Span::styled(" · ", theme::fg(theme::faint())));
            dest_spans.push(count_span(dc.anomalous, theme::warn()));
            dest_spans.push(Span::styled(" anomalous", theme::fg(theme::muted())));
        }
        if dc.syn_retries > 0 {
            dest_spans.push(Span::styled(" · ", theme::fg(theme::faint())));
            dest_spans.push(count_span(dc.syn_retries, theme::warn()));
            dest_spans.push(Span::styled(" SYN retries", theme::fg(theme::muted())));
        }
        if !compact && dest_idx == 0 {
            dest_spans.push(Span::styled(
                "   · expires after 5m",
                theme::fg(theme::faint()),
            ));
        }
        rows.child(
            HealthTarget::Destination(*address),
            !outer_rail,
            Line::from(dest_spans),
        );

        if issues.is_empty() {
            rows.grand_child_note(
                outer_rail,
                Line::styled(
                    "No matching attempt in the 32 most recent issues",
                    theme::fg(theme::muted()),
                ),
            );
            continue;
        }

        let last_issue = issues.len().saturating_sub(1);
        for (issue_idx, issue) in issues.iter().enumerate() {
            let (outcome, color) = match issue.outcome {
                AttemptOutcome::Established => ("estab w/ anomaly", theme::warn()),
                AttemptOutcome::NoHandshake => ("no handshake", theme::warn()),
                AttemptOutcome::Reset => ("reset", theme::err()),
                AttemptOutcome::Superseded => ("superseded", theme::warn()),
            };
            let expires_at = issue.finished_at + crate::network::tcp_attempts::WINDOW;
            let remaining =
                format_remaining_compact(expires_at.duration_since(now).unwrap_or_default());
            let time_str = chrono::DateTime::<chrono::Local>::from(issue.finished_at)
                .format("%H:%M:%S")
                .to_string();
            let local_str = issue.key.local_addr.to_string();
            let anomalies = compact_anomaly_parts(issue);

            let mut spans = vec![
                Span::styled(format!("{time_str}  "), theme::fg(theme::muted())),
                Span::styled(outcome, theme::fg(color)),
            ];
            if compact {
                spans.push(Span::raw(format!("  {local_str}  ")));
                spans.push(Span::styled(remaining, theme::fg(theme::muted())));
                for (text, a_color) in anomalies {
                    spans.push(Span::styled(" · ", theme::fg(theme::faint())));
                    spans.push(Span::styled(text, theme::fg(a_color)));
                }
            } else {
                const OUTCOME_COL: usize = 16;
                const LOCAL_COL: usize = 20;
                const ANOMALY_COL: usize = 14;
                spans.push(Span::raw(
                    " ".repeat(OUTCOME_COL.saturating_sub(outcome.len()).max(2)),
                ));
                let local_pad = LOCAL_COL.saturating_sub(local_str.len()).max(2);
                spans.push(Span::raw(local_str));
                spans.push(Span::raw(" ".repeat(local_pad)));
                if anomalies.is_empty() {
                    spans.push(Span::styled("—", theme::fg(theme::faint())));
                    spans.push(Span::raw(" ".repeat(ANOMALY_COL.saturating_sub(1))));
                } else {
                    let mut anomaly_width = 0usize;
                    for (i, (text, a_color)) in anomalies.into_iter().enumerate() {
                        if i > 0 {
                            spans.push(Span::styled(" · ", theme::fg(theme::faint())));
                            anomaly_width += 3;
                        }
                        anomaly_width += text.chars().count();
                        spans.push(Span::styled(text, theme::fg(a_color)));
                    }
                    spans.push(Span::raw(
                        " ".repeat(ANOMALY_COL.saturating_sub(anomaly_width).max(2)),
                    ));
                }
                spans.push(Span::styled(
                    format!("{remaining:<6}"),
                    theme::fg(theme::muted()),
                ));
            }
            rows.grand_child(
                HealthTarget::Attempt {
                    key: issue.key,
                    created: issue.connection_created_at,
                    seq: issue.initial_sequence,
                    started: issue.started_at,
                },
                outer_rail,
                issue_idx == last_issue,
                Line::from(spans),
            );
        }
    }

    if has_omitted {
        let line = Line::styled(
            format!(
                "Incomplete evidence: {} capacity omissions since clear",
                snapshot.omitted
            ),
            theme::fg(theme::warn()),
        );
        if has_note {
            rows.body(line);
        } else {
            rows.footer(line);
        }
    }
    if has_note {
        rows.footer(Line::styled(
            "Missing capture packets or local cancellation can also prevent observed completion.",
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
        tcp_attempt_lines(&snapshot, false, &mut rows);
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
        tcp_attempt_lines(&snapshot, false, &mut rows);
        let text = rows
            .lines
            .iter()
            .map(|(_, line)| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("1 established"));
        assert!(text.contains("2 no handshake"));
        assert!(text.contains("2 pending"));
        assert!(text.contains("198.51.100.1:443  2/3"));
        assert!(text.contains("4 capacity omissions"));
        assert!(text.contains("Missing capture packets or local cancellation"));
    }

    #[test]
    fn recovered_anomaly_keeps_the_destination_sample_size() {
        let address = "198.51.100.1:443".parse().unwrap();
        let counts = AttemptCounts {
            completed: 100,
            established: 100,
            anomalous: 1,
            recovered_anomalies: 1,
            ..Default::default()
        };
        let snapshot = TcpAttemptSnapshot {
            total: counts.clone(),
            destinations: [(address, counts)].into(),
            ..Default::default()
        };
        let mut rows = FindingRows::default();
        tcp_attempt_lines(&snapshot, false, &mut rows);
        let (row, _) = rows
            .targets
            .iter()
            .find(|(_, target)| *target == HealthTarget::Destination(address))
            .unwrap();
        assert!(
            rows.lines[*row]
                .1
                .to_string()
                .contains("100 established · 1 anomalous")
        );
    }

    #[test]
    fn compact_anomaly_parts_omits_zero_counters() {
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
        let parts: Vec<String> = compact_anomaly_parts(&issue)
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert_eq!(parts, vec!["2× SYN retry", "1× unexp ACK"]);
    }

    #[test]
    fn extended_findings_link_to_connection_details_and_update_badge() {
        use crate::app::Config;
        use crate::network::types::{
            ApplicationProtocol, DpiInfo, HttpsInfo, Protocol, ProtocolState, TcpState, TlsAlert,
            TlsAlertLevel, TlsInfo, TlsVersion,
        };

        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .unwrap();
        let stats = app.get_stats();
        let mut conn = Connection::new(
            Protocol::Tcp,
            "192.168.1.10:50200".parse().unwrap(),
            "198.51.100.30:443".parse().unwrap(),
            ProtocolState::Tcp(TcpState::Established),
        );
        conn.process_name = Some("openssl".into());
        conn.pid = Some(901);
        conn.dpi_info = Some(DpiInfo {
            application: ApplicationProtocol::Https(HttpsInfo {
                tls_info: Some(TlsInfo {
                    version: Some(TlsVersion::Tls10),
                    sni: Some("broken.example".into()),
                    alpn: vec![],
                    cipher_suite: None,
                    alert: Some(TlsAlert {
                        level: TlsAlertLevel::Fatal,
                        description: 42,
                    }),
                }),
            }),
        });
        let conns = vec![conn];
        let badge = health_badge(&app, &stats, &conns, TimeWindow::FiveMinutes);
        assert_eq!(badge.errors, 1);

        let data = HealthInputs::collect(&app, &stats, &conns, TimeWindow::FiveMinutes);
        let mut rows = FindingRows::default();
        append_finding_details(
            &data,
            Finding::Extended(FindingId::TlsHealth),
            TimeWindow::FiveMinutes,
            false,
            &mut rows,
        );
        assert_eq!(rows.targets.len(), 1);
        assert_eq!(rows.targets[0].1.link(&conns), Some("Open Details"));
        let rendered = rows
            .lines
            .iter()
            .map(|(_, line)| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("bad_certificate"), "{rendered}");
        assert!(rendered.contains("openssl (901)"), "{rendered}");
    }
}
