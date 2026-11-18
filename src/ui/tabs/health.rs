//! Expandable network health findings from the existing capture and OS counters.
use std::{net::SocketAddr, sync::atomic::Ordering::Relaxed, time::SystemTime};

use crate::network::{
    process_activity::process_group_label,
    tcp_attempts::AttemptOutcome,
    types::{Connection, ConnectionKey, NetworkEventKind},
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, HostView, PaneScroll,
    UiState, section_header, section_title, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::scrollbar::draw_scrolled_text,
};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum Finding {
    #[default]
    Tcp,
    Events,
    Interfaces,
    Dns,
    Capture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum HealthTarget {
    Finding(Finding),
    Section(HostView),
    Destination(SocketAddr),
    Details(ConnectionKey, SystemTime, u32),
}

impl HealthTarget {
    fn connection(self, connections: &[Connection]) -> Option<usize> {
        let Self::Details(key, created_at, _) = self else {
            return None;
        };
        connections
            .iter()
            .position(|c| c.created_at == created_at && ConnectionKey::from_connection(c) == key)
    }

    fn activate(self, ctx: &mut HandlerContext<'_>) -> Vec<Effect> {
        let state = &mut ctx.ui_state;
        match self {
            Self::Finding(finding) => {
                select_finding(state, finding);
                state.inspecting_finding = true;
                state.health_reveal.set(true);
            }
            Self::Section(view) => {
                state.select_section(view as usize);
                state.return_to_finding = true;
            }
            Self::Destination(addr) => {
                state.health_focus.set(Some(self));
                state.tcp_expanded = (state.tcp_expanded != Some(addr)).then_some(addr);
                state.health_reveal.set(true);
            }
            Self::Details(..) => {
                if let Some(i) = self.connection(ctx.connections) {
                    state.health_focus.set(Some(self));
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
            }
        }
        Vec::new()
    }
}

fn select_finding(state: &mut UiState, finding: Finding) {
    if state.finding != finding {
        state.finding = finding;
        state.health_focus.set(None);
        state.health_scroll.reset();
    }
}

fn health_key(key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
    if key.modifiers != KeyModifiers::NONE {
        return None;
    }
    let state = &mut ctx.ui_state;
    let inspecting = state.inspecting_finding;
    let rows = &ctx.click_regions.health_rows;
    // The index is drawn first, followed by the selected finding's links.
    let boundary = rows.partition_point(|(t, _)| matches!(t, HealthTarget::Finding(_)));
    let rows = if inspecting {
        &rows[boundary..]
    } else {
        &rows[..boundary]
    };
    let focus = if inspecting {
        state.health_focus.get()
    } else {
        Some(HealthTarget::Finding(state.finding))
    };
    let selected = rows.iter().position(|(t, _)| Some(*t) == focus);
    match key.code {
        KeyCode::Esc if inspecting => {
            state.inspecting_finding = false;
            state.health_reveal.set(true);
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Up | KeyCode::Char('k') => {
            if inspecting && state.finding != Finding::Tcp {
                return None;
            }
            let down = matches!(key.code, KeyCode::Down | KeyCode::Char('j'));
            let i = selected?;
            let next = rows[if down {
                (i + 1).min(rows.len() - 1)
            } else {
                i.saturating_sub(1)
            }]
            .0;
            if let HealthTarget::Finding(finding) = next {
                select_finding(state, finding);
            } else {
                state.health_focus.set(Some(next));
            }
            state.health_reveal.set(true);
        }
        KeyCode::Enter => {
            let (target, rect) = rows[selected?];
            if rect.height == 0 {
                state.health_reveal.set(true);
            } else if !matches!(target, HealthTarget::Destination(_)) {
                return Some(target.activate(ctx));
            }
        }
        KeyCode::Left | KeyCode::Right | KeyCode::Char('l' | ' ') if inspecting => {
            let (target, rect) = rows[selected?];
            if rect.height == 0 {
                state.health_reveal.set(true);
                return Some(Vec::new());
            }
            match target {
                HealthTarget::Destination(addr) => {
                    let expanded = state.tcp_expanded == Some(addr);
                    let expand = match key.code {
                        KeyCode::Left => false,
                        KeyCode::Char(' ') => !expanded,
                        _ => true,
                    };
                    if expanded != expand {
                        return Some(target.activate(ctx));
                    }
                }
                HealthTarget::Details(..) if key.code == KeyCode::Left => {
                    state
                        .health_focus
                        .set(state.tcp_expanded.map(HealthTarget::Destination));
                    state.health_reveal.set(true);
                }
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(Vec::new())
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
        lines.push(Line::from("No resets or ICMP errors observed"));
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

pub(in crate::ui) struct HealthTab;

impl Component for HealthTab {
    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        health_key(key, ctx).or_else(|| {
            let scroll = if ctx.ui_state.inspecting_finding {
                &mut ctx.ui_state.health_scroll
            } else {
                &mut ctx.ui_state.finding_list_scroll
            };
            try_handle_pane_scroll(key, usize::from(scroll.viewport_rows()), scroll)
        })
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        let point = (mouse.column, mouse.row).into();
        let regions = ctx.click_regions;
        let in_evidence = regions.evidence_area.contains(point);
        let in_list = regions.findings_area.contains(point);
        if !in_evidence && !in_list {
            return None;
        }
        let state = &mut ctx.ui_state;
        if mouse.kind == MouseEventKind::Down(MouseButton::Left) {
            state.quit_confirmation = false;
            state.clear_confirmation = false;
            state.inspecting_finding = in_evidence;
            if let Some(&(target, rect)) =
                regions.health_rows.iter().find(|(_, r)| r.contains(point))
            {
                match target {
                    HealthTarget::Finding(finding)
                        if regions.evidence_area.width > 0 && mouse.column >= rect.x + 3 =>
                    {
                        select_finding(state, finding);
                    }
                    HealthTarget::Destination(_) if mouse.column >= rect.x + 3 => {
                        state.health_focus.set(Some(target));
                    }
                    _ => return Some(target.activate(ctx)),
                }
            }
            return Some(Vec::new());
        }
        let scroll = if in_evidence {
            &mut state.health_scroll
        } else {
            &mut state.finding_list_scroll
        };
        try_handle_pane_wheel(mouse, scroll)
    }

    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        regions: &mut ClickableRegions,
    ) -> Result<()> {
        let split = area.width >= 100;
        let [list, evidence] = if split {
            Layout::horizontal([Constraint::Percentage(35), Constraint::Fill(1)])
                .spacing(1)
                .areas(area)
        } else if ctx.ui_state.inspecting_finding {
            [Rect::default(), area]
        } else {
            [area, Rect::default()]
        };
        regions.findings_area = list;
        regions.evidence_area = evidence;
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
        let summaries = [
            (
                Finding::Tcp,
                "TCP handshakes",
                if c.completed > 0 {
                    format!(
                        "{}/{} reset or incomplete · {} anomalous",
                        c.reset + c.no_handshake,
                        c.completed,
                        c.anomalous
                    )
                } else if tcp.pending > 0 {
                    format!("{} pending", tcp.pending)
                } else {
                    "No attempts observed".into()
                },
                "5m",
            ),
            (
                Finding::Events,
                "Resets and ICMP",
                format!(
                    "RST {} sent / {} received · {icmp} ICMP",
                    resets.sent, resets.received
                ),
                window.label_since_clear(events.since_clear),
            ),
            (
                Finding::Interfaces,
                "Interface drops",
                if interfaces.is_empty() {
                    "Waiting for interface statistics".to_owned()
                } else {
                    format!("{drops} drops observed")
                },
                window.label_since_clear(since_clear),
            ),
            (
                Finding::Dns,
                "DNS replies",
                format!("{} replies · {} timeouts", dns.answered, dns.timeouts),
                dns.window_label(),
            ),
            (
                Finding::Capture,
                "Capture quality",
                if capture_error.is_some() {
                    "Capture failed".to_owned()
                } else {
                    format!("{reported} reported drops · {queue} queue drops")
                },
                if events.since_clear {
                    "since clear"
                } else {
                    "since startup"
                },
            ),
        ];
        let reveal = state.health_reveal.take();
        if !list.is_empty() {
            let inner = section_header(
                f,
                list,
                section_title(if state.inspecting_finding {
                    "Findings"
                } else {
                    "▌ Findings"
                }),
            );
            let mut lines = Vec::new();
            let mut targets = Vec::new();
            for (finding, name, summary, window) in &summaries {
                targets.push((lines.len(), HealthTarget::Finding(*finding)));
                let selected = *finding == state.finding;
                let marker = if selected { "▌" } else { " " };
                let style = if selected && !state.inspecting_finding {
                    theme::row_highlight()
                } else {
                    Default::default()
                };
                lines.push(Line::styled(
                    format!("{marker} › {name} ({window})  {summary}"),
                    style,
                ));
            }
            draw_rows(
                f,
                inner,
                lines,
                targets,
                &state.finding_list_scroll,
                (reveal && !state.inspecting_finding)
                    .then_some(HealthTarget::Finding(state.finding)),
                regions,
            );
        }
        if !evidence.is_empty() {
            let (_, name, _, label) = &summaries[state.finding as usize];
            let marker = if state.inspecting_finding { "▌ " } else { "" };
            let inner = section_header(
                f,
                evidence,
                section_title(format!("{marker}{name} ({label})")),
            );
            let mut targets = Vec::new();
            let mut lines = Vec::new();
            match state.finding {
                Finding::Tcp => {
                    lines = tcp_attempt_lines(&tcp, state, ctx.connections, &mut targets)
                }
                Finding::Events => {
                    lines.extend(network_event_lines(&events, window, inner.width < 100))
                }
                Finding::Interfaces => {
                    targets.push((lines.len(), HealthTarget::Section(HostView::Interfaces)));
                    lines.push(Line::from("[Open interface counters]"));
                    let mut rows: Vec<_> = interfaces.iter().collect();
                    rows.sort_unstable_by_key(|(name, _)| *name);
                    for (name, c) in rows {
                        lines.push(Line::from(format!(
                            "    {name}  RX drops {} · TX drops {} · RX errors {} · TX errors {}",
                            c.rx_dropped, c.tx_dropped, c.rx_errors, c.tx_errors
                        )));
                    }
                    if interfaces.is_empty() {
                        lines.push(Line::from("    No interface samples available"));
                    }
                }
                Finding::Dns => {
                    targets.push((lines.len(), HealthTarget::Section(HostView::Dns)));
                    lines.push(Line::from("[Open DNS resolvers]"));
                    lines.extend(super::host::dns_evidence_lines(
                        &dns,
                        capture_error.is_some(),
                        None,
                    ));
                    if dns.truncated {
                        lines.push(Line::from("    Incomplete DNS evidence"));
                    }
                }
                Finding::Capture => {
                    if let Some(error) = &capture_error {
                        lines.push(Line::from(format!("    {error}")));
                    }
                    lines.push(Line::from(format!("    Capture backend drops {capture} · interface-reported drops {iface} · processing queue drops {queue}")));
                }
            }
            let old_focus = state.health_focus.get();
            highlight(&mut lines, &targets, state);
            let focus = state.health_focus.get();
            let reveal_focus = state.inspecting_finding && (reveal || old_focus != focus);
            draw_rows(
                f,
                inner,
                lines,
                targets,
                &state.health_scroll,
                focus.filter(|_| reveal_focus),
                regions,
            );
        }
        Ok(())
    }
}

fn draw_rows(
    f: &mut Frame,
    inner: Rect,
    lines: Vec<Line<'_>>,
    targets: Vec<(usize, HealthTarget)>,
    scroll: &PaneScroll,
    reveal: Option<HealthTarget>,
    regions: &mut ClickableRegions,
) {
    // Map logical rows to terminal lines using the scrolled pane's gutter.
    let width = inner.width.saturating_sub(2).max(1);
    let height = |line: &Line<'_>| {
        Paragraph::new(line.clone())
            .wrap(Wrap { trim: false })
            .line_count(width) as u16
    };
    let mut previous = 0;
    let mut row = 0;
    let wrapped_targets: Vec<_> = targets
        .into_iter()
        .map(|(index, target)| {
            row += lines[previous..index].iter().map(height).sum::<u16>();
            previous = index;
            let height = height(&lines[index]);
            if Some(target) == reveal {
                scroll.reveal(row, row + height, inner.height);
            }
            (target, row, height)
        })
        .collect();
    let (text_area, offset) = draw_scrolled_text(
        f,
        inner,
        Paragraph::new(lines).wrap(Wrap { trim: false }),
        scroll,
    );
    for (target, row, height) in wrapped_targets {
        register_health_row(regions, target, row, height, text_area, offset);
    }
}

fn highlight(
    lines: &mut [Line<'_>],
    targets: &[(usize, HealthTarget)],
    state: &crate::ui::UiState,
) {
    let selected = targets
        .iter()
        .find(|(_, target)| Some(*target) == state.health_focus.get())
        .or_else(|| {
            targets.iter().find(|(_, target)| {
                Some(*target) == state.tcp_expanded.map(HealthTarget::Destination)
            })
        })
        .or(targets.first());
    state.health_focus.set(selected.map(|(_, target)| *target));
    for &(index, target) in targets {
        let marker = if Some(target) == state.health_focus.get() {
            if state.inspecting_finding {
                lines[index].style = theme::row_highlight();
            }
            "▌ "
        } else {
            "  "
        };
        lines[index].spans.insert(0, Span::raw(marker));
    }
}

fn register_health_row(
    regions: &mut ClickableRegions,
    target: HealthTarget,
    row: u16,
    height: u16,
    area: Rect,
    offset: u16,
) {
    let top = row.saturating_sub(offset).min(area.height);
    let bottom = (row + height).saturating_sub(offset).min(area.height);
    let rect = Rect::new(area.x, area.y + top, area.width, bottom - top);
    regions.health_rows.push((target, rect));
}

pub(super) fn tcp_attempt_lines(
    snapshot: &crate::network::tcp_attempts::TcpAttemptSnapshot,
    state: &crate::ui::UiState,
    connections: &[Connection],
    targets: &mut Vec<(usize, HealthTarget)>,
) -> Vec<Line<'static>> {
    let c = &snapshot.total;
    let mut lines = vec![
        Line::from(format!(
            "{} completed, {} pending",
            c.completed, snapshot.pending
        )),
        Line::from(format!(
            "  {} established, {} reset, {} no handshake, {} superseded",
            c.established, c.reset, c.no_handshake, c.superseded
        )),
    ];
    let mut destinations: Vec<_> = snapshot
        .destinations
        .iter()
        .filter(|(_, c)| c.is_affected())
        .collect();
    destinations.sort_by(|a, b| super::compare_tcp_destinations(*b, *a));
    let inspecting = state.tcp_expanded;
    let rank = inspecting.and_then(|addr| destinations.iter().position(|(a, _)| **a == addr));
    let extra = rank.filter(|&index| index >= 3).map(|i| &destinations[i]);
    if !destinations.is_empty() || inspecting.is_some() {
        lines.push(Line::from(
            "Affected destinations · Space or ▸ to expand · issues expire after 5 min",
        ));
    } else {
        lines.push(Line::from("No affected destinations in the last 5 min"));
    }
    for &(address, c) in destinations.iter().take(3).chain(extra) {
        let target = HealthTarget::Destination(*address);
        targets.push((lines.len(), target));
        let expanded = state.tcp_expanded == Some(*address);
        let marker = if expanded { "▾" } else { "▸" };
        lines.push(Line::from(format!(
            "{marker} {address}  {}/{} reset or incomplete, {} anomalous, {} SYN retries",
            c.reset + c.no_handshake,
            c.completed,
            c.anomalous,
            c.syn_retries
        )));
        if expanded {
            lines.push(Line::from(format!(
                "    {} established, {} reset, {} no handshake, {} superseded",
                c.established, c.reset, c.no_handshake, c.superseded
            )));
            let mut issues = snapshot
                .recent_issues
                .iter()
                .filter(|issue| issue.key.remote_addr == *address)
                .peekable();
            if issues.peek().is_none() {
                lines.push(Line::from(
                    "    No matching attempt in the 32 most recent issues",
                ));
            }
            for issue in issues {
                let link = issue.connection_created_at.map(|created| {
                    HealthTarget::Details(issue.key, created, issue.initial_sequence)
                });
                let action = if let Some(link) =
                    link.filter(|target| target.connection(connections).is_some())
                {
                    targets.push((lines.len(), link));
                    "[Open Details]"
                } else {
                    "Details unavailable"
                };
                lines.push(Line::from(format!(
                    "    {}  {}  {}  {action} · expires {}",
                    chrono::DateTime::<chrono::Local>::from(issue.finished_at).format("%H:%M:%S"),
                    match issue.outcome {
                        AttemptOutcome::Established => "established after anomaly",
                        AttemptOutcome::NoHandshake => "no handshake observed",
                        outcome => outcome.label(),
                    },
                    issue.key.local_addr,
                    chrono::DateTime::<chrono::Local>::from(
                        issue.finished_at + crate::network::tcp_attempts::WINDOW
                    )
                    .format("%H:%M:%S")
                )));
                if issue.unexpected_acks
                    + issue.invalid_syn_acks
                    + issue.local_resets
                    + issue.syn_retries
                    > 0
                {
                    lines.push(Line::from(format!("      SYN retries {}  unexpected ACKs {}  invalid SYN-ACKs {}  local resets {}", issue.syn_retries, issue.unexpected_acks, issue.invalid_syn_acks, issue.local_resets)));
                }
            }
        }
    }
    if let Some(addr) = inspecting.filter(|_| rank.is_none()) {
        targets.push((lines.len(), HealthTarget::Destination(addr)));
        lines.push(Line::from(format!(
            "▾ {addr}  No affected attempts remain in the last 5 min · ← dismiss"
        )));
    }
    let hidden = destinations
        .len()
        .saturating_sub(3 + usize::from(extra.is_some()));
    if hidden > 0 {
        lines.push(Line::from(format!(
            "  {} more affected destinations in JSON",
            hidden
        )));
    }
    if snapshot.omitted > 0 {
        lines.push(Line::from(format!(
            "  Incomplete evidence: {} capacity omissions since clear",
            snapshot.omitted
        )));
    }
    if c.no_handshake + c.anomalous > 0 {
        lines.push(Line::from(
            "  Missing capture packets or local cancellation can also prevent observed completion.",
        ));
    }
    lines
}

#[cfg(test)]
mod tcp_attempt_tests {
    use super::*;
    use crate::network::tcp_attempts::{AttemptCounts, TcpAttemptSnapshot};

    #[test]
    fn open_destination_survives_reranking_and_explains_expiry_until_dismissed() {
        let addr = "198.51.100.4:443".parse().unwrap();
        let mut state = crate::ui::UiState {
            tcp_expanded: Some(addr),
            ..Default::default()
        };
        let mut snapshot = TcpAttemptSnapshot::default();
        for ip in 1..=4 {
            snapshot.destinations.insert(
                SocketAddr::from(([198, 51, 100, ip], 443)),
                AttemptCounts {
                    completed: 1,
                    reset: 1,
                    ..Default::default()
                },
            );
        }
        let render = |snapshot: &TcpAttemptSnapshot, state: &crate::ui::UiState| {
            let mut targets = Vec::new();
            let mut lines = tcp_attempt_lines(snapshot, state, &[], &mut targets);
            highlight(&mut lines, &targets, state);
            lines
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        let live = render(&snapshot, &state);
        assert!(live.contains(&format!("▌ ▾ {addr}")));
        assert!(!live.contains("more affected destinations"));
        snapshot.destinations.clear();
        let expired = render(&snapshot, &state);
        assert!(expired.contains(&format!("▌ ▾ {addr}  No affected attempts remain")));
        state
            .health_focus
            .get()
            .unwrap()
            .activate(&mut crate::ui::test_support::empty_ctx(
                &crate::test_support::test_app(),
                &mut state,
                &ClickableRegions::default(),
            ));
        assert!(render(&snapshot, &state).contains("No affected destinations in the last 5 min"));
        assert_eq!(state.health_focus.get(), None);
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
        let text = tcp_attempt_lines(&snapshot, &Default::default(), &[], &mut Vec::new())
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
