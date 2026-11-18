//! Expandable network health findings from the existing capture and OS counters.
use std::{net::SocketAddr, sync::atomic::Ordering::Relaxed, time::SystemTime};

use crate::network::{
    process_activity::process_group_label,
    tcp_attempts::AttemptOutcome,
    types::{Connection, ConnectionKey, NetworkEventKind},
};
use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, section_header,
    section_title, theme, try_handle_pane_scroll, try_handle_pane_wheel,
    widgets::scrollbar::draw_scrolled_text,
};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum Finding {
    Tcp,
    Events,
    Interfaces,
    Dns,
    Capture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ui) enum HealthTarget {
    Finding(Finding),
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
        state.health_focus.set(Some(self));
        match self {
            Self::Finding(finding) => {
                state.open_finding = (state.open_finding != Some(finding)).then_some(finding);
                state.tcp_expanded = None;
                if state.open_finding == Some(Finding::Tcp) {
                    state.tcp_expanded =
                        super::worst_tcp_destination(&ctx.app.get_tcp_attempt_snapshot())
                            .map(|(a, _)| *a);
                }
                state.health_reveal.set(true);
            }
            Self::Destination(addr) => {
                state.tcp_expanded = (state.tcp_expanded != Some(addr)).then_some(addr);
                state.health_reveal.set(true);
            }
            Self::Details(..) => {
                if let Some(i) = self.connection(ctx.connections) {
                    state.set_selected_by_index(ctx.connections, i);
                    state.jump_to_tab(1);
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

fn health_key(key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
    if key.modifiers != KeyModifiers::NONE {
        return None;
    }
    let rows = &ctx.click_regions.health_rows;
    let focused = ctx.ui_state.health_focus.get();
    let index = rows
        .iter()
        .position(|(target, _, _)| Some(*target) == focused);
    let next = match (key.code, index) {
        (KeyCode::Esc, _) => {
            let finding = ctx.ui_state.open_finding.take()?;
            ctx.ui_state.tcp_expanded = None;
            ctx.ui_state
                .health_focus
                .set(Some(HealthTarget::Finding(finding)));
            ctx.ui_state.health_reveal.set(true);
            return Some(Vec::new());
        }
        (KeyCode::Enter, Some(i)) if rows[i].1.height > 0 => return Some(rows[i].0.activate(ctx)),
        (KeyCode::Char('e'), _) => rows
            .iter()
            .position(|(t, _, _)| matches!(t, HealthTarget::Destination(_)))?,
        (KeyCode::Up, Some(i)) => i.saturating_sub(1),
        (KeyCode::Down, Some(i)) => (i + 1).min(rows.len() - 1),
        _ => return None,
    };
    let (target, rect, offset) = rows[next];
    ctx.ui_state.health_focus.set(Some(target));
    if rect.height == 0 {
        ctx.ui_state.health_scroll.scroll_to_top();
        ctx.ui_state.health_scroll.scroll_down(offset);
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
        if key.code == KeyCode::Char('w') && key.modifiers == KeyModifiers::NONE {
            ctx.ui_state.host_window = ctx.ui_state.host_window.next();
            ctx.ui_state.dns_questions_scroll.reset();
            return Some(Vec::new());
        }
        health_key(key, ctx).or_else(|| {
            let scroll = &mut ctx.ui_state.health_scroll;
            try_handle_pane_scroll(key, usize::from(scroll.viewport_rows()), scroll)
        })
    }

    fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        ctx: &mut HandlerContext<'_>,
    ) -> Option<Vec<Effect>> {
        if mouse.kind == MouseEventKind::Down(MouseButton::Left)
            && let Some(&(target, _, _)) = ctx
                .click_regions
                .health_rows
                .iter()
                .find(|(_, rect, _)| rect.contains((mouse.column, mouse.row).into()))
        {
            ctx.ui_state.quit_confirmation = false;
            ctx.ui_state.clear_confirmation = false;
            return Some(target.activate(ctx));
        }
        try_handle_pane_wheel(mouse, &mut ctx.ui_state.health_scroll)
    }

    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &ComponentContext<'_>,
        regions: &mut ClickableRegions,
    ) -> Result<()> {
        let inner = section_header(f, area, section_title("Network health"));
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
        let mut targets = Vec::new();
        let wide = inner.width >= 80;
        let mut lines = Vec::new();
        if wide {
            lines.push(Line::styled(
                format!("    {:<17} {:<40} {}", "Signal", "Observed", "Window"),
                theme::fg(theme::muted()),
            ));
        }
        for (finding, name, summary, label) in summaries {
            let open = state.open_finding == Some(finding);
            let marker = if open { "▾" } else { "▸" };
            targets.push((lines.len(), HealthTarget::Finding(finding)));
            let text = if wide {
                format!("{marker} {name:<17} {summary:<40} {label}")
            } else {
                format!("{marker} {name} ({label})  {summary}")
            };
            lines.push(Line::from(text));
            if !open {
                continue;
            }
            match finding {
                Finding::Tcp => {
                    let mut nested = Vec::new();
                    let evidence = tcp_attempt_lines(&tcp, state, ctx.connections, &mut nested);
                    targets.extend(nested.into_iter().map(|(i, t)| (lines.len() + i, t)));
                    lines.extend(evidence);
                }
                Finding::Events => {
                    lines.extend(network_event_lines(&events, window, inner.width < 100))
                }
                Finding::Interfaces => {
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
                    lines.push(Line::from(format!(
                        "    {} lookups · {} pending · {} SERVFAIL · {} refused",
                        dns.lookups, dns.pending, dns.servfail, dns.refused
                    )));
                    if let Some(rtt) = dns.latency_p50 {
                        lines.push(Line::from(format!(
                            "    Median response {}",
                            crate::ui::format::format_rtt_compact(rtt)
                        )));
                    }
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
        }
        highlight(&mut lines, &targets, state);
        let focus = state.health_focus.get();
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
                if reveal && Some(target) == focus {
                    ctx.ui_state
                        .health_scroll
                        .reveal(row, row + height, inner.height);
                }
                (target, row, height)
            })
            .collect();
        let (text_area, offset) = draw_scrolled_text(
            f,
            inner,
            Paragraph::new(lines).wrap(Wrap { trim: false }),
            &ctx.ui_state.health_scroll,
        );
        for (target, row, height) in wrapped_targets {
            register_health_row(regions, target, row, height, text_area, offset);
        }
        Ok(())
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
            lines[index].style = theme::row_highlight();
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
    regions.health_rows.push((target, rect, row));
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
            "Affected destinations · Enter or click · ↑/↓ select · issues age out after 5 min",
        ));
    } else {
        lines.push(Line::from("No affected destinations in the last 5 min"));
    }
    for &(address, c) in destinations.iter().take(3).chain(extra) {
        let target = HealthTarget::Destination(*address);
        targets.push((lines.len(), target));
        let expanded = state.tcp_expanded == Some(*address);
        let marker = if expanded { "[Collapse]" } else { "[Expand]" };
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
            "[Dismiss] {addr}  No affected attempts remain in the last 5 min"
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
        assert!(live.contains(&format!("▌ [Collapse] {addr}")));
        assert!(!live.contains("more affected destinations"));
        snapshot.destinations.clear();
        let expired = render(&snapshot, &state);
        assert!(expired.contains(&format!("▌ [Dismiss] {addr}  No affected attempts remain")));
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
