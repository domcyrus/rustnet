//! Host socket inventory and interface statistics.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Modifier,
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row},
};
use rustnet_host::{HostSocket, HostSocketState, HostTcpState};

use crate::ui::{
    ClickableRegions, Component, ComponentContext, Effect, HandlerContext, HostView,
    format::format_rtt_compact, section_header, section_title, theme, try_handle_pane_scroll,
    try_handle_pane_wheel, widgets::scrollbar::render_scrolled_table,
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
        }
    }

    fn handle_key(&mut self, key: KeyEvent, ctx: &mut HandlerContext<'_>) -> Option<Vec<Effect>> {
        match (key.code, key.modifiers) {
            (KeyCode::Char('s'), KeyModifiers::NONE) | (KeyCode::Left, _) => {
                ctx.ui_state.host_view = HostView::Sockets;
                Some(Vec::new())
            }
            (KeyCode::Char('i'), KeyModifiers::NONE) | (KeyCode::Right, _) => {
                ctx.ui_state.host_view = HostView::Interfaces;
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
        ])),
        Rect::new(area.x, area.y, area.width, area.height.min(1)),
    );
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
    let inner = section_header(f, area, section_title(" Host Socket States"));
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
        "Proto",
        "State",
        "Local endpoint",
        "Peer",
        "Service",
        "PID",
        "Process",
    ]);
    render_scrolled_table(
        f,
        inner,
        header,
        rows,
        &[
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Min(22),
            Constraint::Min(18),
            Constraint::Length(14),
            Constraint::Length(8),
            Constraint::Length(20),
        ],
        &ctx.ui_state.host_sockets_scroll,
    );
}
