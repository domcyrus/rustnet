//! Per-view renderers. Each submodule owns one tab or the contextual
//! help overlay and is invoked from the top-level UI dispatcher.

pub(super) mod activity;
pub(super) mod details;
pub(super) mod graph;
pub(super) mod health;
pub(super) mod help;
pub(super) mod host;
pub(super) mod interfaces;
pub(super) mod overview;

use super::theme;
use crate::network::dns_analytics::DnsHealth;
use crate::network::tcp_attempts::{AttemptCounts, TcpAttemptSnapshot};
use ratatui::{
    style::{Color, Style},
    text::Span,
};
use std::{cmp::Ordering, net::SocketAddr};

fn worst_tcp_destination(snapshot: &TcpAttemptSnapshot) -> Option<(&SocketAddr, &AttemptCounts)> {
    snapshot
        .destinations
        .iter()
        .filter(|(_, c)| c.is_affected())
        .max_by(|a, b| compare_tcp_destinations(*a, *b))
}

/// Rank failure fraction, evidence count, anomalies, then stable endpoint order.
fn compare_tcp_destinations(
    (addr_a, a): (&SocketAddr, &AttemptCounts),
    (addr_b, b): (&SocketAddr, &AttemptCounts),
) -> Ordering {
    let fa = u128::from(a.reset + a.no_handshake);
    let fb = u128::from(b.reset + b.no_handshake);
    (fa * u128::from(b.completed.max(1)))
        .cmp(&(fb * u128::from(a.completed.max(1))))
        .then_with(|| fa.cmp(&fb))
        .then_with(|| {
            (u128::from(a.anomalous) * u128::from(b.completed.max(1)))
                .cmp(&(u128::from(b.anomalous) * u128::from(a.completed.max(1))))
        })
        .then_with(|| a.anomalous.cmp(&b.anomalous))
        .then_with(|| addr_b.cmp(addr_a))
}

/// Use the same evidence and palette in Findings and the Overview sidebar.
fn tcp_handshake_status(
    snapshot: &TcpAttemptSnapshot,
    capture_incomplete: bool,
) -> (&'static str, Color) {
    let c = &snapshot.total;
    if capture_incomplete || snapshot.omitted > 0 {
        ("incomplete evidence", theme::warn())
    } else if c.reset + c.no_handshake > 0 {
        ("degraded", theme::warn())
    } else if c.recovered_anomalies > 0 {
        ("recovered anomalies", theme::warn())
    } else if c.superseded > 0 {
        ("incomplete evidence", theme::warn())
    } else if snapshot.pending > 0 {
        ("checking", theme::muted())
    } else if c.established > 0 {
        ("healthy", theme::ok())
    } else {
        ("not observed", theme::muted())
    }
}

fn dns_health_status(health: DnsHealth, capture_failed: bool) -> (&'static str, Color) {
    if capture_failed {
        return ("unknown (capture stopped)", theme::warn());
    }
    match health {
        DnsHealth::NotObserved => ("not observed", theme::muted()),
        DnsHealth::Checking => ("checking", theme::muted()),
        DnsHealth::Responsive => ("responsive", theme::ok()),
        DnsHealth::Degraded => ("degraded", theme::warn()),
        DnsHealth::Failing => ("failing", theme::err()),
        DnsHealth::NoReplies => ("no replies", theme::err()),
    }
}

/// Color an observed count, leaving zero quiet beside the values that need attention.
fn count_style(count: u64, color: Color) -> Style {
    if count == 0 {
        Style::default()
    } else {
        theme::fg(color)
    }
}

fn count_span(count: u64, color: Color) -> Span<'static> {
    Span::styled(count.to_string(), count_style(count, color))
}
