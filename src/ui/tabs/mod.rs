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

#[derive(Clone, Copy)]
enum HealthLevel {
    Error,
    Warning,
    Healthy,
    Muted,
}

impl HealthLevel {
    fn color(self) -> Color {
        match self {
            Self::Error => theme::err(),
            Self::Warning => theme::warn(),
            Self::Healthy => theme::ok(),
            Self::Muted => theme::muted(),
        }
    }

    fn attention_order(self) -> u8 {
        match self {
            Self::Error => 0,
            Self::Warning => 1,
            Self::Healthy | Self::Muted => 2,
        }
    }

    fn observed(error: bool, warning: bool) -> Self {
        if error {
            Self::Error
        } else if warning {
            Self::Warning
        } else {
            Self::Muted
        }
    }
}

/// Use the same evidence and palette in Findings and the Overview sidebar.
fn tcp_handshake_status(
    snapshot: &TcpAttemptSnapshot,
    capture_incomplete: bool,
) -> (&'static str, HealthLevel) {
    let c = &snapshot.total;
    if capture_incomplete || snapshot.omitted > 0 {
        ("incomplete evidence", HealthLevel::Warning)
    } else if c.reset + c.no_handshake > 0 {
        ("degraded", HealthLevel::Warning)
    } else if c.recovered_anomalies > 0 {
        ("recovered anomalies", HealthLevel::Warning)
    } else if c.superseded > 0 {
        ("incomplete evidence", HealthLevel::Warning)
    } else if snapshot.pending > 0 {
        ("checking", HealthLevel::Muted)
    } else if c.established > 0 {
        ("healthy", HealthLevel::Healthy)
    } else {
        ("not observed", HealthLevel::Muted)
    }
}

fn dns_health_status(health: DnsHealth, capture_failed: bool) -> (&'static str, HealthLevel) {
    if capture_failed {
        return ("unknown (capture stopped)", HealthLevel::Warning);
    }
    match health {
        DnsHealth::NotObserved => ("not observed", HealthLevel::Muted),
        DnsHealth::Checking => ("checking", HealthLevel::Muted),
        DnsHealth::Responsive => ("responsive", HealthLevel::Healthy),
        DnsHealth::Degraded => ("degraded", HealthLevel::Warning),
        DnsHealth::Failing => ("failing", HealthLevel::Error),
        DnsHealth::NoReplies => ("no replies", HealthLevel::Error),
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
