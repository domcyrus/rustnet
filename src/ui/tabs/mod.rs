//! Per-view renderers. Each submodule owns one tab or the contextual
//! help overlay and is invoked from the top-level UI dispatcher.

pub(super) mod activity;
pub(super) mod details;
pub(super) mod graph;
pub(super) mod help;
pub(super) mod host;
pub(super) mod interfaces;
pub(super) mod overview;

use crate::network::tcp_attempts::AttemptCounts;
use std::{cmp::Ordering, net::SocketAddr};

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
