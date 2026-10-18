//! Sampled socket evidence. Counters and queues are never packet-capture totals.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub const DIAGNOSTICS_FRESHNESS: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueKind {
    TcpBytes,
    UdpMemory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSample {
    pub source: &'static str,
    pub sampled_at: SystemTime,
    pub kind: QueueKind,
    pub receive: u64,
    pub send: u64,
    pub socket_drops: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSample {
    /// Collection was (re)enabled; counters cannot extend the previous baseline.
    pub counter_reset: bool,
    pub source: &'static str,
    pub sampled_at: SystemTime,
    pub rtt_us: u32,
    pub rtt_variation_us: u32,
    pub congestion_window_segments: Option<u32>,
    pub retransmissions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketSample {
    pub native_id: u64,
    pub netns: Option<u64>,
    pub queues: Option<QueueSample>,
    pub tcp: Option<TcpSample>,
}

pub fn sample_is_fresh(sampled_at: SystemTime, now: SystemTime) -> bool {
    now.duration_since(sampled_at)
        .is_ok_and(|age| age <= DIAGNOSTICS_FRESHNESS)
}

/// Small per-generation history for interpretation, shared by UI and exports.
#[derive(Debug, Clone)]
pub struct ConnectionDiagnostics {
    pub sample: Arc<SocketSample>,
    pub nonempty_receive_samples: u8,
    pub socket_drop_increase: Option<u64>,
    pub retransmission_increase: Option<u32>,
}

impl ConnectionDiagnostics {
    pub fn update(previous: Option<&Self>, mut sample: Arc<SocketSample>) -> Self {
        let previous = previous.filter(|old| {
            old.sample.native_id == sample.native_id && old.sample.netns == sample.netns
        });
        if sample.tcp.is_none()
            && let Some(old) = previous
        {
            Arc::make_mut(&mut sample).tcp = old.sample.tcp.clone();
        }
        let retransmission_increase = sample.tcp.as_ref().and_then(|tcp| {
            let old = previous?;
            let before = old.sample.tcp.as_ref()?;
            if tcp.counter_reset || tcp.source != before.source {
                return None;
            }
            if tcp == before {
                return old.retransmission_increase;
            }
            (before.sampled_at < tcp.sampled_at
                && sample_is_fresh(before.sampled_at, tcp.sampled_at))
            .then(|| tcp.retransmissions.checked_sub(before.retransmissions))
            .flatten()
        });
        let mut nonempty_receive_samples = 0;
        let mut socket_drop_increase = None;
        if let Some(queue) = &sample.queues {
            if let Some(old) = previous
                && old.sample.queues.as_ref().is_some_and(|q| q == queue)
            {
                return Self {
                    sample,
                    retransmission_increase,
                    ..old.clone()
                };
            }
            if queue.kind == QueueKind::TcpBytes && queue.receive > 0 {
                nonempty_receive_samples = previous
                    .filter(|old| {
                        old.sample.queues.as_ref().is_some_and(|q| {
                            q.source == queue.source
                                && q.sampled_at < queue.sampled_at
                                && sample_is_fresh(q.sampled_at, queue.sampled_at)
                        })
                    })
                    .map_or(1, |old| old.nonempty_receive_samples.saturating_add(1));
            }
            if let Some(old) = previous.and_then(|p| p.sample.queues.as_ref())
                && old.source == queue.source
                && old.sampled_at < queue.sampled_at
                && sample_is_fresh(old.sampled_at, queue.sampled_at)
            {
                socket_drop_increase = queue
                    .socket_drops
                    .zip(old.socket_drops)
                    .and_then(|(current, previous)| current.checked_sub(previous));
            }
        }
        Self {
            sample,
            nonempty_receive_samples,
            socket_drop_increase,
            retransmission_increase,
        }
    }

    pub fn findings(&self, now: SystemTime) -> Vec<&'static str> {
        let mut findings = Vec::new();
        if self
            .sample
            .queues
            .as_ref()
            .is_some_and(|q| sample_is_fresh(q.sampled_at, now))
        {
            if self.socket_drop_increase.is_some_and(|n| n > 0) {
                findings.push("Observed: socket drop counter increased; cause unknown");
            }
            if self.nonempty_receive_samples >= 3 {
                findings.push(
                    "Observed: TCP receive queue remained nonempty across samples; cause unknown",
                );
            }
        }
        if self.retransmission_increase.is_some_and(|n| n > 0)
            && self
                .sample
                .tcp
                .as_ref()
                .is_some_and(|t| sample_is_fresh(t.sampled_at, now))
        {
            findings.push("Observed: kernel TCP retransmissions increased; loss location unknown");
        }
        findings
    }
}

/// Fixed, evidence-qualified findings used by both screens and exports.
impl super::Connection {
    pub fn diagnostic_findings(&self, now: SystemTime) -> Vec<&'static str> {
        if self.is_historic {
            return Vec::new();
        }
        let mut findings = self
            .diagnostics
            .as_ref()
            .map_or_else(Vec::new, |d| d.findings(now));
        if self
            .tcp_analytics
            .as_ref()
            .and_then(|a| a.last_window_in)
            .is_some_and(|w| w.raw == 0)
        {
            findings.push("Observed: last captured peer receive window was zero; cause unknown");
        }
        if matches!(
            self.protocol_state,
            super::ProtocolState::Tcp(super::TcpState::SynSent)
        ) && self.packets_received == 0
            && now
                .duration_since(self.created_at)
                .is_ok_and(|age| age >= Duration::from_secs(10))
        {
            findings
                .push("Possible: unanswered connection attempt; capture cannot locate the loss");
        }
        findings.truncate(3);
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(second: u64, inode: u64, receive: u64, drops: u64) -> Arc<SocketSample> {
        Arc::new(SocketSample {
            native_id: inode,
            netns: Some(1),
            tcp: None,
            queues: Some(QueueSample {
                source: "procfs",
                sampled_at: SystemTime::UNIX_EPOCH + Duration::from_secs(second),
                kind: QueueKind::TcpBytes,
                receive,
                send: 0,
                socket_drops: Some(drops),
            }),
        })
    }
    #[test]
    fn tcp_deltas_require_same_source_identity_and_fresh_ordered_samples() {
        let tcp = |second, id, source, total| {
            Arc::new(SocketSample {
                native_id: id,
                netns: Some(1),
                queues: None,
                tcp: Some(TcpSample {
                    counter_reset: false,
                    source,
                    sampled_at: SystemTime::UNIX_EPOCH + Duration::from_secs(second),
                    rtt_us: 100,
                    rtt_variation_us: 10,
                    congestion_window_segments: None,
                    retransmissions: total,
                }),
            })
        };
        let a = ConnectionDiagnostics::update(None, tcp(10, 1, "windows_estats", 40));
        assert_eq!(a.retransmission_increase, None);
        let b = ConnectionDiagnostics::update(Some(&a), tcp(15, 1, "windows_estats", 43));
        assert_eq!(b.retransmission_increase, Some(3));
        let mut restarted = (*tcp(20, 1, "windows_estats", 100)).clone();
        restarted.tcp.as_mut().unwrap().counter_reset = true;
        assert_eq!(
            ConnectionDiagnostics::update(Some(&b), Arc::new(restarted)).retransmission_increase,
            None
        );
        assert_eq!(
            b.findings(SystemTime::UNIX_EPOCH + Duration::from_secs(15)),
            vec!["Observed: kernel TCP retransmissions increased; loss location unknown"]
        );
        assert!(
            b.findings(SystemTime::UNIX_EPOCH + Duration::from_secs(31))
                .is_empty()
        );
        assert_eq!(
            ConnectionDiagnostics::update(Some(&b), Arc::clone(&b.sample)).retransmission_increase,
            Some(3)
        );
        for next in [
            tcp(20, 2, "windows_estats", 50),
            tcp(20, 1, "tcp_bpf_iterator", 50),
            tcp(20, 1, "windows_estats", 1),
            tcp(14, 1, "windows_estats", 50),
            tcp(40, 1, "windows_estats", 50),
        ] {
            assert_eq!(
                ConnectionDiagnostics::update(Some(&b), next).retransmission_increase,
                None
            );
        }
        let mut with_queue = (*a.sample).clone();
        with_queue.queues = sample(10, 1, 0, 0).queues.clone();
        let a = ConnectionDiagnostics::update(None, Arc::new(with_queue.clone()));
        with_queue.tcp = b.sample.tcp.clone();
        // A repeated queue group must not hide a new independent TCP sample.
        assert_eq!(
            ConnectionDiagnostics::update(Some(&a), Arc::new(with_queue)).retransmission_increase,
            Some(3)
        );
    }

    #[test]
    fn persistence_requires_distinct_fresh_samples_and_resets_on_identity_change() {
        let a = ConnectionDiagnostics::update(None, sample(10, 1, 100, 20));
        let repeated = ConnectionDiagnostics::update(Some(&a), sample(10, 1, 100, 20));
        assert_eq!(repeated.nonempty_receive_samples, 1);
        let b = ConnectionDiagnostics::update(Some(&a), sample(15, 1, 100, 22));
        let c = ConnectionDiagnostics::update(Some(&b), sample(20, 1, 100, 22));
        assert_eq!(
            c.findings(SystemTime::UNIX_EPOCH + Duration::from_secs(20))
                .len(),
            1
        );
        assert!(
            c.findings(SystemTime::UNIX_EPOCH + Duration::from_secs(40))
                .is_empty()
        );
        assert_eq!(b.socket_drop_increase, Some(2));
        let reused = ConnectionDiagnostics::update(Some(&c), sample(25, 2, 100, 100));
        assert_eq!(reused.nonempty_receive_samples, 1);
        assert_eq!(reused.socket_drop_increase, None);
        let drained = ConnectionDiagnostics::update(Some(&c), sample(25, 1, 0, 1));
        assert_eq!(drained.nonempty_receive_samples, 0);
        assert_eq!(drained.socket_drop_increase, None);
    }

    #[test]
    fn nonempty_queue_does_not_imply_unread_payload_or_application_cause() {
        // A pending FIN contributes one to the procfs receive queue even
        // when there is no payload waiting for the application.
        let a = ConnectionDiagnostics::update(None, sample(10, 1, 1, 0));
        let b = ConnectionDiagnostics::update(Some(&a), sample(15, 1, 1, 0));
        let mut conn = super::super::Connection::new(
            super::super::Protocol::Tcp,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
            super::super::ProtocolState::Tcp(super::super::TcpState::CloseWait),
        );
        conn.diagnostics = Some(ConnectionDiagnostics::update(Some(&b), sample(20, 1, 1, 0)));
        assert_eq!(
            conn.diagnostic_findings(SystemTime::UNIX_EPOCH + Duration::from_secs(20)),
            vec!["Observed: TCP receive queue remained nonempty across samples; cause unknown"]
        );
    }
}
