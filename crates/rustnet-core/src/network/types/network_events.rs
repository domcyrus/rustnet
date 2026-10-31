//! Passive packet observations, not firewall verdicts or socket state.

use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkEventKind {
    TcpReset,
    PortUnreachable,
    DestinationUnreachable,
    AdministrativelyProhibited,
    PacketTooBig,
    TimeExceeded,
    ParameterProblem,
}

impl NetworkEventKind {
    pub const ALL: [Self; 7] = [
        Self::TcpReset,
        Self::PortUnreachable,
        Self::DestinationUnreachable,
        Self::AdministrativelyProhibited,
        Self::PacketTooBig,
        Self::TimeExceeded,
        Self::ParameterProblem,
    ];

    /// Group equivalent IPv4/IPv6 errors without losing their original code.
    pub fn from_icmp(ipv6: bool, message_type: u8, code: u8) -> Option<Self> {
        match (ipv6, message_type, code) {
            (false, 3, 3) | (true, 1, 4) => Some(Self::PortUnreachable),
            (false, 3, 9 | 10 | 13) | (true, 1, 1 | 5 | 6) => {
                Some(Self::AdministrativelyProhibited)
            }
            (false, 3, 4) | (true, 2, _) => Some(Self::PacketTooBig),
            (false, 3, _) | (true, 1, _) => Some(Self::DestinationUnreachable),
            (false, 11, _) | (true, 3, _) => Some(Self::TimeExceeded),
            (false, 12, _) | (true, 4, _) => Some(Self::ParameterProblem),
            _ => None,
        }
    }
}

static_names! {
    NetworkEventKind {
        TcpReset => "TCP reset",
        PortUnreachable => "ICMP port unreachable",
        DestinationUnreachable => "ICMP destination unreachable",
        AdministrativelyProhibited => "ICMP administratively prohibited",
        PacketTooBig => "ICMP packet too big / frag needed",
        TimeExceeded => "ICMP time exceeded",
        ParameterProblem => "ICMP parameter problem",
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DirectionalCount {
    pub sent: u64,
    pub received: u64,
}

impl DirectionalCount {
    pub fn record(&mut self, outgoing: bool) {
        let count = if outgoing {
            &mut self.sent
        } else {
            &mut self.received
        };
        *count = count.saturating_add(1);
    }
}

/// Fixed-size packet counters, retained until the tracker is cleared.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEventCounts {
    counts: [DirectionalCount; NetworkEventKind::ALL.len()],
}

impl NetworkEventCounts {
    pub fn record(&mut self, kind: NetworkEventKind, outgoing: bool) {
        self.counts[kind as usize].record(outgoing);
    }

    pub fn observed(&self) -> impl Iterator<Item = (NetworkEventKind, DirectionalCount)> + '_ {
        NetworkEventKind::ALL.into_iter().filter_map(|kind| {
            let count = self.counts[kind as usize];
            (count.sent != 0 || count.received != 0).then_some((kind, count))
        })
    }
}

/// Selected-window observations alongside the cumulative Rustnet total.
#[derive(Debug, Clone)]
pub struct NetworkEventSnapshot {
    pub selected: NetworkEventCounts,
    pub total: NetworkEventCounts,
    pub since_clear: bool,
}

const NETWORK_EVENT_COUNTERS: usize = NetworkEventKind::ALL.len() * 2;

#[derive(Debug, Default)]
pub(crate) struct NetworkEventHistory {
    history: super::super::time_window::CounterHistory<NETWORK_EVENT_COUNTERS>,
}

impl NetworkEventHistory {
    pub fn record(&mut self, kind: NetworkEventKind, outgoing: bool, now: SystemTime) {
        let mut delta = [0; NETWORK_EVENT_COUNTERS];
        delta[kind as usize * 2 + usize::from(!outgoing)] = 1;
        self.history.record(now, delta);
    }

    pub fn snapshot(
        &self,
        now: SystemTime,
        window: super::super::time_window::TimeWindow,
    ) -> NetworkEventSnapshot {
        use super::super::time_window::TimeWindow;
        let convert = |values: [u64; NETWORK_EVENT_COUNTERS]| NetworkEventCounts {
            counts: std::array::from_fn(|index| DirectionalCount {
                sent: values[index * 2],
                received: values[index * 2 + 1],
            }),
        };
        NetworkEventSnapshot {
            selected: convert(self.history.counts(now, window)),
            total: convert(self.history.counts(now, TimeWindow::SinceStartup)),
            since_clear: self.history.since_clear,
        }
    }

    pub fn clear(&mut self) {
        self.history.clear();
    }
}

impl NetworkEventCounts {
    pub fn get(&self, kind: NetworkEventKind) -> DirectionalCount {
        self.counts[kind as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpError {
    pub ipv6: bool,
    pub message_type: u8,
    pub code: u8,
    pub kind: NetworkEventKind,
    pub reporter: IpAddr,
    pub mtu: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct ObservedIcmpError {
    pub error: IcmpError,
    pub outgoing: bool,
    pub observed_at: SystemTime,
}

/// Allocated only for connections with an observed event. No event history
/// grows with traffic; retain counts and the latest ICMP error only.
#[derive(Debug, Default, Clone)]
pub struct ConnectionNetworkEvents {
    pub tcp_resets: DirectionalCount,
    pub icmp_errors: DirectionalCount,
    pub latest_icmp: Option<ObservedIcmpError>,
}

impl ConnectionNetworkEvents {
    pub fn record_icmp(&mut self, error: IcmpError, outgoing: bool, observed_at: SystemTime) {
        self.icmp_errors.record(outgoing);
        if self
            .latest_icmp
            .is_none_or(|last| observed_at >= last.observed_at)
        {
            self.latest_icmp = Some(ObservedIcmpError {
                error,
                outgoing,
                observed_at,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_errors_across_ip_versions_and_excludes_control_messages() {
        for (kind, v4, v6) in [
            (NetworkEventKind::PortUnreachable, (3, 3), (1, 4)),
            (NetworkEventKind::DestinationUnreachable, (3, 1), (1, 0)),
            (
                NetworkEventKind::AdministrativelyProhibited,
                (3, 13),
                (1, 1),
            ),
            (NetworkEventKind::PacketTooBig, (3, 4), (2, 0)),
            (NetworkEventKind::TimeExceeded, (11, 0), (3, 0)),
            (NetworkEventKind::ParameterProblem, (12, 0), (4, 0)),
        ] {
            assert_eq!(NetworkEventKind::from_icmp(false, v4.0, v4.1), Some(kind));
            assert_eq!(NetworkEventKind::from_icmp(true, v6.0, v6.1), Some(kind));
        }
        for (ipv6, message_type) in [
            (false, 0),
            (false, 8),
            (false, 5),
            (true, 128),
            (true, 129),
            (true, 135),
            (true, 136),
        ] {
            assert_eq!(NetworkEventKind::from_icmp(ipv6, message_type, 0), None);
        }
    }
}

#[cfg(test)]
mod history_tests {
    use super::*;
    use crate::network::time_window::TimeWindow;
    use std::time::Duration;

    #[test]
    fn selected_events_expire_but_totals_remain_until_clear() {
        let mut history = NetworkEventHistory::default();
        let start = SystemTime::UNIX_EPOCH;
        history.record(NetworkEventKind::TcpReset, true, start);
        history.record(
            NetworkEventKind::PortUnreachable,
            false,
            start + Duration::from_secs(100),
        );
        let snapshot = history.snapshot(start + Duration::from_secs(100), TimeWindow::OneMinute);
        assert_eq!(snapshot.selected.get(NetworkEventKind::TcpReset).sent, 0);
        assert_eq!(snapshot.total.get(NetworkEventKind::TcpReset).sent, 1);
        assert_eq!(
            snapshot
                .selected
                .get(NetworkEventKind::PortUnreachable)
                .received,
            1
        );
        for window in [
            TimeWindow::FiveMinutes,
            TimeWindow::OneHour,
            TimeWindow::SinceStartup,
        ] {
            let snapshot = history.snapshot(start + Duration::from_secs(100), window);
            assert_eq!(snapshot.selected, snapshot.total);
        }
        history.clear();
        let snapshot = history.snapshot(start + Duration::from_secs(100), TimeWindow::SinceStartup);
        assert!(snapshot.since_clear);
        assert_eq!(snapshot.total, NetworkEventCounts::default());
        assert_eq!(snapshot.selected, snapshot.total);
    }
}
