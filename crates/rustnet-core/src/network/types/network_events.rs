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
    counts: [DirectionalCount; 7],
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
