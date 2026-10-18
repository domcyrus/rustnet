//! One optional EStats category, sampled during the existing inventory refresh.
use crate::{HostSocket, HostSocketState, HostTcpState, SocketSnapshot};
use rustnet_core::network::types::{SocketSample, TcpSample};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, MIB_TCP_STATE, MIB_TCP6ROW,
    MIB_TCPROW_LH, SetPerTcp6ConnectionEStats, SetPerTcpConnectionEStats, TCP_ESTATS_PATH_ROD_v0,
    TcpConnectionEstatsPath,
};

pub(super) fn sample(snapshot: &mut SocketSnapshot) {
    let started = Instant::now();
    let mut unavailable = 0;
    let mut last_error = None;
    let mut truncated = false;
    let samples = Arc::make_mut(&mut snapshot.diagnostics);
    for socket in snapshot
        .sockets
        .iter()
        .filter(|s| s.state == HostSocketState::Tcp(HostTcpState::Established))
    {
        if started.elapsed() > Duration::from_secs(2) {
            truncated = true;
            break;
        }
        let Some(native_id) = socket.native_id else {
            unavailable += 1;
            continue;
        };
        match path_sample(socket) {
            Ok(tcp) => {
                samples.insert(
                    socket.clone(),
                    Arc::new(SocketSample {
                        native_id,
                        netns: None,
                        queues: None,
                        tcp: Some(tcp),
                    }),
                );
            }
            Err(code) => {
                unavailable += 1;
                last_error = Some(code);
            }
        }
    }
    snapshot.diagnostics_status.tcp = format!(
        "EStats Path: {} sampled, {unavailable} unavailable{}{}; enabling collection requires elevation",
        samples.len(),
        last_error.map_or_else(String::new, |code| format!(" (Win32 {code})")),
        if truncated {
            "; refresh deadline reached"
        } else {
            ""
        },
    );
}

fn path_sample(socket: &HostSocket) -> Result<TcpSample, u32> {
    let remote = socket.remote_addr.ok_or(87u32)?;
    // SAFETY: rows are initialized from numeric IP Helper inventory, including
    // IPv6 scope IDs and network-order ports. Buffers have exact v0 sizes.
    unsafe {
        match (socket.local_addr, remote) {
            (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
                let row = MIB_TCPROW_LH {
                    dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
                    dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
                    dwLocalPort: u32::from(local.port().to_be()),
                    dwRemotePort: u32::from(remote.port().to_be()),
                    ..Default::default()
                };
                read_path(
                    |rw, rod| {
                        GetPerTcpConnectionEStats(
                            &row,
                            TcpConnectionEstatsPath,
                            Some(rw),
                            0,
                            None,
                            0,
                            Some(rod),
                            0,
                        )
                    },
                    || SetPerTcpConnectionEStats(&row, TcpConnectionEstatsPath, &[1], 0, 0),
                )
            }
            (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
                let mut row = MIB_TCP6ROW {
                    State: MIB_TCP_STATE(5),
                    dwLocalScopeId: local.scope_id(),
                    dwRemoteScopeId: remote.scope_id(),
                    dwLocalPort: u32::from(local.port().to_be()),
                    dwRemotePort: u32::from(remote.port().to_be()),
                    ..Default::default()
                };
                row.LocalAddr.u.Byte = local.ip().octets();
                row.RemoteAddr.u.Byte = remote.ip().octets();
                read_path(
                    |rw, rod| {
                        GetPerTcp6ConnectionEStats(
                            &row,
                            TcpConnectionEstatsPath,
                            Some(rw),
                            0,
                            None,
                            0,
                            Some(rod),
                            0,
                        )
                    },
                    || SetPerTcp6ConnectionEStats(&row, TcpConnectionEstatsPath, &[1], 0, 0),
                )
            }
            _ => Err(87),
        }
    }
}

fn read_path(
    mut get: impl FnMut(&mut [u8], &mut [u8]) -> u32,
    enable: impl FnOnce() -> u32,
) -> Result<TcpSample, u32> {
    let mut rw = [0u8]; // TCP_ESTATS_PATH_RW_v0 is a single BOOLEAN.
    let mut path = TCP_ESTATS_PATH_ROD_v0::default();
    // SAFETY: PATH_ROD_v0 contains only ULONG fields, all initialized. The
    // slice covers exactly this aligned writable object and cannot escape.
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            (&mut path as *mut TCP_ESTATS_PATH_ROD_v0).cast::<u8>(),
            std::mem::size_of_val(&path),
        )
    };
    let result = get(&mut rw, bytes);
    if result != 0 {
        return Err(result);
    }
    if rw[0] == 0 {
        let result = enable();
        if result != 0 {
            return Err(result);
        }
        // Do not reset existing collection, disable another consumer's
        // collection, or interpret the disabled group's undefined fields.
        let result = get(&mut rw, bytes);
        if result != 0 {
            return Err(result);
        }
        if rw[0] == 0 {
            return Err(50);
        }
    }
    Ok(TcpSample {
        source: "windows_estats",
        sampled_at: SystemTime::now(),
        // Path RTT units are milliseconds, unlike Linux's microseconds.
        rtt_us: path.SmoothedRtt.checked_mul(1000).ok_or(13u32)?,
        rtt_variation_us: path.RttVar.checked_mul(1000).ok_or(13u32)?,
        congestion_window_segments: None,
        retransmissions: path.PktsRetrans,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabled_collection_never_becomes_a_zero_sample() {
        assert!(matches!(
            read_path(
                |rw, _| {
                    rw[0] = 0;
                    0
                },
                || 5
            ),
            Err(5)
        ));
        assert!(matches!(
            read_path(|_, _| 50, || panic!("failed read must not enable")),
            Err(50)
        ));
        assert!(matches!(
            read_path(
                |rw, _| {
                    rw[0] = 0;
                    0
                },
                || 0
            ),
            Err(50)
        ));
    }

    #[test]
    fn enabled_path_preserves_collection_and_converts_units() {
        let sample = read_path(
            |rw, bytes| {
                rw[0] = 1;
                let mut put = |offset: usize, value: u32| {
                    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes())
                };
                put(
                    std::mem::offset_of!(TCP_ESTATS_PATH_ROD_v0, SmoothedRtt),
                    12,
                );
                put(std::mem::offset_of!(TCP_ESTATS_PATH_ROD_v0, RttVar), 3);
                put(std::mem::offset_of!(TCP_ESTATS_PATH_ROD_v0, PktsRetrans), 7);
                0
            },
            || panic!("must not reset existing collection"),
        )
        .unwrap();
        assert_eq!(
            (
                sample.rtt_us,
                sample.rtt_variation_us,
                sample.retransmissions
            ),
            (12000, 3000, 7)
        );
        assert!(sample.congestion_window_segments.is_none());
    }
}
