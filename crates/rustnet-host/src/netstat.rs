//! FreeBSD's system netstat owns the versioned PCB ABI. Read only byte queues.
use crate::{HostSocket, HostSocketState, HostTcpState, Protocol, SocketScan};
use rustnet_core::network::types::{QueueKind, QueueSample, SocketSample};
use std::{net::SocketAddr, sync::Arc, time::SystemTime};

pub(crate) fn apply_queues(stdout: &str, scan: &mut SocketScan) -> anyhow::Result<()> {
    let mut lines = stdout.lines();
    anyhow::ensure!(
        lines
            .next()
            .is_some_and(|s| s.starts_with("Active Internet connections")),
        "unknown netstat preamble"
    );
    anyhow::ensure!(
        lines
            .next()
            .is_some_and(|s| s.split_whitespace().collect::<Vec<_>>()
                == [
                    "Tcpcb", "Proto", "Recv-Q", "Send-Q", "Local", "Address", "Foreign", "Address",
                    "(state)"
                ]),
        "unknown netstat columns"
    );
    let sampled_at = SystemTime::now();
    // Both scans can contain shared descriptors or reused tuples. Only one
    // inventory row and one measurement row may agree on the exact endpoints.
    let mut rows = std::collections::HashMap::new();
    for line in lines {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 7 || !matches!(parts[1], "tcp4" | "tcp6" | "tcp46") {
            continue;
        }
        let (Some(local), Some(remote)) = (endpoint(parts[4]), endpoint(parts[5])) else {
            continue;
        };
        let value = u64::from_str_radix(parts[0], 16)
            .ok()
            .filter(|id| *id != 0)
            .zip(parts[2].parse::<u64>().ok())
            .zip(parts[3].parse::<u64>().ok());
        rows.entry((local, remote))
            .and_modify(|row| *row = None)
            .or_insert(value);
    }
    let mut counts = std::collections::HashMap::new();
    for socket in &scan.sockets {
        *counts
            .entry((socket.local_addr, socket.remote_addr))
            .or_insert(0) += 1;
    }
    for socket in &mut scan.sockets {
        if socket.protocol != Protocol::Tcp
            || socket.state == HostSocketState::Tcp(HostTcpState::Listen)
            || counts[&(socket.local_addr, socket.remote_addr)] != 1
        {
            continue;
        }
        let Some(remote) = socket.remote_addr else {
            continue;
        };
        let Some(Some(((native_id, receive), send))) = rows.get(&(socket.local_addr, remote))
        else {
            continue;
        };
        socket.native_id = Some(*native_id);
        let sample = SocketSample {
            native_id: *native_id,
            netns: None,
            tcp: None,
            queues: Some(QueueSample {
                source: "netstat",
                sampled_at,
                kind: QueueKind::TcpBytes,
                receive: *receive,
                send: *send,
                socket_drops: None,
            }),
        };
        scan.diagnostics
            .insert(HostSocket::clone(socket), Arc::new(sample));
    }
    Ok(())
}

fn endpoint(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.rsplit_once('.')?;
    Some(SocketAddr::new(ip.parse().ok()?, port.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_queues_and_ambiguity_without_affecting_inventory() {
        let mut scan = crate::sockstat::parse_output(
            "USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS STATE\n1000 server 42 3 tcp4 127.0.0.1:8080 127.0.0.1:5000 ESTABLISHED\n",
            Protocol::Tcp,
        );
        let output = "Active Internet connections (including servers)\nTcpcb Proto Recv-Q Send-Q Local Address Foreign Address (state)\nffff1234 tcp4 128 0 127.0.0.1.8080 127.0.0.1.5000 ESTABLISHED\n";
        apply_queues(output, &mut scan).unwrap();
        assert_eq!(
            scan.diagnostics
                .values()
                .next()
                .unwrap()
                .queues
                .as_ref()
                .unwrap()
                .receive,
            128
        );
        scan.diagnostics.clear();
        apply_queues(
            &format!("{output}ffff5678 tcp4 128 0 127.0.0.1.8080 127.0.0.1.5000 ESTABLISHED\n"),
            &mut scan,
        )
        .unwrap();
        assert!(scan.diagnostics.is_empty());
        assert!(scan.complete);
        assert_eq!(endpoint("::1.8080"), Some("[::1]:8080".parse().unwrap()));
        assert_eq!(endpoint("*.8080"), None);
        assert!(apply_queues("unexpected", &mut scan).is_err());
    }
}
