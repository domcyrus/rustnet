//! Optional established-TCP samples. The link is prepared before privilege drop.
use crate::{ConnectionKey, SocketSnapshot};
use anyhow::{Context, Result, ensure};
use libbpf_rs::{Iter, IterOpts, Link, Object, ObjectBuilder};
use rustnet_core::network::types::{Protocol, TcpSample};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

const RECORD_SIZE: usize = 72;
const MAX_RECORDS: u64 = 100_000;

pub(in crate::linux) struct TcpIterator {
    link: Link,
    _object: Object,
}
impl TcpIterator {
    pub(in crate::linux) fn load() -> Result<Self> {
        let object = ObjectBuilder::default()
            .open_memory(include_bytes!(concat!(
                env!("OUT_DIR"),
                "/socket_tracker_tcp_stats.bpf.o"
            )))?
            .load()
            .context("load TCP iterator")?;
        let link = object
            .progs_mut()
            .next()
            .context("missing TCP iterator")?
            .attach_iter_with_opts(IterOpts::None)
            .context("attach TCP iterator")?;
        Ok(Self {
            link,
            _object: object,
        })
    }

    pub(in crate::linux) fn sample(
        &self,
        snapshot: &mut SocketSnapshot,
        cancelled: &AtomicBool,
    ) -> Result<()> {
        let mut reader = std::io::BufReader::with_capacity(
            64 * 1024,
            Iter::new(&self.link).context("open TCP iterator reader")?,
        );
        let records = read_records(&mut reader, cancelled)?;
        let sockets: std::collections::HashMap<_, _> = snapshot
            .sockets
            .iter()
            .filter_map(|s| Some((s.native_id?, s)))
            .collect();
        let samples = Arc::make_mut(&mut snapshot.diagnostics);
        for (inode, netns, key, tcp) in records {
            let Some(socket) = sockets.get(&inode) else {
                continue;
            };
            if socket.protocol != key.protocol
                || socket.local_addr != key.local_addr
                || socket.remote_addr != Some(key.remote_addr)
            {
                continue;
            }
            let Some(sample) = samples.get_mut(&inode) else {
                continue;
            };
            if sample.netns != Some(netns) {
                continue;
            }
            Arc::make_mut(sample).tcp = Some(tcp);
        }
        Ok(())
    }
}

fn read_records(
    reader: &mut impl Read,
    cancelled: &AtomicBool,
) -> Result<Vec<(u64, u64, ConnectionKey, TcpSample)>> {
    let started = Instant::now();
    let sampled_at = SystemTime::now();
    // A bounded temporary result avoids publishing a partially read stream.
    let mut records = Vec::new();
    for _ in 0..=MAX_RECORDS {
        ensure!(!cancelled.load(Ordering::Relaxed), "TCP sampling cancelled");
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "TCP sampling deadline exceeded"
        );
        let mut record = [0; RECORD_SIZE];
        let first = reader.read(&mut record[..1])?;
        if first == 0 {
            break;
        }
        reader
            .read_exact(&mut record[1..])
            .context("truncated TCP sample")?;
        records.push(decode(&record, sampled_at)?);
    }
    ensure!(
        records.len() <= MAX_RECORDS as usize,
        "TCP sample limit exceeded"
    );
    Ok(records)
}

fn decode(
    record: &[u8; RECORD_SIZE],
    sampled_at: SystemTime,
) -> Result<(u64, u64, ConnectionKey, TcpSample)> {
    let u32_at = |offset| u32::from_ne_bytes(record[offset..offset + 4].try_into().unwrap());
    let family = u32_at(12);
    let addr = |offset| -> Result<IpAddr> {
        Ok(match family {
            2 => Ipv4Addr::from(<[u8; 4]>::try_from(&record[offset..offset + 4])?).into(),
            10 => Ipv6Addr::from(<[u8; 16]>::try_from(&record[offset..offset + 16])?).into(),
            _ => anyhow::bail!("unknown TCP address family {family}"),
        })
    };
    let inode = u64::from_ne_bytes(record[..8].try_into()?);
    ensure!(inode != 0, "missing TCP socket identity");
    Ok((
        inode,
        u64::from(u32_at(8)),
        ConnectionKey {
            protocol: Protocol::Tcp,
            local_addr: SocketAddr::new(addr(16)?, u16::from_ne_bytes(record[48..50].try_into()?)),
            remote_addr: SocketAddr::new(addr(32)?, u16::from_ne_bytes(record[50..52].try_into()?)),
        },
        TcpSample {
            sampled_at,
            rtt_us: u32_at(52),
            rtt_variation_us: u32_at(56),
            congestion_window_segments: u32_at(60),
            retransmissions: u32_at(64),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stream_rejects_truncated_records_and_honors_cancellation() {
        let mut record = [0; RECORD_SIZE];
        record[..8].copy_from_slice(&1_u64.to_ne_bytes());
        record[12..16].copy_from_slice(&2_u32.to_ne_bytes());
        let cancelled = AtomicBool::new(false);
        assert!(read_records(&mut &[][..], &cancelled).unwrap().is_empty());
        assert_eq!(read_records(&mut &record[..], &cancelled).unwrap().len(), 1);
        // A complete first record must not hide a truncated second record.
        let mut partial = record.to_vec();
        partial.extend_from_slice(&record[..RECORD_SIZE - 1]);
        assert!(read_records(&mut &partial[..], &cancelled).is_err());
        cancelled.store(true, Ordering::Relaxed);
        assert!(read_records(&mut &record[..], &cancelled).is_err());
    }

    #[test]
    fn record_identity_uses_native_integers_and_network_address_bytes() {
        let mut record = [0; RECORD_SIZE];
        record[..8].copy_from_slice(&123_u64.to_ne_bytes());
        record[8..12].copy_from_slice(&456_u32.to_ne_bytes());
        record[12..16].copy_from_slice(&2_u32.to_ne_bytes());
        record[16..20].copy_from_slice(&[127, 0, 0, 1]);
        record[32..36].copy_from_slice(&[192, 0, 2, 1]);
        record[48..50].copy_from_slice(&8080_u16.to_ne_bytes());
        record[50..52].copy_from_slice(&443_u16.to_ne_bytes());
        record[52..56].copy_from_slice(&100_u32.to_ne_bytes());
        let (inode, netns, key, sample) = decode(&record, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!((inode, netns), (123, 456));
        assert_eq!(key.local_addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(key.remote_addr, "192.0.2.1:443".parse().unwrap());
        assert_eq!(sample.rtt_us, 100);
        record[12..16].copy_from_slice(&10_u32.to_ne_bytes());
        record[16..32].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        record[32..48].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        let (_, _, key, _) = decode(&record, SystemTime::UNIX_EPOCH).unwrap();
        assert_eq!(key.local_addr, "[::1]:8080".parse().unwrap());
        assert_eq!(key.remote_addr, "[2001:db8::1]:443".parse().unwrap());
        record[12..16].copy_from_slice(&123_u32.to_ne_bytes());
        assert!(decode(&record, SystemTime::UNIX_EPOCH).is_err());
    }
}
