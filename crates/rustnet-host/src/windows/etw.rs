//! Event-driven Windows process attribution.
//!
//! IP Helper tables are snapshots, so a process can create traffic and exit
//! entirely between two refreshes. The Microsoft-Windows-Kernel-Network ETW
//! provider reports the PID and tuple at the time of the network operation.
//! We retain those tuples briefly and use the process provider to preserve
//! image names across process exit.

use super::process::get_process_name_from_pid;
use crate::ConnectionKey;
use anyhow::{Result, anyhow};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::trace::UserTrace;
use ferrisetw::{EventRecord, SchemaLocator};
use rustnet_core::network::types::Protocol;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const NETWORK_PROVIDER: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const PROCESS_PROVIDER: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const ENTRY_TTL: Duration = Duration::from_secs(60);
const PROCESS_NAME_TTL: Duration = Duration::from_secs(120);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
const UNKNOWN_PROCESS_NAME: &str = "Unknown";

#[derive(Debug, Clone)]
struct TimedProcess {
    pid: u32,
    name: String,
    seen: Instant,
}

#[derive(Debug, Clone)]
struct TimedProcessName {
    name: String,
    seen: Instant,
}

#[derive(Debug)]
struct CacheInner {
    connections: HashMap<ConnectionKey, TimedProcess>,
    process_names: HashMap<u32, TimedProcessName>,
    last_cleanup: Instant,
}

impl Default for CacheInner {
    fn default() -> Self {
        Self {
            connections: HashMap::new(),
            process_names: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct EtwProcessCache {
    inner: RwLock<CacheInner>,
}

impl EtwProcessCache {
    pub(super) fn lookup(&self, key: &ConnectionKey) -> Option<(u32, String)> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            log::warn!("Windows ETW process cache lock was poisoned, recovering data");
            poisoned.into_inner()
        });
        inner.connections.get(key).and_then(|entry| {
            (entry.seen.elapsed() <= ENTRY_TTL).then(|| (entry.pid, entry.name.clone()))
        })
    }

    fn remember_process_name(&self, pid: u32, name: String) {
        if pid == 0 || name.is_empty() {
            return;
        }

        let mut inner = self.inner.write().unwrap_or_else(|poisoned| {
            log::warn!("Windows ETW process cache lock was poisoned, recovering data");
            poisoned.into_inner()
        });
        let name = executable_name(&name);
        inner.process_names.insert(
            pid,
            TimedProcessName {
                name: name.clone(),
                seen: Instant::now(),
            },
        );
        for entry in inner.connections.values_mut() {
            if entry.pid == pid && entry.name == UNKNOWN_PROCESS_NAME {
                entry.name.clone_from(&name);
            }
        }
    }

    fn remember_connection(&self, key: ConnectionKey, pid: u32) {
        if pid == 0 {
            return;
        }

        let now = Instant::now();

        // Send/receive ETW events can arrive for every packet. Once a tuple is
        // attributed, avoid a write lock and allocations until its retention
        // window expires.
        {
            let inner = self.inner.read().unwrap_or_else(|poisoned| {
                log::warn!("Windows ETW process cache lock was poisoned, recovering data");
                poisoned.into_inner()
            });
            if inner.connections.get(&key).is_some_and(|entry| {
                entry.pid == pid && now.duration_since(entry.seen) <= ENTRY_TTL
            }) {
                return;
            }
        }

        let mut inner = self.inner.write().unwrap_or_else(|poisoned| {
            log::warn!("Windows ETW process cache lock was poisoned, recovering data");
            poisoned.into_inner()
        });

        if now.duration_since(inner.last_cleanup) >= CLEANUP_INTERVAL {
            inner
                .connections
                .retain(|_, entry| now.duration_since(entry.seen) <= ENTRY_TTL);
            inner
                .process_names
                .retain(|_, entry| now.duration_since(entry.seen) <= PROCESS_NAME_TTL);
            inner.last_cleanup = now;
        }

        let name = inner
            .process_names
            .get(&pid)
            .map(|entry| entry.name.clone())
            .or_else(|| get_process_name_from_pid(pid))
            .unwrap_or_else(|| UNKNOWN_PROCESS_NAME.to_string());

        inner.process_names.insert(
            pid,
            TimedProcessName {
                name: name.clone(),
                seen: now,
            },
        );
        inner.connections.insert(
            key.clone(),
            TimedProcess {
                pid,
                name: name.clone(),
                seen: now,
            },
        );

        log::trace!(
            "Windows ETW attribution: {:?} {} -> {} (PID: {}, {})",
            key.protocol,
            key.local_addr,
            key.remote_addr,
            pid,
            name
        );
    }
}

pub(super) struct EtwAttribution {
    // Dropping the trace stops the real-time session.
    _trace: UserTrace,
}

impl EtwAttribution {
    pub(super) fn start(cache: Arc<EtwProcessCache>) -> Result<Self> {
        let network_cache = Arc::clone(&cache);
        let network_provider = Provider::by_guid(NETWORK_PROVIDER)
            .add_callback(move |record, schema_locator| {
                process_network_event(record, schema_locator, &network_cache)
            })
            .build();

        let process_cache = cache;
        let process_provider = Provider::by_guid(PROCESS_PROVIDER)
            .add_callback(move |record, schema_locator| {
                process_lifecycle_event(record, schema_locator, &process_cache)
            })
            .build();

        let trace = UserTrace::new()
            .enable(network_provider)
            .enable(process_provider)
            .start_and_process()
            .map_err(|error| anyhow!("failed to start Windows ETW attribution: {error:?}"))?;

        Ok(Self { _trace: trace })
    }
}

fn process_network_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    cache: &EtwProcessCache,
) {
    let event_id = record.event_id();
    let (protocol, incoming) = match event_id {
        // TCP IPv4 and IPv6. Receive and accept tuples are oriented from the
        // peer to the local host; the other operations are local-to-remote.
        10 | 12 | 13 | 14 | 16 | 26 | 28 | 29 | 30 | 32 => (Protocol::Tcp, false),
        11 | 15 | 27 | 31 => (Protocol::Tcp, true),
        // UDP IPv4 and IPv6.
        42 | 58 => (Protocol::Udp, false),
        43 | 59 => (Protocol::Udp, true),
        _ => return,
    };

    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let (Ok(pid), Ok(source_ip), Ok(destination_ip), Ok(source_port), Ok(destination_port)) = (
        parser.try_parse::<u32>("PID"),
        parser.try_parse::<IpAddr>("saddr"),
        parser.try_parse::<IpAddr>("daddr"),
        parser.try_parse::<u16>("sport"),
        parser.try_parse::<u16>("dport"),
    ) else {
        return;
    };

    // ETW stores the MOF "Port" fields in network byte order.
    let source = SocketAddr::new(source_ip, u16::from_be(source_port));
    let destination = SocketAddr::new(destination_ip, u16::from_be(destination_port));
    let (local_addr, remote_addr) = if incoming {
        (destination, source)
    } else {
        (source, destination)
    };

    cache.remember_connection(
        ConnectionKey {
            protocol,
            local_addr,
            remote_addr,
        },
        pid,
    );
}

fn process_lifecycle_event(
    record: &EventRecord,
    schema_locator: &SchemaLocator,
    cache: &EtwProcessCache,
) {
    let Ok(schema) = schema_locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);

    let pid = parser
        .try_parse::<u32>("ProcessID")
        .or_else(|_| parser.try_parse::<u32>("ProcessId"));
    let image_name = parser
        .try_parse::<String>("ImageName")
        .or_else(|_| parser.try_parse::<String>("ImageFileName"));

    if let (Ok(pid), Ok(image_name)) = (pid, image_name) {
        cache.remember_process_name(pid, image_name);
    }
}

fn executable_name(path: &str) -> String {
    path.trim_end_matches('\0')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::thread;

    #[test]
    fn executable_name_handles_windows_and_nt_paths() {
        assert_eq!(
            executable_name(r"C:\Program Files\App\worker.exe"),
            "worker.exe"
        );
        assert_eq!(
            executable_name(r"\Device\HarddiskVolume3\tool.exe"),
            "tool.exe"
        );
        assert_eq!(executable_name("plain.exe"), "plain.exe");
    }

    #[test]
    fn lifecycle_name_upgrades_pid_only_attribution() {
        let cache = EtwProcessCache::default();
        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1:45000".parse().unwrap(),
            remote_addr: "127.0.0.1:443".parse().unwrap(),
        };
        let pid = u32::MAX;

        cache.remember_connection(key.clone(), pid);
        assert_eq!(cache.lookup(&key), Some((pid, "Unknown".to_string())));

        cache.remember_process_name(pid, r"C:\Tools\short-lived.exe".to_string());
        assert_eq!(
            cache.lookup(&key),
            Some((pid, "short-lived.exe".to_string()))
        );
    }

    #[test]
    fn captures_live_udp_tuple_when_etw_is_available() {
        let cache = Arc::new(EtwProcessCache::default());
        let _trace = match EtwAttribution::start(Arc::clone(&cache)) {
            Ok(trace) => trace,
            Err(error) => {
                // ETW requires trace-session privileges. The production path
                // has the same graceful IP Helper fallback when unavailable.
                eprintln!("skipping live ETW test: {error}");
                return;
            }
        };

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let local_addr = sender.local_addr().unwrap();
        let remote_addr = receiver.local_addr().unwrap();
        sender.send_to(b"rustnet-etw-test", remote_addr).unwrap();

        let key = ConnectionKey {
            protocol: Protocol::Udp,
            local_addr,
            remote_addr,
        };
        let process = (0..50).find_map(|_| {
            let process = cache.lookup(&key);
            if process.is_none() {
                thread::sleep(Duration::from_millis(20));
            }
            process
        });

        assert_eq!(process.map(|entry| entry.0), Some(std::process::id()));
    }
}
