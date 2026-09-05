//! DNS resolver with background async resolution and caching.
//!
//! Provides non-blocking reverse DNS lookups with an LRU cache to avoid
//! repeated lookups for the same IP address.

use crate::network::bogon::{Scope, classify};
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use dns_lookup::lookup_addr;
use log::debug;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Resolution state for a cached entry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolutionState {
    /// Resolution is in progress
    Pending,
    /// Resolution succeeded
    Resolved,
    /// Resolution failed
    Failed,
}

#[derive(Debug, Clone, Copy)]
struct ResolutionRequest {
    ip: IpAddr,
    reserved_at: Instant,
}

type Worker = Box<dyn FnOnce() + Send + 'static>;
type StartupGate = Arc<(Mutex<Option<bool>>, Condvar)>;

fn wait_for_startup(gate: &StartupGate) -> bool {
    let (state, ready) = &**gate;
    let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
    while state.is_none() {
        state = ready.wait(state).unwrap_or_else(|error| error.into_inner());
    }
    state.unwrap_or(false)
}

fn release_startup_gate(gate: &StartupGate, start: bool) {
    let (state, ready) = &**gate;
    *state.lock().unwrap_or_else(|error| error.into_inner()) = Some(start);
    ready.notify_all();
}

/// Cached hostname entry
#[derive(Debug, Clone)]
pub(crate) struct CachedHostname {
    /// The resolved hostname, if successful
    pub hostname: Option<String>,
    /// When this entry was resolved
    pub resolved_at: Instant,
    /// Current resolution state
    pub state: ResolutionState,
}

/// How long a `Pending` entry is trusted before the lookup is considered
/// lost and the address may be queued again.
const PENDING_TIMEOUT: Duration = Duration::from_secs(30);

impl CachedHostname {
    /// Whether this entry still answers for its address: resolved names live
    /// for `cache_ttl`, failures for `negative_cache_ttl`, and in-flight
    /// lookups for [`PENDING_TIMEOUT`].
    fn is_fresh(&self, cache_ttl: Duration, negative_cache_ttl: Duration) -> bool {
        let age = self.resolved_at.elapsed();
        match self.state {
            ResolutionState::Resolved => age < cache_ttl,
            ResolutionState::Failed => age < negative_cache_ttl,
            ResolutionState::Pending => age < PENDING_TIMEOUT,
        }
    }

    fn pending() -> Self {
        Self {
            hostname: None,
            resolved_at: Instant::now(),
            state: ResolutionState::Pending,
        }
    }

    fn resolved(hostname: String) -> Self {
        Self {
            hostname: Some(hostname),
            resolved_at: Instant::now(),
            state: ResolutionState::Resolved,
        }
    }

    fn failed() -> Self {
        Self {
            hostname: None,
            resolved_at: Instant::now(),
            state: ResolutionState::Failed,
        }
    }
}

/// Configuration for DNS resolver
#[derive(Debug, Clone)]
pub(crate) struct DnsResolverConfig {
    /// Cache TTL for resolved hostnames (default: 5 minutes)
    pub cache_ttl: Duration,
    /// Cache TTL for failed lookups (default: 1 minute)
    pub negative_cache_ttl: Duration,
    /// Maximum cache size (default: 10000 entries)
    pub max_cache_size: usize,
    /// Maximum queued lookup requests (default: 10000 entries)
    pub request_queue_capacity: usize,
    /// Number of resolver threads (default: 4)
    pub resolver_threads: usize,
    /// Total time allowed for all DNS workers to stop (default: 1 second)
    pub shutdown_timeout: Duration,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(300),         // 5 minutes
            negative_cache_ttl: Duration::from_secs(60), // 1 minute
            max_cache_size: 10000,
            request_queue_capacity: 10000,
            resolver_threads: 4,
            shutdown_timeout: Duration::from_secs(1),
        }
    }
}

#[derive(Default)]
struct DnsResolverLifecycle {
    started: bool,
    stopped: bool,
    handles: Vec<JoinHandle<()>>,
    stop_report: Option<DnsStopReport>,
}

/// Outcome of stopping the DNS resolver's background workers.
///
/// A worker is counted exactly once. Successfully joined workers contribute to
/// `joined`, workers whose join observed a panic contribute to `panicked`, and
/// workers still running when the shared shutdown deadline expires contribute
/// to `timed_out`. Timed-out worker handles are detached because a blocking
/// system resolver call cannot be forcibly cancelled safely.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsStopReport {
    /// Workers that exited and were joined successfully.
    pub joined: usize,
    /// Workers that exited with a panic.
    pub panicked: usize,
    /// Workers detached after the shutdown deadline expired.
    pub timed_out: usize,
}

/// Background DNS resolver with caching
pub struct DnsResolver {
    /// Hostname cache: IP -> CachedHostname
    cache: Arc<DashMap<IpAddr, CachedHostname>>,
    /// Channel to send IPs for resolution
    request_tx: Sender<ResolutionRequest>,
    /// Channel consumed by resolver threads once background work is started
    request_rx: Receiver<ResolutionRequest>,
    /// Startup, shutdown, and worker ownership
    lifecycle: Mutex<DnsResolverLifecycle>,
    /// Control flag for shutdown
    should_stop: Arc<AtomicBool>,
    /// Configuration
    config: DnsResolverConfig,
}

impl DnsResolver {
    /// Build a DNS resolver without starting background threads.
    fn new_deferred(config: DnsResolverConfig) -> Self {
        let cache = Arc::new(DashMap::new());
        let (request_tx, request_rx) = channel::bounded(config.request_queue_capacity);
        let should_stop = Arc::new(AtomicBool::new(false));

        Self {
            cache,
            request_tx,
            request_rx,
            lifecycle: Mutex::new(DnsResolverLifecycle::default()),
            should_stop,
            config,
        }
    }

    /// Create and start a DNS resolver with the given configuration.
    pub(crate) fn new(config: DnsResolverConfig) -> anyhow::Result<Self> {
        let resolver = Self::new_deferred(config);
        resolver.start()?;
        Ok(resolver)
    }

    /// Create a DNS resolver that will not spawn background threads until
    /// [`DnsResolver::start`] is called.
    ///
    /// This is intended for runtimes that must finish privileged setup and
    /// apply a process sandbox before starting general worker threads.
    pub fn with_defaults_deferred() -> Self {
        Self::new_deferred(DnsResolverConfig::default())
    }

    /// Create and start a DNS resolver with default configuration.
    ///
    /// This compatibility constructor logs a worker startup failure and returns
    /// the inactive resolver so callers can retry [`Self::start`]. Call
    /// [`Self::try_with_defaults`] when startup failure must be propagated.
    pub fn with_defaults() -> Self {
        let resolver = Self::with_defaults_deferred();
        if let Err(error) = resolver.start() {
            log::error!("Failed to start DNS resolver: {error}");
        }
        resolver
    }

    /// Create and start a DNS resolver, propagating worker startup failure.
    pub fn try_with_defaults() -> anyhow::Result<Self> {
        Self::new(DnsResolverConfig::default())
    }

    /// Start the background resolver and cache-cleanup threads.
    ///
    /// Starting is idempotent. A resolver that has already been stopped cannot
    /// be restarted.
    ///
    /// Returns an error if a worker cannot be spawned. Workers staged before
    /// that failure are stopped and joined before the error is returned.
    pub fn start(&self) -> anyhow::Result<()> {
        self.start_with_spawner(|name, worker| thread::Builder::new().name(name).spawn(worker))
    }

    fn start_with_spawner(
        &self,
        mut spawn: impl FnMut(String, Worker) -> std::io::Result<JoinHandle<()>>,
    ) -> anyhow::Result<()> {
        let mut lifecycle = self
            .lifecycle
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if lifecycle.started || lifecycle.stopped || self.should_stop.load(Ordering::Acquire) {
            return Ok(());
        }

        // Staged workers wait here until every spawn succeeds. If a later spawn
        // fails, the workers are released directly into their exit path and can
        // all be joined without starting a potentially blocking resolver call.
        let startup_gate = Arc::new((Mutex::new(None), Condvar::new()));
        let mut handles = Vec::with_capacity(self.config.resolver_threads + 1);

        for index in 0..self.config.resolver_threads {
            let rx = self.request_rx.clone();
            let cache = Arc::clone(&self.cache);
            let should_stop = Arc::clone(&self.should_stop);
            let worker_gate = Arc::clone(&startup_gate);

            let worker: Worker = Box::new(move || {
                if !wait_for_startup(&worker_gate) {
                    return;
                }

                debug!("DNS resolver thread {} started", index);

                while !should_stop.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(request) => {
                            let reservation_is_current =
                                cache.get(&request.ip).is_some_and(|entry| {
                                    entry.state == ResolutionState::Pending
                                        && entry.resolved_at == request.reserved_at
                                });
                            if !reservation_is_current {
                                continue;
                            }

                            let result = match lookup_addr(&request.ip) {
                                Ok(hostname) => {
                                    debug!("Resolved {} -> {}", request.ip, hostname);
                                    CachedHostname::resolved(hostname)
                                }
                                Err(error) => {
                                    debug!("Failed to resolve {}: {}", request.ip, error);
                                    CachedHostname::failed()
                                }
                            };

                            // A timed-out reservation may have been superseded
                            // while the system resolver was blocked. Never let
                            // its late result overwrite the newer generation.
                            if let Entry::Occupied(mut entry) = cache.entry(request.ip)
                                && entry.get().state == ResolutionState::Pending
                                && entry.get().resolved_at == request.reserved_at
                            {
                                entry.insert(result);
                            }
                        }
                        Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                        Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
                    }
                }

                debug!("DNS resolver thread {} stopping", index);
            });

            match spawn(format!("dns-resolver-{index}"), worker) {
                Ok(handle) => handles.push(handle),
                Err(error) => {
                    return Err(Self::rollback_failed_start(&startup_gate, handles, error));
                }
            }
        }

        let cache = Arc::clone(&self.cache);
        let should_stop = Arc::clone(&self.should_stop);
        let cache_ttl = self.config.cache_ttl;
        let negative_cache_ttl = self.config.negative_cache_ttl;
        let max_cache_size = self.config.max_cache_size;
        let worker_gate = Arc::clone(&startup_gate);
        let cleanup: Worker = Box::new(move || {
            if !wait_for_startup(&worker_gate) {
                return;
            }

            debug!("DNS cache cleanup thread started");

            while !should_stop.load(Ordering::Relaxed) {
                // `stop` unparks this thread so shutdown does not wait for
                // the normal cleanup interval to elapse.
                thread::park_timeout(Duration::from_secs(30));

                if should_stop.load(Ordering::Relaxed) {
                    break;
                }

                // Remove expired entries (including timed-out pending lookups)
                cache.retain(|_, entry| entry.is_fresh(cache_ttl, negative_cache_ttl));

                // If cache is too large, remove oldest entries
                if cache.len() > max_cache_size {
                    let mut entries: Vec<_> =
                        cache.iter().map(|e| (*e.key(), e.resolved_at)).collect();
                    entries.sort_by_key(|(_, time)| *time);

                    let to_remove = cache.len() - max_cache_size;
                    for (ip, _) in entries.into_iter().take(to_remove) {
                        cache.remove(&ip);
                    }
                }

                debug!("DNS cache size: {}", cache.len());
            }

            debug!("DNS cache cleanup thread stopping");
        });

        match spawn("dns-cache-cleanup".to_string(), cleanup) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                return Err(Self::rollback_failed_start(&startup_gate, handles, error));
            }
        }

        lifecycle.started = true;
        lifecycle.handles = handles;
        release_startup_gate(&startup_gate, true);
        Ok(())
    }

    fn rollback_failed_start(
        startup_gate: &StartupGate,
        handles: Vec<JoinHandle<()>>,
        error: std::io::Error,
    ) -> anyhow::Error {
        release_startup_gate(startup_gate, false);
        let panicked = handles
            .into_iter()
            .map(|handle| handle.join().is_err())
            .filter(|panicked| *panicked)
            .count();
        if panicked == 0 {
            anyhow::anyhow!("failed to spawn DNS worker: {error}")
        } else {
            anyhow::anyhow!(
                "failed to spawn DNS worker: {error}; {panicked} staged worker(s) panicked during rollback"
            )
        }
    }

    /// Request resolution for an IP address (non-blocking)
    pub fn request_resolution(&self, ip: IpAddr) {
        if self.should_stop.load(Ordering::Acquire)
            || matches!(classify(ip), Scope::Loopback | Scope::LinkLocal)
        {
            return;
        }

        let pending = CachedHostname::pending();
        let request = ResolutionRequest {
            ip,
            reserved_at: pending.resolved_at,
        };
        match self.cache.entry(ip) {
            Entry::Occupied(mut entry) => {
                if entry
                    .get()
                    .is_fresh(self.config.cache_ttl, self.config.negative_cache_ttl)
                {
                    return;
                }
                entry.insert(pending);
            }
            Entry::Vacant(entry) => {
                entry.insert(pending);
            }
        }

        // Never let reverse DNS backpressure packet processing. A full queue
        // drops this attempt. Remove only this attempt's reservation so a later
        // display or export pass can retry without disturbing a newer request.
        if self.request_tx.try_send(request).is_err() {
            self.cache.remove_if(&ip, |_, entry| {
                entry.state == ResolutionState::Pending && entry.resolved_at == request.reserved_at
            });
        }
    }

    /// Get hostname for IP if resolved, otherwise return None
    pub fn get_hostname(&self, ip: &IpAddr) -> Option<String> {
        self.request_resolution(*ip);

        self.cache.get(ip).and_then(|entry| {
            if entry.state == ResolutionState::Resolved {
                entry.hostname.clone()
            } else {
                None
            }
        })
    }

    /// Stop the resolver and join background workers within a shared deadline.
    ///
    /// Stopping is idempotent and prevents a deferred resolver from starting.
    /// All workers share one deadline, so several blocked resolver calls cannot
    /// extend shutdown one timeout at a time. Workers that remain blocked after
    /// the deadline are detached and reported as timed out.
    pub fn stop(&self) -> DnsStopReport {
        self.should_stop.store(true, Ordering::Release);

        let mut lifecycle = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(report) = lifecycle.stop_report {
            return report;
        }

        lifecycle.stopped = true;

        for handle in &lifecycle.handles {
            handle.thread().unpark();
        }

        let deadline = Instant::now() + self.config.shutdown_timeout;
        let mut report = DnsStopReport::default();

        while !lifecycle.handles.is_empty() {
            let mut index = 0;
            while index < lifecycle.handles.len() {
                if lifecycle.handles[index].is_finished() {
                    let handle = lifecycle.handles.swap_remove(index);
                    if handle.join().is_err() {
                        report.panicked += 1;
                        debug!("DNS worker thread panicked during shutdown");
                    } else {
                        report.joined += 1;
                    }
                } else {
                    index += 1;
                }
            }

            if lifecycle.handles.is_empty() {
                break;
            }

            let now = Instant::now();
            if now >= deadline {
                report.timed_out = lifecycle.handles.len();
                lifecycle.handles.clear();
                break;
            }

            thread::sleep((deadline - now).min(Duration::from_millis(1)));
        }

        lifecycle.stop_report = Some(report);
        report
    }
}

impl Drop for DnsResolver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_hostname_states() {
        let pending = CachedHostname::pending();
        assert_eq!(pending.state, ResolutionState::Pending);
        assert!(pending.hostname.is_none());

        let resolved = CachedHostname::resolved("example.com".to_string());
        assert_eq!(resolved.state, ResolutionState::Resolved);
        assert_eq!(resolved.hostname, Some("example.com".to_string()));

        let failed = CachedHostname::failed();
        assert_eq!(failed.state, ResolutionState::Failed);
        assert!(failed.hostname.is_none());
    }

    #[test]
    fn test_loopback_skip() {
        let config = DnsResolverConfig {
            resolver_threads: 1,
            ..Default::default()
        };
        let resolver = DnsResolver::new(config).unwrap();

        // Loopback should not be queued
        resolver.request_resolution("127.0.0.1".parse().unwrap());
        assert!(
            resolver
                .get_hostname(&"127.0.0.1".parse().unwrap())
                .is_none()
        );

        let report = resolver.stop();
        assert_eq!(report.timed_out, 0);
    }

    #[test]
    fn deferred_resolver_stays_inactive_until_started() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            resolver_threads: 0,
            ..Default::default()
        });

        {
            let lifecycle = resolver.lifecycle.lock().unwrap();
            assert!(!lifecycle.started);
            assert!(!lifecycle.stopped);
            assert!(lifecycle.handles.is_empty());
        }

        resolver.start().unwrap();
        {
            let lifecycle = resolver.lifecycle.lock().unwrap();
            assert!(lifecycle.started);
            assert!(!lifecycle.stopped);
            assert_eq!(lifecycle.handles.len(), 1);
        }

        // Starting twice is a no-op.
        resolver.start().unwrap();
        assert_eq!(resolver.lifecycle.lock().unwrap().handles.len(), 1);

        resolver.stop();
    }

    #[test]
    fn stopped_deferred_resolver_cannot_be_started() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            resolver_threads: 0,
            ..Default::default()
        });

        let report = resolver.stop();
        assert_eq!(report, DnsStopReport::default());
        resolver.start().unwrap();

        let lifecycle = resolver.lifecycle.lock().unwrap();
        assert!(!lifecycle.started);
        assert!(lifecycle.stopped);
        assert!(lifecycle.handles.is_empty());
    }

    #[test]
    fn request_queue_is_bounded_and_non_blocking() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            request_queue_capacity: 1,
            resolver_threads: 0,
            ..Default::default()
        });
        let first = "192.0.2.1".parse().unwrap();
        let second = "192.0.2.2".parse().unwrap();

        resolver.request_resolution(first);
        resolver.request_resolution(second);

        assert_eq!(resolver.request_rx.len(), 1);
        assert_eq!(resolver.request_rx.try_recv().unwrap().ip, first);
        assert!(resolver.request_rx.try_recv().is_err());
    }

    #[test]
    fn repeated_requests_share_one_queue_reservation() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            request_queue_capacity: 4,
            resolver_threads: 0,
            ..Default::default()
        });
        let address = "192.0.2.1".parse().unwrap();

        for _ in 0..32 {
            resolver.request_resolution(address);
        }

        assert_eq!(resolver.request_rx.len(), 1);
        assert_eq!(resolver.request_rx.try_recv().unwrap().ip, address);
        assert!(resolver.request_rx.try_recv().is_err());
    }

    #[test]
    fn concurrent_requests_share_one_queue_reservation() {
        let resolver = Arc::new(DnsResolver::new_deferred(DnsResolverConfig {
            request_queue_capacity: 32,
            resolver_threads: 0,
            ..Default::default()
        }));
        let address = "192.0.2.1".parse().unwrap();
        let ready = Arc::new(std::sync::Barrier::new(17));
        let mut callers = Vec::new();
        for _ in 0..16 {
            let resolver = Arc::clone(&resolver);
            let ready = Arc::clone(&ready);
            callers.push(thread::spawn(move || {
                ready.wait();
                resolver.request_resolution(address);
            }));
        }

        ready.wait();
        for caller in callers {
            caller.join().unwrap();
        }

        assert_eq!(resolver.request_rx.len(), 1);
        assert_eq!(resolver.request_rx.try_recv().unwrap().ip, address);
    }

    #[test]
    fn full_queue_releases_reservation_for_retry() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            request_queue_capacity: 1,
            resolver_threads: 0,
            ..Default::default()
        });
        let first = "192.0.2.1".parse().unwrap();
        let retry = "192.0.2.2".parse().unwrap();

        resolver.request_resolution(first);
        resolver.request_resolution(retry);
        assert!(!resolver.cache.contains_key(&retry));

        assert_eq!(resolver.request_rx.try_recv().unwrap().ip, first);
        resolver.request_resolution(retry);
        assert_eq!(resolver.request_rx.try_recv().unwrap().ip, retry);
    }

    #[test]
    fn failed_start_joins_staged_workers_and_can_be_retried() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            resolver_threads: 2,
            ..Default::default()
        });
        let staged_worker_exited = Arc::new(AtomicBool::new(false));
        let exited = Arc::clone(&staged_worker_exited);
        let mut attempts = 0;

        let error = resolver
            .start_with_spawner(move |name, worker| {
                attempts += 1;
                if attempts == 2 {
                    return Err(std::io::Error::other("injected spawn failure"));
                }
                let exited = Arc::clone(&exited);
                thread::Builder::new().name(name).spawn(move || {
                    worker();
                    exited.store(true, Ordering::Release);
                })
            })
            .unwrap_err();

        assert!(error.to_string().contains("injected spawn failure"));
        assert!(staged_worker_exited.load(Ordering::Acquire));
        {
            let lifecycle = resolver.lifecycle.lock().unwrap();
            assert!(!lifecycle.started);
            assert!(!lifecycle.stopped);
            assert!(lifecycle.handles.is_empty());
        }

        resolver.start().unwrap();
        assert_eq!(resolver.lifecycle.lock().unwrap().handles.len(), 3);
        let report = resolver.stop();
        assert_eq!(report.joined, 3);
        assert_eq!(report.timed_out, 0);
    }

    #[test]
    fn stop_joins_workers_and_is_idempotent() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            resolver_threads: 1,
            ..Default::default()
        });
        resolver.start().unwrap();
        assert_eq!(resolver.lifecycle.lock().unwrap().handles.len(), 2);

        let before_stop = Instant::now();
        let report = resolver.stop();
        assert!(before_stop.elapsed() < Duration::from_secs(1));
        assert_eq!(report.joined, 2);
        assert_eq!(report.panicked, 0);
        assert_eq!(report.timed_out, 0);

        {
            let lifecycle = resolver.lifecycle.lock().unwrap();
            assert!(lifecycle.started);
            assert!(lifecycle.stopped);
            assert!(lifecycle.handles.is_empty());
        }

        assert_eq!(resolver.stop(), report);
        assert!(resolver.lifecycle.lock().unwrap().handles.is_empty());
    }

    #[test]
    fn stop_detaches_stalled_worker_at_shared_deadline() {
        let resolver = DnsResolver::new_deferred(DnsResolverConfig {
            resolver_threads: 0,
            shutdown_timeout: Duration::from_millis(25),
            ..Default::default()
        });
        let (release_tx, release_rx) = channel::bounded::<()>(0);
        let stalled = thread::spawn(move || {
            let _ = release_rx.recv();
        });
        resolver.lifecycle.lock().unwrap().handles.push(stalled);

        let before_stop = Instant::now();
        let report = resolver.stop();

        assert!(before_stop.elapsed() < Duration::from_millis(250));
        assert_eq!(
            report,
            DnsStopReport {
                joined: 0,
                panicked: 0,
                timed_out: 1,
            }
        );
        assert_eq!(resolver.stop(), report);

        // The detached worker can still finish safely after the resolver stops.
        let _ = release_tx.send(());
    }

    #[test]
    fn test_default_config() {
        let config = DnsResolverConfig::default();
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
        assert_eq!(config.negative_cache_ttl, Duration::from_secs(60));
        assert_eq!(config.max_cache_size, 10000);
        assert_eq!(config.request_queue_capacity, 10000);
        assert_eq!(config.resolver_threads, 4);
        assert_eq!(config.shutdown_timeout, Duration::from_secs(1));
    }
}
