//! DNS resolver with background async resolution and caching.
//!
//! Provides non-blocking reverse DNS lookups with an LRU cache to avoid
//! repeated lookups for the same IP address.

use crate::network::bogon::{Scope, classify};
use crossbeam::channel::{self, Receiver, Sender};
use dashmap::DashMap;
use dns_lookup::lookup_addr;
use log::debug;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Resolution state for a cached entry
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ResolutionState {
    /// Resolution is in progress
    Pending,
    /// Resolution succeeded
    Resolved,
    /// Resolution failed
    Failed,
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
    /// Number of resolver threads (default: 4)
    pub resolver_threads: usize,
}

impl Default for DnsResolverConfig {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(300),         // 5 minutes
            negative_cache_ttl: Duration::from_secs(60), // 1 minute
            max_cache_size: 10000,
            resolver_threads: 4,
        }
    }
}

/// Background DNS resolver with caching
pub struct DnsResolver {
    /// Hostname cache: IP -> CachedHostname
    cache: Arc<DashMap<IpAddr, CachedHostname>>,
    /// Channel to send IPs for resolution
    request_tx: Sender<IpAddr>,
    /// Control flag for shutdown
    should_stop: Arc<AtomicBool>,
    /// Configuration
    config: DnsResolverConfig,
}

impl DnsResolver {
    /// Create a new DNS resolver with the given configuration
    pub(crate) fn new(config: DnsResolverConfig) -> Self {
        let cache = Arc::new(DashMap::new());
        let (request_tx, request_rx) = channel::unbounded();
        let should_stop = Arc::new(AtomicBool::new(false));

        let resolver = Self {
            cache: Arc::clone(&cache),
            request_tx,
            should_stop: Arc::clone(&should_stop),
            config: config.clone(),
        };

        // Start resolver threads
        resolver.start_resolver_threads(request_rx, &config);

        // Start cache cleanup thread
        resolver.start_cache_cleanup_thread();

        resolver
    }

    /// Create a new DNS resolver with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DnsResolverConfig::default())
    }

    /// Start background resolver threads
    fn start_resolver_threads(&self, request_rx: Receiver<IpAddr>, config: &DnsResolverConfig) {
        let num_threads = config.resolver_threads;

        for i in 0..num_threads {
            let rx = request_rx.clone();
            let cache = Arc::clone(&self.cache);
            let should_stop = Arc::clone(&self.should_stop);
            let cache_ttl = config.cache_ttl;
            let negative_cache_ttl = config.negative_cache_ttl;

            thread::Builder::new()
                .name(format!("dns-resolver-{}", i))
                .spawn(move || {
                    debug!("DNS resolver thread {} started", i);

                    while !should_stop.load(Ordering::Relaxed) {
                        match rx.recv_timeout(Duration::from_millis(100)) {
                            Ok(ip) => {
                                // Skip if already resolved or pending;
                                // expired entries are re-resolved.
                                if cache
                                    .get(&ip)
                                    .is_some_and(|e| e.is_fresh(cache_ttl, negative_cache_ttl))
                                {
                                    continue;
                                }

                                // Mark as pending
                                cache.insert(ip, CachedHostname::pending());

                                // Perform DNS lookup
                                match lookup_addr(&ip) {
                                    Ok(hostname) => {
                                        debug!("Resolved {} -> {}", ip, hostname);
                                        cache.insert(ip, CachedHostname::resolved(hostname));
                                    }
                                    Err(e) => {
                                        debug!("Failed to resolve {}: {}", ip, e);
                                        cache.insert(ip, CachedHostname::failed());
                                    }
                                }
                            }
                            Err(crossbeam::channel::RecvTimeoutError::Timeout) => continue,
                            Err(crossbeam::channel::RecvTimeoutError::Disconnected) => break,
                        }
                    }

                    debug!("DNS resolver thread {} stopping", i);
                })
                .expect("Failed to spawn DNS resolver thread");
        }
    }

    /// Start cache cleanup thread to evict expired entries
    fn start_cache_cleanup_thread(&self) {
        let cache = Arc::clone(&self.cache);
        let should_stop = Arc::clone(&self.should_stop);
        let cache_ttl = self.config.cache_ttl;
        let negative_cache_ttl = self.config.negative_cache_ttl;
        let max_cache_size = self.config.max_cache_size;

        thread::Builder::new()
            .name("dns-cache-cleanup".to_string())
            .spawn(move || {
                debug!("DNS cache cleanup thread started");

                while !should_stop.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_secs(30)); // Cleanup every 30 seconds

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
            })
            .expect("Failed to spawn DNS cache cleanup thread");
    }

    /// Request resolution for an IP address (non-blocking)
    pub fn request_resolution(&self, ip: IpAddr) {
        // Don't resolve localhost or link-local
        if matches!(classify(ip), Scope::Loopback | Scope::LinkLocal) {
            return;
        }

        // Check if already in cache and not expired
        if self
            .cache
            .get(&ip)
            .is_some_and(|e| e.is_fresh(self.config.cache_ttl, self.config.negative_cache_ttl))
        {
            return;
        }

        // Queue for resolution (ignore send errors - channel is unbounded)
        let _ = self.request_tx.send(ip);
    }

    /// Get hostname for IP if resolved, otherwise return None
    pub fn get_hostname(&self, ip: &IpAddr) -> Option<String> {
        // Request resolution if not in cache
        self.request_resolution(*ip);

        // Return cached hostname if available
        self.cache.get(ip).and_then(|entry| {
            if entry.state == ResolutionState::Resolved {
                entry.hostname.clone()
            } else {
                None
            }
        })
    }

    /// Stop the resolver
    pub fn stop(&self) {
        self.should_stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for DnsResolver {
    fn drop(&mut self) {
        self.stop();
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
        let resolver = DnsResolver::new(config);

        // Loopback should not be queued
        resolver.request_resolution("127.0.0.1".parse().unwrap());
        assert!(
            resolver
                .get_hostname(&"127.0.0.1".parse().unwrap())
                .is_none()
        );

        resolver.stop();
    }

    #[test]
    fn test_default_config() {
        let config = DnsResolverConfig::default();
        assert_eq!(config.cache_ttl, Duration::from_secs(300));
        assert_eq!(config.negative_cache_ttl, Duration::from_secs(60));
        assert_eq!(config.max_cache_size, 10000);
        assert_eq!(config.resolver_threads, 4);
    }
}
