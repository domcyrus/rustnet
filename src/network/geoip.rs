//! GeoIP resolver with caching for Country and ASN lookups.
//!
//! Provides GeoIP lookups using MaxMind databases with an LRU cache
//! to avoid repeated lookups for the same IP address.

use dashmap::DashMap;
use log::{debug, info, warn};
use maxminddb::{Reader, geoip2};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// GeoIP information for an IP address
#[derive(Debug, Clone, Default)]
pub struct GeoIpInfo {
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "JP")
    pub country_code: Option<String>,
    /// Country name in English (e.g., "United States", "Germany")
    pub country_name: Option<String>,
    /// Autonomous System Number (e.g., 15169 for Google)
    pub asn: Option<u32>,
    /// AS Organization name (e.g., "GOOGLE")
    pub as_org: Option<String>,
}

impl GeoIpInfo {
    /// Check if any GeoIP data is available
    pub fn has_data(&self) -> bool {
        self.country_code.is_some() || self.asn.is_some()
    }

    /// Get just the country code or "-" if unavailable
    pub fn country_display(&self) -> &str {
        self.country_code.as_deref().unwrap_or("-")
    }
}

/// Cached GeoIP entry
#[derive(Debug, Clone)]
struct CachedGeoIp {
    /// The resolved GeoIP info
    info: GeoIpInfo,
    /// When this entry was cached
    cached_at: Instant,
}

/// Configuration for GeoIP resolver
#[derive(Debug, Clone)]
pub struct GeoIpConfig {
    /// Path to GeoLite2-Country.mmdb database
    pub country_db_path: Option<PathBuf>,
    /// Path to GeoLite2-ASN.mmdb database
    pub asn_db_path: Option<PathBuf>,
    /// Cache TTL (default: 1 hour - GeoIP data rarely changes)
    pub cache_ttl: Duration,
    /// Maximum cache size (default: 50000 entries)
    pub max_cache_size: usize,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            country_db_path: None,
            asn_db_path: None,
            cache_ttl: Duration::from_secs(3600), // 1 hour
            max_cache_size: 50000,
        }
    }
}

/// GeoIP resolver with caching
pub struct GeoIpResolver {
    /// Country database reader
    country_reader: Option<Reader<Vec<u8>>>,
    /// ASN database reader
    asn_reader: Option<Reader<Vec<u8>>>,
    /// Cache: IP -> CachedGeoIp
    cache: Arc<DashMap<IpAddr, CachedGeoIp>>,
    /// Configuration
    config: GeoIpConfig,
}

impl GeoIpResolver {
    /// Create a new GeoIP resolver with the given configuration
    pub fn new(config: GeoIpConfig) -> Self {
        let country_reader =
            config
                .country_db_path
                .as_ref()
                .and_then(|path| match Reader::open_readfile(path) {
                    Ok(reader) => {
                        info!("Loaded GeoIP Country database from: {:?}", path);
                        Some(reader)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load GeoIP Country database from {:?}: {}",
                            path, e
                        );
                        None
                    }
                });

        let asn_reader =
            config
                .asn_db_path
                .as_ref()
                .and_then(|path| match Reader::open_readfile(path) {
                    Ok(reader) => {
                        info!("Loaded GeoIP ASN database from: {:?}", path);
                        Some(reader)
                    }
                    Err(e) => {
                        warn!("Failed to load GeoIP ASN database from {:?}: {}", path, e);
                        None
                    }
                });

        Self {
            country_reader,
            asn_reader,
            cache: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Try to auto-discover and load databases from common paths
    pub fn with_auto_discovery() -> Self {
        let mut config = GeoIpConfig::default();

        // Common paths to search for databases
        let search_paths = Self::get_search_paths();

        for base_path in search_paths {
            // Try Country database
            if config.country_db_path.is_none() {
                let country_path = base_path.join("GeoLite2-Country.mmdb");
                if country_path.exists() {
                    config.country_db_path = Some(country_path);
                }
            }

            // Try ASN database
            if config.asn_db_path.is_none() {
                let asn_path = base_path.join("GeoLite2-ASN.mmdb");
                if asn_path.exists() {
                    config.asn_db_path = Some(asn_path);
                }
            }

            // Stop if both found
            if config.country_db_path.is_some() && config.asn_db_path.is_some() {
                break;
            }
        }

        Self::new(config)
    }

    /// Get common search paths for GeoIP databases
    ///
    /// This is public so that the Landlock sandbox can whitelist these paths
    /// for read access.
    pub fn get_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory / resources
        paths.push(PathBuf::from("resources/geoip2"));
        paths.push(PathBuf::from("."));

        // XDG data directory
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            paths.push(PathBuf::from(&xdg_data).join("rustnet/geoip"));
            paths.push(PathBuf::from(xdg_data).join("GeoIP"));
        }

        // Home directory
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(&home);
            paths.push(home_path.join(".local/share/rustnet/geoip"));
            paths.push(home_path.join(".local/share/GeoIP"));
        }

        // System paths
        paths.push(PathBuf::from("/usr/share/GeoIP"));
        paths.push(PathBuf::from("/usr/local/share/GeoIP"));
        paths.push(PathBuf::from("/opt/homebrew/share/GeoIP"));
        paths.push(PathBuf::from("/var/lib/GeoIP"));

        // Windows paths
        #[cfg(target_os = "windows")]
        {
            if let Ok(program_data) = std::env::var("ProgramData") {
                paths.push(PathBuf::from(program_data).join("GeoIP"));
            }
        }

        paths
    }

    /// Check if the resolver has any databases loaded
    pub fn is_available(&self) -> bool {
        self.country_reader.is_some() || self.asn_reader.is_some()
    }

    /// Check which databases are available
    pub fn get_status(&self) -> (bool, bool) {
        (self.country_reader.is_some(), self.asn_reader.is_some())
    }

    /// Lookup GeoIP information for an IP address
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        // Skip private/local addresses
        if is_private_or_local(&ip) {
            return GeoIpInfo::default();
        }

        // Check cache first
        if let Some(cached) = self.cache.get(&ip)
            && cached.cached_at.elapsed() < self.config.cache_ttl
        {
            return cached.info.clone();
        }

        // Perform lookup
        let info = self.do_lookup(ip);

        // Cache the result
        self.cache.insert(
            ip,
            CachedGeoIp {
                info: info.clone(),
                cached_at: Instant::now(),
            },
        );

        // Evict old entries if cache is too large
        if self.cache.len() > self.config.max_cache_size {
            self.evict_oldest_entries();
        }

        info
    }

    /// Perform the actual database lookup
    fn do_lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let mut info = GeoIpInfo::default();

        // Country lookup
        if let Some(ref reader) = self.country_reader
            && let Ok(country) = reader.lookup::<geoip2::Country>(ip)
            && let Some(c) = country.country
        {
            info.country_code = c.iso_code.map(|s| s.to_string());
            if let Some(names) = c.names {
                info.country_name = names.get("en").map(|s| s.to_string());
            }
        }

        // ASN lookup
        if let Some(ref reader) = self.asn_reader
            && let Ok(asn) = reader.lookup::<geoip2::Asn>(ip)
        {
            info.asn = asn.autonomous_system_number;
            info.as_org = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        info
    }

    /// Evict oldest entries from cache
    fn evict_oldest_entries(&self) {
        let target_size = self.config.max_cache_size * 3 / 4; // Evict to 75%

        let mut entries: Vec<_> = self.cache.iter().map(|e| (*e.key(), e.cached_at)).collect();

        let to_remove = self.cache.len().saturating_sub(target_size);
        if to_remove == 0 {
            return;
        }
        entries.select_nth_unstable_by_key(to_remove - 1, |(_, time)| *time);
        for (ip, _) in entries.into_iter().take(to_remove) {
            self.cache.remove(&ip);
        }

        debug!(
            "GeoIP cache evicted {} entries, now {} entries",
            to_remove,
            self.cache.len()
        );
    }
}

/// Check if IP is private, local, or reserved
fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10 (CGNAT)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // Link-local (fe80::/10)
                || ((v6.segments()[0] & 0xffc0) == 0xfe80)
                // Unique local (fc00::/7)
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_info_has_data() {
        let info = GeoIpInfo {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            asn: Some(15169),
            as_org: Some("GOOGLE".to_string()),
        };

        assert!(info.has_data());
        assert_eq!(info.country_display(), "US");
    }

    #[test]
    fn test_geoip_info_country_only() {
        let info = GeoIpInfo {
            country_code: Some("DE".to_string()),
            country_name: Some("Germany".to_string()),
            asn: None,
            as_org: None,
        };

        assert!(info.has_data());
        assert_eq!(info.country_display(), "DE");
    }

    #[test]
    fn test_geoip_info_asn_only() {
        let info = GeoIpInfo {
            country_code: None,
            country_name: None,
            asn: Some(13335),
            as_org: Some("CLOUDFLARENET".to_string()),
        };

        assert!(info.has_data());
        assert_eq!(info.country_display(), "-");
    }

    #[test]
    fn test_geoip_info_empty() {
        let info = GeoIpInfo::default();
        assert_eq!(info.country_display(), "-");
        assert!(!info.has_data());
    }

    #[test]
    fn test_private_ip_detection() {
        // IPv4 private
        assert!(is_private_or_local(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_or_local(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_or_local(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_or_local(&"127.0.0.1".parse().unwrap()));
        assert!(is_private_or_local(&"169.254.1.1".parse().unwrap())); // Link-local

        // CGNAT range
        assert!(is_private_or_local(&"100.64.0.1".parse().unwrap()));
        assert!(is_private_or_local(&"100.127.255.255".parse().unwrap()));

        // Public IPs
        assert!(!is_private_or_local(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_or_local(&"1.1.1.1".parse().unwrap()));

        // IPv6
        assert!(is_private_or_local(&"::1".parse().unwrap())); // Loopback
        assert!(is_private_or_local(&"fe80::1".parse().unwrap())); // Link-local
        assert!(is_private_or_local(&"fc00::1".parse().unwrap())); // Unique local
        assert!(!is_private_or_local(
            &"2001:4860:4860::8888".parse().unwrap()
        )); // Google DNS
    }

    #[test]
    fn test_country_display() {
        let info = GeoIpInfo {
            country_code: Some("JP".to_string()),
            ..Default::default()
        };
        assert_eq!(info.country_display(), "JP");

        let empty = GeoIpInfo::default();
        assert_eq!(empty.country_display(), "-");
    }
}
