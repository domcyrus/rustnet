//! GeoIP resolver with caching for Country and ASN lookups.
//!
//! Provides GeoIP lookups using MaxMind databases with an LRU cache
//! to avoid repeated lookups for the same IP address.

use crate::network::bogon::{Scope, classify};
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
    /// postal code (e.g., "94043")
    pub postal_code: Option<String>,
    /// city name (e.g., "Mountain View")
    pub city: Option<String>,
}

impl GeoIpInfo {
    /// Check if any GeoIP data is available
    pub fn has_data(&self) -> bool {
        self.country_code.is_some() || self.asn.is_some() || self.city.is_some()
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
    /// Path to GeoLite2-City.mmdb database
    pub city_db_path: Option<PathBuf>,
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
            city_db_path: None,
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
    /// City database reader
    city_reader: Option<Reader<Vec<u8>>>,
    /// Cache: IP -> CachedGeoIp
    cache: Arc<DashMap<IpAddr, CachedGeoIp>>,
    /// Configuration
    config: GeoIpConfig,
}

impl GeoIpResolver {
    /// Create a new GeoIP resolver with the given configuration
    pub fn new(config: GeoIpConfig) -> Self {
        let country_reader = Self::open_reader(config.country_db_path.as_ref(), "Country");
        let asn_reader = Self::open_reader(config.asn_db_path.as_ref(), "ASN");
        let city_reader = Self::open_reader(config.city_db_path.as_ref(), "City");

        Self {
            country_reader,
            asn_reader,
            city_reader,
            cache: Arc::new(DashMap::new()),
            config,
        }
    }

    /// Open a MaxMind database at `path`, logging success or failure.
    ///
    /// Returns `None` when no path is configured or the database cannot be opened.
    fn open_reader(path: Option<&PathBuf>, label: &str) -> Option<Reader<Vec<u8>>> {
        let path = path?;
        match Reader::open_readfile(path) {
            Ok(reader) => {
                info!("Loaded GeoIP {} database from: {:?}", label, path);
                Some(reader)
            }
            Err(e) => {
                warn!(
                    "Failed to load GeoIP {} database from {:?}: {}",
                    label, path, e
                );
                None
            }
        }
    }

    /// Try to auto-discover and load databases from common paths
    pub fn with_auto_discovery() -> Self {
        let mut config = GeoIpConfig::default();

        let search_paths = Self::get_search_paths();

        for base_path in search_paths {
            let mut slots = [
                ("GeoLite2-Country.mmdb", &mut config.country_db_path),
                ("GeoLite2-ASN.mmdb", &mut config.asn_db_path),
                ("GeoLite2-City.mmdb", &mut config.city_db_path),
            ];

            for (file_name, slot) in slots.iter_mut() {
                if slot.is_none() {
                    let path = base_path.join(file_name);
                    if path.exists() {
                        **slot = Some(path);
                    }
                }
            }

            // Stop if all three found
            if slots.iter().all(|(_, slot)| slot.is_some()) {
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
        self.country_reader.is_some() || self.asn_reader.is_some() || self.city_reader.is_some()
    }

    /// Check which databases are available.
    /// Returns (has_location, has_asn, has_city) where has_location is true when
    /// either the country or city database is loaded (city DB is a superset of country).
    pub fn get_status(&self) -> (bool, bool, bool) {
        let has_location = self.country_reader.is_some() || self.city_reader.is_some();
        (
            has_location,
            self.asn_reader.is_some(),
            self.city_reader.is_some(),
        )
    }

    /// Lookup GeoIP information for an IP address
    pub fn lookup(&self, ip: IpAddr) -> GeoIpInfo {
        if is_private_or_local(&ip) {
            return GeoIpInfo::default();
        }

        if let Some(cached) = self.cache.get(&ip)
            && cached.cached_at.elapsed() < self.config.cache_ttl
        {
            return cached.info.clone();
        }

        let info = self.do_lookup(ip);

        self.cache.insert(
            ip,
            CachedGeoIp {
                info: info.clone(),
                cached_at: Instant::now(),
            },
        );

        if self.cache.len() > self.config.max_cache_size {
            self.evict_oldest_entries();
        }

        info
    }

    /// Perform the actual database lookup
    fn do_lookup(&self, ip: IpAddr) -> GeoIpInfo {
        let mut info = GeoIpInfo::default();

        if let Some(ref reader) = self.country_reader
            && let Ok(Some(country)) = reader
                .lookup(ip)
                .and_then(|r| r.decode::<geoip2::Country>())
        {
            let c = &country.country;
            info.country_code = c.iso_code.map(|s| s.to_string());
            info.country_name = c.names.english.map(|s| s.to_string());
        }

        if let Some(ref reader) = self.asn_reader
            && let Ok(Some(asn)) = reader.lookup(ip).and_then(|r| r.decode::<geoip2::Asn>())
        {
            info.asn = asn.autonomous_system_number;
            info.as_org = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        // City lookup (City DB is a superset of Country; also fills country fields as fallback)
        if let Some(ref reader) = self.city_reader
            && let Ok(Some(city)) = reader.lookup(ip).and_then(|r| r.decode::<geoip2::City>())
        {
            info.postal_code = city.postal.code.map(|s| s.to_string());
            // NOTE: City names can be in multiple languages, we take English if available
            info.city = city.city.names.english.map(|s| s.to_string());
            // Fall back to country info from City DB if Country DB was not loaded
            if info.country_code.is_none() {
                info.country_code = city.country.iso_code.map(|s| s.to_string());
                info.country_name = city.country.names.english.map(|s| s.to_string());
            }
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

/// Check if IP is private, local, or reserved.
///
/// Only globally routable addresses (and IPv4-mapped IPv6, which MaxMind
/// handles) are worth a database lookup.
fn is_private_or_local(ip: &IpAddr) -> bool {
    !matches!(classify(*ip), Scope::Public | Scope::Ipv4Mapped)
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
            postal_code: Some("94043".to_string()),
            city: Some("Mountain View".to_string()),
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
            postal_code: None,
            city: None,
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
            postal_code: None,
            city: None,
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
