use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Network interface to monitor
    pub interface: Option<String>,
    /// Interface language (ISO code)
    pub language: String,
    /// Path to MaxMind GeoIP database
    pub geoip_db_path: Option<PathBuf>,
    /// Refresh interval in milliseconds
    pub refresh_interval: u64,
    /// Show IP locations (requires MaxMind DB)
    pub show_locations: bool,
    /// Filter out localhost (loopback) traffic
    pub filter_localhost: bool,
    /// Custom configuration file path
    pub config_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: None,
            language: "en".to_string(),
            geoip_db_path: None,
            refresh_interval: 1000,
            show_locations: true,
            filter_localhost: true,
            config_path: None,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load(path: Option<&str>) -> Result<Self> {
        let config_path = if let Some(path) = path {
            PathBuf::from(path)
        } else {
            Self::find_config_file()?
        };

        let mut config = Config::default();

        if config_path.exists() {
            config.config_path = Some(config_path.clone());

            // Read config file
            let content = fs::read_to_string(&config_path)?;

            // Parse YAML
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim();
                    let value = line[pos + 1..].trim();

                    match key {
                        "interface" => {
                            config.interface = Some(value.to_string());
                        }
                        "language" => {
                            config.language = value.to_string();
                        }
                        "geoip_db_path" => {
                            config.geoip_db_path = Some(PathBuf::from(value));
                        }
                        "refresh_interval" => {
                            if let Ok(interval) = value.parse::<u64>() {
                                config.refresh_interval = interval;
                            }
                        }
                        "show_locations" => {
                            if value == "true" {
                                config.show_locations = true;
                            } else if value == "false" {
                                config.show_locations = false;
                            }
                        }
                        "filter_localhost" => {
                            if value == "true" {
                                config.filter_localhost = true;
                            } else if value == "false" {
                                config.filter_localhost = false;
                            }
                        }
                        _ => {
                            // Ignore unknown keys
                        }
                    }
                }
            }
        }

        // Try to find GeoIP database if not specified in config
        if config.geoip_db_path.is_none() {
            for path in Self::possible_geoip_paths() {
                if path.exists() {
                    config.geoip_db_path = Some(path);
                    break;
                }
            }
        }

        Ok(config)
    }

    /// Find configuration file
    fn find_config_file() -> Result<PathBuf> {
        // Try XDG config directory first
        if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
            let xdg_path = PathBuf::from(xdg_config).join("rustnet/config.yml");
            if xdg_path.exists() {
                return Ok(xdg_path);
            }
        }

        // Try ~/.config/rustnet
        let home = Self::get_home_dir()?;
        let home_config = home.join(".config/rustnet/config.yml");
        if home_config.exists() {
            return Ok(home_config);
        }

        // Try current directory
        let current_config = PathBuf::from("config.yml");
        if current_config.exists() {
            return Ok(current_config);
        }

        // Default to home config path
        Ok(home_config)
    }

    /// Get home directory
    fn get_home_dir() -> Result<PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home));
        }

        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            return Ok(PathBuf::from(userprofile));
        }

        Err(anyhow!("Could not determine home directory"))
    }

    /// Get possible GeoIP database paths
    fn possible_geoip_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Current directory
        paths.push(PathBuf::from("GeoLite2-City.mmdb"));

        // Try XDG data directory
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            paths.push(PathBuf::from(xdg_data).join("rustnet/GeoLite2-City.mmdb"));
        }

        // Try home directory
        if let Ok(home) = Self::get_home_dir() {
            paths.push(home.join(".local/share/rustnet/GeoLite2-City.mmdb"));
        }

        // System paths
        paths.push(PathBuf::from("/usr/share/GeoIP/GeoLite2-City.mmdb"));
        paths.push(PathBuf::from("/usr/local/share/GeoIP/GeoLite2-City.mmdb"));

        paths
    }
}
