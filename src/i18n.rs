use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Internationalization support
#[derive(Debug, Clone)]
pub struct I18n {
    /// ISO language code
    language: String,
    /// Translation lookup table
    translations: HashMap<String, String>,
}

impl I18n {
    /// Create a new I18n instance for the given language
    pub fn new(language: &str) -> Result<Self> {
        let mut i18n = Self {
            language: language.to_string(),
            translations: HashMap::new(),
        };

        // Load translations
        i18n.load_translations()?;

        Ok(i18n)
    }

    /// Get translation for a key
    pub fn get(&self, key: &str) -> String {
        self.translations
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    /// Load translations from file
    fn load_translations(&mut self) -> Result<()> {
        let path = self.find_translation_file()?;

        if path.exists() {
            let content = fs::read_to_string(&path)?;

            // Parse YAML
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                if let Some(pos) = line.find(':') {
                    let key = line[..pos].trim();
                    let value = line[pos + 1..].trim();

                    // Remove quotes if present
                    let value = value.trim_matches('"').trim_matches('\'');

                    self.translations.insert(key.to_string(), value.to_string());
                }
            }

            Ok(())
        } else {
            // Fall back to English if the requested language is not found
            if self.language != "en" {
                self.language = "en".to_string();
                self.load_translations()
            } else {
                // If even English is not found, use built-in defaults
                self.load_default_translations();
                Ok(())
            }
        }
    }

    /// Find translation file for current language
    fn find_translation_file(&self) -> Result<PathBuf> {
        let filename = format!("{}.yml", self.language);

        // Try i18n directory in current directory
        let current_path = PathBuf::from("i18n").join(&filename);
        if current_path.exists() {
            return Ok(current_path);
        }

        // Try XDG data directory
        if let Ok(xdg_data) = std::env::var("XDG_DATA_HOME") {
            let xdg_path = PathBuf::from(xdg_data).join("rustnet/i18n").join(&filename);
            if xdg_path.exists() {
                return Ok(xdg_path);
            }
        }

        // Try ~/.local/share
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(home)
                .join(".local/share/rustnet/i18n")
                .join(&filename);
            if home_path.exists() {
                return Ok(home_path);
            }
        }

        // Try system paths
        let system_path = PathBuf::from("/usr/share/rustnet/i18n").join(&filename);
        if system_path.exists() {
            return Ok(system_path);
        }

        // Default to current directory
        Ok(current_path)
    }

    /// Load default translations (English)
    fn load_default_translations(&mut self) {
        // Basic UI elements
        self.translations
            .insert("rustnet".to_string(), "RustNet".to_string());
        self.translations
            .insert("overview".to_string(), "Overview".to_string());
        self.translations
            .insert("connections".to_string(), "Connections".to_string());
        self.translations
            .insert("processes".to_string(), "Processes".to_string());
        self.translations
            .insert("help".to_string(), "Help".to_string());
        self.translations
            .insert("network".to_string(), "Network".to_string());
        self.translations
            .insert("statistics".to_string(), "Statistics".to_string());
        self.translations
            .insert("top_processes".to_string(), "Top Processes".to_string());
        self.translations.insert(
            "connection_details".to_string(),
            "Connection Details".to_string(),
        );
        self.translations
            .insert("process_details".to_string(), "Process Details".to_string());
        self.translations
            .insert("traffic".to_string(), "Traffic".to_string());

        // Properties
        self.translations
            .insert("interface".to_string(), "Interface".to_string());
        self.translations
            .insert("protocol".to_string(), "Protocol".to_string());
        self.translations
            .insert("local_address".to_string(), "Local Address".to_string());
        self.translations
            .insert("remote_address".to_string(), "Remote Address".to_string());
        self.translations
            .insert("state".to_string(), "State".to_string());
        self.translations
            .insert("process".to_string(), "Process".to_string());
        self.translations
            .insert("pid".to_string(), "PID".to_string());
        self.translations
            .insert("age".to_string(), "Age".to_string());
        self.translations
            .insert("country".to_string(), "Country".to_string());
        self.translations
            .insert("city".to_string(), "City".to_string());
        self.translations
            .insert("bytes_sent".to_string(), "Bytes Sent".to_string());
        self.translations
            .insert("bytes_received".to_string(), "Bytes Received".to_string());
        self.translations
            .insert("packets_sent".to_string(), "Packets Sent".to_string());
        self.translations.insert(
            "packets_received".to_string(),
            "Packets Received".to_string(),
        );
        self.translations
            .insert("last_activity".to_string(), "Last Activity".to_string());
        self.translations
            .insert("process_name".to_string(), "Process Name".to_string());
        self.translations
            .insert("command_line".to_string(), "Command Line".to_string());
        self.translations
            .insert("user".to_string(), "User".to_string());
        self.translations
            .insert("cpu_usage".to_string(), "CPU Usage".to_string());
        self.translations
            .insert("memory_usage".to_string(), "Memory Usage".to_string());
        self.translations.insert(
            "process_connections".to_string(),
            "Process Connections".to_string(),
        );

        // Statistics
        self.translations
            .insert("tcp_connections".to_string(), "TCP Connections".to_string());
        self.translations
            .insert("udp_connections".to_string(), "UDP Connections".to_string());
        self.translations.insert(
            "total_connections".to_string(),
            "Total Connections".to_string(),
        );

        // Status messages
        self.translations.insert(
            "no_connections".to_string(),
            "No connections found".to_string(),
        );
        self.translations
            .insert("no_processes".to_string(), "No processes found".to_string());
        self.translations.insert(
            "process_not_found".to_string(),
            "Process not found".to_string(),
        );
        self.translations.insert(
            "no_pid_for_connection".to_string(),
            "No process ID for this connection".to_string(),
        );
        self.translations.insert(
            "press_for_process_details".to_string(),
            "Press for process details".to_string(),
        );
        self.translations.insert(
            "press_h_for_help".to_string(),
            "Press 'h' for help".to_string(),
        );
        self.translations
            .insert("default".to_string(), "default".to_string());
        self.translations
            .insert("language".to_string(), "Language".to_string());

        // Help screen
        self.translations.insert(
            "help_intro".to_string(),
            "is a cross-platform network monitoring tool".to_string(),
        );
        self.translations
            .insert("help_quit".to_string(), "Quit the application".to_string());
        self.translations.insert(
            "help_refresh".to_string(),
            "Refresh connections".to_string(),
        );
        self.translations
            .insert("help_navigate".to_string(), "Navigate up/down".to_string());
        self.translations.insert(
            "help_select".to_string(),
            "Select connection/view details".to_string(),
        );
        self.translations.insert(
            "help_back".to_string(),
            "Go back to previous view".to_string(),
        );
        self.translations.insert(
            "help_toggle_location".to_string(),
            "Toggle IP location display".to_string(),
        );
        self.translations.insert(
            "help_toggle_help".to_string(),
            "Toggle help screen".to_string(),
        );
    }

    /// Get available languages
    pub fn available_languages() -> Vec<(String, String)> {
        let mut languages = Vec::new();

        // Add built-in languages
        languages.push(("en".to_string(), "English".to_string()));

        // Look for translation files in current directory
        if let Ok(entries) = fs::read_dir("i18n") {
            for entry in entries.flatten() {
                if let Some(filename) = entry.path().file_stem() {
                    if let Some(lang_code) = filename.to_str() {
                        if lang_code != "en" {
                            languages.push((lang_code.to_string(), Self::language_name(lang_code)));
                        }
                    }
                }
            }
        }

        languages
    }

    /// Get language name from ISO code
    fn language_name(code: &str) -> String {
        match code {
            "en" => "English".to_string(),
            "fr" => "Français".to_string(),
            "de" => "Deutsch".to_string(),
            "es" => "Español".to_string(),
            "it" => "Italiano".to_string(),
            "pt" => "Português".to_string(),
            "ru" => "Русский".to_string(),
            "ja" => "日本語".to_string(),
            "zh" => "中文".to_string(),
            _ => code.to_string(),
        }
    }
}
