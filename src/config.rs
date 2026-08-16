//! User configuration file loading.
//!
//! rustnet reads an optional TOML file for settings that do not fit the
//! command line, currently the color theme:
//!
//! ```toml
//! # ~/.config/rustnet/config.toml
//! [theme]
//! name = "tokyo-night"
//!
//! [theme.overrides]
//! accent = "#ff9e64"
//! border = "darkgray"
//! ```
//!
//! Loading never fails: a missing file yields the defaults silently, and an
//! unreadable or invalid file yields the defaults after a single stderr
//! warning (emitted before the terminal enters raw mode).

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

/// Raw on-disk schema. Unknown top-level and `[theme]` keys are ignored for
/// forward compatibility.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawConfig {
    theme: RawTheme,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RawTheme {
    name: Option<String>,
    /// BTreeMap so warnings about bad overrides come out in a stable order.
    overrides: BTreeMap<String, String>,
}

/// Parsed user configuration. Override values are validated later by
/// `ThemeSpec::set_token`, not here.
#[derive(Debug, Default, PartialEq)]
pub struct UserConfig {
    pub theme: Option<String>,
    pub overrides: Vec<(String, String)>,
}

/// Load the user configuration. Never panics, never fails: missing file is
/// a silent default; an unreadable file or parse error prints one stderr
/// warning naming the path and falls back to the default.
pub fn load() -> UserConfig {
    let Some(path) = config_path() else {
        return UserConfig::default();
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return UserConfig::default(),
        Err(e) => {
            eprintln!("rustnet: cannot read {}: {e}", path.display());
            return UserConfig::default();
        }
    };
    match parse(&contents) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("rustnet: invalid config {}: {e}", path.display());
            UserConfig::default()
        }
    }
}

/// Pure parsing core, unit-testable without the filesystem.
fn parse(contents: &str) -> Result<UserConfig, String> {
    let raw: RawConfig = toml::from_str(contents).map_err(|e| e.to_string())?;
    Ok(UserConfig {
        theme: raw.theme.name,
        overrides: raw.theme.overrides.into_iter().collect(),
    })
}

/// Platform config file location, from environment variables only:
/// `%APPDATA%\rustnet\config.toml` on Windows, otherwise
/// `$XDG_CONFIG_HOME/rustnet/config.toml` (when set and non-empty) or
/// `$HOME/.config/rustnet/config.toml`. `None` when the relevant
/// environment variables are unset.
fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .filter(|v| !v.is_empty())
            .map(|appdata| PathBuf::from(appdata).join("rustnet").join("config.toml"))
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Some(PathBuf::from(xdg).join("rustnet").join("config.toml"));
        }
        std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .map(|home| {
                PathBuf::from(home)
                    .join(".config")
                    .join("rustnet")
                    .join("config.toml")
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_theme_name_and_overrides() {
        let config = parse(
            r##"
[theme]
name = "tokyo-night"

[theme.overrides]
accent = "#ff9e64"
border = "darkgray"
selection_bg = "#3b4261"
"##,
        )
        .unwrap();
        assert_eq!(config.theme.as_deref(), Some("tokyo-night"));
        assert_eq!(
            config.overrides,
            vec![
                ("accent".to_string(), "#ff9e64".to_string()),
                ("border".to_string(), "darkgray".to_string()),
                ("selection_bg".to_string(), "#3b4261".to_string()),
            ]
        );
    }

    #[test]
    fn empty_input_yields_default() {
        assert_eq!(parse("").unwrap(), UserConfig::default());
    }

    #[test]
    fn theme_name_without_overrides() {
        let config = parse("[theme]\nname = \"nord\"\n").unwrap();
        assert_eq!(config.theme.as_deref(), Some("nord"));
        assert!(config.overrides.is_empty());
    }

    #[test]
    fn invalid_toml_is_an_error() {
        let err = parse("not [valid toml").unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let config = parse(
            r#"
[capture]
foo = 1

[theme]
name = "gruvbox"
unknown = "x"
"#,
        )
        .unwrap();
        assert_eq!(config.theme.as_deref(), Some("gruvbox"));
        assert!(config.overrides.is_empty());
    }
}
