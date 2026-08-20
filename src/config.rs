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
//! warning (emitted before the terminal enters raw mode). Overrides that
//! leave text unreadable on its background are reported the same way by the
//! contrast guard in `ui::theme`, which warns but never changes a color.

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
/// Home directory of the user who invoked `sudo`, when running under it.
/// `None` when not under sudo, when the invoking user is root anyway (their
/// own HOME is then correct), or when the passwd lookup yields nothing.
#[cfg(not(windows))]
fn invoking_user_home() -> Option<PathBuf> {
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    if uid == 0 {
        return None;
    }
    let user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty())?;
    // Read the home field straight out of the passwd database rather than
    // assuming /home/<user>: it is wrong for root, for macOS (/Users), and
    // for anyone with a relocated home.
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd_home(&passwd, &user)
}

/// Home directory field for `user` in the contents of a passwd file.
#[cfg(not(windows))]
fn passwd_home(passwd: &str, user: &str) -> Option<PathBuf> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != user {
            return None;
        }
        // name:passwd:uid:gid:gecos:home:shell, so home is four past passwd.
        let home = fields.nth(4)?;
        (!home.is_empty()).then(|| PathBuf::from(home))
    })
}

fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .filter(|v| !v.is_empty())
            .map(|appdata| PathBuf::from(appdata).join("rustnet").join("config.toml"))
    }
    #[cfg(not(windows))]
    {
        // Under `sudo rustnet`, which the docs recommend, sudo's env_reset
        // clears XDG_CONFIG_HOME and many distros point HOME at /root, so
        // both would resolve to root's config rather than the config of the
        // person who ran the command. rustnet already drops back to
        // SUDO_UID/SUDO_GID after initialization, so it knows who that is:
        // resolve their home the same way and read their config.
        if let Some(home) = invoking_user_home() {
            return Some(home.join(".config").join("rustnet").join("config.toml"));
        }
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
    #[cfg(not(windows))]
    fn passwd_home_reads_the_home_field_not_a_guessed_path() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      marco:x:1000:1000:Marco:/home/marco:/usr/bin/fish\n\
                      relocated:x:1001:1001::/srv/people/relocated:/bin/sh\n\
                      noshell:x:1002:1002:::\n";
        assert_eq!(
            passwd_home(passwd, "marco"),
            Some(PathBuf::from("/home/marco"))
        );
        // A home outside /home is exactly why the field is read, not guessed.
        assert_eq!(
            passwd_home(passwd, "relocated"),
            Some(PathBuf::from("/srv/people/relocated"))
        );
        assert_eq!(passwd_home(passwd, "root"), Some(PathBuf::from("/root")));
        // An empty home field is not a usable answer.
        assert_eq!(passwd_home(passwd, "noshell"), None);
        assert_eq!(passwd_home(passwd, "absent"), None);
    }

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
