//! Theme presets and the overridable token layer.
//!
//! A [`ThemeSpec`] holds one [`TokenColor`] per semantic token. Config file
//! overrides mutate the spec via [`ThemeSpec::set_token`]; the spec is then
//! resolved into a final [`super::Theme`] (colors plus gradient ramps) by
//! [`super::Theme::resolve`]. Field, TCP-state, and protocol role colors are
//! mapped from these core tokens during resolve, so they are deliberately
//! not part of the spec: overriding `accent` propagates everywhere.

use ratatui::style::Color;

/// One themable color: an RGB value for truecolor terminals plus an
/// ANSI-16 fallback. `rgb: None` means "always emit `ansi`" (used for
/// `Color::Reset` tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenColor {
    pub rgb: Option<(u8, u8, u8)>,
    pub ansi: Color,
    /// True for user config overrides: resolve honors the value even on
    /// presets whose own tokens stay ANSI (muted, vivid), so an explicit
    /// override never silently degrades or vanishes.
    pub exact: bool,
}

/// Selectable built-in themes (`--theme` CLI flag, `[theme] name` config key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemePreset {
    /// Restrained default: one cyan accent, color only for semantic signals.
    Muted,
    /// Colored chrome on the ANSI-16 palette: yellow headings and keys,
    /// magenta borders, where Muted leaves all three gray.
    Vivid,
    /// Catppuccin Mocha (truecolor).
    CatppuccinMocha,
    /// Tokyo Night (truecolor).
    TokyoNight,
    /// Gruvbox dark, bright variants (truecolor).
    Gruvbox,
    /// Nord (truecolor).
    Nord,
}

impl ThemePreset {
    pub const ALL: [ThemePreset; 6] = [
        ThemePreset::Muted,
        ThemePreset::Vivid,
        ThemePreset::CatppuccinMocha,
        ThemePreset::TokyoNight,
        ThemePreset::Gruvbox,
        ThemePreset::Nord,
    ];

    /// Exact CLI/config names, no aliases.
    pub fn from_name(name: &str) -> Option<ThemePreset> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    pub fn name(self) -> &'static str {
        match self {
            ThemePreset::Muted => "muted",
            ThemePreset::Vivid => "vivid",
            ThemePreset::CatppuccinMocha => "catppuccin-mocha",
            ThemePreset::TokyoNight => "tokyo-night",
            ThemePreset::Gruvbox => "gruvbox",
            ThemePreset::Nord => "nord",
        }
    }
}

/// Overridable token layer of a theme. See the module docs: role colors are
/// derived from these during resolve and are not part of the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThemeSpec {
    /// Whether the chrome itself takes color: yellow headings and keys,
    /// magenta borders, plus the per-field palette that goes with them.
    pub vivid: bool,
    /// When false, built-in tokens always emit their `ansi` color (muted,
    /// vivid); `exact` user overrides are still honored.
    pub truecolor_tokens: bool,
    pub accent: TokenColor,
    pub ok: TokenColor,
    pub warn: TokenColor,
    pub err: TokenColor,
    pub info: TokenColor,
    pub special: TokenColor,
    pub muted: TokenColor,
    pub faint: TokenColor,
    pub text: TokenColor,
    pub heading: TokenColor,
    pub label: TokenColor,
    pub key: TokenColor,
    pub border: TokenColor,
    pub rx: TokenColor,
    pub tx: TokenColor,
    /// Ramp seed override for the RX wave; `None` = use `rx`.
    pub rx_wave: Option<TokenColor>,
    /// Ramp seed override for the TX wave; `None` = use `tx`.
    pub tx_wave: Option<TokenColor>,
    /// Selection band background; `None` = REVERSED fallback.
    pub selection_bg: Option<TokenColor>,
    /// Selection band foreground; `None` = keep the row's own fg.
    pub selection_fg: Option<TokenColor>,
    /// Status bar background tint; `None` = REVERSED fallback.
    pub status_bg: Option<TokenColor>,
    /// Hue wheel (degrees) for per-identity tints, indexed by a stable hash
    /// of the identity's name (see `super::identity_color`). Not
    /// overridable from the config file.
    pub identity_hues: &'static [u16],
}

/// Default identity hue wheel: 16 well-separated hues walked in a
/// scattered order, so adjacent hash buckets stay visually distinct. Every
/// built-in shares this list; presets may curate their own later.
pub(super) const IDENTITY_HUES: &[u16] = &[
    220, 280, 170, 30, 330, 140, 200, 260, 50, 0, 185, 20, 235, 295, 155, 340,
];

/// Valid `set_token` keys, matching the `ThemeSpec` token field names.
const TOKEN_NAMES: [&str; 20] = [
    "accent",
    "ok",
    "warn",
    "err",
    "info",
    "special",
    "muted",
    "faint",
    "text",
    "heading",
    "label",
    "key",
    "border",
    "rx",
    "tx",
    "rx_wave",
    "tx_wave",
    "selection_bg",
    "selection_fg",
    "status_bg",
];

impl ThemeSpec {
    pub fn builtin(preset: ThemePreset) -> ThemeSpec {
        match preset {
            ThemePreset::Muted => muted_or_vivid(false),
            ThemePreset::Vivid => muted_or_vivid(true),
            ThemePreset::CatppuccinMocha => catppuccin_mocha(),
            ThemePreset::TokyoNight => tokyo_night(),
            ThemePreset::Gruvbox => gruvbox(),
            ThemePreset::Nord => nord(),
        }
    }

    /// Whether any token carries a user config override (see
    /// [`TokenColor::exact`]). Gates the contrast guard, which only has
    /// something to say about hand-picked colors.
    pub(super) fn has_overrides(&self) -> bool {
        let required = [
            self.accent,
            self.ok,
            self.warn,
            self.err,
            self.info,
            self.special,
            self.muted,
            self.faint,
            self.text,
            self.heading,
            self.label,
            self.key,
            self.border,
            self.rx,
            self.tx,
        ];
        let optional = [
            self.rx_wave,
            self.tx_wave,
            self.selection_bg,
            self.selection_fg,
            self.status_bg,
        ];
        required.iter().any(|t| t.exact) || optional.iter().flatten().any(|t| t.exact)
    }

    /// Apply one config override. `token` is a snake_case key (the field
    /// names above); `value` is an ANSI color name or `#rrggbb`. The `Err`
    /// string is a human-readable message intended for stderr.
    pub fn set_token(&mut self, token: &str, value: &str) -> Result<(), String> {
        if !TOKEN_NAMES.contains(&token) {
            return Err(format!(
                "unknown theme token {token:?}: expected one of {}",
                TOKEN_NAMES.join(", ")
            ));
        }
        let color = parse_color(value)?;
        if color.ansi == Color::Reset
            && matches!(token, "selection_bg" | "selection_fg" | "status_bg")
        {
            return Err(format!(
                "\"reset\" is not a valid value for {token}: use an ANSI color name or #rrggbb"
            ));
        }
        match token {
            "accent" => self.accent = color,
            "ok" => self.ok = color,
            "warn" => self.warn = color,
            "err" => self.err = color,
            "info" => self.info = color,
            "special" => self.special = color,
            "muted" => self.muted = color,
            "faint" => self.faint = color,
            "text" => self.text = color,
            "heading" => self.heading = color,
            "label" => self.label = color,
            "key" => self.key = color,
            "border" => self.border = color,
            "rx" => self.rx = color,
            "tx" => self.tx = color,
            "rx_wave" => self.rx_wave = Some(color),
            "tx_wave" => self.tx_wave = Some(color),
            "selection_bg" => self.selection_bg = Some(color),
            "selection_fg" => self.selection_fg = Some(color),
            "status_bg" => self.status_bg = Some(color),
            _ => unreachable!("token validated above"),
        }
        Ok(())
    }
}

/// Whether the terminal advertises truecolor support: COLORTERM contains
/// "truecolor" or "24bit" (case-insensitive).
pub fn detect_truecolor() -> bool {
    std::env::var("COLORTERM").is_ok_and(|v| {
        let v = v.to_ascii_lowercase();
        v.contains("truecolor") || v.contains("24bit")
    })
}

/// Reference RGB values for the 16 ANSI colors (VGA palette). Used both for
/// name-to-ramp-seed mapping and for nearest-color fallback matching.
const ANSI16: [(Color, (u8, u8, u8)); 16] = [
    (Color::Black, (0x00, 0x00, 0x00)),
    (Color::Red, (0x80, 0x00, 0x00)),
    (Color::Green, (0x00, 0x80, 0x00)),
    (Color::Yellow, (0x80, 0x80, 0x00)),
    (Color::Blue, (0x00, 0x00, 0x80)),
    (Color::Magenta, (0x80, 0x00, 0x80)),
    (Color::Cyan, (0x00, 0x80, 0x80)),
    (Color::Gray, (0xC0, 0xC0, 0xC0)),
    (Color::DarkGray, (0x80, 0x80, 0x80)),
    (Color::LightRed, (0xFF, 0x00, 0x00)),
    (Color::LightGreen, (0x00, 0xFF, 0x00)),
    (Color::LightYellow, (0xFF, 0xFF, 0x00)),
    (Color::LightBlue, (0x00, 0x00, 0xFF)),
    (Color::LightMagenta, (0xFF, 0x00, 0xFF)),
    (Color::LightCyan, (0x00, 0xFF, 0xFF)),
    (Color::White, (0xFF, 0xFF, 0xFF)),
];

/// Reference RGB for an ANSI color, `None` for `Color::Reset` (and any
/// non-ANSI variant, which token colors never hold).
pub(super) fn ansi_seed(ansi: Color) -> Option<(u8, u8, u8)> {
    ANSI16.iter().find(|(c, _)| *c == ansi).map(|(_, rgb)| *rgb)
}

/// The ANSI-16 color with the minimum squared Euclidean RGB distance to
/// `rgb`; first match wins on ties (in `ANSI16` table order).
pub(super) fn nearest_ansi(rgb: (u8, u8, u8)) -> Color {
    fn dist(a: (u8, u8, u8), b: (u8, u8, u8)) -> u32 {
        let d = |x: u8, y: u8| {
            let d = i32::from(x) - i32::from(y);
            (d * d) as u32
        };
        d(a.0, b.0) + d(a.1, b.1) + d(a.2, b.2)
    }
    ANSI16
        .iter()
        .min_by_key(|(_, reference)| dist(rgb, *reference))
        .map(|(c, _)| *c)
        .expect("ANSI16 is non-empty")
}

/// Parse a config color value: an ANSI color name or `#rrggbb`. The result
/// is `exact`: hex values emit their RGB on truecolor terminals whatever
/// the preset, ANSI names always emit the terminal's palette color (their
/// reference RGB is derived from `ansi` when a ramp seed is needed).
pub(super) fn parse_color(value: &str) -> Result<TokenColor, String> {
    if let Some(hex) = value.strip_prefix('#') {
        if hex.len() == 6 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
            let n = u32::from_str_radix(hex, 16).expect("validated hex digits");
            let rgb = ((n >> 16) as u8, (n >> 8) as u8, n as u8);
            return Ok(TokenColor {
                rgb: Some(rgb),
                ansi: nearest_ansi(rgb),
                exact: true,
            });
        }
        return Err(format!(
            "invalid color {value:?}: expected an ANSI color name or #rrggbb"
        ));
    }
    // ANSI names only; deliberately not ratatui's FromStr, which also
    // accepts indexed forms we do not want to support in config.
    let ansi = match value.to_ascii_lowercase().as_str() {
        "black" => Color::Black,
        "red" => Color::Red,
        "green" => Color::Green,
        "yellow" => Color::Yellow,
        "blue" => Color::Blue,
        "magenta" => Color::Magenta,
        "cyan" => Color::Cyan,
        "gray" | "grey" => Color::Gray,
        "darkgray" | "darkgrey" => Color::DarkGray,
        "lightred" => Color::LightRed,
        "lightgreen" => Color::LightGreen,
        "lightyellow" => Color::LightYellow,
        "lightblue" => Color::LightBlue,
        "lightmagenta" => Color::LightMagenta,
        "lightcyan" => Color::LightCyan,
        "white" => Color::White,
        "reset" => Color::Reset,
        _ => {
            return Err(format!(
                "invalid color {value:?}: expected an ANSI color name or #rrggbb"
            ));
        }
    };
    Ok(TokenColor {
        rgb: None,
        ansi,
        exact: true,
    })
}

// --- Built-in specs ---

/// Token with an RGB ramp seed and an ANSI-16 color. On `truecolor_tokens`
/// themes the RGB is emitted (ANSI is the fallback); on muted/vivid the
/// ANSI name is always emitted and the RGB only seeds gradient ramps.
const fn rgb(hex: u32, ansi: Color) -> TokenColor {
    TokenColor {
        rgb: Some(((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)),
        ansi,
        exact: false,
    }
}

/// Token that always emits its ANSI color and has no RGB ramp seed.
const fn ansi_only(ansi: Color) -> TokenColor {
    TokenColor {
        rgb: None,
        ansi,
        exact: false,
    }
}

/// Muted (default) and Vivid share every token except the three Vivid
/// colors the chrome: heading and key go yellow, border goes magenta, where
/// Muted keeps them the terminal foreground, cyan, and dark gray.
/// `truecolor_tokens` is false for both, so neither emits RGB outside the
/// gradient ramps and both follow the terminal's own ANSI-16 palette.
fn muted_or_vivid(vivid: bool) -> ThemeSpec {
    ThemeSpec {
        vivid,
        truecolor_tokens: false,
        accent: rgb(0x0891B2, Color::Cyan),
        ok: rgb(0x10B981, Color::Green),
        warn: rgb(0xD97706, Color::Yellow),
        err: rgb(0xDC2626, Color::Red),
        info: rgb(0x3B82F6, Color::Blue),
        special: rgb(0xC026D3, Color::Magenta),
        muted: rgb(0x6B7280, Color::Gray),
        faint: rgb(0x4B5563, Color::DarkGray),
        text: ansi_only(Color::Reset),
        heading: if vivid {
            ansi_only(Color::Yellow)
        } else {
            ansi_only(Color::Reset)
        },
        label: ansi_only(Color::Gray),
        key: if vivid {
            ansi_only(Color::Yellow)
        } else {
            ansi_only(Color::Cyan)
        },
        border: if vivid {
            ansi_only(Color::Magenta)
        } else {
            ansi_only(Color::DarkGray)
        },
        rx: rgb(0x10B981, Color::Green),
        tx: rgb(0x3B82F6, Color::Blue),
        // Keep today's wave directions: blue RX wave, green TX wave, while
        // the rx/tx table text colors stay Green/Blue respectively.
        rx_wave: Some(rgb(0x3B82F6, Color::Blue)),
        tx_wave: Some(rgb(0x10B981, Color::Green)),
        selection_bg: None,
        selection_fg: None,
        status_bg: None,
        identity_hues: IDENTITY_HUES,
    }
}

fn catppuccin_mocha() -> ThemeSpec {
    ThemeSpec {
        vivid: false,
        truecolor_tokens: true,
        accent: rgb(0xCBA6F7, Color::LightMagenta),
        ok: rgb(0xA6E3A1, Color::LightGreen),
        warn: rgb(0xF9E2AF, Color::LightYellow),
        err: rgb(0xF38BA8, Color::LightRed),
        info: rgb(0x89B4FA, Color::LightBlue),
        special: rgb(0xF5C2E7, Color::LightMagenta),
        muted: rgb(0x7F849C, Color::DarkGray),
        faint: rgb(0x585B70, Color::DarkGray),
        text: ansi_only(Color::Reset),
        heading: rgb(0xBAC2DE, Color::Gray),
        label: rgb(0x7F849C, Color::DarkGray),
        key: rgb(0xCBA6F7, Color::LightMagenta),
        border: rgb(0x585B70, Color::DarkGray),
        rx: rgb(0x74C7EC, Color::LightCyan),
        tx: rgb(0xA6E3A1, Color::LightGreen),
        rx_wave: None,
        tx_wave: None,
        selection_bg: Some(rgb(0x45475A, Color::DarkGray)),
        selection_fg: None,
        status_bg: Some(rgb(0x313244, Color::DarkGray)),
        identity_hues: IDENTITY_HUES,
    }
}

fn tokyo_night() -> ThemeSpec {
    ThemeSpec {
        vivid: false,
        truecolor_tokens: true,
        accent: rgb(0x7AA2F7, Color::LightBlue),
        ok: rgb(0x9ECE6A, Color::LightGreen),
        warn: rgb(0xE0AF68, Color::LightYellow),
        err: rgb(0xF7768E, Color::LightRed),
        info: rgb(0x7DCFFF, Color::LightCyan),
        special: rgb(0xBB9AF7, Color::LightMagenta),
        muted: rgb(0x565F89, Color::DarkGray),
        faint: rgb(0x3B4261, Color::DarkGray),
        text: ansi_only(Color::Reset),
        heading: rgb(0xA9B1D6, Color::Gray),
        label: rgb(0x565F89, Color::DarkGray),
        key: rgb(0x7AA2F7, Color::LightBlue),
        border: rgb(0x3B4261, Color::DarkGray),
        rx: rgb(0x7DCFFF, Color::LightCyan),
        tx: rgb(0x9ECE6A, Color::LightGreen),
        rx_wave: None,
        tx_wave: None,
        selection_bg: Some(rgb(0x33467C, Color::DarkGray)),
        selection_fg: None,
        status_bg: Some(rgb(0x292E42, Color::DarkGray)),
        identity_hues: IDENTITY_HUES,
    }
}

// Some ANSI fallbacks below intentionally deviate from pure nearest-distance
// matching to preserve semantic distinctness (gruvbox ok stays Green so it
// never collides with warn; nord info stays LightBlue).

fn gruvbox() -> ThemeSpec {
    ThemeSpec {
        vivid: false,
        truecolor_tokens: true,
        accent: rgb(0xFE8019, Color::LightRed),
        ok: rgb(0xB8BB26, Color::Green),
        warn: rgb(0xFABD2F, Color::LightYellow),
        err: rgb(0xFB4934, Color::Red),
        info: rgb(0x83A598, Color::Cyan),
        special: rgb(0xD3869B, Color::LightMagenta),
        muted: rgb(0x928374, Color::DarkGray),
        faint: rgb(0x665C54, Color::DarkGray),
        text: ansi_only(Color::Reset),
        heading: rgb(0xD5C4A1, Color::Gray),
        label: rgb(0x928374, Color::DarkGray),
        key: rgb(0xFE8019, Color::LightRed),
        border: rgb(0x504945, Color::DarkGray),
        rx: rgb(0x83A598, Color::Cyan),
        tx: rgb(0xB8BB26, Color::Green),
        rx_wave: None,
        tx_wave: None,
        selection_bg: Some(rgb(0x504945, Color::DarkGray)),
        selection_fg: None,
        status_bg: Some(rgb(0x3C3836, Color::DarkGray)),
        identity_hues: IDENTITY_HUES,
    }
}

fn nord() -> ThemeSpec {
    ThemeSpec {
        vivid: false,
        truecolor_tokens: true,
        accent: rgb(0x88C0D0, Color::LightCyan),
        ok: rgb(0xA3BE8C, Color::LightGreen),
        warn: rgb(0xEBCB8B, Color::LightYellow),
        err: rgb(0xBF616A, Color::Red),
        info: rgb(0x81A1C1, Color::LightBlue),
        special: rgb(0xB48EAD, Color::LightMagenta),
        muted: rgb(0x616E88, Color::DarkGray),
        faint: rgb(0x4C566A, Color::DarkGray),
        text: ansi_only(Color::Reset),
        heading: rgb(0xD8DEE9, Color::Gray),
        label: rgb(0x616E88, Color::DarkGray),
        key: rgb(0x88C0D0, Color::LightCyan),
        border: rgb(0x3B4252, Color::DarkGray),
        rx: rgb(0x88C0D0, Color::LightCyan),
        tx: rgb(0xA3BE8C, Color::LightGreen),
        rx_wave: None,
        tx_wave: None,
        selection_bg: Some(rgb(0x434C5E, Color::DarkGray)),
        selection_fg: None,
        status_bg: Some(rgb(0x3B4252, Color::DarkGray)),
        identity_hues: IDENTITY_HUES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_names_round_trip() {
        for preset in ThemePreset::ALL {
            assert_eq!(ThemePreset::from_name(preset.name()), Some(preset));
        }
        assert_eq!(ThemePreset::from_name("bogus"), None);
    }

    #[test]
    fn cli_preset_list_matches_theme_presets() {
        // The clap value list lives in cli.rs as literals (build.rs
        // include!s that file); this pins it to the source of truth.
        assert_eq!(
            crate::cli::THEME_PRESETS,
            ThemePreset::ALL.map(|p| p.name())
        );
    }

    #[test]
    fn set_token_hex_sets_rgb_and_fallback() {
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        spec.set_token("accent", "#7aa2f7").unwrap();
        assert_eq!(spec.accent.rgb, Some((0x7A, 0xA2, 0xF7)));
        assert_eq!(spec.accent.ansi, nearest_ansi((0x7A, 0xA2, 0xF7)));
    }

    #[test]
    fn set_token_ansi_name_keeps_terminal_palette_color() {
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        spec.set_token("border", "darkgray").unwrap();
        assert_eq!(spec.border.ansi, Color::DarkGray);
        // No RGB: named overrides emit the terminal's own palette color;
        // ramp seeds fall back to the ANSI reference RGB.
        assert_eq!(spec.border.rgb, None);
        assert!(spec.border.exact);
    }

    #[test]
    fn set_token_rejects_bad_input() {
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        assert!(spec.set_token("nope", "red").is_err());
        assert!(spec.set_token("accent", "#12345").is_err());
        assert!(spec.set_token("accent", "notacolor").is_err());
    }

    #[test]
    fn set_token_rejects_reset_for_background_slots() {
        let mut spec = ThemeSpec::builtin(ThemePreset::TokyoNight);
        for token in ["selection_bg", "selection_fg", "status_bg"] {
            assert!(spec.set_token(token, "reset").is_err(), "{token}");
        }
        // "reset" stays valid for foreground tokens.
        assert!(spec.set_token("text", "reset").is_ok());
    }

    #[test]
    fn every_token_name_is_seen_by_has_overrides() {
        // The contrast guard only runs on overridden specs, so a token
        // that set_token accepts but has_overrides cannot see would
        // silently opt out of it.
        for token in TOKEN_NAMES {
            let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
            assert!(!spec.has_overrides(), "{token}");
            spec.set_token(token, "#3b4261").unwrap();
            assert!(spec.has_overrides(), "{token}");
        }
    }

    #[test]
    fn set_token_covers_optional_slots() {
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        spec.set_token("selection_bg", "#3b4261").unwrap();
        assert_eq!(
            spec.selection_bg.map(|t| t.rgb),
            Some(Some((0x3B, 0x42, 0x61)))
        );
        spec.set_token("rx_wave", "lightcyan").unwrap();
        assert_eq!(spec.rx_wave.map(|t| t.ansi), Some(Color::LightCyan));
    }

    #[test]
    fn nearest_ansi_minimizes_euclidean_distance() {
        assert_eq!(nearest_ansi((0x00, 0x00, 0x00)), Color::Black);
        assert_eq!(nearest_ansi((0xFF, 0xFF, 0xFF)), Color::White);
        // #fe8019 (gruvbox orange) sits closest to VGA Yellow (808000) by
        // squared distance; the gruvbox built-in pins LightRed by hand.
        assert_eq!(nearest_ansi((0xFE, 0x80, 0x19)), Color::Yellow);
    }

    #[test]
    fn parse_color_accepts_grey_spellings_and_reset() {
        assert_eq!(parse_color("grey").unwrap().ansi, Color::Gray);
        assert_eq!(parse_color("DarkGrey").unwrap().ansi, Color::DarkGray);
        let reset = parse_color("reset").unwrap();
        assert_eq!(reset.ansi, Color::Reset);
        assert_eq!(reset.rgb, None);
    }
}
