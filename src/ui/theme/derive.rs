//! Theme resolution: spec tokens into final colors, roles, and gradient
//! ramps.
//!
//! The 5-stop gradient ramps used by the braille traffic waves and glow
//! bars are derived here from each token's RGB seed via a small HSL walk,
//! so an override of a core token automatically re-tints its gradients.

use ratatui::style::Color;

use super::definitions::{ThemeSpec, TokenColor, ansi_seed};

/// Fully resolved theme: final `Color` per token and role, plus
/// precomputed gradient ramps. Built once at startup by [`Theme::resolve`]
/// and stored in the module-level `ACTIVE` static.
#[derive(Debug, Clone)]
pub struct Theme {
    pub(super) classic: bool,

    // Core tokens.
    pub(super) accent: Color,
    pub(super) ok: Color,
    pub(super) warn: Color,
    pub(super) err: Color,
    pub(super) info: Color,
    pub(super) muted: Color,
    pub(super) faint: Color,
    pub(super) text: Color,
    pub(super) heading: Color,
    pub(super) label: Color,
    pub(super) key: Color,
    pub(super) border: Color,
    pub(super) rx: Color,
    pub(super) tx: Color,

    // Background tints; `None` unless the theme is truecolor or the user
    // explicitly overrode the slot.
    pub(super) selection_bg: Option<Color>,
    pub(super) selection_fg: Option<Color>,
    pub(super) status_bg: Option<Color>,

    // Role colors mapped from the core tokens at resolve time.
    pub(super) field_local_addr: Color,
    pub(super) field_remote_addr: Color,
    pub(super) field_state: Color,
    pub(super) field_service: Color,
    pub(super) field_location: Color,
    pub(super) field_process: Color,
    pub(super) field_application: Color,
    pub(super) field_attributed_hostname: Color,
    pub(super) tcp_established: Color,
    pub(super) tcp_opening: Color,
    pub(super) tcp_closing: Color,
    pub(super) tcp_waiting: Color,
    pub(super) tcp_closed: Color,
    pub(super) proto_https: Color,
    pub(super) proto_quic: Color,
    pub(super) proto_http: Color,
    pub(super) proto_dns: Color,
    pub(super) proto_ssh: Color,
    pub(super) proto_other: Color,

    // Gradient ramps. These always emit `Color::Rgb` regardless of the
    // terminal's truecolor support (terminals approximate; NO_COLOR still
    // strips them via `fg()`).
    pub(super) rx_ramp: [(u8, u8, u8); 5],
    pub(super) tx_ramp: [(u8, u8, u8); 5],
    pub(super) accent_ramp: [(u8, u8, u8); 5],
    pub(super) ok_ramp: [(u8, u8, u8); 5],
    pub(super) warn_ramp: [(u8, u8, u8); 5],
    pub(super) err_ramp: [(u8, u8, u8); 5],
    pub(super) special_ramp: [(u8, u8, u8); 5],
    pub(super) muted_ramp: [(u8, u8, u8); 5],
    pub(super) expiry_ramp: [(u8, u8, u8); 5],

    /// 3-stop accent shimmer for the loading screen; `None` (static accent)
    /// unless the preset and the terminal both do truecolor.
    pub(super) shimmer_ramp: Option<[(u8, u8, u8); 3]>,
    /// Hue wheel for per-identity tints; `None` disables them (ANSI
    /// terminal, or the classic preset, which keeps its historic look).
    pub(super) identity_hues: Option<&'static [u16]>,

    /// Raised background a status bar keycap sits on, and the recessed tone
    /// its label takes beside it. `None` on the classic preset, which keeps
    /// its historic bold-key status bar.
    pub(super) key_cap_bg: Option<(u8, u8, u8)>,
    pub(super) hint_label: Option<(u8, u8, u8)>,
}

impl Theme {
    /// Resolve a spec into final colors. `terminal_truecolor` should be
    /// [`super::detect_truecolor`]'s result; it is ignored when
    /// `spec.truecolor_tokens` is false.
    pub fn resolve(spec: &ThemeSpec, terminal_truecolor: bool) -> Theme {
        let truecolor = spec.truecolor_tokens && terminal_truecolor;
        // `exact` (user-overridden) tokens are honored on every preset:
        // their RGB is emitted whenever the terminal supports truecolor,
        // and their bg slots are never dropped.
        let color = |t: TokenColor| match t.rgb {
            Some((r, g, b)) if truecolor || (t.exact && terminal_truecolor) => Color::Rgb(r, g, b),
            _ => t.ansi,
        };
        let bg = |t: Option<TokenColor>| t.filter(|t| truecolor || t.exact).map(color);
        // Ramp seed: the token's RGB if set, else the ANSI reference RGB,
        // else (Reset) fall back to Gray. Built-ins never hit the last arm;
        // it is defensive only.
        let seed = |t: TokenColor| {
            t.rgb
                .or_else(|| ansi_seed(t.ansi))
                .unwrap_or((0xC0, 0xC0, 0xC0))
        };

        let accent = color(spec.accent);
        let ok = color(spec.ok);
        let warn = color(spec.warn);
        let err = color(spec.err);
        let info = color(spec.info);
        let special = color(spec.special);
        let muted = color(spec.muted);
        let text = color(spec.text);
        let classic = spec.classic;
        // Keycaps are always RGB, the same bargain the gradient ramps
        // strike: ANSI-16 holds no tone subtle enough for a raised chip, and
        // terminals approximate what they cannot render. Classic opts out and
        // keeps the historic bold-key bar.
        let (key_cap_bg, hint_label) = if classic {
            (None, None)
        } else {
            (
                Some(key_cap_tint(spec.status_bg.map(seed), seed(spec.key))),
                Some(seed(spec.muted)),
            )
        };

        let theme = Theme {
            classic,
            accent,
            ok,
            warn,
            err,
            info,
            muted,
            faint: color(spec.faint),
            text,
            heading: color(spec.heading),
            label: color(spec.label),
            key: color(spec.key),
            border: color(spec.border),
            rx: color(spec.rx),
            tx: color(spec.tx),
            selection_bg: bg(spec.selection_bg),
            selection_fg: bg(spec.selection_fg),
            status_bg: bg(spec.status_bg),
            field_local_addr: accent,
            field_remote_addr: info,
            field_state: if classic { ok } else { text },
            field_service: if classic { warn } else { muted },
            field_location: if classic { special } else { muted },
            field_process: if classic { ok } else { text },
            field_application: if classic { warn } else { muted },
            field_attributed_hostname: muted,
            tcp_established: if classic { ok } else { text },
            tcp_opening: warn,
            tcp_closing: if classic { accent } else { muted },
            tcp_waiting: if classic { special } else { muted },
            tcp_closed: muted,
            proto_https: ok,
            proto_quic: accent,
            proto_http: warn,
            proto_dns: special,
            proto_ssh: info,
            proto_other: muted,
            rx_ramp: glow_ramp(seed(spec.rx_wave.unwrap_or(spec.rx))),
            tx_ramp: glow_ramp(seed(spec.tx_wave.unwrap_or(spec.tx))),
            accent_ramp: glow_ramp(seed(spec.accent)),
            ok_ramp: glow_ramp(seed(spec.ok)),
            warn_ramp: signal_ramp(seed(spec.warn)),
            err_ramp: signal_ramp(seed(spec.err)),
            special_ramp: signal_ramp(seed(spec.special)),
            muted_ramp: signal_ramp(seed(spec.muted)),
            expiry_ramp: expiry_ramp(seed(spec.warn), seed(spec.err)),
            shimmer_ramp: truecolor.then(|| shimmer_ramp(seed(spec.accent))),
            // Identity tints synthesize RGB directly, so they need a
            // truecolor terminal but not a truecolor preset. Classic opts
            // out: its per-field palette is pinned to the historic look.
            identity_hues: (terminal_truecolor && !classic && !spec.identity_hues.is_empty())
                .then_some(spec.identity_hues),
            key_cap_bg,
            hint_label,
        };

        // NO_COLOR strips every color before it reaches the terminal, so
        // there is nothing left to be unreadable: stay quiet there.
        let no_color = crate::ui::NO_COLOR.load(crate::ui::Ordering::Relaxed);
        if spec.has_overrides() && !no_color {
            for warning in contrast_warnings(&theme) {
                eprintln!("rustnet: {warning}");
            }
        }
        theme
    }
}

// --- HSL helpers (h in degrees [0, 360), s and l in [0, 1]) ---

pub(super) fn rgb_to_hsl(rgb: (u8, u8, u8)) -> (f64, f64, f64) {
    let r = f64::from(rgb.0) / 255.0;
    let g = f64::from(rgb.1) / 255.0;
    let b = f64::from(rgb.2) / 255.0;
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;
    if max == min {
        return (0.0, 0.0, l);
    }
    let d = max - min;
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };
    let h = if max == r {
        60.0 * ((g - b) / d)
    } else if max == g {
        60.0 * ((b - r) / d + 2.0)
    } else {
        60.0 * ((r - g) / d + 4.0)
    };
    (h.rem_euclid(360.0), s, l)
}

pub(super) fn hsl_to_rgb(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let hp = h.rem_euclid(360.0) / 60.0;
    let x = c * (1.0 - (hp % 2.0 - 1.0).abs());
    let (r1, g1, b1) = match hp as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    let m = l - c / 2.0;
    let to_u8 = |v: f64| ((v + m) * 255.0).round().clamp(0.0, 255.0) as u8;
    (to_u8(r1), to_u8(g1), to_u8(b1))
}

/// Glow ramp (rx, tx, accent, ok waves): the saturated seed walking
/// brighter, capped, then a white-hot crest. Stop 0 is the seed exactly.
pub(super) fn glow_ramp(seed: (u8, u8, u8)) -> [(u8, u8, u8); 5] {
    let (h, s, l) = rgb_to_hsl(seed);
    // Never below the seed's own lightness: a pale seed (l > 0.85) holds
    // steady instead of dipping darker before the white crest.
    let cap = (l + 0.24).min(0.85).max(l);
    let mut stops = [(0u8, 0u8, 0u8); 5];
    stops[0] = seed; // guard against float drift at i = 0
    for (i, stop) in stops.iter_mut().enumerate().take(4).skip(1) {
        *stop = hsl_to_rgb(h, s, l + (cap - l) * i as f64 / 3.0);
    }
    stops[4] = (0xFF, 0xFF, 0xFF);
    stops
}

/// Signal ramp (warn, err, special, muted waves): darker start below the
/// token, brighter finish, no white crest.
pub(super) fn signal_ramp(seed: (u8, u8, u8)) -> [(u8, u8, u8); 5] {
    let (h, s, l) = rgb_to_hsl(seed);
    let lo = (l - 0.18).clamp(0.20, 0.80);
    let hi = (l + 0.18).clamp(lo, 0.80);
    let mut stops = [(0u8, 0u8, 0u8); 5];
    for (i, stop) in stops.iter_mut().enumerate() {
        *stop = hsl_to_rgb(h, s, lo + (hi - lo) * i as f64 / 4.0);
    }
    stops
}

/// Expiry glow: brightest warn blending into a vivid red endpoint derived
/// from the err token's hue.
pub(super) fn expiry_ramp(warn_seed: (u8, u8, u8), err_seed: (u8, u8, u8)) -> [(u8, u8, u8); 5] {
    let a = signal_ramp(warn_seed)[4];
    let (eh, es, _) = rgb_to_hsl(err_seed);
    let b = hsl_to_rgb(eh, es.max(0.90), 0.58);
    let mut stops = [(0u8, 0u8, 0u8); 5];
    for (i, stop) in stops.iter_mut().enumerate() {
        let t = i as f64 / 4.0;
        *stop = (
            lerp_channel(a.0, b.0, t),
            lerp_channel(a.1, b.1, t),
            lerp_channel(a.2, b.2, t),
        );
    }
    stops
}

/// Midpoint between two colors, one channel at a time. Used by the edge
/// fade to pull a foreground halfway toward the faint tier.
/// Lightness step from a theme's own status band up to its keycap chips.
const KEY_CAP_LIFT: f64 = 0.07;
/// Chip tone for themes with no status band of their own: dark and barely
/// saturated, so the key color on top stays the brightest part of the hint.
const KEY_CAP_SATURATION: f64 = 0.20;
const KEY_CAP_LIGHTNESS: f64 = 0.17;

/// Step the chip darkens by while it hunts for a legible tone.
const KEY_CAP_STEP: f64 = 0.01;

/// Raised background for a status bar keycap. Derived from the theme's own
/// status band when it has one, so the chip reads as one step above it,
/// otherwise from the key color's hue kept dark and desaturated, so the chip
/// recedes and the key on top of it carries the color.
///
/// The tint then darkens in small steps until the key clears `MIN_CONTRAST`
/// on top of it: a dark key color (ANSI cyan, for one) would otherwise sit
/// on a chip too close to its own tone to read.
pub(super) fn key_cap_tint(band: Option<(u8, u8, u8)>, key: (u8, u8, u8)) -> (u8, u8, u8) {
    let (hue, saturation, start) = match band {
        Some(band) => {
            let (h, s, l) = rgb_to_hsl(band);
            (h, s, (l + KEY_CAP_LIFT).min(1.0))
        }
        None => (rgb_to_hsl(key).0, KEY_CAP_SATURATION, KEY_CAP_LIGHTNESS),
    };
    let mut lightness = start;
    loop {
        let tint = hsl_to_rgb(hue, saturation, lightness);
        if lightness <= 0.0 || contrast_ratio(tint, key) >= MIN_CONTRAST {
            return tint;
        }
        lightness = (lightness - KEY_CAP_STEP).max(0.0);
    }
}

pub(super) fn blend_half(a: (u8, u8, u8), b: (u8, u8, u8)) -> (u8, u8, u8) {
    (
        lerp_channel(a.0, b.0, 0.5),
        lerp_channel(a.1, b.1, 0.5),
        lerp_channel(a.2, b.2, 0.5),
    )
}

pub(super) fn lerp_channel(a: u8, b: u8, t: f64) -> u8 {
    (a as f64 + (b as f64 - a as f64) * t).round() as u8
}

/// Walk a 5-stop color ramp at `t` ∈ [0, 1] (4 linear segments).
pub(super) fn five_stop(stops: &[(u8, u8, u8); 5], t: f64) -> Color {
    let seg = t.clamp(0.0, 1.0) * 4.0;
    let i = (seg as usize).min(3);
    let local = seg - i as f64;
    let (a, b) = (stops[i], stops[i + 1]);
    Color::Rgb(
        lerp_channel(a.0, b.0, local),
        lerp_channel(a.1, b.1, local),
        lerp_channel(a.2, b.2, local),
    )
}

// --- Contrast (WCAG) ---

/// Relative luminance of an sRGB color, per the WCAG 2.x definition.
pub(super) fn relative_luminance(r: u8, g: u8, b: u8) -> f64 {
    fn linear(channel: u8) -> f64 {
        let c = f64::from(channel) / 255.0;
        if c <= 0.03928 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    }
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

/// WCAG contrast ratio between two colors, in `[1.0, 21.0]`. Order does
/// not matter.
pub(super) fn contrast_ratio(a: (u8, u8, u8), b: (u8, u8, u8)) -> f64 {
    let la = relative_luminance(a.0, a.1, a.2);
    let lb = relative_luminance(b.0, b.1, b.2);
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// Foreground candidates for [`super::on_color`]: near-black on light
/// backgrounds, near-white on dark ones (pure black/white read as harsh
/// next to the rest of the chrome).
pub(super) const ON_COLOR_DARK: (u8, u8, u8) = (26, 26, 26);
pub(super) const ON_COLOR_LIGHT: (u8, u8, u8) = (240, 240, 240);

/// Minimum fg/bg contrast the guard accepts: WCAG AA for large or bold
/// text, which is what every checked pair renders.
const MIN_CONTRAST: f64 = 3.0;

/// Reference RGB for a resolved color: itself when truecolor, the ANSI
/// reference otherwise, `None` for `Color::Reset` (the terminal's own
/// foreground, which we cannot know).
fn reference_rgb(color: Color) -> Option<(u8, u8, u8)> {
    match color {
        Color::Rgb(r, g, b) => Some((r, g, b)),
        other => ansi_seed(other),
    }
}

/// Warnings for fg/bg pairs a user override pushed below [`MIN_CONTRAST`],
/// one line per failing pair, ready for stderr. Nothing is altered: the
/// user's colors win, they just get told.
///
/// Only pairs whose text must stay readable are checked. The `label` tier
/// is deliberately dim (several built-ins sit below 3:1 on the status
/// band by design) and badge foregrounds are auto-picked by
/// [`super::on_color`], so neither needs a guard. ANSI colors are compared
/// via their reference palette RGB, which is an approximation of what the
/// terminal actually paints.
pub(super) fn contrast_warnings(theme: &Theme) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut check = |fg_name: &str, fg: Option<Color>, bg_name: &str, bg: Option<Color>| {
        let (Some(fg), Some(bg)) = (fg, bg) else {
            return;
        };
        let (Some(fg_rgb), Some(bg_rgb)) = (reference_rgb(fg), reference_rgb(bg)) else {
            return;
        };
        let ratio = contrast_ratio(fg_rgb, bg_rgb);
        if ratio < MIN_CONTRAST {
            warnings.push(format!(
                "theme contrast: {fg_name} on {bg_name} is {ratio:.1}:1, below {MIN_CONTRAST:.1}:1; text may be hard to read"
            ));
        }
    };
    // The selection band, which the filter chip also renders on.
    check(
        "selection_fg",
        theme.selection_fg,
        "selection_bg",
        theme.selection_bg,
    );
    // The status bar: keycaps carry its text.
    check("key", Some(theme.key), "status_bg", theme.status_bg);
    warnings
}

// --- Identity tints ---

const IDENTITY_SATURATION: f64 = 0.45;
const IDENTITY_LIGHTNESS: f64 = 0.68;

/// FNV-1a over the name's bytes: a stable, dependency-free hash, so the
/// same process name keeps the same tint across runs and machines.
fn fnv1a(name: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Tint for `name`: its hash picks a hue from `hues`, which is then
/// synthesized at a fixed pastel saturation and lightness so every
/// identity color carries the same weight. `hues` must be non-empty.
pub(super) fn identity_rgb(hues: &[u16], name: &str) -> (u8, u8, u8) {
    debug_assert!(!hues.is_empty(), "identity hue list must be non-empty");
    let hue = hues[(fnv1a(name) % hues.len() as u64) as usize];
    hsl_to_rgb(f64::from(hue), IDENTITY_SATURATION, IDENTITY_LIGHTNESS)
}

/// Shimmer ramp: the accent walking up to 24% lighter in three steps.
/// Stop 0 is the seed exactly, so a shimmer at rest is the accent color.
pub(super) fn shimmer_ramp(seed: (u8, u8, u8)) -> [(u8, u8, u8); 3] {
    let (h, s, l) = rgb_to_hsl(seed);
    [
        seed,
        hsl_to_rgb(h, s, (l + 0.12).clamp(0.0, 0.95)),
        hsl_to_rgb(h, s, (l + 0.24).clamp(0.0, 0.95)),
    ]
}

/// Walk a 3-stop color ramp at `t` ∈ [0, 1] (2 linear segments).
pub(super) fn three_stop(stops: &[(u8, u8, u8); 3], t: f64) -> Color {
    let seg = t.clamp(0.0, 1.0) * 2.0;
    let i = (seg as usize).min(1);
    let local = seg - i as f64;
    let (a, b) = (stops[i], stops[i + 1]);
    Color::Rgb(
        lerp_channel(a.0, b.0, local),
        lerp_channel(a.1, b.1, local),
        lerp_channel(a.2, b.2, local),
    )
}

#[cfg(test)]
mod tests {
    use super::super::definitions::{ThemePreset, ThemeSpec};
    use super::*;

    #[test]
    fn glow_ramp_keeps_seed_and_white_crest() {
        let seed = (0x3B, 0x82, 0xF6); // muted rx wave seed
        let ramp = glow_ramp(seed);
        assert_eq!(ramp[0], seed);
        assert_eq!(ramp[4], (0xFF, 0xFF, 0xFF));
    }

    #[test]
    fn glow_ramp_is_monotonic_for_pale_seeds() {
        // A seed lighter than the 0.85 cap must not dip darker before the
        // white crest.
        for seed in [(0xFF, 0xE9, 0xC2), (0xFF, 0xFF, 0xFF)] {
            let ramp = glow_ramp(seed);
            for pair in ramp.windows(2) {
                let (_, _, l0) = rgb_to_hsl(pair[0]);
                let (_, _, l1) = rgb_to_hsl(pair[1]);
                assert!(l1 >= l0 - 1e-9, "lightness decreased in {ramp:?}");
            }
        }
    }

    #[test]
    fn signal_ramp_lightness_is_non_decreasing() {
        for seed in [(0xD9, 0x77, 0x06), (0xDC, 0x26, 0x26), (0x6B, 0x72, 0x80)] {
            let ramp = signal_ramp(seed);
            for pair in ramp.windows(2) {
                let (_, _, l0) = rgb_to_hsl(pair[0]);
                let (_, _, l1) = rgb_to_hsl(pair[1]);
                assert!(l1 >= l0 - 1e-9, "lightness decreased in {ramp:?}");
            }
        }
    }

    #[test]
    fn hsl_round_trips_within_one_per_channel() {
        for rgb in [
            (0x3B, 0x82, 0xF6),
            (0xD9, 0x77, 0x06),
            (0x10, 0xB9, 0x81),
            (0x6B, 0x72, 0x80),
            (0x00, 0x00, 0x00),
            (0xFF, 0xFF, 0xFF),
        ] {
            let (h, s, l) = rgb_to_hsl(rgb);
            let back = hsl_to_rgb(h, s, l);
            let close = |a: u8, b: u8| (i16::from(a) - i16::from(b)).abs() <= 1;
            assert!(
                close(rgb.0, back.0) && close(rgb.1, back.1) && close(rgb.2, back.2),
                "{rgb:?} round-tripped to {back:?}"
            );
        }
    }

    #[test]
    fn muted_tokens_stay_ansi_even_on_truecolor_terminals() {
        let theme = Theme::resolve(&ThemeSpec::builtin(ThemePreset::Muted), true);
        assert_eq!(theme.accent, Color::Cyan);
        assert_eq!(theme.selection_bg, None);
    }

    #[test]
    fn overrides_are_honored_on_ansi_presets() {
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        spec.set_token("accent", "#ff9e64").unwrap();
        spec.set_token("selection_bg", "#3b4261").unwrap();

        // Truecolor terminal: the exact values are emitted even though the
        // muted preset itself stays ANSI.
        let theme = Theme::resolve(&spec, true);
        assert_eq!(theme.accent, Color::Rgb(0xFF, 0x9E, 0x64));
        assert_eq!(theme.selection_bg, Some(Color::Rgb(0x3B, 0x42, 0x61)));

        // Non-truecolor terminal: hex degrades to its nearest-ANSI
        // fallback, and the overridden bg slot is still honored.
        let theme = Theme::resolve(&spec, false);
        assert_eq!(theme.accent, spec.accent.ansi);
        assert_eq!(theme.selection_bg, Some(spec.selection_bg.unwrap().ansi));
    }

    #[test]
    fn truecolor_theme_falls_back_to_ansi_without_truecolor() {
        let theme = Theme::resolve(&ThemeSpec::builtin(ThemePreset::TokyoNight), false);
        assert_eq!(theme.accent, Color::LightBlue);
        assert_eq!(theme.selection_bg, None);
        assert_eq!(theme.status_bg, None);
    }

    #[test]
    fn truecolor_theme_emits_rgb_on_truecolor_terminals() {
        let theme = Theme::resolve(&ThemeSpec::builtin(ThemePreset::TokyoNight), true);
        assert_eq!(theme.accent, Color::Rgb(0x7A, 0xA2, 0xF7));
        assert_eq!(theme.selection_bg, Some(Color::Rgb(0x33, 0x46, 0x7C)));
    }

    #[test]
    fn contrast_ratio_matches_wcag_extremes() {
        let black = (0x00, 0x00, 0x00);
        let white = (0xFF, 0xFF, 0xFF);
        assert!((contrast_ratio(black, white) - 21.0).abs() < 1e-6);
        assert!((contrast_ratio(white, black) - 21.0).abs() < 1e-6);
        assert!((contrast_ratio(white, white) - 1.0).abs() < 1e-6);
        // WCAG reference luminances.
        assert!(relative_luminance(0, 0, 0).abs() < 1e-9);
        assert!((relative_luminance(255, 255, 255) - 1.0).abs() < 1e-9);
        assert!(relative_luminance(0, 255, 0) > relative_luminance(0, 0, 255));
    }

    #[test]
    fn blend_half_is_the_channel_midpoint() {
        assert_eq!(
            blend_half((0x00, 0x10, 0xFF), (0x40, 0x20, 0xFF)),
            (0x20, 0x18, 0xFF)
        );
    }

    #[test]
    fn shimmer_ramp_starts_at_the_seed_and_brightens() {
        let seed = (0x08, 0x91, 0xB2);
        let ramp = shimmer_ramp(seed);
        assert_eq!(ramp[0], seed);
        let lightness = ramp.map(|stop| rgb_to_hsl(stop).2);
        assert!(lightness[1] > lightness[0], "{ramp:?}");
        assert!(lightness[2] > lightness[1], "{ramp:?}");
        // Endpoints land exactly on their stops, midpoint interpolates.
        assert_eq!(three_stop(&ramp, 0.0), Color::Rgb(seed.0, seed.1, seed.2));
        assert_eq!(
            three_stop(&ramp, 1.0),
            Color::Rgb(ramp[2].0, ramp[2].1, ramp[2].2)
        );
        assert_eq!(
            three_stop(&ramp, 0.5),
            Color::Rgb(ramp[1].0, ramp[1].1, ramp[1].2)
        );
    }

    #[test]
    fn shimmer_ramp_is_absent_without_truecolor() {
        assert!(
            Theme::resolve(&ThemeSpec::builtin(ThemePreset::TokyoNight), true)
                .shimmer_ramp
                .is_some()
        );
        assert!(
            Theme::resolve(&ThemeSpec::builtin(ThemePreset::TokyoNight), false)
                .shimmer_ramp
                .is_none()
        );
        // Muted is an ANSI preset: static accent even on a truecolor term.
        assert!(
            Theme::resolve(&ThemeSpec::builtin(ThemePreset::Muted), true)
                .shimmer_ramp
                .is_none()
        );
    }

    #[test]
    fn identity_rgb_is_stable_per_name_and_spreads_across_hues() {
        let hues = super::super::definitions::IDENTITY_HUES;
        assert_eq!(identity_rgb(hues, "firefox"), identity_rgb(hues, "firefox"));
        assert_ne!(identity_rgb(hues, "firefox"), identity_rgb(hues, "curl"));

        let names = [
            "firefox", "chrome", "curl", "ssh", "sshd", "systemd", "dockerd", "postgres", "redis",
            "nginx", "code", "slack", "spotify", "zoom",
        ];
        let distinct: std::collections::BTreeSet<_> =
            names.iter().map(|n| identity_rgb(hues, n)).collect();
        assert!(
            distinct.len() >= names.len() * 2 / 3,
            "identity hues clustered: {distinct:?}"
        );
    }

    #[test]
    fn keycap_chips_carry_their_key_legibly_on_every_preset() {
        for preset in ThemePreset::ALL.iter().copied() {
            let spec = ThemeSpec::builtin(preset);
            let theme = Theme::resolve(&spec, true);
            let Some(chip) = theme.key_cap_bg else {
                // Classic derives no chip: it keeps the historic bold-key bar.
                assert!(spec.classic, "{} dropped its chip", preset.name());
                continue;
            };
            let key = reference_rgb(theme.key).expect("key has a reference color");
            assert!(
                relative_luminance(chip.0, chip.1, chip.2)
                    < relative_luminance(key.0, key.1, key.2),
                "{}: chip {chip:?} is not darker than its key {key:?}",
                preset.name()
            );
            assert!(
                contrast_ratio(chip, key) >= MIN_CONTRAST,
                "{}: key on chip is only {:.1}:1",
                preset.name(),
                contrast_ratio(chip, key)
            );
        }
    }

    #[test]
    fn hint_labels_recede_to_the_themes_own_muted_tone() {
        let theme = Theme::resolve(&ThemeSpec::builtin(ThemePreset::Muted), true);
        // The muted seed, not the brighter ANSI label tier the Help tab uses,
        // so the key stays the brightest part of a hint.
        assert_eq!(theme.hint_label, Some((0x6B, 0x72, 0x80)));
        assert_eq!(
            Theme::resolve(&ThemeSpec::builtin(ThemePreset::Classic), true).hint_label,
            None
        );
    }

    #[test]
    fn identity_hues_are_gated_by_terminal_and_preset() {
        // Truecolor terminal: available on every preset but classic, the
        // ANSI muted preset included.
        for preset in [ThemePreset::Muted, ThemePreset::Nord] {
            assert!(
                Theme::resolve(&ThemeSpec::builtin(preset), true)
                    .identity_hues
                    .is_some(),
                "{preset:?}"
            );
        }
        assert!(
            Theme::resolve(&ThemeSpec::builtin(ThemePreset::Classic), true)
                .identity_hues
                .is_none()
        );
        // No truecolor: no synthesized hues anywhere.
        for preset in ThemePreset::ALL {
            assert!(
                Theme::resolve(&ThemeSpec::builtin(preset), false)
                    .identity_hues
                    .is_none(),
                "{preset:?}"
            );
        }
    }

    #[test]
    fn built_in_presets_pass_the_contrast_guard() {
        for preset in ThemePreset::ALL {
            for truecolor in [false, true] {
                let theme = Theme::resolve(&ThemeSpec::builtin(preset), truecolor);
                assert!(
                    contrast_warnings(&theme).is_empty(),
                    "{preset:?} (truecolor={truecolor}): {:?}",
                    contrast_warnings(&theme)
                );
            }
        }
    }

    #[test]
    fn low_contrast_overrides_are_reported() {
        let mut spec = ThemeSpec::builtin(ThemePreset::TokyoNight);
        spec.set_token("selection_bg", "#33467c").unwrap();
        spec.set_token("selection_fg", "#3b4261").unwrap();
        spec.set_token("status_bg", "#292e42").unwrap();
        spec.set_token("key", "#2b3350").unwrap();
        assert!(spec.has_overrides());

        let warnings = contrast_warnings(&Theme::resolve(&spec, true));
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].contains("selection_fg on selection_bg"),
            "{warnings:?}"
        );
        assert!(warnings[1].contains("key on status_bg"), "{warnings:?}");

        // A readable override pair says nothing, and the colors are never
        // altered either way.
        let mut spec = ThemeSpec::builtin(ThemePreset::TokyoNight);
        spec.set_token("selection_bg", "#1a1b26").unwrap();
        spec.set_token("selection_fg", "#c0caf5").unwrap();
        let theme = Theme::resolve(&spec, true);
        assert!(contrast_warnings(&theme).is_empty());
        assert_eq!(theme.selection_fg, Some(Color::Rgb(0xC0, 0xCA, 0xF5)));
    }

    #[test]
    fn built_in_presets_have_no_overrides() {
        for preset in ThemePreset::ALL {
            assert!(!ThemeSpec::builtin(preset).has_overrides(), "{preset:?}");
        }
        let mut spec = ThemeSpec::builtin(ThemePreset::Muted);
        spec.set_token("faint", "darkgray").unwrap();
        assert!(spec.has_overrides());
    }

    #[test]
    fn accent_override_propagates_to_roles_and_ramp() {
        let mut spec = ThemeSpec::builtin(ThemePreset::TokyoNight);
        spec.set_token("accent", "#ff9e64").unwrap();
        let theme = Theme::resolve(&spec, true);
        assert_eq!(theme.field_local_addr, Color::Rgb(0xFF, 0x9E, 0x64));
        assert_eq!(theme.proto_quic, Color::Rgb(0xFF, 0x9E, 0x64));
        assert_eq!(theme.accent_ramp[0], (0xFF, 0x9E, 0x64));
    }
}
