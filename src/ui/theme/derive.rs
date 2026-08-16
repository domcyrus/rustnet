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

        Theme {
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
        }
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
    fn accent_override_propagates_to_roles_and_ramp() {
        let mut spec = ThemeSpec::builtin(ThemePreset::TokyoNight);
        spec.set_token("accent", "#ff9e64").unwrap();
        let theme = Theme::resolve(&spec, true);
        assert_eq!(theme.field_local_addr, Color::Rgb(0xFF, 0x9E, 0x64));
        assert_eq!(theme.proto_quic, Color::Rgb(0xFF, 0x9E, 0x64));
        assert_eq!(theme.accent_ramp[0], (0xFF, 0x9E, 0x64));
    }
}
