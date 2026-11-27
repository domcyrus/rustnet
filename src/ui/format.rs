//! Human-readable formatters for byte counts, per-second rates, and
//! ellipsis truncation, shared across the connection list, stats
//! panel, interface table, activity tab, and graph tab. Binary byte units
//! use IEC labels (`B/s`, `KiB/s`, ...); bit rates use SI decimal (`bps`,
//! `kbps`, `Mbps`, `Gbps`) labels. Observed idle rates render as zero; callers
//! handle missing data.

use std::borrow::Cow;

/// Display unit scale for live traffic rates in the TUI.
/// Cumulative byte totals and headless JSON outputs always stay in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RateUnit {
    #[default]
    Bytes,
    Bits,
}

impl RateUnit {
    pub const ALL: [Self; 2] = [Self::Bytes, Self::Bits];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Bits => "bits",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "bytes" => Some(Self::Bytes),
            "bits" => Some(Self::Bits),
            _ => None,
        }
    }

    pub const fn axis_unit_label(self) -> &'static str {
        match self {
            Self::Bytes => "B/s",
            Self::Bits => "bps",
        }
    }

    pub const fn compact_zero(self) -> &'static str {
        match self {
            Self::Bytes => "0B",
            Self::Bits => "0b",
        }
    }

    pub(super) fn giga_value(self, bytes_per_second: f64) -> f64 {
        match self {
            Self::Bytes => bytes_per_second / 1024.0_f64.powi(3),
            // Divide before multiplying by 8 so f64::MAX stays finite.
            Self::Bits => (bytes_per_second / 1_000_000_000.0) * 8.0,
        }
    }
}

pub(super) fn format_rate(bytes_per_second: f64, unit: RateUnit) -> Cow<'static, str> {
    if bytes_per_second <= 0.0 || bytes_per_second.is_nan() {
        return Cow::Borrowed(match unit {
            RateUnit::Bytes => "0 B/s",
            RateUnit::Bits => "0 bps",
        });
    }

    match unit {
        RateUnit::Bytes => {
            const KIB_PER_SEC: f64 = 1024.0;
            const MIB_PER_SEC: f64 = KIB_PER_SEC * 1024.0;
            const GIB_PER_SEC: f64 = MIB_PER_SEC * 1024.0;

            if bytes_per_second >= GIB_PER_SEC {
                Cow::Owned(format!("{:.2} GiB/s", bytes_per_second / GIB_PER_SEC))
            } else if bytes_per_second >= MIB_PER_SEC {
                Cow::Owned(format!("{:.2} MiB/s", bytes_per_second / MIB_PER_SEC))
            } else if bytes_per_second >= KIB_PER_SEC {
                Cow::Owned(format!("{:.2} KiB/s", bytes_per_second / KIB_PER_SEC))
            } else {
                Cow::Owned(format!("{:.0} B/s", bytes_per_second))
            }
        }
        RateUnit::Bits => {
            const KBPS_BYTES: f64 = 125.0; // 1,000 bps / 8
            const MBPS_BYTES: f64 = 125_000.0; // 1,000,000 bps / 8
            const GBPS_BYTES: f64 = 125_000_000.0; // 1,000,000,000 bps / 8

            if bytes_per_second >= GBPS_BYTES {
                // Divide before multiplying by 8 so f64::MAX stays finite.
                Cow::Owned(format!(
                    "{:.2} Gbps",
                    (bytes_per_second / 1_000_000_000.0) * 8.0
                ))
            } else if bytes_per_second >= MBPS_BYTES {
                Cow::Owned(format!("{:.2} Mbps", bytes_per_second * 8.0 / 1_000_000.0))
            } else if bytes_per_second >= KBPS_BYTES {
                Cow::Owned(format!("{:.2} kbps", bytes_per_second * 8.0 / 1_000.0))
            } else {
                Cow::Owned(format!("{:.0} bps", bytes_per_second * 8.0))
            }
        }
    }
}

/// Format rate to compact form for tight spaces. `zero` is what a
/// zero/absent rate renders as: the "-" placeholder in tables, "0B" or "0b"
/// in the traffic graph y-axis.
pub(super) fn format_rate_compact(
    bytes_per_second: f64,
    zero: &str,
    unit: RateUnit,
) -> Cow<'_, str> {
    if bytes_per_second <= 0.0 || !bytes_per_second.is_finite() {
        return Cow::Borrowed(zero);
    }
    // Each half of the 11-cell RX/TX column has five cells. Promote before
    // rounding would produce a four-digit value with a two-cell unit.
    let (base, first_limit, units) = match unit {
        RateUnit::Bytes => (1024.0, 1023.5, ["B", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"]),
        RateUnit::Bits => (1000.0, 999.5, ["b", "kb", "Mb", "Gb", "Tb", "Pb", "Eb"]),
    };
    let (mut value, start_index) = match unit {
        RateUnit::Bytes => (bytes_per_second, 0),
        RateUnit::Bits => {
            if bytes_per_second > f64::MAX / 8.0 {
                ((bytes_per_second / base) * 8.0, 1)
            } else {
                (bytes_per_second * 8.0, 0)
            }
        }
    };
    for (index, label) in units.iter().enumerate().skip(start_index) {
        let limit = if index == 0 { first_limit } else { 999.5 };
        if value < limit || index == units.len() - 1 {
            return if index >= 2 && value < 9.95 {
                Cow::Owned(format!("{value:.1}{label}"))
            } else {
                Cow::Owned(format!("{value:.0}{label}"))
            };
        }
        value /= base;
    }
    unreachable!("the final unit always formats the value")
}

/// Format a round-trip time for the fixed-width RTT column: one decimal
/// below 10ms ("3.4ms"), whole milliseconds up to a second ("234ms"),
/// seconds above that ("1.2s"). Always fits 7 cells.
pub(super) fn format_rtt_compact(rtt: std::time::Duration) -> String {
    let ms = rtt.as_secs_f64() * 1000.0;
    if ms < 10.0 {
        format!("{:.1}ms", ms)
    } else if ms < 1000.0 {
        format!("{:.0}ms", ms)
    } else {
        format!("{:.1}s", ms / 1000.0)
    }
}

/// Compact time-left display for cleanup countdowns: whole seconds under
/// a minute ("45s"), whole minutes under an hour ("2m"), whole hours
/// beyond that ("3h"). Integer division, so the value never overstates
/// what remains.
pub(super) fn format_countdown(remaining: std::time::Duration) -> String {
    let s = remaining.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m", s / 60)
    } else {
        format!("{}h", s / 3600)
    }
}

pub(super) fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;

    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Terminal display width, using the same Unicode rules as the renderer.
pub(super) fn cell_width(s: &str) -> usize {
    use ratatui::buffer::CellWidth;
    usize::from(s.cell_width())
}

/// Truncate at grapheme boundaries, reserving one cell for the ellipsis.
pub(super) fn truncate_with_ellipsis(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if cell_width(s) <= width {
        return s.to_string();
    }
    let span = ratatui::text::Span::raw(s);
    let mut kept = String::new();
    let mut used = 0;
    for grapheme in span.styled_graphemes(ratatui::style::Style::default()) {
        let cells = cell_width(grapheme.symbol);
        if used + cells > width - 1 {
            break;
        }
        kept.push_str(grapheme.symbol);
        used += cells;
    }
    format!("{}…", kept.trim_end())
}

/// Keep the end of a path without splitting wide or combining graphemes.
pub(super) fn ellipsize_left(s: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if cell_width(s) <= width {
        return s.to_string();
    }
    let span = ratatui::text::Span::raw(s);
    let graphemes: Vec<_> = span
        .styled_graphemes(ratatui::style::Style::default())
        .collect();
    let mut used = 0;
    let mut start = graphemes.len();
    for grapheme in graphemes.iter().rev() {
        let cells = cell_width(grapheme.symbol);
        if used + cells > width - 1 {
            break;
        }
        start -= 1;
        used += cells;
    }
    let mut result = String::from("…");
    for grapheme in &graphemes[start..] {
        result.push_str(grapheme.symbol);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{RateUnit, cell_width, ellipsize_left, format_countdown};
    use std::borrow::Cow;
    use std::time::Duration;

    #[test]
    fn cli_rate_units_stay_in_sync_with_rate_unit_enum() {
        let names: Vec<&str> = RateUnit::ALL.iter().map(|u| u.as_str()).collect();
        assert_eq!(names, crate::cli::RATE_UNITS);
        for unit in RateUnit::ALL {
            assert_eq!(RateUnit::from_name(unit.as_str()), Some(unit));
        }
        assert_eq!(RateUnit::from_name("iec-bits"), None);
        assert_eq!(RateUnit::from_name("bogus"), None);
    }

    #[test]
    fn idle_rates_borrow_display_text() {
        for value in [0.0, -1.0, f64::NEG_INFINITY, f64::NAN] {
            assert!(matches!(
                super::format_rate(value, RateUnit::Bytes),
                Cow::Borrowed("0 B/s")
            ));
            assert!(matches!(
                super::format_rate(value, RateUnit::Bits),
                Cow::Borrowed("0 bps")
            ));
        }
        let custom_zero = String::from("idle");
        for zero in ["-", "0B", "0b", custom_zero.as_str()] {
            for unit in RateUnit::ALL {
                for value in [0.0, -1.0, f64::NEG_INFINITY, f64::INFINITY, f64::NAN] {
                    let formatted = super::format_rate_compact(value, zero, unit);
                    assert!(matches!(formatted, Cow::Borrowed(_)));
                    assert_eq!(formatted, zero);
                }
            }
        }
    }

    #[test]
    fn compact_live_rates_preserve_units_and_rounding() {
        for (value, expected) in [
            (1.0, "1B"),
            (1023.0, "1023B"),
            (1023.5, "1Ki"),
            (999.0 * 1024.0, "999Ki"),
            (999.5 * 1024.0, "1.0Mi"),
            (1048576.0, "1.0Mi"),
            (1073741824.0, "1.0Gi"),
        ] {
            let formatted = super::format_rate_compact(value, "-", RateUnit::Bytes);
            assert!(matches!(formatted, Cow::Owned(_)));
            assert_eq!(formatted, expected);
        }

        for (value, expected) in [
            (1.0, "8b"),
            (124.0, "992b"),
            (125.0, "1kb"),
            (124_000.0, "992kb"),
            (125_000.0, "1.0Mb"),
            (1_250_000.0, "10Mb"),
            (125_000_000.0, "1.0Gb"),
        ] {
            let formatted = super::format_rate_compact(value, "-", RateUnit::Bits);
            assert_eq!(formatted, expected);
        }

        // Every realistic value fits within the 5-cell half-column budget.
        for unit in RateUnit::ALL {
            let mut v = 1.0;
            while v <= 1e15 {
                let formatted = super::format_rate_compact(v, "-", unit);
                assert!(
                    cell_width(&formatted) <= 5,
                    "{unit:?} at {v}: {formatted:?} exceeds 5 cells"
                );
                v *= 3.16227766;
            }
        }
    }

    #[test]
    fn observed_rates_use_selected_units_and_explicit_zero() {
        for (value, expected) in [
            (0.0, "0 B/s"),
            (1023.0, "1023 B/s"),
            (1024.0, "1.00 KiB/s"),
            (1048576.0, "1.00 MiB/s"),
            (1073741824.0, "1.00 GiB/s"),
        ] {
            assert_eq!(super::format_rate(value, RateUnit::Bytes), expected);
        }
        for (value, expected) in [
            (0.0, "0 bps"),
            (124.0, "992 bps"),
            (125.0, "1.00 kbps"),
            (125_000.0, "1.00 Mbps"),
            (12_500_000.0, "100.00 Mbps"),
            (125_000_000.0, "1.00 Gbps"),
        ] {
            assert_eq!(super::format_rate(value, RateUnit::Bits), expected);
        }
        // f64::MAX must stay finite across all modes.
        for unit in RateUnit::ALL {
            let max = super::format_rate(f64::MAX, unit);
            assert!(!max.contains("inf"), "{unit:?}: {max}");
            assert!(unit.giga_value(f64::MAX).is_finite(), "{unit:?}");
        }
        assert_eq!(super::format_bytes(1048576), "1.00 MiB");
    }

    #[test]
    fn truncation_respects_cells_and_keeps_graphemes_whole() {
        use super::{cell_width, truncate_with_ellipsis};
        assert_eq!(truncate_with_ellipsis("日本語-server", 6), "日本…");
        assert_eq!(truncate_with_ellipsis("e\u{301}clair", 3), "e\u{301}c…");
        assert_eq!(truncate_with_ellipsis("👩‍💻server", 3), "👩‍💻…");
        assert_eq!(ellipsize_left("prefix-e\u{301}", 2), "…e\u{301}");
        assert_eq!(ellipsize_left("prefix-👩‍💻", 3), "…👩‍💻");
        for text in ["日本語-server", "e\u{301}clair", "👩‍💻server", "ｶﾞ-data"] {
            for width in 0..20 {
                assert!(cell_width(&truncate_with_ellipsis(text, width)) <= width);
                assert!(cell_width(&ellipsize_left(text, width)) <= width);
            }
        }
    }

    #[test]
    fn truncation_preserves_fitting_text_and_trims_spaces_before_ellipsis() {
        for (text, width, expected) in [
            ("short", 10, "short"),
            ("exactly-10", 10, "exactly-10"),
            ("hello world", 7, "hello…"),
            ("0123456789ab", 10, "012345678…"),
            ("héllö wörld!", 6, "héllö…"),
        ] {
            assert_eq!(
                super::truncate_with_ellipsis(text, width),
                expected,
                "{text:?}, width {width}"
            );
        }
    }

    #[test]
    fn countdown_buckets_round_down() {
        assert_eq!(format_countdown(Duration::ZERO), "0s");
        assert_eq!(format_countdown(Duration::from_secs(45)), "45s");
        assert_eq!(format_countdown(Duration::from_secs(59)), "59s");
        assert_eq!(format_countdown(Duration::from_secs(60)), "1m");
        assert_eq!(format_countdown(Duration::from_secs(150)), "2m");
        assert_eq!(format_countdown(Duration::from_secs(3599)), "59m");
        assert_eq!(format_countdown(Duration::from_secs(3600)), "1h");
        assert_eq!(format_countdown(Duration::from_secs(7199)), "1h");
    }

    #[test]
    fn fitting_strings_are_returned_unchanged() {
        assert_eq!(ellipsize_left("/usr/bin/curl", 13), "/usr/bin/curl");
        assert_eq!(ellipsize_left("/usr/bin/curl", 40), "/usr/bin/curl");
        assert_eq!(ellipsize_left("", 0), "");
    }

    #[test]
    fn truncation_keeps_the_tail_and_fits_the_budget() {
        let cut = ellipsize_left("/usr/libexec/ApplicationFirmwareUpdater", 10);
        assert_eq!(cut, "…reUpdater");
        assert_eq!(cut.chars().count(), 10);
    }

    #[test]
    fn hopeless_budgets_collapse_to_the_ellipsis() {
        assert_eq!(ellipsize_left("/usr/bin/curl", 1), "…");
        assert_eq!(ellipsize_left("/usr/bin/curl", 0), "");
    }

    #[test]
    fn multibyte_input_is_cut_on_char_boundaries() {
        // Wide characters consume two terminal cells.
        assert_eq!(ellipsize_left("/日本語/データ/ファイル", 6), "…イル");
        assert_eq!(ellipsize_left("ααββγγ", 3), "…γγ");
    }
}
