//! Human-readable formatters for byte counts, per-second rates, and
//! ellipsis truncation, shared across the connection list, stats
//! panel, interface table, activity tab, and graph tab. Binary units use
//! IEC labels. Observed idle rates render as zero; callers handle missing data.

pub(super) fn format_rate(bytes_per_second: f64) -> String {
    const KIB_PER_SEC: f64 = 1024.0;
    const MIB_PER_SEC: f64 = KIB_PER_SEC * 1024.0;
    const GIB_PER_SEC: f64 = MIB_PER_SEC * 1024.0;

    if bytes_per_second >= GIB_PER_SEC {
        format!("{:.2} GiB/s", bytes_per_second / GIB_PER_SEC)
    } else if bytes_per_second >= MIB_PER_SEC {
        format!("{:.2} MiB/s", bytes_per_second / MIB_PER_SEC)
    } else if bytes_per_second >= KIB_PER_SEC {
        format!("{:.2} KiB/s", bytes_per_second / KIB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0} B/s", bytes_per_second)
    } else {
        "0 B/s".to_string()
    }
}

/// Format rate to compact form for tight spaces. `zero` is what a
/// zero/absent rate renders as: the "-" placeholder in tables, "0B"
/// in the activity bars.
pub(super) fn format_rate_compact(bytes_per_second: f64, zero: &str) -> String {
    const KIB_PER_SEC: f64 = 1024.0;
    const MIB_PER_SEC: f64 = KIB_PER_SEC * 1024.0;
    const GIB_PER_SEC: f64 = MIB_PER_SEC * 1024.0;

    if bytes_per_second >= GIB_PER_SEC {
        format!("{:.1}Gi", bytes_per_second / GIB_PER_SEC)
    } else if bytes_per_second >= MIB_PER_SEC {
        format!("{:.1}Mi", bytes_per_second / MIB_PER_SEC)
    } else if bytes_per_second >= KIB_PER_SEC {
        format!("{:.0}Ki", bytes_per_second / KIB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0}B", bytes_per_second)
    } else {
        zero.to_string()
    }
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
    use super::{ellipsize_left, format_countdown};
    use std::time::Duration;

    #[test]
    fn observed_rates_use_binary_units_and_explicit_zero() {
        for (value, expected) in [
            (0.0, "0 B/s"),
            (1023.0, "1023 B/s"),
            (1024.0, "1.00 KiB/s"),
            (1048576.0, "1.00 MiB/s"),
            (1073741824.0, "1.00 GiB/s"),
        ] {
            assert_eq!(super::format_rate(value), expected);
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
