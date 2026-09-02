//! Human-readable formatters for byte counts, per-second rates, and
//! ellipsis truncation, shared across the connection list, stats
//! panel, interface table, activity tab, and graph tab. Rates render
//! the parent module's `NONE_PLACEHOLDER` ("-") for zero/absent
//! values so the UI reads consistently.

/// Format rate to human readable form
pub(super) fn format_rate(bytes_per_second: f64) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.2} GB/s", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.2} MB/s", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.2} KB/s", bytes_per_second / KB_PER_SEC)
    } else if bytes_per_second > 0.0 {
        format!("{:.0} B/s", bytes_per_second)
    } else {
        super::NONE_PLACEHOLDER.to_string()
    }
}

/// Format rate to compact form for tight spaces. `zero` is what a
/// zero/absent rate renders as: the "-" placeholder in tables, "0B"
/// in the activity bars.
pub(super) fn format_rate_compact(bytes_per_second: f64, zero: &str) -> String {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        format!("{:.1}G", bytes_per_second / GB_PER_SEC)
    } else if bytes_per_second >= MB_PER_SEC {
        format!("{:.1}M", bytes_per_second / MB_PER_SEC)
    } else if bytes_per_second >= KB_PER_SEC {
        format!("{:.0}K", bytes_per_second / KB_PER_SEC)
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

/// Format bytes to human readable form
pub(super) fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Char-safe truncation to `width` cells, ending in "…" when cut. Trailing
/// whitespace on the kept prefix is dropped so the ellipsis never floats
/// after a space.
pub(super) fn truncate_with_ellipsis(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".to_string();
    }
    let kept: String = s.chars().take(width - 1).collect();
    format!("{}…", kept.trim_end())
}

/// Truncation to `max` chars that keeps the *end* of the string,
/// prefixing "…" when cut. Like [`truncate_with_ellipsis`] it counts
/// chars, not display cells, so a run of wide characters can still
/// overflow a fixed-width column by a few cells.
///
/// The tail is the informative half of a filesystem path (the basename
/// says what the binary is, the leading directories only say where it
/// lives), so a path that has to lose characters loses them from the
/// front.
pub(super) fn ellipsize_left(s: &str, max: usize) -> String {
    let len = s.chars().count();
    if len <= max {
        return s.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let tail: String = s.chars().skip(len - (max - 1)).collect();
    format!("…{tail}")
}

#[cfg(test)]
mod tests {
    use super::{ellipsize_left, format_countdown};
    use std::time::Duration;

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
        assert_eq!(ellipsize_left("/usr/bin/curl", 0), "…");
    }

    #[test]
    fn multibyte_input_is_cut_on_char_boundaries() {
        // Counting bytes here would slice mid-codepoint and panic. The
        // budget is in chars, so the wide-character result is 6 chars
        // wide, not 6 cells.
        assert_eq!(ellipsize_left("/日本語/データ/ファイル", 6), "…/ファイル");
        assert_eq!(ellipsize_left("ααββγγ", 3), "…γγ");
    }
}
