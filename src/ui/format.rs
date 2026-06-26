//! Human-readable formatters for byte counts and per-second rates,
//! shared across the connection list, stats panel, interface table,
//! and graph tab. Returns the parent module's `NONE_PLACEHOLDER`
//! ("-") for zero/absent rates so the UI reads consistently.

use std::borrow::Cow;

/// Format rate to human readable form.
///
/// Returns `Cow::Borrowed` for the idle (`NONE_PLACEHOLDER`) case so the
/// common all-zero rows — most of an idle connection list — don't allocate.
pub(super) fn format_rate(bytes_per_second: f64) -> Cow<'static, str> {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        Cow::Owned(format!("{:.2} GB/s", bytes_per_second / GB_PER_SEC))
    } else if bytes_per_second >= MB_PER_SEC {
        Cow::Owned(format!("{:.2} MB/s", bytes_per_second / MB_PER_SEC))
    } else if bytes_per_second >= KB_PER_SEC {
        Cow::Owned(format!("{:.2} KB/s", bytes_per_second / KB_PER_SEC))
    } else if bytes_per_second > 0.0 {
        Cow::Owned(format!("{:.0} B/s", bytes_per_second))
    } else {
        Cow::Borrowed(super::NONE_PLACEHOLDER)
    }
}

/// Format rate to compact form for tight spaces.
///
/// Like [`format_rate`], the idle case borrows `NONE_PLACEHOLDER` instead
/// of allocating — this one feeds the per-row bandwidth cell.
pub(super) fn format_rate_compact(bytes_per_second: f64) -> Cow<'static, str> {
    const KB_PER_SEC: f64 = 1024.0;
    const MB_PER_SEC: f64 = KB_PER_SEC * 1024.0;
    const GB_PER_SEC: f64 = MB_PER_SEC * 1024.0;

    if bytes_per_second >= GB_PER_SEC {
        Cow::Owned(format!("{:.1}G", bytes_per_second / GB_PER_SEC))
    } else if bytes_per_second >= MB_PER_SEC {
        Cow::Owned(format!("{:.1}M", bytes_per_second / MB_PER_SEC))
    } else if bytes_per_second >= KB_PER_SEC {
        Cow::Owned(format!("{:.0}K", bytes_per_second / KB_PER_SEC))
    } else if bytes_per_second > 0.0 {
        Cow::Owned(format!("{:.0}B", bytes_per_second))
    } else {
        Cow::Borrowed(super::NONE_PLACEHOLDER)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_rate_borrows_placeholder() {
        // The common idle row must not allocate.
        assert!(matches!(format_rate(0.0), Cow::Borrowed(_)));
        assert!(matches!(format_rate_compact(0.0), Cow::Borrowed(_)));
        assert_eq!(format_rate(0.0), super::super::NONE_PLACEHOLDER);
        assert_eq!(format_rate_compact(0.0), super::super::NONE_PLACEHOLDER);
    }

    #[test]
    fn live_rate_owns_formatted_value() {
        assert!(matches!(format_rate(2048.0), Cow::Owned(_)));
        assert_eq!(format_rate(2048.0), "2.00 KB/s");
        assert_eq!(format_rate_compact(2048.0), "2K");
    }
}
