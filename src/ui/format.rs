//! Human-readable formatters for byte counts and per-second rates,
//! shared across the connection list, stats panel, interface table,
//! and graph tab. Returns the parent module's `NONE_PLACEHOLDER`
//! ("-") for zero/absent rates so the UI reads consistently.

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

/// Format rate to compact form for tight spaces
pub(super) fn format_rate_compact(bytes_per_second: f64) -> String {
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
        super::NONE_PLACEHOLDER.to_string()
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
