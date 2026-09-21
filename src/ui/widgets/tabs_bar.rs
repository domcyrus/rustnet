//! Top tab bar: a borderless two-row strip: the brand + numbered tab
//! titles on the first row, and an underline rule on the second with a
//! heavy accent segment under the active tab. The heavy ━ vs light ─
//! glyph difference keeps the active tab readable under NO_COLOR.
//! Click regions cover both rows so a click on the underline works too.
//!
//! The title row also carries two status cues: a `•` after a tab title
//! whose tab has something running (Overview while a filter narrows the
//! list), and a right-aligned capture cluster (`● <iface> · <link>`)
//! whose dot turns red when packet capture has failed.

use ratatui::{Frame, layout::Rect, text::Span};

use crate::ui::{ClickAction, ClickableRegions, UiState, theme};

pub(crate) const TAB_TITLES: [&str; 5] = ["Overview", "Details", "Activity", "Graph", "Host"];
/// Total number of tabs (kept in sync with `TAB_TITLES`).
pub(crate) const TAB_COUNT: usize = TAB_TITLES.len();
/// Index of the Overview tab, the only tab with an activity dot so far.
const OVERVIEW_TAB_INDEX: usize = 0;

/// Height of the tab bar in rows (titles + underline).
pub(crate) const TABS_BAR_HEIGHT: u16 = super::tab_strip::HEIGHT;

const BRAND: &str = " rustnet ";
/// Gap between tab titles, in cells.
const TAB_GAP: u16 = 3;
/// Marks a tab that is doing something the user set up (Overview with an
/// active filter). Rendered right after the title.
const ACTIVITY_DOT: &str = " •";
/// Blank cells kept between the last tab title and the capture cluster.
const CLUSTER_GAP: usize = 2;

/// What the right-aligned capture cluster reports: which interface is
/// being captured, its link layer, and whether capture is still running.
/// Built by `crate::ui::draw` from the same `App` accessors the status
/// bar and the Overview sidebar already read.
#[derive(Debug, Default, Clone, Copy)]
pub(in crate::ui) struct CaptureCluster<'a> {
    /// Interface name, `None` until the capture thread reports one.
    pub interface: Option<&'a str>,
    /// Link layer of that interface ("Ethernet"), appended when it fits.
    pub link_type: Option<&'a str>,
    /// Set while the app has a current capture failure.
    pub failed: bool,
}

/// Spans for the capture cluster, or `None` when there is no interface to
/// show or `room` cells cannot hold it. Degrades in two steps: the link
/// layer suffix is dropped first, then the cluster as a whole, so tab
/// titles never collide with it.
fn capture_cluster_spans(capture: &CaptureCluster<'_>, room: usize) -> Option<Vec<Span<'static>>> {
    let interface = capture.interface?;
    let dot_style = if capture.failed {
        theme::fg(theme::err())
    } else {
        theme::fg(theme::ok())
    };
    let mut spans = vec![
        Span::styled("● ", dot_style),
        Span::styled(interface.to_string(), theme::fg(theme::text())),
    ];
    // Measured the same way the caller pads the row: display width, so a
    // wide glyph in an interface name cannot overrun the reserved room.
    let base = cluster_width(&spans);
    if base > room {
        return None;
    }

    if let Some(link_type) = capture.link_type {
        let suffix = Span::styled(format!(" · {link_type}"), theme::fg(theme::muted()));
        if base + suffix.width() <= room {
            spans.push(suffix);
        }
    }

    Some(spans)
}

/// Rendered width of the capture cluster, in cells.
fn cluster_width(spans: &[Span<'static>]) -> usize {
    spans.iter().map(Span::width).sum()
}

pub(in crate::ui) fn draw_tabs(
    f: &mut Frame,
    ui_state: &UiState,
    capture: &CaptureCluster<'_>,
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let mut strip = super::tab_strip::TabStrip::new(Span::styled(BRAND, theme::primary()));

    // Keep every view reachable when the terminal is narrow. Preserve the
    // numbered shortcuts while reducing gaps, then labels to their shortcut numbers.
    let tab_gap = if area.width < 72 { 1 } else { TAB_GAP };
    let short_labels = area.width < 60;
    let numbers_only = area.width < 46;
    for (i, title) in TAB_TITLES.iter().enumerate() {
        // Numbered titles: the 1-5 jump shortcut becomes discoverable.
        let title = if numbers_only {
            ""
        } else if short_labels {
            ["Ovr", "Dtl", "Act", "Graph", "Host"][i]
        } else {
            title
        };
        let label = if numbers_only {
            format!("{}", i + 1)
        } else {
            format!("{} {title}", i + 1)
        };
        let active = i == ui_state.selected_tab;
        let dotted = i == OVERVIEW_TAB_INDEX && ui_state.is_filtering();
        let mut title_spans = Vec::new();
        if active {
            title_spans.push(Span::styled(
                if numbers_only {
                    format!("{}", i + 1)
                } else {
                    format!("{} ", i + 1)
                },
                theme::fg(theme::accent()),
            ));
            title_spans.push(super::tab_strip::title(title, true));
        } else {
            title_spans.push(super::tab_strip::title(label, false));
        }
        if dotted {
            title_spans.push(Span::styled(ACTIVITY_DOT, theme::fg(theme::accent())));
        }

        strip.push(title_spans, active, tab_gap, ClickAction::SwitchTab(i));
    }
    let used = usize::from(strip.width());

    // Right-align the capture cluster on the title row, keeping at least
    // CLUSTER_GAP cells clear of the last title.
    let room = (area.width as usize).saturating_sub(used + CLUSTER_GAP);
    if let Some(cluster) = capture_cluster_spans(capture, room) {
        let pad = (area.width as usize).saturating_sub(used + cluster_width(&cluster));
        strip.titles.push(Span::raw(" ".repeat(pad)));
        strip.titles.extend(cluster);
    }

    strip.draw(f, area, click_regions);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::spans_text;

    #[test]
    fn cluster_is_empty_without_an_interface() {
        let capture = CaptureCluster::default();
        assert!(capture_cluster_spans(&capture, 80).is_none());
    }

    #[test]
    fn cluster_shows_interface_and_link_type() {
        let capture = CaptureCluster {
            interface: Some("eth0"),
            link_type: Some("Ethernet"),
            failed: false,
        };
        let spans = capture_cluster_spans(&capture, 40).expect("cluster fits");
        assert_eq!(spans_text(&spans), "● eth0 · Ethernet");
    }

    #[test]
    fn cluster_drops_the_link_type_before_the_interface() {
        let capture = CaptureCluster {
            interface: Some("eth0"),
            link_type: Some("Ethernet"),
            failed: false,
        };
        let spans = capture_cluster_spans(&capture, 6).expect("interface alone fits");
        assert_eq!(spans_text(&spans), "● eth0");
    }

    #[test]
    fn cluster_disappears_when_it_cannot_fit() {
        let capture = CaptureCluster {
            interface: Some("eth0"),
            link_type: None,
            failed: false,
        };
        assert!(capture_cluster_spans(&capture, 5).is_none());
    }
}
