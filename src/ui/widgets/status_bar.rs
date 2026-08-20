//! Bottom status line: the active tab's context actions on the left and a
//! fixed global cluster (help, quit) pinned right, or transient
//! confirmation prompts ("press q again to quit"), clipboard feedback, and
//! capture failures (which claim a second row when they do not fit on one).
//!
//! Hints follow a keycap grammar: the key in `theme::key_hint()`, its label
//! in `theme::key_hint_label()`, two spaces between hints. The global
//! cluster is reserved before any context action is placed, so `q quit`
//! never falls off the right edge. When the terminal is too narrow to spell
//! every action out, the labels go first and the keys stand alone; only
//! then are context actions dropped from the end. The exhaustive keymap
//! lives on the Help tab.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{UIState, theme};

/// One keycap hint: the key as typed and the action it triggers.
type Hint = (&'static str, &'static str);

/// Pinned to the right edge on every tab, and the last thing dropped: the
/// two keys worth knowing when nothing else makes sense.
const GLOBAL_HINTS: [Hint; 2] = [("h", "help"), ("q", "quit")];

/// Cells between two hints inside a group.
const HINT_GAP: usize = 2;
/// Minimum blank cells between the context actions and the global cluster,
/// so the two groups never read as one run of hints.
const CLUSTER_GAP: usize = 3;

/// Context actions for the active tab, most useful first. Tab navigation is
/// deliberately absent: the numbered titles in the tab bar already advertise
/// it, and the footer's room is better spent on actions that appear nowhere
/// else on screen.
fn context_hints(ui_state: &UIState) -> Vec<Hint> {
    match ui_state.selected_tab {
        // Overview
        0 => {
            let mut hints = Vec::new();
            // Clearing outranks everything else while a filter is on.
            if ui_state.has_active_filter() {
                hints.push(("esc", "clear filter"));
            }
            hints.extend([
                ("/", "filter"),
                ("a", "group"),
                ("t", "history"),
                ("i", "info"),
                ("c", "copy"),
            ]);
            hints
        }
        // Details
        1 => {
            let mut hints = vec![("j/k", "prev/next")];
            // Ctrl+D/U only moves when the record outgrows its pane, so on a
            // tall terminal the hint would advertise a no-op.
            if ui_state.details_scroll.can_scroll() {
                hints.push(("ctrl-d/u", "scroll"));
            }
            hints.extend([("c", "copy remote addr"), ("esc", "back")]);
            hints
        }
        // Activity, interface list
        2 if ui_state.activity_show_interfaces => vec![
            ("j/k", "scroll"),
            ("i", "process activity"),
            ("esc", "back"),
        ],
        // Activity
        2 => vec![
            ("d", "tx/rx"),
            ("s", "sort"),
            ("S", "order"),
            ("i", "interfaces"),
            ("esc", "back"),
        ],
        // Help
        4 => vec![("j/k", "scroll"), ("esc", "back")],
        // Graph
        _ => vec![("esc", "back")],
    }
}

/// Spans for one hint. Without `labels` the key stands alone, the fallback
/// for a terminal too narrow to spell the action out.
fn hint_spans(hint: Hint, labels: bool) -> Vec<Span<'static>> {
    let (key, label) = hint;
    let mut spans = vec![Span::styled(key, theme::key_hint())];
    if labels {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(label, theme::key_hint_label()));
    }
    spans
}

fn hint_width(hint: Hint, labels: bool) -> usize {
    let (key, label) = hint;
    let mut width = key.chars().count();
    if labels {
        width += 1 + label.chars().count();
    }
    width
}

/// Cells a run of hints occupies, gaps included.
fn group_width(hints: &[Hint], labels: bool) -> usize {
    hints
        .iter()
        .enumerate()
        .map(|(i, hint)| {
            let gap = if i == 0 { 0 } else { HINT_GAP };
            gap + hint_width(*hint, labels)
        })
        .sum()
}

fn push_group(spans: &mut Vec<Span<'static>>, hints: &[Hint], labels: bool) {
    for (i, hint) in hints.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw(" ".repeat(HINT_GAP)));
        }
        spans.extend(hint_spans(*hint, labels));
    }
}

/// Lay the bar out: context actions from the left, the global cluster flush
/// right. Tried once with every label spelled out, then with keys alone,
/// dropping context actions from the end only when even that overflows.
fn hint_line(context: &[Hint], width: u16) -> Line<'static> {
    let width = width as usize;
    for labels in [true, false] {
        let global = group_width(&GLOBAL_HINTS, labels);
        // One pad cell at each edge, plus the reserved global cluster.
        let Some(room) = width.checked_sub(global + 2) else {
            continue;
        };
        let mut kept: Vec<Hint> = Vec::new();
        let mut used = 0usize;
        for hint in context {
            let gap = if kept.is_empty() { 0 } else { HINT_GAP };
            let needed = gap + hint_width(*hint, labels);
            if used + needed + CLUSTER_GAP > room {
                break;
            }
            used += needed;
            kept.push(*hint);
        }
        // Labels are all or nothing: half a spelled-out row reads worse than
        // the full row of bare keys the next pass builds.
        if labels && kept.len() < context.len() {
            continue;
        }
        let mut spans = vec![Span::raw(" ")];
        push_group(&mut spans, &kept, labels);
        spans.push(Span::raw(" ".repeat(room - used)));
        push_group(&mut spans, &GLOBAL_HINTS, labels);
        spans.push(Span::raw(" "));
        return Line::from(spans);
    }
    // Narrower than "h q": show the one key that always matters.
    Line::from(hint_spans(GLOBAL_HINTS[1], false))
}

/// Actionable half of a capture-failure line.
const CAPTURE_RECOVERY_HINT: &str = "Restart rustnet to resume. Press 'q' to quit.";

fn capture_error_one_line(cause: &str) -> String {
    format!(" {cause} {CAPTURE_RECOVERY_HINT} ")
}

/// Rows the status bar needs. Real libpcap errors are far longer than one
/// terminal row and the bar does not wrap, so a failure that does not fit gets
/// a second row instead of losing its recovery hint off the right edge.
pub(in crate::ui) fn status_bar_height(capture_error: Option<&str>, width: u16) -> u16 {
    match capture_error {
        Some(cause) if capture_error_one_line(cause).chars().count() > width as usize => 2,
        _ => 1,
    }
}

fn elide(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{}…", kept.trim_end())
}

/// Lay a capture failure out over the rows `status_bar_height` reserved: cause
/// first, recovery hint below it. When only one row is available the cause is
/// elided instead of the hint, which is the half the user can act on.
fn capture_error_text(cause: &str, width: u16, height: u16) -> String {
    let single = capture_error_one_line(cause);
    if single.chars().count() <= width as usize {
        return single;
    }
    if height >= 2 {
        return format!(
            "{}\n{}",
            elide(&format!(" {cause} "), width as usize),
            elide(&format!(" {CAPTURE_RECOVERY_HINT} "), width as usize),
        );
    }

    // " " + cause + "… " + hint + " "
    let room = (width as usize).saturating_sub(CAPTURE_RECOVERY_HINT.chars().count() + 4);
    if room < 16 {
        // Too narrow for both; show as much of the cause as fits.
        return single;
    }
    let cause: String = cause.chars().take(room).collect();
    format!(" {}… {CAPTURE_RECOVERY_HINT} ", cause.trim_end())
}

pub(in crate::ui) fn draw_status_bar(
    f: &mut Frame,
    ui_state: &UIState,
    capture_error: Option<&str>,
    area: Rect,
) {
    let clipboard_message = ui_state
        .clipboard_message
        .as_ref()
        .filter(|(_, time)| time.elapsed().as_secs() < 3)
        .map(|(message, _)| message);

    let status_bar = if ui_state.quit_confirmation {
        Paragraph::new(" Press 'q' again to quit or any other key to cancel ")
            .style(theme::status_bar_confirm())
    } else if ui_state.clear_confirmation {
        Paragraph::new(" Press 'x' again to clear all connections or any other key to cancel ")
            .style(theme::status_bar_confirm())
    } else if let Some(message) = clipboard_message {
        Paragraph::new(format!(" {message} ")).style(theme::status_bar_success())
    } else if let Some(error) = capture_error {
        Paragraph::new(capture_error_text(error, area.width, area.height))
            .style(theme::status_bar_error())
    } else {
        Paragraph::new(hint_line(&context_hints(ui_state), area.width))
            .style(theme::status_bar_default())
    };

    f.render_widget(status_bar.alignment(ratatui::layout::Alignment::Left), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertises(hints: &[Hint], key: &str) -> bool {
        hints.iter().any(|(hint_key, _)| *hint_key == key)
    }

    fn rendered(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn details_advertises_pane_scrolling_only_once_the_pane_scrolls() {
        let ui_state = UIState {
            selected_tab: 1,
            ..Default::default()
        };
        assert!(!advertises(&context_hints(&ui_state), "ctrl-d/u"));

        // A render that reports headroom turns the hint on.
        ui_state.details_scroll.clamp_for_render(12);
        assert!(advertises(&context_hints(&ui_state), "ctrl-d/u"));
    }

    #[test]
    fn overview_spends_its_room_on_actions_visible_nowhere_else() {
        let hints = context_hints(&UIState::default());
        assert_eq!(hints.first().map(|(key, _)| *key), Some("/"));
        // Tab navigation is advertised by the numbered tab bar itself.
        assert!(!advertises(&hints, "1-5"));
        assert!(!advertises(&hints, "tab"));
    }

    #[test]
    fn clearing_outranks_every_other_overview_action() {
        let ui_state = UIState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        assert_eq!(
            context_hints(&ui_state).first(),
            Some(&("esc", "clear filter"))
        );
    }

    #[test]
    fn the_global_cluster_survives_every_width() {
        let context = context_hints(&UIState::default());
        for width in [200u16, 120, 80, 60, 40, 24, 12] {
            let line = rendered(&hint_line(&context, width));
            assert!(line.contains('q'), "quit dropped at {width}: {line:?}");
            assert!(
                line.chars().count() <= width as usize,
                "overflowed {width}: {line:?}"
            );
        }
    }

    #[test]
    fn labels_are_dropped_before_context_actions_are() {
        let context = context_hints(&UIState::default());
        // Wide enough to spell every action out.
        let wide = rendered(&hint_line(&context, 120));
        assert!(wide.contains("filter"), "{wide:?}");
        assert!(wide.contains("quit"), "{wide:?}");

        // Too narrow for labels, yet every key is still there.
        let narrow = rendered(&hint_line(&context, 40));
        assert!(!narrow.contains("filter"), "{narrow:?}");
        for (key, _) in &context {
            assert!(narrow.contains(key), "{key} dropped: {narrow:?}");
        }
    }

    #[test]
    fn the_global_cluster_sits_flush_right() {
        let line = rendered(&hint_line(&context_hints(&UIState::default()), 120));
        assert!(line.ends_with("q quit "), "{line:?}");
    }
}
