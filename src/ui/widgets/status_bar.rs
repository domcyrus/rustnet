//! Bottom status line: the active tab's context actions on the left and a
//! fixed global cluster (help, quit) pinned right, or transient
//! confirmation prompts ("press q again to quit"), clipboard feedback, and
//! capture failures (which claim a second row when they do not fit on one).
//!
//! Hints follow a keycap grammar: the key in `theme::key_hint()`, its label
//! in `theme::key_hint_label()`, two spaces between hints. Active modes use
//! a compact chip (a tinted box, or a boxed fallback when no tint is
//! available) carrying one padding cell of its own on each side, so a chip
//! sits a cell further from its neighbors than a plain hint does. The
//! global cluster is reserved before any context action is placed, so
//! `q quit` never falls off the right edge. When the terminal is too narrow
//! to spell every action out, the labels go first and the keys stand alone;
//! only then are context actions dropped, plain actions from the end before
//! active mode chips, which show state visible nowhere else on the tab.
//! Contextual keymaps live in the help overlay.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{HostView, UIState, theme};

/// One keycap hint: the key as typed and the action it triggers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hint {
    key: &'static str,
    label: &'static str,
    active: bool,
}

impl Hint {
    const fn action(key: &'static str, label: &'static str) -> Self {
        Self {
            key,
            label,
            active: false,
        }
    }

    const fn mode(key: &'static str, label: &'static str, active: bool) -> Self {
        Self { key, label, active }
    }
}

/// Pinned to the right edge, and the last thing dropped: the two keys worth
/// knowing when nothing else makes sense.
const GLOBAL_HINTS: [Hint; 2] = [Hint::action("h", "help"), Hint::action("q", "quit")];

/// Right-edge cluster while a filter is being typed. `h` and `q` would type
/// a character into the query rather than help or quit, so the two keys that
/// end the mode take their place.
const FILTER_HINTS: [Hint; 2] = [
    Hint::action("enter", "apply"),
    Hint::action("esc", "cancel"),
];

/// Right-edge cluster while contextual help is visible.
const HELP_HINTS: [Hint; 2] = [Hint::action("h/esc", "close"), Hint::action("q", "quit")];

/// Cells between two hints inside a group.
const HINT_GAP: usize = 2;
/// Minimum blank cells between the context actions and the global cluster,
/// so the two groups never read as one run of hints.
const CLUSTER_GAP: usize = 3;
/// How many context actions must still fit with their labels spelled out
/// before the bar gives up on labels entirely. Below this it is showing so
/// few actions that a full row of bare keys carries more.
const MIN_LABELED: usize = 3;

/// Context actions for the active tab, most useful first. Tab navigation is
/// deliberately absent: the numbered titles in the tab bar already advertise
/// it, and the footer's room is better spent on actions that appear nowhere
/// else on screen. Copy drops out entirely when the clipboard is out of
/// reach, rather than advertising a key that can only fail.
fn context_hints(ui_state: &UIState, clipboard: bool) -> Vec<Hint> {
    if ui_state.show_help {
        return ui_state
            .help_scroll
            .can_scroll()
            .then_some(Hint::action("j/k", "scroll"))
            .into_iter()
            .collect();
    }
    // While a filter is being typed the key handler routes every character
    // into the query, so the tab's own actions are unreachable: advertising
    // them would name keys that type a letter instead. Only what the filter
    // editor actually handles is offered.
    if ui_state.filter_mode {
        return vec![Hint::action("\u{2191}\u{2193}", "select")];
    }
    match ui_state.selected_tab {
        // Overview
        0 => {
            let mut hints = Vec::new();
            // Clearing outranks everything else while a filter is on.
            if ui_state.has_active_filter() {
                hints.push(Hint::action("esc", "clear filter"));
            }
            // Grouping turns Space into the most useful local action. The
            // selected group is retained while walking its children, so the
            // label remains accurate on both a header and a child row.
            if ui_state.grouping_enabled
                && let Some(expanded) = ui_state.selected_group_expansion()
            {
                let label = if expanded { "collapse" } else { "expand" };
                hints.push(Hint::action("space", label));
            }
            hints.extend([
                Hint::action("\u{2191}\u{2193}", "select"),
                Hint::action("/", "filter"),
                Hint::mode(
                    "a",
                    if ui_state.grouping_enabled {
                        "grouped"
                    } else {
                        "group"
                    },
                    ui_state.grouping_enabled,
                ),
                Hint::mode("t", "history", ui_state.show_historic),
                Hint::action("i", "info"),
            ]);
            if clipboard {
                hints.push(Hint::action("c", "copy"));
            }
            hints
        }
        // Details
        1 => {
            let mut hints = vec![Hint::action("j/k", "prev/next")];
            // Ctrl+D/U only moves when the record outgrows its pane, so on a
            // tall terminal the hint would advertise a no-op.
            if ui_state.details_scroll.can_scroll() {
                hints.push(Hint::action("ctrl-d/u", "scroll"));
            }
            if clipboard {
                hints.push(Hint::action("c", "copy remote addr"));
            }
            hints.push(Hint::action("esc", "back"));
            hints
        }
        // Activity
        2 => vec![
            Hint::action("d", "tx/rx"),
            Hint::action("s", "sort"),
            Hint::action("S", "order"),
            Hint::action("esc", "back"),
        ],
        // Host
        4 => {
            // Like ctrl-d/u on Details: only advertise scrolling when the
            // table actually outgrew its pane.
            let (scroll, toggle) = match ui_state.host_view {
                HostView::Sockets => (
                    &ui_state.host_sockets_scroll,
                    Hint::action("i", "interfaces"),
                ),
                HostView::Interfaces => (&ui_state.interfaces_scroll, Hint::action("s", "sockets")),
            };
            let mut hints = Vec::new();
            if scroll.can_scroll() {
                hints.push(Hint::action("j/k", "scroll"));
            }
            hints.push(toggle);
            hints.push(Hint::action("esc", "back"));
            hints
        }
        // Graph
        _ => vec![Hint::action("esc", "back")],
    }
}

/// Spans for one hint. Without `labels` the key stands alone, the fallback
/// for a terminal too narrow to spell the action out.
fn hint_spans(hint: Hint, labels: bool) -> Vec<Span<'static>> {
    if hint.active {
        let text = if labels {
            format!(" {} {} ", hint.key, hint.label)
        } else {
            format!(" {} ", hint.key)
        };
        return vec![Span::styled(text, theme::active_key_hint())];
    }

    let mut spans = vec![Span::styled(hint.key, theme::key_hint())];
    if labels {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(hint.label, theme::key_hint_label()));
    }
    spans
}

fn hint_width(hint: Hint, labels: bool) -> usize {
    let mut width = hint.key.chars().count();
    if labels {
        width += 1 + hint.label.chars().count();
    }
    if hint.active {
        // One padding cell on each side turns the selected mode into a chip.
        width += 2;
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

/// Lay the bar out: context actions from the left, `cluster` flush right.
/// Tried once with every label spelled out, then with keys alone, dropping
/// context actions from the end only when even that overflows.
fn hint_line(context: &[Hint], cluster: &[Hint], width: u16) -> Line<'static> {
    let width = width as usize;
    for labels in [true, false] {
        let global = group_width(cluster, labels);
        // One pad cell at each edge, plus the reserved global cluster.
        let Some(room) = width.checked_sub(global + 2) else {
            continue;
        };
        let mut kept: Vec<Hint> = context.to_vec();
        // Dropped back-to-front, except that active mode chips outlive the
        // plain actions around them: a chip is state the user can read
        // nowhere else on the tab, and without it a mode-specific action
        // like "space expand" would show with no sign the mode is on.
        while !kept.is_empty() && group_width(&kept, labels) + CLUSTER_GAP > room {
            let victim = kept
                .iter()
                .rposition(|hint| !hint.active)
                .unwrap_or(kept.len() - 1);
            kept.remove(victim);
        }
        let used = group_width(&kept, labels);
        // A labeled action says what it does, which is the whole point of the
        // footer, so trailing actions are dropped to keep the labels. Only
        // once too few survive is the row better off as bare keys.
        if labels && kept.len() < context.len().min(MIN_LABELED) {
            continue;
        }
        let mut spans = vec![Span::raw(" ")];
        push_group(&mut spans, &kept, labels);
        spans.push(Span::raw(" ".repeat(room - used)));
        push_group(&mut spans, cluster, labels);
        spans.push(Span::raw(" "));
        return Line::from(spans);
    }
    // Narrower than the cluster itself: show the one key that ends the mode.
    Line::from(hint_spans(cluster[cluster.len() - 1], false))
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
    clipboard: bool,
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
        let cluster: &[Hint] = if ui_state.show_help {
            &HELP_HINTS
        } else if ui_state.filter_mode {
            &FILTER_HINTS
        } else {
            &GLOBAL_HINTS
        };
        Paragraph::new(hint_line(
            &context_hints(ui_state, clipboard),
            cluster,
            area.width,
        ))
        .style(theme::status_bar_default())
    };

    f.render_widget(status_bar.alignment(ratatui::layout::Alignment::Left), area);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn advertises(hints: &[Hint], key: &str) -> bool {
        hints.iter().any(|hint| hint.key == key)
    }

    fn hint_for<'a>(hints: &'a [Hint], key: &str) -> &'a Hint {
        hints
            .iter()
            .find(|hint| hint.key == key)
            .unwrap_or_else(|| panic!("missing {key:?} hint"))
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
        assert!(!advertises(&context_hints(&ui_state, true), "ctrl-d/u"));

        // A render that reports headroom turns the hint on.
        ui_state.details_scroll.clamp_for_render(12);
        assert!(advertises(&context_hints(&ui_state, true), "ctrl-d/u"));
    }

    #[test]
    fn overview_spends_its_room_on_actions_visible_nowhere_else() {
        let hints = context_hints(&UIState::default(), true);
        assert_eq!(hints.first().map(|hint| hint.key), Some("\u{2191}\u{2193}"));
        assert!(advertises(&hints, "/"));
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
            context_hints(&ui_state, true).first(),
            Some(&Hint::action("esc", "clear filter"))
        );
    }

    #[test]
    fn overview_marks_grouping_and_history_as_active_modes() {
        let ui_state = UIState {
            grouping_enabled: true,
            show_historic: true,
            ..Default::default()
        };
        let hints = context_hints(&ui_state, true);

        assert_eq!(hint_for(&hints, "a"), &Hint::mode("a", "grouped", true));
        assert_eq!(hint_for(&hints, "t"), &Hint::mode("t", "history", true));
    }

    #[test]
    fn overview_offers_space_to_expand_or_collapse_the_selected_group() {
        let mut ui_state = UIState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            ..Default::default()
        };

        let collapsed = context_hints(&ui_state, true);
        assert_eq!(hint_for(&collapsed, "space").label, "expand");

        ui_state.expanded_groups.insert("firefox".to_string());
        let expanded = context_hints(&ui_state, true);
        assert_eq!(hint_for(&expanded, "space").label, "collapse");

        // Child selection keeps the parent group selected, so Space still
        // advertises the collapse action that the key handler performs.
        ui_state.selected_connection_key = Some("child".to_string());
        let child = context_hints(&ui_state, true);
        assert_eq!(hint_for(&child, "space").label, "collapse");
    }

    #[test]
    fn overview_omits_space_without_an_actionable_group() {
        assert!(!advertises(
            &context_hints(&UIState::default(), true),
            "space"
        ));
        let grouped_empty = UIState {
            grouping_enabled: true,
            ..Default::default()
        };
        assert!(!advertises(&context_hints(&grouped_empty, true), "space"));
    }

    #[test]
    fn the_global_cluster_survives_every_width() {
        let context = context_hints(&UIState::default(), true);
        for width in [200u16, 120, 80, 60, 40, 24, 12] {
            let line = rendered(&hint_line(&context, &GLOBAL_HINTS, width));
            assert!(line.contains('q'), "quit dropped at {width}: {line:?}");
            assert!(
                line.chars().count() <= width as usize,
                "overflowed {width}: {line:?}"
            );
        }
    }

    #[test]
    fn labels_are_dropped_before_context_actions_are() {
        let context = context_hints(&UIState::default(), true);
        // Wide enough to spell every action out.
        let wide = rendered(&hint_line(&context, &GLOBAL_HINTS, 120));
        assert!(wide.contains("filter"), "{wide:?}");
        assert!(wide.contains("quit"), "{wide:?}");

        // Too narrow for labels, yet every key is still there.
        let narrow = rendered(&hint_line(&context, &GLOBAL_HINTS, 40));
        assert!(!narrow.contains("filter"), "{narrow:?}");
        for hint in &context {
            assert!(
                narrow.contains(hint.key),
                "{} dropped: {narrow:?}",
                hint.key
            );
        }
    }

    #[test]
    fn standard_terminal_keeps_group_actions_and_active_modes() {
        let ui_state = UIState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            show_historic: true,
            ..Default::default()
        };
        let context = context_hints(&ui_state, true);
        let line = rendered(&hint_line(&context, &GLOBAL_HINTS, 80));

        for text in ["space expand", "select", "filter", "grouped", "history"] {
            assert!(line.contains(text), "{text:?} dropped: {line:?}");
        }
        assert!(line.ends_with("q quit "), "{line:?}");
        assert!(line.chars().count() <= 80, "{line:?}");
    }

    #[test]
    fn active_mode_chips_outlive_plain_actions_when_room_runs_out() {
        // 80 columns with a filter, grouping, and history all on is the
        // tightest realistic case: the chips must survive it, even at the
        // cost of plain actions, or the bar would show grouping-specific
        // actions with no sign that grouping is on.
        let ui_state = UIState {
            grouping_enabled: true,
            selected_group: Some("firefox".to_string()),
            show_historic: true,
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let context = context_hints(&ui_state, true);
        let line = rendered(&hint_line(&context, &GLOBAL_HINTS, 80));
        for text in ["clear filter", "grouped", "history"] {
            assert!(line.contains(text), "{text:?} dropped: {line:?}");
        }
        assert!(line.chars().count() <= 80, "{line:?}");
    }

    #[test]
    fn labels_survive_a_standard_terminal_by_dropping_trailing_actions() {
        // 80 columns with a filter on is the tightest realistic case: the
        // labels have to survive it, even if the last action does not.
        let ui_state = UIState {
            filter_query: "port:443".to_string(),
            ..Default::default()
        };
        let context = context_hints(&ui_state, true);
        let line = rendered(&hint_line(&context, &GLOBAL_HINTS, 80));
        assert!(line.contains("clear filter"), "{line:?}");
        assert!(line.contains("select"), "{line:?}");
        assert!(line.ends_with("q quit "), "{line:?}");
        assert!(
            !line.contains("copy"),
            "the last action should have gone before the labels: {line:?}"
        );
    }

    #[test]
    fn copy_is_not_offered_when_the_clipboard_is_out_of_reach() {
        for tab in [0, 1] {
            let ui_state = UIState {
                selected_tab: tab,
                ..Default::default()
            };
            assert!(
                advertises(&context_hints(&ui_state, true), "c"),
                "tab {tab} should offer copy when the clipboard works"
            );
            assert!(
                !advertises(&context_hints(&ui_state, false), "c"),
                "tab {tab} still offers a copy that can only fail"
            );
        }
        // Everything else on the tab survives losing copy.
        let sandboxed = context_hints(&UIState::default(), false);
        assert!(advertises(&sandboxed, "/"));
        assert!(advertises(&sandboxed, "i"));
    }

    #[test]
    fn filter_editing_only_offers_keys_the_editor_handles() {
        let editing = UIState {
            filter_mode: true,
            filter_query: "port:44".to_string(),
            ..Default::default()
        };
        let hints = context_hints(&editing, true);
        // Every Char key goes into the query while typing, so none of the
        // tab's own actions may be named here.
        for key in ["/", "a", "t", "i", "c"] {
            assert!(
                !advertises(&hints, key),
                "{key} types a character while filtering, but is advertised"
            );
        }
        // The keys that end the mode move to the right-edge cluster.
        assert_eq!(FILTER_HINTS.map(|hint| hint.key), ["enter", "esc"]);
    }

    #[test]
    fn the_global_cluster_sits_flush_right() {
        let line = rendered(&hint_line(
            &context_hints(&UIState::default(), true),
            &GLOBAL_HINTS,
            120,
        ));
        assert!(line.ends_with("q quit "), "{line:?}");
    }
}
