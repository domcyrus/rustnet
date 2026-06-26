//! Top tab bar — a borderless two-row strip: the brand + numbered tab
//! titles on the first row, and an underline rule on the second with a
//! heavy accent segment under the active tab. The heavy ━ vs light ─
//! glyph difference keeps the active tab readable under NO_COLOR.
//! Click regions cover both rows so a click on the underline works too.

use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{ClickAction, ClickableRegions, UIState, theme};

pub(crate) const TAB_TITLES: [&str; 5] = ["Overview", "Details", "Interfaces", "Graph", "Help"];
/// Total number of tabs (kept in sync with `TAB_TITLES`).
pub(crate) const TAB_COUNT: usize = TAB_TITLES.len();
/// Index of the Help tab. Lets `UIState::jump_to_tab` keep `show_help` in
/// sync without re-checking `TAB_TITLES` at the call site.
pub(crate) const HELP_TAB_INDEX: usize = TAB_COUNT - 1;

/// Height of the tab bar in rows (titles + underline).
pub(crate) const TABS_BAR_HEIGHT: u16 = 2;

const BRAND: &str = " rustnet ";
/// Gap between tab titles, in cells.
const TAB_GAP: u16 = 3;
/// Literal gap string — must be exactly `TAB_GAP` spaces.
const GAP: &str = "   ";

pub(in crate::ui) fn draw_tabs(
    f: &mut Frame,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let mut title_spans: Vec<Span> = vec![Span::styled(BRAND, theme::primary())];
    let mut underline_spans: Vec<Span> = vec![Span::styled(
        "─".repeat(BRAND.chars().count()),
        theme::fg(theme::border()),
    )];

    let mut x_offset = area.x + BRAND.chars().count() as u16;
    for (i, title) in TAB_TITLES.iter().enumerate() {
        // Numbered titles: the 1-5 jump shortcut becomes discoverable.
        let label = format!("{} {}", i + 1, title);
        let label_width = label.chars().count() as u16;
        let active = i == ui_state.selected_tab;

        title_spans.push(Span::raw(GAP));
        if active {
            title_spans.push(Span::styled(
                format!("{} ", i + 1),
                theme::fg(theme::accent()),
            ));
            title_spans.push(Span::styled(*title, theme::primary()));
        } else {
            title_spans.push(Span::styled(label, theme::fg(theme::muted())));
        }

        underline_spans.push(Span::styled(
            "─".repeat(TAB_GAP as usize),
            theme::fg(theme::border()),
        ));
        let rule_glyph = if active { "━" } else { "─" };
        let rule_style = if active {
            theme::fg(theme::accent())
        } else {
            theme::fg(theme::border())
        };
        underline_spans.push(Span::styled(
            rule_glyph.repeat(label_width as usize),
            rule_style,
        ));

        // Click region spans both rows (title + underline).
        let tab_rect = Rect::new(x_offset + TAB_GAP, area.y, label_width, TABS_BAR_HEIGHT);
        click_regions.register(tab_rect, ClickAction::SwitchTab(i));
        x_offset += TAB_GAP + label_width;
    }

    // Extend the rule to the right edge of the bar.
    let used: u16 = x_offset.saturating_sub(area.x);
    if area.width > used {
        underline_spans.push(Span::styled(
            "─".repeat((area.width - used) as usize),
            theme::fg(theme::border()),
        ));
    }

    let titles = Paragraph::new(Line::from(title_spans));
    let underline = Paragraph::new(Line::from(underline_spans));

    f.render_widget(titles, Rect::new(area.x, area.y, area.width, 1));
    if area.height >= TABS_BAR_HEIGHT {
        f.render_widget(underline, Rect::new(area.x, area.y + 1, area.width, 1));
    }
}
