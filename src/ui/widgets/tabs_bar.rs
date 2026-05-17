//! Top tab bar — five fixed tabs styled as a reverse-video pill
//! highlight on the selected one. Also registers click regions so
//! a mouse click on a tab title triggers `ClickAction::SwitchTab`.

use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Tabs,
};

use crate::ui::{ClickAction, ClickableRegions, UIState, panel_block, theme};

/// Custom styling: each title gets one space of padding so the active tab
/// renders as a reverse-video pill. Inactive titles use the muted palette
/// so the bar reads as a quiet header strip with one obvious focus point.
const TAB_TITLES: [&str; 5] = ["Overview", "Details", "Interfaces", "Graph", "Help"];
const TAB_DIVIDER: &str = " ▏ ";

pub(in crate::ui) fn draw_tabs(
    f: &mut Frame,
    ui_state: &UIState,
    area: Rect,
    click_regions: &mut ClickableRegions,
) {
    let inactive = theme::fg(theme::muted());
    let titles: Vec<Line> = TAB_TITLES
        .iter()
        .map(|t| Line::from(Span::styled(format!(" {t} "), inactive)))
        .collect();

    let tabs = Tabs::new(titles)
        .block(panel_block(Span::styled(
            " RustNet Monitor ",
            theme::fg(theme::muted()),
        )))
        .select(ui_state.selected_tab)
        // Drop the widget's default 1-char padding on each side; the title
        // strings carry their own " {title} " spacing so the active pill's
        // reverse-video style covers the whole tab cell, not just the text.
        .padding_left("")
        .padding_right("")
        .divider(Span::styled(TAB_DIVIDER, theme::fg(theme::muted())))
        .style(Style::default())
        .highlight_style(theme::primary().add_modifier(Modifier::REVERSED));

    f.render_widget(tabs, area);

    // Register clickable tab regions. Tabs renders inside the block's inner
    // area (1px border each side); each title is " {title} " (2 chars padding
    // baked in), divider spans 3 cells (" ▏ ").
    let inner = area.inner(ratatui::layout::Margin {
        horizontal: 1,
        vertical: 1,
    });
    let divider_width = TAB_DIVIDER.chars().count() as u16;
    let mut x_offset = inner.x;
    for (i, title) in TAB_TITLES.iter().enumerate() {
        let padded_width = title.len() as u16 + 2; // leading + trailing space
        let tab_rect = Rect::new(x_offset, inner.y, padded_width, inner.height);
        click_regions.register(tab_rect, ClickAction::SwitchTab(i));
        x_offset += padded_width + divider_width;
    }
}
