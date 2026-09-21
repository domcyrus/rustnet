//! Shared section selection, keyboard controls, and responsive chrome.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Frame, layout::Rect, style::Modifier, text::Span, widgets::Paragraph};

use super::{
    ClickAction, ClickableRegions, DetailsSection, Effect, GraphSection, HostView, OverviewSection,
    UiState, section_body, theme,
};

pub(super) const SECTION_KEYS: &str = "v/V";
pub(super) const SECTION_HELP: (&str, &str) = (
    SECTION_KEYS,
    "Next/previous section; click a section name to select it",
);

impl UiState {
    pub(super) fn sections(&self) -> (&'static [&'static str], usize) {
        match self.selected_tab {
            0 => (&["Connections", "System"], self.overview_section as usize),
            1 => (
                &[
                    "Connection",
                    "Network",
                    "Process",
                    "Application",
                    "Health",
                    "Traffic",
                ],
                self.details_section.index(),
            ),
            3 => (
                &["Traffic", "Health", "Distribution"],
                self.graph_section as usize,
            ),
            4 => (&["Sockets", "Interfaces"], self.host_view as usize),
            _ => (&[], 0),
        }
    }

    /// Keyboard and mouse selection share the same validation and scroll reset.
    pub fn select_section(&mut self, index: usize) {
        let (labels, selected) = self.sections();
        if index >= labels.len() || index == selected {
            return;
        }
        match self.selected_tab {
            0 => {
                self.overview_section =
                    [OverviewSection::Connections, OverviewSection::System][index]
            }
            1 => {
                self.details_section = DetailsSection::ALL[index];
                self.details_scroll.reset();
            }
            3 => {
                self.graph_section = [
                    GraphSection::Traffic,
                    GraphSection::Health,
                    GraphSection::Distribution,
                ][index]
            }
            4 => self.host_view = [HostView::Sockets, HostView::Interfaces][index],
            _ => {}
        }
    }
}

pub(super) fn handle_key(key: KeyEvent, state: &mut UiState) -> Option<Vec<Effect>> {
    if !state.section_navigation {
        return None;
    }
    let forward = match (key.code, key.modifiers) {
        (KeyCode::Char('v'), KeyModifiers::NONE) => true,
        (KeyCode::Char('V'), KeyModifiers::NONE | KeyModifiers::SHIFT)
        | (KeyCode::Char('v'), KeyModifiers::SHIFT) => false,
        _ => return None,
    };
    let (labels, selected) = state.sections();
    if !labels.is_empty() {
        let index = if forward {
            (selected + 1) % labels.len()
        } else {
            (selected + labels.len() - 1) % labels.len()
        };
        state.select_section(index);
    }
    Some(Vec::new())
}

/// One row when sections are needed. If all labels do not fit, keep the selected label
/// and its position visible with clickable previous/next controls.
pub(super) fn draw_selector(
    f: &mut Frame,
    area: Rect,
    state: &UiState,
    regions: &mut ClickableRegions,
) -> Rect {
    let (labels, selected) = state.sections();
    if !state.section_navigation || labels.is_empty() || area.height == 0 {
        return area;
    }
    let width: usize = labels.iter().map(|label| label.len() + 4).sum();
    let hint = format!(" {SECTION_KEYS} section");
    let mut x = area.x;
    let mut item = |text: String, index: usize, active: bool| {
        let width = (text.len() as u16).min(area.right().saturating_sub(x));
        let rect = Rect::new(x, area.y, width, 1);
        let style = if active {
            theme::bold_fg(theme::accent()).add_modifier(Modifier::UNDERLINED)
        } else {
            theme::fg(theme::muted())
        };
        f.render_widget(Paragraph::new(Span::styled(text, style)), rect);
        regions.register(rect, ClickAction::SelectSection(index));
        x += width;
    };
    if width <= usize::from(area.width) {
        for (index, label) in labels.iter().enumerate() {
            item(
                if index == selected {
                    format!("[{label}]  ")
                } else {
                    format!(" {label}   ")
                },
                index,
                index == selected,
            );
        }
    } else {
        item(
            "< ".into(),
            (selected + labels.len() - 1) % labels.len(),
            false,
        );
        item(
            format!("{} {}/{} ", labels[selected], selected + 1, labels.len()),
            selected,
            true,
        );
        item(">".into(), (selected + 1) % labels.len(), false);
    }
    let hint = if usize::from(area.right().saturating_sub(x)) >= hint.len() {
        hint
    } else {
        format!(" {SECTION_KEYS}")
    };
    if usize::from(area.right().saturating_sub(x)) >= hint.len() {
        f.render_widget(
            Paragraph::new(Span::styled(hint, theme::fg(theme::muted()))).right_aligned(),
            Rect::new(x, area.y, area.right().saturating_sub(x), 1),
        );
    }
    section_body(area)
}
