//! Shared section selection, keyboard controls, and responsive chrome.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Frame, layout::Rect, text::Span};

use super::{
    ClickAction, ClickableRegions, DetailsSection, Effect, GraphSection, HostView, OverviewSection,
    UiState,
    widgets::tab_strip::{self, TabStrip},
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

/// Share the main tabs' title and underline treatment, including both-row hit targets.
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
    let width =
        labels.iter().map(|label| label.len()).sum::<usize>() + labels.len().saturating_sub(1) * 3;
    let mut strip = TabStrip::new(Span::raw(""));
    if width <= usize::from(area.width) {
        for (index, label) in labels.iter().enumerate() {
            strip.push(
                vec![tab_strip::title(*label, index == selected)],
                index == selected,
                if index == 0 { 0 } else { 3 },
                ClickAction::SelectSection(index),
            );
        }
    } else {
        strip.push(
            vec![tab_strip::title("<", false)],
            false,
            0,
            ClickAction::SelectSection((selected + labels.len() - 1) % labels.len()),
        );
        strip.push(
            vec![tab_strip::title(
                format!("{} {}/{}", labels[selected], selected + 1, labels.len()),
                true,
            )],
            true,
            2,
            ClickAction::SelectSection(selected),
        );
        strip.push(
            vec![tab_strip::title(">", false)],
            false,
            2,
            ClickAction::SelectSection((selected + 1) % labels.len()),
        );
    }
    strip.draw(f, area, regions);
    let height = area.height.min(tab_strip::HEIGHT);
    Rect::new(
        area.x,
        area.y + height,
        area.width,
        area.height.saturating_sub(height),
    )
}
