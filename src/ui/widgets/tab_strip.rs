//! Shared title rows, selection rules, and mouse targets for tab navigation.

use crate::ui::{ClickAction, ClickableRegions, cell_borders, theme};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::Paragraph,
};

pub(in crate::ui) fn height() -> u16 {
    if cell_borders::enabled() { 1 } else { 2 }
}

pub(in crate::ui) fn title(text: impl Into<String>, active: bool) -> Span<'static> {
    Span::styled(
        text.into(),
        if active {
            theme::primary()
        } else {
            theme::fg(theme::muted())
        },
    )
}

pub(in crate::ui) struct TabStrip {
    pub titles: Vec<Span<'static>>,
    rules: Vec<Span<'static>>,
    targets: Vec<(u16, u16, ClickAction, bool)>,
    width: u16,
}

impl TabStrip {
    pub fn new(prefix: Span<'static>) -> Self {
        let width = prefix.width() as u16;
        Self {
            titles: vec![prefix],
            rules: vec![Span::styled(
                "─".repeat(width as usize),
                theme::fg(theme::border()),
            )],
            targets: Vec::new(),
            width,
        }
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn push(&mut self, label: Vec<Span<'static>>, active: bool, gap: u16, action: ClickAction) {
        let width = label.iter().map(Span::width).sum::<usize>() as u16;
        self.titles.push(Span::raw(" ".repeat(gap as usize)));
        self.titles.extend(label);
        self.rules.push(Span::styled(
            "─".repeat(gap as usize),
            theme::fg(theme::border()),
        ));
        self.rules.push(Span::styled(
            (if active { "━" } else { "─" }).repeat(width as usize),
            theme::fg(if active {
                theme::accent()
            } else {
                theme::border()
            }),
        ));
        self.targets.push((self.width + gap, width, action, active));
        self.width += gap + width;
    }

    pub fn draw(mut self, f: &mut Frame, area: Rect, regions: &mut ClickableRegions) {
        if area.height == 0 {
            return;
        }
        self.rules.push(Span::styled(
            "─".repeat(area.width.saturating_sub(self.width) as usize),
            theme::fg(theme::border()),
        ));
        f.render_widget(
            Paragraph::new(Line::from(self.titles)),
            Rect::new(area.x, area.y, area.width, 1),
        );
        if cell_borders::enabled() {
            cell_borders::edge(
                Rect::new(area.x, area.y, area.width, 1),
                cell_borders::BOTTOM,
                theme::border(),
                0,
                false,
            );
        } else if area.height >= 2 {
            f.render_widget(
                Paragraph::new(Line::from(self.rules)),
                Rect::new(area.x, area.y + 1, area.width, 1),
            );
        }
        for (x, width, action, active) in self.targets {
            let rect =
                Rect::new(area.x.saturating_add(x), area.y, width, height()).intersection(area);
            if rect.width > 0 && rect.height > 0 {
                if active {
                    cell_borders::edge(
                        Rect::new(rect.x, rect.y, rect.width, 1),
                        cell_borders::BOTTOM,
                        theme::accent(),
                        1,
                        false,
                    );
                }
                regions.register(rect, action);
            }
        }
    }
}
