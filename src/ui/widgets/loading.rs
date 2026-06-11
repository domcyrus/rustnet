//! Startup splash shown while packet capture initializes.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::Style,
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::ui::{panel_block, theme};

pub(in crate::ui) fn draw_loading_screen(f: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(40),
            Constraint::Length(5),
            Constraint::Percentage(40),
        ])
        .split(f.area());

    let loading_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("⣾ ", theme::bold_fg(theme::accent())),
            Span::styled("Loading network connections...", Style::default()),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "This may take a few seconds",
            theme::fg(theme::muted()),
        )]),
    ];

    let loading_paragraph = Paragraph::new(loading_text)
        .alignment(ratatui::layout::Alignment::Center)
        .block(panel_block("RustNet Monitor"));

    f.render_widget(loading_paragraph, chunks[1]);
}
