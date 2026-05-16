//! Terminal lifecycle: alternate-screen + raw-mode setup and teardown,
//! plus the `Terminal` type alias the rest of the crate uses.

use anyhow::Result;
use ratatui::Terminal as RatatuiTerminal;

pub type Terminal<B> = RatatuiTerminal<B>;

/// Set up the terminal for the TUI application
pub fn setup_terminal<B: ratatui::backend::Backend>(backend: B) -> Result<Terminal<B>>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    let mut terminal = RatatuiTerminal::new(backend)?;
    terminal.clear()?;
    terminal.hide_cursor()?;
    crossterm::terminal::enable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    Ok(terminal)
}

/// Restore the terminal to its original state
pub fn restore_terminal<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}
