//! Terminal lifecycle: alternate-screen + raw-mode setup and teardown,
//! plus the `Terminal` type alias the rest of the crate uses.

use anyhow::Result;
use ratatui::Terminal as RatatuiTerminal;

pub type Terminal<B> = RatatuiTerminal<B>;

/// Set up the terminal for the TUI application.
///
/// Also installs a panic hook (chained ahead of the previous one) that
/// restores the terminal before the panic message is printed. Without
/// it, a panic anywhere in the app leaves the terminal in raw mode on
/// the alternate screen with mouse capture on — a garbled shell that
/// needs `tput reset`. `ratatui::init()` installs an equivalent hook,
/// but it does not enable mouse capture, which rustnet relies on for
/// its clickable hit-test regions, so we keep the manual setup and add
/// the hook ourselves.
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
    install_panic_hook();
    Ok(terminal)
}

/// Restore the terminal to its original state
pub fn restore_terminal<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>) -> Result<()>
where
    <B as ratatui::backend::Backend>::Error: Send + Sync + 'static,
{
    restore_terminal_raw()?;
    terminal.show_cursor()?;
    Ok(())
}

/// Crossterm-level teardown that needs no `Terminal` handle: disable raw
/// mode, leave the alternate screen, disable mouse capture, and show the
/// cursor. Shared by the normal teardown path and the panic hook (which
/// cannot borrow the `Terminal`). Best-effort — errors are ignored when
/// called from the panic hook since we are already unwinding.
fn restore_terminal_raw() -> Result<()> {
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::event::DisableMouseCapture,
        crossterm::cursor::Show
    )?;
    Ok(())
}

/// Chain a panic hook ahead of the existing one that restores the
/// terminal first, so the panic message lands on a usable screen.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort: we are already panicking, so ignore restore errors.
        let _ = restore_terminal_raw();
        previous(info);
    }));
}
