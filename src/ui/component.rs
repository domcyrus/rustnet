//! Per-tab Component pattern adapted for rustnet's synchronous,
//! crossbeam-threaded UI loop.
//!
//! Differences from ratatui's official component template:
//! - No `tokio::sync::mpsc::UnboundedSender<Action>` — the loop is
//!   synchronous; components return `Vec<Effect>` from event
//!   handlers instead of pushing through a channel.
//! - No `register_action_handler` / `register_config_handler` /
//!   `init` — shared state (`App`, `UIState`) is passed through
//!   context structs on each call.

use anyhow::Result;
use crossterm::event::KeyEvent;
use ratatui::{Frame, layout::Rect};

use crate::app::{App, AppStats};
use crate::network::types::Connection;
use crate::ui::{ClickableRegions, GroupedRow, UIState};

/// Read-only bundle passed to every component's `draw`. Lifetime
/// matches the borrow scope inside the main loop's `terminal.draw`
/// closure.
pub struct DrawContext<'a> {
    pub app: &'a App,
    pub connections: &'a [Connection],
    pub ui_state: &'a UIState,
    pub grouped_rows: Option<&'a [GroupedRow<'a>]>,
    pub stats: &'a AppStats,
}

/// Mutable bundle for event handlers. The component owns the
/// mutation of `ui_state`; cross-cutting work (refresh, clipboard,
/// quit) goes back via the returned `Vec<Effect>`.
pub struct HandlerContext<'a> {
    pub app: &'a App,
    pub ui_state: &'a mut UIState,
    pub connections: &'a [Connection],
}

/// Cross-cutting effects a component can request from the main
/// loop. Anything the component can't or shouldn't apply directly
/// (data refresh flag, clipboard write, quit) gets enumerated here
/// so `apply_effects` is the single place that touches the loop.
#[derive(Debug, Clone)]
pub enum Effect {
    /// Connection data needs to be re-pulled from the snapshot
    /// provider before the next render.
    RefreshData,
    /// Grouped rows need to be rebuilt from the existing connection
    /// list (cheaper than full RefreshData when only expand/collapse
    /// changed).
    Regroup,
    /// Copy `value` to the system clipboard. `label` is the
    /// human-readable name shown in the status-bar banner.
    Copy { label: String, value: String },
    // Quit will land when the global keys (q, Ctrl+C) migrate into a
    // shared handler; for now main.rs breaks the loop directly.
}

/// Implemented by every tab. `draw` must be cheap (called every
/// render tick). `handle_key` translates raw keystrokes into
/// `Effect`s; UIState mutations happen in-place through the
/// handler context.
pub trait Component {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &DrawContext<'_>,
        click_regions: &mut ClickableRegions,
    ) -> Result<()>;

    fn handle_key(&mut self, _key: KeyEvent, _ctx: &mut HandlerContext<'_>) -> Vec<Effect> {
        Vec::new()
    }
}
