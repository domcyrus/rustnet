//! Per-tab Component pattern adapted for rustnet's synchronous,
//! crossbeam-threaded UI loop.
//!
//! Differences from ratatui's official component template:
//! - No `tokio::sync::mpsc::UnboundedSender<Action>` — the loop is
//!   synchronous; once event handling moves into components they'll
//!   return `Vec<Effect>` instead of pushing through a channel.
//! - No `register_action_handler` / `register_config_handler` /
//!   `init` — shared state (`App`, `UIState`) is passed through
//!   context structs on each call.
//!
//! This first cut only defines `draw`. `handle_key`/`handle_mouse`
//! and the `Effect` enum will be added alongside the main-loop
//! refactor that gives them a consumer; without one, the warnings
//! would be unavoidable without `#[allow(dead_code)]`.

use anyhow::Result;
use ratatui::{Frame, layout::Rect};

use crate::app::App;
use crate::ui::ClickableRegions;

/// Read-only bundle passed to every component's `draw`. Lifetime
/// matches the borrow scope inside the main loop's `terminal.draw`
/// closure.
///
/// New fields land as more tabs are converted to Components —
/// `ui_state`, `connections`, `grouped_rows`, and `stats` will join
/// when their first Component consumer arrives, to avoid `dead_code`
/// warnings on unused fields.
pub struct DrawContext<'a> {
    pub app: &'a App,
}

/// Implemented by every tab. `draw` must be cheap (called every
/// render tick). Event handlers will be added when the main-loop
/// refactor gives them a consumer.
pub trait Component {
    fn draw(
        &mut self,
        f: &mut Frame,
        area: Rect,
        ctx: &DrawContext<'_>,
        click_regions: &mut ClickableRegions,
    ) -> Result<()>;
}
