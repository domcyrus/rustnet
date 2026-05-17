//! Shared input actions that mutate `UIState` and trigger side
//! effects on `App`. These live here (not on `UIState` directly)
//! because they touch both. Used by `OverviewTab::handle_key` for
//! the Overview-active case and by main.rs's fallback match for
//! the cross-tab case — keeping a single source of truth so both
//! callers stay in lockstep when the action's semantics evolve.

use std::time::Instant;

use log::info;

use crate::app::App;
use crate::ui::UIState;

/// Handle the 'x' (clear all connections) key with two-press
/// confirmation. First press flips `clear_confirmation` on; the
/// second press (while it's on) actually clears.
///
/// Returns `true` when the clear happened — caller should treat
/// this as a data-refresh signal.
pub fn clear_all_with_confirmation(ui_state: &mut UIState, app: &App) -> bool {
    if ui_state.clear_confirmation {
        info!("User confirmed clear all connections");
        app.clear_all_connections();
        ui_state.clear_confirmation = false;
        ui_state.show_historic = false;
        ui_state.selected_connection_key = None;
        ui_state.clipboard_message = Some(("All connections cleared".to_string(), Instant::now()));
        true
    } else {
        info!("User requested clear - showing confirmation");
        ui_state.clear_confirmation = true;
        false
    }
}
