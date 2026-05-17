//! Effect application — the one place the main loop reaches into
//! `Effect`s produced by `Component::handle_key` / `handle_mouse`
//! and translates them into the loop's local state mutations
//! (`needs_data_refresh`, `needs_regroup`) plus side effects
//! (clipboard write).

use crate::app::App;
use crate::ui::{Effect, UIState, copy_to_clipboard};

/// Result of applying a batch of effects. The loop folds this into
/// its own bookkeeping (refresh flags).
#[derive(Default, Debug, Clone, Copy)]
pub struct EffectOutcome {
    pub needs_data_refresh: bool,
    pub needs_regroup: bool,
}

/// Apply a vector of effects and return what the caller needs to
/// know. Clipboard writes happen inline; UIState mutations for
/// the clipboard banner land through `copy_to_clipboard`.
pub fn apply_effects(effects: Vec<Effect>, ui_state: &mut UIState, app: &App) -> EffectOutcome {
    let mut out = EffectOutcome::default();
    for effect in effects {
        match effect {
            Effect::RefreshData => out.needs_data_refresh = true,
            Effect::Regroup => out.needs_regroup = true,
            Effect::Copy { label, value } => {
                copy_to_clipboard(&value, &label, ui_state, app);
            }
        }
    }
    out
}
