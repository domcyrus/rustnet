//! Shared input actions that mutate `UIState` and trigger side
//! effects on `App`. These live here (not on `UIState` directly)
//! because they touch both. Used by `OverviewTab::handle_key` for
//! the Overview-active case and by main.rs's fallback match for
//! the cross-tab case — keeping a single source of truth so both
//! callers stay in lockstep when the action's semantics evolve.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use log::info;

use crate::app::App;
use crate::ui::{Effect, HandlerContext, PaneScroll, UIState};

/// Connection-list navigation + copy that's meaningful on both
/// Overview and Details. Navigation flips which connection has
/// focus (`selected_connection_key`); on Details that's also what
/// drives the displayed record, so keys like `j` / `k` let users
/// flip through connections without bouncing back to Overview.
/// Returns `None` for keys this helper doesn't claim so the caller
/// can fall through to its own match.
pub fn try_handle_connection_nav(
    key: KeyEvent,
    ctx: &mut HandlerContext<'_>,
) -> Option<Vec<Effect>> {
    match (key.code, key.modifiers) {
        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => {
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state.move_selection_up_grouped(rows);
            } else {
                ctx.ui_state.move_selection_up(ctx.connections);
            }
            Some(Vec::new())
        }
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => {
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state.move_selection_down_grouped(rows);
            } else {
                ctx.ui_state.move_selection_down(ctx.connections);
            }
            Some(Vec::new())
        }
        (KeyCode::PageUp, _) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
            let page_size = ctx.ui_state.visible_rows.max(1);
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state.move_selection_page_up_grouped(rows, page_size);
            } else {
                ctx.ui_state
                    .move_selection_page_up(ctx.connections, page_size);
            }
            Some(Vec::new())
        }
        (KeyCode::PageDown, _) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
            let page_size = ctx.ui_state.visible_rows.max(1);
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state
                    .move_selection_page_down_grouped(rows, page_size);
            } else {
                ctx.ui_state
                    .move_selection_page_down(ctx.connections, page_size);
            }
            Some(Vec::new())
        }
        (KeyCode::Char('g'), KeyModifiers::NONE) => {
            ctx.ui_state.move_selection_to_first(ctx.connections);
            Some(Vec::new())
        }
        (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) => {
            ctx.ui_state.move_selection_to_last(ctx.connections);
            Some(Vec::new())
        }
        // Copy selected connection's remote address — works wherever
        // there's a selection (Overview list focus or Details record).
        (KeyCode::Char('c'), KeyModifiers::NONE) => {
            if let Some(idx) = ctx.ui_state.get_selected_index(ctx.connections)
                && let Some(conn) = ctx.connections.get(idx)
            {
                let addr = conn.remote_addr.to_string();
                Some(vec![Effect::Copy {
                    label: addr.clone(),
                    value: addr,
                }])
            } else {
                Some(Vec::new())
            }
        }
        _ => None,
    }
}

/// Shared key handling for read-only scrollable panes (Help and
/// Activity interface details): line, page, and top/bottom movement on the usual
/// vim-style keys. Claims only those keys; everything else falls
/// through to the caller's global handling.
pub fn try_handle_pane_scroll(
    key: KeyEvent,
    page_size: usize,
    scroll: &mut PaneScroll,
) -> Option<Vec<Effect>> {
    let page = page_size.max(1) as u16;
    match (key.code, key.modifiers) {
        (KeyCode::Up, _) | (KeyCode::Char('k'), _) => scroll.scroll_up(1),
        (KeyCode::Down, _) | (KeyCode::Char('j'), _) => scroll.scroll_down(1),
        (KeyCode::PageUp, _) | (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
            scroll.scroll_up(page)
        }
        (KeyCode::PageDown, _) | (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
            scroll.scroll_down(page)
        }
        (KeyCode::Char('g'), KeyModifiers::NONE) | (KeyCode::Home, _) => scroll.scroll_to_top(),
        (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) | (KeyCode::End, _) => {
            scroll.scroll_to_bottom()
        }
        _ => return None,
    }
    Some(Vec::new())
}

/// Shared wheel handling for scrollable panes (Details info panes,
/// Help, and Activity interface details).
pub fn try_handle_pane_wheel(mouse: MouseEvent, scroll: &mut PaneScroll) -> Option<Vec<Effect>> {
    match mouse.kind {
        MouseEventKind::ScrollUp => scroll.scroll_up(1),
        MouseEventKind::ScrollDown => scroll.scroll_down(1),
        _ => return None,
    }
    Some(Vec::new())
}

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
        ui_state.set_connection_key(None);
        ui_state.clipboard_message = Some(("All connections cleared".to_string(), Instant::now()));
        true
    } else {
        info!("User requested clear - showing confirmation");
        ui_state.clear_confirmation = true;
        false
    }
}
