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
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state.move_selection_to_first_grouped(rows);
            } else {
                ctx.ui_state.move_selection_to_first(ctx.connections);
            }
            Some(Vec::new())
        }
        (KeyCode::Char('G'), _) | (KeyCode::Char('g'), KeyModifiers::SHIFT) => {
            if ctx.ui_state.grouping_enabled
                && let Some(rows) = ctx.grouped_rows
            {
                ctx.ui_state.move_selection_to_last_grouped(rows);
            } else {
                ctx.ui_state.move_selection_to_last(ctx.connections);
            }
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::{
        app::Config,
        network::types::{Connection, Protocol, ProtocolState, TcpState},
        ui::{ClickableRegions, GroupedRow, compute_grouped_rows},
    };

    fn test_connection(port: u16, process: &str) -> Connection {
        let mut connection = Connection::new(
            Protocol::Tcp,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443),
            ProtocolState::Tcp(TcpState::Established),
        );
        connection.process_name = Some(process.to_string());
        connection
    }

    #[test]
    fn grouped_boundary_navigation_uses_visible_rows() {
        let app = App::new(Config {
            resolve_dns: false,
            disable_geoip: true,
            ..Config::default()
        })
        .expect("create app");
        let connections = vec![
            test_connection(1000, "beta"),
            test_connection(1001, "alpha"),
            test_connection(1002, "beta"),
            test_connection(1003, "alpha"),
        ];
        let mut ui_state = UIState {
            grouping_enabled: true,
            expanded_groups: ["alpha".to_string(), "beta".to_string()]
                .into_iter()
                .collect(),
            ..UIState::default()
        };
        let grouped_rows = compute_grouped_rows(&connections, &ui_state.expanded_groups);
        let click_regions = ClickableRegions::default();
        ui_state.set_selected_grouped_by_index(&grouped_rows, 1);
        let mut ctx = HandlerContext {
            app: &app,
            ui_state: &mut ui_state,
            connections: &connections,
            grouped_rows: Some(&grouped_rows),
            click_regions: &click_regions,
        };

        let effects = try_handle_connection_nav(
            KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE),
            &mut ctx,
        );
        assert!(matches!(effects, Some(effects) if effects.is_empty()));
        assert_eq!(
            ctx.ui_state.get_selected_grouped_index(&grouped_rows),
            Some(0)
        );
        assert!(matches!(grouped_rows[0], GroupedRow::Group { .. }));

        ctx.ui_state.set_selected_grouped_by_index(&grouped_rows, 1);
        let effects = try_handle_connection_nav(
            KeyEvent::new(KeyCode::Char('G'), KeyModifiers::SHIFT),
            &mut ctx,
        );
        assert!(matches!(effects, Some(effects) if effects.is_empty()));
        assert_eq!(
            ctx.ui_state.get_selected_grouped_index(&grouped_rows),
            Some(grouped_rows.len() - 1)
        );
        assert!(matches!(
            grouped_rows.last(),
            Some(GroupedRow::Connection { .. })
        ));
    }
}
