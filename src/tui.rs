//! Terminal front-end: color theme selection, terminal lifecycle, and the
//! draw/input loop.

use anyhow::Result;
use clap::ArgMatches;
use log::{error, info};
use ratatui::prelude::{Backend, CrosstermBackend};
use std::io;
use std::time::Duration;

use crate::app::App;
use crate::bootstrap::{self, Frontend, shutdown_requested};
use crate::config;
use crate::network::types::Connection;
use crate::ui::{self, clear_all_with_confirmation, copy_to_clipboard, sort_connections};

/// Drive the terminal front-end to completion. Startup and teardown
/// failures propagate; a failure inside the draw/input loop is reported
/// after the terminal has been restored so the message lands on a usable
/// screen, and the process still exits normally.
pub fn run(matches: &ArgMatches) -> Result<()> {
    let prepared = bootstrap::prepare(matches, Frontend::Tui)?;
    apply_theme(matches);

    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = ui::setup_terminal(backend)?;
    info!("Terminal UI initialized");

    let app = prepared.launch()?;
    let res = run_ui_loop(&mut terminal, &app);

    app.stop();
    ui::restore_terminal(&mut terminal)?;

    if let Err(err) = res {
        error!("Application error: {}", err);
        println!("Error: {}", err);
    }
    Ok(())
}

/// Resolve the color theme and install it. Runs before the terminal
/// enters raw mode and the alternate screen, so the warnings print to a
/// normal terminal.
fn apply_theme(matches: &ArgMatches) {
    // Check NO_COLOR environment variable and --no-color flag (https://no-color.org)
    let no_color =
        matches.get_flag("no-color") || std::env::var("NO_COLOR").is_ok_and(|v| !v.is_empty());
    if no_color {
        info!("Colors disabled (NO_COLOR)");
        ui::set_no_color(true);
    }

    // Color theme: CLI --theme > config file > muted default. Warnings go to
    // stderr here, before the terminal enters raw mode.
    let user_config = config::load();
    let theme_name = matches
        .get_one::<String>("theme")
        .map(String::as_str)
        .or(user_config.theme.as_deref())
        .unwrap_or("muted");
    let preset = ui::ThemePreset::from_name(theme_name).unwrap_or_else(|| {
        // Only reachable via the config file; clap validates the CLI value.
        eprintln!("rustnet: unknown theme {theme_name:?} in config, using \"muted\"");
        ui::ThemePreset::Muted
    });
    let mut spec = ui::ThemeSpec::builtin(preset);
    for (token, value) in &user_config.overrides {
        if let Err(e) = spec.set_token(token, value) {
            eprintln!("rustnet: ignoring theme override {token:?}: {e}");
        }
    }
    info!("Using {preset:?} color theme");
    // ANSI Gray (the muted/label text tier) is nearly unreadable on light
    // backgrounds, so ask the terminal for its background (OSC 11) and
    // darken those tiers when it reports a light one. Skipped under
    // NO_COLOR, where no colors are emitted at all.
    if !no_color && ui::detect_light_background() == Some(true) {
        info!("Light terminal background detected; darkening gray text tiers");
        spec.adapt_to_light_background();
    }
    ui::set_theme(ui::Theme::resolve(&spec, ui::detect_truecolor()));
}

fn run_ui_loop<B: Backend>(terminal: &mut ui::Terminal<B>, app: &App) -> Result<()>
where
    <B as Backend>::Error: Send + Sync + 'static,
{
    let tick_rate = Duration::from_millis(200);
    // Idle redraw ceiling. Terminal emulators repaint whenever output
    // arrives (iTerm2's renderer repaints the window on any content
    // change), so the draw cadence directly sets the terminal's CPU
    // cost. Input and data changes redraw immediately; graph animation
    // and the live sidebar counters advance at this heartbeat.
    let redraw_interval = Duration::from_millis(500);
    // Full-size traffic waves scroll between 500ms samples in smaller
    // increments. The one-row Overview waves keep the lower idle repaint rate
    // because their four-dot vertical resolution makes faster motion flicker.
    let wave_redraw_interval = Duration::from_millis(200);
    let mut last_tick = std::time::Instant::now();
    let mut last_draw = std::time::Instant::now();
    let mut needs_redraw = true; // first frame
    let mut ui_state = ui::UiState::default();
    let (has_country_db, _, _) = app.get_geoip_status();
    ui_state.has_geoip = has_country_db;
    let mut click_regions = ui::ClickableRegions::default();

    // Data state persists across loop iterations; only refreshed on timer tick
    // or when an event changes the underlying data (filter, sort, historic toggle, etc.)
    let mut connections: Vec<Connection> = Vec::new();
    let mut grouped_rows: Vec<ui::GroupedRow<'_>> = Vec::new();
    let mut stats = app.get_stats();
    let mut needs_data_refresh = true;
    let mut needs_regroup = false;
    let mut last_seen_generation = u64::MAX; // force the first refresh

    'main: loop {
        if shutdown_requested() {
            info!("Termination signal received, shutting down");
            break 'main;
        }

        // Refresh connection data only when needed:
        // - On timer tick (every 200ms), but only if the snapshot actually
        //   changed since we last consumed it (it rebuilds every
        //   refresh-interval ms, so most ticks would re-clone and re-sort
        //   identical data)
        // - When an event changes filter, sort, or data source
        let tick_elapsed = last_tick.elapsed() >= tick_rate;
        let snapshot_generation = app.snapshot_generation();
        if tick_elapsed {
            // Keep counters (packets processed/dropped, etc.) live on every
            // tick even when the connection list is unchanged.
            stats = app.get_stats();
            last_tick = std::time::Instant::now();
        }
        if needs_data_refresh || (tick_elapsed && snapshot_generation != last_seen_generation) {
            connections = if !ui_state.has_active_filter() && !ui_state.filter_mode {
                app.get_connections()
            } else {
                app.get_filtered_connections(&ui_state.filter_query)
            };
            sort_connections(
                &mut connections,
                ui_state.sort_column,
                ui_state.sort_ascending,
            );
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            last_seen_generation = snapshot_generation;
            needs_data_refresh = false;
            needs_regroup = false;
            needs_redraw = true;
        } else if needs_regroup {
            // Only rebuild grouped rows from existing connections
            // (e.g., after expand/collapse or grouping toggle)
            grouped_rows = if ui_state.grouping_enabled {
                ui::compute_grouped_rows(&connections, &ui_state.expanded_groups)
            } else {
                Vec::new()
            };
            needs_regroup = false;
            needs_redraw = true;
        }

        // Ensure we have a valid selection (handles connection removals)
        if ui_state.grouping_enabled {
            let selected_idx = ui_state
                .ensure_valid_grouped_selection(&grouped_rows)
                .unwrap_or(0);
            ui_state.grouped_scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.grouped_scroll_offset,
                ui_state.visible_rows,
                grouped_rows.len(),
            );
        } else {
            let selected_idx = ui_state.ensure_valid_selection(&connections).unwrap_or(0);
            ui_state.scroll_offset = ui::compute_scroll_offset(
                selected_idx,
                ui_state.scroll_offset,
                ui_state.visible_rows,
                connections.len(),
            );
        }

        // Draw the UI, but only when something warrants it: immediately
        // after input or a data change, otherwise at the idle heartbeat.
        // The sidebar counters are live atomics read at render time, so
        // an unconditional draw here would emit fresh cells (and force a
        // terminal repaint) on every 200ms tick even with nothing going on.
        // The startup splash animates faster than the idle heartbeat, so
        // it gets a shorter redraw interval for its ~1s lifetime.
        let idle_redraw = if app.is_loading() {
            Duration::from_millis(100)
        } else if matches!(ui_state.selected_tab, 1 | 3) {
            wave_redraw_interval
        } else {
            redraw_interval
        };
        if needs_redraw || last_draw.elapsed() >= idle_redraw {
            terminal.draw(|f| {
                let grouped = if ui_state.grouping_enabled {
                    Some(grouped_rows.as_slice())
                } else {
                    None
                };
                if let Err(err) = ui::draw(
                    f,
                    app,
                    &ui_state,
                    &connections,
                    grouped,
                    &stats,
                    &mut click_regions,
                ) {
                    error!("UI draw error: {}", err);
                }
            })?;
            last_draw = std::time::Instant::now();
            needs_redraw = false;
        }

        // Update visible rows for page navigation based on terminal height.
        // Chrome rows: tab bar (2) + section title (1) + table header incl.
        // margin (2) + status bar (1) = 6, plus the filter line (1) while a
        // filter is being typed. This must track the layout in `ui::draw`
        // exactly: a confirmed filter keeps no row of its own, so counting
        // one here would scroll the selection a row early and hand the
        // scrollbar a viewport shorter than what is drawn.
        if let Ok(size) = terminal.size() {
            let chrome = if ui_state.filter_row_visible() { 7 } else { 6 };
            ui_state.visible_rows = (size.height as usize).saturating_sub(chrome);
        }

        // Sleep until the next data tick or redraw heartbeat, whichever
        // comes first, unless an event arrives earlier.
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::from_secs(0))
            .min(idle_redraw.saturating_sub(last_draw.elapsed()));

        if let Some((_, time)) = &ui_state.clipboard_message
            && time.elapsed().as_secs() >= 3
        {
            ui_state.clipboard_message = None;
            needs_redraw = true;
        }

        // Handle input events, draining any queued burst (mouse motion,
        // key auto-repeat) before the next iteration so a flood of
        // events costs one redraw instead of one redraw per event.
        let mut poll_timeout = timeout;
        'events: while crossterm::event::poll(poll_timeout)? {
            poll_timeout = Duration::ZERO;
            let event = crossterm::event::read()?;
            match event {
                crossterm::event::Event::Mouse(mouse) => {
                    use crossterm::event::{MouseButton, MouseEventKind};

                    // Active tab's Component gets first crack; currently
                    // only OverviewTab claims (scroll wheel inside the
                    // scroll area). Click events fall through to the
                    // global ClickableRegions dispatch below.
                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    if let Some(effects) =
                        ui::dispatch_mouse(hctx.ui_state.selected_tab, mouse, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        needs_redraw = true;
                        continue 'events;
                    }

                    if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                        {
                            needs_redraw = true;
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;

                            // Detect double-click (two clicks within 400ms at the same row)
                            let is_double_click =
                                if let Some((_, prev_row, prev_time)) = ui_state.last_click {
                                    prev_row == mouse.row && prev_time.elapsed().as_millis() < 400
                                } else {
                                    false
                                };
                            ui_state.last_click =
                                Some((mouse.column, mouse.row, std::time::Instant::now()));

                            if let Some(action) = click_regions.hit_test(mouse.column, mouse.row) {
                                match action.clone() {
                                    ui::ClickAction::SwitchTab(tab_idx) => {
                                        ui_state.selected_tab = tab_idx;
                                    }
                                    ui::ClickAction::SelectConnection(conn_idx) => {
                                        if ui_state.grouping_enabled {
                                            ui_state.set_selected_grouped_by_index(
                                                &grouped_rows,
                                                conn_idx,
                                            );
                                            if is_double_click
                                                && let Some(row) = grouped_rows.get(conn_idx)
                                            {
                                                match row {
                                                    ui::GroupedRow::Group { .. } => {
                                                        // Double-click group header: toggle expand/collapse
                                                        ui_state.toggle_group_expansion();
                                                        needs_regroup = true;
                                                    }
                                                    ui::GroupedRow::Connection { .. } => {
                                                        // Double-click connection: open Details tab
                                                        ui_state.selected_tab = 1;
                                                    }
                                                }
                                            }
                                        } else {
                                            ui_state.set_selected_by_index(&connections, conn_idx);
                                            if is_double_click {
                                                // Double-click connection in flat view: open Details tab
                                                ui_state.selected_tab = 1;
                                            }
                                        }
                                    }
                                    ui::ClickAction::SelectConnectionKey(key) => {
                                        // Keep the grouped selection coherent: adopt the
                                        // clicked connection's group when grouping is on.
                                        if ui_state.grouping_enabled {
                                            for row in &grouped_rows {
                                                if let ui::GroupedRow::Connection {
                                                    process_name,
                                                    connection,
                                                    ..
                                                } = row
                                                    && connection.key() == key
                                                {
                                                    ui_state.selected_group =
                                                        Some(process_name.clone());
                                                    break;
                                                }
                                            }
                                        }
                                        ui_state.set_connection_key(Some(key));
                                    }
                                    ui::ClickAction::CopyField { label, value } => {
                                        copy_to_clipboard(
                                            &value,
                                            &format!("{}: {}", label, value),
                                            &mut ui_state,
                                            app,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    // Scroll events are handled by OverviewTab::handle_mouse above.
                }
                crossterm::event::Event::Key(key) => {
                    use crossterm::event::{KeyCode, KeyEventKind, KeyModifiers};

                    // Windows crossterm reports Release events too; only
                    // Press is handled so all platforms behave the same.
                    if key.kind != KeyEventKind::Press {
                        continue 'events;
                    }
                    needs_redraw = true;

                    // Give the active tab's Component first crack
                    // at the key (including filter-mode input; OverviewTab
                    // owns that). If it claims (returns Some), the loop
                    // skips its fallback match. The per-key confirmation
                    // reset happens here for both branches so q / x can
                    // still set their own confirmations without the
                    // catch-all clobbering them.
                    match key.code {
                        KeyCode::Char('q') => ui_state.clear_confirmation = false,
                        KeyCode::Char('x') => ui_state.quit_confirmation = false,
                        _ => {
                            ui_state.quit_confirmation = false;
                            ui_state.clear_confirmation = false;
                        }
                    }

                    let grouped_opt = if ui_state.grouping_enabled {
                        Some(grouped_rows.as_slice())
                    } else {
                        None
                    };
                    let mut hctx = ui::HandlerContext {
                        app,
                        ui_state: &mut ui_state,
                        connections: &connections,
                        grouped_rows: grouped_opt,
                        click_regions: &click_regions,
                    };
                    let claimed = if let Some(effects) =
                        ui::dispatch_key(hctx.ui_state.selected_tab, key, &mut hctx)
                    {
                        let outcome = ui::apply_effects(effects, &mut ui_state, app);
                        if outcome.needs_data_refresh {
                            needs_data_refresh = true;
                        }
                        if outcome.needs_regroup {
                            needs_regroup = true;
                        }
                        true
                    } else {
                        false
                    };

                    if claimed {
                        // Component handled the key end-to-end.
                    } else {
                        // Normal-mode fallback: keys that weren't claimed
                        // by the active tab's Component. Global navigation
                        // and quit/help/interface-toggle live here, plus
                        // cross-tab fallbacks for x (clear) and Esc which
                        // would otherwise stop working on non-Overview
                        // tabs.
                        match (key.code, key.modifiers) {
                            (KeyCode::Char('q'), _) => {
                                if ui_state.quit_confirmation {
                                    info!("User confirmed application exit");
                                    break 'main;
                                } else {
                                    info!("User requested quit - showing confirmation");
                                    ui_state.quit_confirmation = true;
                                }
                            }

                            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                                info!("User requested immediate exit with Ctrl+C");
                                break 'main;
                            }

                            (KeyCode::Tab, KeyModifiers::NONE)
                            | (KeyCode::Char(']'), KeyModifiers::NONE) => {
                                ui_state.next_tab();
                            }

                            (KeyCode::BackTab, _)
                            | (KeyCode::Tab, KeyModifiers::SHIFT)
                            | (KeyCode::Char('['), KeyModifiers::NONE) => {
                                ui_state.prev_tab();
                            }

                            // Direct-jump shortcuts to each tab (mirrors the
                            // numeric-jump convention used by htop, tmux, etc.).
                            // Tab indices match `TAB_TITLES` in
                            // `ui::widgets::tabs_bar`: Overview, Details,
                            // Activity, Graph, Host.
                            (KeyCode::Char('1'), KeyModifiers::NONE) => ui_state.jump_to_tab(0),
                            (KeyCode::Char('2'), KeyModifiers::NONE) => ui_state.jump_to_tab(1),
                            (KeyCode::Char('3'), KeyModifiers::NONE) => ui_state.jump_to_tab(2),
                            (KeyCode::Char('4'), KeyModifiers::NONE) => ui_state.jump_to_tab(3),
                            (KeyCode::Char('5'), KeyModifiers::NONE) => ui_state.jump_to_tab(4),

                            // Help overlay, kept because `h` is the universal
                            // mnemonic for help across less / man / vim / tmux.
                            (KeyCode::Char('h'), _) => {
                                ui_state.show_help = true;
                                ui_state.help_scroll.reset();
                            }

                            // x and Esc keep cross-tab fallbacks here so
                            // clear / filter-clear / tab-back still work
                            // from Details / Activity / Graph / Host
                            // (OverviewTab only claims them on Overview).
                            (KeyCode::Char('x'), _)
                                if clear_all_with_confirmation(&mut ui_state, app) =>
                            {
                                needs_data_refresh = true;
                            }

                            (KeyCode::Esc, _) => {
                                if !ui_state.filter_query.is_empty() {
                                    ui_state.clear_filter();
                                    needs_data_refresh = true;
                                } else if ui_state.selected_tab != 0 {
                                    ui_state.selected_tab = 0;
                                }
                            }

                            _ => {}
                        }
                    }
                } // end Event::Key
                crossterm::event::Event::Resize(..) => {
                    needs_redraw = true;
                }
                _ => {} // ignore focus, paste, etc.
            } // end match event
        } // end event drain
    } // end loop

    Ok(())
}
