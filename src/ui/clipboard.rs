//! Cross-platform clipboard helper that updates `UiState` with
//! user-visible feedback. Tries `arboard` first; on Linux/FreeBSD
//! falls back to `wl-copy` for Wayland environments where arboard
//! can't reach the clipboard daemon. Sandbox-aware on Linux:
//! reports a more useful error when Landlock has blocked the path.

use std::time::Instant;

use arboard::Clipboard;
use log::{error, info};

use crate::app::App;
use crate::ui::UiState;

/// Whether the system clipboard can be reached at all. Landlock's
/// filesystem and IPC-scope restrictions both sever the path to the display
/// server's clipboard, so under the default Linux sandbox no copy can
/// succeed and the UI stops offering one.
pub fn clipboard_available(app: &App) -> bool {
    #[cfg(target_os = "linux")]
    {
        let sandbox = app.get_sandbox_info();
        !(sandbox.fs_restricted || sandbox.scope_restricted)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = app;
        true
    }
}

/// Copy `text` to the system clipboard. On success, sets a
/// "Copied: …" banner in the status bar; on failure, sets an error
/// banner instead. `display_msg` is what's shown to the user
/// (typically "label: value"), while `text` is the literal payload.
pub fn copy_to_clipboard(text: &str, display_msg: &str, ui_state: &mut UiState, app: &App) {
    // Only the Linux/FreeBSD error path reads `app`.
    let _ = app;
    let result = Clipboard::new().and_then(|mut cb| cb.set_text(text));

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let result = result.or_else(|_| {
        std::process::Command::new("wl-copy")
            .arg(text)
            .status()
            .map_err(|e| arboard::Error::Unknown {
                description: e.to_string(),
            })
            .and_then(|s| {
                if s.success() {
                    Ok(())
                } else {
                    Err(arboard::Error::Unknown {
                        description: "wl-copy failed".to_string(),
                    })
                }
            })
    });

    match result {
        Ok(()) => {
            info!("Copied to clipboard: {}", display_msg);
            ui_state.clipboard_message = Some((format!("Copied: {}", display_msg), Instant::now()));
        }
        Err(e) => {
            #[cfg(target_os = "linux")]
            let msg = if !clipboard_available(app) {
                "Clipboard unavailable (sandbox active). Use --no-sandbox to enable.".to_string()
            } else {
                format!("Clipboard error: {}", e)
            };
            #[cfg(not(target_os = "linux"))]
            let msg = format!("Clipboard error: {}", e);

            error!("{}", msg);
            ui_state.clipboard_message = Some((msg, Instant::now()));
        }
    }
}
