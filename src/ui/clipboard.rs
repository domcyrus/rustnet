//! Cross-platform clipboard helper that updates `UIState` with
//! user-visible feedback. Tries `arboard` first; on Linux/FreeBSD
//! falls back to `wl-copy` for Wayland environments where arboard
//! can't reach the clipboard daemon. Sandbox-aware on Linux —
//! reports a more useful error when Landlock has blocked the path.

use std::time::Instant;

use arboard::Clipboard;
use log::{error, info};

use crate::app::App;
use crate::ui::UIState;

/// Copy `text` to the system clipboard. On success, sets a
/// "Copied: …" banner in the status bar; on failure, sets an error
/// banner instead. `display_msg` is what's shown to the user
/// (typically "label: value"), while `text` is the literal payload.
pub fn copy_to_clipboard(text: &str, display_msg: &str, ui_state: &mut UIState, app: &App) {
    // Used conditionally on Linux/FreeBSD for sandbox-aware error messages
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
            let msg = if app.get_sandbox_info().fs_restricted {
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
