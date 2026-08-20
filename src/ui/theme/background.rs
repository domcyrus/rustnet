//! Terminal background lightness detection (OSC 11).
//!
//! Asks the terminal for its background color with the xterm `OSC 11 ; ?`
//! query before the TUI takes over, so ANSI presets can darken their gray
//! text tiers on light backgrounds (ANSI Gray, color 7, is nearly
//! invisible on white). Best effort by design: no controlling tty, a
//! terminal that stays silent past the timeout, or a non-Unix platform all
//! yield `None` and the theme stays exactly as authored. Deliberately
//! hand-rolled for the simple case only; multiplexer passthrough and other
//! quirks are out of scope.

#[cfg(unix)]
mod unix {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::io::AsRawFd;
    use std::time::{Duration, Instant};

    /// OSC 11 query, ST-terminated. Terminals reply with the same framing:
    /// `ESC ] 11 ; rgb:RRRR/GGGG/BBBB` plus BEL or ST.
    const QUERY: &[u8] = b"\x1b]11;?\x1b\\";

    /// Total budget for the reply. Supporting terminals answer within a few
    /// milliseconds; this bounds the startup cost on ones that never do.
    const TIMEOUT: Duration = Duration::from_millis(150);

    /// Whether the terminal reports a light background, `None` when it
    /// cannot be determined (no tty, no reply, unparseable reply).
    pub fn detect_light_background() -> Option<bool> {
        let mut tty = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let fd = tty.as_raw_fd();
        let saved = enter_quiet_read(fd)?;
        let rgb = query_background(&mut tty, fd);
        // Best effort: the settings were valid a moment ago.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        rgb.map(super::is_light)
    }

    /// Disable canonical mode and echo on `fd` so the reply can be read
    /// byte-by-byte without echoing to the screen. Returns the original
    /// settings for the caller to restore.
    fn enter_quiet_read(fd: i32) -> Option<libc::termios> {
        // SAFETY: termios is plain old data and tcgetattr fills it in
        // fully on success.
        let mut termios = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return None;
        }
        let saved = termios;
        termios.c_lflag &= !(libc::ICANON | libc::ECHO);
        termios.c_cc[libc::VMIN] = 0;
        termios.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) } != 0 {
            return None;
        }
        Some(saved)
    }

    /// Write the query and wait for the reply until [`TIMEOUT`], tolerating
    /// unrelated bytes (early keypresses) around the OSC response.
    /// `select` rather than `poll`: macOS `poll` reports POLLNVAL for the
    /// `/dev/tty` character device.
    fn query_background(tty: &mut File, fd: i32) -> Option<(u8, u8, u8)> {
        tty.write_all(QUERY).ok()?;
        let deadline = Instant::now() + TIMEOUT;
        let mut buf = Vec::new();
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            // SAFETY: fd_set is plain old data; FD_ZERO/FD_SET initialize
            // it, and fd is a live descriptor below FD_SETSIZE.
            let ready = unsafe {
                let mut readfds = std::mem::zeroed::<libc::fd_set>();
                libc::FD_ZERO(&mut readfds);
                libc::FD_SET(fd, &mut readfds);
                let mut timeout = libc::timeval {
                    tv_sec: remaining.as_secs() as _,
                    tv_usec: remaining.subsec_micros() as _,
                };
                libc::select(
                    fd + 1,
                    &mut readfds,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &mut timeout,
                )
            };
            if ready <= 0 {
                return None; // timeout or select error
            }
            let mut chunk = [0u8; 256];
            let read = tty.read(&mut chunk).ok()?;
            if read == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..read]);
            if let Some(rgb) = super::parse_osc11_reply(&buf) {
                return Some(rgb);
            }
        }
    }
}

#[cfg(unix)]
pub use unix::detect_light_background;

/// Non-Unix stub: reading the reply needs termios-style tty control, which
/// the Windows console does not offer through this path.
#[cfg(not(unix))]
pub fn detect_light_background() -> Option<bool> {
    None
}

/// Whether `rgb` reads as a light background: WCAG relative luminance
/// above 0.5, the midpoint between black (0.0) and white (1.0).
#[cfg_attr(not(unix), allow(dead_code))]
fn is_light((r, g, b): (u8, u8, u8)) -> bool {
    super::derive::relative_luminance(r, g, b) > 0.5
}

/// Extract the background RGB from an OSC 11 reply anywhere in `buf`:
/// `ESC ] 11 ; <color>` terminated by BEL or ESC (the start of ST).
/// `None` while the reply is absent or still incomplete.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_osc11_reply(buf: &[u8]) -> Option<(u8, u8, u8)> {
    const PREFIX: &[u8] = b"\x1b]11;";
    let start = buf.windows(PREFIX.len()).position(|w| w == PREFIX)? + PREFIX.len();
    let payload = &buf[start..];
    let end = payload.iter().position(|&b| b == 0x07 || b == 0x1B)?;
    parse_x11_color(std::str::from_utf8(&payload[..end]).ok()?)
}

/// Parse an X11 `rgb:` color spec (xterm's reply format), scaling each
/// 1-4 hex digit channel to 8 bits. `rgba:` (KDE Konsole) is accepted
/// with its alpha channel ignored.
#[cfg_attr(not(unix), allow(dead_code))]
fn parse_x11_color(spec: &str) -> Option<(u8, u8, u8)> {
    let channels = spec
        .strip_prefix("rgb:")
        .or_else(|| spec.strip_prefix("rgba:"))?;
    let mut parts = channels.split('/');
    let mut channel = || {
        let digits = parts.next()?;
        if digits.is_empty() || digits.len() > 4 {
            return None;
        }
        let value = u32::from_str_radix(digits, 16).ok()?;
        let max = (1u32 << (4 * digits.len() as u32)) - 1;
        Some(((value * 255 + max / 2) / max) as u8)
    };
    Some((channel()?, channel()?, channel()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x11_color_scales_any_digit_width_to_8_bits() {
        assert_eq!(parse_x11_color("rgb:ffff/ffff/ffff"), Some((255, 255, 255)));
        assert_eq!(parse_x11_color("rgb:0000/0000/0000"), Some((0, 0, 0)));
        assert_eq!(parse_x11_color("rgb:8000/8000/8000"), Some((128, 128, 128)));
        assert_eq!(parse_x11_color("rgb:1a/1b/26"), Some((0x1A, 0x1B, 0x26)));
        assert_eq!(parse_x11_color("rgb:f/f/f"), Some((255, 255, 255)));
        // Konsole replies rgba:; alpha is ignored.
        assert_eq!(
            parse_x11_color("rgba:ffff/0000/0000/ffff"),
            Some((255, 0, 0))
        );
    }

    #[test]
    fn x11_color_rejects_malformed_specs() {
        for spec in [
            "",
            "rgb:",
            "rgb:ff/ff",
            "rgb:ff//ff",
            "rgb:12345/0/0",
            "#ffffff",
        ] {
            assert_eq!(parse_x11_color(spec), None, "{spec:?}");
        }
    }

    #[test]
    fn osc11_reply_is_found_amid_other_bytes_and_either_terminator() {
        // BEL-terminated, with a stray keypress before the reply.
        assert_eq!(
            parse_osc11_reply(b"q\x1b]11;rgb:fdf6/f6e3/e3d0\x07"),
            Some((0xFD, 0xF6, 0xE3))
        );
        // ST-terminated.
        assert_eq!(
            parse_osc11_reply(b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
            Some((0, 0, 0))
        );
        // Incomplete reply: keep waiting.
        assert_eq!(parse_osc11_reply(b"\x1b]11;rgb:ffff/ff"), None);
        assert_eq!(parse_osc11_reply(b"nothing here"), None);
    }

    #[test]
    fn lightness_splits_common_backgrounds() {
        assert!(is_light((0xFF, 0xFF, 0xFF)));
        assert!(is_light((0xFD, 0xF6, 0xE3))); // solarized light
        assert!(!is_light((0x00, 0x00, 0x00)));
        assert!(!is_light((0x1A, 0x1B, 0x26))); // tokyo night
        assert!(!is_light((0x28, 0x28, 0x28))); // gruvbox dark
    }
}
