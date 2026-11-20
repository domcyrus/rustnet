//! Optional draft cell-border protocol support without a Ratatui fork.
//!
//! Widgets collect cell-edge rectangles alongside the ordinary Ratatui buffer.
//! After the text diff, clear the previous rectangles and repaint the current
//! ones: printing a changed character resets its borders, even when the border
//! geometry did not change. No pen state is used or left behind. The ordinary
//! layout remains the fallback, and unsupported terminals receive no drawing
//! commands. See https://www.joshka.net/cell-borders/.

use std::cell::RefCell;
use std::io::{self, Write};

use ratatui::{layout::Rect, style::Color};

use super::theme;

pub(super) const TOP: u16 = 3;
pub(super) const RIGHT: u16 = 12;
pub(super) const BOTTOM: u16 = 48;
pub(super) const LEFT: u16 = 192;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Capabilities {
    supported: bool,
    style: bool,
    priority: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Edge {
    area: Rect,
    mask: u16,
    color: Color,
    priority: u8,
    dashed: bool,
}

#[derive(Default)]
struct Borders {
    capabilities: Capabilities,
    viewport: Rect,
    previous_viewport: Rect,
    edges: Vec<Edge>,
    previous: Vec<Edge>,
}

thread_local! {
    // UI drawing and output run on the same thread. Thread-local state also
    // keeps capability-specific rendering tests independent of other tests.
    static BORDERS: RefCell<Borders> = RefCell::new(Borders::default());
}

/// Opt in to probing the draft protocol before the event loop starts. Never
/// infer support from TERM or tunnel commands through tmux/screen.
pub(crate) fn configure(requested: bool) {
    let capabilities = if requested {
        probe()
    } else {
        Capabilities::default()
    };
    BORDERS.with(|state| {
        *state.borrow_mut() = Borders {
            capabilities,
            ..Borders::default()
        }
    });
    if requested {
        log::info!(
            "Experimental cell borders: {}",
            if capabilities.supported {
                "supported"
            } else {
                "using standard layout"
            }
        );
    }
}

pub(super) fn enabled() -> bool {
    BORDERS.with(|state| state.borrow().capabilities.supported)
}

pub(super) fn begin_frame(viewport: Rect) {
    BORDERS.with(|state| {
        let mut state = state.borrow_mut();
        state.viewport = viewport;
        state.edges.clear();
    });
}

pub(super) fn edge(area: Rect, mask: u16, color: Color, priority: u8, dashed: bool) {
    BORDERS.with(|state| {
        let mut state = state.borrow_mut();
        if !state.capabilities.supported {
            return;
        }
        let area = area.intersection(state.viewport);
        if !area.is_empty() {
            state.edges.push(Edge {
                area,
                mask,
                color,
                priority,
                dashed,
            });
        }
    });
}

pub(super) fn outline(area: Rect, color: Color, priority: u8) {
    if area.is_empty() {
        return;
    }
    edge(
        Rect::new(area.x, area.y, area.width, 1),
        TOP,
        color,
        priority,
        false,
    );
    edge(
        Rect::new(area.x, area.bottom() - 1, area.width, 1),
        BOTTOM,
        color,
        priority,
        false,
    );
    edge(
        Rect::new(area.x, area.y, 1, area.height),
        LEFT,
        color,
        priority,
        false,
    );
    edge(
        Rect::new(area.right() - 1, area.y, 1, area.height),
        RIGHT,
        color,
        priority,
        false,
    );
}

/// Opaque popups replace both text and decorations. Split intersecting strips
/// so background borders remain visible only outside the popup's rectangle.
pub(super) fn occlude(area: Rect) {
    BORDERS.with(|state| {
        let mut state = state.borrow_mut();
        let mut visible = Vec::new();
        for edge in state.edges.drain(..) {
            let hit = edge.area.intersection(area);
            if hit.is_empty() {
                visible.push(edge);
                continue;
            }
            let rect = edge.area;
            for part in [
                Rect::new(rect.x, rect.y, rect.width, hit.y - rect.y),
                Rect::new(
                    rect.x,
                    hit.bottom(),
                    rect.width,
                    rect.bottom() - hit.bottom(),
                ),
                Rect::new(rect.x, hit.y, hit.x - rect.x, hit.height),
                Rect::new(hit.right(), hit.y, rect.right() - hit.right(), hit.height),
            ] {
                if !part.is_empty() {
                    visible.push(Edge {
                        area: part,
                        ..edge.clone()
                    });
                }
            }
        }
        state.edges = visible;
    });
}

fn protocol_color(color: Color) -> String {
    match theme::fg(color).fg.unwrap_or(Color::Reset) {
        Color::Reset => "fg".into(),
        Color::Rgb(r, g, b) => format!("{r:02x}{g:02x}{b:02x}"),
        Color::Indexed(index) => format!("p{index}"),
        color => {
            let index = match color {
                Color::Black => 0,
                Color::Red => 1,
                Color::Green => 2,
                Color::Yellow => 3,
                Color::Blue => 4,
                Color::Magenta => 5,
                Color::Cyan => 6,
                Color::Gray => 7,
                Color::DarkGray => 8,
                Color::LightRed => 9,
                Color::LightGreen => 10,
                Color::LightYellow => 11,
                Color::LightBlue => 12,
                Color::LightMagenta => 13,
                Color::LightCyan => 14,
                _ => 15,
            };
            format!("p{index}")
        }
    }
}

fn move_to(out: &mut impl Write, area: Rect) -> io::Result<()> {
    write!(
        out,
        "\x1b[{};{}H",
        u32::from(area.y) + 1,
        u32::from(area.x) + 1
    )
}

fn clear(out: &mut impl Write, area: Rect) -> io::Result<()> {
    if !area.is_empty() {
        move_to(out, area)?;
        write!(
            out,
            "\x1bP1+bcell-border;clear;4095;{};{}\x1b\\",
            area.height, area.width
        )?;
    }
    Ok(())
}

impl Borders {
    fn paint(&mut self, out: &mut impl Write) -> io::Result<()> {
        if !self.capabilities.supported {
            return Ok(());
        }
        // Restore the cursor after rectangle positioning. This also preserves
        // the text renderer's rendition state; rectangle commands don't set it.
        out.write_all(b"\x1b7")?;
        if self.viewport != self.previous_viewport {
            // Resizing can reflow old borders to different coordinates.
            clear(out, self.viewport)?;
        } else {
            for edge in &self.previous {
                clear(out, edge.area.intersection(self.viewport))?;
            }
        }
        for edge in &self.edges {
            move_to(out, edge.area)?;
            write!(
                out,
                "\x1bP1+bcell-border;set;{};{};{};1;0;{};{}",
                edge.mask,
                16 + u16::from(edge.priority) * 16,
                protocol_color(edge.color),
                edge.area.height,
                edge.area.width
            )?;
            if edge.dashed && self.capabilities.style {
                out.write_all(b";style=dashed")?;
            }
            if edge.priority > 0 && self.capabilities.priority {
                write!(out, ";priority={}", edge.priority)?;
            }
            out.write_all(b"\x1b\\")?;
        }
        out.write_all(b"\x1b8")?;
        out.flush()?;
        self.previous.clone_from(&self.edges);
        self.previous_viewport = self.viewport;
        Ok(())
    }
}

/// Run after Ratatui's text diff, even when that diff is empty.
pub(crate) fn paint(out: &mut impl Write) -> io::Result<()> {
    BORDERS.with(|state| state.borrow_mut().paint(out))
}

#[cfg(any(unix, test))]
fn parse_reply(bytes: &[u8]) -> Option<Capabilities> {
    // DA1 is the fence: only replies before it can enable the extension.
    let da = bytes.windows(3).position(|w| w == b"\x1b[?")?;
    let end = bytes[da + 3..].iter().position(|b| *b == b'c')? + da + 3;
    if !bytes[da + 3..end]
        .iter()
        .all(|b| b.is_ascii_digit() || *b == b';')
    {
        return Some(Capabilities::default());
    }
    let prefix = b"\x1bP1+bcell-border;ok;1;";
    let before = &bytes[..da];
    let Some(start) = before.windows(prefix.len()).position(|w| w == prefix) else {
        return Some(Capabilities::default());
    };
    let payload = &before[start + prefix.len()..];
    let Some(end) = payload.windows(2).position(|w| w == b"\x1b\\") else {
        return Some(Capabilities::default());
    };
    if end > 256 {
        return Some(Capabilities::default());
    }
    let features: Vec<_> = payload[..end].split(|b| *b == b',').collect();
    let has = |name: &[u8]| features.contains(&name);
    Some(Capabilities {
        supported: [b"pen".as_slice(), b"rect", b"half", b"center", b"palette"]
            .into_iter()
            .all(has),
        style: has(b"style"),
        priority: has(b"priority"),
    })
}

#[cfg(unix)]
fn probe() -> Capabilities {
    use std::io::IsTerminal;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Capabilities::default();
    }
    std::fs::File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
        .and_then(|mut tty| probe_tty(&mut tty, std::time::Duration::from_millis(150)))
        .unwrap_or_default()
}

#[cfg(unix)]
fn probe_tty(tty: &mut std::fs::File, timeout: std::time::Duration) -> Option<Capabilities> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::Instant;

    let fd = tty.as_raw_fd();
    if fd < 0 || fd as usize >= libc::FD_SETSIZE {
        return None;
    }
    // SAFETY: tcgetattr initializes this POD structure on success.
    let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
    if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
        return None;
    }
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: the tty is still open and these settings came from it.
            unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
        }
    }
    let mut quiet = saved;
    quiet.c_lflag &= !(libc::ICANON | libc::ECHO);
    quiet.c_cc[libc::VMIN] = 0;
    quiet.c_cc[libc::VTIME] = 0;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) } != 0 {
        return None;
    }
    let _restore = Restore(fd, saved);
    tty.write_all(b"\x1bP1+bcell-border;q\x1b\\\x1b[c").ok()?;
    tty.flush().ok()?;
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    while bytes.len() < 1024 {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        // select works on /dev/tty on macOS as well as Linux. fd was
        // checked against FD_SETSIZE; every pointer is live for the call.
        let ready = unsafe {
            let mut fds = std::mem::zeroed::<libc::fd_set>();
            libc::FD_ZERO(&mut fds);
            libc::FD_SET(fd, &mut fds);
            let mut timeout = libc::timeval {
                tv_sec: remaining.as_secs() as _,
                tv_usec: remaining.subsec_micros() as _,
            };
            libc::select(
                fd + 1,
                &mut fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut timeout,
            )
        };
        if ready < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if ready <= 0 {
            return None;
        }
        // Stop exactly at the DA1 terminator, leaving later keyboard input
        // queued for Crossterm. Never flush the terminal's input queue.
        let mut byte = [0];
        if tty.read(&mut byte).ok()? != 1 {
            return None;
        }
        bytes.push(byte[0]);
        if let Some(reply) = parse_reply(&bytes) {
            return Some(reply);
        }
    }
    None
}

#[cfg(not(unix))]
fn probe() -> Capabilities {
    Capabilities::default()
}

#[cfg(test)]
pub(super) fn with_support<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(Borders);
    impl Drop for Restore {
        fn drop(&mut self) {
            BORDERS.with(|s| *s.borrow_mut() = std::mem::take(&mut self.0));
        }
    }
    let previous = BORDERS.with(|s| {
        std::mem::replace(
            &mut *s.borrow_mut(),
            Borders {
                capabilities: Capabilities {
                    supported: true,
                    style: true,
                    priority: true,
                },
                ..Borders::default()
            },
        )
    });
    let _restore = Restore(previous);
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn tty_probe_consumes_replies_restores_modes_and_leaves_following_input() {
        use std::fs::File;
        use std::io::Read;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::time::Duration;

        for supported in [true, false] {
            let (mut master_fd, mut slave_fd) = (-1, -1);
            // SAFETY: openpty writes two owned fds; null optional arguments
            // request default settings and no name buffer.
            assert_eq!(
                unsafe {
                    libc::openpty(
                        &mut master_fd,
                        &mut slave_fd,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            // SAFETY: successful openpty transferred ownership of both fds.
            let mut master = unsafe { File::from_raw_fd(master_fd) };
            let mut slave = unsafe { File::from_raw_fd(slave_fd) };
            let fd = slave.as_raw_fd();
            let mut before = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(unsafe { libc::tcgetattr(fd, &mut before) }, 0);
            let (done, wait) = std::sync::mpsc::channel();
            let terminal = std::thread::spawn(move || {
                let expected = b"\x1bP1+bcell-border;q\x1b\\\x1b[c";
                let mut query = vec![0; expected.len()];
                master.read_exact(&mut query).unwrap();
                assert_eq!(query, expected);
                if supported {
                    for part in b"\x1bP1+bcell-border;ok;1;pen,rect,half,center,palette,style\x1b\\"
                        .chunks(3)
                    {
                        master.write_all(part).unwrap();
                    }
                }
                master.write_all(b"\x1b[?62;22cq\n").unwrap();
                // Keep the master alive until the reader has checked its queue.
                wait.recv_timeout(Duration::from_secs(2)).unwrap();
            });
            let result = probe_tty(&mut slave, Duration::from_millis(500)).unwrap();
            assert_eq!(result.supported, supported);
            let mut after = unsafe { std::mem::zeroed::<libc::termios>() };
            assert_eq!(unsafe { libc::tcgetattr(fd, &mut after) }, 0);
            assert_eq!(after.c_lflag, before.c_lflag);
            assert_eq!(after.c_cc, before.c_cc);
            // A regression should fail immediately, rather than block on input.
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) },
                -1
            );
            let mut pending = [0; 2];
            slave.read_exact(&mut pending).unwrap();
            assert_eq!(&pending, b"q\n");
            done.send(()).unwrap();
            terminal.join().unwrap();
        }
    }

    #[test]
    fn capability_reply_requires_complete_fence_and_core_features() {
        let cap =
            b"\x1bP1+bcell-border;ok;1;pen,rect,half,center,palette,style,priority,future\x1b\\";
        assert_eq!(parse_reply(cap), None);
        let mut reply = cap.to_vec();
        reply.extend_from_slice(b"\x1b[?62;22c");
        assert_eq!(
            parse_reply(&reply),
            Some(Capabilities {
                supported: true,
                style: true,
                priority: true
            })
        );
        for bytes in [
            b"\x1b[?1;2c".as_slice(),
            b"\x1bP1+bcell-border;ok;1;pen\x1b\\\x1b[?1c",
            b"\x1bP1+bcell-border;ok;2;rect\x1b\\\x1b[?1c",
        ] {
            assert!(!parse_reply(bytes).unwrap().supported);
        }
        let late = [b"\x1b[?1c".as_slice(), cap].concat();
        assert!(!parse_reply(&late).unwrap().supported);
    }

    #[test]
    fn repaint_clears_old_selection_and_reapplies_unchanged_edges() {
        with_support(|| {
            let viewport = Rect::new(0, 0, 80, 24);
            begin_frame(viewport);
            outline(Rect::new(1, 4, 20, 1), Color::Blue, 1);
            let mut first = Vec::new();
            paint(&mut first).unwrap();
            let first = String::from_utf8(first).unwrap();
            assert!(first.contains("clear;4095;24;80"));
            assert!(first.contains(";p4;1;0;1;20;priority=1"));
            let mut same = Vec::new();
            paint(&mut same).unwrap();
            assert_eq!(String::from_utf8(same).unwrap().matches(";set;").count(), 4);
            begin_frame(viewport);
            let mut empty = Vec::new();
            paint(&mut empty).unwrap();
            let empty = String::from_utf8(empty).unwrap();
            assert_eq!(empty.matches(";clear;").count(), 4);
            assert!(!empty.contains(";set;"));
        });
    }

    #[test]
    fn popup_masks_background_edges_and_resize_clips_geometry() {
        with_support(|| {
            begin_frame(Rect::new(0, 0, 20, 10));
            edge(Rect::new(0, 4, 80, 1), BOTTOM, Color::Reset, 0, false);
            occlude(Rect::new(5, 2, 10, 5));
            BORDERS.with(|s| {
                let s = s.borrow();
                assert_eq!(
                    s.edges.iter().map(|e| e.area).collect::<Vec<_>>(),
                    vec![Rect::new(0, 4, 5, 1), Rect::new(15, 4, 5, 1)]
                );
            });
            paint(&mut Vec::new()).unwrap();
            begin_frame(Rect::new(0, 0, 10, 5));
            let mut out = Vec::new();
            paint(&mut out).unwrap();
            assert!(String::from_utf8(out).unwrap().contains("clear;4095;5;10"));
        });
    }

    #[test]
    fn optional_extensions_are_only_emitted_when_advertised() {
        with_support(|| {
            BORDERS.with(|state| {
                let mut state = state.borrow_mut();
                state.capabilities.style = false;
                state.capabilities.priority = false;
            });
            begin_frame(Rect::new(0, 0, 80, 24));
            edge(Rect::new(1, 3, 20, 1), TOP, Color::Reset, 1, true);
            let mut out = Vec::new();
            paint(&mut out).unwrap();
            let out = String::from_utf8(out).unwrap();
            assert!(out.contains(";set;3;32;fg;1;0;1;20"));
            assert!(!out.contains("style="));
            assert!(!out.contains("priority="));
        });
    }

    #[test]
    fn unsupported_terminals_receive_no_border_output() {
        assert!(!enabled());
        begin_frame(Rect::new(0, 0, 80, 24));
        outline(Rect::new(0, 0, 80, 24), Color::Blue, 1);
        let mut out = Vec::new();
        paint(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
