# vhs tape for the rustnet demo GIF.
#
# Render with: scripts/record-rustnet-demo.sh
# (wraps `vhs demo.tape` with sudo pre-cache, background traffic,
#  and gifsicle optimization).
#
# Manual render: vhs demo.tape (writes assets/rustnet.gif).
# Pre-build the release binary first: cargo build --release
# Capture needs root: the tape runs `sudo -A`, which reads the password
# from the askpass helper pointed to by $SUDO_ASKPASS. The wrapper script
# above sets that automatically. For manual runs, export SUDO_ASKPASS
# yourself (or on Linux set CAP_NET_RAW on the binary and drop the
# `sudo -A` from the tape).
#
# Pacing principles (from the ratatui showcase review):
#   - never show the blank state: stay hidden until the table is populated
#   - fewer beats, longer dwell on each screen; short overall (~28s)
#   - larger text, less padding: FontSize 16 / Padding 10 — the responsive
#     column hiding keeps the table clean at the narrower cell count, and
#     the sidebar toggle beat shows columns flowing back in
#   - navigations should read as zooming/expanding, not screen replacement
#   - filtering is left to the README screenshots; the GIF shows fewer
#     things for longer
#
# Storyboard (~28s, 6 beats):
#   1. Reveal Overview with live traffic, let it breathe.
#   2. Walk two rows slowly.
#   3. Toggle the System sidebar off and on (i) — columns reflow to fill.
#   4. Group by process (a), expand the selected group (Space), walk into
#      its connections.
#   5. Enter zooms into Details: the continuity strip shows the grouped
#      neighbors; j flips through them without leaving the tab. Esc back.
#   6. Jump to Graph (4), dwell, then back to Overview (1).
#
# Sized for the README: 1600x900 at FontSize 16 yields ~164 terminal
# columns — enough for the near-full column set alongside the System
# sidebar (GitHub scales the GIF down to the README width; wide captures
# stay sharp on click-through/retina). Narrower canvases push the table
# to its degraded column floor, which hides most of the data.

Output assets/rustnet.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 900
Set Padding 10
Set TypingSpeed 50ms
Set Framerate 24
Set PlaybackSpeed 1.0

# Stay hidden until capture has warmed up so the reveal is a busy table,
# never the empty/loading state.
Hide
Type "clear"
Enter
Type "sudo -A target/release/rustnet"
Enter
Sleep 5s
Show

# 1. Overview with live traffic.
Sleep 3500ms

# 2. Walk two rows.
Down
Sleep 1s
Down
Sleep 1500ms

# 3. System sidebar toggle: the table reflows and extra columns appear.
Type "i"
Sleep 2500ms
Type "i"
Sleep 1500ms

# 4. Group by process and step into the expanded group.
Type "a"
Sleep 2s
Space
Sleep 1500ms
Down
Sleep 800ms
Down
Sleep 1s

# 5. Details: the strip at the top continues the grouped list; j flips
#    through the neighbors without leaving the tab.
Enter
Sleep 3500ms
Down
Sleep 1200ms
Down
Sleep 2s
Escape
Sleep 1500ms

# 6. Graph, then close the loop on Overview.
Type "4"
Sleep 3s
Type "1"
Sleep 2s

Hide
Type "q"
Sleep 200ms
Type "q"
