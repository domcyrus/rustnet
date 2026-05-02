# vhs tape for the rustnet showcase demo.
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
# Storyboard (~30s, 7 beats):
#   1. Land on Overview, let traffic populate the table and sparkline.
#   2. Walk three rows so the right-side panels update (continuity).
#   3. Filter mode: /, type "443", briefly settle, Esc to clear.
#   4. Process grouping: a, Down, Space to expand a node, a to flatten.
#   5. Enter zooms into Details on the selected connection.
#   6. Esc back to Overview, Tab x3 to land on Graph.
#   7. Esc back to Overview to close the loop.
#
# Sized for the ratatui showcase: 1200x720 fits the 800-1200px guidance and
# stays readable on phone-width viewports.

Output assets/rustnet.gif

Set Theme "Catppuccin Mocha"
Set FontSize 14
Set Width 1200
Set Height 720
Set Padding 20
Set TypingSpeed 50ms
Set Framerate 24
Set PlaybackSpeed 1.0

Hide
Type "clear"
Enter
Type "sudo -A target/release/rustnet"
Enter
Sleep 2500ms
Show

Sleep 3s

Down
Sleep 1s
Down
Sleep 1s
Down
Sleep 1500ms

Type "/"
Sleep 400ms
Type "443"
Sleep 1500ms
Escape
Sleep 800ms

Type "a"
Sleep 1500ms
Down
Sleep 600ms
Space
Sleep 1500ms
Type "a"
Sleep 800ms

Enter
Sleep 3s

Escape
Sleep 600ms

Tab@400ms 3
Sleep 3s

Escape
Sleep 1500ms

Hide
Type "q"
Sleep 200ms
Type "q"
