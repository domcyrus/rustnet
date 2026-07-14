# vhs tape for the rustnet README screenshots.
#
# Render with: scripts/record-rustnet-demo.sh
# (which runs both demo.tape and this tape, then cleans the throwaway GIF).
#
# Manual render: vhs screenshots.tape
# Pre-build the release binary and grant it capture capabilities first:
#   cargo build --release
#   sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' target/release/rustnet
#
# Walks every tab and emits PNGs under assets/screenshots/.
# Sized larger than demo.tape (1600x1000, FontSize 16) for crisper README
# rendering. The GIF Output is a throwaway and is deleted by the script.
#
# Beats and outputs:
#   1. Overview                      -> assets/screenshots/overview.png
#   2. Filter mode (/port:443)       -> assets/screenshots/filter.png
#   3. Process grouping (a, Space)   -> assets/screenshots/grouping.png
#   4. Details from a grouped child  -> assets/screenshots/details.png
#      (shows the continuity strip + "grouped by process" badge)
#   5. Graph (4)                     -> assets/screenshots/graph.png
#   6. Activity (3)                  -> assets/screenshots/interfaces.png

Output assets/screenshots/_throwaway.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 1000
Set Padding 20
Set TypingSpeed 50ms
Set Framerate 24
Set PlaybackSpeed 1.0

# Stay hidden until capture has warmed up so no shot catches the
# empty/loading state.
Hide
Type "clear"
Enter
Type "target/release/rustnet -i any"
Enter
Sleep 5s
Show

# 1. Overview
Sleep 3s
Down
Sleep 500ms
Down
Sleep 500ms
Screenshot "assets/screenshots/overview.png"
Sleep 500ms

# 2. Filter mode
Type "/"
Sleep 400ms
Type "port:443"
Sleep 1500ms
Screenshot "assets/screenshots/filter.png"
Sleep 500ms
Escape
Sleep 800ms

# 3. Process grouping: expand the selected group and step onto a child.
Type "a"
Sleep 1500ms
Space
Sleep 1000ms
Down
Sleep 400ms
Down
Sleep 1000ms
Screenshot "assets/screenshots/grouping.png"
Sleep 500ms

# 4. Details from the grouped child: continuity strip + grouped badge.
Enter
Sleep 2500ms
Screenshot "assets/screenshots/details.png"
Sleep 500ms
Escape
Sleep 800ms
Type "a"
Sleep 800ms

# 5. Graph
Type "4"
Sleep 2500ms
Screenshot "assets/screenshots/graph.png"
Sleep 500ms

# 6. Activity
Type "3"
Sleep 2500ms
Screenshot "assets/screenshots/interfaces.png"
Sleep 500ms

Hide
Type "q"
Sleep 200ms
Type "q"
