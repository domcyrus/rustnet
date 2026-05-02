# vhs tape for the rustnet README screenshots.
#
# Render with: scripts/record-rustnet-demo.sh
# (which runs both demo.tape and this tape, then cleans the throwaway GIF).
#
# Manual render: vhs screenshots.tape
# Pre-build the release binary first: cargo build --release
#
# Walks every tab and emits PNGs under assets/screenshots/.
# Sized larger than demo.tape (1600x1000, FontSize 16) for crisper README
# rendering. The GIF Output is a throwaway and is deleted by the script.
#
# Beats and outputs:
#   1. Overview                    -> assets/screenshots/overview.png
#   2. Filter mode (/port:443)     -> assets/screenshots/filter.png
#   3. Process grouping (a, Space) -> assets/screenshots/grouping.png
#   4. Details (Enter)             -> assets/screenshots/details.png
#   5. Graph (Tab x3)              -> assets/screenshots/graph.png
#   6. Interfaces (i)              -> assets/screenshots/interfaces.png

Output assets/screenshots/_throwaway.gif

Set Theme "Catppuccin Mocha"
Set FontSize 16
Set Width 1600
Set Height 1000
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

# 3. Process grouping
Type "a"
Sleep 1500ms
Down
Sleep 400ms
Space
Sleep 1500ms
Screenshot "assets/screenshots/grouping.png"
Sleep 500ms
Type "a"
Sleep 800ms

# 4. Details
Enter
Sleep 2500ms
Screenshot "assets/screenshots/details.png"
Sleep 500ms
Escape
Sleep 800ms

# 5. Graph
Tab@400ms 3
Sleep 2500ms
Screenshot "assets/screenshots/graph.png"
Sleep 500ms
Escape
Sleep 800ms

# 6. Interfaces
Type "i"
Sleep 2500ms
Screenshot "assets/screenshots/interfaces.png"
Sleep 500ms

Hide
Type "q"
Sleep 200ms
Type "q"
