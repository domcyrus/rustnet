# RustNet v1.7.0 README views. Render with scripts/record-rustnet-demo.sh.
# Published assets use the v1.7.0 Linux ARM64 release with eBPF and generated
# traffic on an isolated Docker network. The commands below target native Linux.
# Warm up the capture and graphs before taking any screenshots.
# The font includes the Braille glyphs used by the traffic plots.

Output assets/screenshots/_throwaway.gif

Set Theme "Catppuccin Mocha"
Set FontFamily "JetBrainsMono Nerd Font Mono"
Set FontSize 18
Set Width 1600
Set Height 1000
Set Padding 12
Set TypingSpeed 30ms
Set Framerate 15
Set PlaybackSpeed 1.0

Hide
Type "target/release/rustnet -i any --theme catppuccin-mocha"
Enter
Sleep 18s
Show
Sleep 2s
Screenshot "assets/screenshots/overview.png"
Sleep 300ms

# Filter first so unrelated packets cannot change the selected connection.
Type "/process:curl"
Enter
Sleep 1s
Type "a"
Sleep 1s
Space
Sleep 1s
Down
Sleep 500ms
Enter
Sleep 3s
Screenshot "assets/screenshots/details.png"
Sleep 300ms

# Restore the full traffic view.
Type "1"
Type "/"
Escape
Type "3"
Sleep 3s
Screenshot "assets/screenshots/activity.png"
Sleep 300ms

Type "4"
Sleep 3s
Screenshot "assets/screenshots/graph.png"
Sleep 300ms

Type "5"
Sleep 3s
Screenshot "assets/screenshots/host.png"
Sleep 300ms
Type "vv"
Sleep 3s
Screenshot "assets/screenshots/dns.png"
Sleep 300ms

Hide
Type "q"
Sleep 200ms
Type "q"
