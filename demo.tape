# RustNet v1.7.0: live Overview, grouping, Details, Activity, Graph and Host.
# Published assets use the v1.7.0 Linux ARM64 release with eBPF and generated
# traffic on an isolated Docker network. The commands below target native Linux.
# Render with scripts/record-rustnet-demo.sh on Linux after setting capture
# capabilities. Use generated traffic and verify rustnet --version first.
# Keep the warm-up hidden and allow time to read each view.

Output assets/rustnet.gif

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
Sleep 12s
Show

# Live connections, then filter and expand a process group.
Sleep 4s
Type "/process:curl"
Enter
Sleep 2s
Type "a"
Sleep 2s
Space
Sleep 2s
Down
Sleep 1s

# Inspect one connection and its protocol metadata.
Enter
Sleep 5s

# Clear the filter before showing all application traffic and graphs.
Type "1"
Type "/"
Escape
Type "3"
Sleep 5s
Type "4"
Sleep 5s

# Host socket inventory and passive DNS analytics.
Type "5"
Sleep 4s
Type "vv"
Sleep 5s

# Return to the opening view for a gentle loop.
Type "1"
Type "a"
Sleep 3s
Hide
Type "q"
Sleep 200ms
Type "q"
