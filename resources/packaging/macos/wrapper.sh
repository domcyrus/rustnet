#!/bin/bash

# Wrapper script for Rustnet macOS app
# This script launches the Rustnet binary with admin privileges (required for packet capture)

# Get the directory where the app bundle is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Check if we're running in Terminal already
if [[ "$TERM_PROGRAM" == "Apple_Terminal" ]] || [[ "$TERM_PROGRAM" == "iTerm.app" ]]; then
    # Already in terminal, request admin privileges and run
    osascript -e "do shell script \"'$DIR/rustnet' $*\" with administrator privileges"
else
    # Not in terminal, open Terminal and run with admin privileges
    # Note: This will prompt for password in the Terminal window
    osascript <<EOF
tell application "Terminal"
    do script "cd '$DIR' && osascript -e 'do shell script \"./rustnet\" with administrator privileges'; exit"
    activate
end tell
EOF
fi