#!/bin/bash

# Wrapper script for Rustnet macOS app
# This script launches the Rustnet binary in a terminal

# Get the directory where the app bundle is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Check if we're running in Terminal already
if [[ "$TERM_PROGRAM" == "Apple_Terminal" ]] || [[ "$TERM_PROGRAM" == "iTerm.app" ]]; then
    # Already in terminal, just run the binary
    exec "$DIR/rustnet" "$@"
else
    # Not in terminal, open Terminal and run the command
    # This will open a new Terminal window with rustnet running
    osascript -e "tell application \"Terminal\" to do script \"cd '$DIR' && ./rustnet; exit\""
fi