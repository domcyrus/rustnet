#!/bin/sh

# Make the opt-in unit visible without enabling or starting it.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
