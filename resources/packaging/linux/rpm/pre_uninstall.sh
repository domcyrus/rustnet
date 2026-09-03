#!/bin/sh

# Stop and disable only when the package is being removed, not upgraded.
if [ "${1:-0}" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now rustnet-headless.service >/dev/null 2>&1 || :
fi
