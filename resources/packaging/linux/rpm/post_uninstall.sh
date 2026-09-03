#!/bin/sh

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi
