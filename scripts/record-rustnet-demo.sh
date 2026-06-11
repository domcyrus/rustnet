#!/usr/bin/env bash
set -euo pipefail

# Automate the rustnet VHS recording: produces assets/rustnet.gif (demo)
# and assets/screenshots/*.png (README) in one pass.
#
# Prerequisites (Linux):
#   vhs                            # required (https://github.com/charmbracelet/vhs)
#   gifsicle                       # optional, for GIF size optimization
#   cargo build --release          # auto-run if target/release/rustnet missing
#
# Usage:
#   scripts/record-rustnet-demo.sh
#
# What it does:
#   1. Verifies vhs and cargo are installed.
#   2. Builds target/release/rustnet if missing or stale vs Cargo.lock.
#   3. Grants the binary capture capabilities via `sudo setcap`, so the
#      recording runs rustnet UNPRIVILEGED — the Security sidebar shows
#      the sandboxed non-root posture instead of a root warning.
#   4. Spawns a background traffic generator (curl/dig/ping) so the
#      connection table is busy and sparklines move.
#   5. Runs `vhs demo.tape` -> assets/rustnet.gif.
#   6. Runs `vhs screenshots.tape` -> assets/screenshots/*.png.
#   7. Optimizes the GIF with gifsicle -O3 --lossy=80 if available
#      (terminal flat colors are unaffected by the lossy pass).
#   8. Cleans up the throwaway GIF and background processes.
#   9. Prints a summary of the produced assets.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTNET_DIR="$(dirname "$SCRIPT_DIR")"
DEMO_TAPE="${RUSTNET_DIR}/demo.tape"
SCREENSHOTS_TAPE="${RUSTNET_DIR}/screenshots.tape"
GIF_FILE="${RUSTNET_DIR}/assets/rustnet.gif"
SCREENSHOTS_DIR="${RUSTNET_DIR}/assets/screenshots"
THROWAWAY_GIF="${SCREENSHOTS_DIR}/_throwaway.gif"
RELEASE_BIN="${RUSTNET_DIR}/target/release/rustnet"

TRAFFIC_PID=""

cleanup() {
    if [[ -n "${TRAFFIC_PID}" ]] && kill -0 "${TRAFFIC_PID}" 2>/dev/null; then
        kill "${TRAFFIC_PID}" 2>/dev/null || true
        wait "${TRAFFIC_PID}" 2>/dev/null || true
    fi
    rm -f "${THROWAWAY_GIF}"
}
trap cleanup EXIT INT TERM

# Kill stale ttyd / headless-Chrome processes left over from prior failed
# vhs runs. VHS uses go-rod, which writes its Chrome profile to a
# `rod/user-data` tmpdir; if a prior run died, the locked profile causes
# the next run to fail with `could not open ttyd: ERR_CONNECTION_REFUSED`.
preflight_cleanup_vhs() {
    local stale=0
    if pgrep -f "ttyd --port" >/dev/null 2>&1; then
        pkill -f "ttyd --port" 2>/dev/null || true
        stale=1
    fi
    if pgrep -f "rod/user-data" >/dev/null 2>&1; then
        pkill -f "rod/user-data" 2>/dev/null || true
        stale=1
    fi
    if [[ "${stale}" -eq 1 ]]; then
        echo "Cleaned up stale ttyd / Chrome processes from prior vhs run."
        sleep 1
    fi
    rm -rf "${TMPDIR:-/tmp}/rod" 2>/dev/null || true
}
preflight_cleanup_vhs

# Dependency checks
for cmd in vhs cargo setcap; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed."
        exit 1
    fi
done

if ! command -v gifsicle &> /dev/null; then
    echo "Note: gifsicle not found; skipping GIF optimization."
    HAS_GIFSICLE=0
else
    HAS_GIFSICLE=1
fi

# Tape files must exist
[[ -f "${DEMO_TAPE}" ]] || { echo "Error: ${DEMO_TAPE} missing."; exit 1; }
[[ -f "${SCREENSHOTS_TAPE}" ]] || { echo "Error: ${SCREENSHOTS_TAPE} missing."; exit 1; }

# Validate sudo up front (before the potentially long build) so the run
# doesn't die at the setcap step minutes in. Honors SUDO_ASKPASS when
# the caller exports one; otherwise prompts on the terminal as usual.
SUDO=(sudo)
[[ -n "${SUDO_ASKPASS:-}" ]] && SUDO=(sudo -A)
echo "setcap needs sudo; validating credentials..."
"${SUDO[@]}" -v || { echo "Error: sudo authentication failed."; exit 1; }

# Build release binary if missing or stale
if [[ ! -x "${RELEASE_BIN}" ]] || [[ "${RUSTNET_DIR}/Cargo.lock" -nt "${RELEASE_BIN}" ]]; then
    echo "Building release binary..."
    (cd "${RUSTNET_DIR}" && cargo build --release)
fi

# Grant capture capabilities so the tapes can run rustnet unprivileged.
# File capabilities are dropped whenever cargo rewrites the binary, so
# (re)apply them on every run.
echo "Granting capture capabilities (sudo setcap)..."
"${SUDO[@]}" setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' "${RELEASE_BIN}"

# Background traffic generator: HTTPS, DNS, ICMP, multiple processes.
mkdir -p "${SCREENSHOTS_DIR}"
(
    while true; do
        curl -s -o /dev/null --max-time 4 https://example.com || true
        curl -s -o /dev/null --max-time 4 https://github.com || true
        curl -s -o /dev/null --max-time 4 https://wikipedia.org || true
        curl -s -o /dev/null --max-time 4 https://ratatui.rs || true
        dig +short +time=2 +tries=1 example.com >/dev/null 2>&1 || true
        dig +short +time=2 +tries=1 github.com >/dev/null 2>&1 || true
        ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
        sleep 1
    done
) &
TRAFFIC_PID=$!

echo ""
echo "Rendering demo GIF (vhs demo.tape)..."
(cd "${RUSTNET_DIR}" && vhs "${DEMO_TAPE}")

echo ""
echo "Rendering screenshots (vhs screenshots.tape)..."
(cd "${RUSTNET_DIR}" && vhs "${SCREENSHOTS_TAPE}")

# Optimize the GIF. The lossy pass shrinks dithered/AA edges; flat
# terminal colors are visually unaffected.
if [[ "${HAS_GIFSICLE}" -eq 1 ]] && [[ -f "${GIF_FILE}" ]]; then
    echo ""
    echo "Optimizing GIF with gifsicle -O3 --lossy=80..."
    BEFORE_SIZE=$(stat -f%z "${GIF_FILE}" 2>/dev/null || stat -c%s "${GIF_FILE}")
    gifsicle -O3 --lossy=80 --batch "${GIF_FILE}"
    AFTER_SIZE=$(stat -f%z "${GIF_FILE}" 2>/dev/null || stat -c%s "${GIF_FILE}")
    echo "  ${BEFORE_SIZE} -> ${AFTER_SIZE} bytes"
fi

# Summary.
echo ""
echo "Done."
echo ""
echo "GIF:"
ls -lh "${GIF_FILE}" 2>/dev/null | awk '{print "  " $9 " (" $5 ")"}'
echo ""
echo "Screenshots:"
for png in "${SCREENSHOTS_DIR}"/*.png; do
    [[ -f "${png}" ]] && ls -lh "${png}" | awk '{print "  " $9 " (" $5 ")"}'
done
echo ""
echo "Preview:"
echo "  open ${GIF_FILE}"
echo "  open ${SCREENSHOTS_DIR}"
