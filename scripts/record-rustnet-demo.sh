#!/usr/bin/env bash
set -euo pipefail

# Automate the rustnet VHS recording: produces assets/rustnet.gif (showcase)
# and assets/screenshots/*.png (README) in one pass.
#
# Prerequisites:
#   brew install vhs              # required
#   brew install gifsicle         # optional, for GIF size optimization
#   cargo build --release         # auto-run if target/release/rustnet missing
#
# Usage:
#   scripts/record-rustnet-demo.sh
#
# What it does:
#   1. Verifies vhs and cargo are installed.
#   2. Builds target/release/rustnet if missing or stale vs Cargo.lock.
#   3. Pre-caches sudo (PKTAP capture on macOS always needs root).
#   4. Spawns a sudo keepalive loop so a long render does not lose creds.
#   5. Spawns a background traffic generator (curl/dig/ping) so the
#      connection table is busy and sparklines move.
#   6. Runs `vhs demo.tape` -> assets/rustnet.gif.
#   7. Runs `vhs screenshots.tape` -> assets/screenshots/*.png.
#   8. Optimizes the GIF with gifsicle -O3 if available.
#   9. Cleans up the throwaway GIF and background processes.
#  10. Prints a summary of the produced assets.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTNET_DIR="$(dirname "$SCRIPT_DIR")"
DEMO_TAPE="${RUSTNET_DIR}/demo.tape"
SCREENSHOTS_TAPE="${RUSTNET_DIR}/screenshots.tape"
GIF_FILE="${RUSTNET_DIR}/assets/rustnet.gif"
SCREENSHOTS_DIR="${RUSTNET_DIR}/assets/screenshots"
THROWAWAY_GIF="${SCREENSHOTS_DIR}/_throwaway.gif"
RELEASE_BIN="${RUSTNET_DIR}/target/release/rustnet"

TRAFFIC_PID=""
ASKPASS_SCRIPT=""
PW_FILE=""

cleanup() {
    if [[ -n "${TRAFFIC_PID}" ]] && kill -0 "${TRAFFIC_PID}" 2>/dev/null; then
        kill "${TRAFFIC_PID}" 2>/dev/null || true
        wait "${TRAFFIC_PID}" 2>/dev/null || true
    fi
    [[ -n "${ASKPASS_SCRIPT}" ]] && rm -f "${ASKPASS_SCRIPT}"
    [[ -n "${PW_FILE}" ]] && rm -f "${PW_FILE}"
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
for cmd in vhs cargo; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed."
        [[ "$cmd" == "vhs" ]] && echo "Install: brew install vhs"
        [[ "$cmd" == "cargo" ]] && echo "Install: https://rustup.rs"
        exit 1
    fi
done

if ! command -v gifsicle &> /dev/null; then
    echo "Note: gifsicle not found; skipping GIF optimization."
    echo "      Install with: brew install gifsicle"
    HAS_GIFSICLE=0
else
    HAS_GIFSICLE=1
fi

# Tape files must exist
[[ -f "${DEMO_TAPE}" ]] || { echo "Error: ${DEMO_TAPE} missing."; exit 1; }
[[ -f "${SCREENSHOTS_TAPE}" ]] || { echo "Error: ${SCREENSHOTS_TAPE} missing."; exit 1; }

# Build release binary if missing or stale
if [[ ! -x "${RELEASE_BIN}" ]] || [[ "${RUSTNET_DIR}/Cargo.lock" -nt "${RELEASE_BIN}" ]]; then
    echo "Building release binary..."
    (cd "${RUSTNET_DIR}" && cargo build --release)
fi

# Read sudo password and validate it. macOS sudo uses tty_tickets by default,
# so a `sudo -v` cached in this shell does NOT carry over to the new pty
# that vhs/ttyd spawns. Instead, store the validated password in a private
# file and expose it via SUDO_ASKPASS so the in-tape `sudo -A target/release/rustnet`
# can re-authenticate non-interactively.
echo "Capture requires root. Enter your sudo password (3 attempts)."
SUDO_PW=""
for attempt in 1 2 3; do
    printf 'Password: '
    IFS= read -rs SUDO_PW
    printf '\n'
    if [[ -z "${SUDO_PW}" ]]; then
        echo "  empty password, try again ($attempt/3)"
        continue
    fi
    if printf '%s\n' "${SUDO_PW}" | sudo -S -v 2>/dev/null; then
        break
    fi
    echo "  wrong password ($attempt/3)"
    SUDO_PW=""
done
if [[ -z "${SUDO_PW}" ]]; then
    echo "Error: sudo authentication failed after 3 attempts."
    exit 1
fi

# Stash the password in a 0600 temp file and write a tiny askpass helper
# that cats it. SUDO_ASKPASS in the env makes `sudo -A` use this helper.
PW_FILE="$(mktemp -t rustnet-pw.XXXXXX)"
chmod 600 "${PW_FILE}"
printf '%s' "${SUDO_PW}" > "${PW_FILE}"
unset SUDO_PW

ASKPASS_SCRIPT="$(mktemp -t rustnet-askpass.XXXXXX)"
chmod 700 "${ASKPASS_SCRIPT}"
cat > "${ASKPASS_SCRIPT}" <<EOF
#!/bin/sh
cat "${PW_FILE}"
EOF
export SUDO_ASKPASS="${ASKPASS_SCRIPT}"

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

# Render the demo GIF.
# VHS does not propagate the parent shell's env to the recording shell.
# Inject an `Env SUDO_ASKPASS <path>` directive into each tape so the in-tape
# `sudo -A` can find the askpass helper. VHS requires Env to come AFTER all
# `Set` directives but BEFORE the first command (Hide/Type/Sleep/etc.), so
# we use awk to insert it at the first command line.
render_tape_with_askpass() {
    local tape="$1"
    local tmp_tape
    tmp_tape="$(mktemp -t "$(basename "${tape}").XXXXXX")"
    awk -v askpass="${ASKPASS_SCRIPT}" '
        BEGIN { injected = 0 }
        /^(Output|Set|Env|Require|Source|#|[[:space:]]*$)/ { print; next }
        {
            if (!injected) {
                print "Env SUDO_ASKPASS \"" askpass "\""
                injected = 1
            }
            print
        }
    ' "${RUSTNET_DIR}/${tape}" > "${tmp_tape}"
    (cd "${RUSTNET_DIR}" && vhs "${tmp_tape}")
    rm -f "${tmp_tape}"
}

echo ""
echo "Rendering demo GIF (vhs demo.tape)..."
render_tape_with_askpass demo.tape

# Render the screenshots.
echo ""
echo "Rendering screenshots (vhs screenshots.tape)..."
render_tape_with_askpass screenshots.tape

# Optimize the GIF.
if [[ "${HAS_GIFSICLE}" -eq 1 ]] && [[ -f "${GIF_FILE}" ]]; then
    echo ""
    echo "Optimizing GIF with gifsicle -O3..."
    BEFORE_SIZE=$(stat -f%z "${GIF_FILE}" 2>/dev/null || stat -c%s "${GIF_FILE}")
    gifsicle -O3 --batch "${GIF_FILE}"
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
