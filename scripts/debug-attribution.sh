#!/usr/bin/env bash
set -uo pipefail

# Debug harness for the short-lived-process attribution race.
#
# Runs rustnet with debug logging IN THE FOREGROUND for ~20s (you will
# see the TUI take over; it exits by itself), while a background loop
# fires short-lived curl/dig processes. Captures the eBPF bpf_printk
# stream from the kernel tracing pipe, then summarizes what the
# process-lookup pipeline did for exactly those connections.
#
# Usage: scripts/debug-attribution.sh   (will sudo)

OUT_DIR="/tmp/claude/attribution-debug"
mkdir -p "${OUT_DIR}"
rm -f "${OUT_DIR}"/*.log 2>/dev/null

cd "$(dirname "$0")/.."

sudo -v || exit 1

# tracefs location differs across distros.
TRACE_PIPE="/sys/kernel/tracing/trace_pipe"
[[ -e "${TRACE_PIPE}" ]] || TRACE_PIPE="/sys/kernel/debug/tracing/trace_pipe"

# Capture bpf_printk output (e.g. "map update failed") while the test runs.
sudo sh -c "timeout 24 cat ${TRACE_PIPE}" > "${OUT_DIR}/bpf_trace.log" 2>"${OUT_DIR}/bpf_trace.err" &

# Background traffic: short-lived processes, started after capture warms up.
(
    sleep 6
    for i in 1 2 3; do
        curl -s -o /dev/null --max-time 3 https://example.com
        echo "curl #$i done ($(date +%H:%M:%S.%3N))" >> "${OUT_DIR}/traffic.log"
        dig +short +time=1 +tries=1 "example.com" @1.1.1.1 >/dev/null 2>&1
        echo "dig  #$i done ($(date +%H:%M:%S.%3N))" >> "${OUT_DIR}/traffic.log"
        sleep 2
    done
) &
TRAFFIC_PID=$!

echo "Starting rustnet for 20s (TUI will take over this terminal)..."
sleep 1
sudo sh -c 'timeout 20 target/release/rustnet -l debug' || true

# rustnet may have been killed mid-frame; restore the terminal.
stty sane 2>/dev/null
printf '\033[?1049l\033[?25h\033[?1000l\033[?1006l\n'

wait ${TRAFFIC_PID} 2>/dev/null

# The logs/ dir is created 0700 by the (privilege-dropped) rustnet
# process, so globbing it needs sudo.
LOG="$(sudo sh -c 'ls -t logs/rustnet_*.log 2>/dev/null' | head -1)"
if [[ -z "${LOG}" ]]; then
    echo "ERROR: no rustnet log produced; see ${OUT_DIR}/"
    exit 1
fi
sudo cp "${LOG}" "${OUT_DIR}/rustnet-debug.log"
sudo chown "$(id -u)" "${OUT_DIR}/rustnet-debug.log"
LOG="${OUT_DIR}/rustnet-debug.log"

echo ""
echo "=== Summary (${LOG}) ==="
echo "-- lookup outcome counts --"
echo "  eBPF hits:            $(grep -c 'Enhanced lookup: eBPF hit' "${LOG}")"
echo "  eBPF misses:          $(grep -c 'Enhanced lookup: eBPF miss' "${LOG}")"
echo "  zero-source rescues:  $(grep -c 'succeeded with zero source' "${LOG}")"
echo "  procfs name sets:     $(grep -c 'Set process name' "${LOG}")"
echo ""
echo "-- :443 (curl) lookup trace (first 30) --"
grep -E "Trying eBPF|eBPF lookup (successful|missed)|Set process name" "${LOG}" | grep ":443" | head -30
echo ""
echo "-- 1.1.1.1 (dig) lookup trace (first 20) --"
grep -E "Trying eBPF|eBPF lookup (successful|missed)|Set process name" "${LOG}" | grep "1\.1\.1\.1" | head -20
echo ""
echo "-- bpf_printk (kernel side) --"
grep -cE "map update failed" "${OUT_DIR}/bpf_trace.log" | sed 's/^/  map update failures: /'
wc -l < "${OUT_DIR}/bpf_trace.log" | sed 's/^/  total trace lines: /'
echo ""
echo "-- traffic timeline --"
cat "${OUT_DIR}/traffic.log" 2>/dev/null
echo ""
echo "Full logs preserved in ${OUT_DIR}/"
