# RustNet Performance Profiling Guide

This guide explains how to profile RustNet to identify performance bottlenecks.

## Quick Start

### CPU Profiling with perf + flamegraph

The easiest way to profile CPU usage on Linux:

```bash
# 1. Install flamegraph tools
cargo install flamegraph

# 2. Build a release binary with debug symbols
# IMPORTANT: Debug symbols are required for meaningful flamegraphs!
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --features linux-default

# Or add this to Cargo.toml temporarily:
# [profile.release]
# debug = true

# 3. Run with profiling (requires sudo for perf)
# Note: Use full path to flamegraph since sudo doesn't have your user's PATH
# IMPORTANT: Use -- before the command to profile
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet

# Or specify interface and other args after the binary
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet -i eth0

# Alternatively, preserve PATH for cleaner commands:
sudo env "PATH=$PATH" flamegraph -- ./target/release/rustnet

# 4. Open the generated flamegraph.svg in a browser
firefox flamegraph.svg
```

### Alternative: Using perf directly

If you prefer to use `perf` directly:

```bash
# Build with debug symbols
cargo build --release --features linux-default

# Record performance data (run for 30-60 seconds, then Ctrl+C to stop)
sudo perf record -F 99 -g ./target/release/rustnet -i eth0

# Generate flamegraph (requires FlameGraph scripts)
# Install from: https://github.com/brendangregg/FlameGraph
perf script | stackcollapse-perf.pl | flamegraph.pl > flamegraph.svg

# Or view in perf's TUI
sudo perf report
```

### Profiling a Running Instance

If RustNet is already running:

```bash
# Find the PID
ps aux | grep rustnet

# Profile the running process for 60 seconds
sudo -E ~/.cargo/bin/flamegraph -p <PID> --output rustnet-live.svg

# Or with perf directly
sudo perf record -F 99 -g -p <PID> sleep 60
sudo perf report
```

## Interpreting Flamegraphs

Look for:
- **Wide bars at the bottom**: Functions that consume a lot of total CPU time
- **Tall stacks**: Deep call chains (potential optimization targets)
- **Hot spots**: Functions with many samples (bright colors in some viewers)

Common hot spots:
- `packet_parser::parse_packet`: Normal - this is the core packet processing
- `DashMap::iter` or `iter_mut`: If this is a large portion, consider reducing iteration frequency
- `clone`: If excessive, reduce unnecessary cloning
- System calls (`read`, `write`, `ioctl`): Filesystem or network I/O overhead

## Benchmarking

For consistent benchmarks:

```bash
# Run with consistent traffic
sudo ./target/release/rustnet --interface eth0 &
PID=$!

# Monitor CPU usage
top -p $PID

# Or use perf stat for detailed metrics
sudo perf stat -p $PID sleep 60

# Stop the application
sudo kill $PID
```

## Performance Regression Testing

After making changes, compare before/after:

```bash
# Baseline (before changes)
sudo perf stat -r 3 timeout 60s ./target/release/rustnet-before > /dev/null

# After changes
sudo perf stat -r 3 timeout 60s ./target/release/rustnet > /dev/null
```

Key metrics to compare:
- CPU cycles
- Instructions per cycle (IPC)
- Cache misses
- Context switches

## Troubleshooting Flamegraphs

### Empty or Single-Entry Flamegraph

If your flamegraph only shows "rustnet (100%)" with no details:

**Problem**: Debug symbols are missing from the release build.

**Solution**:
```bash
# Rebuild with debug symbols
CARGO_PROFILE_RELEASE_DEBUG=true cargo build --release --features linux-default

# Or add to Cargo.toml:
[profile.release]
debug = true

# Then re-profile
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

### Flamegraph Shows Only Kernel Functions

**Problem**: Running with insufficient permissions or perf can't access user-space symbols.

**Solution**:
```bash
# Check perf_event_paranoid setting
cat /proc/sys/kernel/perf_event_paranoid

# If it's > 1, temporarily lower it (requires root):
sudo sysctl kernel.perf_event_paranoid=1

# Or run as root
sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

### Very Short Flamegraph (< 1000 samples)

**Problem**: Profiling session too short, not enough data collected.

**Solution**:
```bash
# Let rustnet run for at least 30-60 seconds before stopping
# The more network traffic, the better the profile

# For longer profiling:
timeout 60 sudo -E ~/.cargo/bin/flamegraph -- ./target/release/rustnet
```

## Debugging Slow TUI

If the TUI feels sluggish:

1. **Check refresh rate**: Default is 1000ms, can be adjusted with `--refresh-interval`
2. **Check connection count**: High connection counts increase sorting overhead
3. **Profile the UI loop**: Look for hot spots in `run_ui_loop`, `draw`, or `sort_connections`
4. **Monitor thread contention**: Check if packet processing threads are blocking the snapshot provider
