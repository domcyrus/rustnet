<p align="center"><strong>English</strong> | <a href="HEADLESS_PROFILING.zh-CN.md">简体中文</a> | <a href="HEADLESS_PROFILING.ja.md">日本語</a></p>

# Headless snapshot profiling

This development harness supports the measurement task in [#707](https://github.com/domcyrus/rustnet/issues/707). It measures the current full-snapshot protocol, including its bounded historic JSON cache. It does not change the output protocol or consumers.

## Reproduce

Build before measuring, then run one workload at a time on an otherwise idle machine:

```bash
cargo test --locked --release --lib profile_headless --no-run

RUSTNET_PROFILE_CSV=/tmp/matrix.csv cargo test --locked --release --lib \
  profile_headless_matrix -- --ignored --nocapture --test-threads=1
python3 scripts/summarize-headless-profile.py /tmp/matrix.csv

# Controlled 30-minute traces, generated without sending network traffic.
python3 scripts/generate-headless-profile.py /tmp/churn.pcap
python3 scripts/generate-headless-profile.py /tmp/steady.pcap --active 1000 --churn 0

# Repeat for steady.pcap, then for representative captures from your environment.
RUSTNET_PROFILE_PCAP=/tmp/churn.pcap RUSTNET_PROFILE_CSV=/tmp/churn.csv \
  cargo test --locked --release --lib profile_headless_pcap \
  -- --ignored --nocapture --test-threads=1
python3 scripts/summarize-headless-profile.py /tmp/churn.csv
```

Use new output filenames for each run: both tools refuse to overwrite existing files. The harness is compiled only for tests and ignored by the normal suite. It rejects debug builds, unreadable captures, decreasing timestamps, and traces with no supported packets. Captures stream from disk rather than being loaded into memory. The final message reports total and parsed packet counts, so unsupported traffic is visible.

The matrix varies active connections (100, 1,000, 5,000), retained connections (0, 1,000, 5,000, 10,000, 15,000), and extra executable-path metadata (0, 1,024, 4,096 bytes). Each case has 40 samples, with changing active counters, a cold cache at sample 0, and a late historic metadata change at sample 20. History beyond the tracker's default 5,000 limit is seeded directly to exercise the serializer's independent 10,000-entry and 16 MiB limits. Large artificial executable paths isolate payload sensitivity; they are not a claim about normal process metadata.

## What the measurements mean

CSV timings use `Instant` and nanoseconds. They include allocations and normal drops within each call:

- `build_ns`: production tracker snapshot cloning, service enrichment, creation-time sorting, and publication into the app snapshot (including replacement of the previous snapshot).
- `project_ns`: the production headless snapshot constructor, including another connection clone, wire metadata projection, timestamp formatting, and ID sorting.
- `serialize_ns`: the production cache and full JSONL serialization into a new byte buffer, including cache comparison, allocation, and eviction.
- `uncached_ns`: reference full serialization of the same projection. It runs first and warms memory, so do not treat the ratio as an unbiased before/after speedup.
- `payload_bytes`: the complete JSONL record including its newline. `cached_connections` and `cached_bytes` describe the cache retained after serialization. Neither is total process memory.

Every sample checks byte-for-byte equality with uncached full serialization outside the timed regions. CSV writes and packet parsing/tracking are also outside those regions. The summary reports nearest-rank p95 and median per stage, plus the sum of the three production stages per sample. That sum excludes the reference serialization. Cold fill and metadata invalidation are separated from warm matrix samples; replay results are grouped into five-minute trace windows.

Replay uses the capture's link type and microsecond-normalized timestamps, a 500 ms snapshot cadence, five-second cleanup, and the production tracker's default 50,000 active / 5,000 historic limits. It processes idle intervals before later packets and includes an end-of-file snapshot. Trace time advances without sleeping. There are no capture workers, host process attribution, reverse DNS, GeoIP enrichment, or concurrent lock contention. Parser address orientation comes from the replay host, so use the original host where possible and record any mismatch. Packet-derived metadata is retained. Wall-clock-based parser caches are not converted to trace time.

These measurements isolate snapshot cost. They do not measure live capture CPU, packet loss, peak RSS, consumer backpressure, pipe writes, end-to-end latency, or shutdown behavior. The generated traces are synthetic, even though they pass through the real PCAP parser, tracker, snapshot builder, and serializer. A 30-minute trace replay is not a 30-minute live run.

## Representative live captures

Collect at least 30 minutes each of typical workstation traffic, sustained many-connection traffic, and short-flow churn. Record the revision, compiler, features, CPU/OS, interface/link type, traffic source, duration, refresh interval, connection limits, and enrichment settings. Repeat each workload at least three times and retain raw CSV alongside the capture checksum. Capture contents are not needed in the CSV.

Use the release binary with symbols and the existing [perf workflow](PROFILING.md). Profile `--headless --output jsonl`, not `--output json`, which emits only the final snapshot. Sample CPU and RSS across early, growing-history, and saturated-history windows; drain stdout at the expected consumer rate and record generation gaps. Use the same capture/workload for comparison runs. Replay the corresponding PCAP through this harness to associate active/history counts and payload bytes with isolated snapshot-stage timings. Interpret those replay timings alongside the live profile, not as a replacement for it.

## Baseline results

2026-11-06, revision `327a63f` plus this test harness; Rust 1.99.1, default features, standard release profile (thin LTO, one codegen unit), x86_64 Linux 7.2.14-arch1-1, AMD Ryzen AI Max+ Pro 395. One diagnostic run per workload, unpinned CPU; no concurrent builds during timing. These are exploratory measurements, not a repeated live-capture study. Matrix rows below use 38 warm samples each; `a`, `h`, and `m` denote active count, history count, and extra metadata bytes.

| Case | Payload MiB p50 | Build ms p50 | Project ms p50 | Serialize ms p50 | Total ms p50/p95 |
|---|---:|---:|---:|---:|---:|
| a100-h0-m0 | 0.100 | 0.035 | 0.063 | 0.060 | 0.158/0.166 |
| a1000-h0-m0 | 0.994 | 0.450 | 0.624 | 0.646 | 1.723/1.785 |
| a5000-h0-m0 | 4.965 | 4.279 | 4.126 | 3.427 | 11.817/13.183 |
| a100-h1000-m0 | 1.109 | 0.554 | 0.796 | 0.465 | 1.815/1.888 |
| a100-h5000-m0 | 5.143 | 4.863 | 4.994 | 3.717 | 13.568/14.636 |
| a100-h10000-m0 | 10.188 | 11.208 | 13.354 | 7.475 | 32.303/33.888 |
| a100-h15000-m0 | 15.240 | 19.349 | 22.237 | 13.418 | 55.058/57.677 |
| a100-h5000-m4096 | 25.065 | 5.605 | 13.798 | 12.510 | 32.027/36.713 |
| steady 25-30 min | 0.858 | 0.175 | 0.676 | 0.532 | 1.394/1.510 |
| churn 0-5 min | 1.388 | 1.140 | 1.375 | 0.772 | 3.320/7.764 |
| churn 25-30 min | 4.672 | 7.473 | 7.351 | 4.511 | 19.299/21.827 |

Both generated traces span 1,800 seconds and produce 3,601 checked snapshots. Steady traffic contains 1,800,001 parsed packets and keeps 1,000 connections with no history. Churn contains 151,201 parsed packets, 64 persistent flows plus 10 new HTTP/RST flows per second, and reaches the 5,000-history limit. In its last five minutes the active table contains 214-264 records, including closed flows awaiting cleanup. All emitted snapshots match uncached serialization.

At fixed 100 active records, growing history from 1,000 to 5,000 raises the measured median total from 1.815 to 13.568 ms. At 5,000 history records, adding 4,096 metadata bytes raises payload from 5.143 to 25.065 MiB and total from 13.568 to 32.027 ms; the byte cap retains only 3,255-3,256 cached entries. With small metadata, the entry cap retains 10,000 of 15,000 history records. These limits bound cache storage, not total payload or projection work. In the saturated churn window, building and projecting together account for roughly three quarters of measured snapshot time. Prioritize measuring those stages alongside serialization before selecting an incremental protocol.

Live representative capture and perf evidence remain outstanding: no representative user capture was supplied, and privileged capture requires credentials unavailable in this session. The results above must not be presented as production workload CPU or memory measurements.
