#!/usr/bin/env python3
"""Summarize the CSV emitted by the ignored headless release profiling tests."""

import argparse
import csv
import math
import statistics
from collections import defaultdict


def summarize(path):
    groups = defaultdict(list)
    with open(path, newline="", encoding="utf-8") as source:
        for row in csv.DictReader(source):
            workload = row.pop("workload")
            values = {key: int(value) for key, value in row.items()}
            if workload == "pcap":
                start = values["trace_ms"] // 300_000 * 5
                workload = f"pcap {start}-{start + 5} min"
            elif workload != "pcap-final":
                # Report cold fill and late enrichment separately from warm data.
                phase = {0: "cold", 20: "metadata change"}.get(values["sample"], "warm")
                workload += f" {phase}"
            groups[workload].append(values)
    if not groups:
        raise ValueError("profile CSV has no samples")
    print("| Workload | n | Active | History | Payload MiB p50 | Build ms p50/p95 | Project ms p50/p95 | Serialize ms p50/p95 | Total ms p50/p95 | Uncached ms p50/p95 | Cached entries min/max |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
    for name, rows in groups.items():
        def span(field):
            values = [row[field] for row in rows]
            return f"{min(values)}/{max(values)}"

        def timings(field):
            values = sorted(row[field] for row in rows)
            return f"{statistics.median(values) / 1e6:.3f}/{values[math.ceil(len(values) * .95) - 1] / 1e6:.3f}"

        for row in rows:
            row["total_ns"] = row["build_ns"] + row["project_ns"] + row["serialize_ns"]
        payload = statistics.median(row["payload_bytes"] for row in rows) / 2**20
        print(f"| {name} | {len(rows)} | {span('active')} | {span('historic')} | {payload:.3f} | "
              + " | ".join(timings(field) for field in ["build_ns", "project_ns", "serialize_ns", "total_ns", "uncached_ns"])
              + f" | {span('cached_connections')} |")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", help="CSV written by profile_headless_matrix or profile_headless_pcap")
    summarize(parser.parse_args().csv)
