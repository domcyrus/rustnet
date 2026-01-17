#!/usr/bin/env python3
"""
Enrich RustNet PCAP captures with process information from sidecar JSONL.

This script correlates packets in a PCAP file with process information
from the accompanying .connections.jsonl file created by RustNet.

Usage:
    # Show packets with process info
    python pcap_enrich.py capture.pcap

    # Export to annotated PCAPNG (requires editcap from Wireshark)
    python pcap_enrich.py capture.pcap --output annotated.pcapng

    # Generate TSV report
    python pcap_enrich.py capture.pcap --format tsv > report.tsv

Requirements:
    pip install scapy
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: scapy is required. Install with: pip install scapy", file=sys.stderr)
    sys.exit(1)


def parse_systemtime(st) -> float | None:
    """Parse a SystemTime serialized as {secs_since_epoch, nanos_since_epoch}."""
    if st is None:
        return None
    if isinstance(st, dict):
        secs = st.get("secs_since_epoch", 0)
        nanos = st.get("nanos_since_epoch", 0)
        return secs + nanos / 1e9
    # Fallback for other formats
    return None


def load_connections(jsonl_path: Path) -> dict:
    """Load connection-to-process mappings from JSONL file.

    Returns a dict mapping (proto, local, remote) -> list of connection info dicts.
    Multiple connections can exist for the same tuple (port reuse over time).
    """
    lookup = {}

    if not jsonl_path.exists():
        print(f"Warning: Sidecar file not found: {jsonl_path}", file=sys.stderr)
        return lookup

    with open(jsonl_path) as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
                proto = c.get("protocol", "").upper()
                local = c.get("local_addr", "")
                remote = c.get("remote_addr", "")

                if proto and local and remote:
                    info = {
                        "pid": c.get("pid"),
                        "process_name": c.get("process_name"),
                        "first_seen": parse_systemtime(c.get("first_seen")),
                        "last_seen": parse_systemtime(c.get("last_seen")),
                        "bytes_sent": c.get("bytes_sent", 0),
                        "bytes_received": c.get("bytes_received", 0),
                    }

                    # Store both directions, as a list to handle port reuse
                    for key in [(proto, local, remote), (proto, remote, local)]:
                        if key not in lookup:
                            lookup[key] = []
                        lookup[key].append(info)

            except json.JSONDecodeError as e:
                print(f"Warning: Invalid JSON at line {line_num}: {e}", file=sys.stderr)

    return lookup


def find_matching_connection(lookup: dict, pkt_tuple: tuple, pkt_time: float, slack: float) -> dict | None:
    """Find the best matching connection for a packet based on tuple and timestamp.

    Args:
        lookup: Connection lookup dict
        pkt_tuple: (proto, src, dst) tuple from packet
        pkt_time: Packet timestamp (seconds since epoch)
        slack: Allowed time slack in seconds

    Returns:
        Best matching connection info dict, or None if no match
    """
    connections = lookup.get(pkt_tuple, [])
    if not connections:
        return None

    best_match = None
    best_score = float('inf')

    for conn in connections:
        first_seen = conn.get("first_seen")
        last_seen = conn.get("last_seen")

        # If no timestamps, fall back to simple match (first connection wins)
        if first_seen is None or last_seen is None:
            if best_match is None:
                best_match = conn
            continue

        # Check if packet falls within connection time range (with slack)
        if first_seen - slack <= pkt_time <= last_seen + slack:
            # Score by how close the packet is to the connection's time range
            # Prefer connections where the packet is well within the range
            if pkt_time < first_seen:
                score = first_seen - pkt_time
            elif pkt_time > last_seen:
                score = pkt_time - last_seen
            else:
                score = 0  # Perfect match (within range)

            if score < best_score:
                best_score = score
                best_match = conn

    return best_match


def get_packet_tuple(pkt) -> tuple:
    """Extract connection tuple from packet."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        return ("TCP", f"{src_ip}:{tcp.sport}", f"{dst_ip}:{tcp.dport}")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        return ("UDP", f"{src_ip}:{udp.sport}", f"{dst_ip}:{udp.dport}")
    elif pkt.haslayer(ICMP):
        return ("ICMP", src_ip, dst_ip)

    return None


def enrich_packets(pcap_path: Path, lookup: dict, slack: float):
    """Yield enriched packet information."""
    packets = rdpcap(str(pcap_path))

    for frame_num, pkt in enumerate(packets, 1):
        pkt_tuple = get_packet_tuple(pkt)
        pkt_time = float(pkt.time)

        if not pkt_tuple:
            yield {
                "frame": frame_num,
                "time": pkt_time,
                "proto": "OTHER",
                "src": "",
                "dst": "",
                "pid": None,
                "process": None,
            }
            continue

        proto, src, dst = pkt_tuple
        info = find_matching_connection(lookup, pkt_tuple, pkt_time, slack) or {}

        yield {
            "frame": frame_num,
            "time": pkt_time,
            "proto": proto,
            "src": src,
            "dst": dst,
            "pid": info.get("pid"),
            "process": info.get("process_name"),
            "bytes_sent": info.get("bytes_sent"),
            "bytes_received": info.get("bytes_received"),
        }


def print_table(packets: list):
    """Print enriched packets as a formatted table."""
    print(f"{'Frame':>6} {'Proto':<5} {'Source':<24} {'Destination':<24} {'PID':>7} {'Process':<20}")
    print("-" * 95)

    for p in packets:
        pid_str = str(p["pid"]) if p["pid"] else "-"
        proc_str = p["process"] or "-"
        if len(proc_str) > 20:
            proc_str = proc_str[:17] + "..."
        print(f"{p['frame']:>6} {p['proto']:<5} {p['src']:<24} {p['dst']:<24} {pid_str:>7} {proc_str:<20}")


def print_tsv(packets: list):
    """Print enriched packets as TSV."""
    print("frame\ttime\tproto\tsrc\tdst\tpid\tprocess")
    for p in packets:
        print(f"{p['frame']}\t{p['time']:.6f}\t{p['proto']}\t{p['src']}\t{p['dst']}\t{p['pid'] or ''}\t{p['process'] or ''}")


def print_json(packets: list):
    """Print enriched packets as JSON."""
    print(json.dumps(packets, indent=2))


def create_pcapng(pcap_path: Path, packets: list, output_path: Path):
    """Create annotated PCAPNG using editcap."""
    # Check if editcap is available
    try:
        subprocess.run(["editcap", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: editcap not found. Install Wireshark to get editcap.", file=sys.stderr)
        sys.exit(1)

    # First convert to pcapng
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    subprocess.run(["editcap", "-F", "pcapng", str(pcap_path), str(tmp_path)], check=True)

    # Build annotation commands
    # editcap -a "frame:comment" format
    annotations = []
    for p in packets:
        if p["pid"] or p["process"]:
            comment_parts = []
            if p["pid"]:
                comment_parts.append(f"PID:{p['pid']}")
            if p["process"]:
                comment_parts.append(f"Process:{p['process']}")
            comment = " ".join(comment_parts)
            annotations.append(f"{p['frame']}:{comment}")

    if not annotations:
        print("No process information found to annotate.", file=sys.stderr)
        # Just copy the pcapng as-is
        tmp_path.rename(output_path)
        return

    # Apply annotations in batches (editcap has command line limits)
    current_input = tmp_path
    batch_size = 100

    for i in range(0, len(annotations), batch_size):
        batch = annotations[i:i + batch_size]
        with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp2:
            tmp2_path = Path(tmp2.name)

        cmd = ["editcap"]
        for ann in batch:
            cmd.extend(["-a", ann])
        cmd.extend([str(current_input), str(tmp2_path)])

        subprocess.run(cmd, check=True)

        if current_input != tmp_path:
            current_input.unlink()
        current_input = tmp2_path

    # Move final result to output
    current_input.rename(output_path)
    if tmp_path.exists():
        tmp_path.unlink()

    print(f"Created annotated PCAPNG: {output_path}")
    print(f"Annotated {len(annotations)} packets with process information.")


def count_unique_connections(lookup: dict) -> int:
    """Count unique connections (accounting for bidirectional storage)."""
    seen = set()
    count = 0
    for key, conns in lookup.items():
        for conn in conns:
            # Create a unique identifier for each connection
            conn_id = (key, conn.get("first_seen"), conn.get("pid"))
            if conn_id not in seen:
                seen.add(conn_id)
                count += 1
    return count // 2  # Divide by 2 because we store both directions


def print_summary(packets: list, lookup: dict):
    """Print a summary of process information found."""
    total = len(packets)
    with_pid = sum(1 for p in packets if p["pid"])

    # Group by process
    by_process = {}
    for p in packets:
        proc = p["process"] or "<unknown>"
        if proc not in by_process:
            by_process[proc] = {"count": 0, "pid": p["pid"]}
        by_process[proc]["count"] += 1

    print(f"\nSummary:")
    print(f"  Total packets: {total}")
    print(f"  Packets with process info: {with_pid} ({100*with_pid/total:.1f}%)")
    print(f"  Unique connections in sidecar: {count_unique_connections(lookup)}")
    print(f"\nPackets by process:")
    for proc, info in sorted(by_process.items(), key=lambda x: -x[1]["count"]):
        pid_str = f" (PID {info['pid']})" if info["pid"] else ""
        print(f"  {proc}{pid_str}: {info['count']} packets")


def main():
    parser = argparse.ArgumentParser(
        description="Enrich RustNet PCAP captures with process information.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap                    # Show packets with process info
  %(prog)s capture.pcap --format tsv       # Output as TSV
  %(prog)s capture.pcap --format json      # Output as JSON
  %(prog)s capture.pcap -o annotated.pcapng  # Create annotated PCAPNG
  %(prog)s capture.pcap --summary          # Show summary only
  %(prog)s capture.pcap --slack 5          # Use 5 second slack for timestamp matching
        """
    )
    parser.add_argument("pcap", type=Path, help="Path to PCAP file")
    parser.add_argument("-j", "--jsonl", type=Path,
                       help="Path to sidecar JSONL file (default: <pcap>.connections.jsonl)")
    parser.add_argument("-o", "--output", type=Path,
                       help="Output annotated PCAPNG file")
    parser.add_argument("-f", "--format", choices=["table", "tsv", "json"], default="table",
                       help="Output format (default: table)")
    parser.add_argument("-s", "--summary", action="store_true",
                       help="Show summary only")
    parser.add_argument("-l", "--limit", type=int, default=0,
                       help="Limit number of packets to process (0 = no limit)")
    parser.add_argument("--slack", type=float, default=2.0,
                       help="Timestamp matching slack in seconds (default: 2.0)")

    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"Error: PCAP file not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    # Default sidecar path
    jsonl_path = args.jsonl or Path(f"{args.pcap}.connections.jsonl")

    # Load connection mappings
    lookup = load_connections(jsonl_path)
    if lookup:
        print(f"Loaded {count_unique_connections(lookup)} connections from {jsonl_path}", file=sys.stderr)

    # Process packets
    packets = list(enrich_packets(args.pcap, lookup, args.slack))
    if args.limit > 0:
        packets = packets[:args.limit]

    if args.summary:
        print_summary(packets, lookup)
        return

    if args.output:
        create_pcapng(args.pcap, packets, args.output)
        print_summary(packets, lookup)
    else:
        if args.format == "table":
            print_table(packets)
            print_summary(packets, lookup)
        elif args.format == "tsv":
            print_tsv(packets)
        elif args.format == "json":
            print_json(packets)


if __name__ == "__main__":
    main()