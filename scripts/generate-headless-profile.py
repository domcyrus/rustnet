#!/usr/bin/env python3
"""Generate a synthetic Ethernet/IPv4/TCP PCAP for headless profiling.

This is a controlled trace, not a recording of representative user traffic.
Stable ACK flows coexist with short HTTP flows closed by RST. Checksums are
valid, timestamps cover the requested duration, and no traffic is transmitted.
"""

import argparse
import ipaddress
import struct


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def frame(flow, flags, payload=b""):
    local = ipaddress.ip_address("127.0.0.1").packed
    remote = ipaddress.ip_address(int(ipaddress.ip_address("192.0.2.1")) + flow // 50_000).packed
    tcp = struct.pack("!HHIIBBHHH", 1024 + flow % 50_000, 80, 1, 1, 0x50, flags, 65535, 0, 0) + payload
    pseudo = local + remote + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, local, remote)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return bytes.fromhex("0200000000020200000000010800") + ip + tcp


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def generate(args):
    with open(args.output, "xb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        def packet(second, micros, data):
            output.write(struct.pack("<IIII", 1_700_000_000 + second, micros, len(data), len(data)))
            output.write(data)

        stable = [frame(flow, 0x10) for flow in range(args.active)]
        for second in range(args.seconds):
            for data in stable:
                packet(second, 0, data)
            for index in range(args.churn):
                flow = args.active + second * args.churn + index
                request = b"GET / HTTP/1.1\r\nHost: profile.example\r\n\r\n"
                packet(second, 100_000, frame(flow, 0x18, request))
                packet(second, 100_000, frame(flow, 0x14))
        packet(args.seconds, 0, stable[0])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output")
    parser.add_argument("--seconds", type=positive, default=1800)
    parser.add_argument("--active", type=positive, default=64)
    parser.add_argument("--churn", type=nonnegative, default=10, help="new short flows per second")
    generate(parser.parse_args())
