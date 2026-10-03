import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

binary, interface = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='rustnet-smoke-') as directory:
    directory = Path(directory)
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(('127.0.0.1', 0))
    port = listener.getsockname()[1]
    command = [binary, '--headless', '--duration', '3', '--output', 'json', '--log-level', 'debug',
               '--interface', interface, '--show-localhost', '--no-resolve-dns',
               '--bpf-filter', f'udp port {port}', '--pcap-export', str(directory / 'traffic.pcap'),
               '--json-log', str(directory / 'events.jsonl')]
    def send():
        time.sleep(1)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(20):
            sender.sendto(b'rustnet release smoke', ('127.0.0.1', port))
            time.sleep(0.05)
        sender.close()
    process = subprocess.Popen(command, cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    thread = threading.Thread(target=send)
    thread.start()
    stdout, stderr = process.communicate(timeout=20)
    thread.join()
    listener.close()
    print(stderr)
    print(stdout)
    if process.returncode != 0:
        for path in directory.rglob('*.log'):
            print(path.name, path.read_text(errors='replace'))
    assert process.returncode == 0, process.returncode
    snapshot = json.loads(stdout)
    assert snapshot['schema_version'] == 1
    assert snapshot['runtime']['status'] == 'stopped', snapshot['runtime']
    assert snapshot['runtime']['capture_error'] is None
    assert snapshot['connection_count'] > 0, snapshot
    pcap = directory / 'traffic.pcap'
    assert pcap.stat().st_size > 24, pcap.stat().st_size
    # Check actual packet headers, not just a nonempty file: a time32/time64
    # libpcap mismatch can corrupt timestamps and captured packet lengths.
    data = pcap.read_bytes()
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}[data[:4]]
    offset = 24
    while offset < len(data):
        seconds, micros, captured, original = struct.unpack_from(endian + 'IIII', data, offset)
        assert abs(seconds - time.time()) < 30, seconds
        assert micros < 1_000_000, micros
        assert 0 < captured <= original, (captured, original)
        offset += 16 + captured
        assert offset <= len(data), (offset, len(data))
    assert offset == len(data)
    events = directory / 'events.jsonl'
    records = [json.loads(line) for line in events.read_text().splitlines() if line.strip()]
    assert records, 'No event log records'
    for path in [pcap, events]:
        assert path.stat().st_mode & 0o077 == 0, (path, oct(path.stat().st_mode))
    print('PASS: timed headless shutdown, loopback capture, JSON snapshot, private PCAP and event log exports')
