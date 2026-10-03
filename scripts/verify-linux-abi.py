"""Reject release binaries that exceed the DEB baseline or mix ARM time ABIs."""
import re
import subprocess
import sys

binary, target = sys.argv[1:]
versions = subprocess.check_output(["readelf", "--version-info", binary], text=True)
required = {tuple(map(int, version.split(".")))
            for version in re.findall(r"Name: GLIBC_([0-9.]+)", versions)}
if not required:
    sys.exit("No GLIBC requirements found in GNU release binary")
if max(required) > (2, 35):
    sys.exit(f"GLIBC {'.'.join(map(str, max(required)))} exceeds the 2.35 release baseline")
dynamic = subprocess.check_output(["readelf", "-d", binary], text=True)
if target == "armv7-unknown-linux-gnueabihf" and re.search(r"NEEDED.*libpcap", dynamic):
    sys.exit("ARMv7 release binary must embed libpcap to avoid the time64 ABI mismatch")
print(f"PASS: {target} requires at most GLIBC 2.35; libpcap linkage is compatible")
