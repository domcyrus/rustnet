"""Verify Npcap imports in dumpbin /imports output supplied on stdin."""

import re
import sys


def verify_imports(text):
    section = None
    delayed = set()
    for line in text.splitlines():
        line = line.strip().lower()
        heading = re.fullmatch(
            r"section contains the following (delay load )?imports:", line
        )
        if heading:
            section = "delayed" if heading.group(1) else "eager"
        elif line in ("packet.dll", "wpcap.dll"):
            if section != "delayed":
                raise ValueError(f"{line} is not a delay-loaded import")
            delayed.add(line)

    # Native interface enumeration can eliminate Packet.dll entirely. Capture
    # still uses wpcap.dll, which must remain delayed for --help and --version.
    if "wpcap.dll" not in delayed:
        raise ValueError("wpcap.dll is missing from the delay-loaded imports")


if __name__ == "__main__":
    try:
        verify_imports(sys.stdin.read())
    except ValueError as error:
        sys.exit(str(error))
    print("Npcap delay imports verified")
