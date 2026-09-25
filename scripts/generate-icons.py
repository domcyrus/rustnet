#!/usr/bin/env python3
"""Regenerate packaged artwork from assets/rustnet.svg.

Setup and output details: resources/packaging/README.md.
Requires resvg-py==0.5.0 only when regenerating artwork.
"""

import struct
import sys
from pathlib import Path

try:
    from resvg_py import svg_to_bytes
except ImportError:
    sys.exit("Install the export dependency: python -m pip install resvg-py==0.5.0")

ROOT = Path(__file__).resolve().parent.parent
PACKAGING = "resources/packaging"
ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)
# PNG-backed standard and Retina representations supported by modern macOS.
ICNS_SIZES = (
    (b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128),
    (b"ic08", 256), (b"ic09", 512), (b"ic10", 1024),
    (b"ic11", 32), (b"ic12", 64), (b"ic13", 256), (b"ic14", 512),
)


def write(relative: str, data: bytes) -> None:
    (ROOT / relative).write_bytes(data)
    print(relative)


def svg(width: int, height: int, contents: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">\n{contents}\n</svg>\n'
    )


def png(source: str, width: int, height: int | None = None) -> bytes:
    return svg_to_bytes(
        svg_string=source, width=width, height=height or width,
        skip_system_fonts=True,
    )


def ico(rendered: dict[int, bytes]) -> bytes:
    header = struct.pack("<HHH", 0, 1, len(ICO_SIZES))
    offset = len(header) + 16 * len(ICO_SIZES)
    entries = []
    images = []
    for size in ICO_SIZES:
        data = rendered[size]
        # ICO stores 256 as zero in its one-byte width/height fields.
        entries.append(struct.pack(
            "<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(data), offset,
        ))
        images.append(data)
        offset += len(data)
    return header + b"".join(entries + images)


def icns(rendered: dict[int, bytes]) -> bytes:
    chunks = b"".join(
        struct.pack(">4sI", kind, len(rendered[size]) + 8) + rendered[size]
        for kind, size in ICNS_SIZES
    )
    return struct.pack(">4sI", b"icns", len(chunks) + 8) + chunks


def main() -> None:
    # Nest the SVG directly: every export retains the master's geometry/colors.
    mark = (ROOT / "assets/rustnet.svg").read_text(encoding="utf-8").strip()
    desktop = svg(512, 512, f'''  <title>RustNet</title>
  <defs>
    <linearGradient id="tile" x2="0" y2="1">
      <stop stop-color="#1c2531"/>
      <stop offset="1" stop-color="#111827"/>
    </linearGradient>
  </defs>
  <rect x="25" y="25" width="462" height="462" rx="104" fill="url(#tile)" stroke="#374151" stroke-width="2"/>
  <g transform="translate(27 36) scale(.86)">{mark}</g>''')
    write(f"{PACKAGING}/linux/graphics/rustnet.svg", desktop.encode("utf-8"))

    sizes = sorted(set(ICO_SIZES) | {size for _, size in ICNS_SIZES})
    rendered = {size: png(desktop, size) for size in sizes}
    write(f"{PACKAGING}/linux/graphics/rustnet.png", rendered[256])
    write(f"{PACKAGING}/macos/graphics/rustnet.png", rendered[1024])
    write(f"{PACKAGING}/windows/graphics/rustnet.ico", ico(rendered))
    write(f"{PACKAGING}/macos/graphics/rustnet.icns", icns(rendered))

    # Matches create-dmg's 900x450 window, with icons at (300,240)/(620,240).
    # No fonts or external images, so exports are independent of installed fonts.
    background = svg(900, 450, f'''  <rect width="900" height="450" fill="#f3f4f6"/>
  <g transform="translate(380 -2) scale(.25)">{mark}</g>
  <path d="M 427 240 H 483 M 469 226 L 483 240 L 469 254" fill="none" stroke="#6b7280" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>''')
    write(f"{PACKAGING}/macos/graphics/dmg_bg.png", png(background, 900, 450))


if __name__ == "__main__":
    main()
