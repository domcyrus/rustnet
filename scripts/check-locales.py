#!/usr/bin/env python3
"""Check that all translation keys from source code are present in locale files.

Exit codes:
  0 - All keys present and consistent
  1 - Missing keys or inconsistencies found
"""

import re
import sys
from pathlib import Path


def extract_source_keys(src_dir: Path) -> set[str]:
    """Extract t!("key") translation keys from Rust source files."""
    pattern = re.compile(r't!\("([a-z_]+(?:\.[a-z_]+)+)"')
    keys = set()
    for rust_file in src_dir.rglob("*.rs"):
        content = rust_file.read_text()
        keys.update(pattern.findall(content))
    return keys


def extract_locale_keys(locale_file: Path) -> set[str]:
    """Extract keys from a YAML locale file."""
    pattern = re.compile(r'^"([^"]+)":', re.MULTILINE)
    content = locale_file.read_text()
    return set(pattern.findall(content))


def main() -> int:
    root = Path(__file__).parent.parent
    src_dir = root / "src"
    locales_dir = root / "assets" / "locales"

    source_keys = extract_source_keys(src_dir)
    print(f"Source code: {len(source_keys)} unique translation keys")
    print("---")

    all_locale_keys = {}
    for locale_file in sorted(locales_dir.glob("*.yml")):
        locale_keys = extract_locale_keys(locale_file)
        all_locale_keys[locale_file.name] = locale_keys
        print(f"{locale_file.name}: {len(locale_keys)} keys")

    errors = []
    reference_locale = "en.yml"
    reference_keys = all_locale_keys.get(reference_locale, set())

    # Check for missing keys (in source but not in locale)
    missing = source_keys - reference_keys
    if missing:
        errors.append(f"MISSING: {len(missing)} keys in source but not in locales:")
        for key in sorted(missing):
            errors.append(f"  {key}")

    # Check consistency across locale files
    for name, keys in sorted(all_locale_keys.items()):
        if name == reference_locale:
            continue
        missing_in_locale = reference_keys - keys
        extra_in_locale = keys - reference_keys
        if missing_in_locale:
            errors.append(f"{name} missing {len(missing_in_locale)} keys from {reference_locale}:")
            for key in sorted(missing_in_locale):
                errors.append(f"  {key}")
        if extra_in_locale:
            errors.append(f"{name} has {len(extra_in_locale)} extra keys not in {reference_locale}:")
            for key in sorted(extra_in_locale):
                errors.append(f"  {key}")

    if errors:
        print("---", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    print("---")
    print("All translation keys present and consistent")
    return 0


if __name__ == "__main__":
    sys.exit(main())
