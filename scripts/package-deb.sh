#!/usr/bin/env bash
# Package only binaries that meet the declared release ABI baseline.
set -euo pipefail
target=${1:?usage: package-deb.sh TARGET OUTPUT}
output=${2:?usage: package-deb.sh TARGET OUTPUT}
binary="target/$target/release/rustnet"
python3 scripts/verify-linux-abi.py "$binary" "$target"
variant=()
if [[ "$target" == armv7-unknown-linux-gnueabihf ]]; then
  variant=(--variant armhf)
fi
cargo deb --no-build --no-strip --target "$target" "${variant[@]}" --output "$output"
