#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-rustnet-headless.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
rustnet_bin=${RUSTNET_BIN:-/Applications/Rustnet.app/Contents/MacOS/rustnet}

if [ ! -x "$rustnet_bin" ]; then
    echo "RustNet binary is not executable: $rustnet_bin" >&2
    exit 1
fi
case "$rustnet_bin" in
    /*) ;;
    *)
        echo "RUSTNET_BIN must be an absolute path" >&2
        exit 1
        ;;
esac

install -d -o root -g wheel -m 0700 /var/db/rustnet
install -d -o root -g wheel -m 0755 /Library/LaunchDaemons
launchctl disable system/com.domcyrus.rustnet-headless
rendered_plist=$(mktemp -t rustnet-headless.plist)
trap 'rm -f "$rendered_plist"' EXIT
cp "$script_dir/com.domcyrus.rustnet-headless.plist" "$rendered_plist"
plutil -replace ProgramArguments.0 -string "$rustnet_bin" "$rendered_plist"
plutil -lint "$rendered_plist" >/dev/null
install -o root -g wheel -m 0644 \
    "$rendered_plist" \
    /Library/LaunchDaemons/com.domcyrus.rustnet-headless.plist

echo "Installed the disabled launchd definition."
echo "Enable and bootstrap it explicitly when ready; this installer does neither."
echo "Configure local retention for /var/db/rustnet before long-running use."
