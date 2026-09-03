#!/bin/sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "install-rustnet-headless.sh must run as root" >&2
    exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

install -d -o root -g wheel -m 0700 /var/db/rustnet
install -o root -g wheel -m 0555 \
    "$script_dir/rustnet_headless" \
    /usr/local/etc/rc.d/rustnet_headless

echo "Installed with rustnet_headless_enable=NO."
echo "Enable and start it explicitly when ready; this installer does neither."
echo "Configure local retention for /var/db/rustnet before long-running use."
