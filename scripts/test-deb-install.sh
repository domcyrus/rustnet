#!/usr/bin/env bash
set -euo pipefail
# Slim containers exclude docs even when they are in the package.
printf '%s\n' 'path-include /usr/share/doc/rustnet-monitor' \
  'path-include /usr/share/doc/rustnet-monitor/*' > /etc/dpkg/dpkg.cfg.d/zz-rustnet-test
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 /packages/rustnet.deb
test "$(dpkg-deb -f /packages/rustnet.deb Package)" = rustnet-monitor
rustnet --version
rustnet --help > /tmp/rustnet-help.txt
grep -q -- '--headless' /tmp/rustnet-help.txt
ldd /usr/bin/rustnet
if ldd /usr/bin/rustnet | grep -q 'not found'; then exit 1; fi
test -s /usr/share/icons/hicolor/256x256/apps/rustnet.png
test -s /usr/share/icons/hicolor/scalable/apps/rustnet.svg
test -s /usr/share/applications/rustnet.desktop
test -s /usr/share/doc/rustnet-monitor/README.md
case "${CAPTURE_SMOKE:-true}" in
  true) python3 /checks/test-package-capture.py /usr/bin/rustnet lo ;;
  false)
    # QEMU user mode lacks SIOCETHTOOL and PACKET_HDRLEN translations.
    echo 'ARMv7: installation/startup checked; live capture requires native hardware or a full kernel VM'
    ;;
  *) exit 2 ;;
esac
apt-get remove -y rustnet-monitor
test ! -e /usr/bin/rustnet
