#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
package=/packages/rustnet.deb

# Run the real Debian Readline frontend on a terminal. An upgrade must never
# ask again, even if the first installation was unattended.
interactive() {
    env DEBIAN_FRONTEND=readline DEBIAN_PRIORITY=high TERM=dumb expect -f - "$@" <<'EXPECT'
set timeout 90
set answer [lindex $argv 0]
set prompts 0
spawn -noecho {*}[lrange $argv 1 end]
expect {
    -exact "Allow local users to capture network traffic with RustNet without sudo?" {
        incr prompts
        if {$answer eq "skip" || $prompts != 1} { exit 1 }
        send -- "$answer\r"
        exp_continue
    }
    timeout { exit 1 }
    eof {
        set result [wait]
        if {[lindex $result 2] != 0 || [lindex $result 3] != 0} { exit 1 }
        exit [expr {$prompts != ($answer ne "skip")}]
    }
}
EXPECT
}

check_hardened_startup() {
    local launcher=(setpriv --bounding-set=-net_raw --reuid=nobody --regid=nogroup --clear-groups)
    test -z "$(getcap /usr/bin/rustnet)"
    "${launcher[@]}" /usr/bin/rustnet --version
    if "${launcher[@]}" /usr/bin/rustnet --headless --duration 1 --interface lo 2>/tmp/rustnet-permissions.txt; then
        echo 'Expected the ordinary user to lack capture permissions' >&2
        exit 1
    fi
    grep -Fq 'INSUFFICIENT PRIVILEGES' /tmp/rustnet-permissions.txt
    grep -Fq 'CAP_NET_RAW' /tmp/rustnet-permissions.txt
    grep -Fq 'sudo dpkg-reconfigure rustnet-monitor' /tmp/rustnet-permissions.txt
}

# Slim containers exclude docs even when they are in the package.
printf '%s\n' 'path-include /usr/share/doc/rustnet-monitor' \
  'path-include /usr/share/doc/rustnet-monitor/*' > /etc/dpkg/dpkg.cfg.d/zz-rustnet-test
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 apt-utils expect "$package"
test "$(dpkg-deb -f /packages/rustnet.deb Package)" = rustnet-monitor
check_hardened_startup
rustnet --version
rustnet --help > /tmp/rustnet-help.txt
grep -q -- '--headless' /tmp/rustnet-help.txt
ldd /usr/bin/rustnet
if ldd /usr/bin/rustnet | grep -q 'not found'; then exit 1; fi
test -s /usr/share/icons/hicolor/256x256/apps/rustnet.png
test -s /usr/share/icons/hicolor/scalable/apps/rustnet.svg
test -s /usr/share/applications/rustnet.desktop
test -s /usr/share/doc/rustnet-monitor/README.md

upgrade=$(mktemp -d)
dpkg-deb -R "$package" "$upgrade/pkg"
sed -i '/^Version:/s/$/+test1/' "$upgrade/pkg/DEBIAN/control"
dpkg-deb --build "$upgrade/pkg" "$upgrade/rustnet.deb"

interactive skip dpkg -i "$upgrade/rustnet.deb"
check_hardened_startup
apt-get purge -y rustnet-monitor

interactive yes apt-get install -y --no-install-recommends "$package"
setcap -v 'cap_net_raw=ep' /usr/bin/rustnet
DEBIAN_FRONTEND=noninteractive dpkg -i "$upgrade/rustnet.deb"
setcap -v 'cap_net_raw=ep' /usr/bin/rustnet
case "${CAPTURE_SMOKE:-true}" in
  true)
    runuser -u nobody -- python3 /checks/test-package-capture.py /usr/bin/rustnet lo
    ;;
  false)
    # QEMU user mode lacks SIOCETHTOOL and PACKET_HDRLEN translations.
    echo 'ARMv7: installation/startup checked; live capture requires native hardware or a full kernel VM'
    ;;
  *) exit 2 ;;
esac
interactive no dpkg-reconfigure -f readline rustnet-monitor
check_hardened_startup
apt-get purge -y rustnet-monitor
echo 'rustnet-monitor rustnet/allow-capture boolean true' | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$package"
setcap -v 'cap_net_raw=ep' /usr/bin/rustnet
apt-get remove -y rustnet-monitor
test ! -e /usr/bin/rustnet
