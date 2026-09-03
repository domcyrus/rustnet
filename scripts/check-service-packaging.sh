#!/usr/bin/env bash

set -euo pipefail

repo_root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

systemd_unit="resources/packaging/linux/systemd/rustnet-headless.service"
systemd_env="resources/packaging/linux/systemd/rustnet-headless.env"
logrotate_policy="resources/packaging/linux/logrotate/rustnet-headless"
launchd_plist="resources/packaging/macos/launchd/com.domcyrus.rustnet-headless.plist"
macos_installer="resources/packaging/macos/launchd/install-rustnet-headless.sh"
freebsd_service="resources/packaging/freebsd/rc.d/rustnet_headless"
freebsd_installer="resources/packaging/freebsd/rc.d/install-rustnet-headless.sh"
compose_file="compose.headless.yml"
windows_wix="resources/packaging/windows/wix/main.wxs"
rpm_post_install="resources/packaging/linux/rpm/post_install.sh"
rpm_pre_uninstall="resources/packaging/linux/rpm/pre_uninstall.sh"
rpm_post_uninstall="resources/packaging/linux/rpm/post_uninstall.sh"

required_files=(
    "$systemd_unit"
    "$systemd_env"
    "$logrotate_policy"
    "$launchd_plist"
    "$macos_installer"
    "$freebsd_service"
    "$freebsd_installer"
    "$compose_file"
    "$windows_wix"
    "$rpm_post_install"
    "$rpm_pre_uninstall"
    "$rpm_post_uninstall"
    "Dockerfile"
)

fail()
{
    printf 'service packaging check failed: %s\n' "$1" >&2
    exit 1
}

require_literal()
{
    file=$1
    value=$2
    grep -Fq -- "$value" "$file" || fail "$file is missing: $value"
}

for file in "${required_files[@]}"; do
    [ -f "$file" ] || fail "missing $file"
done

executable_files=(
    "$macos_installer"
    "$freebsd_service"
    "$freebsd_installer"
    "$rpm_post_install"
    "$rpm_pre_uninstall"
    "$rpm_post_uninstall"
    "debian/postinst"
    "debian/prerm"
    "debian/postrm"
    "${BASH_SOURCE[0]}"
)
for file in "${executable_files[@]}"; do
    [ -x "$file" ] || fail "$file must be executable"
done

# Every supervisor invokes a fixed headless command. Extra service arguments
# may extend these defaults but cannot replace --headless.
require_literal "$systemd_unit" "ExecStart=/usr/bin/rustnet --headless"
require_literal "$launchd_plist" "<string>--headless</string>"
require_literal "$launchd_plist" "<string>/Applications/Rustnet.app/Contents/MacOS/rustnet</string>"
require_literal "$freebsd_service" "--headless --refresh-interval 5000 --output jsonl"
require_literal "$compose_file" "- --headless"

for file in "$systemd_unit" "$launchd_plist" "$freebsd_service" "$compose_file"; do
    require_literal "$file" "5000"
done

require_literal "$systemd_unit" "--interface any"
require_literal "$compose_file" "- any"
require_literal "$compose_file" 'max-size: "10m"'
require_literal "$compose_file" 'max-file: "7"'
require_literal "$windows_wix" "Start='demand'"
require_literal "$windows_wix" "--windows-service --headless"
require_literal "$windows_wix" "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
require_literal "debian/rules" "dh_installsystemd --no-enable --no-start"
require_literal "Cargo.toml" 'maintainer-scripts = "debian"'
require_literal "debian/prerm" "systemctl disable --now rustnet-headless.service"
require_literal "$rpm_pre_uninstall" "systemctl disable --now rustnet-headless.service"
require_literal "$systemd_unit" "StateDirectoryMode=0700"
require_literal "$systemd_unit" "UMask=0077"
require_literal "$macos_installer" "-m 0700 /var/db/rustnet"
require_literal "$macos_installer" "launchctl disable system/com.domcyrus.rustnet-headless"
state_dir_install="-m 0700 \"\$state_dir\""
require_literal "$freebsd_service" "$state_dir_install"
require_literal "$freebsd_service" 'rustnet_headless_enable:=NO'
require_literal "$freebsd_installer" "rustnet_headless_enable=NO"
require_literal "Dockerfile" "STOPSIGNAL SIGTERM"

if grep -Eq 'launchctl[[:space:]]+(bootstrap|enable|kickstart|load)' "$macos_installer"; then
    fail "$macos_installer must not enable or start the service"
fi

if grep -Eq 'sysrc.*rustnet_headless_enable=.*YES|service[[:space:]]+rustnet_headless[[:space:]]+(start|onestart)' "$freebsd_installer"; then
    fail "$freebsd_installer must not enable or start the service"
fi

if grep -Eq 'systemctl[[:space:]]+(enable|start|restart)|systemctl[[:space:]]+enable[[:space:]]+--now' "$rpm_post_install"; then
    fail "$rpm_post_install must not enable or start the service"
fi

if grep -Eq 'systemctl[[:space:]]+(enable|start|restart)|systemctl[[:space:]]+enable[[:space:]]+--now' debian/postinst; then
    fail "debian/postinst must not enable or start the service"
fi

if grep -Fq "Start='install'" "$windows_wix" || grep -Fq "Start='both'" "$windows_wix"; then
    fail "$windows_wix must not start the service during installation"
fi

sh -n "$macos_installer"
sh -n "$freebsd_service"
sh -n "$freebsd_installer"
sh -n "$rpm_post_install"
sh -n "$rpm_pre_uninstall"
sh -n "$rpm_post_uninstall"
bash -n "${BASH_SOURCE[0]}"

if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$launchd_plist" >/dev/null
fi

if command -v systemd-analyze >/dev/null 2>&1; then
    verify_dir=$(mktemp -d)
    trap 'rm -rf "$verify_dir"' EXIT
    sed 's#ExecStart=/usr/bin/rustnet#ExecStart=/bin/true#' \
        "$systemd_unit" >"$verify_dir/rustnet-headless.service"
    systemd-analyze verify "$verify_dir/rustnet-headless.service" >/dev/null
fi

if command -v logrotate >/dev/null 2>&1; then
    logrotate --debug "$logrotate_policy" >/dev/null
fi

if docker compose version >/dev/null 2>&1; then
    docker compose -f "$compose_file" config --quiet
fi

if LC_ALL=C grep -n "$(printf '\342\200\224')" "${required_files[@]}" "${BASH_SOURCE[0]}"; then
    fail "service assets contain an em dash"
fi

printf 'service packaging checks passed\n'
