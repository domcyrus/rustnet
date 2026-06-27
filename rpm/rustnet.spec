%global debug_package %{nil}

Name:    rustnet
# renovate: datasource=github-releases depName=domcyrus/rustnet extractVersion=true
Version: 1.4.0
Release: 1%{?dist}
Summary: Per-process network monitoring TUI with deep packet inspection
License: Apache-2.0
URL:     https://github.com/domcyrus/%{name}
Source0: %{url}/archive/refs/tags/v%{version}.tar.gz
%if 0%{?suse_version}
Source1: vendor.tar.zst
%endif

%if 0%{?suse_version}
BuildRequires: cargo-packaging
%else
BuildRequires: cargo
%endif
BuildRequires: rust >= 1.88.0
BuildRequires: libpcap-devel
%if 0%{?suse_version}
BuildRequires: libelf-devel
%else
BuildRequires: elfutils-libelf-devel
%endif
BuildRequires: clang
BuildRequires: llvm
%if 0%{?fedora}
BuildRequires: make
BuildRequires: selinux-policy-devel
%endif

Requires: libpcap
Requires: hicolor-icon-theme
%if 0%{?suse_version}
Requires: libelf1
# Pulled in so %post can run setcap (minimal Tumbleweed lacks it).
# Hard Requires (not Recommends) because zypper doesn't pull in new
# Recommends on `zypper update`, which would silently break the cap
# auto-setup for existing users on upgrade.
Requires: libcap-progs
%else
Requires: elfutils-libelf
Requires(post): libcap
%if 0%{?fedora}
Requires(post): policycoreutils
Requires(postun): policycoreutils
%endif
%endif

%description
RustNet is a terminal UI that shows live per-process network activity:
which application owns each TCP, UDP, and QUIC connection, what protocol
it speaks, and how the connection is behaving in real time. It runs
sandboxed by default and drops privileges immediately after libpcap
initializes.

Features:
- Per-process attribution for TCP, UDP, and QUIC via eBPF on Linux,
  PKTAP on macOS, and native APIs on Windows and FreeBSD
- Deep packet inspection for HTTP, HTTPS/TLS (with SNI), DNS, SSH,
  FTP, QUIC, MQTT, BitTorrent, STUN, NTP, mDNS, LLMNR, DHCP, SNMP,
  SSDP, and NetBIOS
- Security sandboxing: Landlock (Linux 5.13+), Seatbelt (macOS),
  token privilege drop and job-object child blocking (Windows)
- TCP analytics: retransmissions, out-of-order packets, and
  fast-retransmit detection, per-connection and aggregate
- Protocol-aware connection lifecycle with staleness indicators
- Vim/fzf-style filtering on port, src, dst, sni, process, state,
  proto, plus regex
- GeoIP country lookups via local MaxMind GeoLite2 (no network calls)
- Cross-platform: Linux, macOS, Windows, FreeBSD

%prep
%if 0%{?suse_version}
%autosetup -n %{name}-%{version} -a 1
%else
%autosetup -n %{name}-%{version}
%endif

%build
%if 0%{?suse_version}
%{cargo_build}
%else
export RUSTFLAGS="%{build_rustflags}"
# eBPF is now enabled by default, no need for explicit feature flag
cargo build --release
%if 0%{?fedora}
make -C selinux
%endif
%endif

%install
%if 0%{?suse_version}
%{cargo_install}
# cargo_install may generate .crates.toml and .crates2.json, we don't want them
rm -f %{buildroot}%{_prefix}/.crates.toml %{buildroot}%{_prefix}/.crates2.json
%else
install -Dpm 0755 target/release/rustnet -t %{buildroot}%{_bindir}/
%endif
install -Dpm 0644 crates/rustnet-core/assets/services -t %{buildroot}%{_datadir}/%{name}/
install -Dpm 0644 resources/packaging/linux/graphics/rustnet.png -t %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/
install -Dpm 0644 resources/packaging/linux/rustnet.desktop -t %{buildroot}%{_datadir}/applications/
%if 0%{?fedora}
install -dpm 0750 %{buildroot}%{_localstatedir}/log/%{name}
install -Dpm 0644 selinux/rustnet.pp %{buildroot}%{_datadir}/selinux/packages/%{name}/rustnet.pp
install -Dpm 0644 selinux/rustnet.fc %{buildroot}%{_datadir}/selinux/packages/%{name}/rustnet.fc
%endif

%files
%license LICENSE
%doc README.md
%{_bindir}/rustnet
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/services
%dir %{_datadir}/icons/hicolor
%dir %{_datadir}/icons/hicolor/256x256
%dir %{_datadir}/icons/hicolor/256x256/apps
%{_datadir}/icons/hicolor/256x256/apps/rustnet.png
%{_datadir}/applications/rustnet.desktop
%if 0%{?fedora}
%dir %attr(0750,root,root) %{_localstatedir}/log/%{name}
%dir %{_datadir}/selinux/packages/%{name}
%{_datadir}/selinux/packages/%{name}/rustnet.pp
%{_datadir}/selinux/packages/%{name}/rustnet.fc
%endif

%post
# Set capabilities for packet capture and eBPF support without requiring root/sudo
# This allows rustnet to run as a normal user with enhanced eBPF process detection
if command -v setcap >/dev/null 2>&1; then
    # Try modern capabilities first (Linux 5.8+)
    # CAP_NET_RAW: read-only packet capture (non-promiscuous mode)
    # CAP_BPF, CAP_PERFMON: eBPF support for enhanced process tracking
    setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' %{_bindir}/rustnet 2>/dev/null || \
        # Fallback for older kernels without CAP_BPF/CAP_PERFMON
        setcap 'cap_net_raw,cap_sys_admin+eip' %{_bindir}/rustnet || :
fi
%if 0%{?fedora}
# Fedora COPR targets modern Fedora with SELinux enabled by default. Install the
# policy in permissive mode first so users generate AVCs without broken capture
# sessions; the module itself owns that permissive setting.
if command -v semodule >/dev/null 2>&1 && [ -e /sys/fs/selinux/enforce ]; then
    semodule -n -i %{_datadir}/selinux/packages/%{name}/rustnet.pp || :
    command -v restorecon >/dev/null 2>&1 && restorecon -R %{_bindir}/rustnet %{_datadir}/%{name} /var/log/%{name} 2>/dev/null || :
fi
%endif

%postun
%if 0%{?fedora}
if [ "$1" -eq 0 ] && command -v semodule >/dev/null 2>&1 && [ -e /sys/fs/selinux/enforce ]; then
    semodule -n -r rustnet || :
fi
%endif

%posttrans
cat <<EOF

================================================================================
RustNet %{version} has been installed with eBPF support!

NETWORK PACKET CAPTURE PERMISSIONS:
  RustNet requires specific Linux capabilities for packet capture and eBPF
  process detection. These have been automatically set if setcap is available.

  To verify permissions are set correctly:
    getcap %{_bindir}/rustnet

  Expected output (modern Linux 5.8+):
    %{_bindir}/rustnet cap_net_raw,cap_bpf,cap_perfmon=eip

  Or for legacy kernels (pre-5.8):
    %{_bindir}/rustnet cap_net_raw,cap_sys_admin=eip

  If capabilities are not set, you can manually set them:
    # For modern Linux 5.8+ with eBPF support
    sudo setcap 'cap_net_raw,cap_bpf,cap_perfmon+eip' %{_bindir}/rustnet

    # Or for legacy kernels without CAP_BPF support
    sudo setcap 'cap_net_raw,cap_sys_admin+eip' %{_bindir}/rustnet

  Note: RustNet uses read-only packet capture (no promiscuous mode).
        CAP_NET_ADMIN is NOT required.

  Alternatively, run rustnet with sudo:
    sudo rustnet

  eBPF FALLBACK:
    If eBPF fails to load, rustnet will automatically fall back to procfs-based
    process detection. Check the TUI Statistics panel to see which detection
    method is active.

%if 0%{?fedora}
FEDORA SELINUX:
  The Fedora COPR RPM installs a rustnet SELinux policy module in permissive
  mode. It labels %{_bindir}/rustnet as rustnet_exec_t and transitions normal
  interactive launches into rustnet_t for AVC collection. Review denials with:
    sudo ausearch -m avc -ts recent

  The RPM does not modify firewalld or nftables rules.

%endif
  For more information, see the documentation at:
    %{_docdir}/%{name}/README.md

GEOIP (OPTIONAL):
  To show country codes for remote IPs, install GeoLite2 databases:
    sudo dnf install geoipupdate
  Edit /etc/GeoIP.conf with your free MaxMind credentials, then run:
    sudo geoipupdate
  See: https://github.com/domcyrus/rustnet/blob/main/INSTALL.md#geoip-databases-optional

USAGE:
  rustnet              # Start network monitoring
  rustnet --help       # Show all options

================================================================================
EOF

%changelog
%if 0%{?suse_version}
# OBS does not support rpmautospec; the changelog is maintained in rustnet.changes
%else
%autochangelog
%endif
