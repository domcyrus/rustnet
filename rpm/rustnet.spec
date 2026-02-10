%global debug_package %{nil}

Name:    rustnet
# renovate: datasource=github-releases depName=domcyrus/rustnet extractVersion=true
Version: 1.0.0
Release: 1%{?dist}
Summary: A cross-platform network monitoring terminal UI tool built with Rust
License: Apache-2.0
URL:     https://github.com/domcyrus/%{name}
Source0: %{url}/archive/refs/tags/v%{version}.tar.gz

BuildRequires: cargo
BuildRequires: rust >= 1.88.0
BuildRequires: libpcap-devel
BuildRequires: elfutils-libelf-devel
BuildRequires: clang
BuildRequires: llvm

Requires: libpcap
Requires: elfutils-libelf

%description
A cross-platform network monitoring tool built with Rust. RustNet provides
real-time visibility into network connections with detailed state information,
connection lifecycle management, deep packet inspection, and a terminal user
interface.

Features include:
- Real-time Network Monitoring for TCP, UDP, ICMP, and ARP connections
- Deep Packet Inspection (DPI) for HTTP/HTTPS, DNS, SSH, and QUIC protocols
- Connection lifecycle management with protocol-aware timeouts
- Process identification and service name resolution
- Cross-platform support (Linux, macOS, Windows, BSD)
- Advanced filtering with vim/fzf-style search
- eBPF-enhanced process detection (enabled by default with automatic fallback)

%prep
%autosetup -n %{name}-%{version}

%build
export RUSTFLAGS="%{build_rustflags}"
# eBPF is now enabled by default, no need for explicit feature flag
cargo build --release

%install
install -Dpm 0755 target/release/rustnet -t %{buildroot}%{_bindir}/
install -Dpm 0644 assets/services -t %{buildroot}%{_datadir}/%{name}/
install -Dpm 0644 README.md -t %{buildroot}%{_docdir}/%{name}/
install -Dpm 0644 resources/packaging/linux/graphics/rustnet.png -t %{buildroot}%{_datadir}/icons/hicolor/256x256/apps/
install -Dpm 0644 resources/packaging/linux/rustnet.desktop -t %{buildroot}%{_datadir}/applications/

%files
%license LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/rustnet
%{_datadir}/%{name}/services
%{_datadir}/icons/hicolor/256x256/apps/rustnet.png
%{_datadir}/applications/rustnet.desktop

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
%autochangelog
