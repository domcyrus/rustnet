%global debug_package %{nil}

Name:    rustnet
# renovate: datasource=github-releases depName=domcyrus/rustnet extractVersion=true
Version: 0.13.0
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
- Optional eBPF support for enhanced Linux performance

%prep
%autosetup -n %{name}-%{version}

%build
export RUSTFLAGS="%{build_rustflags}"
cargo build --release --features "linux-default"

%install
install -Dpm 0755 target/release/rustnet -t %{buildroot}%{_bindir}/
install -Dpm 0644 assets/services -t %{buildroot}%{_datadir}/%{name}/
install -Dpm 0644 README.md -t %{buildroot}%{_docdir}/%{name}/

%files
%license LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/rustnet
%{_datadir}/%{name}/services

%post
# Set capabilities for packet capture and eBPF support without requiring root/sudo
# This allows rustnet to run as a normal user with enhanced eBPF process detection
if command -v setcap >/dev/null 2>&1; then
    # Try modern capabilities first (Linux 5.8+)
    # CAP_NET_RAW, CAP_NET_ADMIN: packet capture
    # CAP_BPF, CAP_PERFMON: eBPF support
    # CAP_SYS_ADMIN: may be required for kprobe attachment on some kernel versions
    setcap 'cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon+eip' %{_bindir}/rustnet 2>/dev/null || \
        # Fallback for older kernels without CAP_BPF/CAP_PERFMON
        setcap 'cap_net_raw,cap_net_admin,cap_sys_admin+eip' %{_bindir}/rustnet || :
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

  Expected output (Linux 5.8+):
    %{_bindir}/rustnet cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon=eip

  Or for older kernels:
    %{_bindir}/rustnet cap_net_raw,cap_net_admin,cap_sys_admin=eip

  If capabilities are not set, you can manually set them:
    # For Linux 5.8+ with eBPF support
    sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin,cap_bpf,cap_perfmon+eip' %{_bindir}/rustnet

    # Or for older kernels
    sudo setcap 'cap_net_raw,cap_net_admin,cap_sys_admin+eip' %{_bindir}/rustnet

  Alternatively, run rustnet with sudo:
    sudo rustnet

  eBPF FALLBACK:
    If eBPF fails to load, rustnet will automatically fall back to procfs-based
    process detection. Check the TUI Statistics panel to see which detection
    method is active.

  For more information, see the documentation at:
    %{_docdir}/%{name}/README.md

USAGE:
  rustnet              # Start network monitoring
  rustnet --help       # Show all options

================================================================================
EOF

%changelog
%autochangelog
