use clap::{Arg, Command};

#[cfg(target_os = "linux")]
const INTERFACE_HELP: &str = "Network interface to monitor (use \"any\" to capture all interfaces)";

#[cfg(not(target_os = "linux"))]
const INTERFACE_HELP: &str = "Network interface to monitor";

#[cfg(target_os = "macos")]
const BPF_HELP: &str = "BPF filter expression for packet capture (e.g., \"tcp port 443\"). Note: Using a BPF filter disables PKTAP (process info falls back to lsof)";

#[cfg(not(target_os = "macos"))]
const BPF_HELP: &str =
    "BPF filter expression for packet capture (e.g., \"tcp port 443\", \"dst port 80\")";

pub fn build_cli() -> Command {
    let cmd = Command::new("rustnet")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Network Monitor")
        .about("Cross-platform network monitoring tool")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help(INTERFACE_HELP)
                .required(false),
        )
        .arg(
            Arg::new("no-localhost")
                .long("no-localhost")
                .help("Filter out localhost connections")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-localhost")
                .long("show-localhost")
                .help("Show localhost connections (overrides default filtering)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh-interval")
                .short('r')
                .long("refresh-interval")
                .value_name("MILLISECONDS")
                .help("UI refresh interval in milliseconds")
                .value_parser(clap::value_parser!(u64))
                .default_value("1000")
                .required(false),
        )
        .arg(
            Arg::new("no-dpi")
                .long("no-dpi")
                .help("Disable deep packet inspection")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help("Set the log level (if not provided, no logging will be enabled)")
                .required(false),
        )
        .arg(
            Arg::new("json-log")
                .long("json-log")
                .value_name("FILE")
                .help("Enable JSON logging of connection events to specified file")
                .required(false),
        )
        .arg(
            Arg::new("pcap-export")
                .long("pcap-export")
                .value_name("FILE")
                .help("Export captured packets to PCAP file for Wireshark analysis")
                .required(false),
        )
        .arg(
            Arg::new("bpf-filter")
                .short('f')
                .long("bpf-filter")
                .value_name("FILTER")
                .help(BPF_HELP)
                .required(false),
        )
        .arg(
            Arg::new("resolve-dns")
                .long("resolve-dns")
                .help("Enable reverse DNS resolution for IP addresses (shows hostnames instead of IPs)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-ptr-lookups")
                .long("show-ptr-lookups")
                .help("Show PTR lookup connections in UI (hidden by default when --resolve-dns is enabled)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .help("Disable all colors in the UI (also respects NO_COLOR env var)")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("geoip-country")
                .long("geoip-country")
                .value_name("PATH")
                .help(
                    "Path to GeoLite2-Country.mmdb database. \
                     Auto-discovered from: ./resources/geoip2, $XDG_DATA_HOME/rustnet/geoip, \
                     ~/.local/share/rustnet/geoip, /usr/share/GeoIP, /usr/local/share/GeoIP, \
                     /opt/homebrew/share/GeoIP, /var/lib/GeoIP",
                )
                .required(false),
        )
        .arg(
            Arg::new("geoip-asn")
                .long("geoip-asn")
                .value_name("PATH")
                .help("Path to GeoLite2-ASN.mmdb database (same search paths as --geoip-country)")
                .required(false),
        )
        .arg(
            Arg::new("no-geoip")
                .long("no-geoip")
                .help("Disable GeoIP lookups entirely")
                .action(clap::ArgAction::SetTrue),
        );

    #[cfg(target_os = "linux")]
    let cmd = cmd
        .arg(
            Arg::new("no-sandbox")
                .long("no-sandbox")
                .help("Disable Landlock sandboxing")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sandbox-strict")
                .long("sandbox-strict")
                .help("Require full sandbox enforcement or exit")
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("no-sandbox"),
        );

    cmd
}
