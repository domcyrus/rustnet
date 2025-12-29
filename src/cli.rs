use clap::{Arg, Command};
use rust_i18n::t;

/// Get the interface help text (platform-specific)
fn interface_help() -> String {
    #[cfg(target_os = "linux")]
    {
        t!("cli.interface_help_linux").to_string()
    }
    #[cfg(not(target_os = "linux"))]
    {
        t!("cli.interface_help").to_string()
    }
}

/// Get the BPF filter help text (platform-specific)
fn bpf_help() -> String {
    #[cfg(target_os = "macos")]
    {
        t!("cli.bpf_help_macos").to_string()
    }
    #[cfg(not(target_os = "macos"))]
    {
        t!("cli.bpf_help").to_string()
    }
}

pub fn build_cli() -> Command {
    let cmd = Command::new("rustnet")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Network Monitor")
        .about(t!("cli.about").to_string())
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help(interface_help())
                .required(false),
        )
        .arg(
            Arg::new("no-localhost")
                .long("no-localhost")
                .help(t!("cli.no_localhost_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-localhost")
                .long("show-localhost")
                .help(t!("cli.show_localhost_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("refresh-interval")
                .short('r')
                .long("refresh-interval")
                .value_name("MILLISECONDS")
                .help(t!("cli.refresh_interval_help").to_string())
                .value_parser(clap::value_parser!(u64))
                .default_value("1000")
                .required(false),
        )
        .arg(
            Arg::new("no-dpi")
                .long("no-dpi")
                .help(t!("cli.no_dpi_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log-level")
                .short('l')
                .long("log-level")
                .value_name("LEVEL")
                .help(t!("cli.log_level_help").to_string())
                .required(false),
        )
        .arg(
            Arg::new("json-log")
                .long("json-log")
                .value_name("FILE")
                .help(t!("cli.json_log_help").to_string())
                .required(false),
        )
        .arg(
            Arg::new("bpf-filter")
                .short('f')
                .long("bpf-filter")
                .value_name("FILTER")
                .help(bpf_help())
                .required(false),
        )
        .arg(
            Arg::new("resolve-dns")
                .long("resolve-dns")
                .help(t!("cli.resolve_dns_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("show-ptr-lookups")
                .long("show-ptr-lookups")
                .help(t!("cli.show_ptr_lookups_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("lang")
                .long("lang")
                .value_name("LOCALE")
                .help(t!("cli.lang_help").to_string())
                .required(false),
        );

    #[cfg(target_os = "linux")]
    let cmd = cmd
        .arg(
            Arg::new("no-sandbox")
                .long("no-sandbox")
                .help(t!("cli.no_sandbox_help").to_string())
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("sandbox-strict")
                .long("sandbox-strict")
                .help(t!("cli.sandbox_strict_help").to_string())
                .action(clap::ArgAction::SetTrue)
                .conflicts_with("no-sandbox"),
        );

    cmd
}
