use clap::{Arg, Command};

pub fn build_cli() -> Command {
    Command::new("rustnet")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Network Monitor")
        .about("Cross-platform network monitoring tool")
        .arg(
            Arg::new("interface")
                .short('i')
                .long("interface")
                .value_name("INTERFACE")
                .help("Network interface to monitor")
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
}
