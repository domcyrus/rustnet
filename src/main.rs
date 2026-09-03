use anyhow::Result;
use log::info;
use rustnet_monitor::{cli, headless, tui};

fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    if matches.get_flag("headless") {
        headless::run(&matches)?;
    } else {
        tui::run(&matches)?;
    }

    info!("RustNet Monitor shutting down");
    Ok(())
}
