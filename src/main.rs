use anyhow::Result;
use log::info;
use rustnet_monitor::{bootstrap, cli, tui};

fn main() -> Result<()> {
    let matches = cli::build_cli().get_matches();

    let prepared = bootstrap::prepare(&matches, true)?;
    tui::run(&matches, prepared)?;

    info!("RustNet Monitor shutting down");
    Ok(())
}
