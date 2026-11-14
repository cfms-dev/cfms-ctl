//! Entrypoint for the `cfms-ctl` binary.

use std::process::ExitCode;
use clap::Parser;
use cfms_ctl::cli::Cli;
use cfms_ctl::ops;
use cfms_ctl::ui::UiConsole;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let default_directive = if cli.global.verbose {
        "cfms_ctl=debug,info"
    } else {
        "cfms_ctl=warn"
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_directive));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .without_time()
        .init();

    let ui = UiConsole::new(cli.global.output);

    match ops::execute(cli, &ui).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            ui.render_error(&err);
            ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1))
        }
    }
}
