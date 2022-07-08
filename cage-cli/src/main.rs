use cage_cli::cli::{build, Command};
use clap::{AppSettings, Parser};
use human_panic::setup_panic;

#[derive(Debug, Parser)]
#[clap(
    name = "cage cli",
    author = "engineering@evervault.com",
    setting = AppSettings::ArgRequiredElseHelp,
    setting = AppSettings::DeriveDisplayOrder
)]
pub struct BaseArgs {
    /// Toggle verbose output
    #[clap(short, long, global = true)]
    pub verbose: bool,

    /// Toggle JSON output for stdout
    #[clap(long, global = true)]
    pub json: bool,

    #[clap(subcommand)]
    pub command: Command,
}

#[tokio::main]
async fn main() {
    // Use human panic to give nicer error logs in the case of a runtime panic
    setup_panic!(Metadata {
        name: env!("CARGO_PKG_NAME").into(),
        version: env!("CARGO_PKG_VERSION").into(),
        authors: "Engineering <engineering@evervault.com>".into(),
        homepage: "https://github.com/evervault/cages".into(),
    });
    let base_args = BaseArgs::parse();

    match base_args.command {
        Command::Build(build_args) => build::run(build_args).await,
    }
}
