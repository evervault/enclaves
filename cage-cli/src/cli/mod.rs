use clap::Subcommand;
pub mod build;

#[derive(Debug, Subcommand)]
pub enum Command {
    Build(build::BuildArgs),
}
