use clap::Parser;
use eros::AnyError;

mod claim;
mod cli;
mod content_type;
mod dns;
#[expect(dead_code, reason = "not used by an endpoint yet")]
mod dyndns;
mod jwt;
mod keypair;
mod pdns;
mod permissions;
mod policy;
mod server;

#[tokio::main]
async fn main() -> eros::Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    cli::run(cli::Cli::parse()).await
}
