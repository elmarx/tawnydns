//! Reverse proxy listening in "localhost:4000" will proxy all requests to "localhost:3000"
//! endpoint.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p example-reverse-proxy
//! ```
use crate::cli::TokenCmd;
use crate::config::resolve_pdns_api_key;
use clap::Parser;
use eros::{AnyError, Context};
use std::collections::HashMap;
use std::sync::OnceLock;

mod cli;
mod config;
mod handler;
mod keygen;
mod proxy;
mod server;
mod token;

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

const X_API_KEY: &str = "X-API-Key";
#[tokio::main]
async fn main() -> eros::Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = cli::Cli::parse();

    match args.command {
        cli::Cmd::Server { pdns_api_key_file } => {
            let pdns_api_key = resolve_pdns_api_key(pdns_api_key_file)?;
            server::server(pdns_api_key).await;
        }
        cli::Cmd::Keygen {
            private_key,
            public_key,
        } => keygen::keygen(private_key, public_key).context("keygen")?,
        cli::Cmd::Token {
            command: TokenCmd::Create { private_key, zone },
        } => println!("{}", token::create(private_key, zone)?),
        cli::Cmd::Token {
            command: TokenCmd::Inspect { public_key, token },
        } => {
            println!("{:#?}", token::inspect(public_key, token)?);
        }
    }

    Ok(())
}
