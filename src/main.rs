//! Reverse proxy listening in "localhost:4000" will proxy all requests to "localhost:3000"
//! endpoint.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p example-reverse-proxy
//! ```
use axum::body::Body;
use clap::Parser;
use eros::{AnyError, Context};
use hyper_util::client::legacy::connect::HttpConnector;
use std::collections::HashMap;
use std::sync::OnceLock;

mod cli;
mod handler;
mod keygen;
mod proxy;
mod server;

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

const X_API_KEY: &str = "X-API-Key";
const ACTUAL_API_KEY: &str = "secret";

#[tokio::main]
async fn main() -> eros::Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = cli::Cli::parse();

    match args.command {
        cli::Cmd::Server => {
            server::server().await;
        }
        cli::Cmd::Keygen {
            private_key,
            public_key,
        } => keygen::keygen(private_key, public_key).context("keygen")?,
        cli::Cmd::Token { .. } => todo!(),
    }

    Ok(())
}
