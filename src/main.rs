use crate::cli::{KeyCmd, TokenCmd};
use crate::config::resolve_pdns_api_key;
use clap::Parser;
use eros::{AnyError, Context};

mod cli;
mod config;
mod content_type;
mod keygen;
mod pdns;
mod policy;
mod server;
mod token;

#[tokio::main]
async fn main() -> eros::Result<(), AnyError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = cli::Cli::parse();

    match args.command {
        cli::Cmd::Server {
            pdns_api_key_file,
            public_key_file: public_key,
            listen,
            pdns_url,
        } => {
            let pdns_api_key = resolve_pdns_api_key(pdns_api_key_file)?;
            server::run(pdns_api_key, public_key, listen, pdns_url).await?;
        }
        cli::Cmd::Key {
            command:
                KeyCmd::Gen {
                    private_key,
                    public_key,
                },
        } => keygen::keygen(private_key, public_key).context("keygen")?,
        cli::Cmd::Key {
            command: KeyCmd::Public { private_key },
        } => print!("{}", keygen::public(private_key)?),
        cli::Cmd::Token {
            command:
                TokenCmd::Create {
                    private_key,
                    zone,
                    acme_names,
                },
        } => println!("{}", token::create(private_key, zone, &acme_names)?),
        cli::Cmd::Token {
            command: TokenCmd::Inspect { public_key, token },
        } => {
            println!("{:#?}", token::inspect(public_key, token)?);
        }
    }

    Ok(())
}
