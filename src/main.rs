use crate::cli::{KeyCmd, TokenCmd};
use crate::config::resolve_pdns_api_key;
use clap::Parser;
use eros::{AnyError, Context};

mod claim;
mod cli;
mod config;
mod content_type;
mod dns;
mod jwt;
mod keygen;
mod output;
mod pdns;
mod permissions;
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
            public_key,
            listen,
            pdns_url,
        } => {
            let pdns_api_key = resolve_pdns_api_key(pdns_api_key_file)?;
            server::run(pdns_api_key, public_key.file, listen, pdns_url).await?;
        }
        cli::Cmd::Key {
            command:
                KeyCmd::Gen {
                    private_key,
                    public_key,
                    force,
                },
        } => keygen::keygen(&private_key.file, &public_key.file, force).context("keygen")?,
        cli::Cmd::Key {
            command: KeyCmd::Public {
                private_key,
                output,
            },
        } => output
            .output
            .write(&keygen::public(private_key.file)?, 0o644, output.force)
            .context("write public key")?,
        cli::Cmd::Token {
            command:
                TokenCmd::Create {
                    private_key,
                    zone,
                    scope,
                    output,
                },
        } => {
            let token = token::create(private_key.file, zone, &scope.into())?;
            output
                .output
                .write(&format!("{token}\n"), 0o600, output.force)
                .context("write token")?;
        }
        cli::Cmd::Token {
            command: TokenCmd::Inspect { public_key, token },
        } => {
            println!("{:#?}", token::inspect(public_key.file, token)?);
        }
    }

    Ok(())
}
