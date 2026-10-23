use super::args::{Cli, Cmd, KeyCmd, TokenCmd};
use super::{key, token};
use crate::server;
use eros::{AnyError, Context};

pub async fn run(cli: Cli) -> eros::Result<(), AnyError> {
    match cli.command {
        Cmd::Server {
            pdns_api_key_file,
            public_key,
            listen,
            pdns_url,
        } => {
            let pdns_api_key = server::resolve_pdns_api_key(pdns_api_key_file)?;
            server::run(pdns_api_key, public_key.file, listen, pdns_url).await?;
        }
        Cmd::Key {
            command:
                KeyCmd::Gen {
                    private_key,
                    public_key,
                    force,
                },
        } => key::keygen(&private_key.file, &public_key.file, force).context("keygen")?,
        Cmd::Key {
            command:
                KeyCmd::Public {
                    private_key,
                    output,
                },
        } => output
            .output
            .write(&key::public(private_key.file)?, 0o644, output.force)
            .context("write public key")?,
        Cmd::Token {
            command:
                TokenCmd::Create {
                    private_key,
                    zone,
                    scope,
                    output,
                },
        } => {
            let token = token::create(private_key.file, zone, &scope)?;
            output
                .output
                .write(&format!("{token}\n"), 0o600, output.force)
                .context("write token")?;
        }
        Cmd::Token {
            command: TokenCmd::Inspect { public_key, token },
        } => {
            println!("{:#?}", token::inspect(public_key.file, token)?);
        }
    }

    Ok(())
}
