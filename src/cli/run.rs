use super::args::{Cli, Cmd, Output, TokenCmd};
use super::{key, output, token};
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
        Cmd::Keygen {
            public,
            private_key,
            output,
        } => {
            let Output { output, force } = output;
            if public {
                let public_key = key::public(&private_key.file)?;
                output
                    .write(&public_key, 0o644, force)
                    .context("write public key")?;
            } else {
                let private_key = key::private()?;
                output
                    .write(&private_key, 0o600, force)
                    .context("write private key")?;
            }
        }
        Cmd::Token {
            command:
                TokenCmd::Create {
                    private_key,
                    append,
                    in_place,
                    zone,
                    scope,
                    output,
                },
        } => {
            // clap ensures `--in-place` comes with `--append`
            let in_place = append.clone().filter(|_| in_place);
            if let Some(path) = &in_place {
                eros::ensure!(path != "-", "--in-place needs a token file, not stdin");
            }
            let token = token::create(&private_key.file, append.as_deref(), zone, &scope)?;
            let token = format!("{token}\n");
            match in_place {
                Some(path) => output::replace(&path, &token, 0o600).context("replace token")?,
                None => output
                    .output
                    .write(&token, 0o600, output.force)
                    .context("write token")?,
            }
        }
        Cmd::Token {
            command: TokenCmd::Inspect { public_key, token },
        } => {
            println!("{:#?}", token::inspect(&public_key.file, &token)?);
        }
    }

    Ok(())
}
