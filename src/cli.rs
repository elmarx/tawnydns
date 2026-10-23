use http::Uri;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(clap::Subcommand)]
pub enum Cmd {
    /// run the tawnydns server
    Server {
        /// file containing the PowerDNS API key (alternatively set `PDNS_API_KEY`)
        #[arg(long, env = "PDNS_API_KEY_FILE")]
        pdns_api_key_file: Option<PathBuf>,
        #[command(flatten)]
        public_key: PublicKey,
        /// address to listen on
        #[arg(long, env = "LISTEN_ADDR", default_value = "[::1]:8082")]
        listen: SocketAddr,
        /// base URL of the PowerDNS API (http only, the path is ignored)
        #[arg(long, env = "PDNS_URL", default_value = "http://localhost:8081")]
        pdns_url: Uri,
    },
    /// manage the key pair to sign and verify tokens
    Key {
        #[command(subcommand)]
        command: KeyCmd,
    },
    /// create or inspect tenant tokens (API keys)
    Token {
        #[command(subcommand)]
        command: TokenCmd,
    },
}

/// The private key to sign tokens.
#[derive(clap::Args)]
pub struct PrivateKey {
    /// file containing the private key to sign tokens
    #[arg(
        id = "private_key_file",
        long = "private-key-file",
        value_name = "FILE",
        env = "PRIVATE_KEY_FILE",
        default_value = "tawnydns.key"
    )]
    pub file: PathBuf,
}

/// The public key to verify tokens.
#[derive(clap::Args)]
pub struct PublicKey {
    /// file containing the public key to verify tokens
    #[arg(
        id = "public_key_file",
        long = "public-key-file",
        value_name = "FILE",
        env = "PUBLIC_KEY_FILE",
        default_value = "tawnydns.pub"
    )]
    pub file: PathBuf,
}

#[derive(clap::Subcommand)]
pub enum KeyCmd {
    /// generate a public/private key pair
    Gen {
        #[command(flatten)]
        private_key: PrivateKey,
        #[command(flatten)]
        public_key: PublicKey,
    },
    /// print the public key of a private key
    Public {
        #[command(flatten)]
        private_key: PrivateKey,
    },
}

#[derive(clap::Args)]
pub struct Scope {
    /// Restrict the token to solving ACME DNS-01 challenges for this name, relative to the
    /// zone: e.g. `www` for `www.<zone>`, `@` for the zone itself or `*` for any name in the
    /// zone. Repeat for more names.
    #[arg(
        long = "acme",
        value_name = "NAME",
        conflicts_with_all = ["names", "any_name", "types", "any_type"]
    )]
    pub acme_names: Vec<String>,
    /// Restrict the token to records with this name, relative to the zone: e.g. `www` for
    /// `www.<zone>`, `@` for the zone itself or `*` for the wildcard record. Repeat for more
    /// names. Requires `--type` or `--any-type`.
    #[arg(long = "name", value_name = "NAME", conflicts_with = "any_name")]
    pub names: Vec<String>,
    /// records of any name, requires `--type` or `--any-type`
    #[arg(long)]
    pub any_name: bool,
    /// Restrict the token to records of this type, e.g. `AAAA`. Repeat for more types. Requires
    /// `--name` or `--any-name`.
    #[arg(long = "type", value_name = "TYPE", conflicts_with = "any_type")]
    pub types: Vec<String>,
    /// records of any type, requires `--name` or `--any-name`
    #[arg(long)]
    pub any_type: bool,
}

impl From<Scope> for crate::token::Scope {
    fn from(scope: Scope) -> Self {
        Self {
            acme_names: scope.acme_names,
            names: scope.names,
            any_name: scope.any_name,
            types: scope.types,
            any_type: scope.any_type,
        }
    }
}

#[derive(clap::Subcommand)]
pub enum TokenCmd {
    /// create a token
    Create {
        #[command(flatten)]
        private_key: PrivateKey,
        /// zone the token is valid for (a trailing dot is stripped, no further normalization)
        zone: String,
        /// what the token permits, without any of these options it has full access to the zone
        #[command(flatten)]
        scope: Scope,
    },
    /// inspect/validate a token
    Inspect {
        #[command(flatten)]
        public_key: PublicKey,
        /// file containing the token, `-` for stdin
        token: PathBuf,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

    #[test]
    fn scope_options_conflict() {
        for sample in [
            &["--acme", "www", "--type", "A"][..],
            &["--acme", "www", "--any-name"],
            &["--name", "a", "--any-name"],
            &["--type", "A", "--any-type"],
        ] {
            let args = ["tawnydns", "token", "create", "example.com"];

            let actual = Cli::try_parse_from(args.iter().chain(sample));

            assert!(actual.is_err(), "{sample:?}");
        }
    }
}
