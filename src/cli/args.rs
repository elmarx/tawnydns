use super::scope::Scope;
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
    /// generate a private key to sign tokens, or print its public key to verify them
    Keygen {
        /// print the public key of the private key (`--private-key-file`) instead of generating one
        #[arg(long)]
        public: bool,
        #[command(flatten)]
        private_key: PrivateKey,
        #[command(flatten)]
        output: Output,
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
    /// file containing the private key to sign tokens, `-` for stdin
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

/// Where to write the result.
#[derive(clap::Args)]
pub struct Output {
    /// file to write to, `-` for stdout
    #[arg(short, long, value_name = "FILE", default_value = "-")]
    pub output: super::output::Output,
    /// replace the output file if it exists
    #[arg(long)]
    pub force: bool,
}

#[derive(clap::Subcommand)]
pub enum TokenCmd {
    /// create a token
    Create {
        #[command(flatten)]
        private_key: PrivateKey,
        /// add the permission to the permissions of this token (`-` for stdin), which must be
        /// signed with the private key; an identical permission is not added twice
        #[arg(long, value_name = "TOKEN")]
        append: Option<PathBuf>,
        /// replace the token given to `--append` with the result
        #[arg(short = 'i', long, requires = "append", conflicts_with = "output")]
        in_place: bool,
        /// zone the token is valid for (a trailing dot is stripped, no further normalization)
        zone: String,
        /// what the token permits, without any of these options it has full access to the zone
        #[command(flatten)]
        scope: Scope,
        #[command(flatten)]
        output: Output,
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
