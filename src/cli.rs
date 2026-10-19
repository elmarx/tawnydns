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
        /// public key to verify tenant tokens
        #[arg(long, env = "PUBLIC_KEY_FILE")]
        public_key_file: PathBuf,
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

#[derive(clap::Subcommand)]
pub enum KeyCmd {
    /// generate a public/private key pair
    Gen {
        #[arg(default_value = "private.key")]
        private_key: PathBuf,
        #[arg(default_value = "tawnydns.pub")]
        public_key: PathBuf,
    },
    /// print the public key of a private key
    Public {
        #[arg(default_value = "private.key")]
        private_key: PathBuf,
    },
}

#[derive(clap::Subcommand)]
pub enum TokenCmd {
    /// create a token
    Create {
        #[arg(default_value = "private.key", long)]
        private_key: PathBuf,
        /// zone the token is valid for (a trailing dot is stripped, no further normalization)
        zone: String,
        /// Restrict the token to solving ACME DNS-01 challenges for this name, relative to the
        /// zone: e.g. `www` for `www.<zone>`, `@` for the zone itself or `*` for any name in the
        /// zone. Repeat for more names. Without, the token has full access to the zone.
        #[arg(long = "acme", value_name = "NAME")]
        acme_names: Vec<String>,
    },
    /// inspect/validate a token
    Inspect {
        #[arg(default_value = "tawnydns.pub", long)]
        public_key: PathBuf,
        /// file containing the token, `-` for stdin
        token: PathBuf,
    },
}
