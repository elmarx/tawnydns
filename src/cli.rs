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
    Server {
        #[arg(long, env = "PDNS_API_KEY_FILE")]
        pdns_api_key_file: Option<PathBuf>,
        #[arg(long, env = "PUBLIC_KEY_FILE")]
        public_key_file: PathBuf,
        /// address to listen on
        #[arg(long, env = "LISTEN_ADDR", default_value = "[::1]:8082")]
        listen: SocketAddr,
        /// base URL of the PowerDNS API (http only, the path is ignored)
        #[arg(long, env = "PDNS_URL", default_value = "http://localhost:8081")]
        pdns_url: Uri,
    },
    Keygen {
        #[arg(default_value = "private.key")]
        private_key: PathBuf,
        #[arg(default_value = "tawnydns.pub")]
        public_key: PathBuf,
    },
    Token {
        #[command(subcommand)]
        command: TokenCmd,
    },
}

#[derive(clap::Subcommand)]
pub enum TokenCmd {
    /// create a token
    Create {
        #[arg(default_value = "private.key", long)]
        private_key: PathBuf,
        /// zone to create the token for. No normalization/validation happens, just the trailing dot will be stripped (and this will be taken in account later)
        zone: String,
    },
    /// inspect/validate a token
    Inspect {
        #[arg(default_value = "tawnydns.pub", long)]
        public_key: PathBuf,
        token: PathBuf,
    },
}
