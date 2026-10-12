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
        zone: String,
    },
    /// inspect/validate a token
    Inspect {
        #[arg(default_value = "tawnydns.pub", long)]
        public_key: PathBuf,
        token: PathBuf,
    },
}
