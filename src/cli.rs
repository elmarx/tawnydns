use std::path::PathBuf;

#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(clap::Subcommand)]
pub enum Cmd {
    Server,
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
    Create,
    Inspect,
}
