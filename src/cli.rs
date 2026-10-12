#[derive(clap::Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(clap::Subcommand)]
pub enum Cmd {
    Server,
    Keygen,
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
