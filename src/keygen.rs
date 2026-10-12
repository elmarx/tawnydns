use std::path::PathBuf;

pub fn keygen(private_key: PathBuf, public_key: PathBuf) {
    tracing::info!(?private_key, ?public_key, "Hello World!");
}
