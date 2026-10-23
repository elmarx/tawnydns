//! Generating keys on the command line.

use super::input;
use crate::keypair::{generate, public_key_pem};
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use std::path::Path;

/// A new private key (PEM).
pub fn private() -> eros::Result<Zeroizing<String>> {
    let (private_key, _) = generate()?;
    Ok(private_key)
}

/// The public key (PEM) of the private key in `private_key_file`, `-` is stdin.
pub fn public(private_key_file: &Path) -> eros::Result<String> {
    let private_key =
        Zeroizing::new(input::read_to_string(private_key_file).context("read private key")?);

    public_key_pem(&private_key)
}
