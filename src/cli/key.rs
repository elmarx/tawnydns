//! Managing the key pair on the command line.

use super::output;
use crate::keypair::{generate, public_key_pem};
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn keygen(private_key_path: &Path, public_key_path: &Path, force: bool) -> eros::Result<()> {
    let (private_key, public_key) = generate()?;

    let mut public_file =
        output::create(public_key_path, 0o644, force).context("create public key file")?;
    // the public key can be derived again, so it is removed if the private key can't be created
    let mut private_file = output::create(private_key_path, 0o600, force)
        .inspect_err(|_| {
            let _ = fs::remove_file(public_key_path);
        })
        .context("create private key file")?;

    private_file
        .write_all(private_key.as_bytes())
        .context("writing the private key")?;
    public_file
        .write_all(public_key.as_bytes())
        .context("writing the public key")?;

    Ok(())
}

pub fn public(private_key_path: PathBuf) -> eros::Result<String> {
    let private_key =
        Zeroizing::new(fs::read_to_string(private_key_path).context("read private key file")?);

    public_key_pem(&private_key)
}
