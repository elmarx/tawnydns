use crate::output;
use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use getrandom::{SysRng, rand_core::UnwrapErr};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// generate a new keypair, returned as PEM: `(private, public)`
pub fn generate() -> eros::Result<(Zeroizing<String>, String)> {
    let mut csprng = UnwrapErr(SysRng);
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let private_key = signing_key
        .to_pkcs8_pem(LineEnding::default())
        .context("private key to pkcs8")?;
    let public_key = verifying_key
        .to_public_key_pem(LineEnding::default())
        .context("public key to pem")?;

    Ok((private_key, public_key))
}

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

/// derive the public key (PEM) from a private key (PEM)
fn public_key_pem(private_key_pem: &str) -> eros::Result<String> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).context("decode private key")?;

    let public_key = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::default())
        .context("public key to pem")?;

    Ok(public_key)
}

pub fn public(private_key_path: PathBuf) -> eros::Result<String> {
    let private_key =
        Zeroizing::new(fs::read_to_string(private_key_path).context("read private key file")?);

    public_key_pem(&private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_the_public_key_of_a_generated_key_pair() {
        let (private_key, public_key) = generate().unwrap();

        let actual = public_key_pem(&private_key).unwrap();

        assert_eq!(actual, public_key);
    }
}
