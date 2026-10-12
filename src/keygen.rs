use ed25519_dalek::SigningKey;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use getrandom::{SysRng, rand_core::UnwrapErr};
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

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

pub fn keygen(private_key_path: PathBuf, public_key_path: PathBuf) -> eros::Result<()> {
    let (private_key, public_key) = generate()?;

    // create_new refuses to overwrite; mode only applies on creation
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        // .create_new(true) // TODO: make this configurable (--force-overwrite flag or similar)
        .mode(0o600)
        .open(private_key_path)
        .context("open private key file")?;
    file.write_all(private_key.as_bytes())
        .context("writing the private key")?;

    fs::write(public_key_path, &public_key).context("writing the public key")?;

    Ok(())
}
