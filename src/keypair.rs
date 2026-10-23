//! The ed25519 key pair to sign and verify tokens, as PEM.

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use getrandom::{SysRng, rand_core::UnwrapErr};

/// generate a new keypair, returned as PEM: `(private, public)`
pub fn generate() -> eros::Result<(Zeroizing<String>, String)> {
    let mut csprng = UnwrapErr(SysRng);
    let signing_key = SigningKey::generate(&mut csprng);

    let private_key = signing_key
        .to_pkcs8_pem(LineEnding::default())
        .context("private key to pkcs8")?;
    let public_key = public_pem(&signing_key)?;

    Ok((private_key, public_key))
}

/// derive the public key (PEM) from a private key (PEM)
pub fn public_key_pem(private_key_pem: &str) -> eros::Result<String> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).context("decode private key")?;
    public_pem(&signing_key)
}

fn public_pem(signing_key: &SigningKey) -> eros::Result<String> {
    let public_key = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::default())
        .context("public key to pem")?;

    Ok(public_key)
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
