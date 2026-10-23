//! Creating and inspecting tokens on the command line.

use super::input;
use super::scope::{Scope, claim_for};
use crate::claim::Claim;
use crate::jwt;
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use std::path::Path;

/// Creates a token, see [`claim_for`].
pub fn create(private_key_file: &Path, zone: String, scope: &Scope) -> eros::Result<String> {
    let claim = claim_for(zone, scope).context("invalid claim")?;
    let key = Zeroizing::new(input::read_to_string(private_key_file).context("read private key")?);
    encode_token(key.as_bytes(), &claim)
}

pub fn inspect(public_key_file: &Path, token: &Path) -> eros::Result<TokenData<Claim>> {
    let token = input::read_to_string(token).context("read token")?;

    let public_key = std::fs::read(public_key_file).context("open public key file")?;
    decode_token(&public_key, &token)
}

fn encode_token(private_key_pem: &[u8], claim: &Claim) -> eros::Result<String> {
    let key = EncodingKey::from_ed_pem(private_key_pem).context("decode private key")?;
    let token = jwt::encode(&key, claim).context("encoding the token")?;
    Ok(token)
}

fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;
    let token = jwt::decode::<Claim>(&key, token.trim()).context("decoding token")?;
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::fixtures::claim;
    use crate::keypair::generate;
    use crate::permissions::fixtures::{acme, owner};

    #[test]
    fn roundtrip() {
        let (private_key, public_key) = generate().unwrap();
        for sample in [
            claim(vec![owner("example.com")]),
            claim(vec![acme("example.com", &["www", "@"])]),
            claim(vec![owner("example.com"), acme("example.org", &["*"])]),
        ] {
            let token = encode_token(private_key.as_bytes(), &sample).unwrap();

            let actual = decode_token(public_key.as_bytes(), &format!("{token}\n")).unwrap();

            assert_eq!(actual.claims, sample);
        }
    }
}
