use eros::Context;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, decode, encode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Read;
use std::path::PathBuf;
use std::sync::LazyLock;

pub static VALIDATION: LazyLock<jsonwebtoken::Validation> = LazyLock::new(|| {
    let mut validation = jsonwebtoken::Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();
    validation
});

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Claim {
    #[serde(rename = "z")]
    pub zones: Vec<String>,
}

pub fn encode_token(private_key_pem: &[u8], claim: &Claim) -> eros::Result<String> {
    let key = EncodingKey::from_ed_pem(private_key_pem).context("decode private key")?;
    let token =
        encode(&Header::new(Algorithm::EdDSA), claim, &key).context("encoding the token")?;

    Ok(token)
}

pub fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;

    let token = decode::<Claim>(token.trim(), &key, &VALIDATION).context("decoding token")?;

    Ok(token)
}

pub fn create(private_key_file: PathBuf, zone: String) -> eros::Result<String> {
    let key = std::fs::read(private_key_file).context("open private key file")?;

    encode_token(&key, &Claim { zones: vec![zone] })
}

pub fn inspect(public_key_file: PathBuf, token: PathBuf) -> eros::Result<TokenData<Claim>> {
    let token = if token == *"-" {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("read token from stdin")?;
        input
    } else {
        std::fs::read_to_string(token).context("read token from disk")?
    };
    let public_key = std::fs::read(public_key_file).context("open public key file")?;

    decode_token(&public_key, &token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate;

    #[test]
    fn roundtrip() {
        let (private_key, public_key) = generate().unwrap();
        let sample = Claim {
            zones: vec!["example.com".to_string()],
        };

        let token = encode_token(private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &format!("{token}\n")).unwrap();

        assert_eq!(actual.header.alg, Algorithm::EdDSA);
        assert_eq!(actual.claims.zones, sample.zones);
    }

    #[test]
    fn rejects_token_signed_by_other_key() {
        let (_, public_key) = generate().unwrap();
        let (other_private_key, _) = generate().unwrap();
        let sample = Claim {
            zones: vec!["example.com".to_string()],
        };

        let token = encode_token(other_private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &token);

        assert!(actual.is_err());
    }

    #[test]
    fn rejects_other_algorithm() {
        let (_, public_key) = generate().unwrap();
        let sample = Claim {
            zones: vec!["example.com".to_string()],
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &sample,
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let actual = decode_token(public_key.as_bytes(), &token);

        assert!(actual.is_err());
    }
}
