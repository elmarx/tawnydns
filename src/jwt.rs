//! Signing and verifying tokens (JWTs signed with Ed25519), independent of the payload.

use jsonwebtoken::errors::Error;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Ed25519 only, tokens don't expire and need no registered claims.
static VALIDATION: LazyLock<Validation> = LazyLock::new(|| {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.required_spec_claims = HashSet::new();
    validation
});

pub fn encode<C: Serialize>(key: &EncodingKey, claims: &C) -> Result<String, Error> {
    jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, key)
}

pub fn decode<C: DeserializeOwned>(
    key: &DecodingKey,
    token: impl AsRef<[u8]>,
) -> Result<TokenData<C>, Error> {
    jsonwebtoken::decode(token, key, &VALIDATION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::generate;
    use serde_json::{Value, json};

    fn keys() -> (EncodingKey, DecodingKey) {
        let (private_key, public_key) = generate().unwrap();
        (
            EncodingKey::from_ed_pem(private_key.as_bytes()).unwrap(),
            DecodingKey::from_ed_pem(public_key.as_bytes()).unwrap(),
        )
    }

    #[test]
    fn roundtrip() {
        let (encoding_key, decoding_key) = keys();
        let sample = json!({"1": [{"o": "example.com"}]});

        let token = encode(&encoding_key, &sample).unwrap();
        let actual = decode::<Value>(&decoding_key, token).unwrap();

        assert_eq!(actual.header.alg, Algorithm::EdDSA);
        assert_eq!(actual.claims, sample);
    }

    #[test]
    fn rejects_token_signed_by_other_key() {
        let (_, decoding_key) = keys();
        let (other_encoding_key, _) = keys();

        let token = encode(&other_encoding_key, &json!({})).unwrap();
        let actual = decode::<Value>(&decoding_key, token);

        assert!(actual.is_err());
    }

    #[test]
    fn rejects_other_algorithm() {
        let (_, decoding_key) = keys();
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &json!({}),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();

        let actual = decode::<Value>(&decoding_key, token);

        assert!(actual.is_err());
    }
}
