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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawClaim", into = "RawClaim")]
pub struct Claim {
    pub zones: Vec<String>,
    pub permission: Permission,
}

/// What the holder of a token may do with its zones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// full access to the zones
    Owner,
}

impl Permission {
    /// Numbers in the token, never change or reuse them.
    const OWNER: u8 = 255;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("unknown permission {0}")]
    UnknownPermission(u8),
}

/// The claim as it is encoded in the token, kept small.
#[derive(Deserialize, Serialize)]
struct RawClaim {
    #[serde(rename = "z")]
    zones: Vec<String>,
    #[serde(rename = "p")]
    permission: u8,
}

impl TryFrom<RawClaim> for Claim {
    type Error = ClaimError;

    fn try_from(raw: RawClaim) -> Result<Self, Self::Error> {
        let permission = match raw.permission {
            Permission::OWNER => Permission::Owner,
            other => return Err(ClaimError::UnknownPermission(other)),
        };

        Ok(Self {
            zones: raw.zones,
            permission,
        })
    }
}

impl From<Claim> for RawClaim {
    fn from(claim: Claim) -> Self {
        let permission = match claim.permission {
            Permission::Owner => Permission::OWNER,
        };

        Self {
            zones: claim.zones,
            permission,
        }
    }
}

pub fn encode_token(private_key_pem: &[u8], claim: &Claim) -> eros::Result<String> {
    let key = EncodingKey::from_ed_pem(private_key_pem).context("decode private key")?;
    let claim = Claim {
        zones: claim
            .zones
            .iter()
            .map(|z| z.strip_suffix('.').unwrap_or(z).to_string())
            .collect(),
        permission: claim.permission,
    };
    let token =
        encode(&Header::new(Algorithm::EdDSA), &claim, &key).context("encoding the token")?;

    Ok(token)
}

pub fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;

    let token = decode::<Claim>(token.trim(), &key, &VALIDATION).context("decoding token")?;

    Ok(token)
}

pub fn create(private_key_file: PathBuf, zone: String) -> eros::Result<String> {
    let key = std::fs::read(private_key_file).context("open private key file")?;

    let claim = Claim {
        zones: vec![zone],
        permission: Permission::Owner,
    };

    encode_token(&key, &claim)
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
            permission: Permission::Owner,
        };

        let token = encode_token(private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &format!("{token}\n")).unwrap();

        assert_eq!(actual.header.alg, Algorithm::EdDSA);
        assert_eq!(actual.claims, sample);
    }

    #[test]
    fn encode_strips_trailing_dot() {
        let (private_key, public_key) = generate().unwrap();
        let sample = Claim {
            zones: vec!["example.com.".to_string(), "example.org".to_string()],
            permission: Permission::Owner,
        };

        let token = encode_token(private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &token).unwrap();

        assert_eq!(actual.claims.zones, vec!["example.com", "example.org"]);
    }

    #[test]
    fn rejects_token_signed_by_other_key() {
        let (_, public_key) = generate().unwrap();
        let (other_private_key, _) = generate().unwrap();
        let sample = Claim {
            zones: vec!["example.com".to_string()],
            permission: Permission::Owner,
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
            permission: Permission::Owner,
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

    mod claim {
        use super::*;
        use serde_json::json;

        #[test]
        fn owner_is_encoded_as_255() {
            let sample = Claim {
                zones: vec!["example.com".to_string()],
                permission: Permission::Owner,
            };

            let actual = serde_json::to_value(&sample).unwrap();

            let expected = json!({"z": ["example.com"], "p": 255});
            assert_eq!(actual, expected);
        }

        #[test]
        fn decodes_owner() {
            let sample = json!({"z": ["example.com"], "p": 255});

            let actual: Claim = serde_json::from_value(sample).unwrap();

            let expected = Claim {
                zones: vec!["example.com".to_string()],
                permission: Permission::Owner,
            };
            assert_eq!(actual, expected);
        }

        #[test]
        fn rejects_invalid_permission() {
            for sample in [
                json!({"z": ["example.com"]}),
                json!({"z": ["example.com"], "p": 0}),
                json!({"z": ["example.com"], "p": 256}),
                json!({"z": ["example.com"], "p": -1}),
                json!({"z": ["example.com"], "p": "255"}),
                json!({"z": ["example.com"], "p": null}),
            ] {
                let actual = serde_json::from_value::<Claim>(sample.clone());

                assert!(actual.is_err(), "{sample}");
            }
        }

        #[test]
        fn rejects_duplicate_permission() {
            let sample = r#"{"z": ["example.com"], "p": 0, "p": 255}"#;

            let actual = serde_json::from_str::<Claim>(sample);

            assert!(actual.is_err());
        }
    }
}
