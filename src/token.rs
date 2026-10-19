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
    /// without trailing dot
    pub zone: String,
    pub permission: Permission,
}

/// What the holder of a token may do with its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    /// full access to the zone
    Owner,
    /// solve ACME DNS-01 challenges for these names, relative to the zone (see [`validate_acme_name`])
    Acme(Vec<String>),
}

impl Permission {
    /// Numbers in the token, never change or reuse them.
    const OWNER: u8 = 255;
    const ACME: u8 = 1;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ClaimError {
    #[error("unknown permission {0}")]
    UnknownPermission(u8),
    #[error("acme names are only allowed with the acme permission")]
    UnexpectedAcmeNames,
    #[error("the acme permission requires at least one name")]
    MissingAcmeNames,
    #[error("invalid acme name {0:?}")]
    InvalidAcmeName(String),
}

/// Checks a name of the acme permission, relative to the zone: `@` for the apex, `*` for any name
/// of the zone, or lowercase labels like `www` or `a.b`, without trailing dot.
pub fn validate_acme_name(name: &str) -> Result<(), ClaimError> {
    let valid_label = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    };

    if name == "@" || name == "*" || (name.len() <= 253 && name.split('.').all(valid_label)) {
        Ok(())
    } else {
        Err(ClaimError::InvalidAcmeName(name.to_string()))
    }
}

/// The claim as it is encoded in the token, kept small.
#[derive(Deserialize, Serialize)]
struct RawClaim {
    #[serde(rename = "z")]
    zone: String,
    #[serde(rename = "p")]
    permission: u8,
    #[serde(rename = "a", default, skip_serializing_if = "Vec::is_empty")]
    acme: Vec<String>,
}

impl TryFrom<RawClaim> for Claim {
    type Error = ClaimError;

    fn try_from(raw: RawClaim) -> Result<Self, Self::Error> {
        let permission = match raw.permission {
            Permission::OWNER if raw.acme.is_empty() => Permission::Owner,
            Permission::OWNER => return Err(ClaimError::UnexpectedAcmeNames),
            Permission::ACME if raw.acme.is_empty() => return Err(ClaimError::MissingAcmeNames),
            Permission::ACME => {
                raw.acme
                    .iter()
                    .try_for_each(|name| validate_acme_name(name))?;
                Permission::Acme(raw.acme)
            }
            other => return Err(ClaimError::UnknownPermission(other)),
        };

        Ok(Self {
            zone: raw.zone,
            permission,
        })
    }
}

impl From<Claim> for RawClaim {
    fn from(claim: Claim) -> Self {
        let (permission, acme) = match claim.permission {
            Permission::Owner => (Permission::OWNER, Vec::new()),
            Permission::Acme(names) => (Permission::ACME, names),
        };

        Self {
            zone: claim.zone,
            permission,
            acme,
        }
    }
}

/// Signs the claim, after stripping a trailing dot of the zone. Fails for a claim that would not
/// decode again.
pub fn encode_token(private_key_pem: &[u8], claim: &Claim) -> eros::Result<String> {
    let key = EncodingKey::from_ed_pem(private_key_pem).context("decode private key")?;
    let claim = Claim {
        zone: claim
            .zone
            .strip_suffix('.')
            .unwrap_or(&claim.zone)
            .to_string(),
        permission: claim.permission.clone(),
    };
    let claim = Claim::try_from(RawClaim::from(claim)).context("invalid claim")?;
    let token =
        encode(&Header::new(Algorithm::EdDSA), &claim, &key).context("encoding the token")?;

    Ok(token)
}

pub fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;

    let token = decode::<Claim>(token.trim(), &key, &VALIDATION).context("decoding token")?;

    Ok(token)
}

/// Creates a token with full access to `zone`, or, if `acme_names` are given, only to solve ACME
/// challenges for these names (relative to the zone, case-insensitive).
pub fn create(
    private_key_file: PathBuf,
    zone: String,
    acme_names: &[String],
) -> eros::Result<String> {
    let permission = if acme_names.is_empty() {
        Permission::Owner
    } else {
        let mut names = Vec::with_capacity(acme_names.len());
        for name in acme_names.iter().map(|n| n.to_ascii_lowercase()) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Permission::Acme(names)
    };

    let key = std::fs::read(private_key_file).context("open private key file")?;

    encode_token(&key, &Claim { zone, permission })
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

    fn owner(zone: &str) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Owner,
        }
    }

    fn acme(zone: &str, names: &[&str]) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Acme(names.iter().map(ToString::to_string).collect()),
        }
    }

    #[test]
    fn roundtrip() {
        let (private_key, public_key) = generate().unwrap();

        for sample in [owner("example.com"), acme("example.com", &["www", "@"])] {
            let token = encode_token(private_key.as_bytes(), &sample).unwrap();
            let actual = decode_token(public_key.as_bytes(), &format!("{token}\n")).unwrap();

            assert_eq!(actual.header.alg, Algorithm::EdDSA);
            assert_eq!(actual.claims, sample);
        }
    }

    #[test]
    fn encode_strips_trailing_dot() {
        let (private_key, public_key) = generate().unwrap();
        let sample = owner("example.com.");

        let token = encode_token(private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &token).unwrap();

        assert_eq!(actual.claims.zone, "example.com");
    }

    #[test]
    fn encode_rejects_claim_that_would_not_decode() {
        let (private_key, _) = generate().unwrap();

        for sample in [
            acme("example.com", &[]),
            acme("example.com", &["WWW"]),
            acme("example.com", &["www.example.com."]),
        ] {
            let actual = encode_token(private_key.as_bytes(), &sample);

            assert!(actual.is_err(), "{sample:?}");
        }
    }

    #[test]
    fn rejects_token_signed_by_other_key() {
        let (_, public_key) = generate().unwrap();
        let (other_private_key, _) = generate().unwrap();
        let sample = owner("example.com");

        let token = encode_token(other_private_key.as_bytes(), &sample).unwrap();
        let actual = decode_token(public_key.as_bytes(), &token);

        assert!(actual.is_err());
    }

    #[test]
    fn rejects_other_algorithm() {
        let (_, public_key) = generate().unwrap();
        let sample = owner("example.com");
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
        use serde_json::{Value, json};

        #[test]
        fn encodes_permissions_as_numbers() {
            for (sample, expected) in [
                (owner("example.com"), json!({"z": "example.com", "p": 255})),
                (
                    acme("example.com", &["www", "@"]),
                    json!({"z": "example.com", "p": 1, "a": ["www", "@"]}),
                ),
            ] {
                let actual = serde_json::to_value(&sample).unwrap();

                assert_eq!(actual, expected);
            }
        }

        #[test]
        fn decodes_permissions() {
            for (sample, expected) in [
                (json!({"z": "example.com", "p": 255}), owner("example.com")),
                (
                    json!({"z": "example.com", "p": 255, "a": []}),
                    owner("example.com"),
                ),
                (
                    json!({"z": "example.com", "p": 1, "a": ["www", "a.b", "@", "*", "_x-1"]}),
                    acme("example.com", &["www", "a.b", "@", "*", "_x-1"]),
                ),
            ] {
                let actual: Claim = serde_json::from_value(sample).unwrap();

                assert_eq!(actual, expected);
            }
        }

        fn rejects(samples: &[Value]) {
            for sample in samples {
                let actual = serde_json::from_value::<Claim>(sample.clone());

                assert!(actual.is_err(), "{sample}");
            }
        }

        #[test]
        fn rejects_invalid_permission() {
            rejects(&[
                json!({"z": "example.com"}),
                json!({"z": "example.com", "p": 0}),
                json!({"z": "example.com", "p": 256}),
                json!({"z": "example.com", "p": -1}),
                json!({"z": "example.com", "p": "255"}),
                json!({"z": "example.com", "p": null}),
            ]);
        }

        #[test]
        fn rejects_invalid_zone() {
            rejects(&[
                json!({"p": 255}),
                json!({"z": ["example.com"], "p": 255}),
                json!({"z": null, "p": 255}),
            ]);
        }

        #[test]
        fn rejects_names_for_owner() {
            rejects(&[json!({"z": "example.com", "p": 255, "a": ["www"]})]);
        }

        #[test]
        fn rejects_acme_without_names() {
            rejects(&[
                json!({"z": "example.com", "p": 1}),
                json!({"z": "example.com", "p": 1, "a": []}),
                json!({"z": "example.com", "p": 1, "a": null}),
            ]);
        }

        #[test]
        fn rejects_invalid_acme_names() {
            for name in [
                "",
                ".",
                "www.",
                ".www",
                "a..b",
                "WWW",
                "*.www",
                "www.*",
                "@.www",
                "a b",
                "w\\119w",
                "ä",
                &"a".repeat(64),
            ] {
                rejects(&[json!({"z": "example.com", "p": 1, "a": ["www", name]})]);
            }
        }

        #[test]
        fn rejects_duplicate_fields() {
            for sample in [
                r#"{"z": "example.com", "p": 1, "p": 255, "a": ["www"]}"#,
                r#"{"z": "example.com", "p": 1, "a": ["www"], "a": ["*"]}"#,
                r#"{"z": "example.com", "z": "example.org", "p": 255}"#,
            ] {
                let actual = serde_json::from_str::<Claim>(sample);

                assert!(actual.is_err(), "{sample}");
            }
        }
    }
}
