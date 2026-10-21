//! Creating and inspecting tokens on the command line.

use crate::claim::Claim;
use crate::jwt;
use crate::permissions::Permission;
use eros::Context;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use std::io::Read;
use std::path::PathBuf;

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
    let claim = claim.validated().context("invalid claim")?;
    let token = jwt::encode(&key, &claim).context("encoding the token")?;

    Ok(token)
}

pub fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;

    let token = jwt::decode::<Claim>(&key, token.trim()).context("decoding token")?;

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
}
