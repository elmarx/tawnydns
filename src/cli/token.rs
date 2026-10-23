//! Creating and inspecting tokens on the command line.

use super::input;
use super::scope::{Scope, permission_for};
use crate::claim::Claim;
use crate::jwt;
use crate::keypair::public_key_pem;
use ed25519_dalek::pkcs8::spki::der::zeroize::Zeroizing;
use eros::Context;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use std::path::Path;

/// Creates a token with the permission for `zone` and `scope` (see [`permission_for`]). With
/// `append`, the permission is added to the permissions of that token, which must be signed with
/// the private key. An identical permission is not added twice.
pub fn create(
    private_key_file: &Path,
    append: Option<&Path>,
    zone: String,
    scope: &Scope,
) -> eros::Result<String> {
    let permission = permission_for(zone, scope).context("invalid permission")?;
    eros::ensure!(
        private_key_file != "-" || append.is_none_or(|token_file| token_file != "-"),
        "the private key and the token to append to can't both be read from stdin"
    );
    let private_key =
        Zeroizing::new(input::read_to_string(private_key_file).context("read private key")?);

    let mut claim = match append {
        Some(token_file) => {
            let token = input::read_to_string(token_file).context("read token to append to")?;
            let public_key = public_key_pem(&private_key)?;
            decode_token(public_key.as_bytes(), &token)
                .context("verify token to append to")?
                .claims
        }
        None => Claim {
            permissions: Vec::new(),
        },
    };
    if !claim.permissions.contains(&permission) {
        claim.permissions.push(permission);
    }

    encode_token(private_key.as_bytes(), &claim)
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

    mod create {
        use super::*;
        use std::fs;
        use std::path::PathBuf;
        use tempfile::TempDir;

        struct Keys {
            dir: TempDir,
            public_key: String,
        }

        impl Keys {
            fn new() -> Self {
                let dir = tempfile::tempdir().unwrap();
                let (private_key, public_key) = generate().unwrap();
                fs::write(dir.path().join("key"), private_key.as_bytes()).unwrap();
                Self { dir, public_key }
            }

            fn private_key_file(&self) -> PathBuf {
                self.dir.path().join("key")
            }

            /// Creates a token for `zone` with full access, appended to the token in `append`.
            fn create(&self, append: Option<&str>, zone: &str) -> eros::Result<String> {
                let token_file = append.map(|token| {
                    let path = self.dir.path().join("token");
                    fs::write(&path, token).unwrap();
                    path
                });
                create(
                    &self.private_key_file(),
                    token_file.as_deref(),
                    zone.to_string(),
                    &Scope::default(),
                )
            }

            fn decode(&self, token: &str) -> Claim {
                decode_token(self.public_key.as_bytes(), token)
                    .unwrap()
                    .claims
            }
        }

        #[test]
        fn creates_a_token_with_one_permission() {
            let keys = Keys::new();

            let actual = keys.create(None, "example.com").unwrap();

            assert_eq!(keys.decode(&actual), claim(vec![owner("example.com")]));
        }

        #[test]
        fn appends_to_a_token() {
            let keys = Keys::new();
            let sample = keys.create(None, "example.com").unwrap();

            let actual = keys
                .create(Some(&format!("{sample}\n")), "example.org")
                .unwrap();

            let expected = claim(vec![owner("example.com"), owner("example.org")]);
            assert_eq!(keys.decode(&actual), expected);
        }

        #[test]
        fn skips_a_duplicate_permission() {
            let keys = Keys::new();
            let sample = keys.create(None, "example.com").unwrap();

            let actual = keys.create(Some(&sample), "example.com.").unwrap();

            assert_eq!(keys.decode(&actual), claim(vec![owner("example.com")]));
        }

        #[test]
        fn rejects_a_token_signed_with_another_key() {
            let keys = Keys::new();
            let sample = Keys::new().create(None, "example.com").unwrap();

            let actual = keys.create(Some(&sample), "example.org");

            assert!(actual.is_err());
        }

        #[test]
        fn rejects_reading_both_from_stdin() {
            let actual = create(
                Path::new("-"),
                Some(Path::new("-")),
                "example.com".to_string(),
                &Scope::default(),
            );

            assert!(actual.is_err());
        }
    }
}
