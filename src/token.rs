//! Creating and inspecting tokens on the command line.

use crate::claim::Claim;
use crate::dns::is_hostname;
use crate::jwt;
use crate::permissions::{AcmeName, Name, Permission, RrType, Zone};
use eros::Context;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScopeError {
    #[error("invalid zone {0:?}")]
    InvalidZone(String),
    #[error("invalid acme name {0:?}")]
    InvalidAcmeName(String),
    #[error("invalid name {0:?}")]
    InvalidName(String),
    #[error("invalid record type {0:?}")]
    InvalidRrType(String),
    #[error(
        "invalid combination: give names (or any name) and types (or any type), acme names, or nothing for full access"
    )]
    Combination,
}

pub fn encode_token(private_key_pem: &[u8], claim: &Claim) -> eros::Result<String> {
    let key = EncodingKey::from_ed_pem(private_key_pem).context("decode private key")?;
    let token = jwt::encode(&key, claim).context("encoding the token")?;
    Ok(token)
}

pub fn decode_token(public_key_pem: &[u8], token: &str) -> eros::Result<TokenData<Claim>> {
    let key = DecodingKey::from_ed_pem(public_key_pem).context("decode public key")?;
    let token = jwt::decode::<Claim>(&key, token.trim()).context("decoding token")?;
    Ok(token)
}

/// What a token created on the command line permits, for a single zone.
#[derive(Debug, Default)]
pub struct Scope {
    /// names to solve ACME challenges for
    pub acme_names: Vec<String>,
    pub names: Vec<String>,
    pub any_name: bool,
    pub types: Vec<String>,
    pub any_type: bool,
}

/// One dimension (names or types) of a [`Scope`].
enum Selection<T> {
    Unset,
    Any,
    /// not empty
    Only(Vec<T>),
}

/// How the items of a [`Selection`] are checked.
struct Syntax<T> {
    normalize: fn(&str) -> String,
    is_valid: fn(&str) -> bool,
    invalid: fn(String) -> ScopeError,
    new: fn(String) -> T,
}

impl<T: PartialEq> Selection<T> {
    fn new(any: bool, items: &[String], syntax: &Syntax<T>) -> Result<Self, ScopeError> {
        let mut unique = Vec::with_capacity(items.len());
        for item in items {
            let item = (syntax.normalize)(item);
            if !(syntax.is_valid)(&item) {
                return Err((syntax.invalid)(item));
            }
            let item = (syntax.new)(item);
            if !unique.contains(&item) {
                unique.push(item);
            }
        }
        match (any, unique.is_empty()) {
            (false, true) => Ok(Self::Unset),
            (true, true) => Ok(Self::Any),
            (false, false) => Ok(Self::Only(unique)),
            (true, false) => Err(ScopeError::Combination),
        }
    }
}

const ACME_NAME: Syntax<AcmeName> = Syntax {
    normalize: str::to_ascii_lowercase,
    is_valid: is_acme_name,
    invalid: ScopeError::InvalidAcmeName,
    new: AcmeName::new,
};

const NAME: Syntax<Name> = Syntax {
    normalize: str::to_ascii_lowercase,
    is_valid: is_name,
    invalid: ScopeError::InvalidName,
    new: Name::new,
};

const RR_TYPE: Syntax<RrType> = Syntax {
    normalize: str::to_ascii_uppercase,
    is_valid: is_rr_type,
    invalid: ScopeError::InvalidRrType,
    new: RrType::new,
};

/// See [`AcmeName`].
fn is_acme_name(name: &str) -> bool {
    name == "@" || name == "*" || is_hostname(name)
}

/// See [`Name`].
fn is_name(name: &str) -> bool {
    match name.strip_prefix('*') {
        Some("") => true,
        Some(rest) => rest.strip_prefix('.').is_some_and(is_hostname),
        None => name == "@" || is_hostname(name),
    }
}

/// See [`RrType`].
fn is_rr_type(rtype: &str) -> bool {
    let mut bytes = rtype.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_uppercase())
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// A claim for `zone` (a trailing dot is stripped): full access without restrictions, otherwise
/// what `scope` permits. Names are lowercased and types uppercased.
fn claim_for(zone: String, scope: &Scope) -> Result<Claim, ScopeError> {
    let zone = zone.strip_suffix('.').map(String::from).unwrap_or(zone);
    if zone.is_empty() || zone.ends_with('.') {
        return Err(ScopeError::InvalidZone(zone));
    }
    let zone = Zone::new(zone);
    let acme = Selection::new(false, &scope.acme_names, &ACME_NAME)?;
    let names = Selection::new(scope.any_name, &scope.names, &NAME)?;
    let types = Selection::new(scope.any_type, &scope.types, &RR_TYPE)?;

    let permission = match (acme, names, types) {
        (Selection::Unset, Selection::Unset, Selection::Unset) => Permission::Owner(zone),
        (Selection::Only(acme), Selection::Unset, Selection::Unset) => Permission::Acme(zone, acme),
        (Selection::Unset, Selection::Any, Selection::Any) => Permission::AnyRecord(zone),
        (Selection::Unset, Selection::Only(names), Selection::Only(types)) => {
            Permission::Records(zone, names, types)
        }
        (Selection::Unset, Selection::Any, Selection::Only(types)) => {
            Permission::AnyName(zone, types)
        }
        (Selection::Unset, Selection::Only(names), Selection::Any) => {
            Permission::AnyType(zone, names)
        }
        _ => return Err(ScopeError::Combination),
    };

    Ok(Claim {
        permissions: vec![permission],
    })
}

/// Creates a token, see [`claim_for`].
pub fn create(private_key_file: PathBuf, zone: String, scope: &Scope) -> eros::Result<String> {
    let claim = claim_for(zone, scope).context("invalid claim")?;
    let key = std::fs::read(private_key_file).context("open private key file")?;
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
    use crate::claim::fixtures::claim;
    use crate::keygen::generate;
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

    mod claim_for {
        use super::*;
        use crate::permissions::fixtures::{names, types, zone};

        fn strings(items: &[&str]) -> Vec<String> {
            items.iter().map(ToString::to_string).collect()
        }

        fn claim_for_example(scope: &Scope) -> Result<Claim, ScopeError> {
            claim_for("example.com".to_string(), scope)
        }

        #[test]
        fn owner_without_restrictions() {
            let actual = claim_for_example(&Scope::default());

            assert_eq!(actual, Ok(claim(vec![owner("example.com")])));
        }

        #[test]
        fn strips_trailing_dot() {
            let actual = claim_for("example.com.".to_string(), &Scope::default());

            assert_eq!(actual, Ok(claim(vec![owner("example.com")])));
        }

        #[test]
        fn acme_with_lowercased_unique_names() {
            let sample = Scope {
                acme_names: strings(&["WWW", "@", "www"]),
                ..Scope::default()
            };

            let actual = claim_for_example(&sample);

            assert_eq!(actual, Ok(claim(vec![acme("example.com", &["www", "@"])])));
        }

        #[test]
        fn records_with_normalized_unique_names_and_types() {
            let sample = Scope {
                names: strings(&["Home", "@", "home", "*"]),
                types: strings(&["a", "AAAA", "A"]),
                ..Scope::default()
            };

            let actual = claim_for_example(&sample);

            let expected = Permission::Records(
                zone("example.com"),
                names(&["home", "@", "*"]),
                types(&["A", "AAAA"]),
            );
            assert_eq!(actual, Ok(claim(vec![expected])));
        }

        #[test]
        fn any_name_any_type_and_any_record() {
            for (sample, expected) in [
                (
                    Scope {
                        any_name: true,
                        types: strings(&["TXT"]),
                        ..Scope::default()
                    },
                    Permission::AnyName(zone("example.com"), types(&["TXT"])),
                ),
                (
                    Scope {
                        names: strings(&["home"]),
                        any_type: true,
                        ..Scope::default()
                    },
                    Permission::AnyType(zone("example.com"), names(&["home"])),
                ),
                (
                    Scope {
                        any_name: true,
                        any_type: true,
                        ..Scope::default()
                    },
                    Permission::AnyRecord(zone("example.com")),
                ),
            ] {
                let actual = claim_for_example(&sample);

                assert_eq!(actual, Ok(claim(vec![expected])), "{sample:?}");
            }
        }

        #[test]
        fn rejects_invalid_combinations() {
            for sample in [
                Scope {
                    names: strings(&["home"]),
                    ..Scope::default()
                },
                Scope {
                    types: strings(&["A"]),
                    ..Scope::default()
                },
                Scope {
                    any_name: true,
                    ..Scope::default()
                },
                Scope {
                    any_type: true,
                    ..Scope::default()
                },
                Scope {
                    names: strings(&["home"]),
                    any_name: true,
                    types: strings(&["A"]),
                    ..Scope::default()
                },
                Scope {
                    names: strings(&["home"]),
                    types: strings(&["A"]),
                    any_type: true,
                    ..Scope::default()
                },
                Scope {
                    acme_names: strings(&["www"]),
                    names: strings(&["home"]),
                    types: strings(&["A"]),
                    ..Scope::default()
                },
                Scope {
                    acme_names: strings(&["www"]),
                    any_name: true,
                    any_type: true,
                    ..Scope::default()
                },
            ] {
                let actual = claim_for_example(&sample);

                assert_eq!(actual, Err(ScopeError::Combination), "{sample:?}");
            }
        }

        fn records(names: &[&str], types: &[&str]) -> Scope {
            Scope {
                names: strings(names),
                types: strings(types),
                ..Scope::default()
            }
        }

        fn acme_names(names: &[&str]) -> Scope {
            Scope {
                acme_names: strings(names),
                ..Scope::default()
            }
        }

        #[test]
        fn accepts_names_and_types() {
            for name in ["@", "www", "a.b", "_dmarc", "*", "*.dev", "*.a.b"] {
                let actual = claim_for_example(&records(&[name], &["A"]));

                assert!(actual.is_ok(), "{name:?}");
            }
            for rtype in ["A", "AAAA", "TXT", "NSEC3PARAM", "TYPE65534", "SOA"] {
                let actual = claim_for_example(&records(&["www"], &[rtype]));

                assert!(actual.is_ok(), "{rtype:?}");
            }
        }

        #[test]
        fn rejects_invalid_acme_names() {
            for name in [
                "",
                ".",
                "www.",
                ".www",
                "a..b",
                "*.www",
                "www.*",
                "@.www",
                "a b",
                "w\\119w",
                "ä",
                &"a".repeat(64),
            ] {
                let actual = claim_for_example(&acme_names(&["www", name]));

                assert_eq!(
                    actual,
                    Err(ScopeError::InvalidAcmeName(name.to_string())),
                    "{name:?}"
                );
            }
        }

        #[test]
        fn rejects_invalid_names() {
            for name in [
                "", ".", "www.", ".www", "a..b", "www.*", "a.*.b", "**", "*a", "*.", "@.www",
                "www.@", "a b", "w\\119w", "ä",
            ] {
                let actual = claim_for_example(&records(&["www", name], &["A"]));

                assert_eq!(
                    actual,
                    Err(ScopeError::InvalidName(name.to_string())),
                    "{name:?}"
                );
            }
        }

        #[test]
        fn rejects_invalid_types() {
            for rtype in ["", "*", "1A", "A A", " A", "A-B", "TÄ"] {
                let actual = claim_for_example(&records(&["www"], &["A", rtype]));

                assert_eq!(
                    actual,
                    Err(ScopeError::InvalidRrType(rtype.to_ascii_uppercase())),
                    "{rtype:?}"
                );
            }
        }

        #[test]
        fn rejects_invalid_input() {
            for (zone, sample) in [
                ("", Scope::default()),
                (".", Scope::default()),
                ("example.com..", Scope::default()),
                (
                    "example.com",
                    Scope {
                        acme_names: strings(&["www.example.com."]),
                        ..Scope::default()
                    },
                ),
                (
                    "example.com",
                    Scope {
                        acme_names: strings(&[""]),
                        ..Scope::default()
                    },
                ),
                (
                    "example.com",
                    Scope {
                        names: strings(&["home.example.com."]),
                        types: strings(&["A"]),
                        ..Scope::default()
                    },
                ),
                (
                    "example.com",
                    Scope {
                        names: strings(&["home"]),
                        types: strings(&["A A"]),
                        ..Scope::default()
                    },
                ),
            ] {
                let actual = claim_for(zone.to_string(), &sample);

                assert!(actual.is_err(), "{zone:?} {sample:?}");
            }
        }
    }
}
