//! The payload of a token.

use crate::dns::is_hostname;
use crate::permissions::Permission;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "RawClaim", into = "RawClaim")]
pub struct Claim {
    /// without trailing dot
    pub zone: String,
    pub permission: Permission,
}

impl Claim {
    /// Fails for a claim that would not decode again.
    pub fn validated(self) -> Result<Self, ClaimError> {
        Self::try_from(RawClaim::from(self))
    }
}

/// Numbers of the permissions in the token, never change or reuse them.
const OWNER: u8 = 255;
const ACME: u8 = 1;

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
            OWNER if raw.acme.is_empty() => Permission::Owner,
            OWNER => return Err(ClaimError::UnexpectedAcmeNames),
            ACME if raw.acme.is_empty() => return Err(ClaimError::MissingAcmeNames),
            ACME => {
                if let Some(name) = raw
                    .acme
                    .iter()
                    .find(|name| !(*name == "@" || *name == "*" || is_hostname(name)))
                {
                    return Err(ClaimError::InvalidAcmeName(name.clone()));
                }
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
            Permission::Owner => (OWNER, Vec::new()),
            Permission::Acme(names) => (ACME, names),
        };

        Self {
            zone: claim.zone,
            permission,
            acme,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

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
