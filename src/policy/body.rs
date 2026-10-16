//! Request body checks, run once the body is buffered, and before it is forwarded. A failure denies the request.
use crate::{pdns, token::Claim};
use bytes::Bytes;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// the request body asks for something the claim does not permit
    #[error("Body not allowed for given token")]
    BodyRejected,

    #[error("invalid body")]
    InvalidBody,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BodyCheck {
    CreateZone,
    PutZone,
}

impl BodyCheck {
    /// Checks a request body, to be called once the body is buffered.
    pub fn apply(self, claim: &Claim, body: &Bytes) -> Result<(), Error> {
        match self {
            BodyCheck::CreateZone => {
                let body = serde_json::from_slice::<pdns::zone::Create>(body)
                    .map_err(|_| Error::InvalidBody)?;

                if body.kind.is_some_and(|k| k != pdns::zone::Kind::Master) {
                    return Err(Error::BodyRejected);
                }

                if !body.name.ends_with('.') {
                    return Err(Error::InvalidBody);
                }

                if claim.permits(&body.name) {
                    Ok(())
                } else {
                    Err(Error::BodyRejected)
                }
            }
            BodyCheck::PutZone => {
                let body = serde_json::from_slice::<pdns::zone::Put>(body)
                    .map_err(|_| Error::InvalidBody)?;

                // modifications to kind/masters is not allowed
                if body.kind.is_some() || body.masters.is_some() {
                    Err(Error::BodyRejected)
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test claim with given zones
    fn test_claim(zones: &[&str]) -> Claim {
        Claim {
            zones: zones.iter().map(ToString::to_string).collect(),
        }
    }

    mod create {
        use super::*;

        // pdns requires canonical names (with trailing dot) in bodies, claims hold zones without it.
        #[test]
        fn rejects_name_without_trailing_dot() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from_static(br#"{"name": "example.com"}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::InvalidBody));
        }

        #[test]
        fn accepts_valid_zone_name_in_claim() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(r#"{"name": "example.com."}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert!(result.is_ok());
        }

        #[test]
        fn rejects_zone_not_in_claim() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(r#"{"name": "other.com."}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }

        #[test]
        fn rejects_forbidden_fields() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(
                r#"{"name": "example.com.", "kind": "Slave", "masters": ["192.0.2.1"]}"#,
            );
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }
    }

    mod put {
        use super::*;

        #[test]
        fn accepts_valid_body_without_kind_or_masters() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(r#"{"dnssec": false, "serial": 2021010101}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert!(result.is_ok());
        }

        #[test]
        fn rejects_kind_modification() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(r#"{"kind": "Slave"}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }

        #[test]
        fn rejects_masters_modification() {
            let claim = test_claim(&["example.com"]);
            let body = Bytes::from(r#"{"masters": ["8.8.8.8"]}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }
    }
}
