//! Request body checks, run once the body is buffered, and before it is forwarded. A failure denies the request.
use crate::{claim::Claim, pdns};
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
    /// every rrset of a PATCH must be permitted by the acme permission
    AcmeRrsets,
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
            BodyCheck::AcmeRrsets => {
                let body = serde_json::from_slice::<pdns::zone::Patch>(body)
                    .map_err(|_| Error::InvalidBody)?;

                if body
                    .rrsets
                    .iter()
                    .all(|r| claim.permits_acme_rrset(&r.name, &r.rtype))
                {
                    Ok(())
                } else {
                    Err(Error::BodyRejected)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions::Permission;

    // Helper to create a test claim with given zone
    fn test_claim(zone: &str) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Owner,
        }
    }

    mod create {
        use super::*;

        // pdns requires canonical names (with trailing dot) in bodies, claims hold zones without it.
        #[test]
        fn rejects_name_without_trailing_dot() {
            let claim = test_claim("example.com");
            let body = Bytes::from_static(br#"{"name": "example.com"}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::InvalidBody));
        }

        #[test]
        fn accepts_valid_zone_name_in_claim() {
            let claim = test_claim("example.com");
            let body = Bytes::from(r#"{"name": "example.com."}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert!(result.is_ok());
        }

        #[test]
        fn rejects_zone_not_in_claim() {
            let claim = test_claim("example.com");
            let body = Bytes::from(r#"{"name": "other.com."}"#);
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }

        #[test]
        fn rejects_forbidden_fields() {
            let claim = test_claim("example.com");
            let body = Bytes::from(
                r#"{"name": "example.com.", "kind": "Slave", "masters": ["192.0.2.1"]}"#,
            );
            let result = BodyCheck::CreateZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }
    }

    mod acme_rrsets {
        use super::*;
        use serde_json::json;

        fn acme_claim() -> Claim {
            Claim {
                zone: "example.com".to_string(),
                permission: Permission::Acme(vec!["www".to_string(), "@".to_string()]),
            }
        }

        fn patch(rrsets: &[(&str, &str)]) -> Bytes {
            let rrsets: Vec<_> = rrsets
                .iter()
                .map(|(name, rtype)| {
                    json!({
                        "name": name,
                        "type": rtype,
                        "changetype": "REPLACE",
                        "ttl": 60,
                        "records": [{"content": "\"token\"", "disabled": false}]
                    })
                })
                .collect();
            Bytes::from(serde_json::to_vec(&json!({ "rrsets": rrsets })).unwrap())
        }

        #[test]
        fn accepts_permitted_rrsets() {
            let sample = patch(&[
                ("_acme-challenge.www.example.com.", "TXT"),
                ("_acme-challenge.example.com.", "TXT"),
            ]);

            let actual = BodyCheck::AcmeRrsets.apply(&acme_claim(), &sample);

            assert_eq!(actual, Ok(()));
        }

        #[test]
        fn accepts_delete() {
            let sample = Bytes::from_static(
                br#"{"rrsets": [{"name": "_acme-challenge.www.example.com.", "type": "TXT", "changetype": "DELETE"}]}"#,
            );

            let actual = BodyCheck::AcmeRrsets.apply(&acme_claim(), &sample);

            assert_eq!(actual, Ok(()));
        }

        #[test]
        fn rejects_if_any_rrset_is_not_permitted() {
            for rrset in [
                ("www.example.com.", "A"),
                ("_acme-challenge.www.example.com.", "CNAME"),
                ("_acme-challenge.other.example.com.", "TXT"),
                ("example.com.", "TXT"),
                ("_acme-challenge.www.example.org.", "TXT"),
            ] {
                let sample = patch(&[("_acme-challenge.www.example.com.", "TXT"), rrset]);

                let actual = BodyCheck::AcmeRrsets.apply(&acme_claim(), &sample);

                assert_eq!(actual, Err(Error::BodyRejected), "{rrset:?}");
            }
        }

        #[test]
        fn rejects_owner() {
            let sample = patch(&[("_acme-challenge.www.example.com.", "TXT")]);

            let actual = BodyCheck::AcmeRrsets.apply(&test_claim("example.com"), &sample);

            assert_eq!(actual, Err(Error::BodyRejected));
        }

        #[test]
        fn rejects_invalid_body() {
            for sample in [
                &br#"{"rrsets": [{"name": "_acme-challenge.www.example.com."}]}"#[..],
                br#"{"rrsets": {}}"#,
                b"{}",
                b"",
            ] {
                let actual =
                    BodyCheck::AcmeRrsets.apply(&acme_claim(), &Bytes::copy_from_slice(sample));

                assert_eq!(actual, Err(Error::InvalidBody));
            }
        }
    }

    mod put {
        use super::*;

        #[test]
        fn accepts_valid_body_without_kind_or_masters() {
            let claim = test_claim("example.com");
            let body = Bytes::from(r#"{"dnssec": false, "serial": 2021010101}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert!(result.is_ok());
        }

        #[test]
        fn rejects_kind_modification() {
            let claim = test_claim("example.com");
            let body = Bytes::from(r#"{"kind": "Slave"}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }

        #[test]
        fn rejects_masters_modification() {
            let claim = test_claim("example.com");
            let body = Bytes::from(r#"{"masters": ["8.8.8.8"]}"#);
            let result = BodyCheck::PutZone.apply(&claim, &body);
            assert_eq!(result, Err(Error::BodyRejected));
        }
    }
}
