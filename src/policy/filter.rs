//! Response filters: remove what the claim doesn't cover from a pdns response to an allowed request.
use bytes::Bytes;

use crate::{pdns, token::Claim};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseFilter {
    /// keeps the zone of the claim
    ZoneList,
    /// keeps the rrsets of a zone permitted by the acme permission
    AcmeRrsets,
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("response is not valid JSON")]
    Json(#[from] serde_json::Error),
}

impl ResponseFilter {
    /// Filters a response body, to be called once the body is buffered.
    pub fn apply(self, claim: &Claim, body: &Bytes) -> Result<Bytes, FilterError> {
        match self {
            Self::ZoneList => {
                let mut zone_list = serde_json::from_slice::<pdns::ZoneList>(body)?;

                zone_list.retain(|z| claim.is_zone(&z.name));

                let body = serde_json::to_vec(&zone_list)?;
                Ok(Bytes::from(body))
            }
            Self::AcmeRrsets => {
                let mut zone = serde_json::from_slice::<pdns::ZoneDetail>(body)?;

                if let Some(rrsets) = &mut zone.rrsets {
                    rrsets.retain(|r| claim.permits_acme_rrset(&r.name, &r.rtype));
                }

                let body = serde_json::to_vec(&zone)?;
                Ok(Bytes::from(body))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::Permission;
    use serde_json::{Value, json};

    fn test_claim(zone: &str) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Owner,
        }
    }

    fn filter_zone_list(claim: &Claim, body: &Value) -> Value {
        let body = Bytes::from(serde_json::to_vec(body).unwrap());
        let filtered = ResponseFilter::ZoneList.apply(claim, &body).unwrap();
        serde_json::from_slice(&filtered).unwrap()
    }

    #[test]
    fn keeps_zone_of_the_claim() {
        let claim = test_claim("example.com");
        let body = json!([{"name": "example.com."}]);

        let actual = filter_zone_list(&claim, &body);

        assert_eq!(actual, body);
    }

    #[test]
    fn drops_zones_not_in_the_claim() {
        let claim = test_claim("example.com");
        let body = json!([
            {"name": "other.com."},
            {"name": "example.com."},
            {"name": "sub.example.com."}
        ]);

        let actual = filter_zone_list(&claim, &body);

        assert_eq!(actual, json!([{"name": "example.com."}]));
    }

    #[test]
    fn keeps_all_fields_of_kept_entries() {
        let claim = test_claim("example.com");
        let body = json!([{
            "id": "example.com.",
            "name": "example.com.",
            "kind": "Native",
            "serial": 2_024_010_101,
            "masters": [],
            "some_future_field": {"nested": [1, 2]}
        }]);

        let actual = filter_zone_list(&claim, &body);

        assert_eq!(actual, body);
    }

    // anything else than a list can't be filtered, so it must not be passed through
    #[test]
    fn rejects_body_that_is_not_a_list() {
        let claim = test_claim("example.com");
        let body = Bytes::from_static(br#"{"name": "other.com."}"#);

        let actual = ResponseFilter::ZoneList.apply(&claim, &body);

        assert!(matches!(actual, Err(FilterError::Json(_))), "{actual:?}");
    }

    fn acme_claim() -> Claim {
        Claim {
            zone: "example.com".to_string(),
            permission: Permission::Acme(vec!["www".to_string()]),
        }
    }

    #[test]
    fn keeps_zone_of_acme_claim() {
        let body = json!([{"name": "example.com."}, {"name": "example.org."}]);

        let actual = filter_zone_list(&acme_claim(), &body);

        assert_eq!(actual, json!([{"name": "example.com."}]));
    }

    mod acme_rrsets {
        use super::*;

        fn filter(body: &Value) -> Value {
            let body = Bytes::from(serde_json::to_vec(body).unwrap());
            let filtered = ResponseFilter::AcmeRrsets
                .apply(&acme_claim(), &body)
                .unwrap();
            serde_json::from_slice(&filtered).unwrap()
        }

        #[test]
        fn keeps_only_permitted_rrsets() {
            let challenge = json!({
                "name": "_acme-challenge.www.example.com.",
                "type": "TXT",
                "ttl": 60,
                "records": [{"content": "\"token\"", "disabled": false}],
                "comments": []
            });
            let body = json!({
                "id": "example.com.",
                "name": "example.com.",
                "kind": "Master",
                "url": "/api/v1/servers/localhost/zones/example.com.",
                "rrsets": [
                    {"name": "example.com.", "type": "SOA", "ttl": 3600, "records": []},
                    {"name": "www.example.com.", "type": "A", "ttl": 3600, "records": []},
                    {"name": "_acme-challenge.www.example.com.", "type": "CNAME", "records": []},
                    {"name": "_acme-challenge.example.com.", "type": "TXT", "records": []},
                    challenge
                ]
            });

            let actual = filter(&body);

            let expected = json!({
                "id": "example.com.",
                "name": "example.com.",
                "kind": "Master",
                "url": "/api/v1/servers/localhost/zones/example.com.",
                "rrsets": [challenge]
            });
            assert_eq!(actual, expected);
        }

        #[test]
        fn passes_zone_without_rrsets() {
            let body = json!({"name": "example.com.", "kind": "Master"});

            let actual = filter(&body);

            assert_eq!(actual, body);
        }

        #[test]
        fn drops_all_rrsets_for_owner() {
            let body = json!({
                "name": "example.com.",
                "rrsets": [{"name": "_acme-challenge.www.example.com.", "type": "TXT"}]
            });
            let body = Bytes::from(serde_json::to_vec(&body).unwrap());

            let actual = ResponseFilter::AcmeRrsets
                .apply(&test_claim("example.com"), &body)
                .unwrap();
            let actual: Value = serde_json::from_slice(&actual).unwrap();

            assert_eq!(actual, json!({"name": "example.com.", "rrsets": []}));
        }

        #[test]
        fn rejects_body_that_is_not_a_zone() {
            let body = Bytes::from_static(br#"[{"name": "example.com."}]"#);

            let actual = ResponseFilter::AcmeRrsets.apply(&acme_claim(), &body);

            assert!(matches!(actual, Err(FilterError::Json(_))), "{actual:?}");
        }
    }
}
