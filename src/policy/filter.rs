//! Response filters: remove what the claim doesn't cover from a pdns response to an allowed request.
use bytes::Bytes;

use crate::{pdns, token::Claim};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseFilter {
    ZoneList,
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

                zone_list.retain(|z| claim.permits(&z.name));

                let body = serde_json::to_vec(&zone_list)?;
                Ok(Bytes::from(body))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn test_claim(zones: &[&str]) -> Claim {
        Claim {
            zones: zones.iter().map(ToString::to_string).collect(),
        }
    }

    fn filter_zone_list(claim: &Claim, body: &Value) -> Value {
        let body = Bytes::from(serde_json::to_vec(body).unwrap());
        let filtered = ResponseFilter::ZoneList.apply(claim, &body).unwrap();
        serde_json::from_slice(&filtered).unwrap()
    }

    #[test]
    fn keeps_zones_of_the_claim() {
        let claim = test_claim(&["example.com", "example.org"]);
        let body = json!([{"name": "example.com."}, {"name": "example.org."}]);

        let actual = filter_zone_list(&claim, &body);

        assert_eq!(actual, body);
    }

    #[test]
    fn drops_zones_not_in_the_claim() {
        let claim = test_claim(&["example.com"]);
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
        let claim = test_claim(&["example.com"]);
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
        let claim = test_claim(&["example.com"]);
        let body = Bytes::from_static(br#"{"name": "other.com."}"#);

        let actual = ResponseFilter::ZoneList.apply(&claim, &body);

        assert!(matches!(actual, Err(FilterError::Json(_))), "{actual:?}");
    }
}
