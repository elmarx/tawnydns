//! Lenient model of the response to `GET /servers/{server_id}/zones/{zone_id}` (`listZone`,
//! `Zone` of the `OpenAPI` spec), to be filtered and sent on to the client.
//!
//! `rrsets` is missing with the query parameter `rrsets=false`. Only the fields the filter
//! inspects are modeled, everything else is kept as is (`rest`).
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Default, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ZoneDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrsets: Option<Vec<Rrset>>,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[derive(Debug, Default, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct Rrset {
    /// canonical (with trailing dot)
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializing_again_keeps_all_fields_and_does_not_add_any() {
        for sample in [
            json!({
                "id": "example.com.",
                "name": "example.com.",
                "kind": "Native",
                "rrsets": [{
                    "name": "example.com.",
                    "type": "SOA",
                    "ttl": 3600,
                    "records": [{"content": "a. b. 1 2 3 4 5", "disabled": false}],
                    "comments": []
                }],
                "some_future_field": {"nested": [1, 2]}
            }),
            json!({"id": "example.com.", "name": "example.com."}),
        ] {
            let actual: ZoneDetail = serde_json::from_value(sample.clone()).unwrap();
            let actual = serde_json::to_value(&actual).unwrap();

            assert_eq!(actual, sample);
        }
    }

    #[test]
    fn rejects_what_is_not_a_zone() {
        for sample in [
            "[]",
            r#"{"rrsets": {}}"#,
            r#"{"rrsets": [{"name": "example.com."}]}"#,
            r#"{"rrsets": [{"name": "a.example.com.", "type": "TXT", "type": "A"}]}"#,
            "",
        ] {
            let actual = serde_json::from_str::<ZoneDetail>(sample);

            assert!(actual.is_err(), "{sample}");
        }
    }
}
