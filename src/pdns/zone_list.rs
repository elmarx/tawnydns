//! Lenient model of the response to `GET /servers/{server_id}/zones` (`listZones`,
//! `ZonesWithoutRRSets` of the `OpenAPI` spec), to be filtered and sent on to the client.
//!
//! This is the only endpoint returning a list of zones. The query parameters `zone` (only that
//! zone, an empty array if it does not exist) and `dnssec` do not change the shape. The other
//! zone endpoints return a single `Zone` object or nothing.
//!
//! Only the fields the filter inspects are modeled. Everything else is kept as is (`rest`),
//! since the entries are sent on to the client.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type ZoneList = Vec<ZoneListEntry>;

/// a zone as listed by the API
#[derive(Debug, Default, PartialEq, Eq, Clone, Deserialize, Serialize)]
pub struct ZoneListEntry {
    /// canonical (with trailing dot). Not required by the spec, but always set by pdns.
    pub name: String,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_a_zone_list() {
        let sample = r#"[
            {"id": "example.com.", "name": "example.com.", "kind": "Native", "serial": 1},
            {"name": "example.org."}
        ]"#;

        let actual: ZoneList = serde_json::from_str(sample).unwrap();

        let actual: Vec<_> = actual.iter().map(|z| z.name.as_str()).collect();
        let expected = ["example.com.", "example.org."];
        assert_eq!(actual, expected);
    }

    #[test]
    fn serializing_again_keeps_all_fields_and_does_not_add_any() {
        let sample = json!([
            {
                "id": "example.com.",
                "name": "example.com.",
                "type": "Zone",
                "masters": [],
                "some_future_field": {"nested": [1, 2]}
            }
        ]);

        let actual: ZoneList = serde_json::from_value(sample.clone()).unwrap();
        let actual = serde_json::to_value(&actual).unwrap();

        assert_eq!(actual, sample);
    }

    #[test]
    fn rejects_what_is_not_a_list_of_objects() {
        for sample in [
            r#"{"name": "example.com."}"#,
            r#"["example.com."]"#,
            r#"[{"name": 1}]"#,
            r#"[{"kind": "Native"}]"#,
            "",
        ] {
            let actual = serde_json::from_str::<ZoneList>(sample);

            assert!(actual.is_err(), "{sample}");
        }
    }
}
