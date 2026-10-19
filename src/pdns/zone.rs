//! Lenient models of the zone request bodies of the PowerDNS authoritative API.
//!
//! The `OpenAPI` spec uses the same `Zone` schema (without required fields) for `POST` and
//! `PUT`, but each endpoint only reads some of its fields. There's one struct per request,
//! with the fields pdns needs being required.
//!
//! Only the fields the body checks inspect are modelled, all other fields are ignored. Duplicate
//! keys of the modelled fields are rejected, so the checks never see a different value than the
//! one a parser with "last one wins" semantics would pick.
use serde::Deserialize;

/// Body of `POST /servers/{server_id}/zones` (create a zone)
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct Create {
    /// the zone to create, canonical (with trailing dot)
    pub name: String,
    pub kind: Option<Kind>,
    pub masters: Option<Vec<String>>,
}

/// Body of `PUT /servers/{server_id}/zones/{zone_id}`: changes basic data of the zone of the path.
/// `name` and `rrsets` are ignored by pdns.
#[derive(Debug, Default, PartialEq, Eq, Clone, Deserialize)]
pub struct Put {
    pub kind: Option<Kind>,
    pub masters: Option<Vec<String>>,
}

/// Zone kind. Strictly the values of the `OpenAPI` spec (case-sensitive, no aliases), so a check
/// never misses a kind spelled differently.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Deserialize)]
pub enum Kind {
    Native,
    Master,
    Slave,
    Producer,
    Consumer,
}

/// Body of `PATCH /servers/{server_id}/zones/{zone_id}`: changes the rrsets of the zone of the
/// path, pdns ignores all other fields.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct Patch {
    pub rrsets: Vec<PatchRrset>,
}

/// An rrset of a [`Patch`], identified by name and type. The changetype is not modelled: whoever
/// may change an rrset may also delete it.
#[derive(Debug, PartialEq, Eq, Clone, Deserialize)]
pub struct PatchRrset {
    /// canonical (with trailing dot)
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_patch() {
        let sample = r#"{"rrsets": [{
            "name": "_acme-challenge.example.com.",
            "type": "TXT",
            "changetype": "REPLACE",
            "ttl": 60,
            "records": [{"content": "\"token\"", "disabled": false}]
        }]}"#;

        let actual: Patch = serde_json::from_str(sample).unwrap();

        let expected = Patch {
            rrsets: vec![PatchRrset {
                name: "_acme-challenge.example.com.".to_string(),
                rtype: "TXT".to_string(),
            }],
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn rejects_invalid_patch() {
        for sample in [
            "{}",
            r#"{"rrsets": {}}"#,
            r#"{"rrsets": [{"name": "example.com."}]}"#,
            r#"{"rrsets": [{"type": "TXT"}]}"#,
            r#"{"rrsets": [{"name": "a.example.com.", "type": "TXT", "name": "example.com."}]}"#,
            r#"{"rrsets": [{"name": "a.example.com.", "type": "TXT", "type": "A"}]}"#,
            r#"{"rrsets": [], "rrsets": []}"#,
        ] {
            let actual = serde_json::from_str::<Patch>(sample);

            assert!(actual.is_err(), "{sample}");
        }
    }
}
