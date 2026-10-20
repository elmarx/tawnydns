//! The payload of a token.

use crate::permissions::Permission;
use serde::{Deserialize, Serialize};

/// What the holder of a token may do. Kept small, the field and variant names are single letters,
/// never change or reuse them. The field name `1` doubles as the version of the format.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    #[serde(rename = "1")]
    pub permissions: Vec<Permission>,
}

#[cfg(test)]
pub mod fixtures {
    use super::*;

    pub fn claim(permissions: Vec<Permission>) -> Claim {
        Claim { permissions }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::claim;
    use super::*;
    use crate::permissions::fixtures::{acme, names, owner, types, zone};
    use serde_json::{Value, json};

    fn all_variants() -> Claim {
        claim(vec![
            owner("example.com"),
            Permission::AnyRecord(zone("example.org")),
            Permission::Records(
                zone("example.org"),
                names(&["home", "@"]),
                types(&["A", "AAAA"]),
            ),
            Permission::AnyName(zone("example.org"), types(&["TXT"])),
            Permission::AnyType(zone("example.org"), names(&["*", "*.dev"])),
            acme("example.org", &["www", "@"]),
            Permission::DynDnsHost(zone("example.net"), names(&["home", "@"])),
            Permission::DynDnsZone(zone("example.net")),
        ])
    }

    fn all_variants_json() -> Value {
        json!({"1": [
            {"o": "example.com"},
            {"x": "example.org"},
            {"r": ["example.org", ["home", "@"], ["A", "AAAA"]]},
            {"n": ["example.org", ["TXT"]]},
            {"t": ["example.org", ["*", "*.dev"]]},
            {"a": ["example.org", ["www", "@"]]},
            {"h": ["example.net", ["home", "@"]]},
            {"z": "example.net"}
        ]})
    }

    #[test]
    fn encodes_permissions_compactly() {
        let actual = serde_json::to_value(all_variants()).unwrap();

        assert_eq!(actual, all_variants_json());
    }

    #[test]
    fn decodes_all_variants() {
        let actual: Claim = serde_json::from_value(all_variants_json()).unwrap();

        assert_eq!(actual, all_variants());
    }

    #[test]
    fn decodes_permissions() {
        for (sample, expected) in [
            (
                json!({"1": [{"o": "example.com"}]}),
                claim(vec![owner("example.com")]),
            ),
            (
                json!({"1": [{"a": ["example.com", ["www", "a.b", "@", "*", "_x-1"]]}]}),
                claim(vec![acme("example.com", &["www", "a.b", "@", "*", "_x-1"])]),
            ),
            (
                json!({"1": [{"o": "example.com"}, {"o": "example.com"}]}),
                claim(vec![owner("example.com"), owner("example.com")]),
            ),
        ] {
            let actual: Claim = serde_json::from_value(sample).unwrap();

            assert_eq!(actual, expected);
        }
    }

    /// The contents are checked when a token is created, unexpected contents just do not match.
    #[test]
    fn decodes_without_checking_contents() {
        for (sample, expected) in [
            (json!({"1": []}), claim(vec![])),
            (
                json!({"1": [{"o": "Example.com."}]}),
                claim(vec![owner("Example.com.")]),
            ),
            (
                json!({"1": [{"a": ["", ["", "a..b"]]}]}),
                claim(vec![acme("", &["", "a..b"])]),
            ),
            (
                json!({"1": [{"r": ["example.com", [], ["a a"]]}]}),
                claim(vec![Permission::Records(
                    zone("example.com"),
                    names(&[]),
                    types(&["a a"]),
                )]),
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
    fn rejects_invalid_permissions() {
        rejects(&[
            json!({}),
            json!({"1": null}),
            json!({"1": {"o": "example.com"}}),
            json!({"1": ["example.com"]}),
            json!({"1": [{}]}),
            json!({"1": [{"y": "example.com"}]}),
            json!({"1": [{"o": "example.com", "a": ["example.com", ["www"]]}]}),
        ]);
    }

    #[test]
    fn rejects_unknown_fields() {
        rejects(&[
            json!({"1": [{"o": "example.com"}], "b": []}),
            json!({"b": [{"o": "example.com"}]}),
            json!({"z": "example.com", "p": 255}),
        ]);
    }

    #[test]
    fn rejects_invalid_zone() {
        rejects(&[
            json!({"1": [{"o": null}]}),
            json!({"1": [{"o": ["example.com"]}]}),
            json!({"1": [{"a": [null, ["www"]]}]}),
        ]);
    }

    #[test]
    fn rejects_invalid_acme_permission() {
        rejects(&[
            json!({"1": [{"a": "example.com"}]}),
            json!({"1": [{"a": ["example.com"]}]}),
            json!({"1": [{"a": ["example.com", null]}]}),
            json!({"1": [{"a": ["example.com", "www"]}]}),
            json!({"1": [{"a": ["example.com", ["www"], ["TXT"]]}]}),
        ]);
    }

    #[test]
    fn rejects_invalid_records_permissions() {
        rejects(&[
            json!({"1": [{"x": ["example.com"]}]}),
            json!({"1": [{"r": ["example.com", ["home"]]}]}),
            json!({"1": [{"r": ["example.com", null, ["A"]]}]}),
            json!({"1": [{"r": ["example.com", ["home"], null]}]}),
            json!({"1": [{"n": ["example.com", ["A"], ["home"]]}]}),
            json!({"1": [{"t": "example.com"}]}),
        ]);
    }

    #[test]
    fn rejects_invalid_dyndns_permissions() {
        rejects(&[
            json!({"1": [{"h": "example.com"}]}),
            json!({"1": [{"h": ["example.com", null]}]}),
            json!({"1": [{"h": ["example.com", ["home"], ["A"]]}]}),
            json!({"1": [{"z": ["example.com"]}]}),
            json!({"1": [{"z": null}]}),
        ]);
    }

    #[test]
    fn rejects_duplicate_fields() {
        for sample in [
            r#"{"1": [{"o": "example.com"}], "1": [{"o": "example.org"}]}"#,
            r#"{"1": [{"o": "example.com", "o": "example.org"}]}"#,
        ] {
            let actual = serde_json::from_str::<Claim>(sample);

            assert!(actual.is_err(), "{sample}");
        }
    }
}
