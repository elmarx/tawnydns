//! Updating the prefix of all AAAA records of a zone, e.g. when the ISP changes the delegated
//! prefix (`ip6lanprefix` of a dyndns request). The interface identifiers are kept.

use super::addresses::merge;
use crate::pdns::client::model::{RRSet, Record};
use ipnet::Ipv6Net;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrefixError {
    #[error("invalid AAAA record {content:?} of {name}")]
    InvalidAddress { name: String, content: String },
}

/// The AAAA rrsets of `rrsets` with the prefix of every record replaced by `prefix` (see
/// [`merge`](super::addresses::merge)), to replace the rrsets of the zone. Other types are left
/// out, they don't change.
pub fn replace_prefix(rrsets: &[RRSet], prefix: Ipv6Net) -> Result<Vec<RRSet>, PrefixError> {
    rrsets
        .iter()
        .filter(|rrset| rrset.r#type == "AAAA")
        .map(|rrset| {
            let records = rrset
                .records
                .iter()
                .map(|record| replace_in_record(&rrset.name, record, prefix))
                .collect::<Result<_, _>>()?;
            Ok(RRSet {
                name: rrset.name.clone(),
                r#type: rrset.r#type.clone(),
                ttl: rrset.ttl,
                records,
            })
        })
        .collect()
}

fn replace_in_record(name: &str, record: &Record, prefix: Ipv6Net) -> Result<Record, PrefixError> {
    let address = record
        .content
        .parse()
        .map_err(|_| PrefixError::InvalidAddress {
            name: name.to_string(),
            content: record.content.clone(),
        })?;
    Ok(Record {
        content: merge(address, prefix).to_string(),
        disabled: record.disabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(prefix: &str) -> Ipv6Net {
        prefix.parse().unwrap()
    }

    fn rrset(name: &str, rtype: &str, contents: &[&str]) -> RRSet {
        RRSet {
            name: name.to_string(),
            r#type: rtype.to_string(),
            ttl: 300,
            records: contents
                .iter()
                .map(|content| Record {
                    content: (*content).to_string(),
                    disabled: false,
                })
                .collect(),
        }
    }

    #[test]
    fn replaces_prefix_of_aaaa_records_only() {
        let sample = [
            rrset(
                "example.com.",
                "SOA",
                &["ns.example.com. hostmaster.example.com. 1 2 3 4 5"],
            ),
            rrset(
                "host.example.com.",
                "AAAA",
                &["2001:db8:1::1", "2001:db8:1::2"],
            ),
            rrset("host.example.com.", "A", &["192.0.2.1"]),
            rrset("www.example.com.", "AAAA", &["2001:db8:1::3"]),
        ];

        let actual = replace_prefix(&sample, prefix("2001:db8:2::/64"));

        let expected = vec![
            rrset(
                "host.example.com.",
                "AAAA",
                &["2001:db8:2::1", "2001:db8:2::2"],
            ),
            rrset("www.example.com.", "AAAA", &["2001:db8:2::3"]),
        ];
        assert_eq!(actual, Ok(expected));
    }

    #[test]
    fn keeps_ttl_and_disabled() {
        let mut sample = rrset("host.example.com.", "AAAA", &["2001:db8:1::1"]);
        sample.ttl = 60;
        sample.records[0].disabled = true;

        let actual = replace_prefix(&[sample], prefix("2001:db8:2::/64"));

        let mut expected = rrset("host.example.com.", "AAAA", &["2001:db8:2::1"]);
        expected.ttl = 60;
        expected.records[0].disabled = true;
        assert_eq!(actual, Ok(vec![expected]));
    }

    #[test]
    fn rejects_invalid_addresses() {
        let sample = [rrset(
            "host.example.com.",
            "AAAA",
            &["2001:db8:1::1", "nonsense"],
        )];

        let actual = replace_prefix(&sample, prefix("2001:db8:2::/64"));

        let expected = PrefixError::InvalidAddress {
            name: "host.example.com.".to_string(),
            content: "nonsense".to_string(),
        };
        assert_eq!(actual, Err(expected));
    }
}
