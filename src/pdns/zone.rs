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
