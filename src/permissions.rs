//! What the holder of a token may do. Purely declarative: the contents are checked when a token is
//! created (see [`crate::token`]), not when it is decoded. Unexpected contents just do not match.

use serde::{Deserialize, Serialize};

/// A permission for a single zone; permissions of a claim add up.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Permission {
    /// full access to the zone, including creating and deleting it
    #[serde(rename = "o")]
    Owner(Zone),
    /// all records of the zone, but not the zone itself
    #[serde(rename = "x")]
    AnyRecord(Zone),
    /// records with one of these names and one of these types
    #[serde(rename = "r")]
    Records(Zone, Vec<Name>, Vec<RrType>),
    /// records of any name with one of these types
    #[serde(rename = "n")]
    AnyName(Zone, Vec<RrType>),
    /// records of any type with one of these names
    #[serde(rename = "t")]
    AnyType(Zone, Vec<Name>),
    /// solve ACME DNS-01 challenges for these names (see [`AcmeName`])
    #[serde(rename = "a")]
    Acme(Zone, Vec<AcmeName>),
    /// dyndns only: update A/AAAA records with these names, no access to the PowerDNS API
    #[serde(rename = "h")]
    DynDnsHost(Zone, Vec<Name>),
    /// dyndns only: update the prefix of all AAAA records of the zone, no access to the PowerDNS
    /// API
    #[serde(rename = "z")]
    DynDnsZone(Zone),
}

impl Permission {
    pub fn zone(&self) -> &Zone {
        match self {
            Permission::Owner(zone)
            | Permission::AnyRecord(zone)
            | Permission::Records(zone, _, _)
            | Permission::AnyName(zone, _)
            | Permission::AnyType(zone, _)
            | Permission::Acme(zone, _)
            | Permission::DynDnsHost(zone, _)
            | Permission::DynDnsZone(zone) => zone,
        }
    }

    /// The permission is for the PowerDNS API, not just for dyndns.
    pub fn is_api(&self) -> bool {
        match self {
            Permission::Owner(_)
            | Permission::AnyRecord(_)
            | Permission::Records(_, _, _)
            | Permission::AnyName(_, _)
            | Permission::AnyType(_, _)
            | Permission::Acme(_, _) => true,
            Permission::DynDnsHost(_, _) | Permission::DynDnsZone(_) => false,
        }
    }
}

/// A zone, without trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Zone(String);

impl Zone {
    pub fn new(zone: String) -> Self {
        Self(zone)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `zone` is this zone. Exact match, `example.com` does not match `sub.example.com.`, a single
    /// trailing dot of `zone` is ignored.
    pub fn matches(&self, zone: &str) -> bool {
        zone.strip_suffix('.').unwrap_or(zone) == self.0
    }
}

/// A name of the acme permission, relative to the zone: `@` for the apex, `*` for any name of the
/// zone, or lowercase labels like `www` or `a.b`, without trailing dot.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct AcmeName(String);

impl AcmeName {
    pub fn new(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A name of a record, relative to the zone: `@` for the apex or lowercase labels like `www` or
/// `a.b`, without trailing dot. The first label may be `*`, for wildcard records like `*` or
/// `*.dev`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Name(String);

impl Name {
    pub fn new(name: String) -> Self {
        Self(name)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A record type, uppercase like `AAAA`, or generic like `TYPE65534`. Any type is accepted, pdns
/// decides what it supports.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct RrType(String);

impl RrType {
    pub fn new(rtype: String) -> Self {
        Self(rtype)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
pub mod fixtures {
    use super::*;

    pub fn zone(zone: &str) -> Zone {
        Zone::new(zone.to_string())
    }

    pub fn owner(zone: &str) -> Permission {
        Permission::Owner(self::zone(zone))
    }

    pub fn names(names: &[&str]) -> Vec<Name> {
        names.iter().map(|n| Name::new((*n).to_string())).collect()
    }

    pub fn types(types: &[&str]) -> Vec<RrType> {
        types
            .iter()
            .map(|t| RrType::new((*t).to_string()))
            .collect()
    }

    pub fn acme(zone: &str, names: &[&str]) -> Permission {
        let names = names.iter().map(|n| AcmeName::new((*n).to_string()));
        Permission::Acme(self::zone(zone), names.collect())
    }
}
