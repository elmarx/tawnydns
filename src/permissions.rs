//! What the holder of a token may do.

/// What the holder of a token may do with its zone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Permission {
    /// full access to the zone
    Owner,
    /// solve ACME DNS-01 challenges for these names, relative to the zone: `@` for the apex, `*`
    /// for any name of the zone, or lowercase labels like `www` or `a.b`, without trailing dot
    Acme(Vec<String>),
}
