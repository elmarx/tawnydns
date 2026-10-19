//! Rule application: applies a rule to a claim/zone to generate a Grant

use crate::policy::grant::{Denied, Grant};
use crate::policy::{BodyCheck, ResponseFilter};
use crate::token::Claim;
use dsl::{granted, granted_with_condition, granted_with_filter, route_denied, zone_denied};

/// What a route requires, independent of the claim.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rule {
    /// always deny
    Never,
    /// always allow
    Open,
    /// allow if the route's zone is the zone of the claim
    Zone,
    /// zone check, then filter the response by the claim
    ZoneAndFilter(ResponseFilter),
    /// zone check, then inspect the body
    ZoneAndBody(BodyCheck),
    /// the claim is checked against the body only (the zone is not part of the path)
    Body(BodyCheck),
    /// allow, but filter the response by the claim
    FilteredList(ResponseFilter),
}

impl Rule {
    /// Resolves the rule for a concrete request; `zone` is the zone addressed by the path, if any.
    pub fn apply(self, claim: &Claim, zone: Option<&str>) -> Result<Grant, Denied> {
        let zone_permitted = zone.is_some_and(|z| claim.is_zone(z));

        match self {
            Rule::Never => route_denied(),
            Rule::Open => granted(),
            Rule::Zone if zone_permitted => granted(),
            Rule::ZoneAndBody(kind) if zone_permitted => granted_with_condition(kind),
            Rule::ZoneAndFilter(kind) if zone_permitted => granted_with_filter(kind),
            Rule::Zone | Rule::ZoneAndBody(_) | Rule::ZoneAndFilter(_) => zone_denied(),
            Rule::Body(kind) => granted_with_condition(kind),
            Rule::FilteredList(kind) => granted_with_filter(kind),
        }
    }
}

mod dsl {
    use crate::policy::{BodyCheck, Denied, Grant, ResponseFilter};

    #[expect(
        clippy::unnecessary_wraps,
        reason = "this is a helper to construct the Decision"
    )]
    pub fn granted() -> Result<Grant, Denied> {
        Ok(Grant {
            filter: None,
            body_condition: None,
        })
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "this is a helper to construct the Decision"
    )]
    pub fn granted_with_condition(kind: BodyCheck) -> Result<Grant, Denied> {
        Ok(Grant {
            filter: None,
            body_condition: Some(kind),
        })
    }

    #[expect(
        clippy::unnecessary_wraps,
        reason = "this is a helper to construct the Decision"
    )]
    pub fn granted_with_filter(kind: ResponseFilter) -> Result<Grant, Denied> {
        Ok(Grant {
            filter: Some(kind),
            body_condition: None,
        })
    }

    pub fn route_denied() -> Result<Grant, Denied> {
        Err(Denied::Route)
    }

    pub fn zone_denied() -> Result<Grant, Denied> {
        Err(Denied::Zone)
    }
}
