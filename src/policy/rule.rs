//! Rule application: applies a rule to a claim/zone to generate a Grant

use crate::claim::Claim;
use crate::policy::grant::{Denied, Grant};
use crate::policy::{BodyCheck, ResponseFilter};
use dsl::{
    granted, granted_with_condition, granted_with_filter, permission_denied, route_denied,
    zone_denied,
};

/// What a route requires, independent of the claim.
///
/// The `Zone…` rules grant every permission for the zone, the filter or body check is applied
/// to non-owners only. The `Owner…` rules require the owner permission for the zone. Without a
/// zone in the path (creating a zone), `OwnerAndBody` leaves that to the body check.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rule {
    /// always deny
    Never,
    /// always allow
    Open,
    /// allow if the claim has a permission for the route's zone
    Zone,
    /// zone check, then filter the response for non-owners
    ZoneAndFilter(ResponseFilter),
    /// zone check, then inspect the body for non-owners
    ZoneAndBody(BodyCheck),
    /// allow owners only
    Owner,
    /// allow owners only, then inspect the body
    OwnerAndBody(BodyCheck),
    /// allow, but filter the response by the claim
    FilteredList(ResponseFilter),
}

impl Rule {
    /// Resolves the rule for a concrete request; `zone` is the zone addressed by the path, if any.
    pub fn apply(self, claim: &Claim, zone: Option<&str>) -> Result<Grant, Denied> {
        match (self, zone) {
            (Rule::Never, _) => route_denied(),
            (Rule::Open, _) => granted(),
            (Rule::FilteredList(kind), _) => granted_with_filter(kind),
            // creating a zone: the zone is in the body, the body check requires the owner permission
            (Rule::OwnerAndBody(kind), None) => granted_with_condition(kind),
            (_, None) => zone_denied(),
            (_, Some(z)) if !claim.is_zone(z) => zone_denied(),
            (Rule::OwnerAndBody(kind), Some(z)) if claim.owns(z) => granted_with_condition(kind),
            (_, Some(z)) if claim.owns(z) => granted(),
            (Rule::Owner | Rule::OwnerAndBody(_), Some(_)) => permission_denied(),
            (Rule::Zone, Some(_)) => granted(),
            (Rule::ZoneAndFilter(kind), Some(_)) => granted_with_filter(kind),
            (Rule::ZoneAndBody(kind), Some(_)) => granted_with_condition(kind),
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

    pub fn permission_denied() -> Result<Grant, Denied> {
        Err(Denied::Permission)
    }
}
