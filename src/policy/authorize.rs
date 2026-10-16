use crate::pdns::Route;
use crate::policy::rule::Rule;
use crate::policy::{Denied, Grant};
use crate::token::Claim;

/// Decides what a token holder may do with a request. Admin never gets here.
pub fn authorize(claim: &Claim, route: &Route) -> Result<Grant, Denied> {
    Rule::from(route).apply(claim, route.zone())
}

impl Claim {
    /// Exact match on the zone name, a claim for `example.com` does not cover `sub.example.com.`.
    /// The claim holds zones without trailing dot, a single trailing dot of `zone` is ignored.
    pub fn permits(&self, zone: &str) -> bool {
        let zone = zone.strip_suffix('.').unwrap_or(zone);
        self.zones.iter().any(|z| z == zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(zones: &[&str]) -> Claim {
        Claim {
            zones: zones.iter().map(ToString::to_string).collect(),
        }
    }

    #[test]
    fn permits_zone_of_claim() {
        assert!(&claim(&["example.com"]).permits("example.com"));
    }

    #[test]
    fn permits_zone_of_claim_with_trailing_dot() {
        assert!(&claim(&["example.com"]).permits("example.com."));
    }

    #[test]
    fn rejects_zone_not_in_claim() {
        let claim = claim(&["example.com"]);

        assert!(!claim.permits("example.org."));
        assert!(!&claim.permits("sub.example.com."));
    }

    #[test]
    fn rejects_different_case() {
        assert!(!claim(&["example.com"]).permits("Example.COM."));
    }
}
