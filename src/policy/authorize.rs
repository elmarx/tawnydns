use crate::pdns::Route;
use crate::policy::rule::Rule;
use crate::policy::{Denied, Grant};
use crate::token::{Claim, Permission};

/// Decides what a token holder may do with a request. Admin never gets here.
pub fn authorize(claim: &Claim, route: &Route) -> Result<Grant, Denied> {
    match claim.permission {
        Permission::Owner => Rule::from(route).apply(claim, route.zone()),
        // not supported by the policy yet
        Permission::Acme(_) => Err(Denied::Route),
    }
}

impl Claim {
    /// Full access to `zone`: the claim is an owner of exactly this zone, a claim for
    /// `example.com` does not cover `sub.example.com.`. The claim holds the zone without trailing
    /// dot, a single trailing dot of `zone` is ignored.
    pub fn permits(&self, zone: &str) -> bool {
        let zone = zone.strip_suffix('.').unwrap_or(zone);
        self.permission == Permission::Owner && self.zone == zone
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(zone: &str) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Owner,
        }
    }

    fn acme_claim(zone: &str) -> Claim {
        Claim {
            zone: zone.to_string(),
            permission: Permission::Acme(vec!["*".to_string()]),
        }
    }

    #[test]
    fn permits_zone_of_claim() {
        assert!(&claim("example.com").permits("example.com"));
    }

    #[test]
    fn permits_zone_of_claim_with_trailing_dot() {
        assert!(&claim("example.com").permits("example.com."));
    }

    #[test]
    fn rejects_zone_not_in_claim() {
        let claim = claim("example.com");

        assert!(!claim.permits("example.org."));
        assert!(!&claim.permits("sub.example.com."));
    }

    #[test]
    fn rejects_different_case() {
        assert!(!claim("example.com").permits("Example.COM."));
    }

    #[test]
    fn acme_is_no_full_access() {
        assert!(!acme_claim("example.com").permits("example.com."));
    }

    #[test]
    fn acme_is_denied_for_now() {
        let sample = Route::GetZone {
            server: "localhost".to_string(),
            zone: "example.com.".to_string(),
        };

        let actual = authorize(&acme_claim("example.com"), &sample);

        assert_eq!(actual, Err(Denied::Route));
    }
}
