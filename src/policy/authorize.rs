use crate::pdns::Route;
use crate::policy::rule::Rule;
use crate::policy::{Denied, Grant};
use crate::token::{Claim, Permission, validate_acme_name};

/// Decides what a token holder may do with a request. Admin never gets here.
pub fn authorize(claim: &Claim, route: &Route) -> Result<Grant, Denied> {
    let rule = match claim.permission {
        Permission::Owner => Rule::owner(route),
        Permission::Acme(_) => Rule::acme(route),
    };

    rule.apply(claim, route.zone())
}

const ACME_CHALLENGE: &str = "_acme-challenge";

impl Claim {
    /// `zone` is the zone of the claim, whatever the permission. Exact match, a claim for
    /// `example.com` does not cover `sub.example.com.`. The claim holds the zone without trailing
    /// dot, a single trailing dot of `zone` is ignored.
    pub fn is_zone(&self, zone: &str) -> bool {
        let zone = zone.strip_suffix('.').unwrap_or(zone);
        self.zone == zone
    }

    /// Full access to `zone`: the claim is an owner of exactly this zone.
    pub fn permits(&self, zone: &str) -> bool {
        self.permission == Permission::Owner && self.is_zone(zone)
    }

    /// The rrset `name`/`rtype` is a TXT record `_acme-challenge.<name>` for a name of the acme
    /// permission, in the zone of the claim. `name` must be canonical (with trailing dot), names
    /// and types are case-insensitive. Escapes are never permitted, so the name is compared as
    /// pdns parses it.
    pub fn permits_acme_rrset(&self, name: &str, rtype: &str) -> bool {
        let Permission::Acme(names) = &self.permission else {
            return false;
        };
        let Some(name) = name.strip_suffix('.') else {
            return false;
        };
        if !rtype.eq_ignore_ascii_case("TXT") || name.contains('\\') {
            return false;
        }

        let name = name.to_ascii_lowercase();
        let zone = self.zone.to_ascii_lowercase();
        let Some(relative) = name
            .strip_prefix(ACME_CHALLENGE)
            .and_then(|n| n.strip_prefix('.'))
        else {
            return false;
        };

        // the name below `_acme-challenge`, relative to the zone, `None` for the apex
        let relative = if relative == zone {
            None
        } else if let Some(relative) = relative.strip_suffix(&format!(".{zone}")) {
            Some(relative)
        } else {
            return false;
        };

        names.iter().any(|n| match (n.as_str(), relative) {
            ("@" | "*", None) => true,
            // plain hostname labels only, the same as for names of the permission
            ("*", Some(relative)) => {
                relative != "@" && relative != "*" && validate_acme_name(relative).is_ok()
            }
            ("@", Some(_)) | (_, None) => false,
            (n, Some(relative)) => n == relative,
        })
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

    fn acme_claim(names: &[&str]) -> Claim {
        Claim {
            zone: "example.com".to_string(),
            permission: Permission::Acme(names.iter().map(ToString::to_string).collect()),
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
    fn acme_is_zone_but_no_full_access() {
        let sample = acme_claim(&["*"]);

        assert!(sample.is_zone("example.com."));
        assert!(!sample.is_zone("example.org."));
        assert!(!sample.permits("example.com."));
    }

    mod acme_rrset {
        use super::*;

        fn assert_permits(names: &[&str], rrsets: &[(&str, &str)]) {
            let claim = acme_claim(names);
            for (name, rtype) in rrsets {
                assert!(
                    claim.permits_acme_rrset(name, rtype),
                    "{names:?}: {name} {rtype}"
                );
            }
        }

        fn assert_rejects(names: &[&str], rrsets: &[(&str, &str)]) {
            let claim = acme_claim(names);
            for (name, rtype) in rrsets {
                assert!(
                    !claim.permits_acme_rrset(name, rtype),
                    "{names:?}: {name} {rtype}"
                );
            }
        }

        #[test]
        fn permits_challenge_of_name() {
            assert_permits(
                &["www", "a.b"],
                &[
                    ("_acme-challenge.www.example.com.", "TXT"),
                    ("_acme-challenge.a.b.example.com.", "TXT"),
                    ("_ACME-Challenge.WWW.Example.COM.", "txt"),
                ],
            );
        }

        #[test]
        fn permits_challenge_of_apex() {
            assert_permits(&["@"], &[("_acme-challenge.example.com.", "TXT")]);
        }

        #[test]
        fn permits_challenges_of_any_name() {
            assert_permits(
                &["*"],
                &[
                    ("_acme-challenge.example.com.", "TXT"),
                    ("_acme-challenge.www.example.com.", "TXT"),
                    ("_acme-challenge.a.b.c.example.com.", "TXT"),
                ],
            );
        }

        #[test]
        fn rejects_other_types() {
            for rtype in [
                "A", "AAAA", "CNAME", "NS", "DNAME", "SOA", "CAA", "TXT2", "",
            ] {
                assert_rejects(&["*"], &[("_acme-challenge.www.example.com.", rtype)]);
            }
        }

        #[test]
        fn rejects_other_names() {
            assert_rejects(
                &["www"],
                &[
                    ("www.example.com.", "TXT"),
                    ("_acme-challenge.example.com.", "TXT"),
                    ("_acme-challenge.other.example.com.", "TXT"),
                    ("_acme-challenge.x.www.example.com.", "TXT"),
                    ("x._acme-challenge.www.example.com.", "TXT"),
                    ("_acme-challengewww.example.com.", "TXT"),
                    ("_acme-challenge.www.example.com", "TXT"),
                    ("_acme-challenge.www.example.com..", "TXT"),
                ],
            );
        }

        #[test]
        fn rejects_names_outside_zone() {
            assert_rejects(
                &["*"],
                &[
                    ("_acme-challenge.example.org.", "TXT"),
                    ("_acme-challenge.www.example.org.", "TXT"),
                    ("_acme-challenge.notexample.com.", "TXT"),
                    ("_acme-challenge.com.", "TXT"),
                    ("_acme-challenge.", "TXT"),
                    (".", "TXT"),
                ],
            );
        }

        #[test]
        fn rejects_wildcards_and_empty_labels_for_any_name() {
            assert_rejects(
                &["*"],
                &[
                    ("_acme-challenge.*.example.com.", "TXT"),
                    ("_acme-challenge.a.*.example.com.", "TXT"),
                    ("*.example.com.", "TXT"),
                    ("_acme-challenge..example.com.", "TXT"),
                    ("_acme-challenge.a..example.com.", "TXT"),
                ],
            );
        }

        #[test]
        fn rejects_names_literally() {
            assert_rejects(
                &["*", "@"],
                &[
                    ("_acme-challenge.@.example.com.", "TXT"),
                    ("_acme-challenge.*.example.com.", "TXT"),
                ],
            );
        }

        #[test]
        fn rejects_escapes() {
            assert_rejects(
                &["*", "www"],
                &[
                    ("_acme-challenge.w\\119w.example.com.", "TXT"),
                    ("_acme-challenge.a\\.b.example.com.", "TXT"),
                    ("_acme-challenge\\.www.example.com.", "TXT"),
                ],
            );
        }

        #[test]
        fn owner_has_no_acme_permission() {
            assert!(
                !claim("example.com").permits_acme_rrset("_acme-challenge.example.com.", "TXT")
            );
        }
    }

    mod acme_routes {
        use super::*;
        use crate::policy::{BodyCheck, ResponseFilter};

        fn route(method: &http::Method, path: &str) -> Route {
            Route::try_from((method, path)).unwrap()
        }

        fn authorize_acme(method: &http::Method, path: &str) -> Result<Grant, Denied> {
            authorize(&acme_claim(&["www"]), &route(method, path))
        }

        #[test]
        fn grants_what_acme_clients_need() {
            let grant = |body_condition, filter| {
                Ok(Grant {
                    body_condition,
                    filter,
                })
            };
            for (method, path, expected) in [
                (http::Method::GET, "/api", grant(None, None)),
                (http::Method::GET, "/api/v1/servers", grant(None, None)),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost",
                    grant(None, None),
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones",
                    grant(None, Some(ResponseFilter::ZoneList)),
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(None, Some(ResponseFilter::AcmeRrsets)),
                ),
                (
                    http::Method::PATCH,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(Some(BodyCheck::AcmeRrsets), None),
                ),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.com./notify",
                    grant(None, None),
                ),
            ] {
                let actual = authorize_acme(&method, path);

                assert_eq!(actual, expected, "{method} {path}");
            }
        }

        #[test]
        fn denies_other_zones() {
            for (method, path) in [
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.org.",
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/www.example.com.",
                ),
                (
                    http::Method::PATCH,
                    "/api/v1/servers/localhost/zones/example.org.",
                ),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.org./notify",
                ),
            ] {
                let actual = authorize_acme(&method, path);

                assert_eq!(actual, Err(Denied::Zone), "{method} {path}");
            }
        }

        #[test]
        fn denies_zone_management() {
            for (method, path) in [
                (http::Method::POST, "/api/v1/servers/localhost/zones"),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.com.",
                ),
                (
                    http::Method::DELETE,
                    "/api/v1/servers/localhost/zones/example.com.",
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.com./export",
                ),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.com./rectify",
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.com./metadata",
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.com./cryptokeys",
                ),
                (http::Method::GET, "/api/v1/servers/localhost/tsigkeys"),
            ] {
                let actual = authorize_acme(&method, path);

                assert_eq!(actual, Err(Denied::Route), "{method} {path}");
            }
        }
    }
}
