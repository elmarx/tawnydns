use crate::claim::Claim;
use crate::dns::is_hostname;
use crate::pdns::Route;
use crate::permissions::{AcmeName, Name, Permission, RrType, Zone};
use crate::policy::rule::Rule;
use crate::policy::{Denied, Grant};

/// Decides what a token holder may do with a request, see [`Rule::apply`]. Admin never gets here.
pub fn authorize(claim: &Claim, route: &Route) -> Result<Grant, Denied> {
    Rule::from(route).apply(claim, route.zone())
}

const ACME_CHALLENGE: &str = "_acme-challenge";

impl Claim {
    /// Any permission of the claim is for the PowerDNS API.
    pub fn is_api(&self) -> bool {
        self.permissions.iter().any(Permission::is_api)
    }

    /// Any API permission of the claim is for `zone` (see [`Zone::matches`]).
    pub fn is_zone(&self, zone: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| p.is_api() && p.zone().matches(zone))
    }

    /// Full access to `zone`: the claim has the owner permission for exactly this zone.
    pub fn owns(&self, zone: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| matches!(p, Permission::Owner(z) if z.matches(zone)))
    }

    /// The rrset `name`/`rtype` of `zone` may be read and changed. `name` must be canonical (with
    /// trailing dot).
    pub fn permits_rrset(&self, zone: &str, name: &str, rtype: &str) -> bool {
        self.permissions
            .iter()
            .any(|p| p.permits_rrset(zone, name, rtype))
    }
}

impl Permission {
    fn permits_rrset(&self, zone: &str, name: &str, rtype: &str) -> bool {
        if !self.zone().matches(zone) {
            return false;
        }
        match self {
            Permission::Owner(z) | Permission::AnyRecord(z) => relative_name(z, name).is_some(),
            Permission::Records(z, names, types) => {
                permits_type(types, rtype) && permits_name(z, names, name)
            }
            Permission::AnyName(z, types) => {
                permits_type(types, rtype) && relative_name(z, name).is_some()
            }
            Permission::AnyType(z, names) => permits_name(z, names, name),
            Permission::Acme(z, names) => permits_acme_rrset(z, names, name, rtype),
            Permission::DynDnsHost(_, _) | Permission::DynDnsZone(_) => false,
        }
    }
}

/// A name of a zone, relative to the zone.
#[derive(Debug, PartialEq, Eq)]
enum Relative {
    Apex,
    /// lowercase, without trailing dot, no empty labels
    Name(String),
}

/// `name` relative to `zone`, `None` if it's not part of the zone. `name` must be canonical (with
/// trailing dot) and is case-insensitive. Escapes are never permitted, so the name is compared as
/// pdns parses it.
fn relative_name(zone: &Zone, name: &str) -> Option<Relative> {
    let name = name.strip_suffix('.')?;
    if name.contains('\\') {
        return None;
    }

    let name = name.to_ascii_lowercase();
    let zone = zone.as_str().to_ascii_lowercase();
    if name == zone {
        return Some(Relative::Apex);
    }

    let relative = name.strip_suffix(&format!(".{zone}"))?;
    if relative.split('.').any(str::is_empty) {
        None
    } else {
        Some(Relative::Name(relative.to_string()))
    }
}

/// `name` (canonical, with trailing dot) is one of `names` of `zone`. `@` is the apex only, a
/// wildcard name only the wildcard record.
fn permits_name(zone: &Zone, names: &[Name], name: &str) -> bool {
    let Some(relative) = relative_name(zone, name) else {
        return false;
    };
    names.iter().any(|n| match (n.as_str(), &relative) {
        ("@", relative) => *relative == Relative::Apex,
        (_, Relative::Apex) => false,
        (n, Relative::Name(relative)) => n == relative,
    })
}

/// Types are case-insensitive.
fn permits_type(types: &[RrType], rtype: &str) -> bool {
    types.iter().any(|t| t.as_str().eq_ignore_ascii_case(rtype))
}

/// The rrset `name`/`rtype` is a TXT record `_acme-challenge.<name>` for one of `names`, in `zone`.
/// `name` must be canonical (with trailing dot), names and types are case-insensitive. Escapes are
/// never permitted, so the name is compared as pdns parses it.
fn permits_acme_rrset(zone: &Zone, names: &[AcmeName], name: &str, rtype: &str) -> bool {
    let Some(name) = name.strip_suffix('.') else {
        return false;
    };
    if !rtype.eq_ignore_ascii_case("TXT") || name.contains('\\') {
        return false;
    }

    let name = name.to_ascii_lowercase();
    let zone = zone.as_str().to_ascii_lowercase();
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

    // plain hostname labels only, the same as for names of the permission
    if relative.is_some_and(|relative| !is_hostname(relative)) {
        return false;
    }

    names.iter().any(|n| match (n.as_str(), relative) {
        ("@" | "*", None) | ("*", Some(_)) => true,
        (n, Some(relative)) => n == relative,
        (_, None) => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::fixtures::claim;
    use crate::permissions::fixtures::{acme, names, owner, zone};

    fn dyndns_claim() -> Claim {
        claim(vec![
            Permission::DynDnsHost(zone("example.com"), names(&["home"])),
            Permission::DynDnsZone(zone("example.org")),
        ])
    }

    #[test]
    fn dyndns_is_no_zone_of_the_api() {
        let sample = claim(vec![
            owner("example.com"),
            Permission::DynDnsHost(zone("example.org"), names(&["home"])),
            Permission::DynDnsZone(zone("example.net")),
        ]);

        assert!(sample.is_api());
        assert!(sample.is_zone("example.com."));
        assert!(!sample.is_zone("example.org."));
        assert!(!sample.is_zone("example.net."));
        assert!(!dyndns_claim().is_api());
    }

    #[test]
    fn dyndns_only_is_denied_every_route() {
        for (method, path) in [
            (http::Method::GET, "/api"),
            (http::Method::GET, "/api/v1/servers"),
            (http::Method::GET, "/api/v1/servers/localhost"),
            (http::Method::GET, "/api/v1/servers/localhost/zones"),
            (http::Method::POST, "/api/v1/servers/localhost/zones"),
            (
                http::Method::GET,
                "/api/v1/servers/localhost/zones/example.com.",
            ),
            (
                http::Method::PATCH,
                "/api/v1/servers/localhost/zones/example.com.",
            ),
            (
                http::Method::PUT,
                "/api/v1/servers/localhost/zones/example.org./notify",
            ),
        ] {
            let route = Route::try_from((&method, path)).unwrap();

            let actual = authorize(&dyndns_claim(), &route);

            assert_eq!(actual, Err(Denied::Permission), "{method} {path}");
        }
    }

    fn owner_claim(zone: &str) -> Claim {
        claim(vec![owner(zone)])
    }

    fn acme_claim(names: &[&str]) -> Claim {
        claim(vec![acme("example.com", names)])
    }

    #[test]
    fn owns_zone_of_claim() {
        assert!(owner_claim("example.com").owns("example.com"));
    }

    #[test]
    fn owns_zone_of_claim_with_trailing_dot() {
        assert!(owner_claim("example.com").owns("example.com."));
    }

    #[test]
    fn does_not_own_zone_not_in_claim() {
        let claim = owner_claim("example.com");

        assert!(!claim.owns("example.org."));
        assert!(!claim.owns("sub.example.com."));
    }

    #[test]
    fn does_not_own_different_case() {
        assert!(!owner_claim("example.com").owns("Example.COM."));
    }

    #[test]
    fn acme_is_zone_but_no_full_access() {
        let sample = acme_claim(&["*"]);

        assert!(sample.is_zone("example.com."));
        assert!(!sample.is_zone("example.org."));
        assert!(!sample.owns("example.com."));
    }

    #[test]
    fn permissions_add_up() {
        let sample = claim(vec![owner("example.com"), acme("example.org", &["www"])]);

        assert!(sample.is_zone("example.com."));
        assert!(sample.is_zone("example.org."));
        assert!(!sample.is_zone("example.net."));
        assert!(sample.owns("example.com."));
        assert!(!sample.owns("example.org."));
    }

    mod rrset {
        use super::*;

        #[test]
        fn dyndns_permits_no_rrset() {
            let sample = claim(vec![
                Permission::DynDnsHost(zone("example.com"), names(&["home", "@"])),
                Permission::DynDnsZone(zone("example.com")),
            ]);

            assert!(!sample.permits_rrset("example.com.", "home.example.com.", "A"));
            assert!(!sample.permits_rrset("example.com.", "example.com.", "AAAA"));
        }

        #[test]
        fn owner_permits_any_rrset_of_its_zone() {
            let sample = owner_claim("example.com");

            assert!(sample.permits_rrset("example.com.", "www.example.com.", "A"));
            assert!(sample.permits_rrset("example.com.", "example.com.", "SOA"));
            assert!(!sample.permits_rrset("example.org.", "www.example.org.", "A"));
        }

        #[test]
        fn checks_names_against_permissions_of_the_given_zone_only() {
            let sample = claim(vec![
                acme("example.com", &["*"]),
                acme("sub.example.com", &["www"]),
            ]);

            assert!(sample.permits_rrset(
                "sub.example.com.",
                "_acme-challenge.www.sub.example.com.",
                "TXT"
            ));
            assert!(!sample.permits_rrset(
                "sub.example.com.",
                "_acme-challenge.other.sub.example.com.",
                "TXT"
            ));
            assert!(sample.permits_rrset(
                "example.com.",
                "_acme-challenge.other.sub.example.com.",
                "TXT"
            ));
        }
    }

    mod records_rrset {
        use super::*;
        use crate::permissions::fixtures::{names, types, zone};

        const ZONE: &str = "example.com.";

        fn records(names_: &[&str], types_: &[&str]) -> Claim {
            claim(vec![Permission::Records(
                zone("example.com"),
                names(names_),
                types(types_),
            )])
        }

        #[test]
        fn records_permits_names_and_types() {
            let sample = records(&["home", "@", "a.b"], &["A", "AAAA"]);

            for (name, rtype) in [
                ("home.example.com.", "A"),
                ("home.example.com.", "AAAA"),
                ("Home.Example.COM.", "aaaa"),
                ("example.com.", "A"),
                ("a.b.example.com.", "A"),
            ] {
                assert!(sample.permits_rrset(ZONE, name, rtype), "{name} {rtype}");
            }
        }

        #[test]
        fn records_rejects_other_names_and_types() {
            let sample = records(&["home", "@"], &["A"]);

            for (name, rtype) in [
                ("home.example.com.", "AAAA"),
                ("home.example.com.", "TXT"),
                ("other.example.com.", "A"),
                ("x.home.example.com.", "A"),
                ("@.example.com.", "A"),
                ("*.example.com.", "A"),
                ("home.example.org.", "A"),
                ("home.example.com", "A"),
                ("home..example.com.", "A"),
                ("ho\\109e.example.com.", "A"),
                ("homeexample.com.", "A"),
            ] {
                assert!(!sample.permits_rrset(ZONE, name, rtype), "{name} {rtype}");
            }
        }

        #[test]
        fn records_wildcard_name_is_the_wildcard_record() {
            let sample = records(&["*", "*.dev"], &["A"]);

            assert!(sample.permits_rrset(ZONE, "*.example.com.", "A"));
            assert!(sample.permits_rrset(ZONE, "*.dev.example.com.", "A"));
            assert!(!sample.permits_rrset(ZONE, "www.example.com.", "A"));
            assert!(!sample.permits_rrset(ZONE, "example.com.", "A"));
            assert!(!sample.permits_rrset(ZONE, "x.dev.example.com.", "A"));
        }

        #[test]
        fn unexpected_names_of_the_token_do_not_match() {
            let sample = records(&["", "WWW", "home.", "a..b"], &["A"]);

            for name in [
                "example.com.",
                ".example.com.",
                "www.example.com.",
                "WWW.example.com.",
                "home.example.com.",
                "home..example.com.",
                "a..b.example.com.",
            ] {
                assert!(!sample.permits_rrset(ZONE, name, "A"), "{name}");
            }
        }

        #[test]
        fn any_name_permits_types_of_all_names() {
            let sample = claim(vec![Permission::AnyName(
                zone("example.com"),
                types(&["TXT"]),
            )]);

            for name in ["example.com.", "www.example.com.", "*.a.b.example.com."] {
                assert!(sample.permits_rrset(ZONE, name, "TXT"), "{name}");
            }
            for (name, rtype) in [
                ("www.example.com.", "A"),
                ("www.example.org.", "TXT"),
                ("w\\119w.example.com.", "TXT"),
            ] {
                assert!(!sample.permits_rrset(ZONE, name, rtype), "{name} {rtype}");
            }
        }

        #[test]
        fn any_type_permits_all_types_of_names() {
            let sample = claim(vec![Permission::AnyType(
                zone("example.com"),
                names(&["home"]),
            )]);

            for rtype in ["A", "TXT", "NS", "CNAME"] {
                assert!(
                    sample.permits_rrset(ZONE, "home.example.com.", rtype),
                    "{rtype}"
                );
            }
            assert!(!sample.permits_rrset(ZONE, "www.example.com.", "A"));
            assert!(!sample.permits_rrset(ZONE, "example.com.", "A"));
        }

        #[test]
        fn any_record_permits_all_records_of_the_zone() {
            let sample = claim(vec![Permission::AnyRecord(zone("example.com"))]);

            assert!(sample.permits_rrset(ZONE, "example.com.", "SOA"));
            assert!(sample.permits_rrset(ZONE, "www.example.com.", "A"));
            assert!(!sample.permits_rrset(ZONE, "www.example.org.", "A"));
            assert!(!sample.permits_rrset("example.org.", "www.example.org.", "A"));
            assert!(!sample.owns(ZONE));
        }
    }

    mod acme_rrset {
        use super::*;

        fn assert_permits(names: &[&str], rrsets: &[(&str, &str)]) {
            let claim = acme_claim(names);
            for (name, rtype) in rrsets {
                assert!(
                    claim.permits_rrset("example.com.", name, rtype),
                    "{names:?}: {name} {rtype}"
                );
            }
        }

        fn assert_rejects(names: &[&str], rrsets: &[(&str, &str)]) {
            let claim = acme_claim(names);
            for (name, rtype) in rrsets {
                assert!(
                    !claim.permits_rrset("example.com.", name, rtype),
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
        fn unexpected_names_of_the_token_do_not_match() {
            assert_rejects(
                &["", "a..b", "*.www", "WWW", "www."],
                &[
                    ("_acme-challenge..example.com.", "TXT"),
                    ("_acme-challenge.a..b.example.com.", "TXT"),
                    ("_acme-challenge.*.www.example.com.", "TXT"),
                    ("_acme-challenge.www.example.com.", "TXT"),
                    ("_acme-challenge.WWW.example.com.", "TXT"),
                    ("_acme-challenge.www..example.com.", "TXT"),
                ],
            );
        }

        #[test]
        fn acme_of_other_zone_is_not_permitted() {
            let sample = claim(vec![acme("example.org", &["*"])]);

            assert!(!sample.permits_rrset("example.com.", "_acme-challenge.example.com.", "TXT"));
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
                    grant(None, Some(ResponseFilter::Rrsets)),
                ),
                (
                    http::Method::PATCH,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(Some(BodyCheck::Rrsets), None),
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
            ] {
                let actual = authorize_acme(&method, path);

                assert_eq!(actual, Err(Denied::Permission), "{method} {path}");
            }
        }

        #[test]
        fn leaves_creating_a_zone_to_the_body_check() {
            let actual = authorize_acme(&http::Method::POST, "/api/v1/servers/localhost/zones");

            let expected = Grant {
                body_condition: Some(BodyCheck::CreateZone),
                filter: None,
            };
            assert_eq!(actual, Ok(expected));
        }

        #[test]
        fn denies_routes_never_permitted() {
            for (method, path) in [
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

    mod mixed_routes {
        use super::*;
        use crate::policy::{BodyCheck, ResponseFilter};

        fn authorize_mixed(method: &http::Method, path: &str) -> Result<Grant, Denied> {
            let sample = claim(vec![owner("example.com"), acme("example.org", &["www"])]);
            let route = Route::try_from((method, path)).unwrap();
            authorize(&sample, &route)
        }

        #[test]
        fn grants_per_zone() {
            let grant = |body_condition, filter| {
                Ok(Grant {
                    body_condition,
                    filter,
                })
            };
            for (method, path, expected) in [
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones",
                    grant(None, Some(ResponseFilter::ZoneList)),
                ),
                (
                    http::Method::POST,
                    "/api/v1/servers/localhost/zones",
                    grant(Some(BodyCheck::CreateZone), None),
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(None, None),
                ),
                (
                    http::Method::DELETE,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(None, None),
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.org.",
                    grant(None, Some(ResponseFilter::Rrsets)),
                ),
                (
                    http::Method::PATCH,
                    "/api/v1/servers/localhost/zones/example.org.",
                    grant(Some(BodyCheck::Rrsets), None),
                ),
                (
                    http::Method::DELETE,
                    "/api/v1/servers/localhost/zones/example.org.",
                    Err(Denied::Permission),
                ),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.com.",
                    grant(Some(BodyCheck::PutZone), None),
                ),
                (
                    http::Method::PUT,
                    "/api/v1/servers/localhost/zones/example.org.",
                    Err(Denied::Permission),
                ),
                (
                    http::Method::GET,
                    "/api/v1/servers/localhost/zones/example.net.",
                    Err(Denied::Zone),
                ),
                (
                    http::Method::DELETE,
                    "/api/v1/servers/localhost/zones/example.net.",
                    Err(Denied::Zone),
                ),
            ] {
                let actual = authorize_mixed(&method, path);

                assert_eq!(actual, expected, "{method} {path}");
            }
        }
    }
}
