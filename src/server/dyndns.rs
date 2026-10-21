//! dyndns2 update endpoints, for routers (e.g. FRITZ!Box) and clients like ddclient.
//!
//! The request determines what is updated, the permissions only allow or deny it (nothing is
//! derived from the token):
//! - `ip6lanprefix`: update the prefix of all AAAA records of the zone, requires `DynDnsZone`
//! - `hostname` with `myip`/`ipaddr`/`ip6addr`: update the addresses of the hosts, requires
//!   `DynDnsHost` for each of them. `DynDnsZone` doesn't cover single hosts.
//! - everything requested must be allowed, else the whole request is rejected (no partial updates)
//!
//! Responses are dyndns2 plain text: `good <ip>`, `nochg <ip>`, `badauth`, `nohost`, `notfqdn`,
//! `dnserr`, `911`.

use crate::server::types::TawnyState;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use serde::Deserialize;

/// The query parameters of a dyndns2 update.
#[derive(Debug, Deserialize)]
#[expect(dead_code, reason = "not implemented yet")]
pub struct UpdateParameters {
    /// the host(s) to update, comma-separated (classic dyndns2, e.g. ddclient)
    hostname: Option<String>,
    /// the IPv4 address of the host (classic dyndns2)
    myip: Option<String>,
    /// the IPv4 address (FRITZ!Box `<ipaddr>`)
    ipaddr: Option<String>,
    /// the IPv6 address (FRITZ!Box `<ip6addr>`)
    ip6addr: Option<String>,
    /// the delegated IPv6 prefix (FRITZ!Box `<ip6lanprefix>`), to update a whole zone
    ip6lanprefix: Option<ipnet::Ipv6Net>,
    /// the domain of the router (FRITZ!Box `<domain>`)
    domain: Option<String>,
}

/// `GET /nic/update`, standard dyndns2: the zone is taken from the token.
pub async fn update(
    State(state): State<TawnyState>,
    headers: HeaderMap,
    Query(parameters): Query<UpdateParameters>,
) -> String {
    // To check:
    // - with `hostname`: for every hostname, find a `DynDnsHost(zone, names)` of the claim it
    //   matches: `hostname == zone` and `names` contains `@`, or `hostname == name.zone` for a
    //   `name` of `names`
    //   - normalize both sides before comparing: lowercase, no trailing dot
    //   - no matching permission: `nohost`
    //   - the matching permission gives the zone (to PATCH) and the name
    // - without `hostname`: no host update (not "all hosts of the token")
    // - with `ip6lanprefix`: the zone comes from `domain` (never from the token), without
    //   `domain`: `notfqdn`; continue as in `update_zone`
    let _ = (state, headers, parameters);
    todo!("dyndns2 update, the zone from the token")
}

/// `GET /nic/update/{zone}`, the zone is given explicitly (not standard dyndns2, but routers and
/// clients allow to configure the path).
pub async fn update_zone(
    State(state): State<TawnyState>,
    headers: HeaderMap,
    Path(zone): Path<String>,
    Query(parameters): Query<UpdateParameters>,
) -> String {
    // To check:
    // - normalize `zone` (lowercase, no trailing dot)
    // - with `ip6lanprefix`: requires `DynDnsZone(zone)`, a `DynDnsHost` is not enough (it
    //   replaces every AAAA record of the zone):
    //   - read the zone (`pdns::client::api`), `dyndns::prefix::replace_prefix`, PATCH the AAAA
    //     rrsets
    //   - invalid AAAA records in the zone: `dnserr`, not a panic
    // - with `hostname`: every hostname must be `zone` (`@`) or end with `.zone`, else `nohost`.
    //   The name is the hostname without `.zone`, it requires `DynDnsHost(zone, names)` with the
    //   name in `names` (`DynDnsZone` doesn't cover single hosts)
    // - with `myip`/`ipaddr` (IPv4): replace the A rrset of the name, `ip6addr`: the AAAA rrset
    // - no permission for `zone`: `nohost` (or `badauth`), don't tell whether the zone exists
    let _ = (state, headers, zone, parameters);
    todo!("dyndns2 update of the given zone")
}
