use crate::server::proxy;
use crate::server::types::TawnyState;
use crate::token::Claim;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, Response};

pub async fn zone_root(
    State(state): State<TawnyState>,
    Path(zone_id): Path<String>,
    axum::Extension(claim): axum::Extension<Claim>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(state, zone_id, None, claim, req).await
}

pub async fn zone_path(
    State(state): State<TawnyState>,
    Path((zone_id, zone_path)): Path<(String, String)>,
    axum::Extension(claim): axum::Extension<Claim>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(state, zone_id, Some(zone_path), claim, req).await
}

pub async fn create_zone(State(state): State<TawnyState>, req: Request<Body>) -> Response<Body> {
    // TODO: filter the request
    proxy::sudo_proxy(State(state), req).await
}

async fn handle_zone(
    state: TawnyState,
    zone_id: String,
    _zone_path: Option<String>,
    claim: Claim,
    req: Request<Body>,
) -> Response<Body> {
    let _path = req.uri().path();

    // the zone in PowerDNS-Api requests may end with a '.' but is not required to end with a '.'
    // so let's normalize it here
    let zone_id = zone_id.strip_suffix('.').unwrap_or(&zone_id);

    // if the current zone_id matches the allowed_zone, then replace the key.
    let is_allowed = claim.zones.iter().any(|z| z == zone_id);

    if is_allowed {
        proxy::sudo_proxy(State(state), req).await
    } else {
        Response::builder()
            .status(http::StatusCode::FORBIDDEN)
            .body(Body::empty())
            .unwrap()
    }
}
