use crate::server::constants::X_API_KEY;
use crate::server::types::TawnyState;
use crate::server::{KEY_TO_ZONE, proxy};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, Response};

pub async fn zone_root(
    State(state): State<TawnyState>,
    Path(zone_id): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(state, zone_id, None, req).await
}

pub async fn zone_path(
    State(state): State<TawnyState>,
    Path((zone_id, zone_path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(state, zone_id, Some(zone_path), req).await
}

pub async fn create_zone(State(state): State<TawnyState>, req: Request<Body>) -> Response<Body> {
    // TODO: filter the request
    proxy::authorized_proxy_handler(State(state), req).await
}

async fn handle_zone(
    state: TawnyState,
    zone_id: String,
    _zone_path: Option<String>,
    req: Request<Body>,
) -> Response<Body> {
    let _path = req.uri().path();

    let allowed_zone = req
        .headers()
        .get(X_API_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|key| KEY_TO_ZONE.get().unwrap().get(key));

    // the zone in PowerDNS-Api requests may end with a '.' but is not required to end with a '.'
    // so let's normalize it here
    let zone_id = zone_id.strip_suffix('.').unwrap_or(&zone_id);

    // if the current zone_id matches the allowed_zone, then replace the key.
    let replace_key = allowed_zone.is_none_or(|allowed_zone| *allowed_zone == zone_id);

    if replace_key {
        proxy::authorized_proxy_handler(State(state), req).await
    } else {
        proxy::passthrough(State(state), req).await
    }
}
