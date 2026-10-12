use crate::server::constants::X_API_KEY;
use crate::server::types::TawnyState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, Uri};
use axum::response::IntoResponse;

/// handler that just proxies any request
pub async fn passthrough(State(s): State<TawnyState>, mut req: Request<Body>) -> Response<Body> {
    let path_query = req.uri().path_and_query().map(ToOwned::to_owned);

    let mut upstream_url = s.pdns_url.into_parts();
    upstream_url.path_and_query = path_query;

    *req.uri_mut() = Uri::try_from(upstream_url).unwrap();

    s.client.request(req).await.unwrap().into_response()
}

/// handler that inserts the actual API key
pub async fn authorized_proxy_handler(
    State(s): State<TawnyState>,
    mut req: Request<Body>,
) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    req.headers_mut().remove(X_API_KEY);
    req.headers_mut().insert(X_API_KEY, s.pdns_api_key);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    s.client.request(req).await.unwrap().into_response()
}
