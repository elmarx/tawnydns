//! Reverse proxy listening in "localhost:4000" will proxy all requests to "localhost:3000"
//! endpoint.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p example-reverse-proxy
//! ```

use axum::body::Body;
use axum::extract::Path;
use axum::response::IntoResponse;
use axum::routing::{any, post};
use axum::{
    Router,
    extract::State,
    http::{Request, Response, uri::Uri},
};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::collections::HashMap;
use std::sync::OnceLock;
use tower_http::trace::TraceLayer;
use tracing::Level;

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

const X_API_KEY: &str = "X-API-Key";
const ACTUAL_API_KEY: &str = "secret";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let mut m = HashMap::new();
    m.insert("mysecret", "example.com");
    KEY_TO_ZONE.set(m).unwrap();

    let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
        .build(HttpConnector::new());

    let app = Router::new()
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}/{*path}",
            any(handle_zone_path),
        )
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}",
            any(handle_zone_root),
        )
        .route(
            "/api/v1/servers/localhost/zones",
            post(handle_create_zone).fallback(proxy_handler),
        )
        .route("/api/v1/servers", any(authorized_proxy_handler))
        .route("/api/v1/servers/{server}", any(authorized_proxy_handler))
        .fallback(proxy_handler)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(tower_http::trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(tower_http::trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(client);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// handler that just proxies any request
async fn proxy_handler(State(client): State<Client>, mut req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    client.request(req).await.unwrap().into_response()
}

/// handler that inserts the actual API key
async fn authorized_proxy_handler(
    State(client): State<Client>,
    mut req: Request<Body>,
) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    // TODO: check if X-API-Key is ANY valid api key
    req.headers_mut().remove(X_API_KEY);
    req.headers_mut()
        .insert(X_API_KEY, ACTUAL_API_KEY.try_into().unwrap());

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    client.request(req).await.unwrap().into_response()
}

async fn handle_zone_root(
    State(client): State<Client>,
    Path(zone_id): Path<String>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(client, zone_id, None, req).await
}

async fn handle_zone_path(
    State(client): State<Client>,
    Path((zone_id, zone_path)): Path<(String, String)>,
    req: Request<Body>,
) -> Response<Body> {
    handle_zone(client, zone_id, Some(zone_path), req).await
}
async fn handle_create_zone(State(client): State<Client>, req: Request<Body>) -> Response<Body> {
    // TODO: filter the request
    authorized_proxy_handler(State(client), req).await
}

async fn handle_zone(
    client: Client,
    zone_id: String,
    _zone_path: Option<String>,
    mut req: Request<Body>,
) -> Response<Body> {
    let path = req.uri().path();

    let allowed_zone = req
        .headers()
        .get(X_API_KEY)
        .and_then(|v| v.to_str().ok())
        .and_then(|key| KEY_TO_ZONE.get().unwrap().get(key));

    // the zone in PowerDNS-Api requests may end with a '.' but is not required to end with a '.'
    // so let's normalize it here
    let zone_id = if zone_id.ends_with('.') {
        zone_id.split_at(zone_id.len() - 1).0
    } else {
        &zone_id
    };

    let path_query = req
        .uri()
        .path_and_query()
        .map_or(path, axum::http::uri::PathAndQuery::as_str);

    let uri = format!("http://127.0.0.1:8081{path_query}");

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    // if the current zone_id matches the allowed_zone, then replace the key.
    let replace_key = allowed_zone.map(|allowed_zone| *allowed_zone == zone_id);
    // if the allowed_zone/replace_key is empty, then do NOT replace the key (maybe the original key is the actual API key)
    if replace_key.unwrap_or(false) {
        req.headers_mut().remove(X_API_KEY);
        req.headers_mut()
            .insert(X_API_KEY, ACTUAL_API_KEY.try_into().unwrap());
    }

    client.request(req).await.unwrap().into_response()
}
