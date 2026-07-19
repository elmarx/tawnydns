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
use axum::routing::{any, post};
use axum::{
    Router,
    extract::State,
    http::{Request, Response},
};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::collections::HashMap;
use std::sync::OnceLock;
use tower_http::trace::TraceLayer;
use tracing::Level;

mod proxy;

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
            post(handle_create_zone).fallback(proxy::proxy_handler),
        )
        .route("/api/v1/servers", any(proxy::authorized_proxy_handler))
        .route(
            "/api/v1/servers/{server}",
            any(proxy::authorized_proxy_handler),
        )
        .fallback(proxy::proxy_handler)
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
    proxy::authorized_proxy_handler(State(client), req).await
}

async fn handle_zone(
    client: Client,
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
        proxy::authorized_proxy_handler(State(client), req).await
    } else {
        proxy::proxy_handler(State(client), req).await
    }
}
