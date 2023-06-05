//! Reverse proxy listening in "localhost:4000" will proxy all requests to "localhost:3000"
//! endpoint.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p example-reverse-proxy
//! ```

use axum::extract::Path;
use axum::routing::any;
use axum::{
    Router,
    extract::State,
    http::{Request, Response, uri::Uri},
};
use hyper::{Body, client::HttpConnector};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::OnceLock;

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

type Client = hyper::client::Client<HttpConnector, Body>;

const X_API_KEY: &str = "X-API-Key";
const ACTUAL_API_KEY: &str = "secret";

#[tokio::main]
async fn main() {
    let mut m = HashMap::new();
    m.insert("mysecret", "example.com");
    KEY_TO_ZONE.set(m).unwrap();

    let client = Client::new();

    let app = Router::new()
        .route(
            "/api/v1/servers/localhost/zones/:zone_id/*path",
            any(handle_zone_path),
        )
        .route(
            "/api/v1/servers/localhost/zones/:zone_id",
            any(handle_zone_root),
        )
        .fallback(handler)
        .with_state(client);

    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));
    println!("reverse proxy listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler(State(client): State<Client>, mut req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();

    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:8081{}", path_query);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    client.request(req).await.unwrap()
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
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:8081{}", path_query);

    *req.uri_mut() = Uri::try_from(uri).unwrap();

    // if the current zone_id matches the allowed_zone, then replace the key.
    let replace_key = allowed_zone.map(|allowed_zone| *allowed_zone == zone_id);
    // if the allowed_zone/replace_key is empty, then do NOT replace the key (maybe the original key is the actual API key)
    if replace_key.unwrap_or(false) {
        req.headers_mut().remove(X_API_KEY);
        req.headers_mut()
            .insert(X_API_KEY, ACTUAL_API_KEY.try_into().unwrap());
    }

    client.request(req).await.unwrap()
}
