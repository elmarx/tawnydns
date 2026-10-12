//! Reverse proxy listening in "localhost:4000" will proxy all requests to "localhost:3000"
//! endpoint.
//!
//! Run with
//!
//! ```not_rust
//! cargo run -p example-reverse-proxy
//! ```

use axum::Router;
use axum::body::Body;
use axum::routing::{any, post};
use clap::Parser;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::collections::HashMap;
use std::sync::OnceLock;
use tower_http::trace::TraceLayer;
use tracing::Level;

mod cli;
mod handler;
mod proxy;

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

type Client = hyper_util::client::legacy::Client<HttpConnector, Body>;

const X_API_KEY: &str = "X-API-Key";
const ACTUAL_API_KEY: &str = "secret";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    cli::Cli::parse();

    let mut m = HashMap::new();
    m.insert("mysecret", "example.com");
    KEY_TO_ZONE.set(m).unwrap();

    let client = hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
        .build(HttpConnector::new());

    let app = Router::new()
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}/{*path}",
            any(handler::zone_path),
        )
        .route(
            "/api/v1/servers/localhost/zones/{zone_id}",
            any(handler::zone_root),
        )
        .route(
            "/api/v1/servers/localhost/zones",
            post(handler::create_zone).fallback(proxy::proxy_handler),
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
