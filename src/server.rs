use axum::Router;
use axum::routing::{any, post};
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
use std::collections::HashMap;
use std::sync::OnceLock;
use tower_http::trace::TraceLayer;
use tracing::Level;

use crate::{handler, proxy};

static KEY_TO_ZONE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();

pub async fn server() {
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
